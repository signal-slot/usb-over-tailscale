//! "magicsock": moves WireGuard and disco packets between peers over UDP
//! (direct) or DERP (relayed), chooses paths, and drives STUN endpoint
//! discovery. Decrypted IP packets are handed to an `IpSink` (the netstack).

use crate::derp::{DerpClient, Event as DerpEvent};
use crate::disco::{self, Message as DiscoMsg, TxId};
use crate::keys::{short, KeyPair};
use crate::net::Dialer;
use crate::stun;
use crate::types::{DerpMap, DerpNode, Node, PeerChange};
use crate::wireguard::{self, Tunn};
use log::{debug, info, trace, warn};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub type IpSink = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// DERP "magic" IP used in `Node.DERP` and as the `src` of relayed pongs.
pub const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);

const TRUST_UDP_ADDR: Duration = Duration::from_millis(6500);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);
const CALL_ME_MAYBE_INTERVAL: Duration = Duration::from_secs(10);
const STUN_INTERVAL: Duration = Duration::from_secs(30);
const DERP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const DERP_PING_IDLE: Duration = Duration::from_secs(55);
const DERP_PING_TIMEOUT: Duration = Duration::from_secs(15);
/// Packets queued for one DERP connection while it is (re)connecting.
const DERP_QUEUE_LIMIT: usize = 64;
/// Endpoints remembered per peer (from control plus call-me-maybe).
const MAX_ENDPOINTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Udp(SocketAddr),
    Derp { region: i32, src: [u8; 32] },
}

struct BestAddr {
    addr: SocketAddr,
    trust_until: Instant,
    latency: Duration,
}

struct Peer {
    key: [u8; 32],
    name: String,
    disco: Option<[u8; 32]>,
    allowed_ips: Vec<(IpAddr, u8)>,
    endpoints: Vec<SocketAddr>,
    home_derp: i32,
    tunn: Tunn,
    best: Option<BestAddr>,
    pings: HashMap<TxId, (SocketAddr, Instant)>,
    last_ping_round: Option<Instant>,
    last_heartbeat: Option<Instant>,
    last_cmm: Option<Instant>,
    last_activity: Option<Instant>,
}

struct State {
    peers: HashMap<[u8; 32], Peer>,
    by_disco: HashMap<[u8; 32], [u8; 32]>,
    by_index: HashMap<u32, [u8; 32]>,
    filter: Option<crate::filter::Filter>,
    derp_map: DerpMap,
    stun_pending: HashMap<TxId, (i32, Instant)>,
    stun_latency: HashMap<i32, Duration>,
    mapped_addr: Option<SocketAddr>,
    last_stun: Option<Instant>,
    local_ip: Option<IpAddr>,
}

struct DerpHandle {
    tx: SyncSender<DerpCmd>,
    connected: Arc<AtomicBool>,
    last_used: Mutex<Instant>,
}

enum DerpCmd {
    Send { dst: [u8; 32], pkt: Vec<u8> },
    NotePreferred(bool),
    Close,
}

struct Inner {
    node_key: RwLock<KeyPair>,
    disco_key: KeyPair,
    udp: UdpSocket,
    udp_port: u16,
    state: Mutex<State>,
    derps: Mutex<HashMap<i32, DerpHandle>>,
    ip_sink: Mutex<Option<IpSink>>,
    dialer: Arc<dyn Dialer>,
    shutdown: AtomicBool,
    home_derp: AtomicI32,
    endpoints_changed: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    stack_size: usize,
    spawner: crate::net::Spawner,
}

#[derive(Clone)]
pub struct MagicSock {
    inner: Arc<Inner>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerStatus {
    pub name: String,
    pub key_short: String,
    pub direct: Option<SocketAddr>,
    pub home_derp: i32,
    pub has_session: bool,
    pub active: bool,
}

impl MagicSock {
    pub fn start(
        node_key: KeyPair,
        disco_key: KeyPair,
        dialer: Arc<dyn Dialer>,
        udp_port: u16,
        local_ip: Option<IpAddr>,
        stack_size: usize,
        spawner: crate::net::Spawner,
    ) -> io::Result<Self> {
        let udp = match UdpSocket::bind(("0.0.0.0", udp_port)) {
            Ok(s) => s,
            Err(e) => {
                warn!("magicsock: bind :{udp_port} failed ({e}); using an ephemeral port");
                UdpSocket::bind(("0.0.0.0", 0))?
            }
        };
        let bound_port = udp.local_addr()?.port();
        udp.set_read_timeout(Some(Duration::from_millis(500)))?;
        info!(
            "magicsock: node {} disco {} udp :{bound_port}",
            short(node_key.public()),
            short(disco_key.public())
        );
        let inner = Arc::new(Inner {
            node_key: RwLock::new(node_key),
            disco_key,
            udp,
            udp_port: bound_port,
            state: Mutex::new(State {
                peers: HashMap::new(),
                by_disco: HashMap::new(),
                by_index: HashMap::new(),
                filter: None,
                derp_map: DerpMap::default(),
                stun_pending: HashMap::new(),
                stun_latency: HashMap::new(),
                mapped_addr: None,
                last_stun: None,
                local_ip,
            }),
            derps: Mutex::new(HashMap::new()),
            ip_sink: Mutex::new(None),
            dialer,
            shutdown: AtomicBool::new(false),
            home_derp: AtomicI32::new(0),
            endpoints_changed: Mutex::new(None),
            stack_size,
            spawner,
        });
        let ms = MagicSock { inner };
        let rx = ms.clone();
        (ms.inner.spawner)("magicsock-udp", stack_size, Box::new(move || rx.udp_loop()))?;
        let tick = ms.clone();
        (ms.inner.spawner)(
            "magicsock-tick",
            stack_size,
            Box::new(move || tick.tick_loop()),
        )?;
        Ok(ms)
    }

    pub fn set_ip_sink(&self, sink: IpSink) {
        *self.inner.ip_sink.lock().unwrap() = Some(sink);
    }

    pub fn set_endpoints_changed(&self, cb: Arc<dyn Fn() + Send + Sync>) {
        *self.inner.endpoints_changed.lock().unwrap() = Some(cb);
    }

    pub fn node_public(&self) -> [u8; 32] {
        *self.inner.node_key.read().unwrap().public()
    }

    pub fn disco_public(&self) -> &[u8; 32] {
        self.inner.disco_key.public()
    }

    pub fn home_derp(&self) -> i32 {
        self.inner.home_derp.load(Ordering::Relaxed)
    }

    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::Relaxed);
        let derps = std::mem::take(&mut *self.inner.derps.lock().unwrap());
        for (_, h) in derps {
            let _ = h.tx.try_send(DerpCmd::Close);
        }
    }

    /// Endpoints to advertise to the control plane: LAN address and the
    /// STUN-mapped public address.
    pub fn local_endpoints(&self) -> Vec<SocketAddr> {
        let st = self.inner.state.lock().unwrap();
        let mut v = Vec::new();
        let lan = st.local_ip.or_else(guess_local_ip);
        if let Some(ip) = lan {
            v.push(SocketAddr::new(ip, self.inner.udp_port));
        }
        if let Some(m) = st.mapped_addr {
            if !v.contains(&m) {
                v.push(m);
            }
        }
        v
    }

    pub fn derp_latency(&self) -> HashMap<String, f64> {
        let st = self.inner.state.lock().unwrap();
        st.stun_latency
            .iter()
            .map(|(r, d)| (r.to_string(), d.as_secs_f64()))
            .collect()
    }

    pub fn peer_status(&self) -> Vec<PeerStatus> {
        let st = self.inner.state.lock().unwrap();
        let now = Instant::now();
        let mut v: Vec<PeerStatus> = st
            .peers
            .values()
            .map(|p| PeerStatus {
                name: p.name.clone(),
                key_short: short(&p.key),
                direct: p
                    .best
                    .as_ref()
                    .filter(|b| b.trust_until > now)
                    .map(|b| b.addr),
                home_derp: p.home_derp,
                has_session: p.tunn.has_session(),
                active: p
                    .last_activity
                    .map(|t| now.duration_since(t) < SESSION_ACTIVE_TIMEOUT)
                    .unwrap_or(false),
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    // ---- Control-plane driven configuration ----

    pub fn set_derp_map(&self, map: DerpMap) {
        let mut st = self.inner.state.lock().unwrap();
        st.derp_map = map;
        st.last_stun = None; // re-probe soon
    }

    /// Replaces the full peer list.
    pub fn set_peers(&self, nodes: &[Node]) {
        let mut st = self.inner.state.lock().unwrap();
        let mut old = std::mem::take(&mut st.peers);
        st.by_disco.clear();
        st.by_index.clear();
        for n in nodes {
            let Some(key) = crate::keys::parse_prefixed(crate::keys::NODE_PUB_PREFIX, &n.key)
            else {
                continue;
            };
            let mut peer = match old.remove(&key) {
                Some(p) => p,
                None => new_peer(self.inner.node_key.read().unwrap().clone(), key),
            };
            apply_node(&mut peer, n);
            if let Some(d) = peer.disco {
                st.by_disco.insert(d, key);
            }
            for idx in peer.tunn.local_indices() {
                st.by_index.insert(idx, key);
            }
            st.peers.insert(key, peer);
        }
        debug!("magicsock: {} peers", st.peers.len());
    }

    pub fn peers_changed(&self, nodes: &[Node]) {
        let mut st = self.inner.state.lock().unwrap();
        for n in nodes {
            let Some(key) = crate::keys::parse_prefixed(crate::keys::NODE_PUB_PREFIX, &n.key)
            else {
                continue;
            };
            let mut peer = st
                .peers
                .remove(&key)
                .unwrap_or_else(|| new_peer(self.inner.node_key.read().unwrap().clone(), key));
            if let Some(d) = peer.disco {
                st.by_disco.remove(&d);
            }
            apply_node(&mut peer, n);
            if let Some(d) = peer.disco {
                st.by_disco.insert(d, key);
            }
            st.peers.insert(key, peer);
        }
    }

    pub fn peers_removed(&self, ids: &[i64], nodes_by_id: &HashMap<i64, [u8; 32]>) {
        let mut st = self.inner.state.lock().unwrap();
        for id in ids {
            if let Some(key) = nodes_by_id.get(id) {
                if let Some(p) = st.peers.remove(key) {
                    if let Some(d) = p.disco {
                        st.by_disco.remove(&d);
                    }
                    st.by_index.retain(|_, k| k != key);
                }
            }
        }
    }

    /// Installs a new node key (after control rotated it): every tunnel is
    /// rebuilt with the new static key and the DERP connections, which are
    /// authenticated with it, are reopened by the tick loop.
    pub fn set_node_key(&self, key: KeyPair) {
        *self.inner.node_key.write().unwrap() = key.clone();
        {
            let mut st = self.inner.state.lock().unwrap();
            st.by_index.clear();
            for (k, p) in st.peers.iter_mut() {
                p.tunn = Tunn::new(key.clone(), *k);
                p.best = None;
            }
        }
        let derps = std::mem::take(&mut *self.inner.derps.lock().unwrap());
        for (_, h) in derps {
            let _ = h.tx.try_send(DerpCmd::Close);
        }
        info!("magicsock: node key rotated to {}", short(key.public()));
    }

    /// Installs the packet filter (ACL) received from control.
    pub fn set_packet_filter(&self, filter: crate::filter::Filter) {
        let mut st = self.inner.state.lock().unwrap();
        st.filter = Some(filter);
    }

    pub fn apply_patches(&self, patches: &[PeerChange], nodes_by_id: &HashMap<i64, [u8; 32]>) {
        let mut st = self.inner.state.lock().unwrap();
        for pc in patches {
            let Some(key) = nodes_by_id.get(&pc.node_id).copied() else {
                continue;
            };
            let Some(peer) = st.peers.get_mut(&key) else {
                continue;
            };
            if pc.derp_region != 0 {
                peer.home_derp = pc.derp_region;
            }
            if let Some(eps) = &pc.endpoints {
                peer.endpoints = eps.iter().filter_map(|e| e.parse().ok()).collect();
            }
            let mut new_disco = None;
            if let Some(d) = &pc.disco_key {
                if let Some(dk) = crate::keys::parse_prefixed(crate::keys::DISCO_PUB_PREFIX, d) {
                    new_disco = Some((peer.disco, dk));
                    peer.disco = Some(dk);
                }
            }
            if let Some((old, new)) = new_disco {
                if let Some(o) = old {
                    st.by_disco.remove(&o);
                }
                st.by_disco.insert(new, key);
            }
        }
    }

    // ---- Data path: netstack -> peer ----

    /// Sends an IP packet produced by the local stack to the right peer.
    pub fn send_ip(&self, pkt: &[u8]) {
        let Some(dst) = ip_dst(pkt) else { return };
        let now = Instant::now();
        let mut st = self.inner.state.lock().unwrap();
        let Some(key) = route(&st, dst) else {
            trace!("magicsock: no peer for {dst}");
            return;
        };
        let Some(peer) = st.peers.get_mut(&key) else {
            return;
        };
        peer.last_activity = Some(now);
        let out = peer.tunn.encapsulate(pkt, now);
        self.refresh_indices(&mut st, key);
        for m in out {
            self.send_wg(&mut st, key, &m, now);
        }
        self.maybe_start_discovery(&mut st, key, now);
    }

    fn refresh_indices(&self, st: &mut State, key: [u8; 32]) {
        if let Some(p) = st.peers.get(&key) {
            let current = p.tunn.local_indices();
            st.by_index
                .retain(|idx, k| *k != key || current.contains(idx));
            for idx in current {
                st.by_index.insert(idx, key);
            }
        }
    }

    /// Sends a WireGuard packet to a peer over the best available path.
    fn send_wg(&self, st: &mut State, key: [u8; 32], pkt: &[u8], now: Instant) {
        let Some(peer) = st.peers.get(&key) else {
            return;
        };
        if let Some(b) = &peer.best {
            if b.trust_until > now {
                let _ = self.inner.udp.send_to(pkt, b.addr);
                return;
            }
        }
        if peer.home_derp != 0 {
            let region = peer.home_derp;
            self.derp_send(st, region, key, pkt);
        } else if let Some(ep) = peer.endpoints.first() {
            // No DERP known (e.g. tests): try the first endpoint directly.
            let _ = self.inner.udp.send_to(pkt, ep);
        }
    }

    fn send_disco(&self, st: &mut State, key: [u8; 32], path: Path, msg: &DiscoMsg) {
        let Some(peer) = st.peers.get(&key) else {
            return;
        };
        let Some(their_disco) = peer.disco else {
            return;
        };
        let pkt = disco::seal(&self.inner.disco_key, &their_disco, msg);
        match path {
            Path::Udp(addr) => {
                let _ = self.inner.udp.send_to(&pkt, addr);
            }
            Path::Derp { region, .. } => self.derp_send(st, region, key, &pkt),
        }
    }

    fn derp_send(&self, st: &mut State, region: i32, dst: [u8; 32], pkt: &[u8]) {
        let mut derps = self.inner.derps.lock().unwrap();
        if let std::collections::hash_map::Entry::Vacant(e) = derps.entry(region) {
            match self.spawn_derp(st, region) {
                Some(h) => {
                    e.insert(h);
                }
                None => {
                    trace!("magicsock: no DERP node for region {region}");
                    return;
                }
            }
        }
        let h = derps.get(&region).unwrap();
        *h.last_used.lock().unwrap() = Instant::now();
        if let Err(TrySendError::Full(_)) = h.tx.try_send(DerpCmd::Send {
            dst,
            pkt: pkt.to_vec(),
        }) {
            trace!("magicsock: DERP {region} send queue full; dropping packet");
        }
    }

    fn spawn_derp(&self, st: &State, region: i32) -> Option<DerpHandle> {
        let node = pick_derp_node(&st.derp_map, region)?;
        let (tx, rx) = mpsc::sync_channel(DERP_QUEUE_LIMIT);
        let connected = Arc::new(AtomicBool::new(false));
        let me = self.clone();
        let c2 = connected.clone();
        let name = format!("derp-{region}");
        if let Err(e) = (self.inner.spawner)(
            &name,
            self.inner.stack_size,
            Box::new(move || me.derp_loop(region, node, rx, c2)),
        ) {
            warn!("magicsock: cannot spawn DERP thread: {e}");
            return None;
        }
        Some(DerpHandle {
            tx,
            connected,
            last_used: Mutex::new(Instant::now()),
        })
    }

    /// Ensures a connection to the home DERP exists and is marked preferred.
    pub fn connect_home_derp(&self, region: i32) {
        self.inner.home_derp.store(region, Ordering::Relaxed);
        let st = self.inner.state.lock().unwrap();
        let mut derps = self.inner.derps.lock().unwrap();
        if let std::collections::hash_map::Entry::Vacant(e) = derps.entry(region) {
            if let Some(h) = self.spawn_derp(&st, region) {
                e.insert(h);
            }
        }
        if let Some(h) = derps.get(&region) {
            let _ = h.tx.try_send(DerpCmd::NotePreferred(true));
            *h.last_used.lock().unwrap() = Instant::now();
        }
    }

    pub fn derp_connected(&self, region: i32) -> bool {
        self.inner
            .derps
            .lock()
            .unwrap()
            .get(&region)
            .map(|h| h.connected.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    // ---- Threads ----

    fn derp_loop(
        &self,
        region: i32,
        node: DerpNode,
        rx: Receiver<DerpCmd>,
        connected: Arc<AtomicBool>,
    ) {
        let mut backoff = Duration::from_secs(1);
        let mut preferred = false;
        'outer: while !self.inner.shutdown.load(Ordering::Relaxed) {
            let mut client = match DerpClient::connect(
                self.inner.dialer.as_ref(),
                &node,
                region,
                &self.inner.node_key.read().unwrap().clone(),
            ) {
                Ok(c) => c,
                Err(e) => {
                    warn!("derp[{region}]: connect to {} failed: {e}", node.host_name);
                    // Drain commands while waiting so senders never block.
                    let until = Instant::now() + backoff;
                    while Instant::now() < until {
                        match rx.recv_timeout(Duration::from_millis(200)) {
                            Ok(DerpCmd::Close) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                                break 'outer
                            }
                            Ok(DerpCmd::NotePreferred(p)) => preferred = p,
                            _ => {}
                        }
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                    continue;
                }
            };
            backoff = Duration::from_secs(1);
            connected.store(true, Ordering::Relaxed);
            info!("derp[{region}]: connected via {}", node.host_name);
            if preferred {
                let _ = client.note_preferred(true);
            }
            let mut pending_ping: Option<Instant> = None;
            loop {
                if self.inner.shutdown.load(Ordering::Relaxed) {
                    break 'outer;
                }
                match client.recv(Duration::from_millis(20)) {
                    Ok(Some(DerpEvent::Packet { src, data })) => {
                        self.handle_packet(Path::Derp { region, src }, &data)
                    }
                    Ok(Some(DerpEvent::PeerGone(k))) => {
                        trace!("derp[{region}]: peer gone {}", short(&k))
                    }
                    Ok(Some(DerpEvent::Pong(_))) => pending_ping = None,
                    Ok(Some(DerpEvent::Health(h))) => warn!("derp[{region}]: health: {h}"),
                    Ok(Some(DerpEvent::Restarting)) => {
                        info!("derp[{region}]: server restarting; reconnecting");
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!("derp[{region}]: {e}; reconnecting");
                        break;
                    }
                }
                let mut failed = false;
                loop {
                    match rx.try_recv() {
                        Ok(DerpCmd::Send { dst, pkt }) => {
                            if let Err(e) = client.send_packet(&dst, &pkt) {
                                warn!("derp[{region}]: send failed: {e}");
                                failed = true;
                                break;
                            }
                        }
                        Ok(DerpCmd::NotePreferred(p)) => {
                            preferred = p;
                            let _ = client.note_preferred(p);
                        }
                        Ok(DerpCmd::Close) | Err(TryRecvError::Disconnected) => break 'outer,
                        Err(TryRecvError::Empty) => break,
                    }
                }
                if failed {
                    break;
                }
                let now = Instant::now();
                if let Some(t) = pending_ping {
                    if now.duration_since(t) > DERP_PING_TIMEOUT {
                        warn!("derp[{region}]: ping timeout; reconnecting");
                        break;
                    }
                } else if now.duration_since(client.last_activity) > DERP_PING_IDLE {
                    if client.ping().is_err() {
                        break;
                    }
                    pending_ping = Some(now);
                }
            }
            connected.store(false, Ordering::Relaxed);
        }
        connected.store(false, Ordering::Relaxed);
        self.inner.derps.lock().unwrap().retain(|r, h| {
            !(*r == region && std::ptr::eq(h.connected.as_ref(), connected.as_ref()))
        });
        debug!("derp[{region}]: thread exit");
    }

    fn udp_loop(&self) {
        let mut buf = vec![0u8; 65536];
        while !self.inner.shutdown.load(Ordering::Relaxed) {
            match self.inner.udp.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let pkt = &buf[..n];
                    if stun::is_stun(pkt) {
                        self.handle_stun(pkt, from);
                    } else {
                        self.handle_packet(Path::Udp(from), pkt);
                    }
                }
                Err(e) if crate::net::is_timeout(&e) => {}
                Err(e) => {
                    warn!("magicsock: udp recv error: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    fn tick_loop(&self) {
        while !self.inner.shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
            let now = Instant::now();
            {
                let mut st = self.inner.state.lock().unwrap();
                let keys: Vec<[u8; 32]> = st.peers.keys().copied().collect();
                for key in keys {
                    let Some(peer) = st.peers.get_mut(&key) else {
                        continue;
                    };
                    let out = peer.tunn.tick(now);
                    self.refresh_indices(&mut st, key);
                    for m in out {
                        self.send_wg(&mut st, key, &m, now);
                    }
                    self.peer_path_maintenance(&mut st, key, now);
                }
                self.stun_maintenance(&mut st, now);
            }
            // Close DERP connections idle for a while (never the home one).
            let home = self.inner.home_derp.load(Ordering::Relaxed);
            if home != 0 && !self.inner.derps.lock().unwrap().contains_key(&home) {
                // The home connection is missing (map arrived late, or the
                // thread exited); bring it back.
                self.connect_home_derp(home);
            }
            let mut derps = self.inner.derps.lock().unwrap();
            let idle: Vec<i32> = derps
                .iter()
                .filter(|(r, h)| {
                    **r != home
                        && now.duration_since(*h.last_used.lock().unwrap()) > DERP_IDLE_TIMEOUT
                })
                .map(|(r, _)| *r)
                .collect();
            for r in idle {
                if let Some(h) = derps.remove(&r) {
                    let _ = h.tx.try_send(DerpCmd::Close);
                    debug!("magicsock: closed idle DERP {r}");
                }
            }
        }
    }

    // ---- Packet handling ----

    fn handle_packet(&self, path: Path, pkt: &[u8]) {
        if disco::is_disco(pkt) {
            self.handle_disco(path, pkt);
            return;
        }
        let Some(t) = wireguard::message_type(pkt) else {
            trace!(
                "magicsock: dropping unknown packet ({} bytes) from {path:?}",
                pkt.len()
            );
            return;
        };
        let now = Instant::now();
        let mut st = self.inner.state.lock().unwrap();
        match t {
            wireguard::MSG_INITIATION => {
                let ci = match wireguard::consume_initiation(
                    &self.inner.node_key.read().unwrap(),
                    pkt,
                ) {
                    Ok(ci) => ci,
                    Err(e) => {
                        trace!("magicsock: bad initiation from {path:?}: {e}");
                        return;
                    }
                };
                let key = ci.peer_public;
                let Some(peer) = st.peers.get_mut(&key) else {
                    debug!("magicsock: initiation from unknown peer {}", short(&key));
                    return;
                };
                match peer.tunn.accept_initiation(ci, now) {
                    Ok(resp) => {
                        self.refresh_indices(&mut st, key);
                        self.note_path(&mut st, key, path, now);
                        self.send_reply(&mut st, key, path, &resp);
                        debug!("magicsock: handshake from {} via {path:?}", short(&key));
                    }
                    Err(e) => trace!("magicsock: initiation rejected: {e}"),
                }
            }
            wireguard::MSG_RESPONSE => {
                let Some(idx) = wireguard::receiver_index(pkt) else {
                    return;
                };
                let Some(key) = st.by_index.get(&idx).copied() else {
                    trace!("magicsock: response for unknown index");
                    return;
                };
                let Some(peer) = st.peers.get_mut(&key) else {
                    st.by_index.remove(&idx);
                    return;
                };
                match peer.tunn.consume_response(pkt, now) {
                    Ok(flushed) => {
                        self.refresh_indices(&mut st, key);
                        self.note_path(&mut st, key, path, now);
                        debug!(
                            "magicsock: handshake with {} complete via {path:?}",
                            short(&key)
                        );
                        for m in flushed {
                            self.send_wg(&mut st, key, &m, now);
                        }
                    }
                    Err(e) => trace!("magicsock: bad response: {e}"),
                }
            }
            wireguard::MSG_TRANSPORT => {
                let Some(idx) = wireguard::receiver_index(pkt) else {
                    return;
                };
                let Some(key) = st.by_index.get(&idx).copied() else {
                    trace!("magicsock: transport for unknown index");
                    return;
                };
                let Some(peer) = st.peers.get_mut(&key) else {
                    st.by_index.remove(&idx);
                    return;
                };
                match peer.tunn.consume_transport(pkt, now) {
                    Ok(Some(ip)) => {
                        peer.last_activity = Some(now);
                        if !allowed_source(peer, &ip) {
                            trace!(
                                "magicsock: packet from {} with disallowed source",
                                short(&key)
                            );
                            return;
                        }
                        // The packet is authenticated, so the path is
                        // trusted even when the ACL drops the payload.
                        self.note_path(&mut st, key, path, now);
                        let allowed = match &st.filter {
                            Some(f) => f.allows(&ip),
                            None => false,
                        };
                        if !allowed {
                            trace!("magicsock: packet from {} denied by ACL", short(&key));
                            return;
                        }
                        drop(st);
                        if let Some(sink) = self.inner.ip_sink.lock().unwrap().as_ref() {
                            sink(ip);
                        }
                    }
                    Ok(None) => {
                        self.note_path(&mut st, key, path, now);
                    }
                    Err(e) => trace!("magicsock: transport error: {e}"),
                }
            }
            _ => {}
        }
    }

    /// Learns that `path` carried an authenticated packet from `key`
    /// (WireGuard-style roaming when no disco-verified path exists).
    fn note_path(&self, st: &mut State, key: [u8; 32], path: Path, now: Instant) {
        if let Path::Udp(addr) = path {
            let Some(peer) = st.peers.get_mut(&key) else {
                return;
            };
            match &mut peer.best {
                Some(b) if b.addr == addr => b.trust_until = now + TRUST_UDP_ADDR,
                Some(b) if b.trust_until > now => {}
                _ => {
                    debug!("magicsock: {} now direct via {addr} (roaming)", short(&key));
                    peer.best = Some(BestAddr {
                        addr,
                        trust_until: now + TRUST_UDP_ADDR,
                        latency: Duration::ZERO,
                    });
                }
            }
        }
    }

    fn send_reply(&self, st: &mut State, key: [u8; 32], path: Path, pkt: &[u8]) {
        match path {
            Path::Udp(addr) => {
                let _ = self.inner.udp.send_to(pkt, addr);
            }
            Path::Derp { region, .. } => self.derp_send(st, region, key, pkt),
        }
    }

    fn handle_disco(&self, path: Path, pkt: &[u8]) {
        let Some(sender) = disco::sender_key(pkt) else {
            return;
        };
        let now = Instant::now();
        let mut st = self.inner.state.lock().unwrap();
        let Some(key) = st.by_disco.get(&sender).copied() else {
            trace!("magicsock: disco from unknown key {}", short(&sender));
            return;
        };
        let msg = match disco::open(&self.inner.disco_key, &sender, pkt) {
            Ok(m) => m,
            Err(_) => {
                trace!("magicsock: disco open failed from {path:?}");
                return;
            }
        };
        match msg {
            DiscoMsg::Ping { txid, .. } => {
                let src = match path {
                    Path::Udp(a) => a,
                    Path::Derp { region, .. } => {
                        SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), region as u16)
                    }
                };
                trace!("magicsock: ping from {} via {path:?}", short(&key));
                self.send_disco(&mut st, key, path, &DiscoMsg::Pong { txid, src });
                if let Path::Udp(addr) = path {
                    // A direct ping reached us: probe the sender's address back.
                    let Some(peer) = st.peers.get_mut(&key) else {
                        return;
                    };
                    let known_good = peer
                        .best
                        .as_ref()
                        .map(|b| b.addr == addr && b.trust_until > now)
                        .unwrap_or(false);
                    if !known_good {
                        self.send_ping(&mut st, key, addr, now);
                    }
                }
            }
            DiscoMsg::Pong { txid, src: _ } => {
                let Some(peer) = st.peers.get_mut(&key) else {
                    return;
                };
                if let Some((addr, sent_at)) = peer.pings.remove(&txid) {
                    let latency = now.duration_since(sent_at);
                    let better = match &peer.best {
                        Some(b) => {
                            b.trust_until <= now
                                || b.addr == addr
                                || latency + Duration::from_millis(5) < b.latency
                        }
                        None => true,
                    };
                    if better {
                        if peer.best.as_ref().map(|b| b.addr != addr).unwrap_or(true) {
                            info!(
                                "magicsock: {} ({}) direct via {addr} ({latency:?})",
                                peer.name,
                                short(&key)
                            );
                        }
                        peer.best = Some(BestAddr {
                            addr,
                            trust_until: now + TRUST_UDP_ADDR,
                            latency,
                        });
                    }
                }
            }
            DiscoMsg::CallMeMaybe { endpoints } => {
                let Some(peer) = st.peers.get_mut(&key) else {
                    return;
                };
                for ep in &endpoints {
                    if !peer.endpoints.contains(ep) && peer.endpoints.len() < MAX_ENDPOINTS {
                        peer.endpoints.push(*ep);
                    }
                }
                debug!(
                    "magicsock: call-me-maybe from {} with {} endpoints",
                    short(&key),
                    endpoints.len()
                );
                self.ping_all_endpoints(&mut st, key, now);
            }
        }
    }

    fn send_ping(&self, st: &mut State, key: [u8; 32], addr: SocketAddr, now: Instant) {
        let txid = disco::new_txid();
        {
            let Some(peer) = st.peers.get_mut(&key) else {
                return;
            };
            if peer.pings.len() > 32 {
                peer.pings
                    .retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(10));
            }
            peer.pings.insert(txid, (addr, now));
        }
        let msg = DiscoMsg::Ping {
            txid,
            node_key: Some(*self.inner.node_key.read().unwrap().public()),
        };
        self.send_disco(st, key, Path::Udp(addr), &msg);
    }

    fn ping_all_endpoints(&self, st: &mut State, key: [u8; 32], now: Instant) {
        let eps: Vec<SocketAddr> = match st.peers.get_mut(&key) {
            Some(p) => {
                p.last_ping_round = Some(now);
                p.endpoints
                    .iter()
                    .copied()
                    .filter(|e| !e.ip().is_unspecified() && e.ip() != IpAddr::V4(DERP_MAGIC_IP))
                    .collect()
            }
            None => return,
        };
        for ep in eps {
            self.send_ping(st, key, ep, now);
        }
    }

    fn send_call_me_maybe(&self, st: &mut State, key: [u8; 32], now: Instant) {
        let region = match st.peers.get_mut(&key) {
            Some(p) if p.home_derp != 0 && p.disco.is_some() => {
                p.last_cmm = Some(now);
                p.home_derp
            }
            _ => return,
        };
        let endpoints = self.local_endpoints_locked(st);
        if endpoints.is_empty() {
            return;
        }
        let msg = DiscoMsg::CallMeMaybe { endpoints };
        self.send_disco(st, key, Path::Derp { region, src: key }, &msg);
    }

    fn local_endpoints_locked(&self, st: &State) -> Vec<SocketAddr> {
        let mut v = Vec::new();
        if let Some(ip) = st.local_ip.or_else(guess_local_ip) {
            v.push(SocketAddr::new(ip, self.inner.udp_port));
        }
        if let Some(m) = st.mapped_addr {
            if !v.contains(&m) {
                v.push(m);
            }
        }
        v
    }

    /// Kicks off discovery when traffic starts and no direct path exists.
    fn maybe_start_discovery(&self, st: &mut State, key: [u8; 32], now: Instant) {
        let (has_best, ping_due, cmm_due) = match st.peers.get(&key) {
            Some(p) => (
                p.best
                    .as_ref()
                    .map(|b| b.trust_until > now)
                    .unwrap_or(false),
                p.last_ping_round
                    .map(|t| now.duration_since(t) >= DISCO_PING_INTERVAL)
                    .unwrap_or(true),
                p.last_cmm
                    .map(|t| now.duration_since(t) >= CALL_ME_MAYBE_INTERVAL)
                    .unwrap_or(true),
            ),
            None => return,
        };
        if has_best {
            return;
        }
        if ping_due {
            self.ping_all_endpoints(st, key, now);
        }
        if cmm_due {
            self.send_call_me_maybe(st, key, now);
        }
    }

    fn peer_path_maintenance(&self, st: &mut State, key: [u8; 32], now: Instant) {
        let (active, best_addr, heartbeat_due) = match st.peers.get_mut(&key) {
            Some(p) => {
                let active = p
                    .last_activity
                    .map(|t| now.duration_since(t) < SESSION_ACTIVE_TIMEOUT)
                    .unwrap_or(false);
                if let Some(b) = &p.best {
                    if b.trust_until <= now && active {
                        debug!(
                            "magicsock: {} direct path {} expired; falling back to DERP",
                            short(&key),
                            b.addr
                        );
                        p.best = None;
                    }
                }
                let hb = p
                    .last_heartbeat
                    .map(|t| now.duration_since(t) >= HEARTBEAT_INTERVAL)
                    .unwrap_or(true);
                (active, p.best.as_ref().map(|b| b.addr), hb)
            }
            None => return,
        };
        if !active {
            return;
        }
        match best_addr {
            Some(addr) => {
                if heartbeat_due {
                    if let Some(p) = st.peers.get_mut(&key) {
                        p.last_heartbeat = Some(now);
                    }
                    self.send_ping(st, key, addr, now);
                }
            }
            None => self.maybe_start_discovery(st, key, now),
        }
    }

    // ---- STUN ----

    fn stun_maintenance(&self, st: &mut State, now: Instant) {
        st.stun_pending
            .retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(5));
        let due = st
            .last_stun
            .map(|t| now.duration_since(t) >= STUN_INTERVAL)
            .unwrap_or(true);
        if !due || st.derp_map.regions.is_empty() {
            return;
        }
        st.last_stun = Some(now);
        let home = self.inner.home_derp.load(Ordering::Relaxed);
        let targets: Vec<(i32, SocketAddr)> = st
            .derp_map
            .regions
            .values()
            .filter(|r| !r.avoid || r.region_id == home)
            .filter_map(|r| {
                // Probe every region until we have latencies, then only home.
                if home != 0 && !st.stun_latency.is_empty() && r.region_id != home {
                    return None;
                }
                let n = r.nodes.iter().find(|n| !n.ipv4.is_empty())?;
                let ip: Ipv4Addr = n.ipv4.parse().ok()?;
                let port = if n.stun_port > 0 {
                    n.stun_port as u16
                } else {
                    3478
                };
                Some((r.region_id, SocketAddr::new(IpAddr::V4(ip), port)))
            })
            .collect();
        for (region, addr) in targets {
            let txid = stun::new_txid();
            st.stun_pending.insert(txid, (region, now));
            let _ = self.inner.udp.send_to(&stun::request(&txid), addr);
        }
    }

    fn handle_stun(&self, pkt: &[u8], _from: SocketAddr) {
        let Some((txid, mapped)) = stun::parse_response(pkt) else {
            return;
        };
        let now = Instant::now();
        let mut st = self.inner.state.lock().unwrap();
        let Some((region, sent)) = st.stun_pending.remove(&txid) else {
            return;
        };
        let rtt = now.duration_since(sent);
        st.stun_latency.insert(region, rtt);
        trace!("magicsock: stun region {region} rtt {rtt:?} mapped {mapped}");
        if st.mapped_addr != Some(mapped) {
            info!("magicsock: public endpoint {mapped} (via DERP region {region})");
            st.mapped_addr = Some(mapped);
            drop(st);
            if let Some(cb) = self.inner.endpoints_changed.lock().unwrap().as_ref() {
                cb();
            }
        }
    }

    /// Sends STUN probes to all regions now and waits briefly for answers.
    /// Returns the region with the lowest latency, if any answered.
    pub fn probe_derp_regions(&self, wait: Duration) -> Option<i32> {
        {
            let mut st = self.inner.state.lock().unwrap();
            st.last_stun = None;
            st.stun_latency.clear();
            self.stun_maintenance(&mut st, Instant::now());
        }
        std::thread::sleep(wait);
        let st = self.inner.state.lock().unwrap();
        st.stun_latency
            .iter()
            .min_by_key(|(_, d)| **d)
            .map(|(r, _)| *r)
    }

    /// Fallback home-region choice when STUN is blocked: prefer a region by
    /// code (e.g. "tok"), else the lowest region id.
    pub fn fallback_region(&self, preferred_code: &str) -> Option<i32> {
        let st = self.inner.state.lock().unwrap();
        let mut regions: Vec<&crate::types::DerpRegion> = st
            .derp_map
            .regions
            .values()
            .filter(|r| !r.avoid && !r.nodes.is_empty())
            .collect();
        if let Some(r) = regions.iter().find(|r| r.region_code == preferred_code) {
            return Some(r.region_id);
        }
        regions.sort_by_key(|r| r.region_id);
        regions.first().map(|r| r.region_id)
    }
}

fn new_peer(local: KeyPair, key: [u8; 32]) -> Peer {
    Peer {
        key,
        name: String::new(),
        disco: None,
        allowed_ips: Vec::new(),
        endpoints: Vec::new(),
        home_derp: 0,
        tunn: Tunn::new(local, key),
        best: None,
        pings: HashMap::new(),
        last_ping_round: None,
        last_heartbeat: None,
        last_cmm: None,
        last_activity: None,
    }
}

fn apply_node(peer: &mut Peer, n: &Node) {
    peer.name = n.name.trim_end_matches('.').to_string();
    let new_disco = crate::keys::parse_prefixed(crate::keys::DISCO_PUB_PREFIX, &n.disco_key);
    if new_disco != peer.disco {
        peer.best = None;
    }
    peer.disco = new_disco;
    // Prefix-length-0 routes (exit nodes) are not installed: they would let
    // that peer send with any source address and swallow every destination.
    peer.allowed_ips = n
        .allowed_ips
        .iter()
        .chain(n.addresses.iter())
        .filter_map(|c| parse_cidr(c))
        .filter(|c| c.1 != 0)
        .collect();
    peer.allowed_ips.dedup();
    peer.endpoints = n.endpoints.iter().filter_map(|e| e.parse().ok()).collect();
    peer.home_derp = n.home_derp_region().unwrap_or(0);
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip.parse::<IpAddr>().ok()?, p.parse::<u8>().ok()?),
        None => {
            let ip = s.parse::<IpAddr>().ok()?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    Some((ip, prefix))
}

fn cidr_contains(cidr: &(IpAddr, u8), ip: IpAddr) -> bool {
    match (cidr.0, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let bits = cidr.1.min(32);
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let bits = cidr.1.min(128);
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
}

fn route(st: &State, dst: IpAddr) -> Option<[u8; 32]> {
    let mut best: Option<(u8, [u8; 32])> = None;
    for (key, p) in &st.peers {
        for c in &p.allowed_ips {
            if cidr_contains(c, dst) && best.map(|(b, _)| c.1 > b).unwrap_or(true) {
                best = Some((c.1, *key));
            }
        }
    }
    best.map(|(_, k)| k)
}

fn allowed_source(peer: &Peer, ip_pkt: &[u8]) -> bool {
    match ip_src(ip_pkt) {
        Some(src) => peer.allowed_ips.iter().any(|c| cidr_contains(c, src)),
        None => false,
    }
}

fn ip_dst(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            pkt[16], pkt[17], pkt[18], pkt[19],
        ))),
        6 if pkt.len() >= 40 => {
            let o: [u8; 16] = pkt[24..40].try_into().ok()?;
            Some(IpAddr::V6(o.into()))
        }
        _ => None,
    }
}

fn ip_src(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            pkt[12], pkt[13], pkt[14], pkt[15],
        ))),
        6 if pkt.len() >= 40 => {
            let o: [u8; 16] = pkt[8..24].try_into().ok()?;
            Some(IpAddr::V6(o.into()))
        }
        _ => None,
    }
}

fn pick_derp_node(map: &DerpMap, region: i32) -> Option<DerpNode> {
    let r = map.regions.get(&region.to_string())?;
    r.nodes.iter().find(|n| !n.stun_only).cloned()
}

/// Best-effort LAN address: the source address the OS would use to reach a
/// public destination (no packets are sent).
pub fn guess_local_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:53").ok()?;
    let ip = s.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{fmt_disco_pub, fmt_node_pub};
    use crate::netstack::NetStack;

    struct NoDialer;
    impl Dialer for NoDialer {
        fn dial_tcp(&self, _: &str, _: u16) -> io::Result<Box<dyn crate::net::Conn>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no network in tests",
            ))
        }
        fn dial_tls(
            &self,
            _: &str,
            _: Option<IpAddr>,
            _: u16,
        ) -> io::Result<Box<dyn crate::net::Conn>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no network in tests",
            ))
        }
    }

    fn node_for(ms: &MagicSock, name: &str, ip: &str, port: u16) -> Node {
        Node {
            id: 1,
            name: name.into(),
            key: fmt_node_pub(&ms.node_public()),
            disco_key: fmt_disco_pub(ms.disco_public()),
            addresses: vec![format!("{ip}/32")],
            allowed_ips: vec![format!("{ip}/32")],
            endpoints: vec![format!("127.0.0.1:{port}")],
            ..Default::default()
        }
    }

    /// Two nodes on localhost: TCP through WireGuard through UDP, direct path
    /// discovered with disco pings.
    #[test]
    fn tcp_over_wireguard_between_two_nodes() {
        let _ = env_logger::builder().is_test(true).try_init();
        let dialer: Arc<dyn Dialer> = Arc::new(NoDialer);
        let a = MagicSock::start(
            KeyPair::generate(),
            KeyPair::generate(),
            dialer.clone(),
            0,
            Some("127.0.0.1".parse().unwrap()),
            256 * 1024,
            crate::net::std_spawner(),
        )
        .unwrap();
        let b = MagicSock::start(
            KeyPair::generate(),
            KeyPair::generate(),
            dialer,
            0,
            Some("127.0.0.1".parse().unwrap()),
            256 * 1024,
            crate::net::std_spawner(),
        )
        .unwrap();
        let (a2, b2) = (a.clone(), b.clone());
        let ns_a = NetStack::start(
            Box::new(move |p| a2.send_ip(&p)),
            256 * 1024,
            &crate::net::std_spawner(),
        )
        .unwrap();
        let ns_b = NetStack::start(
            Box::new(move |p| b2.send_ip(&p)),
            256 * 1024,
            &crate::net::std_spawner(),
        )
        .unwrap();
        let (sa, sb) = (ns_a.clone(), ns_b.clone());
        a.set_ip_sink(Arc::new(move |p| sa.inject(p)));
        b.set_ip_sink(Arc::new(move |p| sb.inject(p)));
        a.set_packet_filter(crate::filter::Filter::allow_all());
        b.set_packet_filter(crate::filter::Filter::allow_all());
        ns_a.set_addresses(vec![("100.64.0.1".parse().unwrap(), 10)]);
        ns_b.set_addresses(vec![("100.64.0.2".parse().unwrap(), 10)]);
        a.set_peers(&[node_for(&b, "b", "100.64.0.2", b.inner.udp_port)]);
        b.set_peers(&[node_for(&a, "a", "100.64.0.1", a.inner.udp_port)]);

        let listener = ns_b.listen(2300);
        let client = ns_a.connect("100.64.0.2:2300".parse().unwrap());
        let server = listener
            .accept(Duration::from_secs(10))
            .expect("accept through wireguard");
        client.write_all(b"ping through wg").unwrap();
        let mut buf = [0u8; 128];
        let n = server.read(&mut buf, Duration::from_secs(10)).unwrap();
        assert_eq!(&buf[..n], b"ping through wg");
        server.write_all(b"pong").unwrap();
        let n = client.read(&mut buf, Duration::from_secs(10)).unwrap();
        assert_eq!(&buf[..n], b"pong");

        // Discovery should have established a disco-verified direct path.
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let st = a.peer_status();
            if st[0].direct.is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "no direct path discovered: {st:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        a.shutdown();
        b.shutdown();
        ns_a.shutdown();
        ns_b.shutdown();
    }

    #[test]
    fn cidr_and_routing() {
        assert!(cidr_contains(
            &("100.64.0.0".parse().unwrap(), 10),
            "100.100.1.1".parse().unwrap()
        ));
        assert!(!cidr_contains(
            &("100.64.0.0".parse().unwrap(), 10),
            "100.128.0.1".parse().unwrap()
        ));
        assert!(cidr_contains(
            &("fd7a:115c:a1e0::".parse().unwrap(), 48),
            "fd7a:115c:a1e0::1".parse().unwrap()
        ));
        assert_eq!(
            parse_cidr("100.64.0.5/32"),
            Some(("100.64.0.5".parse().unwrap(), 32))
        );
    }
}
