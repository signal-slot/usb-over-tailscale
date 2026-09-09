//! Glue: runs the control client, feeds magicsock and the netstack, and
//! exposes status plus TCP listeners on the node's tailnet address.

use crate::control::{hostinfo, ControlClient};
use crate::filter::Filter;
use crate::keys::{fmt_disco_pub, fmt_node_pub, parse_prefixed, KeyPair, NODE_PUB_PREFIX};
use crate::magicsock::{MagicSock, PeerStatus};
use crate::net::Dialer;
use crate::netstack::{NetStack, TcpListener};
use crate::types::*;
use crate::wireguard::WALL_CLOCK_OFFSET_SECS;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Persistent key/value storage for node identity.
pub trait Store: Send + Sync {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&self, key: &str, value: &str) -> io::Result<()>;
    fn remove(&self, key: &str) -> io::Result<()>;
}

pub const KEY_MACHINE: &str = "machine_key";
pub const KEY_NODE: &str = "node_key";
pub const KEY_DISCO: &str = "disco_key";
pub const KEY_REGISTERED: &str = "registered";
pub const KEY_HOME_DERP: &str = "home_derp";

/// The control server sends keep-alives about once a minute on a map stream.
const MAP_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(150);

#[derive(Clone)]
pub struct NodeConfig {
    pub control_url: String,
    /// Auth key used for headless registration; may be absent once registered.
    pub auth_key: Option<String>,
    pub hostname: String,
    pub version: String,
    /// UDP port for WireGuard/disco (0 = ephemeral).
    pub udp_port: u16,
    /// LAN IP to advertise; auto-detected when `None`.
    pub local_ip: Option<IpAddr>,
    /// Stack size for worker threads (UDP, DERP, tick, netstack).
    pub worker_stack: usize,
    /// Stack size for the control thread (TLS + JSON).
    pub control_stack: usize,
    /// DERP region code used when STUN gets no answers (e.g. "tok").
    pub fallback_region_code: String,
    /// Thread spawner (defaults to `std::thread`).
    pub spawner: Option<crate::net::Spawner>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            control_url: "https://controlplane.tailscale.com".into(),
            auth_key: None,
            hostname: "tsnode".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            udp_port: 41641,
            local_ip: None,
            worker_stack: 32 * 1024,
            control_stack: 64 * 1024,
            fallback_region_code: "tok".into(),
            spawner: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeState {
    Starting,
    ConnectingControl,
    Registering,
    /// Registration requires interactive approval at the given URL.
    NeedsLogin(String),
    Running,
    Error(String),
}

#[derive(Clone, Debug)]
pub struct NodeStatus {
    pub state: NodeState,
    pub addresses: Vec<IpAddr>,
    pub dns_name: String,
    pub home_derp: i32,
    pub derp_connected: bool,
    pub endpoints: Vec<SocketAddr>,
    pub peers: Vec<PeerStatus>,
    pub last_error: Option<String>,
    pub map_updates: u64,
}

struct Inner {
    cfg: NodeConfig,
    store: Arc<dyn Store>,
    dialer: Arc<dyn Dialer>,
    magicsock: MagicSock,
    netstack: NetStack,
    node_key: Mutex<KeyPair>,
    machine_key: KeyPair,
    status: Mutex<NodeStatus>,
    shutdown: AtomicBool,
    endpoints_dirty: AtomicBool,
    nodes_by_id: Mutex<HashMap<i64, [u8; 32]>>,
    /// Named ACL rule sets as received from control (`*` is the base set).
    filter_sets: Mutex<std::collections::BTreeMap<String, Vec<FilterRule>>>,
}

#[derive(Clone)]
pub struct Node {
    inner: Arc<Inner>,
}

fn load_or_create_key(store: &dyn Store, name: &str) -> io::Result<KeyPair> {
    if let Some(v) = store.get(name) {
        if let Some(k) = KeyPair::from_secret_hex(&v) {
            return Ok(k);
        }
        warn!("node: stored {name} is invalid; regenerating");
    }
    let k = KeyPair::generate();
    store.set(name, &k.secret_hex())?;
    Ok(k)
}

impl Node {
    pub fn start(
        cfg: NodeConfig,
        store: Arc<dyn Store>,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Node> {
        let machine_key = load_or_create_key(store.as_ref(), KEY_MACHINE)?;
        let node_key = load_or_create_key(store.as_ref(), KEY_NODE)?;
        let disco_key = load_or_create_key(store.as_ref(), KEY_DISCO)?;
        info!(
            "node: machine {} node {}",
            crate::keys::short(machine_key.public()),
            crate::keys::short(node_key.public())
        );

        let spawner = cfg.spawner.clone().unwrap_or_else(crate::net::std_spawner);
        let magicsock = MagicSock::start(
            node_key.clone(),
            disco_key,
            dialer.clone(),
            cfg.udp_port,
            cfg.local_ip,
            cfg.worker_stack,
            spawner.clone(),
        )?;
        let ms = magicsock.clone();
        let netstack = NetStack::start(
            Box::new(move |pkt| ms.send_ip(&pkt)),
            cfg.worker_stack,
            &spawner,
        )?;
        let ns = netstack.clone();
        magicsock.set_ip_sink(Arc::new(move |pkt| ns.inject(pkt)));

        let inner = Arc::new(Inner {
            cfg,
            store,
            dialer,
            magicsock,
            netstack,
            node_key: Mutex::new(node_key),
            machine_key,
            status: Mutex::new(NodeStatus {
                state: NodeState::Starting,
                addresses: Vec::new(),
                dns_name: String::new(),
                home_derp: 0,
                derp_connected: false,
                endpoints: Vec::new(),
                peers: Vec::new(),
                last_error: None,
                map_updates: 0,
            }),
            shutdown: AtomicBool::new(false),
            endpoints_dirty: AtomicBool::new(false),
            nodes_by_id: Mutex::new(HashMap::new()),
            filter_sets: Mutex::new(Default::default()),
        });
        let node = Node {
            inner: inner.clone(),
        };
        let flag = inner.clone();
        inner.magicsock.set_endpoints_changed(Arc::new(move || {
            flag.endpoints_dirty.store(true, Ordering::Relaxed)
        }));
        let ctl = node.clone();
        spawner(
            "control",
            inner.cfg.control_stack,
            Box::new(move || ctl.control_loop()),
        )?;
        Ok(node)
    }

    pub fn status(&self) -> NodeStatus {
        let mut s = self.inner.status.lock().unwrap().clone();
        s.peers = self.inner.magicsock.peer_status();
        s.endpoints = self.inner.magicsock.local_endpoints();
        s.home_derp = self.inner.magicsock.home_derp();
        s.derp_connected = s.home_derp != 0 && self.inner.magicsock.derp_connected(s.home_derp);
        s
    }

    pub fn listen(&self, port: u16) -> TcpListener {
        self.inner.netstack.listen(port)
    }

    pub fn netstack(&self) -> &NetStack {
        &self.inner.netstack
    }

    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::Relaxed);
        self.inner.magicsock.shutdown();
        self.inner.netstack.shutdown();
    }

    fn set_state(&self, state: NodeState) {
        let mut s = self.inner.status.lock().unwrap();
        if s.state != state {
            info!("node: state {:?}", state);
            if let NodeState::Error(e) = &state {
                s.last_error = Some(e.clone());
            }
            s.state = state;
        }
    }

    fn sleep_backoff(&self, backoff: &mut Duration) {
        let d = *backoff;
        let until = Instant::now() + d;
        while Instant::now() < until && !self.inner.shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(250));
        }
        *backoff = (d * 2).min(Duration::from_secs(60));
    }

    fn control_loop(&self) {
        let mut backoff = Duration::from_secs(2);
        let inner = &self.inner;
        while !inner.shutdown.load(Ordering::Relaxed) {
            self.set_state(NodeState::ConnectingControl);
            let client = match ControlClient::connect(
                inner.dialer.clone(),
                &inner.cfg.control_url,
                inner.machine_key.clone(),
            ) {
                Ok(c) => c,
                Err(e) => {
                    self.set_state(NodeState::Error(format!("control: {e}")));
                    self.sleep_backoff(&mut backoff);
                    continue;
                }
            };

            if inner.store.get(KEY_REGISTERED).as_deref() != Some("1") {
                self.set_state(NodeState::Registering);
                match self.register(&client) {
                    Ok(true) => {
                        let _ = inner.store.set(KEY_REGISTERED, "1");
                    }
                    Ok(false) => {
                        // Waiting for interactive approval; poll again later.
                        std::thread::sleep(Duration::from_secs(20));
                        continue;
                    }
                    Err(e) => {
                        self.set_state(NodeState::Error(format!("register: {e}")));
                        self.sleep_backoff(&mut backoff);
                        continue;
                    }
                }
            }

            match self.run_map_stream(&client) {
                Ok(()) => {
                    backoff = Duration::from_secs(2);
                }
                Err(e) => {
                    let msg = e.to_string();
                    warn!("node: map stream ended: {msg}");
                    if msg.contains("HTTP 401")
                        || msg.contains("HTTP 403")
                        || msg.contains("not registered")
                        || msg.contains("expired")
                    {
                        let _ = inner.store.remove(KEY_REGISTERED);
                        backoff = Duration::from_secs(2);
                    } else {
                        self.set_state(NodeState::Error(format!("map: {msg}")));
                    }
                    self.sleep_backoff(&mut backoff);
                }
            }
        }
        debug!("node: control loop exit");
    }

    /// Returns `Ok(true)` when authorized, `Ok(false)` when waiting for approval.
    fn register(&self, client: &ControlClient) -> io::Result<bool> {
        let inner = &self.inner;
        let node_key = inner.node_key.lock().unwrap().clone();
        let auth = inner.cfg.auth_key.clone().filter(|k| !k.is_empty());
        let req = RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: fmt_node_pub(node_key.public()),
            old_node_key: fmt_node_pub(&[0u8; 32]),
            auth: auth.map(|k| RegisterResponseAuth { auth_key: k }),
            expiry: ZERO_TIME.into(),
            followup: String::new(),
            hostinfo: hostinfo(&inner.cfg.hostname, &inner.cfg.version, 0),
            ephemeral: false,
        };
        let resp = client.register(&req)?;
        if !resp.error.is_empty() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, resp.error));
        }
        if resp.node_key_expired {
            info!("node: node key expired; rotating");
            let new_key = KeyPair::generate();
            let mut req2 = req.clone();
            req2.old_node_key = req.node_key.clone();
            req2.node_key = fmt_node_pub(new_key.public());
            let resp2 = client.register(&req2)?;
            if !resp2.error.is_empty() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, resp2.error));
            }
            inner.store.set(KEY_NODE, &new_key.secret_hex())?;
            *inner.node_key.lock().unwrap() = new_key.clone();
            inner.magicsock.set_node_key(new_key);
            return Ok(resp2.machine_authorized);
        }
        if resp.machine_authorized {
            info!("node: registered as {}", resp.login.login_name);
            return Ok(true);
        }
        if !resp.auth_url.is_empty() {
            warn!("node: approval required: {}", resp.auth_url);
            self.set_state(NodeState::NeedsLogin(resp.auth_url));
            return Ok(false);
        }
        Err(io::Error::other("register: not authorized and no auth URL"))
    }

    fn map_request(&self, stream: bool) -> MapRequest {
        let inner = &self.inner;
        let node_key = inner.node_key.lock().unwrap().clone();
        let home = inner.magicsock.home_derp();
        let mut hi = hostinfo(&inner.cfg.hostname, &inner.cfg.version, home);
        if let Some(ni) = hi.net_info.as_mut() {
            ni.derp_latency = inner.magicsock.derp_latency();
        }
        MapRequest {
            version: CAPABILITY_VERSION,
            compress: String::new(),
            keep_alive: stream,
            node_key: fmt_node_pub(node_key.public()),
            disco_key: fmt_disco_pub(inner.magicsock.disco_public()),
            stream,
            hostinfo: hi,
            endpoints: inner
                .magicsock
                .local_endpoints()
                .iter()
                .map(|e| e.to_string())
                .collect(),
            omit_peers: !stream,
            read_only: false,
        }
    }

    fn run_map_stream(&self, client: &ControlClient) -> io::Result<()> {
        let inner = &self.inner;
        // Reconnect to the last known home DERP early so peers can reach us.
        if inner.magicsock.home_derp() == 0 {
            if let Some(r) = inner
                .store
                .get(KEY_HOME_DERP)
                .and_then(|v| v.parse::<i32>().ok())
            {
                inner.magicsock.connect_home_derp(r);
            }
        }
        let req = self.map_request(true);
        let mut stream = client.map_stream(&req)?;
        info!("node: map stream connected");
        self.set_state(NodeState::Running);
        inner.endpoints_dirty.store(false, Ordering::Relaxed);
        let mut last_lite = Instant::now();
        let mut last_msg = Instant::now();
        loop {
            if inner.shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }
            match stream.next(Duration::from_secs(5)) {
                Ok(Some(resp)) => {
                    last_msg = Instant::now();
                    debug!(
                        "node: map message: keepalive={} node={} peers={:?} changed={:?} removed={:?} patch={:?} derpmap={}",
                        resp.keep_alive,
                        resp.node.is_some(),
                        resp.peers.as_ref().map(|p| p.len()),
                        resp.peers_changed.as_ref().map(|p| p.len()),
                        resp.peers_removed.as_ref().map(|p| p.len()),
                        resp.peers_changed_patch.as_ref().map(|p| p.len()),
                        resp.derp_map.is_some()
                    );
                    self.handle_map_response(resp);
                }
                Ok(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "map stream closed",
                    ))
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    if last_msg.elapsed() > MAP_KEEPALIVE_TIMEOUT {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "no keep-alive from control",
                        ));
                    }
                }
                Err(e) => return Err(e),
            }
            if inner.endpoints_dirty.load(Ordering::Relaxed)
                && last_lite.elapsed() > Duration::from_secs(3)
            {
                inner.endpoints_dirty.store(false, Ordering::Relaxed);
                last_lite = Instant::now();
                let lite = self.map_request(false);
                debug!(
                    "node: endpoint update {:?} derp {}",
                    lite.endpoints,
                    inner.magicsock.home_derp()
                );
                if let Err(e) = client.map_once(&lite) {
                    warn!("node: endpoint update failed: {e}");
                    inner.endpoints_dirty.store(true, Ordering::Relaxed);
                }
            }
        }
    }

    fn handle_map_response(&self, resp: MapResponse) {
        let inner = &self.inner;
        if resp.keep_alive
            && resp.node.is_none()
            && resp.peers.is_none()
            && resp.peers_changed.is_none()
            && resp.peers_changed_patch.is_none()
        {
            return;
        }
        inner.status.lock().unwrap().map_updates += 1;
        if let Some(ct) = resp.control_time.as_deref().and_then(parse_rfc3339_secs) {
            let local = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let offset = ct - local;
            if offset.abs() > 5 {
                debug!("node: clock offset from control time: {offset}s");
            }
            WALL_CLOCK_OFFSET_SECS.store(
                offset.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
                Ordering::Relaxed,
            );
        }
        if let Some(node) = &resp.node {
            let mut addrs = Vec::new();
            let mut cidrs = Vec::new();
            for a in &node.addresses {
                let ip_str = a.split('/').next().unwrap_or("");
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    let prefix = if ip.is_ipv4() { 10 } else { 48 };
                    addrs.push(ip);
                    cidrs.push((ip, prefix));
                }
            }
            inner.netstack.set_addresses(cidrs);
            let mut s = inner.status.lock().unwrap();
            if s.addresses != addrs {
                info!("node: addresses {:?}", addrs);
            }
            s.addresses = addrs;
            s.dns_name = node.name.trim_end_matches('.').to_string();
        }
        if let Some(map) = resp.derp_map {
            let regions = map.regions.len();
            inner.magicsock.set_derp_map(map);
            debug!("node: DERP map with {regions} regions");
            let known = inner.magicsock.home_derp();
            if known != 0 {
                // Home region was restored from the store before the map
                // arrived; (re)connect now that the region's nodes are known.
                inner.magicsock.connect_home_derp(known);
                inner.endpoints_dirty.store(true, Ordering::Relaxed);
            } else {
                let home = inner
                    .magicsock
                    .probe_derp_regions(Duration::from_millis(1500))
                    .or_else(|| {
                        inner
                            .magicsock
                            .fallback_region(&inner.cfg.fallback_region_code)
                    });
                if let Some(r) = home {
                    info!("node: home DERP region {r}");
                    inner.magicsock.connect_home_derp(r);
                    let _ = inner.store.set(KEY_HOME_DERP, &r.to_string());
                    inner.endpoints_dirty.store(true, Ordering::Relaxed);
                }
            }
        }
        if let Some(peers) = &resp.peers {
            let mut by_id = inner.nodes_by_id.lock().unwrap();
            by_id.clear();
            for p in peers {
                if let Some(k) = parse_prefixed(NODE_PUB_PREFIX, &p.key) {
                    by_id.insert(p.id, k);
                }
            }
            drop(by_id);
            inner.magicsock.set_peers(peers);
            info!("node: {} peers", peers.len());
        }
        if let Some(changed) = &resp.peers_changed {
            let mut by_id = inner.nodes_by_id.lock().unwrap();
            for p in changed {
                if let Some(k) = parse_prefixed(NODE_PUB_PREFIX, &p.key) {
                    by_id.insert(p.id, k);
                }
            }
            drop(by_id);
            inner.magicsock.peers_changed(changed);
        }
        if let Some(removed) = &resp.peers_removed {
            let mut by_id = inner.nodes_by_id.lock().unwrap();
            let snapshot = by_id.clone();
            inner.magicsock.peers_removed(removed, &snapshot);
            for id in removed {
                by_id.remove(id);
            }
        }
        if let Some(patches) = &resp.peers_changed_patch {
            let by_id = inner.nodes_by_id.lock().unwrap().clone();
            inner.magicsock.apply_patches(patches, &by_id);
        }
        // ACL: the legacy field replaces everything; the named sets are
        // merged (a null entry deletes that set).
        let mut filter_changed = false;
        if let Some(rules) = &resp.packet_filter {
            let mut sets = inner.filter_sets.lock().unwrap();
            sets.clear();
            sets.insert("*".into(), rules.clone());
            filter_changed = true;
        }
        if let Some(named) = &resp.packet_filters {
            let mut sets = inner.filter_sets.lock().unwrap();
            for (name, rules) in named {
                match rules {
                    Some(r) => {
                        sets.insert(name.clone(), r.clone());
                    }
                    None => {
                        sets.remove(name);
                    }
                }
            }
            filter_changed = true;
        }
        if filter_changed {
            let sets = inner.filter_sets.lock().unwrap();
            let all: Vec<FilterRule> = sets.values().flatten().cloned().collect();
            debug!("node: packet filter with {} rules", all.len());
            inner.magicsock.set_packet_filter(Filter::compile(&all));
        }
        if let Some(h) = &resp.health {
            for m in h {
                warn!("node: control health: {m}");
            }
        }
        if resp.ping_request.is_some() {
            debug!("node: ignoring control PingRequest");
        }
    }
}

/// Parses an RFC 3339 timestamp (as emitted by Go) into Unix seconds.
pub fn parse_rfc3339_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day: i64 = s[8..10].parse().ok()?;
    let hour: i64 = s[11..13].parse().ok()?;
    let min: i64 = s[14..16].parse().ok()?;
    let sec: i64 = s[17..19].parse().ok()?;
    // Time zone: 'Z' or +hh:mm / -hh:mm at the end.
    let mut tz = 0i64;
    if let Some(pos) = s.rfind(['+', '-']) {
        if pos > 18 {
            let sign = if &s[pos..pos + 1] == "+" { 1 } else { -1 };
            let h: i64 = s.get(pos + 1..pos + 3)?.parse().ok()?;
            let m: i64 = s.get(pos + 4..pos + 6)?.parse().ok()?;
            tz = sign * (h * 3600 + m * 60);
        }
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86400 + hour * 3600 + min * 60 + sec - tz)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339_secs("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_secs("2026-09-07T09:00:00Z"), Some(1788771600));
        assert_eq!(
            parse_rfc3339_secs("2026-09-07T18:00:00.123456+09:00"),
            Some(1788771600)
        );
    }
}
