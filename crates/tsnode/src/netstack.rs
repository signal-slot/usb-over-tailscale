//! A tiny userspace TCP/IP stack on top of smoltcp that terminates TCP on the
//! node's tailnet addresses. IP packets flow in from WireGuard and out to it.

use log::{debug, warn};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const RX_BUF: usize = 8 * 1024;
const TX_BUF: usize = 8 * 1024;
const USER_TX_LIMIT: usize = 32 * 1024;
/// Bytes buffered for a reader that is not keeping up; beyond this the
/// stack stops draining the socket and TCP flow control holds the sender.
const USER_RX_LIMIT: usize = 16 * 1024;
/// A peer that stops acknowledging (sleeping laptop, vanished NAT mapping)
/// is dropped after this long so the bridge becomes free again.
const DEAD_PEER_TIMEOUT: Duration = Duration::from_secs(120);
const MTU: usize = 1280;

/// Queues between the poll loop and the WireGuard side.
struct TunDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut Vec<Vec<u8>>);

impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push(buf);
        r
    }
}

impl Device for TunDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((RxTok(pkt), TxTok(&mut self.tx)))
    }
    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = MTU;
        c
    }
}

struct ConnState {
    rx: VecDeque<u8>,
    tx: VecDeque<u8>,
    peer_closed: bool,
    local_closed: bool,
    aborted: bool,
    dead: bool,
    remote: SocketAddr,
}

impl ConnState {
    fn new(remote: SocketAddr) -> Self {
        ConnState {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            peer_closed: false,
            local_closed: false,
            aborted: false,
            dead: false,
            remote,
        }
    }
}

struct ConnShared {
    m: Mutex<ConnState>,
    cv: Condvar,
}

struct ListenerShared {
    port: u16,
    queue: Mutex<VecDeque<TcpStream>>,
    cv: Condvar,
    closed: Mutex<bool>,
}

struct State {
    inbound: VecDeque<Vec<u8>>,
    addrs: Vec<IpCidr>,
    addrs_dirty: bool,
    new_listeners: Vec<Arc<ListenerShared>>,
    new_connects: Vec<(SocketAddr, Arc<ConnShared>)>,
    shutdown: bool,
    wake: bool,
}

struct Inner {
    state: Mutex<State>,
    cv: Condvar,
}

/// Handle to the stack; cheap to clone.
#[derive(Clone)]
pub struct NetStack {
    inner: Arc<Inner>,
}

impl NetStack {
    /// Starts the poll thread. `outbound` is called with every IP packet the
    /// stack wants to send (from the poll thread, without locks held).
    pub fn start(
        outbound: Box<dyn Fn(Vec<u8>) + Send + Sync>,
        stack_size: usize,
        spawner: &crate::net::Spawner,
    ) -> io::Result<NetStack> {
        let inner = Arc::new(Inner {
            state: Mutex::new(State {
                inbound: VecDeque::new(),
                addrs: Vec::new(),
                addrs_dirty: false,
                new_listeners: Vec::new(),
                new_connects: Vec::new(),
                shutdown: false,
                wake: false,
            }),
            cv: Condvar::new(),
        });
        let ns = NetStack {
            inner: inner.clone(),
        };
        spawner(
            "netstack",
            stack_size,
            Box::new(move || poll_loop(inner, outbound)),
        )?;
        Ok(ns)
    }

    /// Sets the node's tailnet addresses (with their on-link prefixes).
    pub fn set_addresses(&self, addrs: Vec<(IpAddr, u8)>) {
        let mut st = self.inner.state.lock().unwrap();
        st.addrs = addrs
            .into_iter()
            .map(|(ip, prefix)| match ip {
                IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(v4), prefix),
                IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(v6), prefix),
            })
            .collect();
        st.addrs_dirty = true;
        st.wake = true;
        self.inner.cv.notify_all();
    }

    /// Delivers an IP packet received from a peer.
    pub fn inject(&self, pkt: Vec<u8>) {
        let mut st = self.inner.state.lock().unwrap();
        if st.inbound.len() < 256 {
            st.inbound.push_back(pkt);
        }
        st.wake = true;
        self.inner.cv.notify_all();
    }

    pub fn listen(&self, port: u16) -> TcpListener {
        let shared = Arc::new(ListenerShared {
            port,
            queue: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            closed: Mutex::new(false),
        });
        let mut st = self.inner.state.lock().unwrap();
        st.new_listeners.push(shared.clone());
        st.wake = true;
        self.inner.cv.notify_all();
        TcpListener {
            shared,
            stack: self.clone(),
        }
    }

    /// Active open to `remote`. Data written before the handshake completes is queued.
    pub fn connect(&self, remote: SocketAddr) -> TcpStream {
        let shared = Arc::new(ConnShared {
            m: Mutex::new(ConnState::new(remote)),
            cv: Condvar::new(),
        });
        let mut st = self.inner.state.lock().unwrap();
        st.new_connects.push((remote, shared.clone()));
        st.wake = true;
        self.inner.cv.notify_all();
        TcpStream {
            shared,
            stack: self.clone(),
        }
    }

    pub fn shutdown(&self) {
        let mut st = self.inner.state.lock().unwrap();
        st.shutdown = true;
        st.wake = true;
        self.inner.cv.notify_all();
    }

    fn wake(&self) {
        let mut st = self.inner.state.lock().unwrap();
        st.wake = true;
        self.inner.cv.notify_all();
    }
}

pub struct TcpListener {
    shared: Arc<ListenerShared>,
    stack: NetStack,
}

impl TcpListener {
    pub fn port(&self) -> u16 {
        self.shared.port
    }

    /// Waits up to `timeout` for a new connection.
    pub fn accept(&self, timeout: Duration) -> Option<TcpStream> {
        let mut q = self.shared.queue.lock().unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(c) = q.pop_front() {
                return Some(c);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            q = self.shared.cv.wait_timeout(q, deadline - now).unwrap().0;
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        *self.shared.closed.lock().unwrap() = true;
        self.stack.wake();
    }
}

pub struct TcpStream {
    shared: Arc<ConnShared>,
    stack: NetStack,
}

impl TcpStream {
    pub fn peer_addr(&self) -> SocketAddr {
        self.shared.m.lock().unwrap().remote
    }

    /// Reads available bytes. Returns `Ok(0)` once the peer has closed and the
    /// buffer is drained; `TimedOut` if nothing arrived within `timeout`.
    pub fn read(&self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let mut st = self.shared.m.lock().unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            if !st.rx.is_empty() {
                let n = buf.len().min(st.rx.len());
                for (i, b) in st.rx.drain(..n).enumerate() {
                    buf[i] = b;
                }
                let was_full = st.rx.len() + n >= USER_RX_LIMIT;
                drop(st);
                if was_full {
                    // Room again: let the poll loop drain the socket.
                    self.stack.wake();
                }
                return Ok(n);
            }
            if st.peer_closed || st.dead {
                return Ok(0);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "read timeout"));
            }
            st = self.shared.cv.wait_timeout(st, deadline - now).unwrap().0;
        }
    }

    /// Queues `data` for sending; blocks while the send queue is full.
    pub fn write_all(&self, data: &[u8]) -> io::Result<()> {
        let mut st = self.shared.m.lock().unwrap();
        let mut offset = 0;
        while offset < data.len() {
            if st.dead || st.local_closed {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed",
                ));
            }
            let room = USER_TX_LIMIT.saturating_sub(st.tx.len());
            if room == 0 {
                st = self
                    .shared
                    .cv
                    .wait_timeout(st, Duration::from_millis(200))
                    .unwrap()
                    .0;
                continue;
            }
            let n = room.min(data.len() - offset);
            st.tx.extend(&data[offset..offset + n]);
            offset += n;
            drop(st);
            self.stack.wake();
            st = self.shared.m.lock().unwrap();
        }
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        let st = self.shared.m.lock().unwrap();
        st.dead || st.peer_closed
    }

    /// Graceful close after pending data is sent.
    pub fn close(&self) {
        self.shared.m.lock().unwrap().local_closed = true;
        self.stack.wake();
    }

    pub fn abort(&self) {
        let mut st = self.shared.m.lock().unwrap();
        st.aborted = true;
        st.local_closed = true;
        drop(st);
        self.stack.wake();
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.close();
    }
}

struct ConnEntry {
    handle: SocketHandle,
    shared: Arc<ConnShared>,
}

struct ListenerEntry {
    shared: Arc<ListenerShared>,
    handle: SocketHandle,
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    let mut s = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; RX_BUF]),
        tcp::SocketBuffer::new(vec![0; TX_BUF]),
    );
    s.set_nagle_enabled(false);
    s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
    s.set_timeout(Some(smoltcp::time::Duration::from_secs(
        DEAD_PEER_TIMEOUT.as_secs(),
    )));
    s
}

fn endpoint_to_std(ep: IpEndpoint) -> SocketAddr {
    let ip = match ep.addr {
        IpAddress::Ipv4(a) => IpAddr::V4(a),
        IpAddress::Ipv6(a) => IpAddr::V6(a),
    };
    SocketAddr::new(ip, ep.port)
}

fn poll_loop(inner: Arc<Inner>, outbound: Box<dyn Fn(Vec<u8>) + Send + Sync>) {
    let mut device = TunDevice {
        rx: VecDeque::new(),
        tx: Vec::new(),
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = u64::from_le_bytes(crate::crypto::random_array());
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    let mut sockets = SocketSet::new(vec![]);
    let mut listeners: Vec<ListenerEntry> = Vec::new();
    let mut conns: Vec<ConnEntry> = Vec::new();

    loop {
        // Pull work from the shared state.
        {
            let mut st = inner.state.lock().unwrap();
            if st.shutdown {
                break;
            }
            st.wake = false;
            while let Some(p) = st.inbound.pop_front() {
                device.rx.push_back(p);
            }
            if st.addrs_dirty {
                st.addrs_dirty = false;
                let addrs = st.addrs.clone();
                iface.update_ip_addrs(|a| {
                    a.clear();
                    for cidr in addrs.iter().take(a.capacity()) {
                        let _ = a.push(*cidr);
                    }
                });
                for cidr in &addrs {
                    match cidr.address() {
                        IpAddress::Ipv4(v4) => {
                            let _ = iface.routes_mut().add_default_ipv4_route(v4);
                        }
                        IpAddress::Ipv6(v6) => {
                            let _ = iface.routes_mut().add_default_ipv6_route(v6);
                        }
                    }
                }
                debug!("netstack: addresses {:?}", addrs);
            }
            for l in st.new_listeners.drain(..) {
                let mut s = new_tcp_socket();
                if let Err(e) = s.listen(IpListenEndpoint {
                    addr: None,
                    port: l.port,
                }) {
                    warn!("netstack: listen on {} failed: {e:?}", l.port);
                    continue;
                }
                let handle = sockets.add(s);
                listeners.push(ListenerEntry { shared: l, handle });
            }
            let connects = std::mem::take(&mut st.new_connects);
            drop(st);
            for (remote, shared) in connects {
                let mut s = new_tcp_socket();
                let local_port =
                    49152 + (u16::from_le_bytes(crate::crypto::random_array()) % 16000);
                let remote_ep = IpEndpoint::new(
                    match remote.ip() {
                        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
                        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
                    },
                    remote.port(),
                );
                match s.connect(iface.context(), remote_ep, local_port) {
                    Ok(()) => {
                        let handle = sockets.add(s);
                        conns.push(ConnEntry { handle, shared });
                    }
                    Err(e) => {
                        warn!("netstack: connect to {remote} failed: {e:?}");
                        let mut c = shared.m.lock().unwrap();
                        c.dead = true;
                        shared.cv.notify_all();
                    }
                }
            }
        }

        let now = SmolInstant::now();
        let _ = iface.poll(now, &mut device, &mut sockets);

        // Listeners: a socket that left the LISTEN state has a connection.
        let mut i = 0;
        while i < listeners.len() {
            let closed = *listeners[i].shared.closed.lock().unwrap();
            let sock = sockets.get_mut::<tcp::Socket>(listeners[i].handle);
            if closed {
                sock.abort();
                sockets.remove(listeners[i].handle);
                listeners.remove(i);
                continue;
            }
            match sock.state() {
                tcp::State::Listen => {}
                tcp::State::Closed => {
                    let _ = sock.listen(IpListenEndpoint {
                        addr: None,
                        port: listeners[i].shared.port,
                    });
                }
                _ => {
                    let remote = sock
                        .remote_endpoint()
                        .map(endpoint_to_std)
                        .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
                    let shared = Arc::new(ConnShared {
                        m: Mutex::new(ConnState::new(remote)),
                        cv: Condvar::new(),
                    });
                    conns.push(ConnEntry {
                        handle: listeners[i].handle,
                        shared: shared.clone(),
                    });
                    let stream = TcpStream {
                        shared,
                        stack: NetStack {
                            inner: inner.clone(),
                        },
                    };
                    {
                        let mut q = listeners[i].shared.queue.lock().unwrap();
                        q.push_back(stream);
                        listeners[i].shared.cv.notify_all();
                    }
                    // Replace the listening socket.
                    let mut s = new_tcp_socket();
                    let _ = s.listen(IpListenEndpoint {
                        addr: None,
                        port: listeners[i].shared.port,
                    });
                    listeners[i].handle = sockets.add(s);
                }
            }
            i += 1;
        }

        // Connections.
        let mut i = 0;
        while i < conns.len() {
            let sock = sockets.get_mut::<tcp::Socket>(conns[i].handle);
            let shared = &conns[i].shared;
            let mut st = shared.m.lock().unwrap();
            let mut changed = false;
            let mut buf = [0u8; 1024];
            while sock.can_recv() && st.rx.len() < USER_RX_LIMIT {
                match sock.recv_slice(&mut buf) {
                    Ok(n) if n > 0 => {
                        st.rx.extend(&buf[..n]);
                        changed = true;
                    }
                    _ => break,
                }
            }
            while sock.can_send() && !st.tx.is_empty() {
                let (a, _) = st.tx.as_slices();
                let chunk_len = a.len().min(1024);
                match sock.send_slice(&a[..chunk_len]) {
                    Ok(n) if n > 0 => {
                        st.tx.drain(..n);
                        changed = true;
                    }
                    _ => break,
                }
            }
            if st.aborted {
                sock.abort();
            } else if st.local_closed && st.tx.is_empty() && sock.is_open() {
                sock.close();
            }
            let connecting = matches!(sock.state(), tcp::State::SynSent | tcp::State::SynReceived);
            if !sock.may_recv() && !st.peer_closed && !connecting {
                st.peer_closed = true;
                changed = true;
            }
            let dead = matches!(sock.state(), tcp::State::Closed | tcp::State::TimeWait);
            if dead {
                st.dead = true;
                st.peer_closed = true;
                changed = true;
            }
            if changed {
                shared.cv.notify_all();
            }
            drop(st);
            if dead {
                sockets.remove(conns[i].handle);
                conns.remove(i);
                continue;
            }
            i += 1;
        }

        for pkt in device.tx.drain(..) {
            outbound(pkt);
        }

        let delay = iface
            .poll_delay(now, &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_millis(500))
            .min(Duration::from_millis(500));
        let st = inner.state.lock().unwrap();
        if !st.wake && !st.shutdown {
            let _ = inner.cv.wait_timeout(st, delay).unwrap();
        }
    }
    debug!("netstack: stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two stacks wired back to back: whatever A sends, B receives and vice versa.
    #[test]
    fn tcp_over_two_stacks() {
        let a_ref: Arc<Mutex<Option<NetStack>>> = Arc::new(Mutex::new(None));
        let b_ref: Arc<Mutex<Option<NetStack>>> = Arc::new(Mutex::new(None));
        let (b_for_a, a_for_b) = (b_ref.clone(), a_ref.clone());
        let a = NetStack::start(
            Box::new(move |p| {
                if let Some(b) = b_for_a.lock().unwrap().as_ref() {
                    b.inject(p)
                }
            }),
            256 * 1024,
            &crate::net::std_spawner(),
        )
        .unwrap();
        let b = NetStack::start(
            Box::new(move |p| {
                if let Some(a) = a_for_b.lock().unwrap().as_ref() {
                    a.inject(p)
                }
            }),
            256 * 1024,
            &crate::net::std_spawner(),
        )
        .unwrap();
        *a_ref.lock().unwrap() = Some(a.clone());
        *b_ref.lock().unwrap() = Some(b.clone());
        a.set_addresses(vec![("100.64.0.1".parse().unwrap(), 10)]);
        b.set_addresses(vec![("100.64.0.2".parse().unwrap(), 10)]);

        let listener = b.listen(2300);
        let client = a.connect("100.64.0.2:2300".parse().unwrap());
        let server = listener.accept(Duration::from_secs(5)).expect("accept");
        assert_eq!(
            server.peer_addr().ip(),
            "100.64.0.1".parse::<IpAddr>().unwrap()
        );

        client.write_all(b"hello over smoltcp").unwrap();
        let mut buf = [0u8; 64];
        let n = server.read(&mut buf, Duration::from_secs(5)).unwrap();
        assert_eq!(&buf[..n], b"hello over smoltcp");

        let big: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        server.write_all(&big).unwrap();
        let mut got = Vec::new();
        while got.len() < big.len() {
            let n = client.read(&mut buf, Duration::from_secs(5)).unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, big);

        client.close();
        let n = server.read(&mut buf, Duration::from_secs(5)).unwrap();
        assert_eq!(n, 0);
        a.shutdown();
        b.shutdown();
    }
}
