//! Transport abstraction. The library only needs blocking byte streams with a
//! read timeout; the host binary supplies rustls-backed TLS and the ESP32
//! firmware supplies `esp_tls`.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// A blocking, timeout-capable byte stream.
pub trait Conn: Read + Write + Send {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Conn for TcpStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

/// Opens outbound TCP and TLS connections.
pub trait Dialer: Send + Sync {
    /// Plain TCP. `host` may be a DNS name or an IP literal.
    fn dial_tcp(&self, host: &str, port: u16) -> io::Result<Box<dyn Conn>>;

    /// TLS with SNI/certificate name `sni`, connecting to `addr` if given
    /// (DERP nodes publish both a host name and fixed IPs), else to `sni`.
    fn dial_tls(&self, sni: &str, addr: Option<IpAddr>, port: u16) -> io::Result<Box<dyn Conn>>;
}

pub const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Resolves `host:port` and connects with a timeout, trying IPv4 first.
pub fn connect_tcp(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    addrs.sort_by_key(|a| a.is_ipv6());
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no addresses");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                let _ = s.set_write_timeout(Some(timeout));
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

pub fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Spawns a named thread with the given stack size. Embedded ports use this to
/// choose where stacks live (e.g. PSRAM for network threads on ESP32).
pub type Spawner =
    Arc<dyn Fn(&str, usize, Box<dyn FnOnce() + Send>) -> io::Result<()> + Send + Sync>;

/// Plain `std::thread` spawner.
pub fn std_spawner() -> Spawner {
    Arc::new(|name: &str, stack: usize, f: Box<dyn FnOnce() + Send>| {
        std::thread::Builder::new()
            .name(name.to_string())
            .stack_size(stack)
            .spawn(f)
            .map(|_| ())
    })
}
