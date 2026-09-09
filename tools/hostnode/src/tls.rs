//! rustls-backed `Dialer` for the host tool.

use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use tsnode::net::{connect_tcp, Conn, Dialer, DIAL_TIMEOUT};

pub struct HostDialer {
    tls_config: Arc<rustls::ClientConfig>,
}

impl HostDialer {
    pub fn new() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        HostDialer {
            tls_config: Arc::new(cfg),
        }
    }
}

struct TlsConn {
    inner: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
}

impl Read for TlsConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for TlsConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl Conn for TlsConn {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.sock.set_read_timeout(timeout)
    }
}

impl Dialer for HostDialer {
    fn dial_tcp(&self, host: &str, port: u16) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(connect_tcp(host, port, DIAL_TIMEOUT)?))
    }

    fn dial_tls(&self, sni: &str, addr: Option<IpAddr>, port: u16) -> io::Result<Box<dyn Conn>> {
        let tcp = match addr {
            Some(ip) => connect_tcp(&ip.to_string(), port, DIAL_TIMEOUT)?,
            None => connect_tcp(sni, port, DIAL_TIMEOUT)?,
        };
        let name = rustls::pki_types::ServerName::try_from(sni.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad sni"))?;
        let conn = rustls::ClientConnection::new(self.tls_config.clone(), name)
            .map_err(|e| io::Error::other(format!("tls: {e}")))?;
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        // Complete the handshake eagerly so later errors are I/O errors only.
        stream.sock.set_read_timeout(Some(DIAL_TIMEOUT))?;
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        Ok(Box::new(TlsConn { inner: stream }))
    }
}
