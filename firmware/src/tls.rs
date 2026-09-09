//! `tsnode::net::Dialer` for ESP-IDF: plain TCP via std, TLS via `esp_tls`
//! (mbedTLS with the built-in certificate bundle).

use esp_idf_svc::sys;
use esp_idf_svc::tls::{Config, EspTls, InternalSocket};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::time::Duration;
use tsnode::net::{connect_tcp, Conn, Dialer, DIAL_TIMEOUT};

pub struct EspDialer;

struct TlsConn {
    tls: EspTls<InternalSocket>,
}

// The connection is only ever used from one thread at a time (moved into the
// DERP/control thread that owns it); esp_tls itself has no thread affinity.
unsafe impl Send for TlsConn {}

impl TlsConn {
    fn sockfd(&mut self) -> Option<i32> {
        let mut fd: i32 = -1;
        let rc = unsafe { sys::esp_tls_get_conn_sockfd(self.tls.context_handle(), &mut fd) };
        if rc == sys::ESP_OK && fd >= 0 {
            Some(fd)
        } else {
            None
        }
    }
}

fn map_err(e: sys::EspError) -> io::Error {
    let code = e.code();
    if code == sys::ESP_TLS_ERR_SSL_WANT_READ || code == sys::ESP_TLS_ERR_SSL_WANT_WRITE {
        io::Error::new(io::ErrorKind::WouldBlock, "tls would block")
    } else if code == sys::ESP_TLS_ERR_SSL_TIMEOUT {
        io::Error::new(io::ErrorKind::TimedOut, "tls timeout")
    } else {
        io::Error::other(format!("tls error {code}"))
    }
}

impl Read for TlsConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tls.read(buf).map_err(map_err)
    }
}

impl Write for TlsConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tls.write(buf).map_err(map_err)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Conn for TlsConn {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        let Some(fd) = self.sockfd() else {
            return Err(io::Error::other("no tls socket"));
        };
        let t = timeout.unwrap_or(Duration::ZERO);
        let tv = sys::timeval {
            tv_sec: t.as_secs() as _,
            tv_usec: t.subsec_micros() as _,
        };
        let rc = unsafe {
            sys::lwip_setsockopt(
                fd,
                sys::SOL_SOCKET as i32,
                sys::SO_RCVTIMEO as i32,
                &tv as *const sys::timeval as *const core::ffi::c_void,
                core::mem::size_of::<sys::timeval>() as u32,
            )
        };
        if rc != 0 {
            return Err(io::Error::other("setsockopt SO_RCVTIMEO failed"));
        }
        Ok(())
    }
}

impl Dialer for EspDialer {
    fn dial_tcp(&self, host: &str, port: u16) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(connect_tcp(host, port, DIAL_TIMEOUT)?))
    }

    fn dial_tls(&self, sni: &str, addr: Option<IpAddr>, port: u16) -> io::Result<Box<dyn Conn>> {
        let mut tls = EspTls::new().map_err(map_err)?;
        let target = addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| sni.to_string());
        let cfg = Config {
            common_name: Some(sni),
            timeout_ms: DIAL_TIMEOUT.as_millis() as u32,
            use_global_ca_store: false,
            #[cfg(esp_idf_mbedtls_certificate_bundle)]
            use_crt_bundle_attach: true,
            ..Config::new()
        };
        tls.connect(&target, port, &cfg).map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("tls connect {sni}:{port}: {e}"),
            )
        })?;
        let mut conn = TlsConn { tls };
        let _ = conn.set_read_timeout(Some(DIAL_TIMEOUT));
        Ok(Box::new(conn))
    }
}
