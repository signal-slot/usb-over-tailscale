//! Tailscale control-plane client (`/key`, `/machine/register`, `/machine/map`)
//! over the ts2021 Noise transport.

use crate::controlbase;
use crate::h2::H2Conn;
use crate::http1;
use crate::keys::{fmt_machine_pub, parse_prefixed, KeyPair, MACHINE_PUB_PREFIX};
use crate::net::{Conn, Dialer};
use crate::types::*;
use log::{debug, info, warn};
use serde::Deserialize;
use std::io;
use std::sync::Arc;
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The map stream sends keep-alives roughly every minute; give it slack.
const MAP_STREAM_TIMEOUT: Duration = Duration::from_secs(150);

#[derive(Debug, Clone)]
pub struct ControlUrl {
    pub https: bool,
    pub host: String,
    pub port: Option<u16>,
}

impl ControlUrl {
    pub fn parse(url: &str) -> io::Result<Self> {
        let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control url must start with http:// or https://",
            ));
        };
        let hostport = rest.split('/').next().unwrap_or("");
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if !h.contains(']') || h.ends_with(']') => (
                h.trim_matches(|c| c == '[' || c == ']').to_string(),
                p.parse::<u16>().ok(),
            ),
            _ => (hostport.to_string(), None),
        };
        if host.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control url has no host",
            ));
        }
        Ok(ControlUrl { https, host, port })
    }

    fn api_port(&self) -> u16 {
        self.port.unwrap_or(if self.https { 443 } else { 80 })
    }

    /// Host header / HTTP/2 authority value.
    pub fn authority(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => self.host.clone(),
        }
    }
}

#[derive(Deserialize)]
struct KeyResponse {
    #[serde(rename = "publicKey", default)]
    public_key: String,
}

pub struct ControlClient {
    dialer: Arc<dyn Dialer>,
    url: ControlUrl,
    control_pub: [u8; 32],
    machine: KeyPair,
}

impl ControlClient {
    /// Fetches the server's Noise public key and prepares a client.
    pub fn connect(
        dialer: Arc<dyn Dialer>,
        control_url: &str,
        machine: KeyPair,
    ) -> io::Result<Self> {
        let url = ControlUrl::parse(control_url)?;
        let control_pub = fetch_server_key(dialer.as_ref(), &url)?;
        info!(
            "control: server key {}",
            &fmt_machine_pub(&control_pub)[..21]
        );
        Ok(ControlClient {
            dialer,
            url,
            control_pub,
            machine,
        })
    }

    pub fn url(&self) -> &ControlUrl {
        &self.url
    }

    /// Opens a ts2021 connection and sets up HTTP/2 on it.
    fn dial(&self) -> io::Result<H2Conn> {
        let conn = self.dial_transport()?;
        let mut noise = controlbase::dial(
            conn,
            &self.url.authority(),
            self.machine.secret(),
            &self.control_pub,
            CAPABILITY_VERSION,
        )?;
        debug!("control: noise handshake complete");
        // The server may send an "early payload" (a node-key challenge) before
        // HTTP/2 starts: magic "\xff\xff\xffTS" + u32 BE length + JSON.
        let mut hdr = [0u8; 9];
        noise.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        std::io::Read::read_exact(&mut noise, &mut hdr)?;
        let prefix = if &hdr[..5] == b"\xff\xff\xffTS" {
            let len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
            if len > 1 << 20 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "early payload too large",
                ));
            }
            let mut payload = vec![0u8; len];
            std::io::Read::read_exact(&mut noise, &mut payload)?;
            debug!(
                "control: early payload {}",
                String::from_utf8_lossy(&payload)
            );
            Vec::new()
        } else {
            hdr.to_vec()
        };
        H2Conn::with_prefix(Box::new(noise), &self.url.authority(), prefix)
    }

    fn dial_transport(&self) -> io::Result<Box<dyn Conn>> {
        // The official control plane accepts the Noise upgrade on plain :80 as
        // well as behind TLS on :443. Prefer :80 (no TLS cost on the device) and
        // fall back to TLS on the API port.
        if self.url.https && self.url.port.is_none() {
            match self.dialer.dial_tcp(&self.url.host, 80) {
                Ok(c) => return Ok(c),
                Err(e) => warn!("control: plain :80 dial failed ({e}); trying TLS"),
            }
        }
        if self.url.https {
            self.dialer
                .dial_tls(&self.url.host, None, self.url.api_port())
        } else {
            self.dialer.dial_tcp(&self.url.host, self.url.api_port())
        }
    }

    fn post_json<T: serde::Serialize>(
        &self,
        h2: &mut H2Conn,
        path: &str,
        body: &T,
    ) -> io::Result<u32> {
        let json = serde_json::to_vec(body)?;
        h2.request("POST", path, &[("content-type", "application/json")], &json)
    }

    pub fn register(&self, req: &RegisterRequest) -> io::Result<RegisterResponse> {
        let mut h2 = self.dial()?;
        let id = self.post_json(&mut h2, "/machine/register", req)?;
        let status = h2.response_status(id, REQUEST_TIMEOUT)?;
        let body = h2.read_full_body(id, REQUEST_TIMEOUT, 1 << 20)?;
        if status != 200 {
            return Err(io::Error::other(format!(
                "register: HTTP {status}: {}",
                String::from_utf8_lossy(&body[..body.len().min(300)])
            )));
        }
        let resp: RegisterResponse = serde_json::from_slice(&body).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("register: bad json: {e}"),
            )
        })?;
        Ok(resp)
    }

    /// Starts a long-poll map stream (`Stream: true`).
    pub fn map_stream(&self, req: &MapRequest) -> io::Result<MapStream> {
        let mut h2 = self.dial()?;
        let id = self.post_json(&mut h2, "/machine/map", req)?;
        let status = h2.response_status(id, REQUEST_TIMEOUT)?;
        if status != 200 {
            let body = h2
                .read_full_body(id, REQUEST_TIMEOUT, 65536)
                .unwrap_or_default();
            return Err(io::Error::other(format!(
                "map: HTTP {status}: {}",
                String::from_utf8_lossy(&body[..body.len().min(300)])
            )));
        }
        Ok(MapStream {
            h2,
            id,
            buf: Vec::new(),
            done: false,
        })
    }

    /// A single non-streaming map request, used to push endpoint updates.
    pub fn map_once(&self, req: &MapRequest) -> io::Result<MapResponse> {
        let mut req = req.clone();
        req.stream = false;
        let mut stream = self.map_stream(&req)?;
        match stream.next(REQUEST_TIMEOUT)? {
            Some(r) => Ok(r),
            // A lite (OmitPeers) update is answered with an empty body.
            None => Ok(MapResponse::default()),
        }
    }
}

/// Fetches the control server's Noise public key from `/key`.
pub fn fetch_server_key(dialer: &dyn Dialer, url: &ControlUrl) -> io::Result<[u8; 32]> {
    let mut conn = if url.https {
        dialer.dial_tls(&url.host, None, url.api_port())?
    } else {
        dialer.dial_tcp(&url.host, url.api_port())?
    };
    conn.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    let path = format!("/key?v={CAPABILITY_VERSION}");
    let host = url.authority();
    http1::write_request(
        conn.as_mut(),
        "GET",
        &path,
        &host,
        &[("Connection", "close"), ("Accept", "application/json")],
    )?;
    let head = http1::read_response_head(conn.as_mut())?;
    let body = http1::read_body(conn.as_mut(), &head, 65536)?;
    if head.status != 200 {
        return Err(io::Error::other(format!("/key: HTTP {}", head.status)));
    }
    let kr: KeyResponse = serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("/key: bad json: {e}")))?;
    parse_prefixed(MACHINE_PUB_PREFIX, &kr.public_key)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "/key: missing publicKey"))
}

/// A streaming `/machine/map` response: a sequence of little-endian
/// length-prefixed JSON messages.
pub struct MapStream {
    h2: H2Conn,
    id: u32,
    buf: Vec<u8>,
    done: bool,
}

impl MapStream {
    /// Returns the next `MapResponse`, `Ok(None)` when the server ends the
    /// stream. Blocks up to `timeout` (or the built-in keep-alive timeout).
    pub fn next(&mut self, timeout: Duration) -> io::Result<Option<MapResponse>> {
        let timeout = timeout.min(MAP_STREAM_TIMEOUT);
        loop {
            if let Some(msg) = self.take_message()? {
                return Ok(Some(msg));
            }
            if self.done {
                return Ok(None);
            }
            match self.h2.read_body(self.id, timeout)? {
                Some(chunk) => self.buf.extend_from_slice(&chunk),
                None => self.done = true,
            }
        }
    }

    fn take_message(&mut self) -> io::Result<Option<MapResponse>> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        // Every message is `u32 LE length` + JSON, streaming or not.
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > 8 << 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "map message too large",
            ));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let msg = decode_map(&self.buf[4..4 + len])?;
        self.buf.drain(..4 + len);
        Ok(Some(msg))
    }
}

fn decode_map(bytes: &[u8]) -> io::Result<MapResponse> {
    serde_json::from_slice(bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("map: bad json: {e}")))
}

/// Builds the `Hostinfo` we advertise.
pub fn hostinfo(hostname: &str, version: &str, preferred_derp: i32) -> Hostinfo {
    Hostinfo {
        ipn_version: format!("tsnode-{version}"),
        os: "linux".into(),
        os_version: "esp-idf".into(),
        distro: "esp-idf".into(),
        device_model: "ESP32-S3".into(),
        hostname: hostname.into(),
        go_arch: "xtensa".into(),
        machine: "esp32s3".into(),
        userspace: true,
        net_info: if preferred_derp != 0 {
            Some(NetInfo {
                preferred_derp,
                working_udp: Some(true),
                link_type: "wifi".into(),
                ..Default::default()
            })
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_control_urls() {
        let u = ControlUrl::parse("https://controlplane.tailscale.com").unwrap();
        assert!(u.https);
        assert_eq!(u.host, "controlplane.tailscale.com");
        assert_eq!(u.port, None);
        assert_eq!(u.authority(), "controlplane.tailscale.com");
        let u = ControlUrl::parse("http://headscale.local:8080/").unwrap();
        assert!(!u.https);
        assert_eq!(u.port, Some(8080));
        assert_eq!(u.authority(), "headscale.local:8080");
    }
}
