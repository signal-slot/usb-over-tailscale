//! DERP relay client (Tailscale's TLS-tunnelled packet relay).

use crate::crypto::{nacl_box_open, nacl_box_seal, random_array};
use crate::http1;
use crate::keys::{short, KeyPair};
use crate::net::{is_timeout, Conn, Dialer};
use crate::types::DerpNode;
use log::{debug, warn};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 8-byte magic: "DERP🔑".
pub const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
pub const PROTOCOL_VERSION: i64 = 2;
pub const MAX_PACKET: usize = 64 << 10;
const FRAME_HEADER_LEN: usize = 5;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_NOTE_PREFERRED: u8 = 0x07;
const FRAME_PEER_GONE: u8 = 0x08;
const FRAME_PEER_PRESENT: u8 = 0x09;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;
const FRAME_HEALTH: u8 = 0x14;
const FRAME_RESTARTING: u8 = 0x15;

#[derive(Debug)]
pub enum Event {
    Packet { src: [u8; 32], data: Vec<u8> },
    PeerGone([u8; 32]),
    Health(String),
    Restarting,
    Pong([u8; 8]),
}

pub struct DerpClient {
    conn: Box<dyn Conn>,
    inbuf: Vec<u8>,
    region_id: i32,
    pub server_key: [u8; 32],
    pub last_activity: Instant,
    pub last_ping_sent: Option<Instant>,
}

impl DerpClient {
    /// Connects to `node` (TLS to its IPv4 address if given, else its host name),
    /// performs the DERP handshake with our node key and returns the client.
    pub fn connect(
        dialer: &dyn Dialer,
        node: &DerpNode,
        region_id: i32,
        node_key: &KeyPair,
    ) -> io::Result<Self> {
        let port = if node.derp_port > 0 {
            node.derp_port as u16
        } else {
            443
        };
        let addr: Option<IpAddr> = node.ipv4.parse().ok();
        let host = node.host_name.clone();
        let mut conn = if node.insecure_for_tests {
            dialer.dial_tcp(
                addr.map(|a| a.to_string()).as_deref().unwrap_or(&host),
                port,
            )?
        } else {
            dialer.dial_tls(&host, addr, port)?
        };
        conn.set_read_timeout(Some(Duration::from_secs(15)))?;
        http1::write_request(
            conn.as_mut(),
            "GET",
            "/derp",
            &host,
            &[
                ("Upgrade", "DERP"),
                ("Connection", "Upgrade"),
                ("Derp-Fast-Start", "1"),
            ],
        )?;

        let mut client = DerpClient {
            conn,
            inbuf: Vec::with_capacity(4096),
            region_id,
            server_key: [0; 32],
            last_activity: Instant::now(),
            last_ping_sent: None,
        };
        // Without fast-start support the server answers with an HTTP head first.
        client.fill(Duration::from_secs(15))?;
        if client.inbuf.starts_with(b"HTTP/") {
            let mut cursor = io::Cursor::new(std::mem::take(&mut client.inbuf));
            let head = http1::read_response_head(&mut PrefixReader {
                cursor: &mut cursor,
                conn: client.conn.as_mut(),
            })?;
            if head.status != 101 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("derp upgrade failed: HTTP {}", head.status),
                ));
            }
            client.inbuf = head.leftover;
        }

        // ServerKey frame.
        let (t, payload) = client
            .read_frame(Duration::from_secs(15))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "derp: no server key"))?;
        if t != FRAME_SERVER_KEY
            || payload.len() < MAGIC.len() + KEY_LEN
            || &payload[..MAGIC.len()] != MAGIC
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "derp: bad server greeting",
            ));
        }
        client
            .server_key
            .copy_from_slice(&payload[MAGIC.len()..MAGIC.len() + KEY_LEN]);

        // ClientInfo frame: our public key + nonce + box(json).
        let info = format!("{{\"version\":{PROTOCOL_VERSION}}}");
        let nonce: [u8; NONCE_LEN] = random_array();
        let sealed = nacl_box_seal(
            node_key.secret(),
            &client.server_key,
            &nonce,
            info.as_bytes(),
        );
        let mut body = Vec::with_capacity(KEY_LEN + NONCE_LEN + sealed.len());
        body.extend_from_slice(node_key.public());
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&sealed);
        client.write_frame(FRAME_CLIENT_INFO, &body)?;

        // ServerInfo frame.
        let (t, payload) = client
            .read_frame(Duration::from_secs(15))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "derp: no server info"))?;
        if t != FRAME_SERVER_INFO || payload.len() < NONCE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "derp: bad server info",
            ));
        }
        let nonce: [u8; NONCE_LEN] = payload[..NONCE_LEN].try_into().unwrap();
        let sk = client.server_key;
        let info =
            nacl_box_open(node_key.secret(), &sk, &nonce, &payload[NONCE_LEN..]).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "derp: server info authentication failed",
                )
            })?;
        debug!(
            "derp[{}]: connected to {} ({}), server info {}",
            region_id,
            host,
            short(&sk),
            String::from_utf8_lossy(&info)
        );
        client.last_activity = Instant::now();
        Ok(client)
    }

    pub fn region_id(&self) -> i32 {
        self.region_id
    }

    fn write_frame(&mut self, t: u8, payload: &[u8]) -> io::Result<()> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        out.push(t);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        self.conn.write_all(&out)?;
        self.conn.flush()
    }

    pub fn send_packet(&mut self, dst: &[u8; 32], pkt: &[u8]) -> io::Result<()> {
        if pkt.len() > MAX_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "derp: packet too big",
            ));
        }
        let mut body = Vec::with_capacity(KEY_LEN + pkt.len());
        body.extend_from_slice(dst);
        body.extend_from_slice(pkt);
        self.write_frame(FRAME_SEND_PACKET, &body)
    }

    pub fn note_preferred(&mut self, preferred: bool) -> io::Result<()> {
        self.write_frame(FRAME_NOTE_PREFERRED, &[preferred as u8])
    }

    pub fn ping(&mut self) -> io::Result<[u8; 8]> {
        let data: [u8; 8] = random_array();
        self.write_frame(FRAME_PING, &data)?;
        self.last_ping_sent = Some(Instant::now());
        Ok(data)
    }

    /// Reads more bytes into the buffer, blocking up to `timeout`. Returns
    /// `Ok(false)` on timeout.
    fn fill(&mut self, timeout: Duration) -> io::Result<bool> {
        self.conn
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        let mut tmp = [0u8; 4096];
        match self.conn.read(&mut tmp) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "derp: connection closed",
            )),
            Ok(n) => {
                self.inbuf.extend_from_slice(&tmp[..n]);
                Ok(true)
            }
            Err(e) if is_timeout(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn take_frame(&mut self) -> io::Result<Option<(u8, Vec<u8>)>> {
        if self.inbuf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let t = self.inbuf[0];
        let len = u32::from_be_bytes([self.inbuf[1], self.inbuf[2], self.inbuf[3], self.inbuf[4]])
            as usize;
        if len > MAX_PACKET + KEY_LEN + 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "derp: frame too large",
            ));
        }
        if self.inbuf.len() < FRAME_HEADER_LEN + len {
            return Ok(None);
        }
        let payload = self.inbuf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len].to_vec();
        self.inbuf.drain(..FRAME_HEADER_LEN + len);
        Ok(Some((t, payload)))
    }

    fn read_frame(&mut self, timeout: Duration) -> io::Result<Option<(u8, Vec<u8>)>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(f) = self.take_frame()? {
                return Ok(Some(f));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            if !self.fill(deadline - now)? {
                return Ok(None);
            }
        }
    }

    /// Waits up to `timeout` for the next event. Keep-alives and pings are
    /// handled internally and yield `Ok(None)` like a timeout does.
    pub fn recv(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
        let Some((t, payload)) = self.read_frame(timeout)? else {
            return Ok(None);
        };
        self.last_activity = Instant::now();
        match t {
            FRAME_RECV_PACKET => {
                if payload.len() < KEY_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "derp: short recv packet",
                    ));
                }
                let src: [u8; 32] = payload[..KEY_LEN].try_into().unwrap();
                Ok(Some(Event::Packet {
                    src,
                    data: payload[KEY_LEN..].to_vec(),
                }))
            }
            FRAME_KEEP_ALIVE => Ok(None),
            FRAME_PING => {
                if payload.len() == 8 {
                    self.write_frame(FRAME_PONG, &payload)?;
                }
                Ok(None)
            }
            FRAME_PONG => {
                let mut d = [0u8; 8];
                if payload.len() == 8 {
                    d.copy_from_slice(&payload);
                }
                Ok(Some(Event::Pong(d)))
            }
            FRAME_PEER_GONE => {
                if payload.len() >= KEY_LEN {
                    Ok(Some(Event::PeerGone(
                        payload[..KEY_LEN].try_into().unwrap(),
                    )))
                } else {
                    Ok(None)
                }
            }
            FRAME_PEER_PRESENT => Ok(None),
            FRAME_HEALTH => Ok(Some(Event::Health(
                String::from_utf8_lossy(&payload).to_string(),
            ))),
            FRAME_RESTARTING => Ok(Some(Event::Restarting)),
            other => {
                warn!("derp[{}]: unknown frame type {other:#x}", self.region_id);
                Ok(None)
            }
        }
    }
}

/// Reads from an in-memory prefix first, then from the connection.
struct PrefixReader<'a> {
    cursor: &'a mut io::Cursor<Vec<u8>>,
    conn: &'a mut dyn Conn,
}

impl Read for PrefixReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.cursor.read(buf)?;
        if n > 0 {
            return Ok(n);
        }
        self.conn.read(buf)
    }
}
