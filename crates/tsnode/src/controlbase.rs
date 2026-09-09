//! Tailscale's ts2021 control transport: a Noise IK handshake carried in an
//! HTTP/1.1 `Upgrade: tailscale-control-protocol` request, followed by
//! length-prefixed encrypted records over which HTTP/2 is spoken.

use crate::crypto::{aead_decrypt, aead_encrypt, x25519_generate, x25519_public, TAG_LEN};
use crate::http1;
use crate::net::Conn;
use crate::noise::SymmetricState;
use base64::Engine as _;
use std::io::{self, Read, Write};
use std::time::Duration;

pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_PREFIX: &str = "Tailscale Control Protocol v";
pub const UPGRADE_VALUE: &str = "tailscale-control-protocol";
pub const HANDSHAKE_HEADER: &str = "X-Tailscale-Handshake";
pub const UPGRADE_PATH: &str = "/ts2021";

const MSG_INITIATION: u8 = 1;
const MSG_RESPONSE: u8 = 2;
const MSG_ERROR: u8 = 3;
const MSG_RECORD: u8 = 4;
const HEADER_LEN: usize = 3;
/// Initiation frames carry a 2-byte protocol version before the usual header.
const INITIATION_HEADER_LEN: usize = 5;
const INITIATION_LEN: usize = 101;
const RESPONSE_LEN: usize = 51;
/// Maximum frame size on the wire including the 3-byte header.
const MAX_MESSAGE: usize = 4096;
const MAX_CIPHERTEXT: usize = MAX_MESSAGE - HEADER_LEN;
pub const MAX_PLAINTEXT: usize = MAX_CIPHERTEXT - TAG_LEN;

/// The control transport counts record nonces big-endian (unlike WireGuard).
fn be_nonce_key(counter: u64) -> u64 {
    // aead_* take a little-endian counter; feed the byte-swapped value so the
    // resulting 8 nonce bytes are big-endian.
    counter.swap_bytes()
}

fn aead_encrypt_be(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    aead_encrypt(key, be_nonce_key(counter), plaintext, &[])
}

fn aead_decrypt_be(
    key: &[u8; 32],
    counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, crate::crypto::CryptoError> {
    aead_decrypt(key, be_nonce_key(counter), ciphertext, &[])
}

fn prologue(version: u16) -> Vec<u8> {
    format!("{PROLOGUE_PREFIX}{version}").into_bytes()
}

fn set_header(buf: &mut [u8], msg_type: u8, len: usize) {
    buf[0] = msg_type;
    buf[1..3].copy_from_slice(&(len as u16).to_be_bytes());
}

/// Client side of the handshake, split so the initiation can be sent inside
/// an HTTP header before the response bytes arrive.
pub struct ClientHandshake {
    state: SymmetricState,
    ephemeral_secret: [u8; 32],
    machine_secret: [u8; 32],
    pub initiation: [u8; INITIATION_LEN],
}

impl ClientHandshake {
    pub fn new(machine_secret: &[u8; 32], control_pub: &[u8; 32], version: u16) -> Self {
        let mut s = SymmetricState::new(PROTOCOL_NAME);
        s.mix_hash(&prologue(version));
        // <- s (pre-message: the control server's static key)
        s.mix_hash(control_pub);

        // Layout: version(2) | type(1) | payload length(2) | payload(96).
        let mut init = [0u8; INITIATION_LEN];
        init[0..2].copy_from_slice(&version.to_be_bytes());
        set_header(
            &mut init[2..5],
            MSG_INITIATION,
            INITIATION_LEN - INITIATION_HEADER_LEN,
        );

        // -> e, es, s, ss
        let ephemeral_secret = x25519_generate();
        let ephemeral_pub = x25519_public(&ephemeral_secret);
        init[5..37].copy_from_slice(&ephemeral_pub);
        s.mix_hash(&ephemeral_pub);
        s.mix_dh(&ephemeral_secret, control_pub);
        let machine_pub = x25519_public(machine_secret);
        let enc_static = s.encrypt_and_hash(&machine_pub);
        init[37..85].copy_from_slice(&enc_static);
        s.mix_dh(machine_secret, control_pub);
        let tag = s.encrypt_and_hash(&[]);
        init[85..101].copy_from_slice(&tag);

        ClientHandshake {
            state: s,
            ephemeral_secret,
            machine_secret: *machine_secret,
            initiation: init,
        }
    }

    pub fn initiation_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.initiation)
    }

    /// Consumes the 51-byte response and derives the transport keys.
    pub fn finish(mut self, response: &[u8]) -> io::Result<SessionKeys> {
        if response.len() != RESPONSE_LEN || response[0] != MSG_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bad noise response (type {})",
                    response.first().copied().unwrap_or(0)
                ),
            ));
        }
        let len = u16::from_be_bytes([response[1], response[2]]) as usize;
        if len != RESPONSE_LEN - HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad noise response length",
            ));
        }
        // <- e, ee, se
        let re: [u8; 32] = response[3..35].try_into().unwrap();
        self.state.mix_hash(&re);
        self.state.mix_dh(&self.ephemeral_secret, &re);
        self.state.mix_dh(&self.machine_secret, &re);
        self.state
            .decrypt_and_hash(&response[35..51])
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "noise response authentication failed",
                )
            })?;
        let (tx, rx) = self.state.split();
        Ok(SessionKeys { tx, rx })
    }
}

pub struct SessionKeys {
    pub tx: [u8; 32],
    pub rx: [u8; 32],
}

/// Server side of the handshake. Only used by tests and by tools; the device is
/// always the client.
pub fn server_handshake(
    control_secret: &[u8; 32],
    initiation: &[u8],
) -> io::Result<(SessionKeys, [u8; 32], Vec<u8>)> {
    if initiation.len() != INITIATION_LEN || initiation[2] != MSG_INITIATION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad initiation"));
    }
    let version = u16::from_be_bytes([initiation[0], initiation[1]]);
    let control_pub = x25519_public(control_secret);
    let mut s = SymmetricState::new(PROTOCOL_NAME);
    s.mix_hash(&prologue(version));
    s.mix_hash(&control_pub);
    let re: [u8; 32] = initiation[5..37].try_into().unwrap();
    s.mix_hash(&re);
    s.mix_dh(control_secret, &re);
    let machine_pub: [u8; 32] = s
        .decrypt_and_hash(&initiation[37..85])
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "bad static"))?
        .try_into()
        .unwrap();
    s.mix_dh(control_secret, &machine_pub);
    s.decrypt_and_hash(&initiation[85..101])
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "bad tag"))?;

    let mut resp = [0u8; RESPONSE_LEN];
    set_header(&mut resp, MSG_RESPONSE, RESPONSE_LEN - HEADER_LEN);
    let e = x25519_generate();
    let ep = x25519_public(&e);
    resp[3..35].copy_from_slice(&ep);
    s.mix_hash(&ep);
    s.mix_dh(&e, &re);
    s.mix_dh(&e, &machine_pub);
    let tag = s.encrypt_and_hash(&[]);
    resp[35..51].copy_from_slice(&tag);
    let (k_client_to_server, k_server_to_client) = s.split();
    Ok((
        SessionKeys {
            tx: k_server_to_client,
            rx: k_client_to_server,
        },
        machine_pub,
        resp.to_vec(),
    ))
}

/// An established Noise transport carrying encrypted records.
pub struct NoiseConn {
    inner: Box<dyn Conn>,
    tx_key: [u8; 32],
    tx_n: u64,
    rx_key: [u8; 32],
    rx_n: u64,
    raw_pending: Vec<u8>,
    plain_pending: Vec<u8>,
    plain_pos: usize,
}

impl NoiseConn {
    pub fn new(inner: Box<dyn Conn>, keys: SessionKeys, leftover: Vec<u8>) -> Self {
        NoiseConn {
            inner,
            tx_key: keys.tx,
            tx_n: 0,
            rx_key: keys.rx,
            rx_n: 0,
            raw_pending: leftover,
            plain_pending: Vec::new(),
            plain_pos: 0,
        }
    }

    fn read_raw_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        if !self.raw_pending.is_empty() {
            let n = self.raw_pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.raw_pending[..n]);
            self.raw_pending.drain(..n);
            filled = n;
        }
        if filled < buf.len() {
            self.inner.read_exact(&mut buf[filled..])?;
        }
        Ok(())
    }

    fn read_record(&mut self) -> io::Result<()> {
        let mut hdr = [0u8; HEADER_LEN];
        self.read_raw_exact(&mut hdr)?;
        let len = u16::from_be_bytes([hdr[1], hdr[2]]) as usize;
        if hdr[0] == MSG_ERROR {
            let mut msg = vec![0u8; len];
            self.read_raw_exact(&mut msg)?;
            return Err(io::Error::other(format!(
                "control server error: {}",
                String::from_utf8_lossy(&msg)
            )));
        }
        if hdr[0] != MSG_RECORD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected noise message type {}", hdr[0]),
            ));
        }
        if !(TAG_LEN..=MAX_CIPHERTEXT).contains(&len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short noise record",
            ));
        }
        let mut ct = vec![0u8; len];
        self.read_raw_exact(&mut ct)?;
        let pt = aead_decrypt_be(&self.rx_key, self.rx_n, &ct).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "noise record authentication failed",
            )
        })?;
        self.rx_n += 1;
        self.plain_pending = pt;
        self.plain_pos = 0;
        Ok(())
    }
}

impl Read for NoiseConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.plain_pos >= self.plain_pending.len() {
            self.read_record()?;
        }
        let avail = &self.plain_pending[self.plain_pos..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.plain_pos += n;
        Ok(n)
    }
}

impl Write for NoiseConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut out = Vec::with_capacity(buf.len() + 64);
        for chunk in buf.chunks(MAX_PLAINTEXT) {
            let ct = aead_encrypt_be(&self.tx_key, self.tx_n, chunk);
            self.tx_n += 1;
            let mut hdr = [0u8; HEADER_LEN];
            set_header(&mut hdr, MSG_RECORD, ct.len());
            out.extend_from_slice(&hdr);
            out.extend_from_slice(&ct);
        }
        self.inner.write_all(&out)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Conn for NoiseConn {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }
}

/// Runs the full client handshake over `conn` using the HTTP upgrade.
pub fn dial(
    mut conn: Box<dyn Conn>,
    host: &str,
    machine_secret: &[u8; 32],
    control_pub: &[u8; 32],
    version: u16,
) -> io::Result<NoiseConn> {
    let hs = ClientHandshake::new(machine_secret, control_pub, version);
    let b64 = hs.initiation_base64();
    http1::write_request(
        conn.as_mut(),
        "POST",
        UPGRADE_PATH,
        host,
        &[
            ("Upgrade", UPGRADE_VALUE),
            ("Connection", "upgrade"),
            (HANDSHAKE_HEADER, &b64),
        ],
    )?;
    conn.set_read_timeout(Some(Duration::from_secs(20)))?;
    let head = http1::read_response_head(conn.as_mut())?;
    if head.status != 101 {
        let body = http1::read_body(conn.as_mut(), &head, 4096).unwrap_or_default();
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "ts2021 upgrade failed: status {} {}",
                head.status,
                String::from_utf8_lossy(&body)
            ),
        ));
    }
    if !head
        .header("upgrade")
        .map(|v| v.eq_ignore_ascii_case(UPGRADE_VALUE))
        .unwrap_or(false)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ts2021 upgrade header mismatch",
        ));
    }
    let mut resp = [0u8; RESPONSE_LEN];
    let mut leftover = head.leftover;
    let n = leftover.len().min(RESPONSE_LEN);
    resp[..n].copy_from_slice(&leftover[..n]);
    leftover.drain(..n);
    let mut got = n;
    // Read the header first so an unauthenticated server error can be reported.
    while got < HEADER_LEN {
        let k = conn.read(&mut resp[got..HEADER_LEN])?;
        if k == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "server closed during noise handshake",
            ));
        }
        got += k;
    }
    if resp[0] == MSG_ERROR {
        let len = u16::from_be_bytes([resp[1], resp[2]]) as usize;
        let mut msg = vec![0u8; len];
        let pre = leftover.len().min(len);
        msg[..pre].copy_from_slice(&leftover[..pre]);
        if pre < len {
            let _ = conn.read_exact(&mut msg[pre..]);
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "control server rejected handshake: {}",
                String::from_utf8_lossy(&msg)
            ),
        ));
    }
    while got < RESPONSE_LEN {
        let k = conn.read(&mut resp[got..])?;
        if k == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "server closed during noise handshake",
            ));
        }
        got += k;
    }
    let keys = hs.finish(&resp)?;
    Ok(NoiseConn::new(conn, keys, leftover))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::x25519_public;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn handshake_and_records_roundtrip() {
        let control_secret = x25519_generate();
        let control_pub = x25519_public(&control_secret);
        let machine_secret = x25519_generate();
        let machine_pub = x25519_public(&machine_secret);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut init = [0u8; INITIATION_LEN];
            s.read_exact(&mut init).unwrap();
            let (keys, mpub, resp) = server_handshake(&control_secret, &init).unwrap();
            assert_eq!(mpub, machine_pub);
            s.write_all(&resp).unwrap();
            let mut nc = NoiseConn::new(Box::new(s), keys, vec![]);
            let mut buf = [0u8; 5];
            nc.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"hello");
            nc.write_all(b"world").unwrap();
            let big = vec![7u8; 100_000];
            nc.write_all(&big).unwrap();
        });

        let mut c = TcpStream::connect(addr).unwrap();
        let hs = ClientHandshake::new(&machine_secret, &control_pub, 106);
        c.write_all(&hs.initiation).unwrap();
        let mut resp = [0u8; RESPONSE_LEN];
        c.read_exact(&mut resp).unwrap();
        let keys = hs.finish(&resp).unwrap();
        let mut nc = NoiseConn::new(Box::new(c), keys, vec![]);
        nc.write_all(b"hello").unwrap();
        let mut buf = [0u8; 5];
        nc.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"world");
        let mut big = vec![0u8; 100_000];
        nc.read_exact(&mut big).unwrap();
        assert!(big.iter().all(|&b| b == 7));
        server.join().unwrap();
    }
}
