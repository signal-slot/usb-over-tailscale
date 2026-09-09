//! WireGuard (Noise_IKpsk2) per-peer tunnel state machine, both initiator and
//! responder roles, without any I/O. The caller (magicsock) moves packets.

use crate::crypto::{
    aead_decrypt, aead_encrypt, blake2s, blake2s_mac16, random_array, x25519_generate,
    x25519_public, TAG_LEN,
};
use crate::keys::KeyPair;
use crate::noise::SymmetricState;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_COOKIE_REPLY: u8 = 3;
pub const MSG_TRANSPORT: u8 = 4;

pub const INITIATION_LEN: usize = 148;
pub const RESPONSE_LEN: usize = 92;
pub const TRANSPORT_HEADER_LEN: usize = 16;

pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const MAX_HANDSHAKE_ATTEMPTS: u32 = 18;

/// Offset (seconds) added to the system clock when producing TAI64N
/// timestamps. The node sets it from the control server's `ControlTime` so
/// that devices without an RTC still produce increasing timestamps.
pub static WALL_CLOCK_OFFSET_SECS: AtomicI32 = AtomicI32::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgError {
    BadLength,
    BadType,
    BadMac,
    BadReceiver,
    AuthFailed,
    NoSession,
    Replay,
    UnknownPeer,
}

impl core::fmt::Display for WgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for WgError {}

fn tai64n_now() -> [u8; 12] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = now.as_secs() as i64 + WALL_CLOCK_OFFSET_SECS.load(Ordering::Relaxed) as i64;
    let tai = (secs.max(0) as u64).wrapping_add(0x4000_0000_0000_000a);
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&tai.to_be_bytes());
    out[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    out
}

fn mac1_key(public: &[u8; 32]) -> [u8; 32] {
    blake2s(&[LABEL_MAC1, public])
}

/// Peer's view of a successful handshake: keys and indices.
struct Session {
    local_index: u32,
    remote_index: u32,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    replay: ReplayWindow,
    created: Instant,
    is_initiator: bool,
    /// For responders: becomes true once a transport packet arrived.
    confirmed: bool,
}

/// Anti-replay window (RFC 6479 bitmap). wireguard-go accepts ~8000 packets
/// of reordering; the DERP and UDP paths reorder when the route flips.
const REPLAY_WORDS: usize = 32;
const REPLAY_BITS: u64 = (REPLAY_WORDS as u64 - 1) * 64;

struct ReplayWindow {
    last: u64,
    bitmap: [u64; REPLAY_WORDS],
}

impl ReplayWindow {
    fn new() -> Self {
        ReplayWindow {
            last: 0,
            bitmap: [0; REPLAY_WORDS],
        }
    }
    fn check_and_update(&mut self, counter: u64) -> bool {
        if counter > self.last {
            if counter - self.last >= REPLAY_BITS {
                self.bitmap = [0; REPLAY_WORDS];
            } else {
                // Clear the words the window slides over.
                let mut w = self.last / 64 + 1;
                while w <= counter / 64 {
                    self.bitmap[(w % REPLAY_WORDS as u64) as usize] = 0;
                    w += 1;
                }
            }
            self.last = counter;
            self.mark(counter);
            return true;
        }
        if self.last - counter >= REPLAY_BITS {
            return false;
        }
        let (word, bit) = Self::slot(counter);
        if self.bitmap[word] & bit != 0 {
            return false;
        }
        self.bitmap[word] |= bit;
        true
    }
    fn mark(&mut self, counter: u64) {
        let (word, bit) = Self::slot(counter);
        self.bitmap[word] |= bit;
    }
    fn slot(counter: u64) -> (usize, u64) {
        (
            ((counter / 64) % REPLAY_WORDS as u64) as usize,
            1u64 << (counter % 64),
        )
    }
}

struct PendingInitiation {
    local_index: u32,
    ephemeral_secret: [u8; 32],
    state: SymmetricState,
    sent_at: Instant,
    attempts: u32,
}

/// Result of consuming an initiation at the device level, before the peer is known.
pub struct ConsumedInitiation {
    pub peer_public: [u8; 32],
    remote_index: u32,
    remote_ephemeral: [u8; 32],
    state: SymmetricState,
    pub timestamp: [u8; 12],
}

/// Device-level: decrypts the static key in an initiation to identify the peer.
pub fn consume_initiation(local: &KeyPair, msg: &[u8]) -> Result<ConsumedInitiation, WgError> {
    if msg.len() != INITIATION_LEN {
        return Err(WgError::BadLength);
    }
    if msg[0] != MSG_INITIATION {
        return Err(WgError::BadType);
    }
    let mac1 = blake2s_mac16(&mac1_key(local.public()), &[&msg[..116]]);
    if mac1 != msg[116..132] {
        return Err(WgError::BadMac);
    }
    let remote_index = u32::from_le_bytes(msg[4..8].try_into().unwrap());
    let remote_ephemeral: [u8; 32] = msg[8..40].try_into().unwrap();
    let mut s = SymmetricState::new(CONSTRUCTION);
    s.mix_hash(IDENTIFIER);
    s.mix_hash(local.public());
    s.mix_key(&remote_ephemeral);
    s.mix_hash(&remote_ephemeral);
    s.mix_dh(local.secret(), &remote_ephemeral);
    let peer_public: [u8; 32] = s
        .decrypt_and_hash(&msg[40..88])
        .map_err(|_| WgError::AuthFailed)?
        .try_into()
        .unwrap();
    s.mix_dh(local.secret(), &peer_public);
    let timestamp: [u8; 12] = s
        .decrypt_and_hash(&msg[88..116])
        .map_err(|_| WgError::AuthFailed)?
        .try_into()
        .unwrap();
    Ok(ConsumedInitiation {
        peer_public,
        remote_index,
        remote_ephemeral,
        state: s,
        timestamp,
    })
}

/// Per-peer tunnel.
pub struct Tunn {
    local: KeyPair,
    peer_public: [u8; 32],
    mac1_key_peer: [u8; 32],
    mac1_key_local: [u8; 32],
    pending: Option<PendingInitiation>,
    current: Option<Session>,
    previous: Option<Session>,
    last_initiation_ts: [u8; 12],
    last_sent: Option<Instant>,
    last_received: Option<Instant>,
    need_keepalive: bool,
    queued: Vec<Vec<u8>>,
}

pub enum Decapsulated {
    /// A decrypted IP packet for the local stack.
    Ip(Vec<u8>),
    /// A keepalive or handshake message; `reply` (if any) must be sent back.
    Control { reply: Option<Vec<u8>> },
}

impl Tunn {
    pub fn new(local: KeyPair, peer_public: [u8; 32]) -> Self {
        Tunn {
            mac1_key_peer: mac1_key(&peer_public),
            mac1_key_local: mac1_key(local.public()),
            local,
            peer_public,
            pending: None,
            current: None,
            previous: None,
            last_initiation_ts: [0; 12],
            last_sent: None,
            last_received: None,
            need_keepalive: false,
            queued: Vec::new(),
        }
    }

    pub fn peer_public(&self) -> &[u8; 32] {
        &self.peer_public
    }

    /// Receiver indices that currently belong to this tunnel.
    pub fn local_indices(&self) -> Vec<u32> {
        let mut v = Vec::with_capacity(3);
        if let Some(p) = &self.pending {
            v.push(p.local_index);
        }
        if let Some(s) = &self.current {
            v.push(s.local_index);
        }
        if let Some(s) = &self.previous {
            v.push(s.local_index);
        }
        v
    }

    pub fn has_session(&self) -> bool {
        self.current.is_some()
    }

    pub fn last_received(&self) -> Option<Instant> {
        self.last_received
    }

    fn new_initiation(&mut self, now: Instant) -> Vec<u8> {
        let mut s = SymmetricState::new(CONSTRUCTION);
        s.mix_hash(IDENTIFIER);
        s.mix_hash(&self.peer_public);
        let e = x25519_generate();
        let e_pub = x25519_public(&e);
        s.mix_key(&e_pub);
        s.mix_hash(&e_pub);
        s.mix_dh(&e, &self.peer_public);
        let enc_static = s.encrypt_and_hash(self.local.public());
        s.mix_dh(self.local.secret(), &self.peer_public);
        let enc_ts = s.encrypt_and_hash(&tai64n_now());
        let local_index = u32::from_le_bytes(random_array());
        let mut msg = Vec::with_capacity(INITIATION_LEN);
        msg.extend_from_slice(&[MSG_INITIATION, 0, 0, 0]);
        msg.extend_from_slice(&local_index.to_le_bytes());
        msg.extend_from_slice(&e_pub);
        msg.extend_from_slice(&enc_static);
        msg.extend_from_slice(&enc_ts);
        let mac1 = blake2s_mac16(&self.mac1_key_peer, &[&msg]);
        msg.extend_from_slice(&mac1);
        msg.extend_from_slice(&[0u8; 16]);
        let attempts = self.pending.as_ref().map(|p| p.attempts + 1).unwrap_or(1);
        self.pending = Some(PendingInitiation {
            local_index,
            ephemeral_secret: e,
            state: s,
            sent_at: now,
            attempts,
        });
        msg
    }

    /// Ensures a handshake is in flight (if no usable session exists). Returns
    /// the initiation to send, if a new one was created.
    pub fn initiate_if_needed(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.current.is_some() {
            return None;
        }
        match &self.pending {
            Some(p) if now.duration_since(p.sent_at) < REKEY_TIMEOUT => None,
            Some(p) if p.attempts >= MAX_HANDSHAKE_ATTEMPTS => {
                self.pending = None;
                self.queued.clear();
                None
            }
            _ => Some(self.new_initiation(now)),
        }
    }

    /// Encrypts an IP packet. If no session exists the packet is queued and a
    /// handshake initiation is returned instead.
    pub fn encapsulate(&mut self, ip_packet: &[u8], now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        // Deviation from the WireGuard paper: as responder we send on the
        // new session before the initiator has confirmed it (the initiator
        // already treats it as current, so this interoperates) instead of
        // falling back to the previous session.
        match self.current.as_mut() {
            Some(s) => {
                if now.duration_since(s.created) >= REJECT_AFTER_TIME {
                    self.current = None;
                    self.queue(ip_packet);
                    if let Some(init) = self.initiate_if_needed(now) {
                        out.push(init);
                    }
                    return out;
                }
                out.push(Self::seal(s, ip_packet));
                self.last_sent = Some(now);
                self.need_keepalive = false;
                if s.is_initiator
                    && (now.duration_since(s.created) >= REKEY_AFTER_TIME
                        || s.send_counter >= REKEY_AFTER_MESSAGES)
                    && self.pending.is_none()
                {
                    out.push(self.new_initiation(now));
                }
            }
            None => {
                self.queue(ip_packet);
                if let Some(init) = self.initiate_if_needed(now) {
                    out.push(init);
                }
            }
        }
        out
    }

    fn queue(&mut self, pkt: &[u8]) {
        if self.queued.len() >= 8 {
            self.queued.remove(0);
        }
        self.queued.push(pkt.to_vec());
    }

    fn seal(s: &mut Session, plaintext: &[u8]) -> Vec<u8> {
        let padded_len = (plaintext.len() + 15) & !15;
        let mut padded = Vec::with_capacity(padded_len);
        padded.extend_from_slice(plaintext);
        padded.resize(padded_len, 0);
        let ct = aead_encrypt(&s.send_key, s.send_counter, &padded, &[]);
        let mut msg = Vec::with_capacity(TRANSPORT_HEADER_LEN + ct.len());
        msg.extend_from_slice(&[MSG_TRANSPORT, 0, 0, 0]);
        msg.extend_from_slice(&s.remote_index.to_le_bytes());
        msg.extend_from_slice(&s.send_counter.to_le_bytes());
        msg.extend_from_slice(&ct);
        s.send_counter += 1;
        msg
    }

    /// Handles a handshake response addressed to our pending initiation.
    pub fn consume_response(&mut self, msg: &[u8], now: Instant) -> Result<Vec<Vec<u8>>, WgError> {
        if msg.len() != RESPONSE_LEN {
            return Err(WgError::BadLength);
        }
        if msg[0] != MSG_RESPONSE {
            return Err(WgError::BadType);
        }
        let mac1 = blake2s_mac16(&self.mac1_key_local, &[&msg[..60]]);
        if mac1 != msg[60..76] {
            return Err(WgError::BadMac);
        }
        let remote_index = u32::from_le_bytes(msg[4..8].try_into().unwrap());
        let receiver = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        let pending = match &self.pending {
            Some(p) if p.local_index == receiver => self.pending.take().unwrap(),
            _ => return Err(WgError::BadReceiver),
        };
        let re: [u8; 32] = msg[12..44].try_into().unwrap();
        let mut s = pending.state.clone();
        s.mix_hash(&re);
        s.mix_key(&re);
        s.mix_dh(&pending.ephemeral_secret, &re);
        s.mix_dh(self.local.secret(), &re);
        s.mix_key_and_hash(&[0u8; 32]);
        if s.decrypt_and_hash(&msg[44..60]).is_err() {
            // Keep the pending initiation for retry.
            self.pending = Some(pending);
            return Err(WgError::AuthFailed);
        }
        let (send_key, recv_key) = s.split();
        let session = Session {
            local_index: pending.local_index,
            remote_index,
            send_key,
            recv_key,
            send_counter: 0,
            replay: ReplayWindow::new(),
            created: now,
            is_initiator: true,
            confirmed: true,
        };
        self.previous = self.current.take();
        self.current = Some(session);
        Ok(self.flush_queue(now))
    }

    fn flush_queue(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let queued = std::mem::take(&mut self.queued);
        let mut out = Vec::with_capacity(queued.len());
        if let Some(s) = self.current.as_mut() {
            for pkt in queued {
                out.push(Self::seal(s, &pkt));
            }
            if !out.is_empty() {
                self.last_sent = Some(now);
            }
        }
        out
    }

    /// Accepts a consumed initiation from this peer and produces the response.
    pub fn accept_initiation(
        &mut self,
        ci: ConsumedInitiation,
        now: Instant,
    ) -> Result<Vec<u8>, WgError> {
        if ci.peer_public != self.peer_public {
            return Err(WgError::UnknownPeer);
        }
        if ci.timestamp <= self.last_initiation_ts {
            return Err(WgError::Replay);
        }
        self.last_initiation_ts = ci.timestamp;
        let mut s = ci.state;
        let local_index = u32::from_le_bytes(random_array());
        let e = x25519_generate();
        let e_pub = x25519_public(&e);
        s.mix_hash(&e_pub);
        s.mix_key(&e_pub);
        s.mix_dh(&e, &ci.remote_ephemeral);
        s.mix_dh(&e, &self.peer_public);
        s.mix_key_and_hash(&[0u8; 32]);
        let empty = s.encrypt_and_hash(&[]);
        let mut msg = Vec::with_capacity(RESPONSE_LEN);
        msg.extend_from_slice(&[MSG_RESPONSE, 0, 0, 0]);
        msg.extend_from_slice(&local_index.to_le_bytes());
        msg.extend_from_slice(&ci.remote_index.to_le_bytes());
        msg.extend_from_slice(&e_pub);
        msg.extend_from_slice(&empty);
        let mac1 = blake2s_mac16(&self.mac1_key_peer, &[&msg]);
        msg.extend_from_slice(&mac1);
        msg.extend_from_slice(&[0u8; 16]);
        let (initiator_send, responder_send) = s.split();
        let session = Session {
            local_index,
            remote_index: ci.remote_index,
            send_key: responder_send,
            recv_key: initiator_send,
            send_counter: 0,
            replay: ReplayWindow::new(),
            created: now,
            is_initiator: false,
            confirmed: false,
        };
        self.previous = self.current.take();
        self.current = Some(session);
        // A handshake from the peer supersedes any initiation of ours.
        self.pending = None;
        Ok(msg)
    }

    /// Decrypts a transport message. Returns the IP packet, or `None` for a keepalive.
    pub fn consume_transport(
        &mut self,
        msg: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, WgError> {
        if msg.len() < TRANSPORT_HEADER_LEN + TAG_LEN {
            return Err(WgError::BadLength);
        }
        if msg[0] != MSG_TRANSPORT {
            return Err(WgError::BadType);
        }
        let receiver = u32::from_le_bytes(msg[4..8].try_into().unwrap());
        let counter = u64::from_le_bytes(msg[8..16].try_into().unwrap());
        let (slot, is_current) = if self
            .current
            .as_ref()
            .map(|s| s.local_index == receiver)
            .unwrap_or(false)
        {
            (self.current.as_mut().unwrap(), true)
        } else if self
            .previous
            .as_ref()
            .map(|s| s.local_index == receiver)
            .unwrap_or(false)
        {
            (self.previous.as_mut().unwrap(), false)
        } else {
            return Err(WgError::NoSession);
        };
        if now.duration_since(slot.created) >= REJECT_AFTER_TIME {
            return Err(WgError::NoSession);
        }
        let pt = aead_decrypt(&slot.recv_key, counter, &msg[16..], &[])
            .map_err(|_| WgError::AuthFailed)?;
        if !slot.replay.check_and_update(counter) {
            return Err(WgError::Replay);
        }
        slot.confirmed = true;
        self.last_received = Some(now);
        if is_current {
            // The peer confirmed the newest session; the old one is no longer needed.
            self.previous = None;
        }
        if pt.is_empty() {
            return Ok(None);
        }
        let len = ip_packet_len(&pt).unwrap_or(pt.len()).min(pt.len());
        self.need_keepalive = true;
        let mut out = pt;
        out.truncate(len);
        Ok(Some(out))
    }

    /// Periodic maintenance: handshake retransmits, passive keepalives, expiry.
    pub fn tick(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if let Some(s) = &self.current {
            if now.duration_since(s.created) >= REJECT_AFTER_TIME {
                self.current = None;
            }
        }
        if let Some(s) = &self.previous {
            if now.duration_since(s.created) >= REJECT_AFTER_TIME {
                self.previous = None;
            }
        }
        if self.pending.is_some() || (!self.queued.is_empty() && self.current.is_none()) {
            if let Some(init) = self.initiate_if_needed(now) {
                out.push(init);
            }
        }
        if self.need_keepalive {
            if let (Some(rx), Some(s)) = (self.last_received, self.current.as_mut()) {
                let since_send = self
                    .last_sent
                    .map(|t| now.duration_since(t))
                    .unwrap_or(Duration::MAX);
                if now.duration_since(rx) < KEEPALIVE_TIMEOUT * 2 && since_send >= KEEPALIVE_TIMEOUT
                {
                    out.push(Self::seal(s, &[]));
                    self.last_sent = Some(now);
                    self.need_keepalive = false;
                }
            }
        }
        out
    }

    /// Drops all session state (e.g. the peer's key changed).
    pub fn reset(&mut self) {
        self.pending = None;
        self.current = None;
        self.previous = None;
        self.queued.clear();
    }
}

/// Length of an IP packet according to its header, used to strip WireGuard padding.
pub fn ip_packet_len(pkt: &[u8]) -> Option<usize> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(u16::from_be_bytes([pkt[2], pkt[3]]) as usize),
        6 if pkt.len() >= 40 => Some(40 + u16::from_be_bytes([pkt[4], pkt[5]]) as usize),
        _ => None,
    }
}

/// Message type of a WireGuard packet, if it looks like one.
pub fn message_type(pkt: &[u8]) -> Option<u8> {
    if pkt.len() < 4 || pkt[1] != 0 || pkt[2] != 0 || pkt[3] != 0 {
        return None;
    }
    match pkt[0] {
        MSG_INITIATION if pkt.len() == INITIATION_LEN => Some(MSG_INITIATION),
        MSG_RESPONSE if pkt.len() == RESPONSE_LEN => Some(MSG_RESPONSE),
        MSG_COOKIE_REPLY if pkt.len() == 64 => Some(MSG_COOKIE_REPLY),
        MSG_TRANSPORT if pkt.len() >= TRANSPORT_HEADER_LEN + TAG_LEN => Some(MSG_TRANSPORT),
        _ => None,
    }
}

pub fn receiver_index(pkt: &[u8]) -> Option<u32> {
    match message_type(pkt)? {
        MSG_RESPONSE => Some(u32::from_le_bytes(pkt[8..12].try_into().unwrap())),
        MSG_TRANSPORT | MSG_COOKIE_REPLY => Some(u32::from_le_bytes(pkt[4..8].try_into().unwrap())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(payload_len: usize) -> Vec<u8> {
        let total = 20 + payload_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        for (i, b) in p[20..].iter_mut().enumerate() {
            *b = i as u8;
        }
        p
    }

    #[test]
    fn handshake_and_transport_both_directions() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let mut ta = Tunn::new(a.clone(), *b.public());
        let mut tb = Tunn::new(b.clone(), *a.public());
        let now = Instant::now();

        // A wants to send: gets an initiation and queues the packet.
        let pkt = ipv4_packet(33);
        let msgs = ta.encapsulate(&pkt, now);
        assert_eq!(msgs.len(), 1);
        assert_eq!(message_type(&msgs[0]), Some(MSG_INITIATION));

        // B consumes it at device level, then at peer level.
        let ci = consume_initiation(&b, &msgs[0]).expect("consume initiation");
        assert_eq!(ci.peer_public, *a.public());
        let resp = tb.accept_initiation(ci, now).unwrap();
        assert_eq!(message_type(&resp), Some(MSG_RESPONSE));
        assert!(receiver_index(&resp).is_some());

        // A consumes the response and flushes the queued packet.
        let flushed = ta.consume_response(&resp, now).unwrap();
        assert_eq!(flushed.len(), 1);
        assert_eq!(message_type(&flushed[0]), Some(MSG_TRANSPORT));
        let got = tb.consume_transport(&flushed[0], now).unwrap().unwrap();
        assert_eq!(got, pkt);

        // B replies.
        let reply = ipv4_packet(7);
        let msgs = tb.encapsulate(&reply, now);
        assert_eq!(msgs.len(), 1);
        let got = ta.consume_transport(&msgs[0], now).unwrap().unwrap();
        assert_eq!(got, reply);

        // Replay is rejected.
        assert_eq!(
            ta.consume_transport(&msgs[0], now).unwrap_err(),
            WgError::Replay
        );

        // Passive keepalive from B after receiving without sending for 10s.
        let later = now + Duration::from_secs(11);
        let _ = tb
            .consume_transport(&ta.encapsulate(&pkt, later)[0], later)
            .unwrap();
        let ka = tb.tick(later + Duration::from_secs(1));
        assert_eq!(ka.len(), 1);
        assert!(ta.consume_transport(&ka[0], later).unwrap().is_none());
    }

    #[test]
    fn initiation_replay_and_bad_mac_rejected() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let mut ta = Tunn::new(a.clone(), *b.public());
        let mut tb = Tunn::new(b.clone(), *a.public());
        let now = Instant::now();
        let init = ta.initiate_if_needed(now).unwrap();
        let ci = consume_initiation(&b, &init).expect("consume");
        tb.accept_initiation(ci, now).unwrap();
        let ci2 = consume_initiation(&b, &init).expect("consume again");
        assert_eq!(tb.accept_initiation(ci2, now).unwrap_err(), WgError::Replay);
        let mut bad = init.clone();
        bad[120] ^= 1;
        assert!(matches!(consume_initiation(&b, &bad), Err(WgError::BadMac)));
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(3));
        assert!(w.check_and_update(2));
        assert!(!w.check_and_update(2));
        assert!(w.check_and_update(100));
        assert!(!w.check_and_update(3));
        assert!(w.check_and_update(4));
        assert!(!w.check_and_update(4));
        assert!(w.check_and_update(99));
        // Far behind the window: rejected. Just inside: accepted once.
        assert!(w.check_and_update(5000));
        assert!(!w.check_and_update(5000 - REPLAY_BITS));
        assert!(w.check_and_update(5000 - REPLAY_BITS + 1));
        assert!(!w.check_and_update(5000 - REPLAY_BITS + 1));
        // A jump larger than the window clears everything old.
        assert!(w.check_and_update(1_000_000));
        assert!(!w.check_and_update(5000));
        assert!(w.check_and_update(999_999));
        // Counter 0 was never seen, so it is accepted exactly once.
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(0));
        assert!(!w.check_and_update(0));
    }
}
