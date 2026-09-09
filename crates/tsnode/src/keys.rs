//! Key types and Tailscale's textual key encodings (`mkey:`, `nodekey:`,
//! `discokey:`, `privkey:`).

use crate::crypto::{x25519_generate, x25519_public};
use std::fmt;

pub const MACHINE_PUB_PREFIX: &str = "mkey:";
pub const NODE_PUB_PREFIX: &str = "nodekey:";
pub const DISCO_PUB_PREFIX: &str = "discokey:";
pub const PRIV_PREFIX: &str = "privkey:";

/// An X25519 key pair used for the machine key, node (WireGuard) key and disco key.
#[derive(Clone)]
pub struct KeyPair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        Self::from_secret(x25519_generate())
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        KeyPair {
            public: x25519_public(&secret),
            secret,
        }
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret)
    }

    pub fn from_secret_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix(PRIV_PREFIX).unwrap_or(s);
        parse_hex32(s).map(Self::from_secret)
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyPair(pub={})", hex::encode(self.public))
    }
}

pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s.trim()).ok()?;
    v.try_into().ok()
}

/// Parses a prefixed public key such as `nodekey:ab12...`. The prefix must match.
pub fn parse_prefixed(prefix: &str, s: &str) -> Option<[u8; 32]> {
    let rest = s.strip_prefix(prefix)?;
    parse_hex32(rest)
}

pub fn fmt_prefixed(prefix: &str, key: &[u8; 32]) -> String {
    format!("{}{}", prefix, hex::encode(key))
}

pub fn fmt_machine_pub(key: &[u8; 32]) -> String {
    fmt_prefixed(MACHINE_PUB_PREFIX, key)
}
pub fn fmt_node_pub(key: &[u8; 32]) -> String {
    fmt_prefixed(NODE_PUB_PREFIX, key)
}
pub fn fmt_disco_pub(key: &[u8; 32]) -> String {
    fmt_prefixed(DISCO_PUB_PREFIX, key)
}

/// Short form used in logs: first 5 bytes of the public key.
pub fn short(key: &[u8; 32]) -> String {
    format!("[{}]", hex::encode(&key[..5]))
}
