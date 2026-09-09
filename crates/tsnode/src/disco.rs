//! Tailscale "disco" NAT-traversal messages (ping / pong / call-me-maybe),
//! sealed with NaCl box between disco keys.

use crate::crypto::{nacl_box_open, nacl_box_seal, random_array, CryptoError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 6-byte magic: "TS💬".
pub const MAGIC: &[u8; 6] = b"TS\xf0\x9f\x92\xac";
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = MAGIC.len() + KEY_LEN + NONCE_LEN;

const TYPE_PING: u8 = 1;
const TYPE_PONG: u8 = 2;
const TYPE_CALL_ME_MAYBE: u8 = 3;
const VERSION: u8 = 0;

pub type TxId = [u8; 12];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping {
        txid: TxId,
        node_key: Option<[u8; 32]>,
    },
    Pong {
        txid: TxId,
        src: SocketAddr,
    },
    CallMeMaybe {
        endpoints: Vec<SocketAddr>,
    },
}

impl Message {
    pub fn marshal(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64);
        match self {
            Message::Ping { txid, node_key } => {
                b.push(TYPE_PING);
                b.push(VERSION);
                b.extend_from_slice(txid);
                if let Some(k) = node_key {
                    b.extend_from_slice(k);
                }
            }
            Message::Pong { txid, src } => {
                b.push(TYPE_PONG);
                b.push(VERSION);
                b.extend_from_slice(txid);
                b.extend_from_slice(&ip16(src.ip()));
                b.extend_from_slice(&src.port().to_be_bytes());
            }
            Message::CallMeMaybe { endpoints } => {
                b.push(TYPE_CALL_ME_MAYBE);
                b.push(VERSION);
                for ep in endpoints {
                    b.extend_from_slice(&ip16(ep.ip()));
                    b.extend_from_slice(&ep.port().to_be_bytes());
                }
            }
        }
        b
    }

    pub fn parse(p: &[u8]) -> Option<Message> {
        if p.len() < 2 {
            return None;
        }
        let (t, ver, d) = (p[0], p[1], &p[2..]);
        if ver != VERSION {
            return None;
        }
        match t {
            TYPE_PING => {
                if d.len() < 12 {
                    return None;
                }
                let txid: TxId = d[..12].try_into().ok()?;
                let node_key = if d.len() >= 12 + 32 {
                    let k: [u8; 32] = d[12..44].try_into().ok()?;
                    if k == [0u8; 32] {
                        None
                    } else {
                        Some(k)
                    }
                } else {
                    None
                };
                Some(Message::Ping { txid, node_key })
            }
            TYPE_PONG => {
                if d.len() < 12 + 18 {
                    return None;
                }
                let txid: TxId = d[..12].try_into().ok()?;
                let ip = from_ip16(&d[12..28]);
                let port = u16::from_be_bytes([d[28], d[29]]);
                Some(Message::Pong {
                    txid,
                    src: SocketAddr::new(ip, port),
                })
            }
            TYPE_CALL_ME_MAYBE => {
                if d.is_empty() || d.len() % 18 != 0 {
                    return None;
                }
                let endpoints = d
                    .as_chunks::<18>()
                    .0
                    .iter()
                    .map(|c| {
                        SocketAddr::new(from_ip16(&c[..16]), u16::from_be_bytes([c[16], c[17]]))
                    })
                    .collect();
                Some(Message::CallMeMaybe { endpoints })
            }
            _ => None,
        }
    }
}

fn ip16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn from_ip16(b: &[u8]) -> IpAddr {
    let o: [u8; 16] = b.try_into().unwrap();
    let v6 = Ipv6Addr::from(o);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

pub fn new_txid() -> TxId {
    random_array()
}

pub fn is_disco(p: &[u8]) -> bool {
    p.len() >= HEADER_LEN && &p[..MAGIC.len()] == MAGIC
}

/// Sender's disco public key from a raw disco packet.
pub fn sender_key(p: &[u8]) -> Option<[u8; 32]> {
    if !is_disco(p) {
        return None;
    }
    p[MAGIC.len()..MAGIC.len() + KEY_LEN].try_into().ok()
}

/// Builds a full disco packet: magic || our disco pub || nonce || box(msg).
pub fn seal(
    our_disco: &crate::keys::KeyPair,
    their_disco_pub: &[u8; 32],
    msg: &Message,
) -> Vec<u8> {
    let nonce: [u8; NONCE_LEN] = random_array();
    let sealed = nacl_box_seal(our_disco.secret(), their_disco_pub, &nonce, &msg.marshal());
    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(our_disco.public());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    out
}

/// Opens a disco packet whose sender key was already looked up.
pub fn open(
    our_disco: &crate::keys::KeyPair,
    sender_disco_pub: &[u8; 32],
    p: &[u8],
) -> Result<Message, CryptoError> {
    if !is_disco(p) {
        return Err(CryptoError);
    }
    let nonce: [u8; NONCE_LEN] = p[MAGIC.len() + KEY_LEN..HEADER_LEN].try_into().unwrap();
    let pt = nacl_box_open(
        our_disco.secret(),
        sender_disco_pub,
        &nonce,
        &p[HEADER_LEN..],
    )?;
    Message::parse(&pt).ok_or(CryptoError)
}

pub fn unspecified_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn roundtrip_messages() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let msgs = vec![
            Message::Ping {
                txid: new_txid(),
                node_key: Some([7u8; 32]),
            },
            Message::Ping {
                txid: new_txid(),
                node_key: None,
            },
            Message::Pong {
                txid: new_txid(),
                src: "203.0.113.5:41641".parse().unwrap(),
            },
            Message::Pong {
                txid: new_txid(),
                src: "[2001:db8::1]:5".parse().unwrap(),
            },
            Message::CallMeMaybe {
                endpoints: vec![
                    "192.168.1.2:41641".parse().unwrap(),
                    "[fd00::2]:41641".parse().unwrap(),
                ],
            },
        ];
        for m in msgs {
            let pkt = seal(&a, b.public(), &m);
            assert!(is_disco(&pkt));
            assert_eq!(sender_key(&pkt).unwrap(), *a.public());
            let got = open(&b, a.public(), &pkt).unwrap();
            assert_eq!(got, m);
            assert!(open(&a, a.public(), &pkt).is_err());
        }
    }
}
