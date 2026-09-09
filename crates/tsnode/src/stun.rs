//! Minimal STUN binding request/response (RFC 5389) for endpoint discovery.

use crate::crypto::random_array;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_XOR_MAPPED_ADDRESS_ALT: u16 = 0x8020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const HEADER_LEN: usize = 20;
const SOFTWARE: &[u8] = b"tsnode";

pub type TxId = [u8; 12];

pub fn new_txid() -> TxId {
    random_array()
}

pub fn request(txid: &TxId) -> Vec<u8> {
    let software_padded = (SOFTWARE.len() + 3) & !3;
    let attrs_len = 4 + software_padded + 8;
    let mut b = Vec::with_capacity(HEADER_LEN + attrs_len);
    b.extend_from_slice(&[0x00, 0x01]);
    b.extend_from_slice(&(attrs_len as u16).to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE);
    b.extend_from_slice(txid);
    b.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    b.extend_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    b.extend_from_slice(SOFTWARE);
    b.resize(HEADER_LEN + 4 + software_padded, 0);
    let fp = crc32(&b) ^ 0x5354_554e;
    b.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    b.extend_from_slice(&4u16.to_be_bytes());
    b.extend_from_slice(&fp.to_be_bytes());
    b
}

pub fn is_stun(b: &[u8]) -> bool {
    b.len() >= HEADER_LEN && b[4..8] == MAGIC_COOKIE && b[0] & 0xc0 == 0
}

/// Parses a binding success response, returning the transaction id and the mapped address.
pub fn parse_response(b: &[u8]) -> Option<(TxId, SocketAddr)> {
    if !is_stun(b) || b[0] != 0x01 || b[1] != 0x01 {
        return None;
    }
    let txid: TxId = b[8..20].try_into().ok()?;
    let attrs_len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let mut attrs = &b[HEADER_LEN..];
    if attrs.len() < attrs_len {
        return None;
    }
    attrs = &attrs[..attrs_len];
    let mut fallback = None;
    while attrs.len() >= 4 {
        let t = u16::from_be_bytes([attrs[0], attrs[1]]);
        let l = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        if attrs.len() < 4 + l {
            return None;
        }
        let v = &attrs[4..4 + l];
        match t {
            ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS_ALT => {
                if let Some(a) = parse_mapped(v, Some(&txid)) {
                    return Some((txid, a));
                }
            }
            ATTR_MAPPED_ADDRESS => fallback = parse_mapped(v, None),
            _ => {}
        }
        let padded = (l + 3) & !3;
        attrs = &attrs[(4 + padded).min(attrs.len())..];
    }
    fallback.map(|a| (txid, a))
}

fn parse_mapped(v: &[u8], xor: Option<&TxId>) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let family = v[1];
    let mut port = u16::from_be_bytes([v[2], v[3]]);
    if xor.is_some() {
        port ^= u16::from_be_bytes([MAGIC_COOKIE[0], MAGIC_COOKIE[1]]);
    }
    match family {
        0x01 if v.len() >= 8 => {
            let mut o: [u8; 4] = v[4..8].try_into().ok()?;
            if xor.is_some() {
                for i in 0..4 {
                    o[i] ^= MAGIC_COOKIE[i];
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), port))
        }
        0x02 if v.len() >= 20 => {
            let mut o: [u8; 16] = v[4..20].try_into().ok()?;
            if let Some(tx) = xor {
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&MAGIC_COOKIE);
                key[4..].copy_from_slice(tx);
                for i in 0..16 {
                    o[i] ^= key[i];
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        _ => None,
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (!(crc & 1)).wrapping_add(1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shape_and_response_parse() {
        let tx = new_txid();
        let req = request(&tx);
        assert!(is_stun(&req));
        assert_eq!(req.len(), 20 + 4 + 8 + 8);
        // Build a response with XOR-MAPPED-ADDRESS 203.0.113.9:41641.
        let ip = Ipv4Addr::new(203, 0, 113, 9).octets();
        let port: u16 = 41641;
        let mut resp = vec![0x01, 0x01, 0, 12];
        resp.extend_from_slice(&MAGIC_COOKIE);
        resp.extend_from_slice(&tx);
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0);
        resp.push(1);
        resp.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        for i in 0..4 {
            resp.push(ip[i] ^ MAGIC_COOKIE[i]);
        }
        let (got_tx, addr) = parse_response(&resp).unwrap();
        assert_eq!(got_tx, tx);
        assert_eq!(addr, "203.0.113.9:41641".parse().unwrap());
    }

    #[test]
    fn crc32_known() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
