//! Packet filter (Tailscale ACL) enforcement on the receiving side.
//!
//! Control sends the rules that apply to this node as `FilterRule`s; every
//! decrypted packet from a peer is checked against them before it reaches the
//! local stack. As in tailscaled, only TCP SYNs, UDP and ICMP are subject to
//! the rules: a TCP segment without SYN belongs to an established flow and is
//! passed on for the stack to match against its sockets.

use crate::types::FilterRule;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// An IP set as it appears in a rule: `*`, a CIDR, a single address, or an
/// inclusive range `a-b`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IpSet {
    Any,
    Cidr(IpAddr, u8),
    Range(IpAddr, IpAddr),
}

impl IpSet {
    fn parse(s: &str) -> Option<IpSet> {
        let s = s.trim();
        if s == "*" {
            return Some(IpSet::Any);
        }
        if let Some((a, b)) = s.split_once('-') {
            let a: IpAddr = a.parse().ok()?;
            let b: IpAddr = b.parse().ok()?;
            if a.is_ipv4() != b.is_ipv4() {
                return None;
            }
            return Some(IpSet::Range(a, b));
        }
        if let Some((ip, bits)) = s.split_once('/') {
            let ip: IpAddr = ip.parse().ok()?;
            let bits: u8 = bits.parse().ok()?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if bits > max {
                return None;
            }
            return Some(IpSet::Cidr(ip, bits));
        }
        let ip: IpAddr = s.parse().ok()?;
        Some(IpSet::Cidr(ip, if ip.is_ipv4() { 32 } else { 128 }))
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match self {
            IpSet::Any => true,
            IpSet::Cidr(net, bits) => cidr_contains(*net, *bits, ip),
            IpSet::Range(a, b) => match (a, b, ip) {
                (IpAddr::V4(a), IpAddr::V4(b), IpAddr::V4(ip)) => {
                    (u32::from(*a)..=u32::from(*b)).contains(&u32::from(ip))
                }
                (IpAddr::V6(a), IpAddr::V6(b), IpAddr::V6(ip)) => {
                    (u128::from(*a)..=u128::from(*b)).contains(&u128::from(ip))
                }
                _ => false,
            },
        }
    }
}

fn cidr_contains(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let bits = bits.min(32);
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let bits = bits.min(128);
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
}

#[derive(Debug, Clone)]
struct Rule {
    srcs: Vec<IpSet>,
    /// (destination set, first port, last port)
    dsts: Vec<(IpSet, u16, u16)>,
    /// Empty means the Tailscale default set: TCP, UDP and ICMP.
    protos: Vec<u8>,
}

impl Rule {
    fn proto_allowed(&self, proto: u8) -> bool {
        if self.protos.is_empty() {
            matches!(proto, PROTO_TCP | PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6)
        } else {
            self.protos.contains(&proto)
        }
    }
}

/// Compiled packet filter. `Filter::default()` denies everything.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    rules: Vec<Rule>,
}

/// The parts of a packet the filter looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuple {
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub dst_port: u16,
    /// TCP segment without SYN (part of an established flow).
    pub tcp_established: bool,
}

impl Filter {
    pub fn compile(rules: &[FilterRule]) -> Filter {
        let rules = rules
            .iter()
            .map(|r| Rule {
                srcs: r.src_ips.iter().filter_map(|s| IpSet::parse(s)).collect(),
                dsts: r
                    .dst_ports
                    .iter()
                    .filter_map(|d| Some((IpSet::parse(&d.ip)?, d.ports.first, d.ports.last)))
                    .collect(),
                protos: r
                    .ip_proto
                    .iter()
                    .filter_map(|p| u8::try_from(*p).ok())
                    .collect(),
            })
            .collect();
        Filter { rules }
    }

    /// A filter that lets everything through (for tests and loopback setups).
    pub fn allow_all() -> Filter {
        Filter {
            rules: vec![Rule {
                srcs: vec![IpSet::Any],
                dsts: vec![(IpSet::Any, 0, 65535)],
                protos: Vec::new(),
            }],
        }
    }

    pub fn allows(&self, ip_pkt: &[u8]) -> bool {
        match parse_tuple(ip_pkt) {
            Some(t) => self.allows_tuple(&t),
            None => false,
        }
    }

    pub fn allows_tuple(&self, t: &Tuple) -> bool {
        if t.proto == PROTO_TCP && t.tcp_established {
            return true;
        }
        for r in &self.rules {
            if !r.proto_allowed(t.proto) {
                continue;
            }
            if !r.srcs.iter().any(|s| s.contains(t.src)) {
                continue;
            }
            let port_matters = matches!(t.proto, PROTO_TCP | PROTO_UDP);
            let hit = r.dsts.iter().any(|(set, first, last)| {
                set.contains(t.dst) && (!port_matters || (*first..=*last).contains(&t.dst_port))
            });
            if hit {
                return true;
            }
        }
        false
    }
}

/// Extracts protocol, addresses and destination port. Returns `None` for
/// packets the stack could not use anyway (truncated, unknown version,
/// IPv6 with extension headers).
pub fn parse_tuple(p: &[u8]) -> Option<Tuple> {
    let (proto, src, dst, l4) = match p.first()? >> 4 {
        4 => {
            if p.len() < 20 {
                return None;
            }
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            if ihl < 20 || p.len() < ihl {
                return None;
            }
            let frag_offset = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
            if frag_offset != 0 {
                // Later fragments carry no transport header; the stack does
                // not reassemble, so they are of no use.
                return None;
            }
            (
                p[9],
                IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])),
                IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])),
                &p[ihl..],
            )
        }
        6 => {
            if p.len() < 40 {
                return None;
            }
            let src: [u8; 16] = p[8..24].try_into().ok()?;
            let dst: [u8; 16] = p[24..40].try_into().ok()?;
            (
                p[6],
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                &p[40..],
            )
        }
        _ => return None,
    };
    let (dst_port, tcp_established) = match proto {
        PROTO_TCP => {
            if l4.len() < 14 {
                return None;
            }
            let flags = l4[13];
            (u16::from_be_bytes([l4[2], l4[3]]), flags & 0x02 == 0)
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            (u16::from_be_bytes([l4[2], l4[3]]), false)
        }
        _ => (0, false),
    };
    Some(Tuple {
        proto,
        src,
        dst,
        dst_port,
        tcp_established,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{NetPortRange, PortRange};

    fn rule(srcs: &[&str], dst: &str, first: u16, last: u16, protos: &[i32]) -> FilterRule {
        FilterRule {
            src_ips: srcs.iter().map(|s| s.to_string()).collect(),
            dst_ports: vec![NetPortRange {
                ip: dst.into(),
                ports: PortRange { first, last },
            }],
            ip_proto: protos.to_vec(),
        }
    }

    fn tcp4(src: &str, dst: &str, port: u16, syn: bool) -> Vec<u8> {
        let s: Ipv4Addr = src.parse().unwrap();
        let d: Ipv4Addr = dst.parse().unwrap();
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&s.octets());
        p[16..20].copy_from_slice(&d.octets());
        p[22..24].copy_from_slice(&port.to_be_bytes());
        p[33] = if syn { 0x02 } else { 0x10 };
        p
    }

    #[test]
    fn syn_is_filtered_by_source_and_port() {
        let f = Filter::compile(&[rule(&["100.64.0.0/10"], "100.64.0.9/32", 2300, 2300, &[6])]);
        assert!(f.allows(&tcp4("100.64.0.1", "100.64.0.9", 2300, true)));
        assert!(!f.allows(&tcp4("100.64.0.1", "100.64.0.9", 22, true)));
        assert!(!f.allows(&tcp4("100.64.0.1", "100.64.0.8", 2300, true)));
        assert!(!f.allows(&tcp4("10.0.0.1", "100.64.0.9", 2300, true)));
        // Established segments are the stack's business.
        assert!(f.allows(&tcp4("10.0.0.1", "100.64.0.9", 22, false)));
    }

    #[test]
    fn empty_filter_denies_and_star_allows() {
        assert!(!Filter::default().allows(&tcp4("100.64.0.1", "100.64.0.9", 2300, true)));
        let f = Filter::compile(&[rule(&["*"], "*", 0, 65535, &[])]);
        assert!(f.allows(&tcp4("100.64.0.1", "100.64.0.9", 2300, true)));
        let mut udp = tcp4("100.64.0.1", "100.64.0.9", 53, true);
        udp[9] = PROTO_UDP;
        assert!(f.allows(&udp));
        let mut icmp = tcp4("100.64.0.1", "100.64.0.9", 0, true);
        icmp[9] = PROTO_ICMP;
        assert!(f.allows(&icmp));
        // A rule limited to TCP does not admit UDP or ICMP.
        let t = Filter::compile(&[rule(&["*"], "*", 0, 65535, &[6])]);
        assert!(!t.allows(&udp));
        assert!(!t.allows(&icmp));
    }

    #[test]
    fn ip_sets() {
        assert!(IpSet::parse("100.64.0.1-100.64.0.5")
            .unwrap()
            .contains("100.64.0.3".parse().unwrap()));
        assert!(!IpSet::parse("100.64.0.1-100.64.0.5")
            .unwrap()
            .contains("100.64.0.6".parse().unwrap()));
        assert!(IpSet::parse("fd7a:115c:a1e0::/48")
            .unwrap()
            .contains("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(IpSet::parse("100.64.0.1")
            .unwrap()
            .contains("100.64.0.1".parse().unwrap()));
        assert!(IpSet::parse("100.64.0.1/33").is_none());
        assert!(IpSet::parse("garbage").is_none());
    }

    #[test]
    fn truncated_packets_are_denied() {
        let f = Filter::allow_all();
        assert!(!f.allows(&[0x45, 0, 0]));
        assert!(!f.allows(&tcp4("100.64.0.1", "100.64.0.9", 2300, true)[..30]));
        assert!(!f.allows(&[0x60; 39]));
    }
}
