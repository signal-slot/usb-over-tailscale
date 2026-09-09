//! JSON types exchanged with the Tailscale control plane (subset of `tailcfg`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The capability version we claim. Kept deliberately conservative so the
/// control server uses the well-understood, older response shapes.
pub const CAPABILITY_VERSION: u16 = 106;

pub const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct NetInfo {
    #[serde(rename = "PreferredDERP")]
    pub preferred_derp: i32,
    #[serde(rename = "WorkingUDP")]
    pub working_udp: Option<bool>,
    #[serde(rename = "WorkingIPv6")]
    pub working_ipv6: Option<bool>,
    pub link_type: String,
    #[serde(rename = "DERPLatency", skip_serializing_if = "HashMap::is_empty")]
    pub derp_latency: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct Hostinfo {
    #[serde(rename = "IPNVersion")]
    pub ipn_version: String,
    #[serde(rename = "OS")]
    pub os: String,
    #[serde(rename = "OSVersion")]
    pub os_version: String,
    pub distro: String,
    pub device_model: String,
    pub hostname: String,
    pub go_arch: String,
    pub machine: String,
    pub userspace: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_info: Option<NetInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct RegisterResponseAuth {
    pub auth_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct RegisterRequest {
    pub version: u16,
    pub node_key: String,
    pub old_node_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<RegisterResponseAuth>,
    pub expiry: String,
    pub followup: String,
    pub hostinfo: Hostinfo,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct UserProfile {
    #[serde(rename = "ID")]
    pub id: i64,
    pub login_name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct Login {
    #[serde(rename = "ID")]
    pub id: i64,
    pub login_name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct RegisterResponse {
    pub login: Login,
    pub node_key_expired: bool,
    pub machine_authorized: bool,
    #[serde(rename = "AuthURL")]
    pub auth_url: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct MapRequest {
    pub version: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub compress: String,
    pub keep_alive: bool,
    pub node_key: String,
    pub disco_key: String,
    pub stream: bool,
    pub hostinfo: Hostinfo,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub omit_peers: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct Node {
    #[serde(rename = "ID")]
    pub id: i64,
    #[serde(rename = "StableID")]
    pub stable_id: String,
    pub name: String,
    pub user: i64,
    pub key: String,
    pub key_expiry: String,
    pub machine: String,
    pub disco_key: String,
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<String>,
    pub endpoints: Vec<String>,
    /// Legacy home DERP encoding: `127.3.3.40:<region>`.
    #[serde(rename = "DERP")]
    pub derp: String,
    #[serde(rename = "HomeDERP")]
    pub home_derp: i32,
    pub hostinfo: Hostinfo,
    pub online: Option<bool>,
    pub machine_authorized: bool,
}

impl Node {
    pub fn home_derp_region(&self) -> Option<i32> {
        if self.home_derp != 0 {
            return Some(self.home_derp);
        }
        self.derp
            .rsplit(':')
            .next()
            .and_then(|s| s.parse().ok())
            .filter(|r| *r != 0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct PeerChange {
    #[serde(rename = "NodeID")]
    pub node_id: i64,
    #[serde(rename = "DERPRegion")]
    pub derp_region: i32,
    pub endpoints: Option<Vec<String>>,
    pub key: Option<String>,
    pub disco_key: Option<String>,
    pub online: Option<bool>,
    pub key_expiry: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpNode {
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: i32,
    pub host_name: String,
    pub cert_name: String,
    #[serde(rename = "IPv4")]
    pub ipv4: String,
    #[serde(rename = "IPv6")]
    pub ipv6: String,
    #[serde(rename = "STUNPort")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly")]
    pub stun_only: bool,
    #[serde(rename = "DERPPort")]
    pub derp_port: i32,
    pub insecure_for_tests: bool,
    pub can_port80: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: i32,
    pub region_code: String,
    pub region_name: String,
    pub avoid: bool,
    pub nodes: Vec<DerpNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct DerpMap {
    pub regions: HashMap<String, DerpRegion>,
    pub omit_default_regions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct DnsConfig {
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct PingRequest {
    #[serde(rename = "URL")]
    pub url: String,
    pub log: bool,
    pub types: String,
    #[serde(rename = "IP")]
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default, rename_all = "PascalCase")]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default, rename_all = "PascalCase")]
pub struct NetPortRange {
    #[serde(rename = "IP")]
    pub ip: String,
    pub ports: PortRange,
}

/// One ACL rule as sent by control (`tailcfg.FilterRule`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default, rename_all = "PascalCase")]
pub struct FilterRule {
    #[serde(rename = "SrcIPs")]
    pub src_ips: Vec<String>,
    pub dst_ports: Vec<NetPortRange>,
    #[serde(rename = "IPProto")]
    pub ip_proto: Vec<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct MapResponse {
    pub map_session_handle: String,
    pub seq: i64,
    pub keep_alive: bool,
    pub ping_request: Option<PingRequest>,
    pub node: Option<Node>,
    #[serde(rename = "DERPMap")]
    pub derp_map: Option<DerpMap>,
    pub peers: Option<Vec<Node>>,
    pub peers_changed: Option<Vec<Node>>,
    pub peers_removed: Option<Vec<i64>>,
    pub peers_changed_patch: Option<Vec<PeerChange>>,
    /// Legacy whole-filter replacement. `Some(vec![])` denies everything.
    pub packet_filter: Option<Vec<FilterRule>>,
    /// Named filter sets (capability version 81+): `*` is the base set, a
    /// `null` value deletes the named set.
    pub packet_filters: Option<HashMap<String, Option<Vec<FilterRule>>>>,
    pub online_change: Option<HashMap<String, bool>>,
    #[serde(rename = "DNSConfig")]
    pub dns_config: Option<DnsConfig>,
    pub domain: String,
    pub user_profiles: Option<Vec<UserProfile>>,
    pub health: Option<Vec<String>>,
    pub control_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_derp_parsing() {
        let n: Node = serde_json::from_str(
            r#"{"ID":1,"Key":"nodekey:00","DERP":"127.3.3.40:4","Addresses":["100.64.0.1/32"]}"#,
        )
        .unwrap();
        assert_eq!(n.home_derp_region(), Some(4));
        let n: Node = serde_json::from_str(r#"{"HomeDERP":7}"#).unwrap();
        assert_eq!(n.home_derp_region(), Some(7));
    }

    #[test]
    fn packet_filter_parsing() {
        let m: MapResponse = serde_json::from_str(
            r#"{"PacketFilter":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}],"IPProto":[6,17]}],
                "PacketFilters":{"*":[{"SrcIPs":["100.64.0.1"],"DstPorts":[{"IP":"100.64.0.2/32","Ports":{"First":22,"Last":22}}]}],"old":null}}"#,
        )
        .unwrap();
        let pf = m.packet_filter.unwrap();
        assert_eq!(pf[0].src_ips, vec!["*"]);
        assert_eq!(pf[0].dst_ports[0].ports.last, 65535);
        assert_eq!(pf[0].ip_proto, vec![6, 17]);
        let pfs = m.packet_filters.unwrap();
        assert_eq!(pfs["*"].as_ref().unwrap()[0].dst_ports[0].ports.first, 22);
        assert!(pfs["old"].is_none());
        let m: MapResponse = serde_json::from_str(r#"{"PacketFilter":[]}"#).unwrap();
        assert_eq!(m.packet_filter.unwrap().len(), 0);
        let m: MapResponse = serde_json::from_str(r#"{"KeepAlive":true}"#).unwrap();
        assert!(m.packet_filter.is_none() && m.packet_filters.is_none());
    }

    #[test]
    fn register_request_json_shape() {
        let r = RegisterRequest {
            version: 106,
            node_key: "nodekey:ab".into(),
            expiry: ZERO_TIME.into(),
            ..Default::default()
        };
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["Version"], 106);
        assert_eq!(j["NodeKey"], "nodekey:ab");
        assert!(j.get("Auth").is_none());
        assert!(j.get("Ephemeral").is_none());
        let h = serde_json::to_value(Hostinfo {
            os: "linux".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(h["OS"], "linux");
        assert!(h.get("IPNVersion").is_some());
    }
}
