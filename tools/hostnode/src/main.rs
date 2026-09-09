//! Host-side harness for the `tsnode` stack.
//!
//! Subcommands:
//!   probe-control [URL]
//!       fetch /key, run the ts2021 handshake and a register request without an
//!       auth key (expects an AuthURL back).
//!   run --authkey K [--hostname H] [--control URL] [--port 35932] [--state FILE]
//!       join the tailnet and serve a TCP echo on the port; prints status.

mod tls;

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tsnode::control::{hostinfo, ControlClient};
use tsnode::keys::{fmt_node_pub, KeyPair};
use tsnode::node::{Node, NodeConfig, NodeState, Store};
use tsnode::types::*;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("probe-control") => probe_control(
            args.get(2)
                .map(|s| s.as_str())
                .unwrap_or("https://controlplane.tailscale.com"),
        ),
        Some("run") => run(&args[2..]),
        _ => {
            eprintln!("usage:\n  hostnode probe-control [URL]\n  hostnode run --authkey K [--hostname H] [--control URL] [--port 35932] [--state FILE]");
            std::process::exit(2);
        }
    }
}

fn probe_control(url: &str) {
    let dialer = Arc::new(tls::HostDialer::new());
    let machine = KeyPair::generate();
    let node = KeyPair::generate();
    let client = ControlClient::connect(dialer, url, machine).expect("fetch server key");
    let req = RegisterRequest {
        version: CAPABILITY_VERSION,
        node_key: fmt_node_pub(node.public()),
        old_node_key: fmt_node_pub(&[0u8; 32]),
        auth: None,
        expiry: ZERO_TIME.into(),
        followup: String::new(),
        hostinfo: hostinfo("tsnode-probe", env!("CARGO_PKG_VERSION"), 0),
        ephemeral: false,
    };
    match client.register(&req) {
        Ok(resp) => {
            println!("register OK");
            println!("  MachineAuthorized: {}", resp.machine_authorized);
            println!("  AuthURL: {}", resp.auth_url);
            println!("  Error: {:?}", resp.error);
        }
        Err(e) => {
            eprintln!("register failed: {e}");
            std::process::exit(1);
        }
    }
}

/// JSON-file backed store.
struct FileStore {
    path: String,
    data: Mutex<HashMap<String, String>>,
}

impl FileStore {
    fn open(path: &str) -> Self {
        let data = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json_lite::parse_map(&s))
            .unwrap_or_default();
        FileStore {
            path: path.to_string(),
            data: Mutex::new(data),
        }
    }
    fn flush(&self, data: &HashMap<String, String>) -> std::io::Result<()> {
        let mut f = std::fs::File::create(&self.path)?;
        f.write_all(serde_json_lite::to_string(data).as_bytes())
    }
}

impl Store for FileStore {
    fn get(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }
    fn set(&self, key: &str, value: &str) -> std::io::Result<()> {
        let mut d = self.data.lock().unwrap();
        d.insert(key.to_string(), value.to_string());
        self.flush(&d)
    }
    fn remove(&self, key: &str) -> std::io::Result<()> {
        let mut d = self.data.lock().unwrap();
        d.remove(key);
        self.flush(&d)
    }
}

/// Just enough JSON for a flat string map, to avoid pulling serde into the tool.
mod serde_json_lite {
    use std::collections::HashMap;

    pub fn to_string(m: &HashMap<String, String>) -> String {
        let mut s = String::from("{\n");
        let mut keys: Vec<_> = m.keys().collect();
        keys.sort();
        for (i, k) in keys.iter().enumerate() {
            s.push_str(&format!(
                "  \"{}\": \"{}\"{}\n",
                esc(k),
                esc(&m[*k]),
                if i + 1 < keys.len() { "," } else { "" }
            ));
        }
        s.push('}');
        s
    }
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    pub fn parse_map(s: &str) -> Option<HashMap<String, String>> {
        let mut m = HashMap::new();
        for line in s.lines() {
            let line = line.trim().trim_end_matches(',');
            if !line.starts_with('"') {
                continue;
            }
            let (k, v) = line.split_once("\": \"")?;
            let k = k.trim_start_matches('"');
            let v = v.trim_end_matches('"');
            m.insert(
                k.replace("\\\"", "\"").replace("\\\\", "\\"),
                v.replace("\\\"", "\"").replace("\\\\", "\\"),
            );
        }
        Some(m)
    }
}

fn run(args: &[String]) {
    let mut cfg = NodeConfig {
        hostname: "hostnode".into(),
        worker_stack: 256 * 1024,
        control_stack: 1024 * 1024,
        ..Default::default()
    };
    let mut port = 2300u16;
    let mut state = "hostnode-state.json".to_string();
    let mut i = 0;
    while i < args.len() {
        let v = args.get(i + 1).cloned();
        match args[i].as_str() {
            "--authkey" => cfg.auth_key = v,
            "--hostname" => cfg.hostname = v.unwrap_or_default(),
            "--control" => cfg.control_url = v.unwrap_or_default(),
            "--port" => port = v.and_then(|p| p.parse().ok()).unwrap_or(35932),
            "--state" => state = v.unwrap_or_default(),
            "--udp-port" => cfg.udp_port = v.and_then(|p| p.parse().ok()).unwrap_or(41641),
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
        i += 2;
    }
    let store = Arc::new(FileStore::open(&state));
    if store.get("registered").is_none() && cfg.auth_key.is_none() {
        log::info!("no --authkey: an approval URL will be printed; open it in a browser");
    }
    let dialer = Arc::new(tls::HostDialer::new());
    let node = Node::start(cfg, store, dialer).expect("start node");
    let listener = node.listen(port);

    let status_node = node.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(10));
        let s = status_node.status();
        let peers: Vec<String> = s
            .peers
            .iter()
            .filter(|p| p.active || p.has_session)
            .map(|p| {
                format!(
                    "{}{}",
                    p.name,
                    p.direct
                        .map(|d| format!("@{d}"))
                        .unwrap_or_else(|| "@derp".into())
                )
            })
            .collect();
        log::info!(
            "status: {:?} addrs={:?} name={} derp={}{} endpoints={:?} peers={} active=[{}] updates={}",
            s.state,
            s.addresses,
            s.dns_name,
            s.home_derp,
            if s.derp_connected { "(up)" } else { "(down)" },
            s.endpoints,
            s.peers.len(),
            peers.join(","),
            s.map_updates
        );
        if let NodeState::NeedsLogin(url) = &s.state {
            log::warn!("visit {url} to approve this node");
        }
    });

    log::info!("echo server on tailnet port {port}; connect with: nc <this-node> {port}");
    loop {
        let Some(conn) = listener.accept(Duration::from_secs(1)) else {
            continue;
        };
        log::info!("client connected from {}", conn.peer_addr());
        std::thread::spawn(move || {
            let _ = conn.write_all(b"hostnode echo: type and it comes back\r\n");
            let mut buf = [0u8; 1024];
            loop {
                match conn.read(&mut buf, Duration::from_secs(60)) {
                    Ok(0) => break,
                    Ok(n) => {
                        if conn.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(_) => break,
                }
            }
            log::info!("client disconnected");
        });
    }
}
