//! `shell::Platform` for the ESP32: wires the setup shell to Wi-Fi, NVS, the
//! Tailscale node and the USB host driver.

use crate::nvs_store::{self, NvsStore};
use crate::tls::EspDialer;
use crate::usb_host::UsbSerial;
use crate::wifi::WifiManager;
use adapter_core::shell::{ApInfo, NodeState, Platform, SavedConfig, StatusSnapshot};
use esp_idf_svc::sys;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tsnode::net::Spawner;
use tsnode::node::{Node, NodeConfig, NodeState as TsState};

pub struct EspPlatform {
    pub store: Arc<NvsStore>,
    pub wifi: Arc<WifiManager>,
    pub node: Mutex<Option<Node>>,
    pub serial: Option<UsbSerial>,
    pub setup_mode: bool,
}

impl EspPlatform {
    pub fn node(&self) -> Option<Node> {
        self.node.lock().unwrap().clone()
    }

    /// Builds the node configuration from the saved settings.
    pub fn node_config(cfg: &SavedConfig) -> NodeConfig {
        NodeConfig {
            control_url: "https://controlplane.tailscale.com".into(),
            auth_key: cfg.auth_key.clone(),
            hostname: if cfg.hostname.is_empty() {
                "target-console".into()
            } else {
                cfg.hostname.clone()
            },
            version: crate::FIRMWARE_VERSION.into(),
            udp_port: 41641,
            local_ip: None,
            worker_stack: 20 * 1024,
            control_stack: 40 * 1024,
            fallback_region_code: "tok".into(),
            spawner: Some(spawner()),
        }
    }
}

impl Platform for EspPlatform {
    fn status(&self) -> StatusSnapshot {
        let node = self.node().map(|n| n.status());
        let (derp, peers) = match &node {
            Some(s) => (
                if s.home_derp == 0 {
                    "none".to_string()
                } else {
                    format!(
                        "region {}{}",
                        s.home_derp,
                        if s.derp_connected {
                            " (connected)"
                        } else {
                            " (down)"
                        }
                    )
                },
                {
                    let active: Vec<String> = s
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
                    format!(
                        "{} known, active: {}",
                        s.peers.len(),
                        if active.is_empty() {
                            "-".into()
                        } else {
                            active.join(", ")
                        }
                    )
                },
            ),
            None => ("-".into(), "-".into()),
        };
        let heap = unsafe {
            format!(
                "free {} KB, min {} KB, internal {} KB",
                sys::esp_get_free_heap_size() / 1024,
                sys::esp_get_minimum_free_heap_size() / 1024,
                sys::esp_get_free_internal_heap_size() / 1024
            )
        };
        StatusSnapshot {
            firmware: crate::FIRMWARE_VERSION.into(),
            setup_mode: self.setup_mode,
            wifi: self.wifi.describe(),
            node: Some(self.node_state()),
            derp,
            peers,
            usb: match &self.serial {
                Some(s) => format!("{} ({})", s.describe(), crate::usb_host::root_port_state()),
                None => "device mode (setup console)".into(),
            },
            heap,
        }
    }

    fn scan_wifi(&self) -> Result<Vec<ApInfo>, String> {
        self.wifi.scan().map_err(|e| e.to_string())
    }

    fn connect_wifi(&self, ssid: &str, password: &str) -> Result<String, String> {
        self.wifi
            .connect(ssid, password, Duration::from_secs(20))
            .map(|ip| ip.to_string())
            .map_err(|e| e.to_string())
    }

    fn reconnect_wifi(&self) -> Result<String, String> {
        if let Some(c) = self.config() {
            self.wifi.set_networks(c.networks);
        }
        self.wifi
            .connect_best(Duration::from_secs(30))
            .map(|ip| ip.to_string())
            .map_err(|e| e.to_string())
    }

    fn config(&self) -> Option<SavedConfig> {
        nvs_store::load_config(self.store.as_ref())
    }

    fn save_config(&self, cfg: &SavedConfig) -> Result<(), String> {
        nvs_store::save_config(self.store.as_ref(), cfg).map_err(|e| e.to_string())?;
        self.wifi.set_networks(cfg.networks.clone());
        Ok(())
    }

    fn start_node(&self) -> Result<(), String> {
        let mut slot = self.node.lock().unwrap();
        if slot.is_some() {
            return Ok(());
        }
        let cfg = self.config().ok_or("not configured")?;
        let node = Node::start(
            Self::node_config(&cfg),
            self.store.clone(),
            Arc::new(EspDialer),
        )
        .map_err(|e| e.to_string())?;
        if cfg.auth_key.is_some() {
            // Once registered the key is not needed again; drop it from flash.
            let (n, store) = (node.clone(), self.store.clone());
            let _ = spawn_thread(
                "authkey-scrub",
                6 * 1024,
                true,
                Box::new(move || {
                    while !matches!(n.status().state, TsState::Running) {
                        std::thread::sleep(Duration::from_secs(5));
                    }
                    match nvs_store::forget_auth_key(store.as_ref()) {
                        Ok(()) => log::info!("auth key removed from flash after registration"),
                        Err(e) => log::warn!("could not remove auth key: {e}"),
                    }
                }),
            );
        }
        *slot = Some(node);
        Ok(())
    }

    fn node_state(&self) -> NodeState {
        match self.node() {
            None => NodeState::Off,
            Some(n) => {
                let s = n.status();
                match s.state {
                    TsState::Starting | TsState::ConnectingControl | TsState::Registering => {
                        NodeState::Connecting
                    }
                    TsState::NeedsLogin(url) => NodeState::NeedsLogin(url),
                    TsState::Running => NodeState::Running {
                        addresses: s.addresses.iter().map(|a| a.to_string()).collect(),
                        dns_name: s.dns_name,
                    },
                    TsState::Error(e) => NodeState::Error(e),
                }
            }
        }
    }

    fn is_registered(&self) -> bool {
        nvs_store::is_registered(self.store.as_ref())
    }

    fn factory_reset(&self) -> Result<(), String> {
        nvs_store::factory_reset(self.store.as_ref()).map_err(|e| e.to_string())
    }

    fn reboot(&self) -> ! {
        std::thread::sleep(Duration::from_millis(300));
        unsafe { sys::esp_restart() }
    }
}

/// Thread spawner that puts the stacks of network worker threads in PSRAM.
/// Threads that may write flash (NVS) must keep internal-RAM stacks because
/// the flash cache is disabled during writes; only the control thread does.
pub fn spawner() -> Spawner {
    Arc::new(|name: &str, stack: usize, f: Box<dyn FnOnce() + Send>| {
        spawn_thread(name, stack, name != "control", f)
    })
}

pub fn spawn_thread(
    name: &str,
    stack: usize,
    psram: bool,
    f: Box<dyn FnOnce() + Send>,
) -> std::io::Result<()> {
    use esp_idf_svc::hal::task::thread::{MallocCap, ThreadSpawnConfiguration};
    let cfg = ThreadSpawnConfiguration {
        stack_size: stack,
        inherit: false,
        stack_alloc_caps: if psram {
            MallocCap::Spiram | MallocCap::Cap8bit
        } else {
            MallocCap::Internal | MallocCap::Cap8bit
        },
        ..Default::default()
    };
    cfg.set()
        .map_err(|e| std::io::Error::other(format!("thread config: {e}")))?;
    let r = std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(stack)
        .spawn(f)
        .map(|_| ());
    let _ = ThreadSpawnConfiguration::default().set();
    r
}
