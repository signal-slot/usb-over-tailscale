//! NVS-backed persistent storage: node identity (via `tsnode::node::Store`)
//! and the device configuration entered through the setup shell.

use adapter_core::shell::{SavedConfig, WifiNetwork};
use anyhow::Result;
use esp_idf_svc::nvs::{EspNvs, EspNvsPartition, NvsDefault};
use std::sync::Mutex;
use tsnode::node::Store;

/// NVS strings can hold up to 4000 bytes; read with a buffer of that size so
/// a long Wi-Fi list never fails to load (which would look like "unconfigured").
const MAX_VALUE: usize = 4000;

pub struct NvsStore {
    nvs: Mutex<EspNvs<NvsDefault>>,
}

impl NvsStore {
    pub fn open(partition: EspNvsPartition<NvsDefault>, namespace: &str) -> Result<Self> {
        let nvs = EspNvs::new(partition, namespace, true)?;
        Ok(NvsStore {
            nvs: Mutex::new(nvs),
        })
    }
}

impl Store for NvsStore {
    fn get(&self, key: &str) -> Option<String> {
        let nvs = self.nvs.lock().unwrap();
        let mut buf = vec![0u8; MAX_VALUE];
        match nvs.get_str(key, &mut buf) {
            Ok(Some(s)) => Some(s.to_string()),
            _ => None,
        }
    }

    fn set(&self, key: &str, value: &str) -> std::io::Result<()> {
        let nvs = self.nvs.lock().unwrap();
        nvs.set_str(key, value)
            .map_err(|e| std::io::Error::other(format!("nvs set {key}: {e}")))
    }

    fn remove(&self, key: &str) -> std::io::Result<()> {
        let nvs = self.nvs.lock().unwrap();
        nvs.remove(key)
            .map(|_| ())
            .map_err(|e| std::io::Error::other(format!("nvs remove {key}: {e}")))
    }
}

/// Keys are limited to 15 characters by NVS.
const K_SSID: &str = "wifi_ssid";
const K_PASS: &str = "wifi_password";
const K_NETS: &str = "wifi_list";
const K_AUTH: &str = "auth_key";
const K_HOST: &str = "hostname";
const K_PORT: &str = "tcp_port";
const K_BAUD: &str = "baud_rate";
const K_USBIF: &str = "usb_if";
const K_USBDRV: &str = "usb_drv";

const ALL_KEYS: &[&str] = &[
    K_SSID,
    K_PASS,
    K_NETS,
    K_AUTH,
    K_HOST,
    K_PORT,
    K_BAUD,
    K_USBIF,
    K_USBDRV,
    tsnode::node::KEY_MACHINE,
    tsnode::node::KEY_NODE,
    tsnode::node::KEY_DISCO,
    tsnode::node::KEY_REGISTERED,
    tsnode::node::KEY_HOME_DERP,
];

/// Known networks are stored as one NVS string: `ssid<TAB>password<LF>...`.
fn parse_networks(text: &str) -> Vec<WifiNetwork> {
    text.lines()
        .filter_map(|l| {
            let (ssid, pw) = l.split_once('\t')?;
            if ssid.is_empty() {
                return None;
            }
            Some(WifiNetwork {
                ssid: ssid.to_string(),
                password: pw.to_string(),
            })
        })
        .collect()
}

fn format_networks(nets: &[WifiNetwork]) -> String {
    nets.iter()
        .map(|n| format!("{}\t{}\n", n.ssid, n.password))
        .collect()
}

/// Returns the saved configuration if at least one Wi-Fi network is known.
pub fn load_config(store: &dyn Store) -> Option<SavedConfig> {
    let mut networks = store
        .get(K_NETS)
        .map(|t| parse_networks(&t))
        .unwrap_or_default();
    // Migration from the single-network keys.
    if let Some(ssid) = store.get(K_SSID).filter(|s| !s.is_empty()) {
        if !networks.iter().any(|n| n.ssid == ssid) {
            networks.push(WifiNetwork {
                ssid,
                password: store.get(K_PASS).unwrap_or_default(),
            });
        }
    }
    if networks.is_empty() {
        return None;
    }
    Some(SavedConfig {
        networks,
        hostname: store.get(K_HOST).unwrap_or_default(),
        auth_key: store.get(K_AUTH).filter(|k| !k.is_empty()),
        tcp_port: store.get(K_PORT).and_then(|p| p.parse().ok()),
        baud_rate: store.get(K_BAUD).and_then(|b| b.parse().ok()),
        usb_interface: store.get(K_USBIF).and_then(|i| i.parse().ok()),
        usb_driver: store.get(K_USBDRV).filter(|d| !d.is_empty()),
    })
}

/// Stores the configuration. A new auth key means the node must register
/// again, so the registration flag is cleared in that case. The hostname
/// travels in every map request and needs no re-registration.
pub fn save_config(store: &dyn Store, cfg: &SavedConfig) -> std::io::Result<()> {
    let old = load_config(store);
    let identity_changed = match &old {
        Some(o) => cfg.auth_key.is_some() && o.auth_key != cfg.auth_key,
        None => true,
    };
    store.set(K_NETS, &format_networks(&cfg.networks))?;
    let _ = store.remove(K_SSID);
    let _ = store.remove(K_PASS);
    store.set(K_HOST, &cfg.hostname)?;
    set_or_remove(store, K_AUTH, cfg.auth_key.as_deref())?;
    set_or_remove(
        store,
        K_PORT,
        cfg.tcp_port.map(|p| p.to_string()).as_deref(),
    )?;
    set_or_remove(
        store,
        K_BAUD,
        cfg.baud_rate.map(|b| b.to_string()).as_deref(),
    )?;
    set_or_remove(
        store,
        K_USBIF,
        cfg.usb_interface.map(|i| i.to_string()).as_deref(),
    )?;
    set_or_remove(store, K_USBDRV, cfg.usb_driver.as_deref())?;
    if identity_changed {
        let _ = store.remove(tsnode::node::KEY_REGISTERED);
        let _ = store.remove(tsnode::node::KEY_HOME_DERP);
    }
    Ok(())
}

fn set_or_remove(store: &dyn Store, key: &str, value: Option<&str>) -> std::io::Result<()> {
    match value {
        Some(v) => store.set(key, v),
        None => store.remove(key).or(Ok(())),
    }
}

pub fn is_registered(store: &dyn Store) -> bool {
    store.get(tsnode::node::KEY_REGISTERED).as_deref() == Some("1")
}

/// Forgets the auth key once it has done its job: it is a bearer credential
/// and has no business staying in flash (SOW section 12).
pub fn forget_auth_key(store: &dyn Store) -> std::io::Result<()> {
    store.remove(K_AUTH)
}

/// Erases configuration and node identity. NVS is log-structured, so a
/// removed key survives in older pages; the whole partition is erased
/// (Wi-Fi calibration data included) and the caller must reboot.
pub fn factory_reset(store: &dyn Store) -> std::io::Result<()> {
    for k in ALL_KEYS {
        let _ = store.remove(k);
    }
    let rc = unsafe { esp_idf_svc::sys::nvs_flash_erase() };
    if rc != esp_idf_svc::sys::ESP_OK {
        return Err(std::io::Error::other(format!(
            "nvs_flash_erase: esp_err {rc}"
        )));
    }
    Ok(())
}
