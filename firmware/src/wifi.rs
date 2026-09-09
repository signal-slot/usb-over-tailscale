//! Wi-Fi station: scanning, connecting to the strongest known network,
//! automatic reconnection.

use adapter_core::shell::{ApInfo, WifiNetwork};
use anyhow::Result;
use esp_idf_svc::eventloop::{EspSubscription, EspSystemEventLoop, System};
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::wifi::{AuthMethod, ClientConfiguration, Configuration, EspWifi, WifiEvent};
use log::{info, warn};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct WifiManager {
    wifi: Mutex<EspWifi<'static>>,
    /// Known networks (from the configuration).
    networks: Mutex<Vec<WifiNetwork>>,
    /// Network currently being used, if any.
    current: Mutex<Option<String>>,
    _events: Mutex<Option<EspSubscription<'static, System>>>,
}

impl WifiManager {
    /// Starts the station (unconfigured) and the reconnect monitor thread.
    pub fn new(
        modem: Modem<'static>,
        sysloop: EspSystemEventLoop,
        nvs: EspDefaultNvsPartition,
    ) -> Result<Arc<Self>> {
        let mut wifi = EspWifi::new(modem, sysloop.clone(), Some(nvs))?;
        wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
        wifi.start()?;
        // Power save adds tens of milliseconds of latency to every packet;
        // an interactive console is better off without it.
        unsafe {
            esp_idf_svc::sys::esp_wifi_set_ps(esp_idf_svc::sys::wifi_ps_type_t_WIFI_PS_NONE);
        }
        let events = sysloop
            .subscribe::<WifiEvent, _>(|e| match e {
                WifiEvent::StaDisconnected(d) => {
                    warn!(
                        "wifi: disconnected from {:?}, reason {}",
                        String::from_utf8_lossy(d.ssid()),
                        d.reason()
                    )
                }
                WifiEvent::StaConnected(_) => info!("wifi: associated"),
                WifiEvent::StaBeaconTimeout => warn!("wifi: beacon timeout"),
                other => log::debug!("wifi: event {other:?}"),
            })
            .ok();
        let mgr = Arc::new(WifiManager {
            wifi: Mutex::new(wifi),
            networks: Mutex::new(Vec::new()),
            current: Mutex::new(None),
            _events: Mutex::new(events),
        });
        let m = mgr.clone();
        std::thread::Builder::new()
            .name("wifi".into())
            .stack_size(6 * 1024)
            .spawn(move || m.monitor())?;
        Ok(mgr)
    }

    pub fn set_networks(&self, nets: Vec<WifiNetwork>) {
        *self.networks.lock().unwrap() = nets;
    }

    pub fn scan(&self) -> Result<Vec<ApInfo>> {
        let mut w = self.wifi.lock().unwrap();
        let aps = w.scan()?;
        Ok(aps
            .into_iter()
            .map(|a| ApInfo {
                ssid: a.ssid.to_string(),
                rssi: a.signal_strength,
                secure: !matches!(a.auth_method, Some(AuthMethod::None) | None),
            })
            .collect())
    }

    /// Applies credentials and waits up to `timeout` for an IP address.
    pub fn connect(&self, ssid: &str, password: &str, timeout: Duration) -> Result<Ipv4Addr> {
        {
            let mut w = self.wifi.lock().unwrap();
            let auth_method = if password.is_empty() {
                AuthMethod::None
            } else {
                AuthMethod::WPA2Personal
            };
            let conf = Configuration::Client(ClientConfiguration {
                ssid: ssid
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("ssid too long"))?,
                password: password
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("password too long"))?,
                auth_method,
                ..Default::default()
            });
            if w.is_connected().unwrap_or(false) {
                let _ = w.disconnect();
            }
            w.set_configuration(&conf)?;
            w.connect()?;
        }
        *self.current.lock().unwrap() = Some(ssid.to_string());
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(ip) = self.ip() {
                info!("wifi: connected to {ssid:?}, ip {ip}");
                return Ok(ip);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err(anyhow::anyhow!(
            "no IP address after {}s (wrong password or out of range?)",
            timeout.as_secs()
        ))
    }

    /// Scans and connects to the strongest known network.
    pub fn connect_best(&self, timeout: Duration) -> Result<Ipv4Addr> {
        let known = self.networks.lock().unwrap().clone();
        if known.is_empty() {
            return Err(anyhow::anyhow!("no known networks"));
        }
        let mut aps = self.scan()?;
        aps.sort_by_key(|a| -(a.rssi as i32));
        let Some(best) = aps.iter().find_map(|a| {
            known
                .iter()
                .find(|n| n.ssid == a.ssid)
                .map(|n| (n.clone(), a.rssi))
        }) else {
            let names: Vec<&str> = known.iter().map(|n| n.ssid.as_str()).collect();
            return Err(anyhow::anyhow!(
                "none of the known networks ({}) is in range",
                names.join(", ")
            ));
        };
        info!("wifi: choosing {:?} ({} dBm)", best.0.ssid, best.1);
        self.connect(&best.0.ssid, &best.0.password, timeout)
    }

    fn monitor(&self) {
        let mut was_up = false;
        let mut last_attempt = Instant::now();
        loop {
            std::thread::sleep(Duration::from_secs(2));
            if self.networks.lock().unwrap().is_empty() {
                continue;
            }
            let up = self.is_connected() && self.ip().is_some();
            if up && !was_up {
                info!("wifi: connected, ip {:?}", self.ip());
            } else if !up && was_up {
                warn!("wifi: disconnected");
            }
            was_up = up;
            if !up && last_attempt.elapsed() >= Duration::from_secs(20) {
                last_attempt = Instant::now();
                info!("wifi: reconnecting");
                if let Err(e) = self.connect_best(Duration::from_secs(15)) {
                    warn!("wifi: {e}");
                }
            }
        }
    }

    pub fn is_connected(&self) -> bool {
        self.wifi.lock().unwrap().is_connected().unwrap_or(false)
    }

    pub fn ip(&self) -> Option<Ipv4Addr> {
        let w = self.wifi.lock().unwrap();
        let info = w.sta_netif().get_ip_info().ok()?;
        if info.ip.is_unspecified() {
            None
        } else {
            Some(info.ip)
        }
    }

    pub fn describe(&self) -> String {
        let cur = self.current.lock().unwrap().clone();
        match (cur, self.ip()) {
            (None, _) => "not connected".into(),
            (Some(ssid), Some(ip)) => format!("connected to {ssid} ({ip})"),
            (Some(ssid), None) => format!("connecting to {ssid}"),
        }
    }
}
