//! Interactive setup shell shared by the UART0 console and the USB CDC
//! console. Platform-independent: I/O goes through [`Console`], device
//! actions through [`Platform`], so the wizard is unit-tested on the host.

use std::time::{Duration, Instant};

/// Byte-oriented terminal.
pub trait Console {
    /// Returns the next byte, or `None` if nothing arrived within `timeout`.
    fn read_byte(&mut self, timeout: Duration) -> Option<u8>;
    fn write(&mut self, s: &str);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApInfo {
    pub ssid: String,
    pub rssi: i8,
    pub secure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WifiNetwork {
    pub ssid: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SavedConfig {
    /// Known networks; the strongest visible one is used.
    pub networks: Vec<WifiNetwork>,
    pub hostname: String,
    pub auth_key: Option<String>,
    pub tcp_port: Option<u16>,
    pub baud_rate: Option<u32>,
    /// USB interface index of the target's console (devices such as the
    /// Raspberry Pi Debug Probe expose the UART on interface 1).
    pub usb_interface: Option<u8>,
    /// Forced USB serial driver name (`cdc`, `ftdi`, `cp210x`, `ch34x`);
    /// `None` auto-detects from the device's vendor and product ID.
    pub usb_driver: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    /// Node not started (setup mode before `login`).
    Off,
    Connecting,
    NeedsLogin(String),
    Running {
        addresses: Vec<String>,
        dns_name: String,
    },
    Error(String),
}

#[derive(Debug, Clone, Default)]
pub struct StatusSnapshot {
    pub firmware: String,
    pub setup_mode: bool,
    pub wifi: String,
    pub node: Option<NodeState>,
    pub derp: String,
    pub peers: String,
    pub usb: String,
    pub heap: String,
}

/// Device actions the shell can perform. Methods take `&self`; implementors
/// use interior mutability so several consoles can share one platform.
pub trait Platform {
    fn status(&self) -> StatusSnapshot;
    fn scan_wifi(&self) -> Result<Vec<ApInfo>, String>;
    /// Connects and waits for an IP address; returns it as text.
    fn connect_wifi(&self, ssid: &str, password: &str) -> Result<String, String>;
    /// Reconnects to the strongest visible known network.
    fn reconnect_wifi(&self) -> Result<String, String>;
    fn config(&self) -> Option<SavedConfig>;
    fn save_config(&self, cfg: &SavedConfig) -> Result<(), String>;
    /// Starts the Tailscale node with the saved configuration (idempotent).
    fn start_node(&self) -> Result<(), String>;
    fn node_state(&self) -> NodeState;
    /// True once the node has completed Tailscale registration.
    fn is_registered(&self) -> bool {
        false
    }
    /// Erases configuration and node identity.
    fn factory_reset(&self) -> Result<(), String>;
    fn reboot(&self) -> !;
}

const PROMPT: &str = "> ";
const LOGIN_WAIT: Duration = Duration::from_secs(600);

pub struct Shell<'a, C: Console, P: Platform> {
    console: &'a mut C,
    platform: &'a P,
    /// The previous line ended with CR; a directly following LF is ignored.
    swallow_lf: bool,
}

/// Reads a line with minimal editing (backspace) and optional echo.
/// Returns `None` if the console reports nothing for `idle_timeout`
/// before any key was typed (used to keep UART0 quiet).
pub fn read_line(
    console: &mut dyn Console,
    echo: bool,
    idle_timeout: Option<Duration>,
    swallow_lf: &mut bool,
) -> Option<String> {
    let mut line: Vec<u8> = Vec::new();
    let first_deadline = idle_timeout.map(|t| Instant::now() + t);
    loop {
        let timeout = match first_deadline {
            Some(d) if line.is_empty() => {
                let now = Instant::now();
                if now >= d {
                    return None;
                }
                (d - now).min(Duration::from_millis(500))
            }
            _ => Duration::from_millis(500),
        };
        let Some(b) = console.read_byte(timeout) else {
            continue;
        };
        // Terminals sending CR LF must not produce an extra empty line.
        let skip = b == b'\n' && *swallow_lf;
        *swallow_lf = b == b'\r';
        if skip {
            continue;
        }
        match b {
            b'\r' | b'\n' => {
                console.write("\r\n");
                return Some(String::from_utf8_lossy(&line).trim().to_string());
            }
            0x08 | 0x7f => {
                if line.pop().is_some() && echo {
                    console.write("\x08 \x08");
                }
            }
            0x03 => {
                // Ctrl-C: abandon the line.
                console.write("^C\r\n");
                return Some(String::new());
            }
            0x20..=0x7e if line.len() < 200 => {
                line.push(b);
                if echo {
                    console.write(std::str::from_utf8(&[b]).unwrap_or(""));
                } else {
                    console.write("*");
                }
            }
            _ => {}
        }
    }
}

impl<'a, C: Console, P: Platform> Shell<'a, C, P> {
    pub fn new(console: &'a mut C, platform: &'a P) -> Self {
        Shell {
            console,
            platform,
            swallow_lf: false,
        }
    }

    fn out(&mut self, s: &str) {
        self.console.write(s);
    }

    fn line(&mut self, s: &str) {
        self.console.write(s);
        self.console.write("\r\n");
    }

    fn ask(&mut self, prompt: &str, echo: bool) -> String {
        self.out(prompt);
        read_line(self.console, echo, None, &mut self.swallow_lf).unwrap_or_default()
    }

    pub fn banner(&mut self) {
        let st = self.platform.status();
        self.line("");
        self.line(&format!(
            "usb-serial-over-tailscale {} - {}",
            st.firmware,
            if st.setup_mode {
                "setup mode"
            } else {
                "normal mode"
            }
        ));
        self.line("Type 'help' for commands, 'setup' for the setup wizard.");
    }

    /// Command loop. With `idle_prompt` set, the prompt is only shown after
    /// the user presses a key (keeps a shared log port quiet).
    pub fn run(&mut self, auto_wizard: bool, quiet: bool) {
        if !quiet {
            self.banner();
        }
        if auto_wizard {
            self.out("Press Enter to start setup, or type a command: ");
            let first =
                read_line(self.console, true, None, &mut self.swallow_lf).unwrap_or_default();
            if first.is_empty() {
                self.wizard(false);
            } else {
                self.dispatch(&first);
            }
        }
        loop {
            if !quiet {
                self.out(PROMPT);
            }
            let Some(cmd) = read_line(
                self.console,
                true,
                if quiet {
                    Some(Duration::from_secs(3600))
                } else {
                    None
                },
                &mut self.swallow_lf,
            ) else {
                continue;
            };
            if cmd.is_empty() {
                if quiet {
                    self.out(PROMPT);
                    let Some(cmd) = read_line(self.console, true, None, &mut self.swallow_lf)
                    else {
                        continue;
                    };
                    self.dispatch(&cmd);
                }
                continue;
            }
            self.dispatch(&cmd);
        }
    }

    pub fn dispatch(&mut self, cmd: &str) {
        let mut parts = cmd.split_whitespace();
        let Some(verb) = parts.next() else { return };
        let args: Vec<&str> = parts.collect();
        match verb {
            "help" | "?" => self.help(),
            "status" => self.status(),
            "setup" => match args.as_slice() {
                [] => self.wizard(false),
                ["all"] | ["full"] => self.wizard(true),
                _ => self.line("usage: setup | setup all"),
            },
            "scan" => {
                self.scan();
            }
            "connect" => match self.platform.reconnect_wifi() {
                Ok(ip) => self.line(&format!("Connected ({ip})")),
                Err(e) => self.line(&format!("Wi-Fi failed: {e}")),
            },
            "wifi" => match args.as_slice() {
                ["list"] => self.wifi_list(),
                ["forget", ssid] => {
                    let mut c = self.platform.config().unwrap_or_default();
                    let before = c.networks.len();
                    c.networks.retain(|n| n.ssid != *ssid);
                    if c.networks.len() == before {
                        self.line("no such network");
                    } else {
                        match self.platform.save_config(&c) {
                            Ok(()) => self.line("forgotten"),
                            Err(e) => self.line(&format!("save failed: {e}")),
                        }
                    }
                }
                [ssid] => {
                    self.set_wifi(ssid, "");
                }
                [ssid, pass @ ..] => {
                    self.set_wifi(ssid, &pass.join(" "));
                }
                _ => self.line("usage: wifi <ssid> [password] | wifi list | wifi forget <ssid>"),
            },
            "hostname" => match args.as_slice() {
                [h] => self.set_field(|c| c.hostname = h.to_string()),
                _ => self.line("usage: hostname <name>"),
            },
            "authkey" => match args.as_slice() {
                [k] if k.starts_with("tskey-") => self.set_field(|c| c.auth_key = Some(k.to_string())),
                _ => self.line("usage: authkey tskey-auth-... (optional; otherwise 'login' prints an approval URL)"),
            },
            "port" => match args.first().and_then(|p| p.parse::<u16>().ok()) {
                Some(p) if p != 0 => self.set_field(|c| c.tcp_port = Some(p)),
                _ => self.line("usage: port <1-65535>"),
            },
            "usbdrv" => match args.first().copied() {
                Some("auto") => self.set_field(|c| c.usb_driver = None),
                Some(d @ ("cdc" | "ftdi" | "cp210x" | "ch34x")) => {
                    let d = d.to_string();
                    self.set_field(|c| c.usb_driver = Some(d))
                }
                _ => self.line("usage: usbdrv <auto|cdc|ftdi|cp210x|ch34x>"),
            },
            "usbif" => match args.first().and_then(|i| i.parse::<u8>().ok()) {
                Some(i) => self.set_field(|c| c.usb_interface = Some(i)),
                _ => self.line("usage: usbif <interface index> (0 is the first CDC interface; the Raspberry Pi Debug Probe's UART is 1)"),
            },
            "baud" => match args.first().and_then(|b| b.parse::<u32>().ok()) {
                Some(b) if b != 0 => self.set_field(|c| c.baud_rate = Some(b)),
                _ => self.line("usage: baud <rate>"),
            },
            "login" => {
                self.login();
            }
            "reboot" => {
                self.line("Rebooting...");
                self.platform.reboot();
            }
            "reset" => {
                let a = self.ask("Erase configuration and node identity? [y/N] ", true);
                if a.eq_ignore_ascii_case("y") {
                    match self.platform.factory_reset() {
                        Ok(()) => {
                            self.line("Erased. Rebooting...");
                            self.platform.reboot();
                        }
                        Err(e) => self.line(&format!("reset failed: {e}")),
                    }
                }
            }
            other => self.line(&format!("unknown command '{other}'; try 'help'")),
        }
    }

    fn help(&mut self) {
        for l in [
            "setup              wizard: Wi-Fi only if the rest is already set up",
            "setup all          wizard for everything (Wi-Fi, hostname, Tailscale login)",
            "status             show Wi-Fi / Tailscale / USB state",
            "scan               list Wi-Fi networks",
            "wifi <ssid> [pw]   add a Wi-Fi network and connect to it",
            "wifi list          list known networks; wifi forget <ssid> removes one",
            "connect            reconnect to the strongest known network",
            "hostname <name>    set the tailnet hostname",
            "authkey <key>      optional auth key for headless login",
            "login              register with Tailscale (prints approval URL)",
            "port <n>           TCP port of the serial bridge (default 35932)",
            "baud <rate>        USB serial baud rate (default 115200)",
            "usbif <n>          USB interface of the target console (default 0; Debug Probe UART is 1)",
            "usbdrv <name>      force the USB serial driver (auto/cdc/ftdi/cp210x/ch34x)",
            "reset              erase configuration and identity",
            "reboot             restart",
        ] {
            self.line(l);
        }
    }

    fn status(&mut self) {
        let st = self.platform.status();
        self.line(&format!(
            "Firmware:  {} ({})",
            st.firmware,
            if st.setup_mode {
                "setup mode"
            } else {
                "normal mode"
            }
        ));
        self.line(&format!("Wi-Fi:     {}", st.wifi));
        let node = match st.node.clone().unwrap_or(NodeState::Off) {
            NodeState::Off => "not started".to_string(),
            NodeState::Connecting => "connecting to control plane".into(),
            NodeState::NeedsLogin(url) => format!("waiting for approval at {url}"),
            NodeState::Running {
                addresses,
                dns_name,
            } => format!("running as {dns_name} {}", addresses.join(" ")),
            NodeState::Error(e) => format!("error: {e}"),
        };
        self.line(&format!("Tailscale: {node}"));
        self.line(&format!("DERP:      {}", st.derp));
        self.line(&format!("Peers:     {}", st.peers));
        self.line(&format!("USB:       {}", st.usb));
        self.line(&format!("Memory:    {}", st.heap));
        if let Some(c) = self.platform.config() {
            self.line(&format!(
                "Config:    networks={} hostname={} port={} baud={} usbif={} usbdrv={} authkey={}",
                c.networks
                    .iter()
                    .map(|n| n.ssid.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                c.hostname,
                c.tcp_port.unwrap_or(35932),
                c.baud_rate.unwrap_or(115200),
                c.usb_interface.unwrap_or(0),
                c.usb_driver.as_deref().unwrap_or("auto"),
                if c.auth_key.is_some() { "set" } else { "none" }
            ));
        } else {
            self.line("Config:    none");
        }
    }

    fn scan(&mut self) -> Vec<ApInfo> {
        self.line("Scanning Wi-Fi...");
        match self.platform.scan_wifi() {
            Ok(mut aps) => {
                aps.sort_by_key(|a| -(a.rssi as i32));
                aps.dedup_by(|a, b| a.ssid == b.ssid);
                aps.retain(|a| !a.ssid.is_empty());
                aps.truncate(15);
                for (i, ap) in aps.iter().enumerate() {
                    self.line(&format!(
                        "  {:>2}) {:<32} ({} dBm{})",
                        i + 1,
                        ap.ssid,
                        ap.rssi,
                        if ap.secure { "" } else { ", open" }
                    ));
                }
                if aps.is_empty() {
                    self.line("  no networks found");
                }
                aps
            }
            Err(e) => {
                self.line(&format!("scan failed: {e}"));
                Vec::new()
            }
        }
    }

    fn wifi_list(&mut self) {
        let c = self.platform.config().unwrap_or_default();
        if c.networks.is_empty() {
            self.line("no known networks");
        }
        for n in &c.networks {
            self.line(&format!("  {}", n.ssid));
        }
    }

    fn set_field(&mut self, f: impl FnOnce(&mut SavedConfig)) {
        let mut c = self.platform.config().unwrap_or_default();
        f(&mut c);
        match self.platform.save_config(&c) {
            Ok(()) => self.line("saved"),
            Err(e) => self.line(&format!("save failed: {e}")),
        }
    }

    fn set_wifi(&mut self, ssid: &str, password: &str) -> bool {
        if !password.is_empty() && (password.len() < 8 || password.len() > 63) {
            self.line("password must be 8..63 characters (or empty for an open network)");
            return false;
        }
        self.line(&format!("Connecting to {ssid}..."));
        match self.platform.connect_wifi(ssid, password) {
            Ok(ip) => {
                self.line(&format!("Connected ({ip})"));
                let mut c = self.platform.config().unwrap_or_default();
                c.networks.retain(|n| n.ssid != ssid);
                c.networks.push(WifiNetwork {
                    ssid: ssid.to_string(),
                    password: password.to_string(),
                });
                if let Err(e) = self.platform.save_config(&c) {
                    self.line(&format!("save failed: {e}"));
                    return false;
                }
                true
            }
            Err(e) => {
                self.line(&format!("Wi-Fi failed: {e}"));
                false
            }
        }
    }

    /// Starts the node and waits for approval/running. Returns true when running.
    fn login(&mut self) -> bool {
        let Some(cfg) = self.platform.config() else {
            self.line("configure Wi-Fi first (setup or wifi <ssid> <pw>)");
            return false;
        };
        if cfg.networks.is_empty() {
            self.line("configure Wi-Fi first (setup or wifi <ssid> <pw>)");
            return false;
        }
        if let Err(e) = self.platform.start_node() {
            self.line(&format!("cannot start node: {e}"));
            return false;
        }
        self.line("Registering with Tailscale... (press q to stop waiting)");
        let deadline = Instant::now() + LOGIN_WAIT;
        let mut shown_url: Option<String> = None;
        let mut last_state: Option<NodeState> = None;
        while Instant::now() < deadline {
            let st = self.platform.node_state();
            if last_state.as_ref() != Some(&st) {
                match &st {
                    NodeState::NeedsLogin(url) if shown_url.as_deref() != Some(url.as_str()) => {
                        self.line("Open this URL in a browser to approve the device:");
                        self.line(&format!("  {url}"));
                        self.line("Waiting for approval...");
                        shown_url = Some(url.clone());
                    }
                    NodeState::Running {
                        addresses,
                        dns_name,
                    } => {
                        self.line(&format!(
                            "Tailscale is up: {} {}",
                            dns_name,
                            addresses.join(" ")
                        ));
                        return true;
                    }
                    NodeState::Error(e) => self.line(&format!("  {e} (retrying)")),
                    _ => {}
                }
                last_state = Some(st);
                continue;
            }
            if let Some(b) = self.console.read_byte(Duration::from_millis(500)) {
                if b == b'q' || b == 0x03 {
                    self.line("stopped waiting; the node keeps trying in the background");
                    return false;
                }
            }
        }
        self.line("timed out waiting for approval; run 'login' again later");
        false
    }

    /// Setup wizard. Without `full`, a device whose hostname and Tailscale
    /// login are already done only gets the Wi-Fi step.
    pub fn wizard(&mut self, full: bool) {
        self.line("");
        self.line(if full {
            "=== Setup (all) ==="
        } else {
            "=== Setup ==="
        });
        // Wi-Fi
        let existing = self.platform.config().unwrap_or_default();
        let mut wifi_ok = false;
        loop {
            let aps = self.scan();
            let sel = self.ask(
                "Select network number, or type an SSID (Enter to rescan, q to quit): ",
                true,
            );
            if sel.is_empty() {
                continue;
            }
            if sel == "q" {
                self.line("Setup aborted; type 'setup' to start again.");
                return;
            }
            let (ssid, secure) = match sel.parse::<usize>() {
                Ok(n) if n >= 1 && n <= aps.len() => (aps[n - 1].ssid.clone(), aps[n - 1].secure),
                _ => (sel, true),
            };
            let password = if secure {
                self.ask(&format!("Password for {ssid}: "), false)
            } else {
                String::new()
            };
            if self.set_wifi(&ssid, &password) {
                wifi_ok = true;
                break;
            }
            let again = self.ask("Try again? [Y/n] ", true);
            if again.eq_ignore_ascii_case("n") {
                break;
            }
        }
        if !wifi_ok {
            self.line("Wi-Fi not configured; run 'setup' again later.");
            return;
        }
        if !full && !existing.hostname.is_empty() && self.platform.is_registered() {
            self.line("Wi-Fi updated; hostname and Tailscale login are already set up ('setup all' redoes everything).");
            if self.platform.status().setup_mode {
                self.line("Type 'reboot' to switch to normal mode.");
            }
            return;
        }
        // Hostname
        let default_host = if existing.hostname.is_empty() {
            "target-console".to_string()
        } else {
            existing.hostname.clone()
        };
        let host = loop {
            let h = self.ask(&format!("Hostname on the tailnet [{default_host}]: "), true);
            let h = if h.is_empty() {
                default_host.clone()
            } else {
                h
            };
            if valid_hostname(&h) {
                break h;
            }
            self.line("use 1..63 letters, digits or hyphens");
        };
        let mut c = self.platform.config().unwrap_or_default();
        c.hostname = host;
        if let Err(e) = self.platform.save_config(&c) {
            self.line(&format!("save failed: {e}"));
            return;
        }
        // Tailscale
        if self.login() {
            let a = self.ask("Setup complete. Reboot into normal mode now? [Y/n] ", true);
            if !a.eq_ignore_ascii_case("n") {
                self.line("Rebooting. Connect the adapter's USB port to the target board.");
                self.platform.reboot();
            }
        }
    }
}

pub fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 63
        && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !h.starts_with('-')
        && !h.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct FakeConsole {
        input: VecDeque<u8>,
        output: String,
        strict: bool,
    }
    impl Console for FakeConsole {
        fn read_byte(&mut self, _t: Duration) -> Option<u8> {
            let b = self.input.pop_front();
            if b.is_none() && self.strict {
                panic!("input exhausted; output so far:\n{}", self.output);
            }
            b
        }
        fn write(&mut self, s: &str) {
            self.output.push_str(s);
        }
    }

    #[derive(Default)]
    struct FakePlatform {
        cfg: RefCell<Option<SavedConfig>>,
        node_started: RefCell<bool>,
        polls: RefCell<u32>,
        rebooted: RefCell<bool>,
    }
    impl Platform for FakePlatform {
        fn status(&self) -> StatusSnapshot {
            StatusSnapshot {
                firmware: "t".into(),
                setup_mode: true,
                ..Default::default()
            }
        }
        fn scan_wifi(&self) -> Result<Vec<ApInfo>, String> {
            Ok(vec![
                ApInfo {
                    ssid: "weak".into(),
                    rssi: -80,
                    secure: true,
                },
                ApInfo {
                    ssid: "home".into(),
                    rssi: -50,
                    secure: true,
                },
                ApInfo {
                    ssid: "home".into(),
                    rssi: -60,
                    secure: true,
                },
            ])
        }
        fn connect_wifi(&self, ssid: &str, password: &str) -> Result<String, String> {
            if ssid == "home" && password == "secret123" {
                Ok("192.168.1.42".into())
            } else {
                Err("auth failed".into())
            }
        }
        fn reconnect_wifi(&self) -> Result<String, String> {
            Err("no radio".into())
        }
        fn config(&self) -> Option<SavedConfig> {
            self.cfg.borrow().clone()
        }
        fn save_config(&self, cfg: &SavedConfig) -> Result<(), String> {
            *self.cfg.borrow_mut() = Some(cfg.clone());
            Ok(())
        }
        fn start_node(&self) -> Result<(), String> {
            *self.node_started.borrow_mut() = true;
            Ok(())
        }
        fn node_state(&self) -> NodeState {
            let mut p = self.polls.borrow_mut();
            *p += 1;
            match *p {
                1 => NodeState::Connecting,
                2 => NodeState::NeedsLogin("https://login.tailscale.com/a/abc".into()),
                _ => NodeState::Running {
                    addresses: vec!["100.64.0.9".into()],
                    dns_name: "target-console.example.ts.net".into(),
                },
            }
        }
        fn factory_reset(&self) -> Result<(), String> {
            Ok(())
        }
        fn reboot(&self) -> ! {
            *self.rebooted.borrow_mut() = true;
            panic!("reboot");
        }
    }

    #[test]
    fn wizard_end_to_end() {
        // Select network 1 (home, strongest after sort/dedup), wrong password once, then right one,
        // accept default hostname, then decline reboot.
        let input = b"1\rwrongpass\r\r1\rsecret123\r\rn\r".to_vec();
        let mut con = FakeConsole {
            input: input.into(),
            output: String::new(),
            strict: true,
        };
        let plat = FakePlatform::default();
        let mut sh = Shell::new(&mut con, &plat);
        sh.wizard(false);
        let out = con.output.clone();
        assert!(out.contains("1) home"), "{out}");
        assert!(out.contains("Wi-Fi failed: auth failed"), "{out}");
        assert!(out.contains("Connected (192.168.1.42)"), "{out}");
        assert!(out.contains("https://login.tailscale.com/a/abc"), "{out}");
        assert!(
            out.contains("Tailscale is up: target-console.example.ts.net 100.64.0.9"),
            "{out}"
        );
        let cfg = plat.config().unwrap();
        assert_eq!(
            cfg.networks,
            vec![WifiNetwork {
                ssid: "home".into(),
                password: "secret123".into()
            }]
        );
        assert_eq!(cfg.hostname, "target-console");
        assert!(*plat.node_started.borrow());
        assert!(!*plat.rebooted.borrow());
        // Password was masked.
        assert!(!out.contains("secret123"));
    }

    #[test]
    fn commands_and_line_editing() {
        let plat = FakePlatform::default();
        let mut con = FakeConsole {
            input: b"hostname my-host\rauthkey nope\rport 2301\rbaud 9600\rstatus\r"
                .to_vec()
                .into(),
            output: String::new(),
            strict: true,
        };
        {
            let mut sh = Shell::new(&mut con, &plat);
            for _ in 0..5 {
                let cmd = read_line(sh.console, true, None, &mut sh.swallow_lf).unwrap();
                sh.dispatch(&cmd);
            }
        }
        let cfg = plat.config().unwrap();
        assert_eq!(cfg.hostname, "my-host");
        assert_eq!(cfg.auth_key, None);
        assert_eq!(cfg.tcp_port, Some(2301));
        assert_eq!(cfg.baud_rate, Some(9600));
        assert!(con.output.contains("usage: authkey"));
        assert!(con
            .output
            .contains("Config:    networks= hostname=my-host port=2301 baud=9600 usbif=0 usbdrv=auto authkey=none"));

        let mut con = FakeConsole {
            input: b"abd\x7fc\r".to_vec().into(),
            output: String::new(),
            strict: true,
        };
        assert_eq!(read_line(&mut con, true, None, &mut false).unwrap(), "abc");
        // CR LF line endings yield one line each, not a line and an empty one.
        let mut con = FakeConsole {
            input: b"one\r\ntwo\r\n".to_vec().into(),
            output: String::new(),
            strict: true,
        };
        let mut sw = false;
        assert_eq!(read_line(&mut con, true, None, &mut sw).unwrap(), "one");
        assert_eq!(read_line(&mut con, true, None, &mut sw).unwrap(), "two");
        let mut con = FakeConsole {
            input: VecDeque::new(),
            output: String::new(),
            strict: false,
        };
        assert_eq!(
            read_line(&mut con, true, Some(Duration::from_millis(1)), &mut false),
            None
        );
    }
}
