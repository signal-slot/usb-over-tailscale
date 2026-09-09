//! USB Host with the CDC-ACM class driver: the target board's USB serial
//! console. Handles attach/detach without restarting anything else.

use adapter_core::usbserial::{ch34x_baud_registers, ftdi_baud_request, FtdiChip};
use anyhow::{anyhow, Result};
use esp_idf_svc::sys::{self, usb};
use log::{debug, info, warn};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const OUT_BUFFER: usize = 512;
const IN_BUFFER: usize = 512;
const RX_QUEUE_LIMIT: usize = 16 * 1024;

/// Vendor IDs of the USB-serial bridges we know how to drive beyond CDC-ACM.
const VID_FTDI: u16 = 0x0403;
const VID_SILABS: u16 = 0x10c4;
const VID_WCH: u16 = 0x1a86;

/// WCH product IDs that speak the vendor protocol. Newer parts (CH343, CH9102)
/// are CDC-ACM compliant and are handled by the CDC path instead.
const PID_CH34X: [u16; 5] = [0x5512, 0x5523, 0x5584, 0x7522, 0x7523];

/// How the attached device's serial port is configured and framed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Driver {
    /// A CDC-ACM compliant console (the Phase 1 target).
    Cdc,
    /// FTDI bridges: vendor control requests for the line settings, and a
    /// 2-byte status header on every IN packet. `chip` (from `bcdDevice`)
    /// selects the baud clock and the wIndex layout.
    Ftdi { packet_size: usize, chip: FtdiChip },
    /// Silicon Labs CP210x: vendor requests addressed to the interface.
    Cp210x,
    /// WCH CH340/CH341: vendor register writes with a computed divisor.
    Ch34x,
}

impl Driver {
    pub fn name(&self) -> &'static str {
        match self {
            Driver::Cdc => "CDC ACM",
            Driver::Ftdi { .. } => "FTDI",
            Driver::Cp210x => "CP210x",
            Driver::Ch34x => "CH34x",
        }
    }

    /// Parses a driver name from the shell (`auto` yields `None`).
    pub fn parse(name: &str) -> Option<Option<Driver>> {
        match name {
            "auto" => Some(None),
            "cdc" => Some(Some(Driver::Cdc)),
            "ftdi" => Some(Some(Driver::Ftdi {
                packet_size: 64,
                chip: FtdiChip::from_bcd_device(0x0800),
            })),
            "cp210x" => Some(Some(Driver::Cp210x)),
            "ch34x" => Some(Some(Driver::Ch34x)),
            _ => None,
        }
    }

    /// Picks a driver from the device's USB vendor and product ID and, for
    /// FTDI, the chip generation encoded in `bcdDevice`.
    fn detect(vid: u16, pid: u16, bcd_device: u16) -> Driver {
        match vid {
            VID_FTDI => Driver::ftdi_for(bcd_device),
            VID_SILABS => Driver::Cp210x,
            VID_WCH if PID_CH34X.contains(&pid) => Driver::Ch34x,
            _ => Driver::Cdc,
        }
    }

    fn ftdi_for(bcd_device: u16) -> Driver {
        Driver::Ftdi {
            packet_size: 64,
            chip: FtdiChip::from_bcd_device(bcd_device),
        }
    }

    /// A forced `ftdi` still takes the chip generation from the descriptor.
    fn refine(self, bcd_device: u16) -> Driver {
        match self {
            Driver::Ftdi { .. } => Driver::ftdi_for(bcd_device),
            d => d,
        }
    }
}

/// FTDI vendor requests (bmRequestType 0x40, host-to-device, vendor, device).
const FTDI_REQ_TYPE_OUT: u8 = 0x40;
const FTDI_SIO_RESET: u8 = 0x00;
const FTDI_SIO_SET_MODEM_CTRL: u8 = 0x01;
const FTDI_SIO_SET_FLOW_CTRL: u8 = 0x02;
const FTDI_SIO_SET_BAUDRATE: u8 = 0x03;
const FTDI_SIO_SET_DATA: u8 = 0x04;
const FTDI_SIO_SET_LATENCY_TIMER: u8 = 0x09;
/// Milliseconds the chip may hold received bytes before sending a short
/// packet (the power-on default of 16 ms makes a console feel sluggish).
const FTDI_LATENCY_MS: u16 = 2;

/// CP210x vendor requests (bmRequestType 0x41: host-to-device, vendor, interface).
const CP210X_REQ_TYPE_OUT: u8 = 0x41;
const CP210X_IFC_ENABLE: u8 = 0x00;
const CP210X_SET_LINE_CTL: u8 = 0x03;
const CP210X_SET_MHS: u8 = 0x07;
const CP210X_SET_BAUDRATE: u8 = 0x1e;

/// CH34x vendor requests (bmRequestType 0x40: host-to-device, vendor, device).
const CH34X_REQ_TYPE_OUT: u8 = 0x40;
const CH34X_REQ_TYPE_IN: u8 = 0xc0;
const CH34X_REQ_READ_VERSION: u8 = 0x5f;
const CH34X_REQ_WRITE_REG: u8 = 0x9a;
const CH34X_REQ_SERIAL_INIT: u8 = 0xa1;
const CH34X_REQ_MODEM_CTRL: u8 = 0xa4;
const CH34X_REG_PRESCALER: u16 = 0x12;
const CH34X_REG_DIVISOR: u16 = 0x13;
const CH34X_REG_LCR: u16 = 0x18;
const CH34X_REG_LCR2: u16 = 0x25;
/// 8 data bits, no parity, 1 stop bit, receiver and transmitter enabled.
const CH34X_LCR_8N1: u16 = 0x80 | 0x40 | 0x03;
/// DTR and RTS asserted (the chip wants the complement on the wire).
const CH34X_MCR_DTR_RTS: u16 = (1 << 6) | (1 << 5);

/// Raw CDC device handle; the driver is thread-safe for the calls we make.
struct DevHandle(usb::cdc_acm_dev_hdl_t);
unsafe impl Send for DevHandle {}

/// The open device and who is using it. The disconnect callback must not
/// close a handle another thread is transferring on, so a close requested
/// while `in_use` is parked in `pending_close` for that thread to perform.
struct DevState {
    handle: Option<DevHandle>,
    in_use: bool,
    pending_close: Option<DevHandle>,
}

struct Inner {
    dev: Mutex<DevState>,
    rx: Mutex<VecDeque<u8>>,
    rx_cv: Condvar,
    attached: AtomicBool,
    vid: AtomicU32,
    pid: AtomicU32,
    bcd_device: AtomicU32,
    baud: u32,
    interface: u8,
    driver: Mutex<Driver>,
    /// Forced driver from the configuration; `None` means auto-detect.
    forced: Option<Driver>,
}

#[derive(Clone)]
pub struct UsbSerial {
    inner: Arc<Inner>,
}

// Shared with the C callbacks (there is exactly one USB host instance).
static INSTANCE: Mutex<Option<Arc<Inner>>> = Mutex::new(None);

unsafe extern "C" fn data_cb(data: *const u8, len: usize, _user: *mut c_void) -> bool {
    if let Some(inner) = INSTANCE.lock().unwrap().as_ref() {
        let raw = std::slice::from_raw_parts(data, len);
        // FTDI prefixes every IN packet with two status bytes (modem, line).
        let stripped: Vec<u8>;
        let slice: &[u8] = match *inner.driver.lock().unwrap() {
            Driver::Ftdi { packet_size, .. } => {
                stripped = raw
                    .chunks(packet_size)
                    .flat_map(|c| c.iter().skip(2).copied())
                    .collect();
                &stripped
            }
            // CDC-ACM, CP210x and CH34x deliver the serial bytes as they are.
            _ => raw,
        };
        let len = slice.len();
        if len == 0 {
            return true;
        }
        let mut q = inner.rx.lock().unwrap();
        if q.len() + len > RX_QUEUE_LIMIT {
            let drop_n = (q.len() + len - RX_QUEUE_LIMIT).min(q.len());
            q.drain(..drop_n);
        }
        q.extend(slice);
        inner.rx_cv.notify_all();
    }
    true
}

unsafe extern "C" fn event_cb(
    event: *const usb::cdc_acm_host_dev_event_data_t,
    _user: *mut c_void,
) {
    let ev = &*event;
    match ev.type_ {
        usb::cdc_acm_host_dev_event_t_CDC_ACM_HOST_DEVICE_DISCONNECTED => {
            info!("usb: device disconnected");
            if let Some(inner) = INSTANCE.lock().unwrap().as_ref() {
                let mut d = inner.dev.lock().unwrap();
                inner.attached.store(false, Ordering::SeqCst);
                if let Some(h) = d.handle.take() {
                    if d.in_use {
                        // A transfer is in flight: its thread closes the handle.
                        d.pending_close = Some(h);
                    } else {
                        drop(d);
                        usb::cdc_acm_host_close(h.0);
                    }
                }
                inner.rx_cv.notify_all();
            }
        }
        usb::cdc_acm_host_dev_event_t_CDC_ACM_HOST_ERROR => {
            warn!("usb: cdc error {}", ev.data.error)
        }
        usb::cdc_acm_host_dev_event_t_CDC_ACM_HOST_SERIAL_STATE => {
            debug!("usb: serial state changed")
        }
        _ => {}
    }
}

unsafe extern "C" fn new_dev_cb(dev: usb::usb_device_handle_t) {
    let mut desc: *const usb::usb_device_desc_t = core::ptr::null();
    if usb::usb_host_get_device_descriptor(dev, &mut desc) == sys::ESP_OK && !desc.is_null() {
        let d = &(*desc).__bindgen_anon_1;
        let (vid, pid, bcd, class) = (d.idVendor, d.idProduct, d.bcdDevice, d.bDeviceClass);
        info!("usb: new device VID {vid:04x} PID {pid:04x} rev {bcd:04x} class {class:02x}");
        if let Some(inner) = INSTANCE.lock().unwrap().as_ref() {
            inner.vid.store(vid as u32, Ordering::Relaxed);
            inner.pid.store(pid as u32, Ordering::Relaxed);
            inner.bcd_device.store(bcd as u32, Ordering::Relaxed);
        }
    }
}

fn esp_check(rc: sys::esp_err_t, what: &str) -> Result<()> {
    if rc == sys::ESP_OK {
        Ok(())
    } else {
        Err(anyhow!("{what} failed: esp_err {rc}"))
    }
}

impl UsbSerial {
    pub fn start(baud: u32, interface: u8, forced: Option<Driver>) -> Result<Self> {
        let inner = Arc::new(Inner {
            dev: Mutex::new(DevState {
                handle: None,
                in_use: false,
                pending_close: None,
            }),
            rx: Mutex::new(VecDeque::new()),
            rx_cv: Condvar::new(),
            attached: AtomicBool::new(false),
            vid: AtomicU32::new(0),
            pid: AtomicU32::new(0),
            bcd_device: AtomicU32::new(0),
            baud,
            interface,
            driver: Mutex::new(Driver::Cdc),
            forced,
        });
        *INSTANCE.lock().unwrap() = Some(inner.clone());

        unsafe {
            let mut host_cfg: usb::usb_host_config_t = core::mem::zeroed();
            host_cfg.intr_flags = sys::ESP_INTR_FLAG_LEVEL1 as i32;
            esp_check(usb::usb_host_install(&host_cfg), "usb_host_install")?;
        }
        // USB host library event pump.
        std::thread::Builder::new()
            .name("usb-events".into())
            .stack_size(4 * 1024)
            .spawn(|| unsafe {
                loop {
                    let mut flags: u32 = 0;
                    usb::usb_host_lib_handle_events(u32::MAX, &mut flags);
                    if flags & usb::USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS != 0 {
                        usb::usb_host_device_free_all();
                    }
                }
            })?;
        unsafe {
            let mut drv: usb::cdc_acm_host_driver_config_t = core::mem::zeroed();
            // The data callback runs on this task (FTDI status stripping,
            // queue locking, logging), so give it room.
            drv.driver_task_stack_size = 8192;
            drv.driver_task_priority = 10;
            drv.xCoreID = 0;
            drv.new_dev_cb = Some(new_dev_cb);
            esp_check(usb::cdc_acm_host_install(&drv), "cdc_acm_host_install")?;
        }
        info!("usb: host installed, waiting for a CDC-ACM device");
        let serial = UsbSerial { inner };
        let s = serial.clone();
        std::thread::Builder::new()
            .name("usb-open".into())
            .stack_size(6 * 1024)
            .spawn(move || s.open_loop())?;
        Ok(serial)
    }

    fn open_loop(&self) {
        loop {
            if self.inner.attached.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            match self.try_open() {
                Ok(()) => {
                    info!(
                        "usb: console attached ({}) at {} baud",
                        self.describe(),
                        self.inner.baud
                    );
                }
                Err(e) => {
                    if !e.to_string().starts_with("no device") {
                        warn!("usb: open failed: {e}");
                    }
                    std::thread::sleep(Duration::from_millis(1000));
                }
            }
        }
    }

    fn try_open(&self) -> Result<()> {
        unsafe {
            let mut cfg: usb::cdc_acm_host_open_config_t = core::mem::zeroed();
            cfg.vid = usb::CDC_HOST_ANY_VID as u16;
            cfg.pid = usb::CDC_HOST_ANY_PID as u16;
            cfg.interface_idx = self.inner.interface;
            cfg.dev_addr = usb::CDC_HOST_ANY_DEV_ADDR as u8;
            cfg.connection_timeout_ms = 1000;
            cfg.out_buffer_size = OUT_BUFFER;
            cfg.in_buffer_size = IN_BUFFER;
            cfg.event_cb = Some(event_cb);
            cfg.data_cb = Some(data_cb);
            cfg.user_arg = core::ptr::null_mut();
            let mut hdl: usb::cdc_acm_dev_hdl_t = core::ptr::null_mut();
            let rc = usb::cdc_acm_host_open_v2(&cfg, &mut hdl);
            if rc != sys::ESP_OK {
                return Err(anyhow!("no device ({rc})"));
            }
            // Publish the handle before configuring, marked in use: a
            // disconnect during setup then defers the close to us instead
            // of freeing a handle we are still sending requests on.
            {
                let mut d = self.inner.dev.lock().unwrap();
                if let Some(stale) = d.pending_close.take() {
                    usb::cdc_acm_host_close(stale.0);
                }
                d.handle = Some(DevHandle(hdl));
                d.in_use = true;
            }
            let vid = self.inner.vid.load(Ordering::Relaxed) as u16;
            let pid = self.inner.pid.load(Ordering::Relaxed) as u16;
            let bcd = self.inner.bcd_device.load(Ordering::Relaxed) as u16;
            let driver = match self.inner.forced {
                Some(d) => d.refine(bcd),
                None => Driver::detect(vid, pid, bcd),
            };
            *self.inner.driver.lock().unwrap() = driver;
            let configured = self.configure(hdl, driver);
            let mut d = self.inner.dev.lock().unwrap();
            d.in_use = false;
            if let Some(h) = d.pending_close.take() {
                // Disconnected while we were configuring.
                d.handle = None;
                drop(d);
                usb::cdc_acm_host_close(h.0);
                return Err(anyhow!("device left during setup"));
            }
            if let Err(e) = configured {
                if let Some(h) = d.handle.take() {
                    drop(d);
                    usb::cdc_acm_host_close(h.0);
                }
                return Err(e);
            }
            self.inner.rx.lock().unwrap().clear();
            self.inner.attached.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    fn configure(&self, hdl: usb::cdc_acm_dev_hdl_t, driver: Driver) -> Result<()> {
        unsafe {
            match driver {
                Driver::Cdc => {
                    let coding = usb::cdc_acm_line_coding_t {
                        dwDTERate: self.inner.baud,
                        bCharFormat: 0,
                        bParityType: 0,
                        bDataBits: 8,
                    };
                    if usb::cdc_acm_host_line_coding_set(hdl, &coding) != sys::ESP_OK {
                        debug!("usb: device ignores line coding (fine for native CDC consoles)");
                    }
                    let _ = usb::cdc_acm_host_set_control_line_state(hdl, true, true);
                }
                Driver::Ftdi { chip, .. } => self.configure_ftdi(hdl, chip)?,
                Driver::Cp210x => self.configure_cp210x(hdl)?,
                Driver::Ch34x => self.configure_ch34x(hdl)?,
            }
        }
        Ok(())
    }

    /// Applies the line settings a CP210x bridge needs.
    fn configure_cp210x(&self, hdl: usb::cdc_acm_dev_hdl_t) -> Result<()> {
        let iface = self.inner.interface as u16;
        let send = |req: u8, value: u16, data: &mut [u8]| unsafe {
            usb::cdc_acm_host_send_custom_request(
                hdl,
                CP210X_REQ_TYPE_OUT,
                req,
                value,
                iface,
                data.len() as u16,
                if data.is_empty() {
                    core::ptr::null_mut()
                } else {
                    data.as_mut_ptr()
                },
            )
        };
        if send(CP210X_IFC_ENABLE, 0x0001, &mut []) != sys::ESP_OK {
            warn!("usb: CP210x IFC_ENABLE failed");
        }
        // The baud rate travels in the data stage as a little-endian u32.
        let mut baud = self.inner.baud.to_le_bytes();
        if send(CP210X_SET_BAUDRATE, 0, &mut baud) != sys::ESP_OK {
            warn!("usb: CP210x SET_BAUDRATE failed");
        }
        // 8 data bits, no parity, 1 stop bit.
        let _ = send(CP210X_SET_LINE_CTL, 0x0800, &mut []);
        // Assert DTR and RTS (low byte = values, high byte = write mask).
        let _ = send(CP210X_SET_MHS, 0x0303, &mut []);
        debug!(
            "usb: CP210x interface {iface} configured for {} baud",
            self.inner.baud
        );
        Ok(())
    }

    /// Applies the line settings a CH340/CH341 bridge needs.
    fn configure_ch34x(&self, hdl: usb::cdc_acm_dev_hdl_t) -> Result<()> {
        let out = |req: u8, value: u16, index: u16| unsafe {
            usb::cdc_acm_host_send_custom_request(
                hdl,
                CH34X_REQ_TYPE_OUT,
                req,
                value,
                index,
                0,
                core::ptr::null_mut(),
            )
        };
        // The version is only reported; every CH340/CH341 takes the same setup.
        let mut version = [0u8; 2];
        let rc = unsafe {
            usb::cdc_acm_host_send_custom_request(
                hdl,
                CH34X_REQ_TYPE_IN,
                CH34X_REQ_READ_VERSION,
                0,
                0,
                2,
                version.as_mut_ptr(),
            )
        };
        let version = if rc == sys::ESP_OK { version[0] } else { 0 };

        if out(CH34X_REQ_SERIAL_INIT, 0, 0) != sys::ESP_OK {
            warn!("usb: CH34x SERIAL_INIT failed");
        }
        let regs = ch34x_baud_registers(self.inner.baud);
        if out(
            CH34X_REQ_WRITE_REG,
            (CH34X_REG_DIVISOR << 8) | CH34X_REG_PRESCALER,
            regs,
        ) != sys::ESP_OK
        {
            warn!("usb: CH34x baud rate write failed");
        }
        let _ = out(
            CH34X_REQ_WRITE_REG,
            (CH34X_REG_LCR2 << 8) | CH34X_REG_LCR,
            CH34X_LCR_8N1,
        );
        // The modem-control request takes the complement of the wanted bits.
        let _ = out(CH34X_REQ_MODEM_CTRL, !CH34X_MCR_DTR_RTS, 0);
        debug!(
            "usb: CH34x (version {version:#04x}) configured for {} baud (registers {regs:#06x})",
            self.inner.baud
        );
        Ok(())
    }

    /// Applies the line settings an FTDI bridge needs (it ignores CDC requests).
    fn configure_ftdi(&self, hdl: usb::cdc_acm_dev_hdl_t, chip: FtdiChip) -> Result<()> {
        let port = chip.port_index(self.inner.interface);
        let baud = ftdi_baud_request(self.inner.baud, chip, self.inner.interface);
        let requests: [(u8, u16, u16); 6] = [
            (FTDI_SIO_RESET, 0, port),         // reset the port
            (FTDI_SIO_SET_FLOW_CTRL, 0, port), // no flow control
            (FTDI_SIO_SET_BAUDRATE, baud.value, baud.index),
            (FTDI_SIO_SET_DATA, 0x0008, port), // 8 data bits, no parity, 1 stop
            (FTDI_SIO_SET_LATENCY_TIMER, FTDI_LATENCY_MS, port),
            (FTDI_SIO_SET_MODEM_CTRL, 0x0303, port), // DTR and RTS asserted
        ];
        for (req, value, index) in requests {
            let rc = unsafe {
                usb::cdc_acm_host_send_custom_request(
                    hdl,
                    FTDI_REQ_TYPE_OUT,
                    req,
                    value,
                    index,
                    0,
                    core::ptr::null_mut(),
                )
            };
            if rc != sys::ESP_OK {
                warn!("usb: FTDI request {req:#04x} failed ({rc})");
            }
        }
        debug!(
            "usb: FTDI port {port} ({}) configured for {} baud (wValue {:#06x} wIndex {:#06x})",
            if chip.fast_clock { "12 MHz clock" } else { "3 MHz clock" },
            self.inner.baud,
            baud.value,
            baud.index
        );
        Ok(())
    }

    pub fn is_attached(&self) -> bool {
        self.inner.attached.load(Ordering::Relaxed)
    }

    pub fn describe(&self) -> String {
        if self.is_attached() {
            format!(
                "{} {:04x}:{:04x} if{}",
                self.inner.driver.lock().unwrap().name(),
                self.inner.vid.load(Ordering::Relaxed),
                self.inner.pid.load(Ordering::Relaxed),
                self.inner.interface
            )
        } else {
            "detached".into()
        }
    }

    /// Reads bytes received from the target; `Ok(0)` on timeout.
    pub fn read(&self, buf: &mut [u8], timeout: Duration) -> usize {
        let mut q = self.inner.rx.lock().unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            if !q.is_empty() {
                let n = buf.len().min(q.len());
                for (i, b) in q.drain(..n).enumerate() {
                    buf[i] = b;
                }
                return n;
            }
            let now = Instant::now();
            if now >= deadline {
                return 0;
            }
            q = self.inner.rx_cv.wait_timeout(q, deadline - now).unwrap().0;
        }
    }

    /// Writes to the target. Data is dropped (with an error) while detached.
    pub fn write(&self, data: &[u8]) -> Result<()> {
        let hdl = {
            let mut d = self.inner.dev.lock().unwrap();
            if d.in_use {
                return Err(anyhow!("usb serial busy"));
            }
            match d.handle.as_ref().map(|h| h.0) {
                Some(h) => {
                    d.in_use = true;
                    h
                }
                None => return Err(anyhow!("usb serial detached")),
            }
        };
        let mut result = Ok(());
        for chunk in data.chunks(OUT_BUFFER) {
            let rc = unsafe {
                usb::cdc_acm_host_data_tx_blocking(hdl, chunk.as_ptr(), chunk.len(), 1000)
            };
            if rc != sys::ESP_OK {
                result = Err(anyhow!("usb tx failed ({rc})"));
                break;
            }
        }
        let mut d = self.inner.dev.lock().unwrap();
        d.in_use = false;
        if let Some(h) = d.pending_close.take() {
            // The device left while we were sending; finish the close now.
            drop(d);
            unsafe { usb::cdc_acm_host_close(h.0) };
            return Err(anyhow!("usb serial detached"));
        }
        result
    }
}

/// Raw DWC-OTG host port status (HPRT register), for diagnostics:
/// whether the port is powered and whether a device's pull-up is seen.
pub fn root_port_state() -> String {
    const USB_HPRT_REG: *const u32 = 0x6008_0440 as *const u32;
    let v = unsafe { core::ptr::read_volatile(USB_HPRT_REG) };
    let conn = v & 1 != 0;
    let enabled = v & (1 << 2) != 0;
    let power = v & (1 << 12) != 0;
    let speed = (v >> 17) & 0x3;
    // PHY mux / pad configuration, to verify the pins are routed to the OTG controller.
    const RTC_CNTL_USB_CONF_REG: *const u32 = 0x6000_8120 as *const u32;
    const USB_WRAP_OTG_CONF_REG: *const u32 = 0x6003_9000 as *const u32;
    let rtc = unsafe { core::ptr::read_volatile(RTC_CNTL_USB_CONF_REG) };
    let wrap = unsafe { core::ptr::read_volatile(USB_WRAP_OTG_CONF_REG) };
    format!(
        "port power={} connected={} enabled={} speed={}; rtc_usb_conf={:#x} (sw_hw_sel={} sw_sel={}) otg_conf={:#x} (phy_sel={} pad_en={} pull_ovr={} dp_pu={} dp_pd={} dm_pu={} dm_pd={})",
        power as u8,
        conn as u8,
        enabled as u8,
        match speed { 0 => "high", 1 => "full", 2 => "low", _ => "?" },
        rtc,
        (rtc >> 20) & 1,
        (rtc >> 19) & 1,
        wrap,
        (wrap >> 2) & 1,
        (wrap >> 18) & 1,
        (wrap >> 12) & 1,
        (wrap >> 13) & 1,
        (wrap >> 14) & 1,
        (wrap >> 15) & 1,
        (wrap >> 16) & 1,
    )
}
