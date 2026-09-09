//! `Console` implementations: UART0 (shared with the log output) and the
//! ESP32-S3 USB Serial/JTAG port used as the Setup Mode console.

use adapter_core::shell::Console;
use anyhow::Result;
use esp_idf_svc::hal::delay::TickType;
use esp_idf_svc::hal::gpio::{Gpio19, Gpio20};
use esp_idf_svc::hal::uart::UartDriver;
use esp_idf_svc::hal::usb_serial::{config::Config, UsbSerialDriver, USB_SERIAL};
use log::info;
use std::time::Duration;

/// UART0 through the UART driver (logs keep using the VFS console path on
/// the same pins; interleaving is acceptable for a debug port).
pub struct UartConsole {
    drv: UartDriver<'static>,
}

impl UartConsole {
    pub fn new(drv: UartDriver<'static>) -> Self {
        UartConsole { drv }
    }
}

impl Console for UartConsole {
    fn read_byte(&mut self, timeout: Duration) -> Option<u8> {
        let mut b = [0u8; 1];
        match self.drv.read(&mut b, TickType::from(timeout).ticks()) {
            Ok(1) => Some(b[0]),
            _ => None,
        }
    }

    fn write(&mut self, s: &str) {
        let _ = self.drv.write(s.as_bytes());
    }
}

/// The chip's built-in USB Serial/JTAG CDC device on the native USB port.
/// No TinyUSB involved; the PHY belongs to it until USB host mode is started.
pub struct UsbSerialConsole {
    drv: UsbSerialDriver<'static>,
}

impl UsbSerialConsole {
    pub fn install(
        usb_serial: USB_SERIAL<'static>,
        d_minus: Gpio19<'static>,
        d_plus: Gpio20<'static>,
    ) -> Result<Self> {
        let mut drv = UsbSerialDriver::new(
            usb_serial,
            d_minus,
            d_plus,
            &Config::new().rx_buffer_size(1024).tx_buffer_size(2048),
        )?;
        // Discard anything left in the receive path from the ROM bootloader.
        let mut junk = [0u8; 64];
        while matches!(drv.read(&mut junk, TickType::from(Duration::from_millis(50)).ticks()), Ok(n) if n > 0)
        {
        }
        info!("usb: USB Serial/JTAG setup console installed");
        Ok(UsbSerialConsole { drv })
    }

    /// True while a host has the port open.
    pub fn terminal_open(&self) -> bool {
        self.drv.is_connected()
    }
}

impl Console for UsbSerialConsole {
    fn read_byte(&mut self, timeout: Duration) -> Option<u8> {
        let mut b = [0u8; 1];
        match self.drv.read(&mut b, TickType::from(timeout).ticks()) {
            Ok(1) => Some(b[0]),
            _ => None,
        }
    }

    fn write(&mut self, s: &str) {
        if !self.terminal_open() {
            return;
        }
        let mut rest = s.as_bytes();
        while !rest.is_empty() {
            match self
                .drv
                .write(rest, TickType::from(Duration::from_millis(200)).ticks())
            {
                Ok(n) if n > 0 => rest = &rest[n..],
                _ => break,
            }
        }
    }
}
