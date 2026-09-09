//! BOOT button (GPIO0, active low) used to request Setup Mode.

use anyhow::Result;
use esp_idf_svc::hal::gpio::{Gpio0, Input, PinDriver, Pull};
use std::time::{Duration, Instant};

pub struct Button {
    pin: PinDriver<'static, Input>,
}

impl Button {
    pub fn new(gpio0: Gpio0<'static>) -> Result<Self> {
        let pin = PinDriver::input(gpio0, Pull::Up)?;
        Ok(Button { pin })
    }

    pub fn is_pressed(&self) -> bool {
        self.pin.is_low()
    }

    /// True if the button is held for at least 50 ms right now.
    pub fn held_at_boot(&mut self) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(50) {
            if !self.is_pressed() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    /// Blocks until a press of at least `min_hold` is seen.
    #[allow(dead_code)]
    pub fn wait_for_press(&mut self, min_hold: Duration) {
        loop {
            while !self.is_pressed() {
                std::thread::sleep(Duration::from_millis(20));
            }
            let start = Instant::now();
            while self.is_pressed() {
                std::thread::sleep(Duration::from_millis(20));
            }
            if start.elapsed() >= min_hold {
                return;
            }
        }
    }
}
