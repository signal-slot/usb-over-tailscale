//! Baud-rate encodings for USB-serial bridge chips that ignore the CDC-ACM
//! line-coding request. Pure functions, unit-tested on the host.
//!
//! Written from FTDI's application note AN232B-05, Espressif's esp-usb VCP
//! drivers (Apache-2.0) and FreeBSD's `uftdi` and `uchcom` drivers
//! (BSD-2-Clause). The expected values in the tests were produced with those
//! implementations.

/// What the FTDI baud-rate generator of a given chip can do, derived from
/// `bcdDevice` in the USB device descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FtdiChip {
    /// The chip can run its baud-rate generator from 12 MHz (120 MHz / 10)
    /// instead of 3 MHz (48 MHz / 16): FT2232H, FT4232H, FT232H.
    pub fast_clock: bool,
    /// The chip expects the extra divisor bits in the high byte of wIndex
    /// and a 1-based port number in the low byte. Single-port classic chips
    /// (FT232B, FT232R) take the bits in the low byte and no port number.
    pub port_in_index: bool,
}

impl FtdiChip {
    /// `bcdDevice` identifies the silicon generation: 0x0200 FT232AM/BM,
    /// 0x0400 FT232BM, 0x0500 FT2232C/D, 0x0600 FT232R, 0x0700 FT2232H,
    /// 0x0800 FT4232H, 0x0900 FT232H, 0x1000 FT-X.
    pub fn from_bcd_device(bcd_device: u16) -> FtdiChip {
        let generation = bcd_device >> 8;
        FtdiChip {
            fast_clock: matches!(generation, 0x07..=0x09),
            port_in_index: matches!(generation, 0x05 | 0x07..=0x09 | 0x10),
        }
    }

    /// wIndex for the requests that only address a port (reset, flow
    /// control, line settings, modem control, latency timer).
    pub fn port_index(&self, interface: u8) -> u16 {
        if self.port_in_index {
            interface as u16 + 1
        } else {
            0
        }
    }
}

/// wValue and wIndex of an FTDI SET_BAUDRATE (0x03) request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FtdiBaudRequest {
    pub value: u16,
    pub index: u16,
}

/// The chip's fraction table, indexed by eighths: the generator supports
/// divisors n + k/8 and stores k as a 3-bit code in this order.
const FTDI_EIGHTHS_CODE: [u32; 8] = [0, 3, 2, 4, 1, 5, 6, 7];
const FTDI_MAX_INTEGER: u32 = (1 << 14) - 1;

/// Encodes `baud` for an FTDI bridge: the reference clock (3 MHz, or 12 MHz on
/// H-series chips for rates from 1200 baud) divided by n + k/8, rounded to the
/// nearest reachable rate. Divisor 1 means the full reference clock and 1.5
/// two thirds of it; those two are encoded as 0 and 1. Rates outside the
/// generator's range (184 baud to the clock) are clamped to its limits.
pub fn ftdi_baud_request(baud: u32, chip: FtdiChip, interface: u8) -> FtdiBaudRequest {
    let baud = baud.max(1) as u64;
    let (clock, fast_bit): (u64, u32) = if chip.fast_clock && baud >= 1200 {
        (12_000_000, 1 << 17)
    } else {
        (3_000_000, 0)
    };
    // Divisor in eighths, rounded to nearest; at least 1.0 (the clock itself)
    // and at most what 14 integer bits can hold.
    let eighths = ((clock * 8 + baud / 2) / baud) as u32;
    let eighths = eighths.clamp(8, FTDI_MAX_INTEGER * 8 + 7);
    let (integer, eighth) = match (eighths >> 3, eighths & 7) {
        // Between 1.0 and 2.0 only 1.0 and 1.5 exist, coded as 0 and 1.
        (1, k) if k < 4 => (0, 0),
        (1, _) => (1, 0),
        (n, k) => (n, k),
    };
    let bits = integer | (FTDI_EIGHTHS_CODE[eighth as usize] << 14) | fast_bit;
    let high = (bits >> 16) as u16;
    FtdiBaudRequest {
        value: bits as u16,
        index: if chip.port_in_index {
            (high << 8) | chip.port_index(interface)
        } else {
            high
        },
    }
}

/// Reference clocks of the CH340/CH341 baud-rate generator with the code
/// that selects each one (register 0x12, bits 0..2). The generator divides
/// the clock by a count of 2..=255 stored as 256 - count in register 0x13.
/// Listed in order of preference: the fastest standard clock that reaches
/// the rate wins, and the doubled 12 MHz clock is used only when it is
/// strictly more accurate (as for 921600).
const CH34X_CLOCKS: [(u16, u32); 5] = [
    (3, 6_000_000),
    (2, 750_000),
    (1, 93_750),
    (0, 11_719),
    (7, 12_000_000),
];
/// Register 0x12 bit 7: deliver received bytes without waiting for a full
/// USB packet.
const CH34X_NO_PACKET_WAIT: u16 = 0x80;

/// Encodes `baud` for a CH340/CH341 as the 16-bit wIndex of the register
/// write request (0x9A, wValue 0x1312): register 0x13 in the high byte and
/// register 0x12 in the low byte. The clock and count with the smallest rate
/// error win; on a tie the earlier entry of `CH34X_CLOCKS` is kept.
pub fn ch34x_baud_registers(baud: u32) -> u16 {
    let baud = baud.max(1) as u64;
    let mut best: Option<(u64, u16, u32)> = None; // (error, clock code, count)
    for (code, clock) in CH34X_CLOCKS {
        let clock = clock as u64;
        let count = ((clock + baud / 2) / baud).clamp(2, 255);
        let actual = clock / count;
        let error = actual.abs_diff(baud);
        if best.map(|(e, _, _)| error < e).unwrap_or(true) {
            best = Some((error, code, count as u32));
        }
    }
    let (_, code, count) = best.expect("clock table is not empty");
    (((256 - count) as u16) << 8) | code | CH34X_NO_PACKET_WAIT
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLASSIC: FtdiChip = FtdiChip {
        fast_clock: false,
        port_in_index: false,
    };
    const H_SERIES: FtdiChip = FtdiChip {
        fast_clock: true,
        port_in_index: true,
    };

    /// Decodes an FTDI request back into the rate the chip will produce.
    fn ftdi_actual(req: FtdiBaudRequest, chip: FtdiChip) -> f64 {
        let high = if chip.port_in_index {
            req.index >> 8
        } else {
            req.index
        } as u32;
        let bits = (high << 16) | req.value as u32;
        let clock = if bits & (1 << 17) != 0 {
            12_000_000.0
        } else {
            3_000_000.0
        };
        let n = bits & 0x3fff;
        let code = (bits >> 14) & 7;
        let eighths = FTDI_EIGHTHS_CODE.iter().position(|c| *c == code).unwrap() as f64;
        match (n, eighths) {
            (0, _) => clock,
            (1, _) => clock / 1.5,
            _ => clock / (n as f64 + eighths / 8.0),
        }
    }

    #[test]
    fn ftdi_classic_matches_reference_drivers() {
        // (baud, wValue) from FreeBSD uftdi and Espressif ftdi_vcp (3 MHz clock).
        let table: [(u32, u16); 16] = [
            (300, 0x2710),
            (1200, 0x09c4),
            (2400, 0x04e2),
            (4800, 0x0271),
            (9600, 0x4138),
            (19200, 0x809c),
            (38400, 0xc04e),
            (57600, 0xc034),
            (115200, 0x001a),
            (230400, 0x000d),
            (460800, 0x4006),
            (921600, 0x8003),
            (1_000_000, 0x0003),
            (1_500_000, 0x0002),
            (2_000_000, 0x0001),
            (3_000_000, 0x0000),
        ];
        for (baud, value) in table {
            let req = ftdi_baud_request(baud, CLASSIC, 0);
            assert_eq!((baud, req.value, req.index), (baud, value, 0));
        }
    }

    #[test]
    fn ftdi_h_series_matches_reference_driver() {
        // (baud, wValue, wIndex high byte) from FreeBSD uftdi (12 MHz clock),
        // port B of a multi-port chip.
        let table: [(u32, u16, u16); 12] = [
            (300, 0x2710, 0),
            (1200, 0x2710, 2),
            (9600, 0x04e2, 2),
            (57600, 0x00d0, 3),
            (115200, 0xc068, 2),
            (921600, 0x000d, 2),
            (2_000_000, 0x0006, 2),
            (3_000_000, 0x0004, 2),
            (4_000_000, 0x0003, 2),
            (6_000_000, 0x0002, 2),
            (8_000_000, 0x0001, 2),
            (12_000_000, 0x0000, 2),
        ];
        for (baud, value, high) in table {
            let req = ftdi_baud_request(baud, H_SERIES, 1);
            assert_eq!((baud, req.value, req.index), (baud, value, (high << 8) | 2));
        }
    }

    #[test]
    fn ftdi_rates_are_within_tolerance() {
        for baud in [
            200, 300, 1200, 9600, 14400, 31250, 76800, 128000, 250000, 576000,
        ] {
            for chip in [CLASSIC, H_SERIES] {
                let req = ftdi_baud_request(baud, chip, 0);
                let actual = ftdi_actual(req, chip);
                let error = (actual - baud as f64).abs() / baud as f64;
                assert!(error < 0.03, "{baud} on {chip:?}: {actual} ({error:.3})");
            }
        }
    }

    #[test]
    fn ftdi_chip_table() {
        assert_eq!(FtdiChip::from_bcd_device(0x0600), CLASSIC); // FT232R
        assert_eq!(FtdiChip::from_bcd_device(0x0400), CLASSIC); // FT232BM
        assert_eq!(FtdiChip::from_bcd_device(0x0800), H_SERIES); // FT4232H
        assert_eq!(FtdiChip::from_bcd_device(0x0900), H_SERIES); // FT232H
        let ft2232c = FtdiChip::from_bcd_device(0x0500);
        assert_eq!((ft2232c.fast_clock, ft2232c.port_in_index), (false, true));
        let ftx = FtdiChip::from_bcd_device(0x1000);
        assert_eq!((ftx.fast_clock, ftx.port_in_index), (false, true));
        assert_eq!(H_SERIES.port_index(3), 4);
        assert_eq!(CLASSIC.port_index(3), 0);
    }

    #[test]
    fn ch34x_matches_reference_drivers() {
        // (baud, wIndex) from FreeBSD uchcom and Espressif ch34x_vcp.
        let table: [(u32, u16); 17] = [
            (300, 0xd980),
            (1200, 0xb281),
            (2400, 0xd981),
            (4800, 0x6482),
            (9600, 0xb282),
            (19200, 0xd982),
            (38400, 0x6483),
            (57600, 0x9883),
            (115200, 0xcc83),
            (230400, 0xe683),
            (460800, 0xf383),
            (500000, 0xf483),
            (921600, 0xf387),
            (1_000_000, 0xfa83),
            (1_500_000, 0xfc83),
            (2_000_000, 0xfd83),
            (3_000_000, 0xfe83),
        ];
        for (baud, regs) in table {
            assert_eq!((baud, ch34x_baud_registers(baud)), (baud, regs));
        }
    }

    #[test]
    fn ch34x_picks_the_more_accurate_clock() {
        // 1.8 Mbaud: 6 MHz / 3 = 2 Mbaud (11 % off), 12 MHz / 7 = 1.71 Mbaud (4.8 % off).
        assert_eq!(ch34x_baud_registers(1_800_000), (249 << 8) | 7 | 0x80);
        // Out-of-range requests clamp to the slowest and fastest rates.
        assert_eq!(ch34x_baud_registers(1), 0x0180);
        assert_eq!(ch34x_baud_registers(100_000_000), 0xfe87);
    }
}
