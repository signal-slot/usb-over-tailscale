//! Transparent bridge between one TCP client on the tailnet and the USB serial
//! console. Bytes are forwarded unchanged in both directions.
//!
//! Accepting runs on its own thread so that a second client is told the
//! bridge is busy right away instead of waiting in the backlog.

use crate::usb_host::UsbSerial;
use anyhow::{anyhow, Result};
use log::{info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use tsnode::netstack::TcpStream;
use tsnode::node::Node;

static BUSY: AtomicBool = AtomicBool::new(false);

pub fn run(node: Node, serial: UsbSerial, port: u16) -> Result<()> {
    let listener = node.listen(port);
    info!("bridge: listening on tailnet port {port}");
    let (tx, rx) = mpsc::sync_channel::<TcpStream>(1);
    crate::platform::spawn_thread(
        "bridge-accept",
        6 * 1024,
        true,
        Box::new(move || loop {
            let Some(conn) = listener.accept(Duration::from_secs(1)) else {
                continue;
            };
            if BUSY.swap(true, Ordering::SeqCst) {
                warn!("bridge: rejecting {} (busy)", conn.peer_addr());
                let _ = conn.write_all(b"busy: another client is connected\r\n");
                conn.close();
                continue;
            }
            if tx.send(conn).is_err() {
                break;
            }
        }),
    )?;
    loop {
        let conn = rx
            .recv()
            .map_err(|_| anyhow!("bridge: accept thread exited"))?;
        serve(&serial, conn)?;
        BUSY.store(false, Ordering::SeqCst);
    }
}

/// Runs one client session until either side closes.
fn serve(serial: &UsbSerial, conn: TcpStream) -> Result<()> {
    let peer = conn.peer_addr();
    info!("bridge: client connected from {peer}");
    let conn = Arc::new(conn);
    let serial2 = serial.clone();
    let c2 = conn.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    // Serial -> TCP
    let rx_done = Arc::new(AtomicBool::new(false));
    let rx_done2 = rx_done.clone();
    crate::platform::spawn_thread(
        "bridge-rx",
        6 * 1024,
        true,
        Box::new(move || {
            let mut buf = [0u8; 512];
            while !stop2.load(Ordering::Relaxed) {
                let n = serial2.read(&mut buf, Duration::from_millis(100));
                if n > 0 && c2.write_all(&buf[..n]).is_err() {
                    break;
                }
                if c2.is_closed() {
                    break;
                }
            }
            rx_done2.store(true, Ordering::Relaxed);
        }),
    )?;
    // TCP -> Serial
    let mut buf = [0u8; 512];
    let mut dropped_warned = false;
    loop {
        match conn.read(&mut buf, Duration::from_millis(100)) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = serial.write(&buf[..n]) {
                    if !dropped_warned {
                        warn!("bridge: dropping input, {e}");
                        dropped_warned = true;
                    }
                } else {
                    dropped_warned = false;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    stop.store(true, Ordering::Relaxed);
    while !rx_done.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(20));
    }
    conn.close();
    info!("bridge: client {peer} disconnected");
    Ok(())
}
