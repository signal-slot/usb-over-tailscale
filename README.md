# usb-serial-over-tailscale

[日本語](README-ja.md)

An ESP32-S3 board with PSRAM that joins a tailnet on its own and bridges the USB serial console of a target SBC to a TCP port on the tailnet.

![A laptop reaches the target board's serial console through Tailscale; the ESP32-S3 is powered from a USB charger and plugged into the target's USB port](web/overview.webp)

```text
Remote PC ──Tailscale / TCP:35932──▶ ESP32-S3 ──USB host──▶ serial console of the target SBC
```

Everything a Tailscale node needs (control protocol, WireGuard, DERP, NAT traversal) is implemented in Rust in this repository.
Initial setup is an interactive shell over USB serial; flashing and setup are done from a browser, with nothing to install.

## Status

Verified on hardware:

- Wi-Fi setup through the wizard and joining a tailnet with the approval URL.
- `tailscale ping` from another node, both via DERP and over a direct path.
- Console access to a Raspberry Pi Debug Probe (CDC-ACM) and a Toradex Dahlia (FT4232H).
- Recovery after adapter reboot, Wi-Fi reconnection and USB replug.

Not verified:

- Headless registration with an auth key.
- CP210x, CH340/CH341, and non-H-series FTDI chips such as the FT232R.
- Recovery after a reboot of the target SBC, an internet outage, or an unreachable control server.
- Long-running operation, behaviour after node key expiry (180 days by default), and reboots triggered by the task watchdog.

### Module variants

Flash size and PSRAM mode are build-time settings, so CI builds one image per ESP32-S3 module variant (`firmware/variants/`).
PSRAM is required: network thread stacks and TLS buffers live there.

| Variant | Flash | PSRAM | Partition table | Status |
| --- | --- | --- | --- | --- |
| N16R8 | 16 MB | 8 MB octal | `partitions.csv` (6 MB app) | tested |
| N8R8 | 8 MB | 8 MB octal | `partitions.csv` | built, untested |
| N4R8 | 4 MB | 8 MB octal | `partitions-4m.csv` (3 MB app) | built, untested |
| N16R2, N8R2, N4R2 | 16, 8, 4 MB | 2 MB quad | as above | built, untested |
| WROOM-2 N16R8V, N32R8V | 16, 32 MB octal | 8 MB octal | `partitions.csv` | built, untested |
| N4, N8, N16 (no PSRAM) | | none | | not supported |

The WROOM-1U (external antenna) uses the same variants as the WROOM-1. The MINI-1 N4R2 matches `n4r2`.

To build a variant locally, point esp-idf-sys at its defaults file and pass the variant to the image script:

```bash
cd firmware
ESP_IDF_SDKCONFIG_DEFAULTS="sdkconfig.defaults;variants/n8r2.defaults" cargo build --release
tools/mkimage.sh n8r2 release
```

## Layout

| Path | Role |
| --- | --- |
| `crates/tsnode` | Tailscale node: control plane (ts2021 Noise and a minimal HTTP/2), WireGuard, DERP, disco, STUN, TCP termination with smoltcp. Runs on a host and on ESP-IDF. |
| `crates/adapter-core` | Interactive setup shell. I/O and device operations are traits, so the wizard is unit-tested on the host. |
| `tools/hostnode` | Runs tsnode on Linux for verification: joins a real tailnet and serves an echo server. |
| `firmware` | ESP32-S3 firmware (esp-idf-svc): setup console, USB host (CDC-ACM, FTDI, CP210x, CH34x), Wi-Fi, Tailscale node, TCP bridge. |

tsnode is split into these modules.

| Module | Contents |
| --- | --- |
| `controlbase`, `h2`, `control` | `/key` fetch, Noise IK handshake over `POST /ts2021`, `/machine/register` and `/machine/map` over HTTP/2. `/key` is always TLS; the Noise transport tries plain :80 first and falls back to TLS. |
| `wireguard` | Noise IKpsk2 handshake (initiator and responder), transport, replay window, rekey and keepalive timers. |
| `derp` | DERP relay client (TLS, fast-start, ping/pong, NotePreferred). |
| `disco`, `stun` | ping, pong and call-me-maybe for direct paths; public endpoint discovery with STUN. |
| `magicsock` | Path selection between UDP and DERP, handshake handling, peer table. |
| `netstack` | TCP termination on the tailnet addresses with smoltcp. |
| `node` | Ties the above together in threads. Keys persist in NVS or a file. |

## Usage

### Prepare the board (soldering required)

Use an ESP32-S3 board with PSRAM and two USB-C ports (COM and native USB).
Short the `USB-OTG` solder pad on the back of the board (shown below before bridging).

<img src="web/usb-otg-pad.webp" alt="USB-OTG solder pad on the back of the board, still open" width="360">
This is required: it feeds 5 V from the board to the target's USB port, and without it the target chip never powers up and is never detected.
The two ports have fixed roles: **`COM` = 5 V power in** (a charger or a PC), **`USB` = the SBC** (the target's debug USB port). Only for flashing and setup does `USB` go to the PC instead.
See "Power and wiring" below for the safety rule that follows from it.

### Flash from a browser

Open [signal-slot.github.io/usb-serial-over-tailscale](https://signal-slot.github.io/usb-serial-over-tailscale/) in Chrome or Edge to flash and configure the board without installing anything.
The page opens the board's USB Serial/JTAG port with WebSerial and writes the CI-built binaries with ESP Web Tools (esptool-js).
A terminal on the same page runs the setup wizard.
It works on Windows 10 and later, macOS, Linux and ChromeOS; it does not work in Firefox, Safari or on phones.
Connect the native USB port. The COM port (CH343) needs a driver on Windows and is not used.

Pick the module variant on the page from the marking on the module's metal can (for example `ESP32-S3-WROOM-1-N16R8`).
CI (GitHub Actions) builds every variant on each push. Tags matching `v*` also attach `usb-serial-over-tailscale-<variant>.bin` (bootloader, partition table and app merged into one file) to a release.
The merged file can be written with `esptool write_flash 0x0`, but it also overwrites the NVS area with 0xFF, which erases the configuration and registration.
Updates from the page write only the three regions and keep the configuration.

### Initial setup

An unconfigured board plugged into a PC through the native USB port shows up as a USB serial port (Espressif USB JTAG/serial, 303a:1001).
Open it in a terminal and press Enter to start the wizard.

```bash
screen /dev/ttyACM0 115200
```

```text
usb-serial-over-tailscale 0.1.0 - setup mode
Press Enter to start setup, or type a command:
=== Setup ===
Scanning Wi-Fi...
   1) home-wifi        (-48 dBm)
Select network number, or type an SSID (Enter to rescan, q to quit): 1
Password for home-wifi: ********
Connected (192.168.1.42)
Hostname on the tailnet [target-console]:
Registering with Tailscale... (press q to stop waiting)
Open this URL in a browser to approve the device:
  https://login.tailscale.com/a/xxxxxxxx
Waiting for approval...
Tailscale is up: target-console.example.ts.net 100.x.y.z
Setup complete. Reboot into normal mode now? [Y/n]
```

`setup` only adds a Wi-Fi network when the hostname and the Tailscale registration are already done.
`setup all` starts over.
To use an auth key, run `authkey tskey-auth-...` and then `login`.

The main commands are listed below; `help` prints the full list.

| Command | Description |
| --- | --- |
| `wifi <ssid> <pw>` | Add a Wi-Fi network and connect. Several can be stored; the strongest known AP is chosen at boot and on reconnect. |
| `wifi list`, `wifi forget <ssid>` | List and remove stored networks. |
| `usbif <n>` | USB interface number of the target. The UART of a Raspberry Pi Debug Probe is 1; the Verdin console on a Toradex Dahlia is 3. |
| `usbdrv <auto\|cdc\|ftdi\|cp210x\|ch34x>` | USB-serial bridge chip. The default detects it from VID and PID. |
| `port <n>`, `baud <rate>` | TCP port of the bridge (default 35932, "ESP32" with E=3, S=5, P=9) and baud rate of the target (default 115200). |
| `status`, `reset`, `reboot` | Show status, erase configuration and keys, reboot. |

The same shell is always available on the UART port (115200 bps, shared with the log).
Press Enter to get a prompt.
Holding BOOT while powering on enters setup mode again.

### Connecting

From any machine on the tailnet, open a raw TCP connection to port 35932 of the hostname or tailnet address.

```bash
socat -,rawer,escape=0x1d TCP:target-console:35932   # Ctrl-] to exit
nc target-console 35932
```

One connection at a time is served.
A second connection while one is active receives `busy` and is closed.
A peer that stops responding is dropped after 120 seconds and the next connection is accepted.
Bytes flow unchanged in both directions; there is no protocol on top.
The baud rate is set on the adapter and cannot be changed by the client.

### Power and wiring

Power the board through the COM-side USB port, from a PC or a USB charger.
The native port is the USB host port for the target; the target's debug port is not expected to supply power.

To supply 5 V from the native port, bridge the `USB-OTG` solder pad on the back of the board (present on many DevKitC-1-compatible boards with two USB-C ports; boards without it need their own way of feeding VBUS to the native port).
This ties the VBUS of the two USB-C connectors together, so after bridging it **never plug both ports into PCs at the same time**.
For setup, connect only the native port to the PC; in normal operation, connect the COM port to power and the native port to the target.
If the target is a CDC-ACM or FTDI-style bridge chip, that chip is usually bus-powered and needs this 5 V.

## Building and flashing

Prerequisites are the `esp` toolchain installed with `espup`, `ldproxy` and `espflash`.
ESP-IDF v5.3.3 and the `espressif/usb_host_cdc_acm` component are fetched into `firmware/.embuild/` on the first build (several GB, several minutes).

```bash
# host-side unit tests and verification tool
cargo test
cargo run -p hostnode -- probe-control                      # control-plane check (an AuthURL from a keyless registration is enough)
cargo run -p hostnode -- run --hostname tsnode-test        # join a real tailnet and serve an echo server (prints the approval URL)

# firmware
cd firmware
cargo build --release
cargo run --release      # espflash flash --monitor --flash-size 16mb --partition-table partitions.csv
```

Do not source `~/export-esp.sh`.
gcc and clang come from what esp-idf-sys installs into `.embuild/`; with espup's Xtensa gcc first on PATH the link fails.

The partition tables are `firmware/partitions.csv` (6 MB factory app, for 8 and 16 MB flash) and `firmware/partitions-4m.csv` (3 MB, for 4 MB flash).
To flash with esptool, build the binaries into `dist/<variant>/` with `tools/mkimage.sh <variant> release`.

```bash
cd firmware && tools/mkimage.sh n16r8 release
PY=$(ls -d .embuild/espressif/python_env/*/bin/python | head -1)
$PY -m esptool --chip esp32s3 --port /dev/ttyACM0 --baud 921600 write_flash \
  0x0 dist/n16r8/bootloader.bin 0x8000 dist/n16r8/partition-table.bin 0x10000 dist/n16r8/app.bin
```

The cargo runner pins the board's UART port to `/dev/ttyACM0`; adjust `.cargo/config.toml` for your machine.
`hostnode run` stores its keys in plain text in `hostnode-state.json`.

## Design decisions

- Capability version 106; map responses are received uncompressed. Headscale is not supported.
- Authentication defaults to the approval URL; an auth key is optional and is removed from NVS once registration succeeds.
- Tailscale ACLs (PacketFilter) are enforced on the receiving side. Every packet is dropped until the filter arrives.
- The home DERP region is chosen at boot by STUN round-trip time to each region, falling back to `tok` and then to the lowest region ID.
- Direct paths are established with disco ping/pong and call-me-maybe. The source of an authenticated UDP packet from a peer is also adopted as a path.
- WireGuard timestamps are corrected with the offset between the system clock and control time, and with SNTP.
- Network thread stacks live in PSRAM; only the control thread, which writes flash, keeps an internal-RAM stack.
- The USB host relies on the CDC-ACM host driver's fallback of opening any interface with two bulk endpoints; FTDI, CP210x and CH34x get only their chip-specific setup through vendor control transfers.

## Out of scope

Secure Boot and flash encryption, OTA, a web management UI, multiple simultaneous connections, USB hubs and a dedicated PCB.

## License

MIT.
The Tailscale and WireGuard protocol code was written from the protocol descriptions and the Tailscale (BSD-3-Clause) and wireguard-go (MIT) sources.
The USB-serial baud-rate encodings were written from FTDI's application note AN232B-05, Silicon Labs' AN571, Espressif's esp-usb VCP drivers (Apache-2.0) and FreeBSD's `uftdi` and `uchcom` drivers (BSD-2-Clause).
