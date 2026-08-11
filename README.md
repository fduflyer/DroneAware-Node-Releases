# DroneAware Node — Setup Guide

⚡ Get a node online in ~10–15 minutes → [Start Here](#quick-start)

Detections from nodes already running on the network:

![DroneAware_Screenshot1](https://github.com/fduflyer/DroneAware-Node-Releases/blob/c6f2f37dc3cdacef408afa28104e1fcccff734e3/Global%20Detections.png)

See drones flying near you in real time - most people never see Remote ID unless they build something like this. 

Nodes are already running in the US, Germany, and Canada - and growing daily.

DroneAware Network is a community-built, open Remote ID detection network. The goal is to create a distributed, real-time view of drone activity with low-cost sensors - where the value isn't just the software, but the shared detection network everyone contributes to.

Run one command and start detecting drones around you, from a few hundred yards to miles away depending on your setup::

```bash
curl -fsSL https://github.com/fduflyer/DroneAware-Node-Releases/releases/latest/download/install.sh | sudo bash
```
_No Linux experience needed — if you can plug in a USB device, you can run this._

Your new DroneAware node will listen for FAA-mandated Remote ID broadcasts from drones flying
in your area and forward them to the DroneAware Network, where they appear on a
live map at [droneaware.io](https://droneaware.io/live.html).

![DroneAware_Screenshot2](https://github.com/fduflyer/DroneAware-Node-Releases/blob/c6f2f37dc3cdacef408afa28104e1fcccff734e3/New%20Jersey%20Detections.png)

Once connected, you'll also get real-time email alerts anytime your node(s) detect a drone. You can also go back and view all of your detections by date and time to watch a replay of their flight paths. 

![DroneAware Screenshot2](https://github.com/fduflyer/DroneAware-Node-Releases/blob/10c30b8860323ae1a3d88da870fb7073cec8d9a1/IMG_3538.png)

---

## What You Need

| Item | Notes |
|---|---|
| Raspberry Pi 4 (1 GB or more) | 2 GB+ recommended if running other software |
| MicroSD card (16 GB+, Class 10) | Samsung Endurance or SanDisk High Endurance preferred |
| USB Bluetooth adapter | **Sena UD100** (newer variants with Bluetooth 4.0+ only) or any CSR/Cambridge Silicon Radio USB dongle. **Older UD100 variants (G01, G02, G03 and similar) are Bluetooth Classic (BT 2.0/2.1) only and will not work.** If unsure which version you have, the Pi's built-in Bluetooth works out of the box at shorter range. |
| Optional Sniffle receiver | A **Sonoff ZBDongle-P** flashed with Sniffle can replace the HCI Bluetooth adapter. Sniffle is installed separately; see [Sonoff/Sniffle backend](#sonoffsniffle-backend). |
| WiFi adapter (required) | **Alfa AWUS036N** (Ralink RT3070 chipset, 2.4 GHz) |
| 5V/3A USB-C power supply | Official Raspberry Pi PSU recommended |
| Ethernet cable or WiFi credentials | For initial setup |

> **Why a USB Bluetooth adapter?**
> The Pi's built-in Bluetooth works, but its antenna is inside the case. A USB
> dongle with an external antenna has significantly better range. The Sena UD100
> / CSR chipset is confirmed working and widely available for under $20.

> **Why the Alfa WiFi adapter?**
> The Alfa AWUS036N supports monitor mode, which is required to capture Wi-Fi
> Remote ID beacon frames (the 802.11 transport used by many newer drones). The
> Pi's built-in WiFi cannot be put into monitor mode reliably.

---

## How It Works

DroneAware nodes run two background services that continuously scan for drone
Remote ID broadcasts:

**BLE Feeder (`droneaware-ble`)**
Listens through either a Linux HCI controller (BlueZ/Bleak) or an optional
Sniffle serial radio for Bluetooth Low Energy advertisements carrying Remote ID service data
(UUID 0xFFFA, ASTM F3411). When a drone broadcast is detected, the raw 25-byte
ODID message is decoded locally (drone ID, position, speed, operator location)
and forwarded to the DroneAware server in batches.

**WiFi Feeder (`droneaware-wifi`)**
Places the Alfa adapter into monitor mode and hops across 2.4 GHz channels
(1–11) looking for 802.11 beacon frames carrying vendor-specific Remote ID
payloads (OUI FA:0B:BC, ASTM F3411) and Wi-Fi NAN action frames (OUI 50:6F:9A).
Detected payloads are forwarded to the server alongside MAC address and RSSI.

**Data Flow**
```
Drone (Remote ID broadcast)
  → Pi USB BT/WiFi adapter (raw capture)
    → ble_feeder / wifi_feeder (batch over HTTPS)
      → api.droneaware.io (decode + store)
        → droneaware.io (live map)
```

Both services start automatically at boot, restart on crash, and send a
heartbeat to the server every 60 seconds so the dashboard shows the node as
online. Detections are forwarded to the DroneAware server in real time and also
written to a local ring buffer (`/run/droneaware/detections.jsonl`) stored in
RAM — the last 60 minutes of detections are kept on the Pi and purged
automatically. Nothing is written to the SD card.

**What data is collected?**
Only data broadcast publicly by the drones themselves via FAA-mandated Remote ID
transmissions. Remote ID is an open broadcast equivalent to a drone's tail
number visible on a radar screen. No private communications, networks, or
personal devices are accessed. Your node's GPS coordinates are stored on the
DroneAware server to correctly place detections on the map.

---

## Quick Start

### Step 1 — Flash the SD Card

1. Download **[Raspberry Pi Imager](https://www.raspberrypi.com/software/)** on your computer.
2. Click **Choose OS → Raspberry Pi OS (other) → Raspberry Pi OS Lite (64-bit)**.
3. Click the **gear icon** (Advanced Options) and configure:
   - Set hostname: e.g. `droneaware-node`
   - Enable SSH and set a username/password
   - **Optional but recommended:** enter your WiFi credentials here to avoid
     needing an Ethernet cable
4. Select your SD card and click **Write**.

### Step 2 — Boot the Pi

1. Insert the SD card, plug in your USB Bluetooth adapter, connect power.
2. Wait 60–90 seconds for the Pi to boot.
3. SSH into the Pi:
   ```bash
   ssh <your-username>@<pi-ip-address>
   ```
   Then switch to root:
   ```bash
   sudo -i
   ```

> **Finding your Pi's IP address:** check your router's device list, or if you
> set a hostname try `ssh droneaware-node.local`.

### Step 3 — Run the Installer

Run this single command:

```bash
curl -fsSL https://github.com/fduflyer/DroneAware-Node-Releases/releases/latest/download/install.sh | sudo bash
```

The installer will:

1. **Display the DroneAware Feeder Node Contributor Agreement** — you must type
   `yes` to accept before installation proceeds. By accepting, you agree to the
   terms governing data ownership and network participation. See [LICENSE](LICENSE)
   for full terms.

2. **Prompt for a node nickname** — a short name to identify this sensor on the
   DroneAware network (e.g. `my-garage`, `rooftop-east`).

3. **Auto-detect your USB WiFi adapter** — the installer finds the external
   adapter automatically. If none is found, it will exit with instructions.

4. **Install system packages and download binaries** from the
   [latest release](https://github.com/fduflyer/DroneAware-Node-Releases/releases/latest).

5. **Enroll the node** — you will be prompted to open
   [droneaware.io/nodes](https://droneaware.io/nodes), log in,
   click **Add Node**, and paste the enrollment token shown. The node is
   immediately active on your account — no separate claim step required.

### Step 4 — Confirm Your Node is Live

At the end of installation the installer displays:

```
╔══════════════════════════════════════════════════════════════════════╗
║                    Installation Complete!                           ║
║  Node ID : my-garage                                                ║
╠══════════════════════════════════════════════════════════════════════╣
║  Your node is enrolled and active on the DroneAware network.       ║
║  View it at: https://droneaware.io/nodes                    ║
╚══════════════════════════════════════════════════════════════════════╝
```

Log into [droneaware.io/nodes](https://droneaware.io/nodes) to
see your node on the live map and access:

- Detection history and alerts
- Remote node management
- Network contribution statistics

---

## Useful Commands

```bash
# Check service status
sudo systemctl status droneaware-ble
sudo systemctl status droneaware-wifi

# Watch live detection logs
sudo journalctl -u droneaware-ble -f
sudo journalctl -u droneaware-wifi -f

# Edit node config (location, server URL, etc.)
sudo nano /opt/droneaware/config.env
sudo systemctl restart droneaware-ble droneaware-wifi

# Start feeders manually (they start automatically on next reboot)
sudo systemctl start droneaware-ble droneaware-wifi

# To upgrade an existing node
sudo droneaware update
```

---

## Sonoff/Sniffle backend

The Sonoff ZBDongle-P is not a Linux Bluetooth controller and therefore never
appears as `hciN`. DroneAware can instead read it through Sniffle's serial
protocol. Sniffle remains a separate GPL-licensed project and is not bundled in
DroneAware's binary or installer.

1. Flash the Sonoff with the correct Sniffle firmware variant by following the
   [Sniffle firmware instructions](https://github.com/nccgroup/Sniffle#firmware-installation-sonoff-usb-dongle).
2. Install Sniffle separately, for example under `/opt/sniffle`, and confirm its
   `python_cli/sniffle` package is present.
3. Edit `/opt/droneaware/config.env`:

   ```bash
   BLE_BACKEND=sniffle
   SNIFFLE_PYTHON=/opt/sniffle/python_cli
   SNIFFLE_SERIAL=/dev/serial/by-id/usb-ITead_Sonoff_Zigbee_3.0_USB_Dongle_Plus_YOUR_SERIAL-if00-port0
   SNIFFLE_BAUD=2000000
   ```

   Some older Sonoff units use a CP2102 bridge limited to 921600 baud and need
   both Sniffle's `_1M` firmware variant and `SNIFFLE_BAUD=921600`.
4. Restart the feeder with `sudo systemctl restart droneaware-bt-select droneaware-ble`.

### Profile mode

One radio cannot hear coded, extended, and legacy advertisements at the same
time, so `SNIFFLE_PROFILE_MODE` decides how the single Sonoff is spent.

`rotate` (default) listens for coded PHY for 30 seconds, extended
advertisements for 15 seconds, and legacy advertisements for 15 seconds, each
configurable through `SNIFFLE_*_SECONDS`. Repeated Remote ID broadcasts reduce
but do not eliminate time-slicing misses.

`coded-only` dedicates the radio to the coded PHY continuously. Rotation leaves
coded unwatched for the whole extended plus legacy dwell, which is a
deterministic blind window rather than a probabilistic miss, and some coded-PHY
airframes are only ever heard there. Dedicating the Sonoff closes that window
and gives up this receiver's coverage of the other two profiles, which is a
good trade when an `hciN` controller is present alongside it to cover ordinary
BLE. Set it with:

```bash
SNIFFLE_PROFILE_MODE=coded-only
```

At startup, and on every rotation profile change, the backend sends a unique
marker and then reads only complete records until that marker returns, bounded
by `SNIFFLE_SYNC_TIMEOUT` (default 5s). This drains advertisements captured
under the previous profile without clearing the UART mid-record, and a marker
that never arrives fails the capture loop rather than leaving a receiver that
looks active but is frozen.

Only one process can own the Sonoff serial port. This backend is for
installations where DroneAware should own that port and perform the Sniffle
capture itself; local consumers can then use DroneAware's UDP output or HTTP
API. If an existing local collector already owns the Sonoff, do not enable
`BLE_BACKEND=sniffle` and do not try to share or multiplex the bidirectional
Sniffle serial connection. Keep the collector as the receiver owner and forward
captured advertisements through a supported local-event input instead.

---

## Collector-owned local-event backend

Set `BLE_BACKEND=external` when another local service owns the BLE receiver and
DroneAware should only validate, decode, locally publish, and upload the
advertisements it receives. DroneAware opens no radio in this mode. It listens
only on a Unix socket, so the input is not exposed to the LAN or Internet.

Configure `/opt/droneaware/config.env`:

```bash
BLE_BACKEND=external
EXTERNAL_BLE_SOCKET=/run/droneaware/ble-input.sock
EXTERNAL_BLE_SOCKET_MODE=0660
EXTERNAL_BLE_SOCKET_GROUP=rid-collector
EXTERNAL_BLE_MAX_LINE_BYTES=8192
```

`EXTERNAL_BLE_SOCKET_GROUP` is optional. When set, it must name an existing
local group whose members may write to the socket. Keep the default `0660` mode
or use a more restrictive mode; do not make the socket world-writable.

The producer connects to the socket and sends one JSON object per line. Each
object uses protocol `version` 1 and contains the original FFFA service data,
not a DroneAware-decoded record:

```json
{"version":1,"observed_at":"2026-08-11T19:42:03.123Z","receiver":"sonoff-sniffle","profile":"bt5-coded","source_mac":"AA:BB:CC:DD:EE:FF","rssi":-67,"channel":37,"tx_power":12,"service_uuid":"0000fffa-0000-1000-8000-00805f9b34fb","service_data_hex":"0d01000102030405060708090a0b0c0d0e0f101112131415161718"}
```

Required fields are `version`, `receiver`, `service_uuid`, and
`service_data_hex`. `observed_at` is optional but, when present, must be an
ISO-8601 timestamp with a UTC offset. The remaining receiver metadata is
optional. DroneAware replies with one JSON line per event:

```json
{"accepted":true}
```

Invalid or unsupported events receive `{"accepted":false,"error":"..."}` and
are not queued for upload. The producer should reconnect after either service
restarts; the socket is recreated by `droneaware-ble`.

This topology keeps receiver control and durable raw capture in the local
collector while reusing DroneAware's normal authenticated batching, heartbeat,
server upload, UDP output, and in-memory detection history.

---

## Local / Offline Use

Every detection is also broadcast as a JSON line over UDP to
`255.255.255.255:9999` on your local network. Any device on the same LAN can
consume detections in real time without any data leaving your network.

**Listen from any machine on your LAN:**
```bash
nc -luk 9999
```

**Or in Python:**
```python
import socket, json
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', 9999))
while True:
    print(json.loads(s.recv(4096)))
```

Each record looks like:
```json
{"t":1745000000.0,"mac":"fa:0b:bc:12:34:56","radio":"wifi_beacon","rssi":-68,"type":"Location/Vector","lat":40.7128,"lon":-74.0060,"alt":120.5,"speed":8.25,"hdg":270.0,"id":null}
```

The same detections are also saved to `/run/droneaware/detections.jsonl` on the
Pi — a rolling 60-minute window stored entirely in RAM (no SD card writes,
cleared on reboot). You can tail it directly:
```bash
tail -f /run/droneaware/detections.jsonl
```

**Local Web UI (v1.4.0+) — works offline (v1.4.5+):**
If you installed the optional Web UI (`sudo droneaware install-webui`),
point any LAN device at `http://<pi-ip>:5000/` for a live detection map.
The Web UI runs entirely on the Pi — no internet connectivity to
droneaware.io required.

From v1.4.5+, the Web UI also bundles a world-overview basemap inside
the binary, so the map renders cleanly even when the browser can't
reach CartoDB. Online operators get full street-level detail from
CartoDB; offline operators get a recognizable country / state context
with drone markers correctly positioned. The fallback is automatic —
Leaflet detects failed tile loads and switches sources without a
refresh.

**HTTP API (v1.4.0+):**
The Web UI service exposes a small read-only JSON / SSE API on the same
port (5000) — often easier to consume than UDP for Home Assistant,
Node-RED, Homebridge, or any HTTP-aware automation tool. Unlike UDP,
you also get a full snapshot of recent state on connect.

**Endpoints** (all `GET`, no auth, LAN-accessible):

| Endpoint | Returns |
|---|---|
| `/api/detections` | JSON snapshot of all currently tracked drones |
| `/api/status` | Node telemetry (version, uptime, load, home location, buffer stats) |
| `/events` | Server-Sent Events stream — real-time push of each new detection |

---

### `/api/detections` response shape

Top-level object:

| Field | Type | Notes |
|---|---|---|
| `macs` | array | One entry per tracked drone (see below) |
| `total_events` | int | Raw events held across all drones |
| `mac_count` | int | Number of currently tracked drones |
| `buffer_bytes` | int | Ring buffer bytes in use |
| `buffer_max` | int | Configured max bytes |
| `buffer_pct` | int | 0–100 |
| `snapshot_at` | float | Unix seconds at snapshot build time |

Each `macs[]` entry:

| Field | Type | Notes |
|---|---|---|
| `mac` | string | MAC address, e.g. `"fa:0b:bc:12:34:56"` |
| `latest` | object | Merged ASTM fields (table below) |
| `first_seen` | float | Unix seconds — first event for this drone |
| `last_seen` | float | Unix seconds — most recent event |
| `age_sec` | float | Seconds since `last_seen` |
| `event_count` | int | Raw events held for this drone |
| `trail` | array of `[lat, lon]` | Last 60 unique positions, chronological |

The `latest` object — any field may be `null` until the relevant ASTM
message type is received:

| Field | Type | Range / units | Source |
|---|---|---|---|
| `t` | float | Unix seconds | Broadcast time of most recent event |
| `id` | string | hex | UAS-ID — from Basic ID message |
| `lat` | float | [-90, 90] degrees, WGS84 | Location/Vector message |
| `lon` | float | [-180, 180] degrees, WGS84 | Location/Vector message |
| `alt` | float | meters, geodetic (WGS84) | Location/Vector message |
| `speed` | float | m/s, ground speed | Location/Vector message |
| `hdg` | float | [0, 360) degrees, compass | Location/Vector message |
| `rssi` | int | dBm (negative, e.g. `-68`) | Capture-time signal strength |
| `radio` | string | `"wifi_beacon"`, `"wifi_nan"`, `"ble"` | Capture transport |
| `type` | string | ASTM message type | e.g. `"Basic ID"`, `"Location/Vector"`, `"System"` |
| `operator_lat` | float | [-90, 90] degrees, WGS84 | System message |
| `operator_lon` | float | [-180, 180] degrees, WGS84 | System message |

---

### `/api/status` response shape

| Field | Type | Notes |
|---|---|---|
| `version` | string | Node firmware version, e.g. `"1.4.0"` |
| `uptime_s` | int | Seconds since web_ui started |
| `cpu_temp_c` | float \| null | Pi CPU temperature; null on non-Pi hardware |
| `load_1m` / `load_5m` / `load_15m` | float \| null | Unix load averages |
| `sse_clients` | int | Active SSE subscribers |
| `home` | object \| null | `{"lat": float, "lon": float, "source": string}` |
| `node_id` | string | `NODE_ID` from config.env |
| `mac_count` | int | Currently tracked drones |
| `event_count` | int | Total events in buffer |
| `buffer_bytes` / `buffer_max` / `buffer_pct` | int | Ring buffer stats |

---

### `/events` SSE stream

Each message is a single decoded detection — the same wire format as a
UDP broadcast record (see UDP section above). Same field types as the
`latest` object table; aggregate fields (`mac_count`, `event_count`, etc.)
do not appear on individual events. SSE framing is:

```
data: {"t":1745000000.0,"mac":"fa:0b:bc:12:34:56","radio":"wifi_beacon","rssi":-68,"type":"Location/Vector","lat":40.7128,"lon":-74.0060,"alt":120.5,"speed":8.25,"hdg":270.0,"id":null}\n
\n
```

Keep-alive comment (`: keep-alive`) is emitted every 15 seconds of
silence to prevent proxies/browsers from timing out the connection.

---

### Examples

**Snapshot:**
```bash
curl http://<pi-ip>:5000/api/detections | jq .
```

**Live stream in Python:**
```python
import requests, json
r = requests.get("http://<pi-ip>:5000/events", stream=True)
for line in r.iter_lines():
    if line.startswith(b"data: "):
        print(json.loads(line[6:]))
```

**Or simply tail it from the shell:**
```bash
curl -N http://<pi-ip>:5000/events
```

The API is read-only — there are no POST/PUT endpoints, so it cannot
be used to inject detections or change node configuration. Bound to
`0.0.0.0:5000` with no authentication; treat it like any other LAN
service.

> **Privacy note:** Your node's precise GPS coordinates are never publicly
> visible. The DroneAware map displays only a 2-mile detection ring around your
> node — your exact location is kept private.

---

## Testing Your Node

Not seeing any detections and want to confirm your node is working? Run the
built-in test command:

```bash
sudo droneaware test
```

This transmits a 60-second sanctioned test flight from your WiFi adapter. Your
node captures it, decodes it, and forwards it to the server — the same path a
real drone detection takes. A test marker will appear on the Live map within 30 seconds —
visible only to you when signed in to the account that owns the node.

**Rate limits:** 3-minute cooldown between tests, 5 per hour.

**Check availability without transmitting:**
```bash
sudo droneaware test --dry-run
```

Test detections are tagged server-side and never appear on the public live map
or anyone else's dashboard.

---

## Troubleshooting

**"USB WiFi adapter required" — installer exits immediately**
The installer requires a USB WiFi adapter to be present. Connect your Alfa
AWUS036N (or compatible monitor-mode adapter) before running the installer, then
run it again.

**The BLE feeder starts but shows 0 detections**
This is normal — there may simply be no drones broadcasting Remote ID nearby.
Remote ID is only required for drones registered after September 2023, and most
recreational fliers are not yet compliant. Detection depends entirely on local
drone activity.

**WiFi feeder fails to start or keeps restarting**
```bash
sudo journalctl -u droneaware-wifi -n 50
```
Common causes:
- USB WiFi adapter not plugged in or not detected (`ip link show`)
- Adapter does not support monitor mode (must be Ralink RT3070 or compatible)
- Another process (NetworkManager) has taken control of the interface —
  the installer configures NM to ignore the adapter, but a reinstall of NM
  may revert this

**BLE feeder fails to start or reports a BLE error on startup**
Your Bluetooth adapter may not support BLE. The Sena UD100 product line spans multiple generations — older variants (including the G01, G02, and G03) are Bluetooth Classic (BT 2.0/2.1) only and will not work for Remote ID, which requires BLE advertising. Newer UD100 variants with Bluetooth 4.0+ are BLE-capable and will work.

Confirm what you have by running:
```bash
hciconfig -a | grep "LMP Version"
```
`LMP Version: 2.0` or `2.1` = Bluetooth Classic only, won't work.
`LMP Version: 4.0` or higher = BLE capable, should work.

If your adapter isn't BLE-capable, you can use the Pi's built-in Bluetooth instead — it supports BLE out of the box on all Pi 4 models, just with shorter range than an external dongle.

**The BLE feeder keeps restarting**
```bash
sudo journalctl -u droneaware-ble -n 50
```
Common causes:
- USB Bluetooth adapter not detected — run `hciconfig -a` to confirm the Pi
  sees it; unplug and replug the dongle if not
- Adapter MAC in `config.env` doesn't match the installed adapter — update
  `BLE_ADAPTER_MAC` in `/opt/droneaware/config.env` and restart
- In Sniffle mode, `SNIFFLE_SERIAL` does not resolve to the connected Sonoff,
  `SNIFFLE_PYTHON` does not contain the Sniffle package, or the configured baud
  does not match the firmware variant

**"No internet connection" during install**
- Ethernet: check the cable and that your router assigned an IP
  (`ip addr show eth0`)
- WiFi: verify your credentials are correct, then reboot and try again

**I need to change my node's location**
Log into [droneaware.io/nodes](https://droneaware.io/nodes), select
your node, and update its location there. Node location is managed server-side.

---

## Node File Locations

| Path | Purpose |
|---|---|
| `/usr/local/bin/ble_feeder` | BLE Remote ID feeder binary |
| `/usr/local/bin/wifi_feeder` | WiFi Remote ID feeder binary |
| `/usr/local/bin/droneaware-bt-select` | Boot-time Bluetooth adapter selector |
| `external_backend.py` | Source: optional collector-owned Unix-socket BLE input |
| External Sniffle `python_cli` directory | Optional Sonoff serial backend; path selected by `SNIFFLE_PYTHON` |
| `/opt/droneaware/config.env` | Node configuration (ID, location, adapters) |
| `/etc/droneaware/token` | Node credential (written at enrollment) |
| `/etc/systemd/system/droneaware-ble.service` | BLE feeder systemd unit |
| `/etc/systemd/system/droneaware-wifi.service` | WiFi feeder systemd unit |
| `/etc/systemd/system/droneaware-bt-select.service` | BT selector systemd unit |

---

## Contributing & Direction

DroneAware Network is an open project and forks are welcome. If you're building on this or experimenting, we'd love to hear what you're working on — especially around detection accuracy, range improvements, or new visualization approaches.

The real power of this project is the shared detection network. If you're running nodes, consider feeding data into the main DroneAware Network so detections benefit everyone.

**Join the community on Discord: [discord.gg/J4ZHpdgzeb](https://discord.gg/J4ZHpdgzeb)**

Already a FlightAware or ADS-B feeder? [See the upgrade guide →](https://github.com/fduflyer/DroneAware-Node-Releases/blob/main/docs/hardware/flightaware-upgrade.md)

Have an idea or improvement? Open an issue or start a discussion — we're actively building.

---

## Verifying Binary Attestation

Every DroneAware Node binary is built in GitHub Actions and cryptographically signed via Sigstore. You can independently verify that any release binary was built from the published source code in a known, controlled environment — not on someone's laptop.

This matters because the Contributor Agreement commits the feeder software to a specific scope of data collection (Section 3.1). Attestation lets you confirm that the binary running on your node actually implements those guarantees.

To verify a binary you downloaded from a release:


`gh attestation verify ble_feeder --owner fduflyer`
`gh attestation verify wifi_feeder --owner fduflyer`
A successful verification confirms the binary was built by GitHub Actions from a specific source commit in this repository.

Requires the GitHub CLI and a free GitHub account:

macOS: `brew install gh && gh auth login`
Debian / Ubuntu / Pi OS: `sudo apt install gh && gh auth login`

---

## Support

- Website: [droneaware.io](https://droneaware.io)
- GitHub: [github.com/fduflyer/DroneAware-Node-Releases](https://github.com/fduflyer/DroneAware-Node-Releases)

---

*Copyright (c) 2026 DroneAware, LLC. Use of this software is subject to the
terms of the DroneAware Feeder Node Software License. See [LICENSE](LICENSE) for details.*
