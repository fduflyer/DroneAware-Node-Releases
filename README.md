# DroneAware Node — Setup Guide

Detect nearby drones (Remote ID) with a Raspberry Pi in minutes.

![DroneAware Screenshot](https://github.com/fduflyer/DroneAware-Node-Releases/blob/6ad45edcb46c6b23012bfdd0ee40fc80a8e9320b/IMG_3421.jpeg)

Get a Raspberry Pi 4 and an external wifi adapter, run this single command,and you could be detecting drones around you in 10-15 minutes. 

```bash
curl -fsSL https://github.com/fduflyer/DroneAware-Node-Releases/releases/download/v1.0.11/install.sh | sudo bash
```

Your new DronwAware node will listen for FAA-mandated Remote ID broadcasts from drones flying
in your area and forward them to the DroneAware Network, where they appear on a
live map at [droneaware.io](https://droneaware.io).

Once connected, you'll also get real-time email alerts anytime your node(s) detect a drone. You can also go back and view all of your detectioms by date and time to watch a replay of their flight paths. 

![DroneAware Screenshot2](https://github.com/fduflyer/DroneAware-Node-Releases/blob/10c30b8860323ae1a3d88da870fb7073cec8d9a1/IMG_3538.png)

---

## What You Need

| Item | Notes |
|---|---|
| Raspberry Pi 4 (1 GB or more) | 2 GB+ recommended if running other software |
| MicroSD card (16 GB+, Class 10) | Samsung Endurance or SanDisk High Endurance preferred |
| USB Bluetooth adapter | **Sena UD100** or any CSR/Cambridge Silicon Radio USB dongle |
| WiFi adapter (optional, recommended) | **Alfa AWUS036N** (Ralink RT3070 chipset, 2.4 GHz) |
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
Listens for Bluetooth Low Energy advertisements carrying Remote ID service data
(UUID 0xFFFA, ASTM F3411). When a drone broadcast is detected, the raw 25-byte
ODID message is forwarded to the DroneAware server in batches. All decoding
(drone ID, position, speed, operator location) happens server-side.

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
        → flight.droneaware.io (live map)
```

Both services start automatically at boot, restart on crash, and send a
heartbeat to the server every 60 seconds so the dashboard shows the node as
online. No data is stored on the Pi — everything is forwarded in real time.

![DroneAware Screenshot3](https://github.com/fduflyer/DroneAware-Node-Releases/blob/10c30b8860323ae1a3d88da870fb7073cec8d9a1/IMG_3537.png)

**What data is collected?**
Only data broadcast publicly by the drones themselves via FAA-mandated Remote ID
transmissions. Remote ID is an open broadcast — equivalent to a drone's tail
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
curl -fsSL https://github.com/fduflyer/DroneAware-Node-Releases/releases/download/v1.0.11/install.sh | sudo bash
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
   [v1.0.11 release](https://github.com/fduflyer/DroneAware-Node/releases/tag/v1.0.11).

5. **Enroll the node** — you will be prompted to open
   [flight.droneaware.io/nodes](https://flight.droneaware.io/nodes), log in,
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
║  View it at: https://flight.droneaware.io/nodes                    ║
╚══════════════════════════════════════════════════════════════════════╝
```

Log into [flight.droneaware.io/nodes](https://flight.droneaware.io/nodes) to
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
```

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

**The BLE feeder keeps restarting**
```bash
sudo journalctl -u droneaware-ble -n 50
```
Common causes:
- USB Bluetooth adapter not detected — run `hciconfig -a` to confirm the Pi
  sees it; unplug and replug the dongle if not
- Adapter MAC in `config.env` doesn't match the installed adapter — update
  `BLE_ADAPTER_MAC` in `/opt/droneaware/config.env` and restart

**"No internet connection" during install**
- Ethernet: check the cable and that your router assigned an IP
  (`ip addr show eth0`)
- WiFi: verify your credentials are correct, then reboot and try again

**I need to change my node's location**
Log into [flight.droneaware.io/nodes](https://flight.droneaware.io/nodes), select
your node, and update its location there. Node location is managed server-side.

---

## Node File Locations

| Path | Purpose |
|---|---|
| `/usr/local/bin/ble_feeder` | BLE Remote ID feeder binary |
| `/usr/local/bin/wifi_feeder` | WiFi Remote ID feeder binary |
| `/usr/local/bin/droneaware-bt-select` | Boot-time Bluetooth adapter selector |
| `/opt/droneaware/config.env` | Node configuration (ID, location, adapters) |
| `/etc/droneaware/token` | Node credential (written at enrollment) |
| `/etc/systemd/system/droneaware-ble.service` | BLE feeder systemd unit |
| `/etc/systemd/system/droneaware-wifi.service` | WiFi feeder systemd unit |
| `/etc/systemd/system/droneaware-bt-select.service` | BT selector systemd unit |

---

## Support

- Website: [droneaware.io](https://droneaware.io)
- GitHub: [github.com/fduflyer/DroneAware-Node](https://github.com/fduflyer/DroneAware-Node)

---

*Copyright (c) 2026 DroneAware, LLC. Use of this software is subject to the
terms of the DroneAware Feeder Node Software License. See [LICENSE](LICENSE) for details.*
