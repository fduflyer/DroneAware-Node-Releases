# Adding DroneAware to an Existing FlightAware Feeder

> **Already feeding ADS-B data to FlightAware or Flightradar24?  
> You're 90% of the way to running a DroneAware node.**

---

> ⚠️ **DroneAware Network is not affiliated with FlightAware, Flightradar24,
> or any ADS-B data network.** DroneAware is an independent project focused
> exclusively on FAA Remote ID drone detection. This guide is provided as a
> convenience for ADS-B operators who want to add drone detection alongside
> their existing setup.

---

## Why This Works

Your Pi almost certainly uses its **onboard WiFi chip** (`wlan0`) to connect
to your home network. DroneAware puts an **external USB WiFi adapter**
(`wlan1`) into monitor mode to passively listen for drone Remote ID broadcasts
— a completely separate radio, completely separate interface, no conflict.

Both `dump1090` (FlightAware) and the DroneAware feeder run as independent
`systemd` services and never interact with each other.

---

## OS Requirement

> ⚠️ **DroneAware needs Raspberry Pi OS 64-bit. Trixie is recommended.**
> Bookworm is supported with the Panda AC600, but the Alfa AWUS036ACS will not
> work on Bookworm — its driver is not in Bookworm's kernel, and no update adds
> it. If your FlightAware setup is running an older OS (Buster or Bullseye), you
> will need to reflash and reconfigure before proceeding. Check your OS version
> with `grep VERSION_CODENAME /etc/os-release`.

---

## Additional Hardware Required

| Item | Recommended |
|---|---|
| USB WiFi adapter | **Panda AC600** (MT7610U) — works on Bookworm and Trixie. On Trixie, the **Alfa AWUS036ACS** is faster. |
| External antenna (optional) | Dual-band (2.4 + 5 GHz) omni for rooftop or attic placement. Match the connector on your adapter. |

**Why a dual-band adapter?** Drones broadcast Remote ID on both 2.4 GHz and
5 GHz. A 2.4 GHz-only adapter such as the Alfa AWUS036N still works and sees
most DJI aircraft, but it cannot see anything broadcasting on 5 GHz. See
[Which WiFi adapter](../../README.md#which-wifi-adapter) for measured
comparisons.

**Staying on Bookworm?** Use the Panda AC600 — its driver is in both Bookworm
and Trixie, so it works without any additional drivers. The AWUS036ACS is the
fastest adapter we've measured, but on Bookworm it shows up in `lsusb` and
never gets a network interface.

If you already have an adapter from a previous project, check the
[community hardware guides](README.md) before buying new.

**Optional: Bluetooth adapter**
Adding a USB Bluetooth dongle (e.g. Sena UD100 with BLE support, or any
Bluetooth 4.0+ adapter) enables BLE Remote ID detection alongside Wi-Fi. Many
drones broadcast on both transports — BLE-only nodes and Wi-Fi-only nodes both
contribute meaningfully to the network. Pi 3 and newer have built-in Bluetooth
which covers this without any additional hardware.

---

## Antenna Placement

The same logic that makes your ADS-B antenna placement good applies here:

- **Higher is better.** Rooftop or attic placement dramatically extends range.
- **Clear sky view.** Walls and floors attenuate WiFi signals significantly,
  and 5 GHz more than 2.4 GHz.
- **Away from WiFi routers.** Your home router operates on the same frequency
  bands. Distance reduces noise.

If your ADS-B antenna is already on your roof, run the DroneAware antenna
alongside it. Detection range of 1–3 miles is typical; elevated outdoor
placement can reach 5+ miles.

---

## Power Supply Note

Adding a second USB device increases current draw. If your Pi is running on a
marginal power supply, now is a good time to upgrade to the official Raspberry
Pi USB-C power supply (5V/3A). A low-voltage condition causes instability that
can affect both feeders.

The lightning bolt icon in the top-right corner of the Pi OS desktop indicates
insufficient power — if you see it, upgrade the supply before proceeding.

---

## Installation

Your existing FlightAware setup is untouched. The DroneAware installer adds
its own service alongside it.

**Step 1 — Plug in the USB WiFi adapter.**

**Step 2 — Confirm it's detected:**

```bash
lsusb
# Panda AC600:     ID 0e8d:7610 MediaTek Inc. WiFi
# Alfa AWUS036ACS: ID 0bda:0811 Realtek Semiconductor Corp. Realtek 8812AU/8821AU ...
```

**Step 3 — Confirm it has a network interface:**

```bash
ip link show
# Look for a new wlan interface alongside wlan0 (your onboard chip)
```

If `lsusb` lists the adapter but no new interface appears, your kernel has no
driver for it — see [Troubleshooting](#troubleshooting) before running the
installer.

**Step 4 — Run the DroneAware installer:**

```bash
curl -fsSL https://github.com/fduflyer/DroneAware-Node-Releases/releases/latest/download/install.sh | sudo bash
```

The installer finds the USB adapter and configures it automatically.
When prompted for a node name, choose something that identifies your location
(e.g. `seattle-wa-01`).

**Step 5 — Verify both are running:**

```bash
sudo droneaware status
sudo systemctl status piaware        # or dump1090-fa, depending on your setup
```

`droneaware status` should list your adapter in `monitor` mode as a feeder,
and `piaware` should show `active (running)`.

---

## Confirming It Works

1. Log in at [droneaware.io](https://droneaware.io)
2. Go to **My Nodes** — your node should appear as Online with a green Wi-Fi indicator within a minute of installation
3. Detections appear on the Live Map and Detection History as drones fly within range

Most suburban and rural nodes see their first detection within a few days.
Parks, construction sites, real estate corridors, and urban areas see activity
more frequently.

---

## Troubleshooting

**The installer says "No USB WiFi adapter detected"**

First check whether the Pi sees the adapter at all:

```bash
lsusb
ip link show
```

- **Not in `lsusb`:** the adapter isn't connecting. Try another USB port or
  cable, and check your power supply (see [Power Supply Note](#power-supply-note)).
- **In `lsusb`, but no new `wlan` interface:** your kernel has no driver for
  it. Run `grep VERSION_CODENAME /etc/os-release`. On `bookworm` with an Alfa
  AWUS036ACS, no update will fix this — use a Panda AC600, or reflash with
  Trixie. On `trixie`, update to the current kernel and reboot:
  `sudo apt update && sudo apt full-upgrade -y && sudo reboot`.
- **The adapter is carrying your Pi's network connection:** the installer
  never takes that interface. Connect the Pi over Ethernet or its onboard WiFi
  instead.

**My node shows "Wi-Fi — Fault"**

Run:

```bash
sudo droneaware refresh
```

DroneAware identifies adapters by MAC address, so this finds your adapter even
if its interface name changed after a reboot or a move to another USB port. If
the fault remains, run `sudo droneaware status` and check the adapter is listed.

**Will DroneAware affect my ADS-B feed quality?**

No. The DroneAware feeder runs on a completely separate USB device and
interface. It does not share any resources with `dump1090` or `piaware` and
has no effect on your ADS-B feed statistics or reliability.

---

## Updating

Once installed, use the DroneAware CLI to keep your node current:

```bash
sudo droneaware update
```

This checks for the latest release, downloads updated binaries to
`/opt/droneaware/`, and restarts the service — without touching your
FlightAware setup.

---

## What You're Contributing

FlightAware's 43,000+ feeders created the definitive global picture of manned
aircraft. DroneAware is building the equivalent for unmanned aircraft — and
the feeder community is doing it the same way: one rooftop antenna at a time.

FAA Remote ID is a public broadcast. Every drone manufactured after September
2023 is required to transmit it. Your node captures that signal and contributes
it to a shared, real-time national picture of drone activity.

Your ADS-B antenna watches the skies above 500 feet.  
Your DroneAware antenna watches what's happening below.

**[Join the community on Discord →](https://discord.gg/J4ZHpdgzeb)**

---

*Guide maintained by the DroneAware community.*

*Have a working setup not listed here? Share it in [Discord](https://discord.gg/J4ZHpdgzeb) and we'll add it.*
