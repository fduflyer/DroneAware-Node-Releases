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

> ⚠️ **The DroneAware installer requires Raspberry Pi OS Bookworm 64-bit.**
> If your FlightAware setup is running an older OS (Buster or Bullseye), you
> will need to reflash and reconfigure before proceeding. Check your OS version
> with `cat /etc/os-release`.

---

## Additional Hardware Required

| Item | Recommended | Approx. Cost |
|---|---|---|
| USB WiFi adapter | Alfa AWUS036N (Ralink RT3070 chipset) | $15–$20 |
| External antenna | 2.4 GHz omni, N-female, 5–9 dBi | $8–$15 |
| Pigtail cable | RP-SMA male to N-male | $5–$8 |
| **Total upgrade cost** | | **~$28–$43** |

**Why the Alfa AWUS036N?** The RT3070 chipset has native monitor mode
support in the Pi OS kernel — no additional drivers required. Plug in and go.

If you already have a compatible adapter from a previous project, check
the [confirmed working adapters list](AWUS036ACH.md) before buying new.

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
- **Clear sky view.** Walls and floors attenuate 2.4 GHz signals significantly.
- **Away from WiFi routers.** Your home router operates on the same frequency
  band. Distance reduces noise.

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

**Step 1 — Plug in the Alfa adapter.**

**Step 2 — Confirm it's detected:**

```bash
lsusb
# Should show: Ralink Technology, Corp. RT2870/RT3070
```

**Step 3 — Confirm the interface name:**

```bash
ip link show
# Look for wlan1 (your Alfa) alongside wlan0 (onboard chip)
```

**Step 4 — Run the DroneAware installer:**

```bash
curl -fsSL https://github.com/fduflyer/DroneAware-Node-Releases/releases/download/v1.0.18/install.sh | sudo bash
```

The installer will detect the Alfa on `wlan1` and configure it automatically.
When prompted for a node name, choose something that identifies your location
(e.g. `seattle-wa-01`).

**Step 5 — Verify both services are running:**

```bash
sudo systemctl status droneaware-wifi
sudo systemctl status piaware        # or dump1090-fa, depending on your setup
```

Both should show `active (running)`.

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

The Alfa may have been assigned `wlan0` if the onboard chip was disabled or
not detected at boot. Check:

```bash
ip link show
```

If the Alfa is on `wlan0`, you can either re-enable the onboard chip or edit
the config after installation:

```bash
sudo nano /opt/droneaware/config.env
# Change WIFI_ADAPTER=wlan1 to WIFI_ADAPTER=wlan0
sudo systemctl restart droneaware-wifi
```

**My node shows "Wi-Fi — Fault"**

The interface name in the config doesn't match where the Alfa actually landed.
Run `ip link show` to find the correct interface and update
`/opt/droneaware/config.env` accordingly.

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
