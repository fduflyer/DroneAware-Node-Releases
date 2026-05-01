# ALFA AWUS036ACH — Community Setup Guide

> **Guide by:** AndyVickers (DroneAware Discord community)  
> **Tested on:** Raspberry Pi OS (Debian Trixie / 6.12 kernel)  
> **Adapter:** ALFA AWUS036ACH (RTL8812AU chipset, USB-C)  
> **Status:** ✅ Confirmed working

---

This guide was contributed by community member **AndyVickers**, who successfully 
got the ALFA AWUS036ACH running with DroneAware on a Raspberry Pi. This adapter 
is not part of the standard supported hardware list, but with the steps below it 
works reliably for Wi-Fi Remote ID detection.

If you run into issues or have improvements, drop a note in the 
[DroneAware Discord](https://discord.gg/J4ZHpdgzeb) or open a GitHub Discussion.

---

## Hardware Notes (Read First)

- The adapter ships with a short **USB-C to USB-A cable** — always use this cable.
- Plug the USB-A end into a regular USB port on the Pi, preferably the **USB 3.0 (blue) port**.
- **Do not** plug directly into the Pi's USB-C power port.
- Use a quality power supply (official Pi PSU recommended). This adapter draws significant power.

---

## Step 1 — Update System & Install Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential bc dkms git linux-headers-rpi-v8
```

## Step 2 — Install the Driver (lwfinger rtw88 backport)

The standard 8812au driver fails to build on the 6.12 kernel. The lwfinger/rtw88
backport is the reliable solution.

```bash
mkdir -p ~/src && cd ~/src
git clone https://github.com/lwfinger/rtw88.git
cd rtw88

make clean
make -j2
sudo make install
sudo make install_fw
sudo depmod -a
```

## Step 3 — Blacklist the Old Driver & Load the New One

```bash
# Prevent the conflicting driver from loading
echo "blacklist 8812au" | sudo tee /etc/modprobe.d/blacklist-8812au.conf

# Load the correct module
sudo modprobe rtw_8812au

# Persist across reboots
echo "rtw_8812au" | sudo tee /etc/modules-load.d/rtw8812au.conf
```

## Step 4 — Reboot & Verify

```bash
sudo reboot
```

After reboot, plug in the adapter and run:

```bash
lsusb                    # Should show: Realtek RTL8812AU (0bda:8812)
lsmod | grep rtw         # Should show: rtw_8812au
ip -c link show          # Look for wlan1 (or wlan0 if no onboard WiFi)
iwconfig
```

You should see a wlan1 interface. If you don't, check `dmesg | grep rtw` for errors.

## Step 5 — Configure DroneAware

Now that the adapter has a network interface, update the DroneAware config to use it:

```bash
sudo nano /opt/droneaware/config.env
# Set WIFI_ADAPTER=wlan1 (or whatever interface appeared in Step 4)
sudo systemctl restart droneaware-wifi
```

Check your node status on the [My Nodes](https://droneaware.io/nodes) page —
the Wi-Fi indicator should go green within a minute or two.

---

## Quick Reference — All Commands

```bash
# Dependencies
sudo apt update && sudo apt install -y build-essential bc dkms git linux-headers-rpi-v8

# Driver
mkdir -p ~/src && cd ~/src
git clone https://github.com/lwfinger/rtw88.git && cd rtw88
make clean && make -j2 && sudo make install && sudo make install_fw
sudo depmod -a

# Config
echo "blacklist 8812au" | sudo tee /etc/modprobe.d/blacklist-8812au.conf
echo "rtw_8812au" | sudo tee /etc/modules-load.d/rtw8812au.conf
sudo reboot

# After reboot — update DroneAware config
sudo nano /opt/droneaware/config.env   # Set WIFI_ADAPTER=wlan1
sudo systemctl restart droneaware-wifi
```

---

## Notes

- This method was confirmed working after multiple older drivers failed to build on the 6.12 kernel.
- The AWUS036ACH is dual-band (2.4 GHz + 5 GHz) and long-range — excellent for Wi-Fi Remote ID coverage.
- If your interface appears as `wlan0` instead of `wlan1`, update `config.env` accordingly.

---

*Community guide contributed by AndyVickers — May 2026.*

Have a setup that works? Share it in [Discord](https://discord.gg/J4ZHpdgzeb) and we'll add it here.
