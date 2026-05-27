# BrosTrend AX900 Linux WiFi 6 USB Adapter — Community Setup Guide

> **Guide by:** Jeroen Goudeseune (DroneAware Discord community)  
> **Tested on:** Promox 9.x, Vmware Workstation Pro, Virtual Machine Debian Trixie / > 6.86 & 7.x Kernel  
> **Adapter:** BrosTrend AX7PL (AIC8800D80 chipset, USB-A)  
> **Website:** https://www.brostrend.com/products/ax7pl  
> **Status:** ✅ Confirmed working

---

This guide was contributed by community member **Jeroen Goudeseune**, who successfully 
got the BrosTrend AX7PL running with DroneAware on a Proxmox Host with Debian Trixie. This adapter 
is not part of the standard supported hardware and operating system list, but with the steps below it 
works reliably for Wi-Fi Remote ID detection. Packet Injection doesnt work. Manufacturer declares support for Raspbery Pi.0 13-8.

If you run into issues or have improvements, drop a note in the 
[DroneAware Discord](https://discord.gg/J4ZHpdgzeb) or open a GitHub Discussion.

---

## Hardware Notes (Read First)

- The adapter ships without an USB Cable
- Plug the USB-A end into a regular USB port 2.0 or 3.0 port. 
- In this case, we used USB Pass through from VM Host to Virtual Machine

---

Installation manual provided by manufacturer: https://linux.brostrend.com/

```bash
sh -c 'wget linux.brostrend.com/install -O /tmp/install && sh /tmp/install'
```

```bash
sudo reboot
```

After reboot, plug in the adapter and run:

```bash
lsusb                    # Should show: AICSemi AIC 8800D80
iw dev                   # Should show interface, type and current channel
ip -c link show          # Look for wlx.... 
iwconfig                 # Look for wlx... and  Nickname:"AIC@8800"
```

You should see a wlx interface. If you don't, rerun installation command or pull/insert USB device in to the computer.

## Step 5 — Configure DroneAware

Now that the adapter has a network interface, update the DroneAware config to use it:

```bash
sudo nano /opt/droneaware/config.env
# Set WIFI_ADAPTER=wlx... (interface appeared in iwconfig or iw dev)
sudo systemctl restart droneaware-wifi
```

Check your node status on the [My Nodes](https://droneaware.io/nodes) page —
the Wi-Fi indicator should go green within a minute or two.

---

## Notes

- The Brostrend AX900 Linux (AX7PL) is dual-band (2.4 GHz + 5 GHz) and long-range.
- There is a chance the interface wont appear as`wlan0` or `wlan1`, update `config.env` accordingly. Interface name should start with WLX.
- Watch-out, this vendor also sells a Brostrend AX900 Non linux (Windows) device, which is cheaper. This hasnt been tested.

---

*Community guide contributed by Jeroen Goudeseune — May 2026.*

Have a setup that works? Share it in [Discord](https://discord.gg/J4ZHpdgzeb) and we'll add it here.
