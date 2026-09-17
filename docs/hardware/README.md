# Community Hardware Guides

These guides are contributed by DroneAware community members who have successfully 
run the node software on non-standard or advanced hardware configurations.

The standard supported setup is a **Raspberry Pi 4** running **Raspberry Pi OS Trixie 64-bit**
with an **Alfa AWUS036ACS** or **Panda AC600** — see
[Which WiFi adapter](../../README.md#which-wifi-adapter). Bookworm is also supported with the
Panda AC600, but the AWUS036ACS will not work on Bookworm. Everything in this folder is beyond
that baseline.

## Confirmed Working

| Adapter / Setup | Chipset | Guide | Contributor |
|---|---|---|---|
| Alfa AWUS036ACH (USB-C) | RTL8812AU | [Setup Guide](AWUS036ACH.md) | AndyVickers |
| Brostrend AX900 Linux (USB-A) | AIC8800D80  | [Setup Guide](BrosTrendAX7PL.md) | Jeroen Goudeseune |
| Existing FlightAware / ADS-B Pi | Various | [Upgrade Guide](flightaware-upgrade.md) | DroneAware Community |

## Adding a Guide

- Open a [GitHub Discussion](https://github.com/fduflyer/DroneAware-Network/discussions) 
in the Hardware category with your tested configuration and we'll format and add it here.
- Fork the repository and create a pull request.
