#!/usr/bin/env python3
"""
DroneAware WiFi Feeder - Remote ID Capture Script
Hardware: Raspberry Pi 4 + Alfa AWUS036N (RT3070, 2.4 GHz)
Captures WiFi Remote ID in 802.11 Beacon frames (ASTM F3411) and forwards to
the DroneAware server.

Supports:
  - Wi-Fi Beacon transport (vendor IE, OUI FA:0B:BC, type 0x0D)  [F3411-19/22a]
  - Wi-Fi NAN transport detection (action frames, OUI 50:6F:9A)  [F3411-22a]

Uses raw AF_PACKET sockets (stdlib only — no scapy dependency).

Usage:
    sudo python3 wifi_feeder.py --iface wlan1 --node-id NJ001 --server http://server/api

Requirements:
    pip3 install requests
    sudo apt install iw wireless-tools
"""

import threading
import subprocess
import time
import struct
import json
import hashlib
import logging
import argparse
import socket
import glob
import os
import sys
import serial
import requests

# -- Logging -------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/droneaware_wifi.log"),
    ],
)
log = logging.getLogger("droneaware.wifi")

def _read_fw_version(fallback: str) -> str:
    try:
        with open("/opt/droneaware/version") as f:
            v = f.read().strip()
            return v if v else fallback
    except Exception:
        return fallback

FW_VERSION = _read_fw_version("1.1.3")

# -- GPS State -----------------------------------------------------------------

_gps_lat  = None
_gps_lon  = None
_gps_lock = threading.Lock()


# -- Constants -----------------------------------------------------------------

# Vendor-specific IE OUI for ASTM F3411 Wi-Fi Beacon transport
ASTM_OUI      = bytes([0xFA, 0x0B, 0xBC])
ASTM_OUI_TYPE = 0x0D  # Remote ID app code

# Wi-Fi Alliance NAN OUI (action frames)
NAN_OUI      = bytes([0x50, 0x6F, 0x9A])
NAN_OUI_TYPE = 0x13  # NAN

# ASTM F3411-22a Open Drone ID NAN Service ID
# First 6 bytes of SHA-256("org.opendroneid.remoteid")
# Consumer NAN (Apple AirDrop, Google Nearby Share, etc.) will never match this.
ODID_NAN_SERVICE_ID = hashlib.sha256(b"org.opendroneid.remoteid").digest()[:6]

# 2.4 GHz channels (RT3070 is 2.4 GHz only)
CHANNELS_24 = list(range(1, 12))  # 1-11 (US band)

MSG_TYPE = {
    0x0: "Basic ID",
    0x1: "Location/Vector",
    0x2: "Authentication",
    0x3: "Self ID",
    0x4: "System",
    0x5: "Operator ID",
    0xF: "Message Pack",
}

ID_TYPE = {
    0: "None",
    1: "Serial Number (ANSI/CTA-2063-A)",
    2: "CAA Assigned",
    3: "UTM Assigned",
    4: "Specific Session ID",
}

UA_TYPE = {
    0: "None",
    1: "Aeroplane",
    2: "Helicopter/Multirotor",
    3: "Gyroplane",
    4: "Hybrid Lift",
    5: "Ornithopter",
    6: "Glider",
    7: "Kite",
    8: "Free Balloon",
    9: "Captive Balloon",
    10: "Airship",
    11: "Free Fall/Parachute",
    12: "Rocket",
    13: "Tethered Powered Aircraft",
    14: "Ground Obstacle",
    255: "Other",
}


# -- Remote ID Decoder ---------------------------------------------------------
# (mirrors ble_feeder.py — pure functions, no shared state)

def parse_basic_id(data: bytes) -> dict:
    if len(data) < 25:
        return {}
    id_type = (data[1] >> 4) & 0x0F
    ua_type = data[1] & 0x0F
    uas_id  = data[2:22].rstrip(b'\x00').decode('ascii', errors='replace')
    return {
        "id_type": ID_TYPE.get(id_type, f"Unknown({id_type})"),
        "ua_type": UA_TYPE.get(ua_type, f"Unknown({ua_type})"),
        "uas_id":  uas_id,
    }


def parse_location(data: bytes) -> dict:
    """
    Decode ASTM F3411-22a Location/Vector message (25 bytes).
    Byte layout (matches server-side canonical decoder):
      0     header (msg_type/version)
      1     status flags (speed_mult bit 0, EW bit 1, height_type bit 2)
      2     track direction (raw 0-179, +180 if EW bit set)
      3     speed (encoding depends on speed_mult)
      4     vertical speed (raw * 0.5 - 62.0)
      5-8   latitude  (int32 LE, * 1e-7)
      9-12  longitude (int32 LE, * 1e-7)
     13-14  pressure altitude (uint16 LE, * 0.5 - 1000.0)
     15-16  geometric altitude (uint16 LE, * 0.5 - 1000.0)
     17-18  height AGL/above-takeoff (uint16 LE, * 0.5 - 1000.0)
    """
    if len(data) < 25:
        return {}

    status      = data[1]
    speed_mult  = (status >> 0) & 0x01
    ew_bit      = (status >> 1) & 0x01
    height_type = (status >> 2) & 0x01

    direction   = data[2] + (180 if ew_bit else 0)
    speed       = data[3] * 0.75 + 63.75 if speed_mult else data[3] * 0.25
    vspeed      = data[4] * 0.5 - 62.0

    lat = struct.unpack_from('<i', data, 5)[0] * 1e-7
    lon = struct.unpack_from('<i', data, 9)[0] * 1e-7

    # Reject null/placeholder GPS values broadcast before lock (e.g. DJI firmware
    # transmits lat>90 or lon>180 as a sentinel until GPS acquires).
    if abs(lat) > 90.0 or abs(lon) > 180.0:
        return {}

    geo_alt = struct.unpack_from('<H', data, 15)[0] * 0.5 - 1000.0
    height  = struct.unpack_from('<H', data, 17)[0] * 0.5 - 1000.0

    return {
        "latitude":       round(lat, 7),
        "longitude":      round(lon, 7),
        "altitude_geo":   round(geo_alt, 1),
        "height_agl":     round(height, 1),
        "ground_speed":   round(speed, 2),
        "vertical_speed": round(vspeed, 2),
        "heading":        round(direction, 1),
        "height_type":    "AGL" if height_type == 0 else "Above Takeoff",
    }


def parse_system_msg(data: bytes) -> dict:
    """
    Decode ASTM F3411-22a System Message (16+ bytes).
    Byte layout (matches server-side canonical decoder):
       1 (low nibble)  op_location_type  (d[1] & 0x0F)
       2-5             operator latitude   (int32 LE, * 1e-7)
       6-9             operator longitude  (int32 LE, * 1e-7)
      10-11            area_count          (uint16 LE)
      12               area_radius_m       (raw * 10)
      13-14            alt_takeoff_geo     (uint16 LE, * 0.5 - 1000.0)
    """
    if len(data) < 16:
        return {}
    op_location_type = data[1] & 0x0F
    op_lat = struct.unpack_from('<i', data, 2)[0] * 1e-7
    op_lon = struct.unpack_from('<i', data, 6)[0] * 1e-7

    # Reject placeholder/pre-lock values (same convention as parse_location)
    if abs(op_lat) > 90.0 or abs(op_lon) > 180.0:
        op_lat = op_lon = None

    area_count    = struct.unpack_from('<H', data, 10)[0]
    area_radius_m = data[12] * 10
    alt_takeoff   = struct.unpack_from('<H', data, 13)[0] * 0.5 - 1000.0

    return {
        "op_location_type": op_location_type,
        "operator_lat":     round(op_lat, 7) if op_lat is not None else None,
        "operator_lon":     round(op_lon, 7) if op_lon is not None else None,
        "area_count":       area_count,
        "area_radius_m":    area_radius_m,
        "alt_takeoff_geo":  round(alt_takeoff, 1),
    }


def parse_operator_id(data: bytes) -> dict:
    if len(data) < 22:
        return {}
    return {
        "operator_id_type": data[1],
        "operator_id":      data[2:22].rstrip(b'\x00').decode('ascii', errors='replace'),
    }


def parse_message_pack(data: bytes) -> list:
    if len(data) < 3:
        return []
    msg_size  = data[1]
    msg_count = data[2]
    messages  = []
    for i in range(msg_count):
        offset = 3 + i * msg_size
        if offset + msg_size > len(data):
            break
        messages.append(data[offset: offset + msg_size])
    return messages


def decode_rid_message(raw_bytes: bytes) -> dict | None:
    if len(raw_bytes) < 2:
        return None
    msg_type  = (raw_bytes[0] >> 4) & 0x0F
    type_name = MSG_TYPE.get(msg_type, f"Unknown(0x{msg_type:X})")
    result    = {"message_type": type_name, "raw_hex": raw_bytes.hex().upper()}
    if msg_type == 0x0:
        result.update(parse_basic_id(raw_bytes))
    elif msg_type == 0x1:
        result.update(parse_location(raw_bytes))
    elif msg_type == 0x4:
        result.update(parse_system_msg(raw_bytes))
    elif msg_type == 0x5:
        result.update(parse_operator_id(raw_bytes))
    elif msg_type == 0xF:
        sub_msgs = parse_message_pack(raw_bytes)
        result["messages"] = [m for m in (decode_rid_message(s) for s in sub_msgs) if m]
    return result


# -- Raw 802.11 Frame Parsers --------------------------------------------------
# Replaces scapy — uses stdlib socket + struct only.

def _freq_to_channel(freq_mhz: int) -> int | None:
    """Convert WiFi center frequency (MHz) to channel number. None if unknown."""
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2412) // 5 + 1
    if freq_mhz == 2484:
        return 14
    if 5180 <= freq_mhz <= 5825:
        return (freq_mhz - 5000) // 5
    return None


def _parse_radiotap(data: bytes) -> tuple[int, int | None, int | None]:
    """
    Parse RadioTap header (IEEE 802.11-2020 Annex I).
    Returns (header_length, rssi_dbm_or_None, channel_or_None).

    Fields are walked in present-bitmap order with natural alignment relative
    to the start of the header. Only fields needed to reach dBm Signal (bit 5)
    are decoded; the rest are skipped by size.
    """
    if len(data) < 8:
        return len(data), None, None

    rt_len  = struct.unpack_from('<H', data, 2)[0]
    present = struct.unpack_from('<I', data, 4)[0]

    rssi    = None
    channel = None
    offset  = 8  # first field starts after the fixed 8-byte header

    # Bit 31 (EXT): chipsets like Atheros AR9271 chain additional present words
    # before field data begins. Read each word and check its own bit 31 — do not
    # re-check the first word, which never changes. `present` (first word) is
    # preserved for field parsing since standard bits 0–28 live only there.
    ext_word = present
    while ext_word & (1 << 31):
        if offset + 4 > len(data):
            return rt_len, None, None
        ext_word = struct.unpack_from('<I', data, offset)[0]
        offset += 4

    # Bit 0: TSFT — uint64, align 8
    if present & (1 << 0):
        offset = (offset + 7) & ~7
        offset += 8
    # Bit 1: Flags — uint8
    if present & (1 << 1):
        offset += 1
    # Bit 2: Rate — uint8
    if present & (1 << 2):
        offset += 1
    # Bit 3: Channel — uint16 freq + uint16 flags, align 2
    if present & (1 << 3):
        offset = (offset + 1) & ~1
        if offset + 2 <= len(data):
            freq_mhz = struct.unpack_from('<H', data, offset)[0]
            channel = _freq_to_channel(freq_mhz)
        offset += 4
    # Bit 4: FHSS — uint8 hop_set + uint8 hop_pattern
    if present & (1 << 4):
        offset += 2
    # Bit 5: dBm Antenna Signal — int8
    if present & (1 << 5):
        if offset < len(data):
            rssi = struct.unpack_from('b', data, offset)[0]
        offset += 1

    return rt_len, rssi, channel


def _mac_str(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b)


def _parse_dot11_mgmt(data: bytes) -> tuple[int, str, int] | None:
    """
    Parse an 802.11 management frame MAC header.

    Returns (subtype, addr2_mac_str, body_offset) or None if not a mgmt frame.
    addr2 is the transmitter (Source Address).
    body_offset is the byte offset of the frame body within `data`.
    Management frames have a fixed 24-byte MAC header.
    """
    if len(data) < 24:
        return None
    fc0 = data[0]
    frame_type    = (fc0 >> 2) & 0x3
    frame_subtype = (fc0 >> 4) & 0xF
    if frame_type != 0:          # 0 = management
        return None
    addr2 = _mac_str(data[10:16])
    return frame_subtype, addr2, 24


def _extract_beacon_rid(body: bytes) -> bytes | None:
    """
    Walk 802.11 beacon Information Elements looking for the vendor-specific
    ASTM F3411 Remote ID payload (OUI FA:0B:BC, type 0x0D).

    Beacon frame body layout (after 24-byte MAC header):
      Fixed parameters: 8 (timestamp) + 2 (beacon interval) + 2 (capability) = 12 bytes
      Then: IE chain — tag(1) + length(1) + value(length)

    Returns the 25-byte ODID message or None.
    """
    offset = 12  # skip fixed parameters
    while offset + 2 <= len(body):
        tag_id  = body[offset]
        tag_len = body[offset + 1]
        end     = offset + 2 + tag_len
        if end > len(body):
            break
        if tag_id == 221:  # Vendor Specific IE
            info = body[offset + 2: end]
            if len(info) >= 5 and info[:3] == ASTM_OUI and info[3] == ASTM_OUI_TYPE:
                return info[4:]  # full payload — may be single msg or Message Pack
        offset = end
    return None


def _is_nan_action(body: bytes) -> bool:
    """
    Detect Wi-Fi NAN action frames carrying ODID (ASTM F3411-22a).
    Requires the ODID NAN Service ID (sha256('org.opendroneid.remoteid')[:6])
    to be present in the frame body. This filters out consumer NAN traffic
    (Apple AirDrop/Handoff, Google Nearby Share, etc.) which uses the same
    OUI/type but a completely different Service ID.
    """
    if not (
        len(body) >= 6 and
        body[0] == 4 and           # Category: Public Action
        body[2:5] == NAN_OUI and
        body[5] == NAN_OUI_TYPE
    ):
        return False
    # Scan the first 64 bytes of frame body for the ODID Service ID.
    # In a well-formed NAN SDF the Service ID appears at a known offset inside
    # the Service Descriptor attribute — scanning is simpler and equally correct.
    return ODID_NAN_SERVICE_ID in body[:64]


# -- Monitor Mode --------------------------------------------------------------

_NM_CONF       = "/etc/NetworkManager/conf.d/droneaware.conf"
_MONITOR_MACS  = "/opt/droneaware/monitor_macs"


def _get_backhaul_iface() -> str | None:
    """Return the interface currently carrying the default route."""
    try:
        r = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        parts = r.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


def _get_iface_mac(iface: str) -> str | None:
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except Exception:
        return None


def _persist_monitor_mac(mac: str):
    """Add MAC to known monitor MACs file and update NM unmanaged config."""
    known: set = set()
    try:
        with open(_MONITOR_MACS) as f:
            known = {l.strip() for l in f if l.strip()}
    except FileNotFoundError:
        pass

    if mac in known:
        return

    known.add(mac)
    try:
        with open(_MONITOR_MACS, "w") as f:
            f.write("\n".join(sorted(known)) + "\n")
    except Exception as e:
        log.warning(f"[Monitor] Could not write monitor MACs file: {e}")
        return

    unmanaged = ",".join(f"mac:{m}" for m in sorted(known))
    nm_body = (
        "# DroneAware — prevent NetworkManager from managing the monitor adapter.\n"
        "# If NM manages the monitor interface it fights the feeder's monitor mode\n"
        "# setup, causing zero packet capture and intermittent SSH instability.\n"
        "[keyfile]\n"
        f"unmanaged-devices={unmanaged}\n"
    )
    try:
        os.makedirs(os.path.dirname(_NM_CONF), exist_ok=True)
        with open(_NM_CONF, "w") as f:
            f.write(nm_body)
        log.info(f"[Monitor] NM unmanaged config updated: {unmanaged}")
    except Exception as e:
        log.warning(f"[Monitor] Could not update NM config: {e}")


def _ensure_monitor_safe(iface: str):
    """
    Refuse to monitor-mode the active backhaul interface (same check as installer).
    If the interface is NM-managed but not the backhaul, auto-release and persist its MAC.
    """
    backhaul = _get_backhaul_iface()
    if backhaul and iface == backhaul:
        log.error(f"Refusing to monitor {iface} — it is your active management interface.")
        log.error("Plug in ethernet or swap adapters and re-run the installer.")
        sys.exit(1)

    # Check if NM is currently managing this interface
    try:
        r = subprocess.run(
            ["nmcli", "-g", "GENERAL.STATE", "device", "show", iface],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if "unmanaged" not in r.stdout.lower():
            mac = _get_iface_mac(iface)
            log.warning(
                f"[Monitor] {iface} is managed by NetworkManager — "
                "auto-releasing for monitor mode."
            )
            subprocess.run(
                ["nmcli", "device", "set", iface, "managed", "no"],
                capture_output=True, check=False,
            )
            if mac:
                _persist_monitor_mac(mac)
    except Exception:
        pass


def set_monitor_mode(iface: str):
    """Bring interface up in monitor mode."""
    _ensure_monitor_safe(iface)
    log.info(f"Setting {iface} to monitor mode...")
    subprocess.run(["rfkill", "unblock", "all"], check=False, capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "down"],  check=True)
    subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], check=True)
    subprocess.run(["ip", "link", "set", iface, "up"],   check=True)
    log.info(f"{iface} is now in monitor mode")


def restore_managed_mode(iface: str):
    """Restore interface to managed mode on exit."""
    log.info(f"Restoring {iface} to managed mode...")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],    check=False)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=False)
        subprocess.run(["ip", "link", "set", iface, "up"],     check=False)
    except Exception as e:
        log.warning(f"Could not restore managed mode: {e}")


def set_channel(iface: str, channel: int):
    """Set the monitor interface to a specific 2.4 GHz channel."""
    subprocess.run(
        ["iw", "dev", iface, "set", "channel", str(channel)],
        check=False, capture_output=True,
    )


# -- Channel Hopper ------------------------------------------------------------

class ChannelHopper(threading.Thread):
    """Cycles through 2.4 GHz channels at a fixed dwell time (legacy flat hop)."""

    def __init__(self, iface: str, channels: list, dwell: float):
        super().__init__(daemon=True)
        self.iface           = iface
        self.channels        = channels
        self.dwell           = dwell
        self.current_channel = channels[0] if channels else None
        self._stop           = threading.Event()

    def run(self):
        log.info(f"Flat channel hopper started: {self.channels} @ {self.dwell}s dwell")
        while not self._stop.is_set():
            for ch in self.channels:
                if self._stop.is_set():
                    break
                set_channel(self.iface, ch)
                self.current_channel = ch
                time.sleep(self.dwell)

    def notify_detection(self, channel: int | None):
        """No-op — flat hop ignores detection feedback. Present for API parity."""
        pass

    def stop(self):
        self._stop.set()


class AdaptiveChannelHopper(threading.Thread):
    """
    Two-mode channel hopper biased to ASTM F3411-mandated channels.

    Spec basis: F3411 + opendroneid-core-c require 1 Hz Wi-Fi Beacon RID
    broadcasts on channel 6 (2.4 GHz) or 149 (5 GHz). Off-channel broadcasts
    must be at 5 Hz, which no manufacturer accepts. Even-hop scanning across
    1–11 spends ~91% of time on channels where compliant 1 Hz RID cannot
    exist.

    Sweep mode (idle, no detection within ACTIVE_WINDOW):
      ~80% on channel 6, brief peeks at 1 and 11.

    Sticky mode (active detection within ACTIVE_WINDOW):
      Hold on the channel that produced the detection. Forced peek every
      STICKY_PEEK_INTERVAL cycles to avoid lockout of other airspace.
    """

    # Defaults — overridable via config.env (v1.2.0+)
    PRIMARY_CHANNEL       = 6
    PEEK_CHANNELS         = [1, 11]
    ACTIVE_WINDOW         = 3.0     # seconds — sticky-mode reset threshold

    SWEEP_PRIMARY_MS      = 800
    SWEEP_PEEK_MS         = 50
    SWEEP_PRIMARY_TAIL_MS = 100     # → total sweep cycle ≈ 1000ms

    STICKY_DWELL_MS       = 950
    STICKY_PEEK_INTERVAL  = 10
    STICKY_PEEK_MS        = 25

    def __init__(self, iface: str):
        super().__init__(daemon=True)
        self.iface                  = iface
        self.current_channel        = self.PRIMARY_CHANNEL
        self.last_detection_time    = 0.0
        self.last_detection_channel = self.PRIMARY_CHANNEL
        self.sticky_cycle_count     = 0
        self._stop                  = threading.Event()

        # config.env overrides — log invalid values as warnings and fall back
        def _parse_int(name: str, default):
            raw = os.environ.get(name, "").strip()
            if not raw:
                return default
            try:
                return int(raw)
            except ValueError:
                log.warning(f"{name}={raw!r} is not an integer — using default {default}")
                return default

        def _parse_float(name: str, default):
            raw = os.environ.get(name, "").strip()
            if not raw:
                return default
            try:
                return float(raw)
            except ValueError:
                log.warning(f"{name}={raw!r} is not a number — using default {default}")
                return default

        self.fixed_channel    = _parse_int("FIXED_CHANNEL", None)
        self.active_window    = _parse_float("ACTIVE_WINDOW_SEC", self.ACTIVE_WINDOW)
        self.sweep_primary_ms = _parse_int("DWELL_CH6_MS",  self.SWEEP_PRIMARY_MS)
        self.sweep_peek_ms    = _parse_int("DWELL_PEEK_MS", self.SWEEP_PEEK_MS)

        # Guard against zero/negative dwells that would spin the loop
        if self.sweep_primary_ms <= 0:
            log.warning(f"DWELL_CH6_MS={self.sweep_primary_ms} invalid — using {self.SWEEP_PRIMARY_MS}")
            self.sweep_primary_ms = self.SWEEP_PRIMARY_MS
        if self.sweep_peek_ms < 0:
            log.warning(f"DWELL_PEEK_MS={self.sweep_peek_ms} invalid — using {self.SWEEP_PEEK_MS}")
            self.sweep_peek_ms = self.SWEEP_PEEK_MS

    def notify_detection(self, channel: int | None):
        """Called by the feeder when an RID packet is received."""
        self.last_detection_time = time.time()
        if channel is not None:
            self.last_detection_channel = channel

    def _set(self, ch: int):
        set_channel(self.iface, ch)
        self.current_channel = ch

    def _sleep_ms(self, ms: int) -> bool:
        """Sleep for ms milliseconds, returning True if stop was signaled."""
        return self._stop.wait(timeout=ms / 1000.0)

    def run(self):
        # FIXED_CHANNEL: lock to one channel forever (DFR / single-drone monitoring)
        if self.fixed_channel is not None:
            log.info(f"Adaptive hopper: FIXED_CHANNEL={self.fixed_channel} — locking, no hop")
            self._set(self.fixed_channel)
            self._stop.wait()
            return

        log.info(
            f"Adaptive hopper started: primary=ch{self.PRIMARY_CHANNEL}, "
            f"peek={self.PEEK_CHANNELS}, ACTIVE_WINDOW={self.active_window}s, "
            f"DWELL_CH6_MS={self.sweep_primary_ms}, DWELL_PEEK_MS={self.sweep_peek_ms}"
        )
        prev_mode = "sweep"

        while not self._stop.is_set():
            in_active = (time.time() - self.last_detection_time) < self.active_window
            mode      = "sticky" if in_active else "sweep"

            if mode != prev_mode:
                log.debug(f"Hopper: {prev_mode}→{mode}")
                if mode == "sweep":
                    self.sticky_cycle_count = 0
                prev_mode = mode

            if mode == "sticky":
                self._set(self.last_detection_channel)
                if self._sleep_ms(self.STICKY_DWELL_MS):
                    break
                self.sticky_cycle_count += 1

                if self.sticky_cycle_count % self.STICKY_PEEK_INTERVAL == 0:
                    for ch in self.PEEK_CHANNELS:
                        self._set(ch)
                        if self._sleep_ms(self.STICKY_PEEK_MS):
                            return
            else:
                # Sweep cycle: primary → peek1 → peek2 → primary_tail
                self._set(self.PRIMARY_CHANNEL)
                if self._sleep_ms(self.sweep_primary_ms):
                    break
                for ch in self.PEEK_CHANNELS:
                    self._set(ch)
                    if self._sleep_ms(self.sweep_peek_ms):
                        return
                self._set(self.PRIMARY_CHANNEL)
                if self._sleep_ms(self.SWEEP_PRIMARY_TAIL_MS):
                    break

    def stop(self):
        self._stop.set()


# -- Health Checks -------------------------------------------------------------

def get_cpu_temp() -> float | None:
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return round(int(f.read().strip()) / 1000.0, 1)
    except Exception:
        return None


def get_wifi_health(adapter: str | None) -> tuple[bool | None, str | None]:
    if not adapter:
        return None, None
    try:
        path = f"/sys/class/net/{adapter}/operstate"
        if not os.path.exists(path):
            return False, adapter
        with open(path) as f:
            state = f.read().strip()
        return state in ("up", "unknown"), adapter
    except Exception:
        return False, adapter


# -- HTTP Forwarder ------------------------------------------------------------
# (identical contract to ble_feeder.Forwarder)

class Forwarder:
    def __init__(self, server_url: str, node_id: str,
                 batch_size: int = 10, flush_interval: float = 2.0,
                 token: str = ""):
        self.url            = server_url.rstrip("/") + "/ingest"
        self.node_id        = node_id
        self.batch_size     = batch_size
        self.flush_interval = flush_interval
        self.token          = token
        self.buffer         = []
        self.last_flush     = time.time()
        self.sent_total     = 0
        self.failed_total   = 0
        self._lock          = threading.Lock()

    def add(self, event: dict):
        with self._lock:
            self.buffer.append(event)
            if len(self.buffer) >= self.batch_size:
                self._flush_locked()

    def tick(self):
        with self._lock:
            if time.time() - self.last_flush >= self.flush_interval:
                self._flush_locked()
                self.last_flush = time.time()

    def _flush_locked(self):
        if not self.buffer:
            return
        payload      = {"node_id": self.node_id, "events": self.buffer.copy()}
        self.buffer.clear()
        try:
            headers = {"X-Node-Token": self.token} if self.token else {}
            r = requests.post(self.url, json=payload, headers=headers, timeout=5)
            r.raise_for_status()
            self.sent_total += len(payload["events"])
            log.debug(f"Forwarded {len(payload['events'])} events ({self.sent_total} total)")
        except requests.RequestException as e:
            self.failed_total += len(payload["events"])
            log.warning(f"Forward failed: {e} ({self.failed_total} events lost)")


# -- GPS Reader ----------------------------------------------------------------

def nmea_to_decimal(value: str, direction: str) -> float:
    d = int(float(value) / 100)
    m = float(value) - d * 100
    decimal = d + m / 60.0
    if direction in ('S', 'W'):
        decimal = -decimal
    return round(decimal, 6)


GPS_BAUD_RATES = [4800, 9600, 38400, 115200]


def find_gps_device() -> str | None:
    env_device = os.environ.get("GPS_DEVICE", "").strip()
    if env_device:
        return env_device
    candidates = glob.glob('/dev/ttyUSB*') + glob.glob('/dev/ttyACM*')
    return candidates[0] if candidates else None


def _nmea_checksum_valid(sentence: str) -> bool:
    """Validate NMEA sentence checksum (XOR of bytes between $ and *)."""
    try:
        if '*' not in sentence:
            return False
        content, checksum_str = sentence.rsplit('*', 1)
        if content.startswith('$'):
            content = content[1:]
        expected = int(checksum_str[:2], 16)
        actual = 0
        for c in content:
            actual ^= ord(c)
        return actual == expected
    except Exception:
        return False


def detect_baud_rate(device: str) -> int | None:
    """Try common baud rates; require 2 consecutive valid NMEA sentences with correct checksum."""
    for baud in GPS_BAUD_RATES:
        try:
            valid_count = 0
            with serial.Serial(device, baudrate=baud, timeout=2) as ser:
                for _ in range(24):
                    line = ser.readline().decode('ascii', errors='ignore').strip()
                    if line.startswith(('$GP', '$GN')) and _nmea_checksum_valid(line):
                        valid_count += 1
                        if valid_count >= 2:
                            log.info(f"[GPS] Detected baud rate {baud} on {device}")
                            return baud
                    else:
                        valid_count = 0  # reset on any invalid line
        except serial.SerialException:
            pass
    return None


def gps_reader_thread(device: str):
    """Background thread: reads NMEA sentences, updates _gps_lat/_gps_lon."""
    global _gps_lat, _gps_lon
    while True:
        try:
            # Use GPS_BAUD from config.env if set, otherwise auto-detect
            configured_baud = os.environ.get("GPS_BAUD", "").strip()
            if configured_baud:
                try:
                    baud = int(configured_baud)
                    log.info(f"[GPS] Using configured baud rate {baud}")
                except ValueError:
                    log.warning(f"[GPS] Invalid GPS_BAUD value '{configured_baud}' — falling back to auto-detect")
                    baud = detect_baud_rate(device)
            else:
                baud = detect_baud_rate(device)

            if baud is None:
                log.warning(f"[GPS] Could not detect baud rate on {device} — retrying in 10s")
                time.sleep(10)
                continue
            with serial.Serial(device, baudrate=baud, timeout=2) as ser:
                log.info(f"[GPS] Reading from {device} at {baud} baud")
                while True:
                    line = ser.readline().decode('ascii', errors='ignore').strip()
                    if not line.startswith(('$GPRMC', '$GNRMC')):
                        continue
                    parts = line.split(',')
                    if len(parts) < 7 or parts[2] != 'A':
                        continue
                    try:
                        lat = nmea_to_decimal(parts[3], parts[4])
                        lon = nmea_to_decimal(parts[5], parts[6].split('*')[0])
                        with _gps_lock:
                            _gps_lat = lat
                            _gps_lon = lon
                    except (ValueError, IndexError):
                        continue
        except serial.SerialException as e:
            log.warning(f"[GPS] Serial error: {e} — retrying in 10s")
            time.sleep(10)
        except Exception as e:
            log.warning(f"[GPS] Unexpected error: {e} — retrying in 10s")
            time.sleep(10)


# -- Local Publisher -----------------------------------------------------------

class LocalPublisher:
    """
    Writes decoded detections to a tmpfs ring buffer and UDP LAN broadcast.

    Buffer: /run/droneaware/detections.jsonl  (RAM only — gone on reboot,
            zero SD card wear). Bounded to MAX_LINES entries.
    UDP:    255.255.255.255:9999 — any device on the LAN can listen.
    """
    BUFFER_PATH = "/run/droneaware/detections.jsonl"
    UDP_PORT    = 9999
    MAX_LINES   = 3600  # ~60 min at 1 event/sec

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        os.makedirs(os.path.dirname(self.BUFFER_PATH), exist_ok=True)
        self._line_count = 0

    def publish(self, event: dict):
        decoded = event.get("decoded") or {}
        if not decoded:
            return

        record = {
            "t":       event.get("timestamp") or event.get("observed_at"),
            "mac":     event.get("source_mac") or event.get("mac"),
            "radio":   event.get("radio"),
            "rssi":    event.get("rssi"),
            "channel": event.get("channel"),
            "type":    decoded.get("message_type"),
            "lat":     decoded.get("latitude"),
            "lon":     decoded.get("longitude"),
            "alt":     decoded.get("altitude_geo"),
            "speed":   decoded.get("ground_speed"),
            "hdg":     decoded.get("heading"),
            "id":      decoded.get("uas_id"),
        }
        line = json.dumps(record, separators=(',', ':'))

        try:
            self._sock.sendto((line + '\n').encode(), ('255.255.255.255', self.UDP_PORT))
        except Exception:
            pass

        try:
            with open(self.BUFFER_PATH, 'a') as f:
                f.write(line + '\n')
            self._line_count += 1
            if self._line_count > self.MAX_LINES:
                self._trim()
        except Exception:
            pass

    def _trim(self):
        try:
            with open(self.BUFFER_PATH, 'r') as f:
                lines = f.readlines()
            if len(lines) > self.MAX_LINES:
                with open(self.BUFFER_PATH, 'w') as f:
                    f.writelines(lines[-self.MAX_LINES:])
            self._line_count = min(len(lines), self.MAX_LINES)
        except Exception:
            pass


# -- WiFi Feeder ---------------------------------------------------------------

class WiFiFeeder:
    def __init__(self, iface: str, node_id: str, server_url: str,
                 verbose: bool = False, batch_size: int = 10,
                 flush_interval: float = 2.0, channel_dwell: float = 0.2,
                 token: str = ""):
        self.iface       = iface
        self.node_id     = node_id
        self.verbose     = verbose
        self.token       = token
        self.start_time  = time.time()
        self.forwarder   = Forwarder(server_url, node_id, batch_size, flush_interval, token)
        self.publisher   = LocalPublisher()
        # ADAPTIVE_DWELL=false reverts to legacy flat 1–11 hop (A/B testing)
        adaptive_dwell = os.environ.get("ADAPTIVE_DWELL", "true").strip().lower() \
                            in ("true", "1", "yes", "on")
        if adaptive_dwell:
            log.info("Hopper mode: adaptive (sweep + sticky, channel-6 biased)")
            self.hopper = AdaptiveChannelHopper(iface)
        else:
            log.info("Hopper mode: flat (legacy even hop across 1–11)")
            self.hopper = ChannelHopper(iface, CHANNELS_24, channel_dwell)
        self.count       = 0
        self.nan_count   = 0
        self._scanning   = False

    def _on_packet(self, data: bytes):
        # Parse RadioTap header to get RSSI, channel, and skip to 802.11 MAC header
        rt_len, rssi, channel = _parse_radiotap(data)
        if rt_len >= len(data):
            return

        # Radiotap Channel field is optional; fall back to hopper state
        if channel is None:
            channel = self.hopper.current_channel

        mac_data = data[rt_len:]
        header = _parse_dot11_mgmt(mac_data)
        if header is None:
            return

        subtype, addr2, body_offset = header
        body = mac_data[body_offset:]

        # ---- Wi-Fi Beacon Remote ID (subtype 8) ----
        if subtype == 8:
            rid_payload = _extract_beacon_rid(body)
            if rid_payload is None:
                return

            decoded = decode_rid_message(rid_payload)
            if decoded is None:
                return

            # Unpack Message Pack into individual sub-messages so the server
            # receives each message type (Basic ID, Location, System, etc.)
            # as a discrete event rather than one opaque blob.
            if decoded.get("message_type") == "Message Pack":
                sub_messages = decoded.get("messages", [])
            else:
                sub_messages = [decoded]

            ts = time.time()
            for msg in sub_messages:
                # Drop Location/Vector messages with no valid GPS fix
                if msg.get("message_type") == "Location/Vector" and "latitude" not in msg:
                    continue
                self.count += 1
                raw_hex = msg.get("raw_hex", rid_payload.hex().upper())
                event = {
                    "node_id":   self.node_id,
                    "timestamp": ts,
                    "radio":     "wifi_beacon",
                    "mac":       addr2,
                    "rssi":      rssi,
                    "channel":   channel,
                    "payload":   raw_hex,
                    "decoded":   msg,
                }
                if self.verbose or msg.get("message_type") in ("Basic ID", "Location/Vector"):
                    mtype  = msg.get("message_type", "?")
                    uas_id = msg.get("uas_id", "")
                    lat    = msg.get("latitude", "")
                    lon    = msg.get("longitude", "")
                    detail = f"UAS-ID={uas_id}" if uas_id else f"lat={lat} lon={lon}" if lat else ""
                    log.info(
                        f"[WiFi-Beacon] MAC={addr2}  RSSI={rssi}dBm  "
                        f"Type={mtype}  {detail}"
                    )
                self.forwarder.add(event)
                self.publisher.publish(event)
            self.hopper.notify_detection(channel)
            return

        # ---- Wi-Fi NAN Remote ID (subtype 13 — action frame) ----
        if subtype == 13 and _is_nan_action(body):
            self.nan_count += 1
            raw = body.hex().upper()

            if self.verbose:
                log.info(f"[WiFi-NAN] MAC={addr2}  RSSI={rssi}dBm  raw={raw[:40]}...")

            event = {
                "node_id":   self.node_id,
                "timestamp": time.time(),
                "radio":     "wifi_nan",
                "mac":       addr2,
                "rssi":      rssi,
                "channel":   channel,
                "payload":   raw,
                "decoded":   None,  # NAN full parsing is a future enhancement
            }
            self.forwarder.add(event)
            self.hopper.notify_detection(channel)

    def run(self):
        log.info(f"DroneAware WiFi Feeder - Node: {self.node_id}")
        log.info(f"Interface: {self.iface or '<not configured>'}  |  Channels: {CHANNELS_24}")

        # FAULT mode — missing or invalid WiFi adapter
        if not self.iface or not os.path.exists(f"/sys/class/net/{self.iface}"):
            log.error(
                f"WiFi adapter '{self.iface or 'none'}' not present — entering FAULT mode."
            )
            log.error("BLE detection (if available) is unaffected and continues independently.")
            log.error("To restore WiFi: connect a USB monitor-mode adapter and re-run the installer.")
            self._fault_loop("adapter not present")
            return

        try:
            set_monitor_mode(self.iface)
        except Exception as e:
            log.error(f"Could not put {self.iface} into monitor mode: {e}")
            log.error("Entering FAULT mode — adapter likely does not support monitor mode.")
            self._fault_loop("monitor mode unsupported")
            return

        self.hopper.start()

        log.info("Scanning for Remote ID beacon frames (ASTM F3411)...")

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.bind((self.iface, 0))
        sock.settimeout(1.0)
        self._scanning = True

        flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        flush_thread.start()

        try:
            while True:
                try:
                    data = sock.recv(65535)
                    self._on_packet(data)
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            log.info("Feeder stopped by user.")
        finally:
            sock.close()
            self.hopper.stop()
            restore_managed_mode(self.iface)
            log.info(
                f"[Summary] Beacon RID={self.count}  NAN frames={self.nan_count}  "
                f"sent={self.forwarder.sent_total}  failed={self.forwarder.failed_total}"
            )

    def _fault_loop(self, reason: str):
        """
        Degraded loop entered when no usable WiFi adapter is present.
        Emits heartbeats with wifi_ok=False so the server marks the radio as FAULT.
        Performs no monitor-mode setup, no packet capture, no event forwarding.
        """
        log.warning(f"[FAULT] wifi feeder running in degraded mode: {reason}")
        while True:
            try:
                time.sleep(60)
                log.info(
                    f"[Heartbeat] FAULT — wifi_ok=False  reason={reason}  "
                    f"uptime={int(time.time() - self.start_time)}s"
                )
                if not self.token:
                    continue
                with _gps_lock:
                    lat, lon = _gps_lat, _gps_lon
                cpu_temp = get_cpu_temp()
                has_gps  = os.path.exists(os.environ.get("GPS_DEVICE", "/dev/ttyUSB0"))
                mobile   = os.environ.get("NODE_MOBILE", "false").lower() == "true"
                requests.post(
                    "https://api.droneaware.io/api/node/heartbeat",
                    json={
                        # Per-feeder heartbeat: wifi_* fields only (see note above)
                        "node_id":      self.node_id,
                        "uptime_s":     int(time.time() - self.start_time),
                        "fw_version":   FW_VERSION,
                        "cpu_temp_c":   cpu_temp,
                        "wifi_ok":      False,
                        "wifi_adapter": self.iface or None,
                        "wifi_fault":   reason,
                        "scanning":     False,
                        "mobile":       mobile,
                        "has_gps":      has_gps,
                        "lat":          lat,
                        "lon":          lon,
                    },
                    headers={"X-Node-Token": self.token},
                    timeout=5,
                )
            except requests.RequestException as e:
                log.warning(f"FAULT heartbeat failed: {e}")
            except Exception as e:
                log.warning(f"FAULT loop error: {e}")

    def _flush_loop(self):
        """Periodically flush the forwarder buffer (runs in background thread)."""
        last_heartbeat = time.time()
        while True:
            time.sleep(1.0)
            self.forwarder.tick()
            if time.time() - last_heartbeat >= 60:
                last_heartbeat = time.time()
                log.info(
                    f"[Heartbeat] Beacon RID={self.count}  NAN={self.nan_count}  "
                    f"sent={self.forwarder.sent_total}  failed={self.forwarder.failed_total}"
                )
                if self.token:
                    try:
                        with _gps_lock:
                            lat, lon = _gps_lat, _gps_lon
                        wifi_ok, wifi_adp = get_wifi_health(self.iface)
                        cpu_temp          = get_cpu_temp()
                        has_gps           = os.path.exists(os.environ.get("GPS_DEVICE", "/dev/ttyUSB0"))
                        mobile            = os.environ.get("NODE_MOBILE", "false").lower() == "true"
                        requests.post(
                            "https://api.droneaware.io/api/node/heartbeat",
                            json={
                                # Per-feeder heartbeat: wifi_* fields only.
                                # Do NOT include ble_ok or ble_fault — the server
                                # uses presence of an ok-field to route the
                                # heartbeat to that feeder's status row.
                                "node_id":      self.node_id,
                                "uptime_s":     int(time.time() - self.start_time),
                                "fw_version":   FW_VERSION,
                                "cpu_temp_c":   cpu_temp,
                                "wifi_ok":      wifi_ok,
                                "wifi_adapter": wifi_adp,
                                "scanning":     self._scanning,
                                "mobile":       mobile,
                                "has_gps":      has_gps,
                                "lat":          lat,
                                "lon":          lon,
                            },
                            headers={"X-Node-Token": self.token},
                            timeout=5,
                        )
                        log.debug("Heartbeat sent to droneaware.io")
                    except requests.RequestException as e:
                        log.warning(f"Heartbeat failed: {e}")


# -- Enrollment ----------------------------------------------------------------

TOKEN_FILE = "/etc/droneaware/token"


def resolve_token() -> str:
    """Load the node credential written by the installer.

    Exits with a clear error if the credential is missing — enrollment
    is handled entirely by the installer, not the feeder.
    """
    if os.path.exists(TOKEN_FILE):
        token = open(TOKEN_FILE).read().strip()
        if token:
            log.info(f"Loaded node credential from {TOKEN_FILE}")
            return token

    log.error("No node credential found at %s.", TOKEN_FILE)
    log.error("This node has not been enrolled. Run the DroneAware installer:")
    log.error("  curl -fsSL https://droneaware.io/install | sudo bash")
    sys.exit(1)


# -- Entry Point ---------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DroneAware WiFi Remote ID Feeder (Raspberry Pi + Alfa AWUS036N)"
    )
    parser.add_argument(
        "--iface", default=os.environ.get("WIFI_ADAPTER", "") or "wlan1",
        help="Monitor-mode interface (default: $WIFI_ADAPTER from config.env, or wlan1)"
    )
    parser.add_argument(
        "--node-id", default=socket.gethostname(),
        help="Unique node ID (default: hostname)"
    )
    parser.add_argument(
        "--server", default="http://localhost:8000/api",
        help="DroneAware server base URL"
    )
    parser.add_argument(
        "--batch-size", type=int, default=10,
        help="Events per HTTP batch (default: 10)"
    )
    parser.add_argument(
        "--flush-interval", type=float, default=2.0,
        help="Max seconds between flushes (default: 2.0)"
    )
    parser.add_argument(
        "--channel-dwell", type=float, default=0.2,
        help="Seconds to dwell on each channel before hopping (default: 0.2)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Log every decoded packet"
    )
    args = parser.parse_args()

    token = resolve_token()

    gps_device = find_gps_device()
    if gps_device:
        log.info(f"[GPS] Dongle detected at {gps_device}")
        t = threading.Thread(target=gps_reader_thread, args=(gps_device,), daemon=True)
        t.start()
    else:
        log.info("[GPS] No GPS dongle detected — position will not be reported")

    feeder = WiFiFeeder(
        iface=args.iface,
        node_id=args.node_id,
        server_url=args.server,
        verbose=args.verbose,
        batch_size=args.batch_size,
        flush_interval=args.flush_interval,
        channel_dwell=args.channel_dwell,
        token=token,
    )
    feeder.run()


if __name__ == "__main__":
    main()
