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
import logging
import argparse
import socket
import os
import sys
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

# -- Constants -----------------------------------------------------------------

# Vendor-specific IE OUI for ASTM F3411 Wi-Fi Beacon transport
ASTM_OUI      = bytes([0xFA, 0x0B, 0xBC])
ASTM_OUI_TYPE = 0x0D  # Remote ID app code

# Wi-Fi Alliance NAN OUI (action frames)
NAN_OUI      = bytes([0x50, 0x6F, 0x9A])
NAN_OUI_TYPE = 0x13  # NAN

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
    if len(data) < 25:
        return {}
    speed_mult  = data[1] & 0x01
    height_type = (data[1] >> 2) & 0x01
    lat = struct.unpack_from('<i', data, 2)[0] * 1e-7
    lon = struct.unpack_from('<i', data, 6)[0] * 1e-7

    # Reject null/placeholder GPS values broadcast before lock (e.g. DJI firmware
    # transmits lat>90 or lon>180 as a sentinel until GPS acquires).
    if abs(lat) > 90.0 or abs(lon) > 180.0:
        return {}

    alt_geodetic = struct.unpack_from('<H', data, 12)[0] * 0.5 - 1000.0
    height       = struct.unpack_from('<H', data, 14)[0] * 0.5 - 1000.0
    speed        = data[16] * (0.75 if speed_mult else 0.25)
    vspeed       = data[17] * 0.5 - 62.0
    heading      = struct.unpack_from('<H', data, 18)[0] * 0.01
    return {
        "latitude":       round(lat, 7),
        "longitude":      round(lon, 7),
        "altitude_geo":   round(alt_geodetic, 1),
        "height_agl":     round(height, 1),
        "ground_speed":   round(speed, 2),
        "vertical_speed": round(vspeed, 2),
        "heading":        round(heading, 1),
        "height_type":    "AGL" if height_type == 0 else "Above Takeoff",
    }


def parse_system_msg(data: bytes) -> dict:
    if len(data) < 16:
        return {}
    op_lat      = struct.unpack_from('<i', data, 4)[0] * 1e-7
    op_lon      = struct.unpack_from('<i', data, 8)[0] * 1e-7
    area_count  = data[12]
    area_radius = data[13] * 10
    alt_takeoff = struct.unpack_from('<H', data, 14)[0] * 0.5 - 1000.0
    return {
        "operator_lat":    round(op_lat, 7),
        "operator_lon":    round(op_lon, 7),
        "area_count":      area_count,
        "area_radius_m":   area_radius,
        "alt_takeoff_geo": round(alt_takeoff, 1),
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

def _parse_radiotap(data: bytes) -> tuple[int, int | None]:
    """
    Parse RadioTap header (IEEE 802.11-2020 Annex I).
    Returns (header_length, rssi_dbm_or_None).

    Fields are walked in present-bitmap order with natural alignment relative
    to the start of the header. Only fields needed to reach dBm Signal (bit 5)
    are decoded; the rest are skipped by size.
    """
    if len(data) < 8:
        return len(data), None

    rt_len  = struct.unpack_from('<H', data, 2)[0]
    present = struct.unpack_from('<I', data, 4)[0]

    rssi   = None
    offset = 8  # first field starts after the fixed 8-byte header

    # Bit 31 (EXT): chipsets like Atheros AR9271 chain additional present words
    # before field data begins. Read each word and check its own bit 31 — do not
    # re-check the first word, which never changes. `present` (first word) is
    # preserved for field parsing since standard bits 0–28 live only there.
    ext_word = present
    while ext_word & (1 << 31):
        if offset + 4 > len(data):
            return rt_len, None
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
        offset += 4
    # Bit 4: FHSS — uint8 hop_set + uint8 hop_pattern
    if present & (1 << 4):
        offset += 2
    # Bit 5: dBm Antenna Signal — int8
    if present & (1 << 5):
        if offset < len(data):
            rssi = struct.unpack_from('b', data, offset)[0]
        offset += 1

    return rt_len, rssi


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
    Detect Wi-Fi NAN action frames (category 4, OUI 50:6F:9A, type 0x13).
    body: frame body starting after the 24-byte MAC header.
    Full NAN RID parsing is a future enhancement — raw capture only for now.
    """
    return (
        len(body) >= 6 and
        body[0] == 4 and           # Category: Public Action
        body[2:5] == NAN_OUI and
        body[5] == NAN_OUI_TYPE
    )


# -- Monitor Mode --------------------------------------------------------------

def set_monitor_mode(iface: str):
    """Bring interface up in monitor mode."""
    log.info(f"Setting {iface} to monitor mode...")
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
    """Cycles through 2.4 GHz channels at a fixed dwell time."""

    def __init__(self, iface: str, channels: list, dwell: float):
        super().__init__(daemon=True)
        self.iface    = iface
        self.channels = channels
        self.dwell    = dwell
        self._stop    = threading.Event()

    def run(self):
        log.info(f"Channel hopper started: {self.channels} @ {self.dwell}s dwell")
        while not self._stop.is_set():
            for ch in self.channels:
                if self._stop.is_set():
                    break
                set_channel(self.iface, ch)
                time.sleep(self.dwell)

    def stop(self):
        self._stop.set()


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
            "t":     event.get("timestamp") or event.get("observed_at"),
            "mac":   event.get("source_mac") or event.get("mac"),
            "radio": event.get("radio"),
            "rssi":  event.get("rssi"),
            "type":  decoded.get("message_type"),
            "lat":   decoded.get("latitude"),
            "lon":   decoded.get("longitude"),
            "alt":   decoded.get("altitude_geo"),
            "speed": decoded.get("ground_speed"),
            "hdg":   decoded.get("heading"),
            "id":    decoded.get("uas_id"),
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
        self.hopper      = ChannelHopper(iface, CHANNELS_24, channel_dwell)
        self.count       = 0
        self.nan_count   = 0

    def _on_packet(self, data: bytes):
        # Parse RadioTap header to get RSSI and skip to 802.11 MAC header
        rt_len, rssi = _parse_radiotap(data)
        if rt_len >= len(data):
            return

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
                "payload":   raw,
                "decoded":   None,  # NAN full parsing is a future enhancement
            }
            self.forwarder.add(event)

    def run(self):
        log.info(f"DroneAware WiFi Feeder - Node: {self.node_id}")
        log.info(f"Interface: {self.iface}  |  Channels: {CHANNELS_24}")

        set_monitor_mode(self.iface)
        self.hopper.start()

        log.info("Scanning for Remote ID beacon frames (ASTM F3411)...")

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.bind((self.iface, 0))
        sock.settimeout(1.0)

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
                        requests.post(
                            "https://api.droneaware.io/api/node/heartbeat",
                            json={
                                "node_id":    self.node_id,
                                "uptime_s":   int(time.time() - self.start_time),
                                "fw_version": "1.0.16",
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
        "--iface", default="wlan1",
        help="Monitor-mode interface (default: wlan1)"
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
