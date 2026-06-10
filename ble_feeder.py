#!/usr/bin/env python3
"""
DroneAware BLE Feeder - Remote ID Capture Script
Hardware: Raspberry Pi 4 + USB Bluetooth Adapter (Sena UD100 / CSR)

Captures BLE Remote ID advertisements (ASTM F3411 / UUID 0xFFFA) and forwards
raw payloads to the DroneAware server in 5-second batches.

The node does NO ODID decoding — all interpretation is done server-side.

Usage:
    sudo python3 ble_feeder.py --node-id NJ001 --server https://your-server/api

Requirements:
    pip3 install bleak requests
    sudo apt install bluetooth bluez
"""

import asyncio
import json
import logging
import argparse
import time
import socket
import struct
import collections
import os
import subprocess
import sys
import requests
from datetime import datetime, timezone
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

# -- Logging -------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/droneaware_ble.log"),
    ],
)
log = logging.getLogger("droneaware.ble")

def _read_fw_version(fallback: str) -> str:
    try:
        with open("/opt/droneaware/version") as f:
            v = f.read().strip()
            return v if v else fallback
    except Exception:
        return fallback

FW_VERSION = _read_fw_version("1.1.3")

# -- Constants -----------------------------------------------------------------
REMOTE_ID_SERVICE_UUID = "0000fffa-0000-1000-8000-00805f9b34fb"

# v1.3.0 byte-bounded forwarder buffer defaults — replaces the pre-v1.3.0
# event-count cap (MAX_BUFFER=1000). Bytes are the right unit: a 100/sec
# spoof flood filled the old 1000-event cap in 10 seconds; the new 50 MB
# cap preserves ~33 minutes of spoof evidence in the same scenario, and
# weeks of normal-traffic outage on the heaviest known node (dfw-drones).
# Tunable via env vars at startup (config.env):
#   DRONEAWARE_BUFFER_MAX_BYTES  — hard cap on buffer size
#   DRONEAWARE_BUFFER_WARN_PCT   — log a warning at this fill %
DEFAULT_BUFFER_MAX_BYTES = 50_000_000
DEFAULT_BUFFER_WARN_PCT  = 75

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


# -- Adapter Resolution --------------------------------------------------------

def find_adapter_by_mac(target_mac: str) -> str | None:
    """
    Resolve a Bluetooth adapter MAC address to its HCI device name (e.g. 'hci0').
    Parses hciconfig output — immune to index changes across reboots.
    """
    import re
    target = target_mac.lower().strip()
    try:
        out = subprocess.check_output(["hciconfig", "-a"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    # Each block starts with "hciN:" followed by "BD Address: XX:XX:XX:XX:XX:XX"
    current = None
    for line in out.splitlines():
        m = re.match(r'^(hci\d+):', line)
        if m:
            current = m.group(1)
        if current and "BD Address:" in line:
            addr = re.search(r'BD Address:\s+([0-9A-Fa-f:]{17})', line)
            if addr and addr.group(1).lower() == target:
                return current
    return None


# -- Health Checks -------------------------------------------------------------

def get_cpu_temp() -> float | None:
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return round(int(f.read().strip()) / 1000.0, 1)
    except Exception:
        return None


def get_cpu_load() -> tuple[float | None, float | None, float | None]:
    """Read /proc/loadavg and return (1-min, 5-min, 15-min) load averages.
    Returns (None, None, None) if /proc/loadavg is unavailable."""
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except Exception:
        return None, None, None


# /proc/stat baseline for cpu_percent delta calculation.
# Stored across heartbeat calls so we never block (the standard psutil-style
# `cpu_percent(interval=1.0)` would sleep 1s every minute, which is wasteful
# in the asyncio loop).
_cpu_stat_prev: tuple[int, int] | None = None


def get_cpu_percent() -> float | None:
    """Instantaneous CPU utilization since the previous call, computed from
    /proc/stat deltas (same metric htop / top / psutil report — fraction of
    time the CPU was NOT idle).

    Returns None on the first call (no baseline yet), if /proc/stat is
    unavailable, or on counter wraparound. Otherwise a float in [0.0, 100.0]
    rounded to one decimal place.

    Distinct from load average: high load with low cpu_percent indicates
    I/O wait (slow SD card, network); high cpu_percent indicates CPU bound.
    For DroneAware's "is this Pi about to thermal throttle?" question,
    cpu_percent is the more direct signal."""
    global _cpu_stat_prev
    try:
        with open("/proc/stat") as f:
            fields = f.readline().split()[1:]  # skip the "cpu" label
        nums = [int(x) for x in fields]
        total = sum(nums)
        # Kernel fields order: user, nice, system, idle, iowait, irq, softirq, ...
        # Count idle + iowait as "not doing useful work."
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    except Exception:
        return None

    prev = _cpu_stat_prev
    _cpu_stat_prev = (total, idle)

    if prev is None:
        return None  # first call — establish baseline, return None
    prev_total, prev_idle = prev
    total_delta = total - prev_total
    idle_delta  = idle  - prev_idle
    if total_delta <= 0:
        return None  # no time passed, or counter wraparound
    return round((1 - idle_delta / total_delta) * 100, 1)


def get_ble_health(adapter: str = "hci0") -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["hciconfig", adapter],
            capture_output=True, text=True, timeout=5,
        )
        return "UP RUNNING" in result.stdout, adapter
    except Exception:
        return False, adapter


async def _attempt_ble_recovery(adapter: str) -> bool:
    """Run the standard adapter-recovery sequence before tripping FAULT mode.
    Returns True if the adapter is healthy after recovery, False otherwise.

    Steps (progressive escalation, stops as soon as the adapter comes up):

      1. `rfkill unblock bluetooth` — clears any soft block. Cheap, idempotent,
         no side effects if no block was set.
      2. `hciconfig <adapter> up` — brings the interface up if it was DOWN
         (the common case for the Pi onboard BT after a boot where the UART
         link to the BT firmware didn't sync correctly — "Can't init device
         hciN: Connection timed out").
      3. `systemctl restart hciuart` — last resort. Cycles the UART driver
         service that owns the link to the Pi's onboard BT chip. Harmless on
         USB BT dongles (hciuart isn't involved) and on systems without that
         service. Followed by another `hciconfig up` and re-check.

    All subprocess calls are best-effort (`check=False`) — recovery is an
    optimistic side path, not load-bearing. If any step fails the next one
    still runs."""

    log.info(f"[Recovery] Attempting standard recovery on {adapter}")

    # Step 1: clear soft rfkill blocks
    log.info(f"[Recovery] (1/3) rfkill unblock bluetooth")
    subprocess.run(
        ["rfkill", "unblock", "bluetooth"],
        capture_output=True, check=False, timeout=5,
    )

    # Step 2: bring the interface up
    log.info(f"[Recovery] (2/3) hciconfig {adapter} up")
    subprocess.run(
        ["hciconfig", adapter, "up"],
        capture_output=True, check=False, timeout=5,
    )
    await asyncio.sleep(2)

    ble_ok, _ = get_ble_health(adapter)
    if ble_ok:
        log.info(f"[Recovery] Adapter {adapter} healthy after rfkill + hciconfig up")
        return True

    # Step 3: cycle the hciuart driver (Pi onboard BT only — no-op for USB)
    log.info(f"[Recovery] (3/3) systemctl restart hciuart && hciconfig {adapter} up")
    subprocess.run(
        ["systemctl", "restart", "hciuart"],
        capture_output=True, check=False, timeout=10,
    )
    await asyncio.sleep(3)
    subprocess.run(
        ["hciconfig", adapter, "up"],
        capture_output=True, check=False, timeout=5,
    )
    await asyncio.sleep(2)

    ble_ok, _ = get_ble_health(adapter)
    if ble_ok:
        log.info(f"[Recovery] Adapter {adapter} healthy after hciuart restart")
        return True

    log.warning(f"[Recovery] All recovery attempts failed for {adapter}")
    return False


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


# -- Payload Extraction --------------------------------------------------------

def extract_rid_payload(service_data: bytes) -> tuple[str, str] | tuple[None, None]:
    """
    Strip the 2-byte ASTM header (App Code 0x0D + counter) from BLE service
    data and return (rid_payload_hex, strategy).

    ASTM F3411-22a BLE service data layout:
      Byte 0:    App Code (0x0D)
      Byte 1:    Rotation counter
      Bytes 2-26: 25-byte ODID message

    Returns (None, None) if the data doesn't match any known format.
    """
    if len(service_data) == 27 and service_data[0] == 0x0D:
        return service_data[2:].hex(), "tail25_of_27"
    if len(service_data) == 26 and service_data[0] == 0x0D:
        return service_data[1:].hex(), "tail25_of_26"
    if len(service_data) == 25:
        return service_data.hex(), "raw25"
    return None, None


# -- Remote ID Decoder ---------------------------------------------------------
# (mirrors wifi_feeder.py — pure functions, no shared state)

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
    See wifi_feeder.py for full byte layout — kept in sync with that file.
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
    See wifi_feeder.py for full byte layout — kept in sync with that file.
    """
    if len(data) < 16:
        return {}
    op_location_type = data[1] & 0x0F
    op_lat = struct.unpack_from('<i', data, 2)[0] * 1e-7
    op_lon = struct.unpack_from('<i', data, 6)[0] * 1e-7

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


# -- Local Publisher -----------------------------------------------------------

# Decoded keys already exposed via short aliases in the local record, plus
# raw_hex (noise). Everything else in the decoded dict is added verbatim so
# LAN/offline consumers get the full ODID picture.
_LOCAL_ALIASED = {"message_type", "raw_hex", "latitude", "longitude",
                  "altitude_geo", "ground_speed", "heading", "uas_id"}


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
            # Backward-compatible short aliases (original schema)
            "lat":     decoded.get("latitude"),
            "lon":     decoded.get("longitude"),
            "alt":     decoded.get("altitude_geo"),
            "speed":   decoded.get("ground_speed"),
            "hdg":     decoded.get("heading"),
            "id":      decoded.get("uas_id"),
        }
        # Surface every remaining decoded field so offline/LAN consumers get the
        # full ODID picture (operator location, area, id_type, height_agl, etc.).
        for k, v in decoded.items():
            if k not in _LOCAL_ALIASED:
                record[k] = v
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


# -- HTTP Forwarder ------------------------------------------------------------

def _event_size(event: dict) -> int:
    """JSON-encoded byte size of a single event — used for cap accounting.
    Computed once at add-time and stored alongside the event in the buffer
    so we don't re-serialize on every eviction check."""
    return len(json.dumps(event, separators=(',', ':')))


class Forwarder:
    """
    Buffers raw BLE events and POSTs 5-second batches to the DroneAware server.

    Uses a byte-bounded ring buffer so that if the uplink is down for an
    extended period, oldest events are dropped rather than consuming
    unbounded memory. Failed batches are re-queued at the front of the
    buffer (drop-oldest on overflow preserves recency for forensics).

    Tunable via env vars at startup:
        DRONEAWARE_BUFFER_MAX_BYTES — hard cap on buffer size (default 50 MB)
        DRONEAWARE_BUFFER_WARN_PCT  — log a warning at this fill % (default 75)
    """

    def __init__(self, server_url: str, node_id: str,
                 batch_size: int = 200, flush_interval: float = 5.0,
                 token: str = ""):
        self.url               = server_url.rstrip("/") + "/ingest"
        self.node_id           = node_id
        self.batch_size        = batch_size
        self.flush_interval    = flush_interval
        self.token             = token
        # buffer holds (event_dict, size_bytes) tuples — single json.dumps
        # per event, reused on eviction without re-serializing.
        self.buffer            = collections.deque()
        self.buffer_bytes      = 0
        self.max_buffer_bytes  = int(os.environ.get("DRONEAWARE_BUFFER_MAX_BYTES",
                                                    str(DEFAULT_BUFFER_MAX_BYTES)))
        self.warn_pct          = int(os.environ.get("DRONEAWARE_BUFFER_WARN_PCT",
                                                    str(DEFAULT_BUFFER_WARN_PCT)))
        self.last_flush        = time.monotonic()
        self.sent_total        = 0
        self.dropped_total     = 0
        self._warned_high      = False  # one-shot, resets when buffer drains

    def add(self, event: dict):
        size = _event_size(event)
        self.buffer.append((event, size))
        self.buffer_bytes += size
        self._evict_to_cap()
        if len(self.buffer) >= self.batch_size:
            self._flush()

    def tick(self):
        """Time-based flush — call once per second from the main loop."""
        if time.monotonic() - self.last_flush >= self.flush_interval:
            self._flush()
            self.last_flush = time.monotonic()

    def _evict_to_cap(self):
        """Drop oldest events until buffer_bytes <= max_buffer_bytes. Logs
        threshold crossings (one warning per fill, one info on drain)."""
        while self.buffer_bytes > self.max_buffer_bytes and len(self.buffer) > 1:
            _, size = self.buffer.popleft()
            self.buffer_bytes -= size
            self.dropped_total += 1
        pct = (self.buffer_bytes * 100) // self.max_buffer_bytes if self.max_buffer_bytes else 0
        if pct >= self.warn_pct and not self._warned_high:
            log.warning(
                f"Forwarder buffer at {pct}% of {self.max_buffer_bytes // 1_000_000} MB cap "
                f"({len(self.buffer)} events, dropped_total={self.dropped_total})"
            )
            self._warned_high = True
        elif pct < 10 and self._warned_high:
            log.info(f"Forwarder buffer drained to {pct}% — caught up")
            self._warned_high = False

    def _flush(self):
        if not self.buffer:
            return

        batch = list(self.buffer)
        self.buffer.clear()
        self.buffer_bytes = 0
        events = [e for e, _ in batch]

        payload = {
            "node_id":     self.node_id,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "count":       len(events),
            "events":      events,
        }

        try:
            headers = {"X-Node-Token": self.token} if self.token else {}
            r = requests.post(self.url, json=payload, headers=headers, timeout=5)
            r.raise_for_status()
            self.sent_total += len(events)
            log.debug(f"Sent {len(events)} events ({self.sent_total} total)")
        except requests.RequestException as e:
            # Re-queue failed events at the front. _evict_to_cap drops the
            # oldest from the front if we now exceed the byte cap.
            for event, size in reversed(batch):
                self.buffer.appendleft((event, size))
                self.buffer_bytes += size
            self._evict_to_cap()
            log.warning(
                f"Flush failed: {e}  "
                f"(buffered={len(self.buffer)}, "
                f"buffer_bytes={self.buffer_bytes}, "
                f"dropped_total={self.dropped_total})"
            )


# -- BLE Feeder ----------------------------------------------------------------

class BLEFeeder:
    def __init__(self, node_id: str, server_url: str, adapter: str = "hci0",
                 verbose: bool = False, batch_size: int = 200,
                 flush_interval: float = 5.0, token: str = "",
                 wifi_adapter: str | None = None):
        self.node_id      = node_id
        self.adapter      = adapter
        self.wifi_adapter = wifi_adapter
        self.verbose      = verbose
        self.token        = token
        self.start_time   = time.monotonic()
        self.forwarder    = Forwarder(server_url, node_id, batch_size, flush_interval, token)
        self.publisher    = LocalPublisher()
        self.count        = 0

    def on_advertisement(self, device: BLEDevice, adv: AdvertisementData):
        """Callback for every BLE advertisement containing UUID 0xFFFA service data."""
        # Locate the FFFA service data entry
        svc_data  = None
        svc_uuid  = None
        for uuid, data in adv.service_data.items():
            if "fffa" in uuid.lower():
                svc_data = data
                svc_uuid = uuid
                break

        if svc_data is None:
            return

        rid_payload_hex, strategy = extract_rid_payload(svc_data)
        if rid_payload_hex is None:
            log.warning(
                f"Unrecognised service data from {device.address} "
                f"({len(svc_data)} bytes: {svc_data.hex()}) — skipped"
            )
            return

        self.count += 1

        event = {
            "node_id":              self.node_id,
            "observed_at":          datetime.now(timezone.utc).isoformat(),
            "observed_monotonic":   time.monotonic(),
            "radio":                "ble",
            "source_mac":           device.address,
            "source_name":          device.name or None,
            "rssi":                 adv.rssi,
            "channel":              None,  # BLE adv channel (37/38/39) not exposed by bleak
            "tx_power":             getattr(adv, "tx_power", None),
            "service_uuid":         svc_uuid,
            "service_data_hex":     svc_data.hex(),
            "service_data_len":     len(svc_data),
            "rid_payload_hex":      rid_payload_hex,
            "rid_payload_strategy": strategy,
            "adapter":              self.adapter,
        }

        if self.verbose:
            log.info(
                f"[BLE] MAC={device.address}  RSSI={adv.rssi}dBm  "
                f"payload={rid_payload_hex[:16]}...  strategy={strategy}"
            )

        self.forwarder.add(event)

        # Local publish — decode and fan out sub-messages for Message Pack
        decoded = decode_rid_message(bytes.fromhex(rid_payload_hex))
        if decoded:
            if decoded.get("message_type") == "Message Pack":
                sub_messages = decoded.get("messages", [])
            else:
                sub_messages = [decoded]
            for msg in sub_messages:
                pub_event = dict(event)
                pub_event["decoded"] = msg
                self.publisher.publish(pub_event)

    async def _fault_loop(self, reason: str):
        """
        Degraded loop entered when the BLE adapter is unhealthy or absent.
        Emits heartbeats with ble_ok=False so the server marks the radio as FAULT.
        Performs no BLE scanning. WiFi status (if measurable) is still reported.
        """
        log.warning(f"[FAULT] ble feeder running in degraded mode: {reason}")
        while True:
            try:
                await asyncio.sleep(60)
                cpu_temp = get_cpu_temp()
                cpu_pct  = get_cpu_percent()
                load_1m, load_5m, load_15m = get_cpu_load()
                temp_str    = f"{cpu_temp}°C" if cpu_temp is not None else "n/a"
                cpu_pct_str = f"{cpu_pct:.1f}%" if cpu_pct is not None else "n/a"
                load_str    = f"{load_1m:.2f}" if load_1m is not None else "n/a"
                log.info(
                    f"[Heartbeat] FAULT — ble_ok=False  reason={reason}  "
                    f"temp={temp_str}  cpu={cpu_pct_str}  load={load_str}"
                )
                if not self.token:
                    continue
                requests.post(
                    "https://api.droneaware.io/api/node/heartbeat",
                    json={
                        # Per-feeder heartbeat: ble_* fields only (see note above)
                        "node_id":      self.node_id,
                        "uptime_s":     int(time.monotonic() - self.start_time),
                        "fw_version":   FW_VERSION,
                        "cpu_count":    os.cpu_count(),
                        "cpu_temp_c":   cpu_temp,
                        "cpu_percent":  cpu_pct,
                        "load_1m":      load_1m,
                        "load_5m":      load_5m,
                        "load_15m":     load_15m,
                        "ble_ok":       False,
                        "ble_adapter":  self.adapter,
                        "ble_fault":    reason,
                    },
                    headers={"X-Node-Token": self.token},
                    timeout=5,
                )
            except requests.RequestException as e:
                log.warning(f"FAULT heartbeat failed: {e}")
            except Exception as e:
                log.warning(f"FAULT loop error: {e}")

    async def run(self):
        log.info(f"DroneAware BLE Feeder - Node: {self.node_id}  Adapter: {self.adapter}")

        # Adapter not healthy at startup — try the standard recovery sequence
        # before declaring FAULT. Auto-heals the Pi onboard BT UART sync issue
        # that intermittently leaves hci0 DOWN at boot, without requiring
        # operator intervention.
        ble_ok, _ = get_ble_health(self.adapter)
        if not ble_ok:
            log.warning(
                f"BLE adapter '{self.adapter}' not healthy at startup — attempting recovery..."
            )
            ble_ok = await _attempt_ble_recovery(self.adapter)

        if not ble_ok:
            log.error(
                f"BLE adapter '{self.adapter}' not healthy after recovery attempts — entering FAULT mode."
            )
            log.error("WiFi detection (if available) is unaffected and continues independently.")
            log.error("To restore BLE: connect a working Bluetooth adapter and restart this service.")
            await self._fault_loop("adapter not present (recovery attempted)")
            return

        log.info(f"Scanning for Remote ID broadcasts (UUID 0xFFFA)...")

        # No service_uuids filter here — the CSR adapter doesn't reliably
        # support BlueZ's UUID pre-filter. We filter for 0xFFFA in the callback.
        scanner = BleakScanner(
            detection_callback=self.on_advertisement,
            adapter=self.adapter,
        )

        async with scanner:
            ticker = 0
            while True:
                await asyncio.sleep(1.0)
                self.forwarder.tick()
                ticker += 1

                if ticker % 60 == 0:
                    cpu_temp        = get_cpu_temp()
                    cpu_pct         = get_cpu_percent()
                    load_1m, load_5m, load_15m = get_cpu_load()
                    ble_ok, ble_adp = get_ble_health(self.adapter)
                    temp_str    = f"{cpu_temp}°C" if cpu_temp is not None else "n/a"
                    cpu_pct_str = f"{cpu_pct:.1f}%" if cpu_pct is not None else "n/a"
                    load_str    = f"{load_1m:.2f}" if load_1m is not None else "n/a"

                    log.info(
                        f"[Heartbeat] seen={self.count}  "
                        f"sent={self.forwarder.sent_total}  "
                        f"dropped={self.forwarder.dropped_total}  "
                        f"buffered={len(self.forwarder.buffer)}  "
                        f"temp={temp_str}  cpu={cpu_pct_str}  load={load_str}  ble={ble_ok}"
                    )
                    if self.token:
                        try:
                            requests.post(
                                "https://api.droneaware.io/api/node/heartbeat",
                                json={
                                    # Per-feeder heartbeat: ble_* fields only.
                                    # Do NOT include wifi_ok or wifi_fault — the
                                    # server uses presence of an ok-field to
                                    # route the heartbeat to that feeder's
                                    # status row. WiFi status comes from
                                    # wifi_feeder's own heartbeat.
                                    "node_id":      self.node_id,
                                    "uptime_s":     int(time.monotonic() - self.start_time),
                                    "fw_version":   FW_VERSION,
                                    "cpu_count":    os.cpu_count(),
                                    "cpu_temp_c":   cpu_temp,
                                    "cpu_percent":  cpu_pct,
                                    "load_1m":      load_1m,
                                    "load_5m":      load_5m,
                                    "load_15m":     load_15m,
                                    "dropped_total": self.forwarder.dropped_total,
                                    "ble_ok":       ble_ok,
                                    "ble_adapter":  ble_adp,
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
        description="DroneAware BLE Remote ID Feeder"
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
        "--adapter", default="hci0",
        help="HCI adapter to use for scanning (default: hci0)"
    )
    parser.add_argument(
        "--adapter-mac", default=None,
        help="Resolve adapter by BD address instead of HCI index (recommended — immune to reboot index swaps)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=200,
        help="Max events per batch before forcing a flush (default: 200)"
    )
    parser.add_argument(
        "--flush-interval", type=float, default=5.0,
        help="Seconds between time-based flushes (default: 5.0)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Log every received packet"
    )
    args = parser.parse_args()

    wifi_adapter = os.environ.get("WIFI_ADAPTER") or None
    token        = resolve_token()

    adapter = args.adapter
    if args.adapter_mac:
        resolved = find_adapter_by_mac(args.adapter_mac)
        if resolved:
            log.info(f"Resolved adapter MAC {args.adapter_mac} -> {resolved}")
            adapter = resolved
        else:
            log.error(f"No adapter found with MAC {args.adapter_mac} — falling back to {adapter}")

    feeder = BLEFeeder(
        node_id=args.node_id,
        server_url=args.server,
        adapter=adapter,
        verbose=args.verbose,
        batch_size=args.batch_size,
        flush_interval=args.flush_interval,
        token=token,
        wifi_adapter=wifi_adapter,
    )

    try:
        asyncio.run(feeder.run())
    except KeyboardInterrupt:
        log.info("Feeder stopped by user.")


if __name__ == "__main__":
    main()
