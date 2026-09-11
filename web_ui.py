#!/usr/bin/env python3
"""
DroneAware Local Web UI (v1.4.0)
=================================

Pi-local viewer for drone Remote ID detections. Always-works LAN dashboard
that runs alongside ble_feeder and wifi_feeder — operators on the same
network can browse live + recent detections without any server connectivity.

Architecture (Phase A — backend):

  - Tmpfs ring file tail on /run/droneaware/detections.jsonl. This is
    the LocalPublisher's authoritative log of recent decoded detections;
    polling it for new lines is the reliable on-Pi consumer pattern.
    (We initially tried a UDP listener on 9999 with SO_REUSEPORT to mirror
    the LocalPublisher broadcaster, but Linux doesn't reliably deliver
    UDP broadcasts to local listeners on the same machine — sendto to
    255.255.255.255 routes packets out the default-route interface
    without loopback delivery to 0.0.0.0:9999 listeners. Confirmed
    empirically on NJ001 2026-06-23: broadcasts visible in tcpdump as
    `wlan0 Out` but never appeared on `lo` In or any 0.0.0.0 listener.
    Tmpfs file tail sidesteps the kernel quirk entirely.)

  - In-memory ring buffer of detections, per-MAC indexed, byte-bounded at
    DRONEAWARE_LOCAL_BUFFER_MAX_BYTES (default 50 MB when web UI is
    installed — install.sh bumps this from the LocalPublisher default of
    10 MB at install time). FIFO drop-oldest on overflow.

  - The tail thread also handles startup replay: at boot, reads the
    whole file from offset 0 (seeds the store with whatever LocalPublisher
    has already accumulated), then keeps the cursor and polls for new
    lines every TAIL_POLL_SEC. Handles file truncation (LocalPublisher
    trims) by resetting the cursor when current size < cursor.

  - Background sweep every 1s: prune events older than 30 minutes (matches
    the brand guide's maximum freshness tier — older than 30 min fades to
    gray on the UI).

  - Flask app on DRONEAWARE_WEB_PORT (default 5000):
      GET  /                → bundled HTML/CSS/JS dashboard
                              (Phase B: full UI — sidebar + map + filters +
                              detail modal + status bar, brand-guide
                              compliant. Mobile responsive < 768px.)
      GET  /static/<file>   → bundled Leaflet + any other static assets
      GET  /api/detections  → JSON snapshot of per-MAC current state
      GET  /api/status      → buffer %, CPU %, event/MAC counts, uptime
      GET  /events          → Server-Sent Events stream — pushes events as
                              they arrive via UDP, no polling required

Wire format compatibility: the LocalPublisher publish() method writes the
same JSON shape over UDP AND to the tmpfs ring file, so a single parsing
path handles both sources. The web UI is a pure consumer — does not modify
the feeders, the forwarder, or the wire format in any way.
"""
import argparse
import collections
import datetime
import json
import logging
import math
import os
import re
import socket
import subprocess
import sys
import tempfile

import spool
import threading
import urllib.request

import requests
import time
from queue import Empty, Full, Queue

from flask import Flask, Response, jsonify, request, send_file


# ---- Version stamping (CI overwrites .ver file at build time) ---------------

# What `droneaware update` / install.sh record as the node's firmware. Used
# as the fallback below, and by the update check.
INSTALLED_VERSION_PATH = "/opt/droneaware/version"


def _read_fw_version() -> str:
    """Version of the running binary.

    CI stamps web_static/.ver at build time (build.sh writes it before the
    PyInstaller --add-data call), so a released binary knows its own version.
    At runtime that resolves to _MEIPASS/web_static/.ver.

    Running from source there is no stamp. This used to fall back to a
    hardcoded "1.4.0", which reported a plausible-looking version number that
    was simply false — the footer claimed v1.4.0 while the node ran v1.5.2.1.
    Prefer the node's installed version, and if even that is missing say
    "dev", which cannot be mistaken for a real release.
    """
    try:
        ver_path = os.path.join(
            getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))),
            "web_static", ".ver",
        )
        with open(ver_path) as f:
            stamped = f.read().strip()
        if stamped:
            return stamped
    except Exception:
        pass
    try:
        with open(INSTALLED_VERSION_PATH) as f:
            installed = f.read().strip()
        if installed:
            return installed
    except Exception:
        pass
    return "dev"


FW_VERSION = _read_fw_version()


def _static_root() -> str:
    """Locate the bundled web_static directory containing index.html and
    leaflet.{js,css}. For PyInstaller runs, _MEIPASS points at the
    extracted bundle dir; for source runs (this dev path), it's
    web_static/ next to this file."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "web_static")


# ---- Configuration ----------------------------------------------------------

DEFAULT_PORT       = int(os.environ.get("DRONEAWARE_WEB_PORT", "5000"))
DEFAULT_BIND       = os.environ.get("DRONEAWARE_WEB_BIND", "0.0.0.0")
LOCAL_RING_PATH    = "/run/droneaware/detections.jsonl"
TAIL_POLL_SEC      = 0.5  # how often to poll the tmpfs ring for new lines

# Buffer cap. Mirrors DRONEAWARE_LOCAL_BUFFER_MAX_BYTES the LocalPublisher
# uses. When web UI is installed, install.sh bumps that to 50 MB so the
# tmpfs file and the web UI's in-memory ring have matching capacity.
DEFAULT_BUFFER_MAX_BYTES = int(os.environ.get(
    "DRONEAWARE_LOCAL_BUFFER_MAX_BYTES", str(50_000_000)
))

# Maximum event age before pruning. Extended from the brand guide's
# ~30-60 min default to 12 hours so quieter nodes still have something
# on their map after long idle periods (per Dan's request 2026-06-24 —
# many operators don't have constant drone activity; a 30-min window
# leaves their map empty most of the time). The byte cap
# (DRONEAWARE_LOCAL_BUFFER_MAX_BYTES, default 50 MB) still bounds RAM,
# so this just changes the time-based eviction not the size limit.
STALE_AGE_SEC      = 12 * 3600
PRUNE_INTERVAL_SEC = 1.0

# SSE per-client queue depth — slow clients drop events rather than
# blocking the publisher. 100 events buffered per client is comfortable.
SSE_CLIENT_QUEUE_MAX = 100

# Coarse world pack, downloaded from our own tile host. Replaces a bundled
# MBTiles file of tiles scraped from CartoDB's CDN — their rendered tiles
# redistributed inside our binary, the same exposure the live layer had.
# This is the offline floor: what a node with no region pack and no uplink
# can still draw.
WORLD_PACK_PATH = os.environ.get(
    "DRONEAWARE_WORLD_PACK_PATH", "/opt/droneaware/world.pmtiles")
WORLD_PACK_URL = os.environ.get(
    "DRONEAWARE_WORLD_PACK_URL", "https://tiles.droneaware.io/world.pmtiles")


def _world_pack_path() -> str | None:
    """The downloaded coarse world pack, or None."""
    return WORLD_PACK_PATH if os.path.isfile(WORLD_PACK_PATH) else None

# A downloaded Protomaps region pack: vector tiles (MVT) in a single
# PMTiles archive, rendered client-side by protomaps-leaflet. Replaces both
# the CartoDB CDN dependency and the zoom-0-6 raster bundle where present.
#
# Measured: a 10 km radius at zoom 0-15 is ~10 MB — roughly 14x smaller than
# the equivalent raster area, because vector tiles carry geometry rather
# than pixels and overzoom cleanly past their maximum zoom instead of
# blurring. One archive serves both day and night: the flavor is a
# client-side render option, not a separate download.
REGION_PACK_FILENAME = "region.pmtiles"

# The pack is DOWNLOADED, so it must not live in _static_root(). Under
# PyInstaller --onefile that resolves to _MEIPASS, a temp directory the
# loader recreates on every start and deletes on exit — a pack written there
# would silently vanish on the next restart. /opt/droneaware is persistent
# and already droneaware-owned, same as config.env.
REGION_PACK_PATH = os.environ.get(
    "DRONEAWARE_MAP_PACK_PATH", "/opt/droneaware/region.pmtiles")

# Upstream archive, used until a region pack has been downloaded.
#
# A node's browser cannot read this host directly: the bucket's CORS policy
# lists droneaware.io, and a node's origin is a LAN IP over plain HTTP that
# differs on every node and every network — there is no set of origins to
# enumerate. So web_ui forwards the byte ranges itself and the browser reads
# same-origin, which needs no CORS grant at all.
#
# Deliberately NOT a dated filename. Pinning 20260905.pmtiles in firmware
# would mean a release every time the planet is rebuilt.
TILE_UPSTREAM_URL = os.environ.get(
    "DRONEAWARE_TILE_URL", "https://tiles.droneaware.io/planet.pmtiles")

_tile_sess = None
_tile_sess_lock = threading.Lock()

# Reachability is cached: the map layer asks on every status poll, and a node
# with no uplink must not spend 8s in a connect timeout each time.
_tile_reach = {"at": 0.0, "ok": False}


def _tile_session() -> "requests.Session":
    """One session, so range requests reuse the TCP+TLS connection. Without
    this every range costs a fresh handshake, which is what made a naive
    per-tile walk take minutes rather than seconds."""
    global _tile_sess
    with _tile_sess_lock:
        if _tile_sess is None:
            _tile_sess = requests.Session()
            _tile_sess.headers["User-Agent"] = "droneaware-node"
        return _tile_sess


def _tile_upstream_reachable() -> bool:
    """Whether the tile host is usable right now. Cached for 60s."""
    if not TILE_UPSTREAM_URL:
        return False
    now = time.time()
    if now - _tile_reach["at"] < 60:
        return _tile_reach["ok"]
    ok = False
    try:
        r = _tile_session().get(TILE_UPSTREAM_URL,
                                headers={"Range": "bytes=0-7"}, timeout=6)
        # Byte 0-6 spell PMTiles. A captive portal returning 200 with an HTML
        # login page would otherwise read as a working tile host.
        ok = r.status_code == 206 and r.content[:7] == b"PMTiles"
    except Exception:
        ok = False
    _tile_reach.update(at=now, ok=ok)
    return ok


def _region_pack_path() -> str | None:
    """Absolute path to the downloaded region pack, or None if absent.

    Checks the persistent location first, then the bundle — the latter only
    so a source checkout with a pack dropped in web_static/ still works for
    development.
    """
    for candidate in (REGION_PACK_PATH,
                      os.path.join(_static_root(), REGION_PACK_FILENAME)):
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


# ── Node configuration (v1.6.0) ──────────────────────────────────────────────
# The settings panel edits config.env so operators do not have to SSH in.
#
# NEVER READ, NEVER WRITTEN, NEVER SENT TO THE BROWSER. This page answers to
# anyone on the network, so these must not leave the node:
#   NODE_TOKEN        — authenticates this node to the server. Leaking it lets
#                       someone impersonate the node and inject detections.
#   ENROLLMENT_SECRET — same class as NODE_TOKEN.
#   SERVER_URL        — rewrite it and the node's detections go elsewhere.
# The filter is an allowlist (CONFIG_SCHEMA), not a denylist, so a key added
# to config.env in future is invisible here until someone deliberately adds
# it — the safe direction to fail.
CONFIG_SECRETS = frozenset({"NODE_TOKEN", "ENROLLMENT_SECRET", "SERVER_URL"})

CONFIG_SCHEMA = [
    # NODE_ID is deliberately NOT here. It must match the node's enrollment
    # on the server, so it is shown as identity at the top of the panel
    # rather than offered as a field someone can break.
    {"group": "Location", "widget": "pickmap", "fields": [
        {"key": "NODE_MOBILE", "label": "Mobile node", "type": "bool",
         "help": "On: position comes from GPS. Off: from the fixed "
                 "coordinates below."},
        {"key": "NODE_LAT", "label": "Latitude", "type": "text"},
        {"key": "NODE_LON", "label": "Longitude", "type": "text"},
        {"key": "NODE_ELEVATION_AGL_M", "label": "Antenna height",
         "type": "number", "unit": "m above ground"},
    ]},
    {"group": "GPS", "fields": [
        {"key": "GPS_DEVICE", "label": "Serial device", "type": "text",
         "placeholder": "auto-detect",
         "help": "Leave blank to search /dev/ttyUSB* and /dev/ttyACM*."},
        {"key": "GPS_BAUD", "label": "Baud rate", "type": "text",
         "placeholder": "auto-detect"},
    ]},
    # Adapter roles are NOT free-text fields. `_orchestrate_wifi_mode`
    # reassigns them on every refresh, so a hand-typed MAC silently reverts —
    # the exact trap `droneaware swap` was built to close. Rendered as live
    # hardware plus a Swap button instead; see /api/adapters.
    {"group": "Radios", "widget": "adapters", "fields": [
        {"key": "BLE_ADAPTER", "label": "Bluetooth adapter", "type": "text"},
    ]},
    # "default" mirrors wifi_feeder.py ScanPlanHopper.DEFAULT_* (~line 1426-1468).
    # Duplicated across a process boundary because the feeder is a separate
    # binary; if those change, these must change with them.
    {"group": "Scanning", "widget": "defaults", "fields": [
        {"key": "ADAPTIVE_DWELL", "default": "true", "label": "Adaptive dwell", "type": "bool",
         "info": "Lets the node lengthen or shorten its time per channel "
                 "based on what it is hearing, instead of a fixed rotation. "
                 "Leave on unless you are reproducing a specific test."},
        {"key": "WIFI_DWELL_EXPLORE_SEC", "default": "1.0", "label": "Explore dwell",
         "type": "number", "unit": "s",
         "info": "How long the radio sits on each non-primary channel while "
                 "sweeping. Drones off the common channels beacon at 3-5 per "
                 "second, so even a short stop usually catches one. Raising "
                 "this makes each channel more reliable but lengthens the "
                 "time before the sweep returns to any given channel."},
        {"key": "WIFI_CAMP_TRIGGER_FRAMES", "default": "1", "label": "Frames to camp",
         "type": "number",
         "info": "How many Remote ID frames must arrive on a channel before "
                 "the radio stops sweeping and stays there. One is the "
                 "default: only an aircraft transmits the Remote ID "
                 "identifier, so a single frame already proves something is "
                 "flying. Raising this makes the node ignore aircraft it can "
                 "only hear intermittently, which are usually the distant "
                 "ones."},
        {"key": "WIFI_CAMP_TRIGGER_WINDOW_SEC", "default": "2.0", "label": "Camp trigger window",
         "type": "number", "unit": "s",
         "info": "The window those frames have to arrive within. Has no "
                 "effect while the frame count is 1, since the first frame "
                 "arms the camp immediately."},
        {"key": "WIFI_CAMP_SILENCE_SEC", "default": "6.0", "label": "Camp silence (common channels)",
         "type": "number", "unit": "s",
         "info": "How long to keep holding a common channel (2.4 GHz ch6, "
                 "5 GHz ch149) after the traffic stops. Aircraft on these "
                 "channels beacon only once per second, so a short gap is "
                 "normal and leaving too early loses the aircraft."},
        {"key": "WIFI_CAMP_SILENCE_OFFSOCIAL_SEC", "default": "3.0",
         "label": "Camp silence (other channels)", "type": "number", "unit": "s",
         "info": "The same timer for every other channel. Aircraft off the "
                 "common channels beacon several times a second, so silence "
                 "there means the aircraft has genuinely gone — this can be "
                 "shorter, which returns the radio to sweeping sooner."},
        {"key": "WIFI_CAMP_RELEASE_INTERVAL_SEC", "default": "9.5", "label": "Camp release",
         "type": "number", "unit": "s",
         "info": "While camped on a busy channel, how often to briefly leave "
                 "and check the others. Without this a single talkative "
                 "aircraft would hold the radio indefinitely and everything "
                 "else in the air would go unseen."},
    ]},
    # Rendered as presets plus an advanced grid, not as four text fields.
    # These keys already worked in config.env before v1.6 — the picker is a
    # front end for them, not a new mechanism.
    {"group": "Channels", "widget": "channels", "hidden": True, "fields": [
        {"key": "WIFI_SOCIAL_2G_CHANNEL", "default": "6", "type": "text"},
        {"key": "WIFI_SOCIAL_5G_CHANNEL", "default": "149", "type": "text"},
        {"key": "WIFI_EXPLORE_2G", "default": "", "type": "text"},
        {"key": "WIFI_EXPLORE_5G", "default": "", "type": "text"},
    ]},
    {"group": "History", "fields": [
        {"key": "DRONEAWARE_SPOOL_RETENTION_DAYS", "default": "90",
         "label": "Keep detections for", "type": "text", "unit": "days",
         "placeholder": "90",
         "info": "How long the node keeps its own record of what it saw, "
                 "after those detections have been uploaded. Enter a number of "
                 "days, or \"never\" to keep them until the size limit below "
                 "is reached. Detections that have NOT been uploaded yet are "
                 "kept no matter what this says — nothing is discarded just "
                 "because time has passed."},
        {"key": "DRONEAWARE_SPOOL_MAX_GB", "default": "4",
         "label": "History size limit", "type": "number", "unit": "GB",
         "placeholder": "4",
         "info": "A hard ceiling on the flight history, whichever setting is "
                 "smaller. It exists for the case where a node is fed "
                 "detections far faster than it would ever see legitimately, "
                 "which would otherwise fill the card in the name of keeping "
                 "history. Already-uploaded records are discarded first, and "
                 "the node never stops recording to stay under it."},
    ]},
    {"group": "Uploads", "fields": [
        # BATCH_SIZE and FLUSH_INTERVAL are deliberately absent: they are
        # coordinated with the server's ingest, and a node that disagrees
        # does not fail loudly, it just uploads badly.
        {"key": "DRONEAWARE_BUFFER_MAX_BYTES", "label": "Upload buffer",
         "type": "megabytes", "unit": "MB",
         "info": "How much of the upload backlog is held in memory before "
                 "being written to disk. Detections are saved to the node's "
                 "flight history either way, so a restart during an outage no "
                 "longer loses them — see History below for how long they are "
                 "kept."},
        {"key": "DRONEAWARE_BUFFER_WARN_PCT", "label": "Buffer warning",
         "type": "number", "unit": "%",
         "info": "How full the upload buffer gets before the node starts "
                 "warning in its logs and heartbeat."},
    ]},
    {"group": "Local interfaces", "fields": [
        {"key": "DRONEAWARE_WEB_PORT", "label": "Web UI port", "type": "number",
         "help": "Takes effect after the web service restarts."},
        {"key": "DRONEAWARE_LOCAL_UDP_TARGETS", "label": "UDP broadcast targets",
         "type": "text", "placeholder": "255.255.255.255:9999",
         "info": "Where this node re-broadcasts detections on your own "
                 "network, for tools like a Docker consumer or a second "
                 "display. Blank broadcasts to the whole subnet."},
        {"key": "DRONEAWARE_LOCAL_BUFFER_MAX_BYTES", "label": "Local ring buffer",
         "type": "megabytes", "unit": "MB",
         "info": "How much recent detection history the node keeps for this "
                 "page and the local feed. Larger means the map can show a "
                 "longer history after a browser reload."},
        {"key": "DRONEAWARE_LOG_MAX_BYTES", "label": "Log size cap",
         "type": "megabytes", "unit": "MB",
         "info": "Total size of each feeder's rotated log files. Roughly six "
                 "months of history at 40 MB; the cap exists to stop a fault "
                 "loop filling the SD card."},
    ]},
]

CONFIG_EDITABLE = frozenset(
    f["key"] for g in CONFIG_SCHEMA for f in g["fields"]
) - CONFIG_SECRETS

# ── Offline map region packs (v1.6.0) ────────────────────────────────────────
# The bundled world bundle is zoom 0-6: a global overview, far too coarse to
# follow a local track. An operator can download a pack for their own area
# instead, and these bound what they are allowed to ask for.
# Region packs are vector (Protomaps/PMTiles), not raster, so the old
# tile-count-times-bytes-per-tile model no longer applies. The published
# basemap builds stop at zoom 15; vector overzooms cleanly past that, so
# there is no zoom ladder to choose from and no depth to price.
PROTOMAPS_MAX_ZOOM = 15
OFFLINE_MAP_MIN_RADIUS_KM = 1.0
OFFLINE_MAP_MAX_RADIUS_KM = 30.0

# The pmtiles binary ships alongside the feeders. It reads the planet by HTTP
# range — it never downloads the 128 GiB archive — so a region extract costs
# tens of requests and seconds, not a mirror of the source.
PMTILES_BIN = os.environ.get("DRONEAWARE_PMTILES_BIN", "/opt/droneaware/pmtiles")

_MERC_LAT_MAX = 85.051129        # Web Mercator's own latitude limit


def _bbox(lat: float, lon: float, km: float) -> tuple:
    """Bounding box of +/- km around a point, as (w, s, e, n).

    The cos(lat) term is load-bearing: the same 50 km spans 1.18 deg of
    longitude at 40 N but 2.59 deg at 70 N. Without it a northern node gets
    a box less than half the width it asked for. max(cos, 0.01) stops the
    division exploding near the poles.

    Does NOT handle the antimeridian — a node at 179.8 E clamps to 180 and
    silently loses its eastern half. A single bbox cannot express a wrapped
    box; it needs two extracts merged. Left unhandled deliberately.
    """
    dlat = km / 111.0
    dlon = km / (111.0 * max(math.cos(math.radians(lat)), 0.01))
    return (max(-180.0, lon - dlon), max(-_MERC_LAT_MAX, lat - dlat),
            min(180.0, lon + dlon), min(_MERC_LAT_MAX, lat + dlat))


_SIZE_RE  = re.compile(r"archive size of ([\d.]+)\s*([kMG]?B)")
_TILES_RE = re.compile(r"fetching (\d+) tiles")
_UNIT = {"B": 1, "kB": 1000, "MB": 1000_000, "GB": 1000_000_000}


def _pmtiles_dry_run(bbox: tuple, maxzoom: int, timeout: int = 45) -> dict:
    """Ask pmtiles what a region would actually cost. Seconds, downloads nothing.

    Strictly better than modelling it. Pack size varies roughly 47x between
    open country and a dense city at the same radius, so an interpolated
    estimate is wrong nearly everywhere; this is exact for THIS location.
    """
    if not os.path.isfile(PMTILES_BIN):
        return {"error": "no_binary",
                "detail": "The map extractor is not installed on this node."}
    cmd = [PMTILES_BIN, "extract", TILE_UPSTREAM_URL, os.devnull,
           "--bbox=%.6f,%.6f,%.6f,%.6f" % bbox,
           f"--maxzoom={maxzoom}", "--dry-run"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "detail": "The tile host did not respond."}
    except Exception as e:
        return {"error": "failed", "detail": str(e)}
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        return {"error": "failed", "detail": out.strip()[-300:] or "extract failed"}
    m = _SIZE_RE.search(out)
    if not m:
        return {"error": "unparsed", "detail": out.strip()[-300:]}
    tiles = _TILES_RE.search(out)
    return {"bytes": int(float(m.group(1)) * _UNIT.get(m.group(2), 1)),
            "tiles": int(tiles.group(1)) if tiles else None}


# Headroom that must survive the download. A node that stops recording
# detections because the card filled with map tiles is strictly worse than a
# node with no offline map at all. Covers the 40 MB feeder log cap, the 50 MB
# forwarder buffer, and room for OS updates.
OFFLINE_MAP_RESERVE_BYTES = 500 * 1024 * 1024

START_TIME = time.time()

# ---- Logging ----------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("web_ui")

# Quiet down Flask/Werkzeug's default request logger — too noisy for SSE.
logging.getLogger("werkzeug").setLevel(logging.WARNING)


# ---- DetectionStore ---------------------------------------------------------

class DetectionStore:
    """Thread-safe per-MAC ring of recent detections with byte-bounded total.

    Each MAC maps to a deque of (event_dict, byte_size, received_at) tuples.
    On overflow (total_bytes > max_buffer_bytes), the OLDEST event across
    all MACs is dropped (FIFO drop-oldest, recency bias preserved).

    Stale pruning is separate from byte capping: prune_stale() removes
    events older than STALE_AGE_SEC regardless of total bytes used.
    """

    def __init__(self, max_bytes: int = DEFAULT_BUFFER_MAX_BYTES):
        self._lock = threading.Lock()
        self._by_mac: dict[str, collections.deque] = {}
        self._total_bytes = 0
        self._max_bytes = max_bytes

    @staticmethod
    def _mac_of(event: dict) -> str | None:
        # LocalPublisher writes "mac" key; some legacy events use source_mac.
        return event.get("mac") or event.get("source_mac")

    @staticmethod
    def _event_size(event: dict) -> int:
        return len(json.dumps(event, separators=(",", ":")))

    def add(self, event: dict) -> bool:
        """Add an event to the store. Returns True if accepted (had a MAC),
        False if dropped (no MAC — can't index).

        Timestamp note: we use the BROADCAST time (event.t — when the
        feeder captured the packet over the air) as the third tuple
        element, NOT time.time() at insertion. This matters for replay-
        at-startup: a 10-hour-old event in the tmpfs ring file should
        be displayed as 10 hours old, not as 'just arrived'. Without
        this, restarting web_ui made every old detection look LIVE
        until the next prune sweep ran (which also used insertion-time
        and so wouldn't prune them either)."""
        mac = self._mac_of(event)
        if not mac:
            return False
        size = self._event_size(event)
        # Use event.t (broadcast timestamp) when present; fall back to
        # current wall clock for events that somehow lack it (shouldn't
        # happen with LocalPublisher output, but defensive).
        ts = event.get("t")
        if isinstance(ts, str):
            # v1.5.0.8: pre-v1.5.0.8 ble_feeder emitted an ISO-8601 string
            # here. This branch used to fall straight through to time.time(),
            # so every replayed BLE event was stamped with ingest time — the
            # exact "restarting web_ui made every old detection look LIVE"
            # failure this method's docstring warns about, except it only ever
            # hit BLE. Parse rather than discard: the tmpfs ring survives the
            # upgrade, so ISO records keep replaying after the feeder is fixed.
            try:
                ts = datetime.datetime.fromisoformat(ts).timestamp()
            except ValueError:
                ts = None
        if not isinstance(ts, (int, float)):
            ts = time.time()
        with self._lock:
            if mac not in self._by_mac:
                self._by_mac[mac] = collections.deque()
            self._by_mac[mac].append((event, size, ts))
            self._total_bytes += size
            self._evict_to_cap_locked()
        return True

    def _evict_to_cap_locked(self):
        """FIFO drop-oldest across all MACs until total <= cap. Caller
        must hold self._lock."""
        while self._total_bytes > self._max_bytes:
            oldest_mac = None
            oldest_ts = float("inf")
            for mac, dq in self._by_mac.items():
                if dq and dq[0][2] < oldest_ts:
                    oldest_ts = dq[0][2]
                    oldest_mac = mac
            if oldest_mac is None:
                break
            _, size, _ = self._by_mac[oldest_mac].popleft()
            self._total_bytes -= size
            if not self._by_mac[oldest_mac]:
                del self._by_mac[oldest_mac]

    def prune_stale(self, max_age_sec: float = STALE_AGE_SEC):
        """Remove events older than max_age_sec. MACs with no remaining
        events are removed from the index."""
        cutoff = time.time() - max_age_sec
        with self._lock:
            empty_macs = []
            for mac, dq in self._by_mac.items():
                while dq and dq[0][2] < cutoff:
                    _, size, _ = dq.popleft()
                    self._total_bytes -= size
                if not dq:
                    empty_macs.append(mac)
            for mac in empty_macs:
                del self._by_mac[mac]

    def snapshot(self) -> dict:
        """Build a JSON-serializable snapshot for the /api/detections endpoint.

        Returns one entry per MAC with a MERGED view of the most-recent
        events plus metadata. Per-MAC trail (full event list) is intentionally
        not included here — sidebar list view only needs the merged state.
        Trail data ships in Tier 2.

        Why merged instead of literal-latest: ASTM RID drones broadcast a
        sequence of different message types (Basic ID, Location/Vector,
        System, Auth, etc.), each carrying a different subset of fields.
        Basic ID has the UAS-ID; Location/Vector has lat/lon/heading; System
        has operator location. If we returned only the literal most-recent
        event, half the rendering would have nulls for the wrong half of
        the time. Merging oldest-to-newest with "most recent non-null wins
        per field" gives a complete picture: lat/lon from the most recent
        Location/Vector, id from the most recent Basic ID, etc., all in
        one composite dict."""
        now = time.time()
        with self._lock:
            macs = []
            for mac, dq in self._by_mac.items():
                if not dq:
                    continue
                _, _, latest_ts = dq[-1]
                _, _, first_ts = dq[0]
                merged: dict = {}
                # Trail: chronological list of unique lat/lon positions
                # across this MAC's retained events. Capped at the last
                # 10,000 unique positions (~2.8h at 1Hz Location broadcasts,
                # comfortably beyond any single-sortie flight and within
                # the 12h stale window). Lets the frontend reconstruct
                # the flight-path polyline immediately on snapshot load
                # — without this, trails are client-only state that
                # gets lost on web_ui restart or browser reload.
                trail: list = []
                for event, _, _ in dq:
                    for k, v in event.items():
                        if v is not None:
                            merged[k] = v
                    lat = event.get("lat")
                    lon = event.get("lon")
                    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                        # Third element is altitude. Leaflet accepts
                        # [lat, lng, alt] triples wherever it takes a LatLng,
                        # so the flight path can be hue-coded by height
                        # without carrying a second parallel array.
                        alt = event.get("alt")
                        pt = [lat, lon, alt if isinstance(alt, (int, float)) else None]
                        if not trail or trail[-1][:2] != pt[:2]:
                            trail.append(pt)
                # Always include the MAC explicitly (the dict key is
                # authoritative — overwrite whatever was in events)
                merged["mac"] = mac
                macs.append({
                    "mac":          mac,
                    "latest":       merged,
                    "first_seen":   first_ts,
                    "last_seen":    latest_ts,
                    "age_sec":      now - latest_ts,
                    "event_count":  len(dq),
                    "trail":        trail[-10000:],
                })
            total_events = sum(len(dq) for dq in self._by_mac.values())
            return {
                "macs":          macs,
                "total_events":  total_events,
                "mac_count":     len(self._by_mac),
                "buffer_bytes":  self._total_bytes,
                "buffer_max":    self._max_bytes,
                "buffer_pct":    int(self._total_bytes * 100 / self._max_bytes)
                                 if self._max_bytes else 0,
                "snapshot_at":   now,
            }

    def stats(self) -> dict:
        """Cheap stats for /api/status (no full snapshot construction)."""
        with self._lock:
            return {
                "buffer_bytes": self._total_bytes,
                "buffer_max":   self._max_bytes,
                "buffer_pct":   int(self._total_bytes * 100 / self._max_bytes)
                                if self._max_bytes else 0,
                "mac_count":    len(self._by_mac),
                "event_count":  sum(len(dq) for dq in self._by_mac.values()),
            }


# ---- SSE broker -------------------------------------------------------------

class SSEBroker:
    """Fans out events to all subscribed SSE clients. Each subscriber gets
    its own bounded queue — slow clients drop events rather than blocking
    publishers (UDP loop, prune sweep)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers: list[Queue] = []

    def subscribe(self) -> Queue:
        q: Queue = Queue(maxsize=SSE_CLIENT_QUEUE_MAX)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: Queue):
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def publish(self, event: dict):
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(event)
            except Full:
                pass  # slow client — drop, don't block

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


# ---- Module-level singletons ------------------------------------------------

store = DetectionStore()
broker = SSEBroker()


# ---- Tmpfs ring file tail (the data source) ---------------------------------

def consumer_thread():
    """Single thread that handles both startup replay and live tailing of
    /run/droneaware/detections.jsonl — the LocalPublisher's tmpfs ring file.

    Initial pass reads from offset 0 (replays all currently-known events
    into the store so the UI has immediate recent history). Subsequent
    polls every TAIL_POLL_SEC read only new bytes since the last cursor
    position. Partial lines (file write in progress at poll boundary) are
    buffered in `pending` until the trailing newline arrives.

    Handles LocalPublisher's periodic file truncation: if current_size <
    cursor, the file shrunk (was trimmed), so reset cursor to 0 and
    re-read. Duplicate events from the re-read are harmless — the
    DetectionStore is per-MAC indexed and naturally deduplicates
    (a duplicate event for an existing MAC just updates last_seen)."""
    cursor = 0
    pending = b""
    initial_replay_done = False

    while True:
        try:
            if not os.path.exists(LOCAL_RING_PATH):
                if not initial_replay_done:
                    log.info(f"Waiting for {LOCAL_RING_PATH} to appear "
                             f"(feeders may not be running yet)")
                    initial_replay_done = True  # only log once
                time.sleep(TAIL_POLL_SEC)
                continue

            current_size = os.path.getsize(LOCAL_RING_PATH)

            if current_size < cursor:
                # LocalPublisher truncated the file (ring trim).
                log.info(f"Ring file truncated ({cursor} → {current_size}); "
                         f"resetting tail cursor")
                cursor = 0
                pending = b""

            if current_size > cursor:
                with open(LOCAL_RING_PATH, "rb") as f:
                    f.seek(cursor)
                    pending += f.read(current_size - cursor)
                cursor = current_size

                events_added = 0
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line.decode("utf-8", errors="ignore"))
                    except json.JSONDecodeError:
                        continue
                    if store.add(event):
                        events_added += 1
                        broker.publish(event)

                if not initial_replay_done and events_added:
                    log.info(f"Initial replay: {events_added} events from "
                             f"{LOCAL_RING_PATH}")
                    initial_replay_done = True

        except Exception as e:
            log.warning(f"Tail error: {e}")

        time.sleep(TAIL_POLL_SEC)


# ---- Background pruning -----------------------------------------------------

def prune_thread():
    """Every PRUNE_INTERVAL_SEC, drop events older than STALE_AGE_SEC."""
    while True:
        try:
            store.prune_stale()
        except Exception as e:
            log.warning(f"Prune error: {e}")
        time.sleep(PRUNE_INTERVAL_SEC)


# ---- CPU / load helpers (mirror feeders for /api/status consistency) -------

def get_cpu_temp() -> float | None:
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return round(int(f.read().strip()) / 1000, 1)
    except Exception:
        return None


def get_cpu_load() -> tuple[float | None, float | None, float | None]:
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except Exception:
        return None, None, None


CONFIG_ENV_PATH = "/opt/droneaware/config.env"
GPS_STATE_PATH  = "/run/droneaware/gps_state.json"


# config.env parsed on demand, re-read whenever the file changes on disk.
_cfg_cache = {"mtime": None, "values": {}}


def _config_file_values() -> dict:
    """Every key currently in config.env. Re-parsed only when it changes."""
    try:
        mtime = os.path.getmtime(CONFIG_ENV_PATH)
    except OSError:
        return _cfg_cache["values"]
    if mtime != _cfg_cache["mtime"]:
        values = {}
        try:
            with open(CONFIG_ENV_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    values[k.strip()] = v.strip()
        except Exception:
            return _cfg_cache["values"]
        _cfg_cache.update(mtime=mtime, values=values)
    return _cfg_cache["values"]


def _read_config_env(key: str) -> str | None:
    """Get a config value. If config.env defines it, the FILE wins.

    🚨 systemd starts this service with EnvironmentFile=config.env, so
    os.environ is a snapshot taken when the service started. Anything that
    rewrites config.env afterwards — the settings panel, `droneaware swap`,
    `droneaware refresh` — changes the file while this process keeps serving
    the boot-time value.

    An earlier version gated this on CONFIG_EDITABLE, which covered the
    settings panel but not the adapter roles: `swap` rewrote them, restarted
    the feeders, and left the Web UI showing the old assignment, so `status`
    and the Radios panel disagreed about which dongle was on which band.

    The rule that actually holds: a key present in config.env is owned by
    config.env, because the environment copy of it can only be stale. The
    environment is the fallback for keys the file does not define, which
    keeps genuine overrides working for a manual `python3 web_ui.py` run.
    """
    val = _config_file_values().get(key)
    if val is not None:
        return val.strip() or None
    val = os.environ.get(key)
    if val is not None:
        return val.strip() or None
    return None


# Whether this node can reach DroneAware. Distinct from whether the BROWSER
# can reach the node — the header shows both, because they fail separately
# and mean different things to an operator.
#
# Cached: the status poll runs every few seconds and a node with no uplink
# must not spend a connect timeout on every one of them.
_uplink = {"at": 0.0, "ok": False}


def _server_reachable() -> bool:
    url = (_read_config_env("SERVER_URL") or "").strip()
    if not url:
        return False
    now = time.time()
    if now - _uplink["at"] < 30:
        return _uplink["ok"]
    ok = False
    try:
        # Any answer at all proves the route. A 404 from the wrong path still
        # means the node reached DroneAware, which is the question asked.
        r = requests.get(url.rstrip("/") + "/health", timeout=4)
        ok = r.status_code < 500
    except Exception:
        ok = False
    _uplink.update(at=now, ok=ok)
    return ok


def _gps_device_present() -> bool:
    """Whether a GPS device exists. Mirrors the feeder's own discovery order
    rather than trusting GPS_DEVICE, which is blank on auto-detect nodes."""
    dev = (_read_config_env("GPS_DEVICE") or "").strip()
    if dev:
        return os.path.exists(dev)
    import glob
    return bool(glob.glob("/dev/ttyUSB*") or glob.glob("/dev/ttyACM*"))


def _elevation_agl() -> float | None:
    """Antenna height above ground, if the operator configured one."""
    try:
        return float(_read_config_env("NODE_ELEVATION_AGL_M"))
    except (TypeError, ValueError):
        return None


def get_home_location() -> dict | None:
    """Returns the node's home location for map centering and distance
    rings. Two sources:

      - Static node (NODE_MOBILE=false): NODE_LAT / NODE_LON from
        config.env (set at install time during enrollment).
      - Mobile node (NODE_MOBILE=true): current GPS fix from
        /run/droneaware/gps_state.json. Returns None if no fix yet.

    Returns None on any failure or missing data — frontend then keeps
    the map at the default continental-US view with no rings drawn."""
    try:
        mobile = (_read_config_env("NODE_MOBILE") or "false").lower() == "true"
        if mobile:
            try:
                with open(GPS_STATE_PATH) as f:
                    s = json.load(f)
            except Exception:
                return None
            if s.get("status") != "fix":
                return None
            lat, lon = s.get("lat"), s.get("lon")
            if lat is None or lon is None:
                return None
            return {"lat": float(lat), "lon": float(lon), "source": "gps",
                    "elevation_agl_m": _elevation_agl()}
        else:
            lat_str = _read_config_env("NODE_LAT")
            lon_str = _read_config_env("NODE_LON")
            if not lat_str or not lon_str:
                return None
            return {"lat": float(lat_str), "lon": float(lon_str),
                    "source": "static", "elevation_agl_m": _elevation_agl()}
    except Exception:
        return None




# ---- Flask app --------------------------------------------------------------

app = Flask(
    __name__,
    static_folder=_static_root(),
    static_url_path="/static",
)


# Phase A placeholder — kept around as a fallback if web_static/index.html is
# missing (e.g., dev runs without the full asset bundle). Phase B's index.html
# is served from disk via `/` below — see index() handler. Production deploys
# always have the full bundle, so this fallback shouldn't fire.
_PHASE_A_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DroneAware Local Viewer — Phase A</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           background: #0A1228; color: #E4ECFA; padding: 24px; }
    h1 { color: #10b981; font-size: 18px; font-weight: 700; }
    .label { color: #94A3B8; font-size: 9px; text-transform: uppercase;
             letter-spacing: 0.1em; }
    .metric { font-size: 24px; font-weight: 700; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
            margin: 24px 0; }
    .card { background: #0F1B3A; border: 1px solid #1E3A6E;
            padding: 16px; border-radius: 6px; }
    .accent { color: #00E5FF; }
    pre { background: #0F1B3A; padding: 12px; border-radius: 6px;
          overflow-x: auto; font-size: 12px; }
  </style>
</head>
<body>
  <h1>DroneAware Local Viewer — Phase A backend running</h1>
  <p class="label">v__VERSION__ — Phase B (full UI) ships next</p>
  <div class="grid">
    <div class="card">
      <div class="label">Active MACs</div>
      <div class="metric" id="m-mac">—</div>
    </div>
    <div class="card">
      <div class="label">Total Events</div>
      <div class="metric" id="m-events">—</div>
    </div>
    <div class="card">
      <div class="label">Buffer</div>
      <div class="metric" id="m-buffer">—</div>
    </div>
    <div class="card">
      <div class="label">Uptime</div>
      <div class="metric" id="m-uptime">—</div>
    </div>
  </div>
  <p class="label">Live event stream (SSE)</p>
  <pre id="log">waiting for events…</pre>
  <script>
    function poll() {
      fetch("/api/status").then(r => r.json()).then(s => {
        document.getElementById("m-mac").textContent = s.mac_count;
        document.getElementById("m-events").textContent = s.event_count;
        document.getElementById("m-buffer").textContent =
            s.buffer_pct + "% (" + (s.buffer_bytes/1e6).toFixed(1) + " MB)";
        const u = s.uptime_s, h = Math.floor(u/3600), m = Math.floor((u%3600)/60);
        document.getElementById("m-uptime").textContent = h + "h " + m + "m";
      }).catch(() => {});
    }
    poll(); setInterval(poll, 2000);

    const log = document.getElementById("log");
    const es = new EventSource("/events");
    let lines = [];
    es.onmessage = (e) => {
      const evt = JSON.parse(e.data);
      const mac = evt.mac || evt.source_mac || "—";
      const t = evt.type || "?";
      const ts = new Date().toLocaleTimeString();
      lines.unshift(ts + "  " + mac + "  " + t);
      lines = lines.slice(0, 20);
      log.textContent = lines.join("\\n");
    };
  </script>
</body>
</html>"""


@app.route("/")
def index():
    """Serve the bundled Phase B UI (web_static/index.html). Falls back to
    the Phase A placeholder if the bundle is missing — e.g., running from
    source without the web_static/ directory present."""
    bundle_index = os.path.join(_static_root(), "index.html")
    if os.path.isfile(bundle_index):
        return app.send_static_file("index.html")
    log.warning(f"No bundled UI at {bundle_index} — falling back to Phase A placeholder")
    return _PHASE_A_HTML.replace("__VERSION__", FW_VERSION), 200, {
        "Content-Type": "text/html; charset=utf-8",
    }


@app.route("/api/detections")
def api_detections():
    return jsonify(store.snapshot())


def _read_feeder_states() -> dict:
    """v1.5.0 Gap 3: read the per-band wifi state files written by the
    wifi_feeder process(es). Returns a dict shaped:
        {"wifi_2g": {...}, "wifi_5g": {...}}
    Missing / stale / unreadable state files map to None entries so the
    frontend can render "unknown" placeholders instead of crashing.

    Also includes a static BLE entry — v1.5.0 doesn't yet have a BLE
    state file (planned for v1.5.x), so we surface the systemd service
    status as a coarse indicator until then.
    """
    out = {"ble": None, "wifi_2g": None, "wifi_5g": None}
    names = _adapter_names_by_mac()
    for band in ("2g", "5g"):
        path = f"/run/droneaware/wifi_state_{band}.json"
        try:
            with open(path) as f:
                s = json.load(f)
            age = time.time() - (s.get("updated_at") or 0)
            s["age_sec"] = int(age)
            # Stale if not refreshed in >180s (heartbeat cycle is 60s;
            # 3 missed cycles = something is wrong)
            s["stale"] = age > 180
            # Name the hardware, not just the interface. wlan1/wlan2 tells an
            # operator nothing about which of two dongles they are looking at.
            mac = (s.get("adapter_mac") or "").lower()
            if mac and mac in names:
                s["adapter_name"] = names[mac]
            out[f"wifi_{band}"] = s
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    # BLE — read feeder-authored state, exactly like the WiFi bands above.
    # v1.5.0.7: ble_feeder now writes /run/droneaware/ble_state.json. This
    # used to shell out to `systemctl is-active` unconditionally, which is
    # liveness rather than health: a feeder looping in FAULT with a dead
    # adapter is still "active", so the UI showed BLE green while the CLI
    # and the server both correctly reported it down.
    try:
        with open("/run/droneaware/ble_state.json") as f:
            s = json.load(f)
        age = time.time() - (s.get("updated_at") or 0)
        s["age_sec"] = int(age)
        s["stale"] = age > 180
        # The frontend renders all three rows from one field name.
        s["wifi_ok"] = bool(s.get("ble_ok"))
        s["iface"] = s.get("adapter") or "hci0"
        s["health_source"] = "feeder"
        # v1.5.2.3+ publishes the radio's bus and USB id. Absent on older
        # feeders, so key off presence rather than assuming onboard.
        if s.get("adapter_usb_id"):
            s["adapter_name"] = f"USB adapter {s['adapter_usb_id']}"
        elif s.get("adapter_bus"):
            s["adapter_name"] = "Onboard Bluetooth"
        out["ble"] = s
    except (OSError, ValueError, json.JSONDecodeError):
        # No state file — either a pre-v1.5.0.7 ble_feeder, or one that has
        # not reached its first heartbeat yet. Fall back to systemd, but do
        # not present the result as health.
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "droneaware-ble.service"],
                capture_output=True, text=True, timeout=2,
            )
            active = r.stdout.strip() == "active"
            asked  = True
        except Exception:
            # Failing to ask is NOT a negative answer. The previous code
            # swallowed any exception into active=False, so a systemctl
            # that timed out or was refused under User=droneaware rendered
            # as "BLE down" — reported by two operators.
            active = False
            asked  = False
        out["ble"] = {
            "feeder": "ble",
            "iface": "hci0",      # conventional — actual adapter may vary
            "scan_mode": "lock",  # BLE listens on all advertising channels
            "wifi_ok": active,
            "health_source": "systemd" if asked else "unknown",
            "stale": not asked,   # unknown renders as stale, never as green
        }
    return out


@app.route("/api/status")
def api_status():
    s = store.stats()
    load_1m, load_5m, load_15m = get_cpu_load()
    s.update({
        "version":     FW_VERSION,
        "uptime_s":    int(time.time() - START_TIME),
        "cpu_temp_c":  get_cpu_temp(),
        "load_1m":     load_1m,
        "load_5m":     load_5m,
        "load_15m":    load_15m,
        "sse_clients": broker.subscriber_count(),
        "home":        get_home_location(),  # {lat, lon, source, elevation_agl_m}
        # The location row's label keys off these two, not off whether a fix
        # has landed — a mobile node with GPS hardware says "Live GPS" and
        # then "Awaiting fix", matching nodes.html.
        "mobile":      (_read_config_env("NODE_MOBILE") or "false").lower() == "true",
        "has_gps":     _gps_device_present(),
        # The SERVER_URL itself never leaves the node — only whether
        # the node can currently reach it.
        "uplink_ok":   _server_reachable(),
        # The browser MUST NOT use its own clock to age these detections. A Pi
        # has no RTC, and an offline node — the case this UI exists for — has
        # no NTP either, so its clock resumes from whatever was last written to
        # disk and can sit hours behind the phone looking at it. Ageing
        # node-stamped timestamps against a browser clock made live, moving
        # aircraft render as ">1 hour old" in both the text and the colour.
        "now":     time.time(),
        # Whether that clock can be shown to a human as a real date. When
        # false the UI must label history relatively ("3h ago") and never
        # print a wall-clock time the node cannot stand behind.
        "clock_synced": _clock_synced(),
        "node_id":     _read_config_env("NODE_ID") or "this-node",
        # Whether a Protomaps region pack has been downloaded. When true the
        # frontend renders vector tiles from /map.pmtiles and needs neither
        # a network round trip nor a second download — any zoom, either theme.
        "map_pack": (_region_pack_path() is not None
                     or _tile_upstream_reachable()
                     or _world_pack_path() is not None),
        "map_pack_bytes": (os.path.getsize(_region_pack_path())
                           if _region_pack_path() else None),
        # Changes whenever the pack on disk does. The client puts it in the
        # basemap URL, so downloading a new area busts both the browser cache
        # and the reader's in-memory copy of the previous archive's directory.
        # Without it a second download is invisible: same URL, a response the
        # browser has cached for a day, and a PMTiles reader that has already
        # parsed the file that used to be there.
        "map_pack_version": (int(os.path.getmtime(_region_pack_path()))
                             if _region_pack_path() else 0),
        # local  — a downloaded pack, works with no uplink
        # proxy  — streaming from the tile host through this node
        # none   — neither; the client keeps its raster fallback
        "map_source": ("region" if _region_pack_path()
                       else "proxy" if _tile_upstream_reachable()
                       else "world" if _world_pack_path() else "none"),
        # v1.5.0 Gap 3: per-feeder status for the three-row BLE/2.4/5
        # panel in the offline UI (matching My Nodes layout).
        "feeders":     _read_feeder_states(),
    })
    return jsonify(s)


@app.route("/api/offline-map/estimate")
def api_offline_map_estimate():
    """Price a region pack for three terrain densities.

    A single number is not honest here. MEASURED against the Protomaps
    planet build (2026-09-06), same radius, three places:

        10 km radius   rural Montana 0.7 MB
                       suburban NJ    10 MB
                       dense NYC      32 MB

    That is a 47x spread, so any bytes-per-area constant is wrong almost
    everywhere. The operator knows which of the three they live in; the
    node does not. So return all three and let them read the row that
    applies, rather than inventing a precision we do not have.
    """
    home = get_home_location() or {}
    if home.get("lat") is None:
        try:
            home = {"lat": float(_read_config_env("NODE_LAT")),
                    "lon": float(_read_config_env("NODE_LON"))}
        except (TypeError, ValueError):
            home = {}
    try:
        lat = float(request.args.get("lat", home.get("lat")))
        lon = float(request.args.get("lon", home.get("lon")))
    except (TypeError, ValueError):
        return jsonify({
            "error": "no_location",
            "detail": "No latitude/longitude given, and the node does not know "
                      "where it is. Set NODE_LAT/NODE_LON, or wait for a GPS fix.",
        }), 400
    try:
        radius = float(request.args.get("radius_km", 20.0))
    except ValueError:
        radius = 20.0
    radius = max(OFFLINE_MAP_MIN_RADIUS_KM, min(radius, OFFLINE_MAP_MAX_RADIUS_KM))

    # 🚨 Measure the filesystem the pack will actually be WRITTEN to, not the
    # one this code is running from. _static_root() is sys._MEIPASS in the
    # shipped PyInstaller binary — a temp directory under /tmp, which on a Pi
    # is a tmpfs sized at half of RAM. On a 1 GB node that is ~400 MB, below
    # the reserve, so the estimator reported zero usable space and refused
    # every download while the SD card sat 93% empty.
    #
    # Invisible when running from source, where _static_root() is the repo on
    # the real disk. It only appears in the binary operators actually run.
    try:
        st = os.statvfs(os.path.dirname(REGION_PACK_PATH))
        free = st.f_bavail * st.f_frsize
    except OSError:
        free = 0
    usable = max(free - OFFLINE_MAP_RESERVE_BYTES, 0)

    try:
        maxzoom = int(request.args.get("maxzoom", PROTOMAPS_MAX_ZOOM))
    except ValueError:
        maxzoom = PROTOMAPS_MAX_ZOOM
    maxzoom = max(6, min(maxzoom, PROTOMAPS_MAX_ZOOM))

    box = _bbox(lat, lon, radius)
    est = _pmtiles_dry_run(box, maxzoom)
    if "error" in est:
        return jsonify({**est, "center": {"lat": lat, "lon": lon},
                        "radius_km": radius, "maxzoom": maxzoom}), 503

    # Judge against the real number plus headroom. Telling an operator it
    # fits and then filling their card is the failure that matters.
    need = est["bytes"]
    return jsonify({
        "center": {"lat": lat, "lon": lon},
        "bbox": {"w": box[0], "s": box[1], "e": box[2], "n": box[3]},
        "radius_km": radius,
        "maxzoom": maxzoom,
        "limits": {
            "radius_km_min": OFFLINE_MAP_MIN_RADIUS_KM,
            "radius_km_max": OFFLINE_MAP_MAX_RADIUS_KM,
            "maxzoom_max": PROTOMAPS_MAX_ZOOM,
        },
        "disk": {
            "free_bytes": free,
            "reserve_bytes": OFFLINE_MAP_RESERVE_BYTES,
            "usable_bytes": usable,
        },
        "bytes": need,
        "tiles": est.get("tiles"),
        "fits": need <= usable,
        # No longer an estimate — pmtiles reports what the archive will be.
        "estimate_is_approximate": False,
    })


# USB id -> the name on the box. The descriptor strings report the chipset
# vendor ("Ralink", "MediaTek Inc.") not the brand an operator bought, which
# is not much help when two adapters are plugged into one Pi. Unknown ids
# fall back to the descriptor rather than showing nothing.
KNOWN_ADAPTERS = {
    "148f:3070": "Alfa AWUS036NH (Ralink RT3070)",
    "0e8d:7612": "Alfa AWUS036ACM (MediaTek MT7612U)",
    "0e8d:7610": "Panda/Alfa (MediaTek MT7610U)",
    "0bda:8812": "Alfa AWUS036ACH (Realtek RTL8812AU)",
    "0bda:881a": "Alfa AWUS036ACH (Realtek RTL8812AU)",
    "0bda:8811": "Alfa AWUS036ACS (Realtek RTL8811AU)",
    "0bda:a811": "Alfa AWUS036ACS (Realtek RTL8811AU)",
}


def _usb_ancestor(start: str) -> str | None:
    """Walk up from a net device to the USB device node that owns it."""
    path = start
    for _ in range(6):
        if os.path.isfile(os.path.join(path, "idVendor")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return None


def _read_first_line(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return ""


# ── Update check and operator actions (v1.6.0) ───────────────────────────────
# Checking for a release needs no privilege at all — it is one GitHub API
# call — so it is done here in Python rather than shelling out. Only APPLYING
# an update needs root, and that goes through the CLI via the narrow sudoers
# rule in /etc/sudoers.d/droneaware-webui.
GITHUB_RELEASES_API = (
    "https://api.github.com/repos/fduflyer/DroneAware-Node-Releases/releases")
VERSION_FILE = INSTALLED_VERSION_PATH

# Unauthenticated GitHub allows 60 requests/hour per IP. Cache so a panel
# left open on a wall display cannot exhaust that on its own.
_update_cache = {"at": 0.0, "data": None}
_update_lock = threading.Lock()

# One action at a time, with its result kept for the UI to poll. Actions
# restart feeders, so overlapping runs would fight each other.
_action_state = {"running": None, "started": 0.0, "last": None}
_action_lock = threading.Lock()

ACTIONS = {
    "refresh": ["sudo", "-n", "/usr/local/bin/droneaware", "refresh"],
    "swap":    ["sudo", "-n", "/usr/local/bin/droneaware", "swap"],
    "update":  ["sudo", "-n", "/usr/local/bin/droneaware", "update"],
    # Powering down cleanly is what makes the detection database survive being
    # moved: systemd sends SIGTERM, the feeders flush what they are holding to
    # disk, and nothing is lost. Pulling the plug instead costs the last few
    # seconds. Exists for the operator carrying a node in a vehicle who has no
    # keyboard on it.
    # ⚠️ This page is unauthenticated on the LAN, so anyone who can reach it
    # can switch the node off. That is the same exposure the Refresh, Swap and
    # Install buttons already carry — see project_webui_privilege — but this
    # one is the most obviously disruptive, hence the confirm step in the UI.
    "poweroff": ["sudo", "-n", "/usr/bin/systemctl", "poweroff"],
}

# The CLI writes for a terminal, so its output carries SGR color escapes.
# Rendered in a browser those show up as literal garbage around the words
# the operator actually needs to read.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


@app.route("/api/update-check")
def api_update_check():
    current = _read_first_line(VERSION_FILE) or "unknown"
    with _update_lock:
        fresh = (time.time() - _update_cache["at"]) < 900
        cached = _update_cache["data"]
    if fresh and cached:
        return jsonify({**cached, "current": current, "cached": True})

    try:
        req = urllib.request.Request(
            GITHUB_RELEASES_API,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "droneaware-node"})
        with urllib.request.urlopen(req, timeout=8) as r:
            releases = json.load(r)
    except Exception as e:
        # Offline is the normal case for a deployed node, not an error worth
        # shouting about — the panel just says it could not check.
        return jsonify({"current": current, "latest": None,
                        "available": False, "reachable": False,
                        "detail": str(e)})

    latest = None
    for rel in releases:
        if rel.get("draft") or rel.get("prerelease"):
            continue
        # Installer-only releases carry no binaries and must not be offered.
        if not any(a.get("name") == "wifi_feeder"
                   for a in rel.get("assets", [])):
            continue
        latest = rel.get("tag_name")
        break

    data = {"latest": latest, "reachable": True,
            "available": bool(latest
                              and _version_tuple(latest) > _version_tuple(current))}
    with _update_lock:
        _update_cache["at"] = time.time()
        _update_cache["data"] = data
    return jsonify({**data, "current": current, "cached": False})


def _run_action(name: str) -> None:
    cmd = ACTIONS[name]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        ok = p.returncode == 0
        detail = _ANSI_RE.sub("", (p.stdout or p.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        ok, detail = False, "timed out"
    except FileNotFoundError:
        ok, detail = False, "droneaware CLI not found"
    except Exception as e:
        ok, detail = False, str(e)
    log.info("[action] %s -> %s", name, "ok" if ok else f"FAILED: {detail}")
    with _action_lock:
        _action_state["running"] = None
        _action_state["last"] = {"action": name, "ok": ok,
                                 "detail": detail[-2000:],
                                 "at": time.time()}


@app.route("/api/action", methods=["GET", "POST"])
def api_action():
    if request.method == "GET":
        with _action_lock:
            return jsonify(dict(_action_state))

    name = (request.get_json(silent=True) or {}).get("action")
    if name not in ACTIONS:
        return jsonify({"error": "unknown_action"}), 400
    with _action_lock:
        if _action_state["running"]:
            return jsonify({"error": "busy",
                            "detail": f"{_action_state['running']} is still running."}), 409
        _action_state["running"] = name
        _action_state["started"] = time.time()
        _action_state["last"] = None
    threading.Thread(target=_run_action, args=(name,), daemon=True).start()
    return jsonify({"ok": True, "started": name})


def _retune_by_mac() -> dict:
    """MAC -> measured retune in ms, from the per-band state files.

    The feeder times its own radio at startup. The spread across adapters we
    have tested is 22-1007 ms, and the radio is deaf for all of it, so this
    is what tells an operator which of two adapters should be the one
    sweeping 5 GHz — the sweeper pays the cost on every leg.
    """
    out = {}
    for band in ("2g", "5g", ""):
        suffix = f"_{band}" if band else ""
        try:
            with open(f"/run/droneaware/wifi_state{suffix}.json") as f:
                st = json.load(f)
            mac = (st.get("adapter_mac") or "").lower()
            if mac and st.get("retune_ms"):
                out[mac] = st["retune_ms"]
        except (OSError, ValueError):
            continue
    return out


def _enumerate_adapters() -> list:
    """Live WiFi hardware and the role each adapter currently holds.

    Answers "which of these two identical-looking dongles is doing 5 GHz",
    which is the question an operator actually has. Shared by /api/adapters
    and the feeder rows, so both name the same hardware the same way.
    """
    roles = {}
    for key, role in (("WIFI_ADAPTER_2G_MAC", "2.4 GHz"),
                      ("WIFI_ADAPTER_5G_MAC", "5 GHz"),
                      ("WIFI_ADAPTER_MAC", "monitor")):
        mac = (_read_config_env(key) or "").strip().lower()
        if mac:
            roles.setdefault(mac, role)

    retune = _retune_by_mac()
    out = []
    try:
        ifaces = sorted(os.listdir("/sys/class/net"))
    except Exception:
        ifaces = []

    for iface in ifaces:
        base = f"/sys/class/net/{iface}"
        if not os.path.exists(os.path.join(base, "phy80211")):
            continue
        mac = _read_first_line(os.path.join(base, "address")).lower()
        driver = ""
        try:
            driver = os.path.basename(
                os.path.realpath(os.path.join(base, "device", "driver")))
        except Exception:
            pass

        usb_id = vendor = product = ""
        try:
            dev = os.path.realpath(os.path.join(base, "device"))
            usb = _usb_ancestor(dev)
            if usb:
                vid = _read_first_line(os.path.join(usb, "idVendor"))
                pid = _read_first_line(os.path.join(usb, "idProduct"))
                usb_id = f"{vid}:{pid}" if vid and pid else ""
                vendor = _read_first_line(os.path.join(usb, "manufacturer"))
                product = _read_first_line(os.path.join(usb, "product"))
        except Exception:
            pass

        # Onboard radios are backhaul by architecture and can't do monitor
        # mode — say so rather than leaving them looking like a candidate.
        onboard = driver == "brcmfmac" or not usb_id
        name = KNOWN_ADAPTERS.get(usb_id) or (
            " ".join(x for x in (vendor, product) if x).strip()
            or driver or "unknown")

        out.append({
            "iface": iface,
            "mac": mac,
            "driver": driver,
            "usb_id": usb_id,
            "name": "Onboard WiFi (network uplink)" if onboard else name,
            "onboard": onboard,
            "role": "network uplink" if onboard else roles.get(mac, "unassigned"),
            "retune_ms": retune.get(mac),
        })

    return out


@app.route("/api/adapters")
def api_adapters():
    return jsonify({"adapters": _enumerate_adapters()})


# Mirrors ScanPlanHopper.EXPLORE_*_CANDIDATES in wifi_feeder.py. Duplicated
# across a process boundary because the feeder is a separate binary; if those
# lists change, these must change with them.
# What the feeder scans when the explore keys are left empty. Shown in the
# advanced grid so "Both bands" renders as the channels actually visited —
# 2.4 goes past 1/6/11 because Parrot beacons on 5 MHz steps, which is how an
# ANAFI turned up on ch5.
DEFAULT_EXPLORE_2G = [1, 5, 6, 9, 11, 13]
DEFAULT_EXPLORE_5G = [149, 153, 157, 161, 165, 52, 56, 60, 64,
                      100, 104, 108, 112, 116, 120, 124, 128,
                      132, 136, 140, 144]

CHANNEL_BANDS = [
    {"band": "2.4 GHz", "social": 6,
     "channels": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]},
    {"band": "5 GHz U-NII-1", "channels": [36, 40, 44, 48]},
    {"band": "5 GHz U-NII-2 (DFS)", "channels": [52, 56, 60, 64]},
    {"band": "5 GHz U-NII-2C (DFS)",
     "channels": [100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]},
    {"band": "5 GHz U-NII-3", "social": 149,
     "channels": [149, 153, 157, 161, 165]},
]


# What a radio can tune to changes only when the hardware does, but probing it
# costs two `iw` calls per adapter and the settings panel re-reads it on every
# rebuild. During a refresh those calls run against interfaces being torn down
# and recreated, where each can sit until its timeout.
_phy_cache = {}


def _phy_channels_cached(iface: str) -> set:
    hit = _phy_cache.get(iface)
    if hit and time.time() - hit[0] < 300:
        return hit[1]
    chans = _phy_channels(iface)
    # Only cache a real answer. An empty set means the probe failed — often
    # because the interface is mid-reconfiguration — and caching that would
    # keep the picker empty for five minutes after it recovered.
    if chans:
        _phy_cache[iface] = (time.time(), chans)
    return chans


def _phy_channels(iface: str) -> set:
    """Channel numbers this iface's PHY can tune to.

    Same parse as wifi_feeder._supported_channels: `iw phy phyN info` prints
    lines like "* 5745 MHz [149] (10.0 dBm)", and newer iw prints "5745.0 MHz"
    — the bracketed channel number is the part that is stable across versions.
    Regulatory domain and hardware both show up here, which is why the picker
    asks the radio instead of assuming a channel list.
    """
    try:
        info = subprocess.run(["iw", "dev", iface, "info"],
                              capture_output=True, text=True, timeout=2, check=False)
        phy = None
        for line in info.stdout.splitlines():
            if line.strip().startswith("wiphy "):
                phy = line.strip().split()[-1]
                break
        if phy is None:
            return set()
        out = subprocess.run(["iw", "phy", f"phy{phy}", "info"],
                             capture_output=True, text=True, timeout=2, check=False)
        chans = set()
        for line in out.stdout.splitlines():
            if "MHz" not in line or "[" not in line or "disabled" in line:
                continue
            a, b = line.find("["), line.find("]", line.find("["))
            if a != -1 and b != -1:
                try:
                    chans.add(int(line[a + 1:b]))
                except ValueError:
                    pass
        return chans
    except Exception:
        return set()


# ── Is the node's clock trustworthy in ABSOLUTE terms? ───────────────────────
# A Pi has no RTC, and a node used offline has no NTP either, so its clock
# resumes from whatever was last written to disk. Relative ages ("3h ago") stay
# correct on such a node because both ends of the subtraction come from the
# same clock. Absolute times ("14:32 on the 9th") do not, and printing one the
# node cannot stand behind is worse than not printing it.
_clock_cache = {"at": 0.0, "synced": False}


def _clock_synced() -> bool:
    """True when the kernel says its clock is disciplined by a time source.

    Asks the kernel via ntp_adjtime() rather than a specific daemon, so it
    reads the same whether systemd-timesyncd, chrony or ntpd is running — or
    whether the operator set the time by hand with no daemon at all. A zeroed
    buffer means modes=0, which makes the call a read-only query. The return
    code is the whole answer: TIME_ERROR (5) is what the kernel reports while
    STA_UNSYNC is set. Deliberately not parsing the timex struct, whose field
    offsets vary by architecture.
    """
    now = time.time()
    if now - _clock_cache["at"] < 30:
        return _clock_cache["synced"]
    synced = False
    try:
        import ctypes, ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        buf = (ctypes.c_byte * 512)()
        synced = libc.ntp_adjtime(ctypes.byref(buf)) != 5   # 5 == TIME_ERROR
    except Exception:
        # No libc binding available — fall back to systemd-timesyncd's stamp
        # file, which only exists once it has actually synchronised.
        synced = os.path.exists("/run/systemd/timesync/synchronized")
    _clock_cache.update(at=now, synced=bool(synced))
    return _clock_cache["synced"]


@app.route("/api/channels")
def api_channels():
    """What this node's radios can tune to, and what they are set to scan.

    `supported` is the union across every monitor adapter, so on a
    dual-adapter node the grid shows the pair's combined reach. Empty means
    the query failed rather than "nothing is supported" — the UI has to show
    every channel as selectable in that case, because the feeder falls back to
    scanning the full list unfiltered for exactly the same reason.
    """
    supported = set()
    probed = 0
    for a in _enumerate_adapters():
        iface = a.get("iface")
        if not iface:
            continue
        found = _phy_channels_cached(iface)
        if found:
            probed += 1
            supported |= found
    return jsonify({
        "bands": CHANNEL_BANDS,
        "supported": sorted(supported),
        "probed": probed,
        "defaults": {
            "explore_2g": DEFAULT_EXPLORE_2G,
            "explore_5g": DEFAULT_EXPLORE_5G,
            "social_2g": 6,
            "social_5g": 149,
        },
    })


def _adapter_names_by_mac() -> dict:
    """MAC -> product name, for labelling the feeder rows."""
    try:
        return {a["mac"]: a["name"] for a in _enumerate_adapters() if a["mac"]}
    except Exception:
        return {}


# ── Flight history (the on-disk spool) ───────────────────────────────────────
# Read-only views over what the feeders wrote. web_ui runs as the login user
# and the spool is root-owned 0755/0644, so it can read but never modify —
# which is the right direction for a page that answers to anyone on the LAN.

@app.route("/api/history/bounds")
def api_history_bounds():
    """The extent of the node's own history, and whether it can be dated.

    `clock_synced` is load-bearing for the caller, not decoration. On a node
    whose clock has never been disciplined these timestamps are internally
    consistent but not real wall-clock times, so the UI must render the extent
    relatively ("3h ago" to "now") and withhold calendar dates.
    """
    try:
        b = spool.bounds()
    except Exception as e:
        return jsonify({"error": "unavailable", "detail": str(e)}), 500
    b["now"] = time.time()
    b["clock_synced"] = _clock_synced()
    return jsonify(b)


@app.route("/api/history/track")
def api_history_track():
    """Per-column tones for the replay slider: 0 gap, 1 listening, 2 detections.

    Three tones because an empty bucket is ambiguous. "Recording, heard
    nothing" and "the node was switched off" are both zero detections, and
    drawing them alike is wrong in exactly the case this release exists for —
    drive out, fly, drive home.
    """
    try:
        t0 = float(request.args.get("from", 0))
        t1 = float(request.args.get("to", 0))
        cols = int(request.args.get("columns", 600))
    except (TypeError, ValueError):
        return jsonify({"error": "bad_request"}), 400
    if not (t1 > t0):
        return jsonify({"error": "bad_range"}), 400
    return jsonify({"from": t0, "to": t1,
                    "tones": spool.track(t0, t1, cols)})


# The spool stores what the SERVER ingests: the raw feeder event, with the
# decoded ODID message nested under "decoded". The map renders what the
# LocalPublisher writes to the tmpfs ring: a flat record with lat/lon/id at the
# top level. Replay reads the first and has to hand back the second, so the
# translation lives here — mirroring LocalPublisher.publish() in wifi_feeder.py
# and ble_feeder.py. If those change, this must change with them.
_ALIASED = {"message_type", "raw_hex", "latitude", "longitude",
            "altitude_geo", "ground_speed", "heading", "uas_id"}


def _flatten_event(ev: dict) -> dict:
    decoded = ev.get("decoded") or {}
    if not decoded:
        # NAN frames and anything else the feeder could not decode carry no
        # position, so there is nothing for the map to draw. The ring drops
        # these too; replay matches it rather than inventing empty markers.
        return {}
    rec = {
        "t":       ev.get("timestamp") or ev.get("observed_at"),
        "mac":     ev.get("source_mac") or ev.get("mac"),
        "radio":   ev.get("radio"),
        "rssi":    ev.get("rssi"),
        "channel": ev.get("channel"),
        "type":    decoded.get("message_type"),
        "lat":     decoded.get("latitude"),
        "lon":     decoded.get("longitude"),
        "alt":     decoded.get("altitude_geo"),
        "speed":   decoded.get("ground_speed"),
        "hdg":     decoded.get("heading"),
        "id":      decoded.get("uas_id"),
    }
    for k, v in decoded.items():
        if k not in _ALIASED:
            rec[k] = v
    return rec


@app.route("/api/history/range")
def api_history_range():
    """Detections inside a window, oldest first, for playback."""
    try:
        t0 = float(request.args.get("from", 0))
        t1 = float(request.args.get("to", 0))
        limit = min(int(request.args.get("limit", 20000)), 50000)
    except (TypeError, ValueError):
        return jsonify({"error": "bad_request"}), 400
    if not (t1 > t0):
        return jsonify({"error": "bad_range"}), 400
    raw = spool.read_range(t0, t1, limit)
    events = [r for r in (_flatten_event(e) for e in raw) if r]
    return jsonify({"from": t0, "to": t1,
                    "count": len(events), "truncated": len(raw) >= limit,
                    "events": events})


@app.route("/api/config")
def api_config_get():
    """Current values for every editable key, plus the schema to render.

    Reads config.env directly rather than os.environ: the running process
    was started with the values as they were at boot, and the point of this
    page is to show what is on disk now.
    """
    on_disk = {}
    try:
        with open(CONFIG_ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                on_disk[k.strip()] = v.strip()
    except Exception:
        return jsonify({"error": "unreadable",
                        "detail": "Cannot read config.env."}), 500

    # Allowlist. A secret can never be reached even if it were listed.
    values = {k: on_disk.get(k, "") for k in CONFIG_EDITABLE}
    # Identity, shown but never editable — a multi-node operator has to be
    # able to see which node they are about to change.
    return jsonify({"schema": CONFIG_SCHEMA, "values": values,
                    "node_id": on_disk.get("NODE_ID", "")})


@app.route("/api/config", methods=["POST"])
def api_config_set():
    """Write changed keys back to config.env, preserving everything else.

    Rewrites in place line by line so comments, ordering and untouched keys
    survive — config.env is heavily commented and those comments are the
    only documentation some of these knobs have.
    """
    payload = request.get_json(silent=True) or {}
    changes = payload.get("values")
    if not isinstance(changes, dict):
        return jsonify({"error": "bad_request"}), 400

    rejected = [k for k in changes if k not in CONFIG_EDITABLE]
    if rejected:
        return jsonify({"error": "not_editable", "keys": sorted(rejected)}), 403

    clean = {}
    for k, v in changes.items():
        v = "" if v is None else str(v)
        # A newline would let one field forge additional config lines.
        if "\n" in v or "\r" in v:
            return jsonify({"error": "invalid_value", "key": k}), 400
        clean[k] = v.strip()

    try:
        with open(CONFIG_ENV_PATH) as f:
            lines = f.readlines()

        seen = set()
        out = []
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.split("=", 1)[0].strip()
                if key in clean:
                    out.append(f"{key}={clean[key]}\n")
                    seen.add(key)
                    continue
            out.append(line)

        for key in sorted(set(clean) - seen):
            out.append(f"{key}={clean[key]}\n")

        # Write via a temp file in the same directory, then replace, so a
        # crash mid-write cannot leave a node with a truncated config.
        d = os.path.dirname(CONFIG_ENV_PATH)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".config.env.")
        try:
            with os.fdopen(fd, "w") as f:
                f.writelines(out)
            os.chmod(tmp, 0o600)
            os.replace(tmp, CONFIG_ENV_PATH)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except PermissionError:
        return jsonify({"error": "read_only",
                        "detail": "The web service cannot write config.env."}), 403
    except Exception as e:
        return jsonify({"error": "write_failed", "detail": str(e)}), 500

    log.info("[config] updated %d key(s) from the local UI: %s",
             len(clean), ", ".join(sorted(clean)))
    return jsonify({"ok": True, "written": sorted(clean),
                    "restart_required": True})


# ── Region pack extraction (v1.6.0) ──────────────────────────────────────────
# The node builds its own pack from its own coordinates. pmtiles reads the
# planet by HTTP range, so this is tens of requests and seconds — the archive
# is never mirrored.
_ex = {"running": False, "pct": 0, "error": None, "bytes": 0, "at": 0.0}
_ex_lock = threading.Lock()


def _run_extract(lat: float, lon: float, radius_km: float, maxzoom: int) -> None:
    box = _bbox(lat, lon, radius_km)
    tmp = REGION_PACK_PATH + ".tmp"
    try:
        os.makedirs(os.path.dirname(REGION_PACK_PATH), exist_ok=True)
        # Two threads rather than the default four: kinder to a node on
        # domestic broadband, and the whole job is only tens of requests.
        cmd = [PMTILES_BIN, "extract", TILE_UPSTREAM_URL, tmp,
               "--bbox=%.6f,%.6f,%.6f,%.6f" % box,
               f"--maxzoom={maxzoom}", "--download-threads=2"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError(_ANSI_RE.sub(
                "", (r.stderr or r.stdout or "")).strip()[-300:] or "extract failed")

        # Verify before it becomes the live map. A truncated or failed
        # extract renamed into place renders a blank map with no explanation.
        with open(tmp, "rb") as f:
            if f.read(7) != b"PMTiles":
                raise RuntimeError("extract produced a file that is not PMTiles")
        size = os.path.getsize(tmp)
        os.replace(tmp, REGION_PACK_PATH)   # atomic on the same filesystem

        # Record what produced this pack so the node can later answer "is my
        # map still right for where I am?" without guessing.
        with open(REGION_PACK_PATH + ".json", "w") as f:
            json.dump({"lat": lat, "lon": lon, "radius_km": radius_km,
                       "maxzoom": maxzoom, "bytes": size,
                       "created": time.time()}, f)
        log.info("[pack] region pack built: %.1f MB, %.0f km, z%d",
                 size / 1e6, radius_km, maxzoom)
        with _ex_lock:
            _ex.update(running=False, pct=100, bytes=size, error=None,
                       at=time.time())
    except Exception as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        log.warning("[pack] region extract failed: %s", e)
        with _ex_lock:
            _ex.update(running=False, error=str(e), at=time.time())


@app.route("/api/offline-map/download", methods=["GET", "POST"])
def api_pack_download():
    if request.method == "GET":
        with _ex_lock:
            return jsonify(dict(_ex))

    if not os.path.isfile(PMTILES_BIN):
        return jsonify({"error": "no_binary",
                        "detail": "The map extractor is not installed."}), 503

    body = request.get_json(silent=True) or {}
    home = get_home_location() or {}
    try:
        lat = float(body.get("lat", home.get("lat")))
        lon = float(body.get("lon", home.get("lon")))
    except (TypeError, ValueError):
        return jsonify({"error": "no_location",
                        "detail": "This node does not know where it is."}), 400
    try:
        radius = float(body.get("radius_km", 20.0))
    except (TypeError, ValueError):
        radius = 20.0
    radius = max(OFFLINE_MAP_MIN_RADIUS_KM,
                 min(radius, OFFLINE_MAP_MAX_RADIUS_KM))
    try:
        maxzoom = int(body.get("maxzoom", PROTOMAPS_MAX_ZOOM))
    except (TypeError, ValueError):
        maxzoom = PROTOMAPS_MAX_ZOOM
    maxzoom = max(6, min(maxzoom, PROTOMAPS_MAX_ZOOM))

    # Price it first and refuse if it will not fit. A node that stops
    # recording detections because the card filled with map tiles is
    # strictly worse than a node with no offline map.
    est = _pmtiles_dry_run(_bbox(lat, lon, radius), maxzoom)
    if "error" in est:
        return jsonify(est), 503
    try:
        st = os.statvfs(os.path.dirname(REGION_PACK_PATH))
        usable = max(st.f_bavail * st.f_frsize - OFFLINE_MAP_RESERVE_BYTES, 0)
    except OSError:
        usable = 0
    if est["bytes"] > usable:
        return jsonify({"error": "no_space",
                        "detail": f"Needs {est['bytes'] // 1_000_000} MB but only "
                                  f"{usable // 1_000_000} MB is free once space is "
                                  f"kept for detection logs."}), 507

    with _ex_lock:
        if _ex["running"]:
            return jsonify({"error": "busy",
                            "detail": "A map download is already running."}), 409
        _ex.update(running=True, pct=0, error=None, bytes=0)
    threading.Thread(target=_run_extract,
                     args=(lat, lon, radius, maxzoom), daemon=True).start()
    return jsonify({"ok": True, "bytes": est["bytes"], "tiles": est.get("tiles")})


@app.route("/world.pmtiles")
def world_pack():
    """The coarse global overview, served on its own URL.

    /map.pmtiles serves the BEST archive available — a region pack when one
    exists. That made a downloaded pack replace the world overview instead of
    adding to it: zoom out past the downloaded box and there was nothing to
    draw, because a region archive contains only its own bbox.

    Serving the world pack separately lets the client stack them, coarse
    underneath and detailed on top, which is what "download detail for your
    own area" was always meant to mean.
    """
    path = _world_pack_path()
    if path is None:
        return jsonify({"error": "no_world_pack"}), 404
    return send_file(path, mimetype="application/octet-stream",
                     conditional=True, max_age=86400)


@app.route("/map.pmtiles")
def region_pack():
    """Serve the downloaded Protomaps region pack.

    conditional=True is load-bearing, not a nicety: PMTiles is read by HTTP
    byte range. The client fetches the header, then the directory, then
    individual tiles — all as Range requests. Without it Flask answers 200
    with the whole archive and the reader cannot seek, so the map renders
    blank with no error in the console.
    """
    path = _region_pack_path()
    if path is not None:
        return send_file(
            path,
            mimetype="application/octet-stream",
            conditional=True,          # -> 206 Partial Content
            max_age=86400,
        )

    # No local pack yet: forward the range to the tile host. Streamed, never
    # buffered — the upstream archive is ~138 GB and a single range can be
    # megabytes.
    if not TILE_UPSTREAM_URL or not _tile_upstream_reachable():
        # Offline floor: the coarse world pack, if it has been downloaded.
        world = _world_pack_path()
        if world:
            return send_file(world, mimetype="application/octet-stream",
                             conditional=True, max_age=86400)
        return Response(status=404)
    # Range is obvious. If-Match is load-bearing and easy to miss: the tile
    # archive is replaced in place on a planet rebuild, and a PMTiles client
    # holding a cached header sends If-Match with the ETag it read. Forward
    # it and a swap mid-session returns 412, so the client re-reads the
    # header. Strip it — as this did — and the conditional silently always
    # succeeds, and the client reads at offsets belonging to the previous
    # archive. That is garbage tiles with no error anywhere.
    headers = {}
    for h in ("Range", "If-Match", "If-None-Match"):
        v = request.headers.get(h)
        if v:
            headers[h] = v
    try:
        up = _tile_session().get(TILE_UPSTREAM_URL, headers=headers,
                                 stream=True, timeout=(6, 30))
    except Exception as e:
        log.warning("[tiles] upstream unreachable: %s", e)
        return Response(status=504)

    # 412 and 304 are answers, not failures, and both carry no body. Turning
    # a 412 into a 502 would hide exactly the signal the client needs.
    if up.status_code in (304, 412):
        out = Response(status=up.status_code)
        for h in ("ETag", "Cache-Control"):
            if h in up.headers:
                out.headers[h] = up.headers[h]
        up.close()
        return out

    if up.status_code not in (200, 206):
        log.warning("[tiles] upstream returned %s", up.status_code)
        up.close()
        return Response(status=502)

    out = Response(up.iter_content(chunk_size=65536),
                   status=up.status_code,
                   mimetype="application/octet-stream")
    # Content-Range and Accept-Ranges are what make the reader able to seek;
    # dropping them turns a working proxy into a blank map.
    for h in ("Content-Range", "Content-Length", "Accept-Ranges", "ETag"):
        if h in up.headers:
            out.headers[h] = up.headers[h]
    out.headers["Cache-Control"] = "public, max-age=3600"
    return out


@app.route("/events")
def sse_events():
    """Server-Sent Events stream. Each detection received by the UDP
    listener is pushed to all subscribers. Sends a keep-alive comment
    every 15s of silence so proxies/browsers don't time out the connection."""
    def stream():
        q = broker.subscribe()
        try:
            while True:
                try:
                    event = q.get(timeout=15)
                    yield f"data: {json.dumps(event)}\n\n"
                except Empty:
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            pass
        finally:
            broker.unsubscribe(q)
    return Response(stream(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",  # disable nginx-style proxy buffering
    })


# ---- main -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DroneAware Local Web UI (v1.4.0)",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"HTTP port (default {DEFAULT_PORT})")
    parser.add_argument("--bind", default=DEFAULT_BIND,
                        help=f"Bind address (default {DEFAULT_BIND})")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    log.info(f"DroneAware Local Web UI v{FW_VERSION}")
    log.info(f"Buffer cap: {store._max_bytes // 1_000_000} MB  "
             f"Stale threshold: {STALE_AGE_SEC}s")
    log.info(f"Data source: tail {LOCAL_RING_PATH} every {TAIL_POLL_SEC}s")


    threading.Thread(target=consumer_thread, daemon=True).start()
    threading.Thread(target=prune_thread, daemon=True).start()

    log.info(f"HTTP server starting on http://{args.bind}:{args.port}/")
    app.run(host=args.bind, port=args.port, threaded=True, debug=False,
            use_reloader=False)


if __name__ == "__main__":
    main()
