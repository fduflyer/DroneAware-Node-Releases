#!/usr/bin/env python3
"""
DroneAware Local Web UI (v1.4.0)
=================================

Pi-local viewer for drone Remote ID detections. Always-works LAN dashboard
that runs alongside ble_feeder and wifi_feeder — operators on the same
network can browse live + recent detections without any server connectivity.

Architecture (Phase A — backend):

  - UDP listener on port 9999 with SO_REUSEPORT to coexist with the
    LocalPublisher broadcaster the feeders run. Receives JSONL detection
    events as they're broadcast and feeds them into the in-memory ring.

  - In-memory ring buffer of detections, per-MAC indexed, byte-bounded at
    DRONEAWARE_LOCAL_BUFFER_MAX_BYTES (default 50 MB when web UI is
    installed — install.sh bumps this from the LocalPublisher default of
    10 MB at install time). FIFO drop-oldest on overflow.

  - Startup replay: at boot, read /run/droneaware/detections.jsonl (the
    LocalPublisher tmpfs ring file) to seed recent state so the web UI has
    immediate history available without waiting for new UDP events.

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
import json
import logging
import os
import socket
import sys
import threading
import time
from queue import Empty, Full, Queue

from flask import Flask, Response, jsonify, request


# ---- Version stamping (CI overwrites .ver file at build time) ---------------

def _read_fw_version(fallback: str) -> str:
    """Read embedded version file (written by CI build). Falls back to dev
    value when running from source."""
    try:
        ver_path = os.path.join(
            getattr(sys, "_MEIPASS", os.path.dirname(__file__)), ".ver",
        )
        with open(ver_path) as f:
            return f.read().strip()
    except Exception:
        return fallback


FW_VERSION = _read_fw_version("1.4.0")


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
UDP_LISTEN_PORT    = 9999
LOCAL_RING_PATH    = "/run/droneaware/detections.jsonl"

# Buffer cap. Mirrors DRONEAWARE_LOCAL_BUFFER_MAX_BYTES the LocalPublisher
# uses. When web UI is installed, install.sh bumps that to 50 MB so the
# tmpfs file and the web UI's in-memory ring have matching capacity.
DEFAULT_BUFFER_MAX_BYTES = int(os.environ.get(
    "DRONEAWARE_LOCAL_BUFFER_MAX_BYTES", str(50_000_000)
))

# Maximum event age before pruning. Matches brand guide's "Buffer age —
# last ~30-60 min from RAM" and the max freshness tier (>30 min fades).
STALE_AGE_SEC      = 30 * 60
PRUNE_INTERVAL_SEC = 1.0

# SSE per-client queue depth — slow clients drop events rather than
# blocking the publisher. 100 events buffered per client is comfortable.
SSE_CLIENT_QUEUE_MAX = 100

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
        False if dropped (no MAC — can't index)."""
        mac = self._mac_of(event)
        if not mac:
            return False
        size = self._event_size(event)
        now = time.time()
        with self._lock:
            if mac not in self._by_mac:
                self._by_mac[mac] = collections.deque()
            self._by_mac[mac].append((event, size, now))
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

        Returns one entry per MAC with the most-recent event plus metadata.
        Per-MAC trail (full event list) is intentionally not included here —
        sidebar list view only needs the latest. Trail data ships in Tier 2."""
        now = time.time()
        with self._lock:
            macs = []
            for mac, dq in self._by_mac.items():
                if not dq:
                    continue
                latest_event, _, latest_ts = dq[-1]
                _, _, first_ts = dq[0]
                macs.append({
                    "mac":          mac,
                    "latest":       latest_event,
                    "first_seen":   first_ts,
                    "last_seen":    latest_ts,
                    "age_sec":      now - latest_ts,
                    "event_count":  len(dq),
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


# ---- UDP listener -----------------------------------------------------------

def udp_listen_thread():
    """Listen on UDP 9999 for LocalPublisher broadcasts. Parse JSON, add
    to store, push to SSE subscribers. SO_REUSEPORT lets us coexist with
    the feeders' broadcaster (which only sends, doesn't receive)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # SO_REUSEADDR for cross-restart, SO_REUSEPORT for coexistence with
    # other listeners on the same port (e.g., operator running `nc -luk 9999`).
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("0.0.0.0", UDP_LISTEN_PORT))
    log.info(f"UDP listener bound to 0.0.0.0:{UDP_LISTEN_PORT}")
    while True:
        try:
            data, _ = sock.recvfrom(65536)
        except OSError as e:
            log.warning(f"UDP recv error: {e}")
            time.sleep(0.5)
            continue
        try:
            event = json.loads(data.decode("utf-8", errors="ignore").strip())
        except json.JSONDecodeError:
            continue
        if store.add(event):
            broker.publish(event)


# ---- Startup replay ---------------------------------------------------------

def replay_ring_file():
    """At startup, replay the LocalPublisher tmpfs ring file into the store
    so the web UI has immediate recent history before any new UDP event
    arrives. Soft-fails if the file doesn't exist (feeder not running yet)."""
    if not os.path.exists(LOCAL_RING_PATH):
        log.info(f"No tmpfs ring at {LOCAL_RING_PATH} — starting with empty store")
        return
    replayed = 0
    try:
        with open(LOCAL_RING_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if store.add(event):
                    replayed += 1
    except Exception as e:
        log.warning(f"Replay of {LOCAL_RING_PATH} failed: {e}")
        return
    log.info(f"Replayed {replayed} events from {LOCAL_RING_PATH}")


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
    })
    return jsonify(s)


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

    replay_ring_file()

    threading.Thread(target=udp_listen_thread, daemon=True).start()
    threading.Thread(target=prune_thread, daemon=True).start()

    log.info(f"HTTP server starting on http://{args.bind}:{args.port}/")
    app.run(host=args.bind, port=args.port, threaded=True, debug=False,
            use_reloader=False)


if __name__ == "__main__":
    main()
