# Changelog

All notable changes to DroneAware Node will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Full release artifacts and discussion notes live at the
[GitHub Releases page](https://github.com/fduflyer/DroneAware-Node-Releases/releases).

---

## [1.4.5] — Unreleased

Delivers the offline operability the v1.4.0 Local Web UI release
promised but only half-delivered. v1.4.0 made the Web UI itself work
without internet to droneaware.io (feeders, sidebar, API, SSE all
local), but the Leaflet basemap still required the browser to reach
CartoDB at runtime — air-gapped operators got drone markers floating
on a blank background. v1.4.5 closes that gap.

### Added

- **Bundled world-overview basemap inside the web_ui binary.** A
  ~15 MB MBTiles file (`web_static/world-tiles.mbtiles`) covering
  zoom 0-6 worldwide in CartoDB Dark Matter style ships inside the
  web_ui PyInstaller binary via the existing `--add-data
  web_static:web_static`. At those zoom levels the operator sees
  country boundaries, state outlines, coastlines, and major cities —
  enough recognizable context to know where drone markers are even
  with zero internet connectivity from the browser.

- **`/tiles/<z>/<x>/<y>.png` route in web_ui.** Serves the bundled
  MBTiles content. Queries the SQLite file by tile coordinate (with
  XYZ→TMS row conversion), returns the PNG bytes with aggressive
  browser caching (`Cache-Control: max-age=86400, immutable` —
  tile content is fixed for the life of the release). Returns 404
  for zoom levels beyond the bundle range or for missing tiles, so
  Leaflet's tile error handler degrades gracefully.

- **`tiles_local` + `tiles_local_max_zoom` fields in `/api/status`.**
  Lets the frontend (and any API consumer) know whether the bundled
  basemap is available on this node and up to what zoom level.

- **Dual-layer Leaflet config with online/offline auto-fallback.**
  The Web UI's tile source is no longer hardcoded to CartoDB:
  - Initial source picked by `navigator.onLine` at page load
  - First `tileerror` event on the CartoDB layer triggers an
    immediate swap to the bundled local layer — covers the
    "navigator says online but firewall blocks CartoDB" case
  - `window.online` / `offline` events keep the source in sync
    with the browser's network state
  - Online operators get the full street-level CartoDB experience
    unchanged; offline operators get the world overview seamlessly
    without any setup or page refresh
  - Local layer uses `maxNativeZoom: 6` — Leaflet stretches the
    zoom-6 tiles for higher zooms so the operator can still zoom
    into a drone's position; the basemap gets blurry but stays
    correctly positioned

### Architecture notes

- **No new dependencies.** `sqlite3` is in the Python standard
  library; MBTiles is just a SQLite file with a specific schema.
- **No operator action required.** Operators upgrade via
  `sudo droneaware update`; the bundled MBTiles ships with the new
  web_ui binary automatically. Existing Web UI installs get the
  offline basemap on next update.
- **No CDN dependencies for the offline path.** The bundled basemap
  serves from the local file system; the only external requests
  remain CartoDB tile loads while online (unchanged from v1.4.0).
- **Online behavior unchanged.** Online operators see exactly what
  they saw in v1.4.0 — CartoDB Dark Matter or Positron tiles, full
  street-level detail at all zoom levels.

### Known limitations (acceptable trade-offs)

- **Bundled tiles are dark-mode only.** Bundling both Dark Matter
  and Positron would roughly double the binary size (~30 MB
  instead of ~15 MB). Day-mode toggle while offline leaves the
  basemap on Dark Matter; the rest of the UI chrome (sidebar,
  popups, status bar) still flips to day colors. Online operators
  in day mode see Positron tiles as before.
- **Maximum offline zoom is 6.** At higher zoom levels the bundle's
  zoom-6 tiles stretch (visibly blurry but positionally correct).
  Operators wanting street-level offline detail can either re-run
  the maintainer script with `--max-zoom 7` for a ~50 MB bundle
  (and we ship a bigger binary), or wait for v1.4.6's per-region
  download command which provides street-level detail for the
  operator's area without inflating the universal world bundle.

---

## [1.4.4] — Unreleased

Closes the install.sh side of the same config-key drift bug that v1.4.2
fixed for the install-webui path. Also the **first non-pre-release in
the v1.4.x line** — operators on v1.3.0.2 will get all of v1.4.x's
work (Local Web UI, API, UDP target configurability, UX polish, render
perf, version display fixes, and now the config-key fix) in a single
`sudo droneaware update` hop, skipping the broken-version-display
prereleases v1.4.0 through v1.4.2 entirely.

### Fixed

- **Fresh installs now get every release config key.** install.sh's
  `write_config` was a parallel list of "current release keys" that
  drifted from the canonical list in the droneaware CLI's
  `migrate_config_env`. Concretely, `DRONEAWARE_LOCAL_UDP_TARGETS`
  (added late in the v1.4.0 cycle) reached `migrate_config_env` but
  never reached `write_config`, so brand-new installs missed the key
  in their config.env. Functionally harmless — feeders default to
  broadcasting on `255.255.255.255:9999` — but operators couldn't
  discover the override in their config without reading docs.

  Fix: install.sh runs `/usr/local/bin/droneaware __migrate` after
  `write_config` completes (new `migrate_config` step in the main
  flow). `migrate_config_env` is now the single source of truth for
  release keys; install.sh's `write_config` only writes the minimum
  bootstrap config. Future release keys added to `migrate_config_env`
  automatically reach fresh installs without install.sh updates.
  Failure is non-fatal — every release key has a code-side default.

### What v1.4.4 brings forward (cumulative since v1.3.0.2)

Operators updating directly from v1.3.0.2 → v1.4.4 receive everything
shipped in the v1.4.x prereleases:

- **v1.4.0:** Local Web UI (Pi-local detection viewer) + HTTP API + configurable LocalPublisher UDP targets
- **v1.4.1:** Web UI polish — day-mode tile swap, sidebar sort, Detection Details panel stability, opt-in flight paths
- **v1.4.2:** Web UI close-zoom render perf (Canvas + ring hiding), web_ui version stamping (build side), install-webui config migration
- **v1.4.3:** web_ui version-file path lookup (Python side)
- **v1.4.4:** install.sh release-config migration (this release)

See individual prerelease entries below for full per-version detail.

---

## [1.4.3] — Unreleased

One-line follow-up to v1.4.2's `.ver` stamping work. The v1.4.2 build
correctly wrote `web_static/.ver` and PyInstaller correctly bundled it
into the binary at `_MEIPASS/web_static/.ver` — but `_read_fw_version()`
in `web_ui.py` was looking for the file at `_MEIPASS/.ver` (bundle
root), not under `web_static/`. So the v1.4.2 binary embedded the
right version string but couldn't find it at runtime, fell through to
the hardcoded fallback in `web_ui.py:84`, and continued to misreport
as `1.4.0`. Verified via `find /tmp -name .ver` on a v1.4.2 install —
the file was present with the correct value.

### Fixed

- **`web_ui` now actually self-reports the correct version.** Path
  fix in `_read_fw_version()` — append `web_static/` so the lookup
  matches the location PyInstaller bundles the file. Single-line
  Python change. `build.sh`, `.gitignore`, and the workflow's
  `VERSION` export are unchanged from v1.4.2; they were correct, the
  Python lookup was the missing piece.

---

## [1.4.2] — Unreleased

Three small follow-ups to v1.4.0/v1.4.1, all surfaced during NJ007
field deployment. One is a render-perf fix (operator-visible), two
are quality-of-life cleanups for operator config + build telemetry.
No new features, no schema changes, no breaking changes.

### Fixed

- **Web UI no longer lags at close zoom.** The Local Web UI's
  10 concentric distance rings around home are drawn as Leaflet vector
  overlays. At street-level zoom (>~14), the 10-mile ring is ~27,000
  pixels across — most of it off-screen, but the default SVG renderer
  keeps the full path in the DOM and re-projects it on every pan.
  Measured: 329 ms of browser Presentation delay per pointer event
  (Chrome DevTools INP) at the affected zoom range. Two changes:
  - Switch Leaflet to the Canvas renderer (`preferCanvas: true` on
    the map). Canvas culls off-screen vector geometry far more
    aggressively than SVG. Also benefits the dashed
    operator→drone connectors and the flight-path polyline when
    toggled on. HTML divIcon markers (drone, operator H, home
    pulse) are unaffected — they're DOM elements, not overlays.
  - Hide `state.homeLayer` (rings + ring labels + home pulse marker)
    when zoom > 14. At street-level zoom the rings provide no useful
    range context anyway. Layer membership is preserved, so panning
    or zooming back out restores everything instantly.

- **`web_ui` now self-reports the correct firmware version.** The
  binary's `_read_fw_version()` was looking for a `.ver` file
  embedded by CI at build time, but `build.sh` never wrote that
  file — so every release fell through to the hardcoded fallback
  string in `web_ui.py`. As a result, both v1.4.0 and v1.4.1 self-
  reported as `v1.4.0` in `/api/status.version` and the UI footer,
  even though the actual content was correct. `build.sh` now writes
  `web_static/.ver` from the `VERSION` env var (passed in by
  `.github/workflows/build.yaml` from `inputs.version`) before the
  web_ui PyInstaller call. PyInstaller's existing `--add-data`
  picks it up automatically; no Python changes needed. `.gitignore`
  updated to skip the build artifact. (Note: this fixes the version
  string display going forward — installed v1.4.0/v1.4.1 binaries
  will continue to misreport. `sudo droneaware status` was always
  correct on those nodes — it reads `/opt/droneaware/version`, not
  the binary's embedded value.)

- **`sudo droneaware install-webui` now adds every release-level
  config.env key**, not just the two Web-UI-specific ones. The
  post-install opt-in path previously wrote only
  `DRONEAWARE_LOCAL_BUFFER_MAX_BYTES` and `DRONEAWARE_WEB_PORT`
  directly, skipping `migrate_config_env`. Operators who landed on
  the Web UI via `install-webui` (rather than via the regular
  `droneaware update` flow) missed `DRONEAWARE_LOCAL_UDP_TARGETS` and
  its comment block. Functionally nothing was broken — the feeders
  default to broadcasting to `255.255.255.255:9999` when the var is
  unset — but the key wasn't documented in config.env so operators
  couldn't discover the override. `cmd_install_webui` now calls
  `migrate_config_env` at the end of its work (idempotent, harmless
  if migrate already ran via `cmd_update`).

---

## [1.4.1] — Unreleased

Local Web UI polish — four UX fixes from initial field testing of
v1.4.0 on a deployed node. Frontend-only changes (web_static/
index.html); no changes to web_ui.py, the feeders, the droneaware
CLI, or config.env. Operators with the Web UI installed pick up the
fixes via `sudo droneaware update` (which redownloads the web_ui
binary with the embedded static bundle), followed by
`sudo systemctl restart droneaware-web`.

### Fixed

- **Day-mode now swaps the map basemap too.** Clicking the theme
  toggle previously flipped the UI chrome (sidebar, status bar,
  popup) to light colors but left the Leaflet map on CartoDB Dark
  Matter, leaving a jarring light/dark mismatch. The map now uses
  CartoDB Positron in day mode and Dark Matter in dark mode. Theme
  switch is instantaneous; no page reload required.

- **Sidebar drone cards now sort newest-first.** Previously the list
  was in MAC-insertion order (effectively oldest-detected at the
  top). Cards now sort by `last_seen` descending within each
  freshness tier (LIVE / RECENT / OLDER), so the most recent
  broadcast surfaces first. Re-sort happens on every refresh — a
  drone that just emitted a new broadcast jumps to the top of its
  tier.

- **Drone popup's "Detection Details" panel stays open when
  expanded** (renamed from "Specs" per operator feedback).
  Previously the popup's HTML was replaced on every event update for
  the selected drone, which closed any open `<details>` panel
  mid-read and detached the click handler from the Show Flight Path
  button. Popup content is no longer re-rendered on live updates;
  fresh data is available by closing and reopening the popup. Map
  marker position + tier color continue to update in real time, and
  the sidebar card always shows live data.

- **Flight path polyline is now opt-in per drone.** Previously every
  tracked drone's full trail (up to 60 positions) rendered
  automatically on the map, cluttering the view. The default view
  now shows only the operator H markers and the dashed connector
  from operator to drone. The "Show Flight Path" button in the
  drone popup toggles the polyline on/off; the button label updates
  to "Hide Flight Path" while shown. Trail data is still tracked
  continuously, so the polyline appears with full history the moment
  the user toggles it on.

---

## [1.4.0] — Unreleased

Local Web UI milestone. First new user-facing service since the feeders
themselves. Optional, opt-in at install time (default Y on Pi 3+ class
hardware, default N on Pi Zero 2 W class due to RAM constraints). The
node works fully without it — detections still forward to droneaware.io,
email alerts still trigger, public map presence still works.

### Added

- **Local Web UI** — operator-facing detection viewer running on the Pi
  itself, available to anyone on the LAN at `http://<pi-ip>:5000/`. Works
  even when the Pi has no internet connectivity to droneaware.io. New
  `web_ui` PyInstaller binary (~13 MB) + new `droneaware-web.service`
  systemd unit.

  **What it shows:**
  - Dark-themed Leaflet map with CartoDB Dark Matter tiles (matches the
    public droneaware.io/live.html style)
  - Paper-airplane drone markers colored by freshness tier
    (cyan < 2 min, orange < 10 min, red > 10 min — same scale as the
    public site)
  - Per-drone flight-path polylines (last 60 unique positions)
  - Per-drone "H" operator markers + dashed connector lines
    (when ASTM System messages provide operator location)
  - Sidebar with detection cards grouped by freshness tier
    (LIVE / RECENT / OLDER)
  - Filter chips for freshness and radio type
  - Detail popup per drone with full ASTM field set (Type/Altitude/
    Speed/Heading/RSSI/Channel/first-seen/last-seen)
  - 10 concentric distance rings at 1-mile intervals centered on the
    node's home location (config.env NODE_LAT/NODE_LON for static
    nodes, current GPS fix for mobile nodes)
  - Theme toggle (dark default, day mode override, persisted to
    localStorage)

  **Architecture:**
  - Single PyInstaller binary bundles Flask + Leaflet + all static
    assets. No CDN dependencies at runtime; the only external requests
    are CartoDB tile loads in the browser (operators on air-gapped
    networks see a blank tile background but everything else works).
  - Tails `/run/droneaware/detections.jsonl` (the LocalPublisher tmpfs
    ring file) for new events every 500 ms. No UDP listener — Linux
    doesn't reliably loopback-deliver UDP broadcasts to listeners on the
    same machine as the sender.
  - In-memory ring per MAC, byte-bounded at
    `DRONEAWARE_LOCAL_BUFFER_MAX_BYTES` (default 50 MB, bumped from the
    10 MB LocalPublisher default when Web UI is installed). Events
    older than 12 hours pruned.
  - Server-Sent Events (`/events` endpoint) push new detections to
    connected browsers — no polling, sub-second latency from feeder
    capture to browser display.
  - Backend snapshot includes the per-MAC trail array so flight-path
    polylines render immediately on browser load instead of building
    up empty over time.

  **Install-time prompt:**
  ```
  ─── Optional: Local Web UI ───
  ...
  Install local Web UI? [Y/n]
  ```
  RAM-aware: defaults to N on hardware with less than 700 MB total RAM
  (Pi Zero / Pi 1 / Pi 2 class). Otherwise defaults to Y.

  **Failure-safe:** if the binary or service file download fails during
  install, the installer logs a warning and continues. The base install
  always completes; the Web UI is purely additive.

- **Local HTTP API** — three read-only endpoints exposed by the Web UI
  service on the same port (default 5000), making detection data
  accessible to Home Assistant, Node-RED, Homebridge, and any HTTP-aware
  automation tool:
  - `GET /api/detections` — JSON snapshot of all currently tracked
    drones with merged ASTM fields, trail of last 60 positions per
    drone, first/last seen, age.
  - `GET /api/status` — node telemetry (version, uptime, CPU temp,
    load average, SSE client count, home location, node_id, ring
    buffer stats).
  - `GET /events` — Server-Sent Events stream, real-time push of each
    new detection. Sub-second latency, no polling.

  Read-only by design (no POST/PUT). LAN-accessible on `0.0.0.0:5000`
  with no authentication — treat as a trusted-LAN service. See README
  "Local / Offline Use" for full response shape and consumer examples.

- **`sudo droneaware install-webui`** — new CLI subcommand for
  post-install opt-in. Operators who declined the Web UI at install time
  can add it later without re-running install.sh. Requires the node to
  already be enrolled (token at `/etc/droneaware/token`). Installs the
  same components as the install-time path but starts the service
  immediately (no reboot required on an already-running node).

  Visible in `sudo droneaware help` output alongside `update`/`status`/
  `test`. install.sh's decline path explicitly mentions the subcommand
  so operators know it exists.

- **`sudo droneaware status` shows Web UI URL** when the service is
  active:
  ```
  Web UI   : http://192.168.68.187:5000/
  ```

- **`sudo droneaware update` updates the Web UI binary** alongside the
  feeders when the service is installed. Download failure for `web_ui`
  is non-fatal — feeder update completes normally and the Web UI keeps
  running on the previous version.

- **New config.env keys** (added via migrate_config_env on update, or
  written directly by install.sh / install-webui at first install):
  - `DRONEAWARE_WEB_PORT=5000` — port the Web UI listens on. Change to
    avoid conflict with other services (Grafana etc.).
  - `DRONEAWARE_LOCAL_UDP_TARGETS=` — comma-separated list of
    `host:port` pairs the feeders forward each detection JSON to via
    UDP. Default (empty) sends to `255.255.255.255:9999` (LAN
    broadcast). Operators with consumers that can't receive broadcasts
    (Docker containers, point-to-point listeners behind NAT, airport
    tower displays, etc.) can override with explicit unicast targets:
    `DRONEAWARE_LOCAL_UDP_TARGETS=192.168.1.100:5555`. Mix broadcast +
    unicast with `255.255.255.255:9999,192.168.1.100:5555`. Per-target
    send failures are silent — one unreachable consumer won't disrupt
    delivery to others.
  - When Web UI is installed: `DRONEAWARE_LOCAL_BUFFER_MAX_BYTES` is
    bumped from 10000000 (10 MB default) to 50000000 (50 MB) so the
    LocalPublisher tmpfs ring holds more recent history for the Web
    UI to display.

### Architecture notes

- **systemd unit runs as `droneaware` user**, not root. Web UI is
  network-facing (even if LAN-only) and binds an unprivileged port —
  least-privilege reduces blast radius of any future vulnerability.
  install.sh creates the droneaware system user if missing (most Pis
  already have it as the imager-created user).

- **No server-side accommodation needed.** The Web UI is a pure local
  consumer of LocalPublisher data. Wire format unchanged, heartbeat
  schema unchanged, no new API endpoints.

### Known limitations (deferred to v1.4.x)

These items are out of scope for v1.4.0 and will land in follow-up
releases as their server-side dependencies become available:

- **Drone make/model enrichment** — sidebar cards and detail popups
  show UAS-ID only, not make/model. Server-side enrichment endpoint
  needs to be defined before the Web UI can query it.
- **Drone thumbnail images** — same blocker.
- **Search bar** for drone models — blocked on enrichment.
- **Time-slider scrubbing** — design discussion needed.
- **Marker labels** on the map — blocked on enrichment (UAS-ID hex
  strings aren't useful labels).

---

## [1.3.0.2] — Unreleased

Follow-up hotfix to v1.3.0.1 — addresses a secondary UX bug that v1.3.0.1's
fix exposed by making the `not_configured` GPS state much more common on
static nodes.

### Fixed
- **`droneaware status` no longer falsely reports "state stale" for
  not-configured GPS.** v1.3.0.2 reorders the GPS state-file check in
  `cmd_status` so `not_configured` is handled BEFORE the 120-second
  staleness check. Pre-v1.3.0.2, after a static node had been running for
  2+ minutes without GPS hardware, `sudo droneaware status` showed
  "GPS: state stale (Ns old — wifi_feeder may have stopped)" — misleading
  because wifi_feeder was running fine; the state file simply isn't
  refreshed when no reader thread exists.

  The staleness check was originally written (in A.2 / v1.3.0) assuming
  the state file would always be refreshed by an active reader thread
  every NMEA cycle. v1.3.0.1's GPIO-gating made `not_configured` a
  legitimate terminal state where the file is written exactly once at
  service startup — exposing this assumption gap.

  Active GPS states (`fix`, `reading`, `detecting_baud`, `no_nmea`,
  `device_missing`) still trip the staleness warning if their reader
  thread genuinely dies — that signal is preserved. Only `not_configured`
  is exempt because by definition it has no reader thread.

  Validated on NJ007 (droneaware-node-3) during the v1.3.0.1 post-update
  check: confirmed staleness warning fires after ~4 minutes pre-v1.3.0.2,
  not at all post-v1.3.0.2.

---

## [1.3.0.1] — 2026-06-16

Hotfix for a v1.3.0 regression in GPS auto-discovery. Two operators on
static nodes (NJ007 + JeGoBE8900, the latter on non-Pi x86_64 Debian)
hit persistent log noise from the new A.3 GPIO fallback path: `/dev/serial0`
exists on every Pi by default as the onboard UART symlink, so v1.3.0's
unconditional GPIO probing surfaced it as a "GPS candidate" on nodes
without any GPS hardware. The reader thread then either failed baud
detection (quiet 10s retries) or hit kernel `Input/output error` on
non-Pi `/dev/serial0` paths (loud 10s WARNING spam) — neither suppressible
operator-side in v1.3.0.

### Fixed
- **GPS GPIO fallback now gated on `NODE_MOBILE=true`.** `find_gps_device()`
  unchanged for the manual-override case (`GPS_DEVICE` env var still wins
  always) and the USB-present case (still probed on every node — operator
  plugged something in, we honor it). Only the GPIO/UART path list
  (`/dev/serial0`, `/dev/ttyAMA0`, `/dev/ttyS0`) is now gated. Static nodes
  with no GPS hardware go back to the pre-v1.3.0 behavior: silent
  "GPS: not configured", no probing, no log noise. Mobile nodes (GPIO
  NEO-6M builds — the Kbrooks use case) still get GPIO auto-discovery
  as in v1.3.0. Operators with exotic configurations (static + GPS for
  time sync) can still force a device path via `GPS_DEVICE`.

  Reported as GitHub issue by @JeGoBE8900 on 2026-06-14. Also surfaced
  on NJ007 (static node, droneaware-node-3) 2026-06-12.

---

## [1.3.0] — 2026-06-11

Reliability + Observability milestone. Scope intentionally narrowed from the
original "multi-radio" plan (which moved to v1.5.0) to focus on improvements
that emerged from real operator incidents during the v1.2.x cycle.

### Added
- **LocalPublisher buffer upgraded to byte cap, matching the Forwarder pattern.**
  The tmpfs ring buffer at `/run/droneaware/detections.jsonl` (read by
  LAN consumers like `nc -luk 9999`, `droneaware test`, and future local
  dashboards) was previously bounded by `MAX_LINES=3600` — at busy nodes
  with peak burst rates (~50 events/sec on dfw-drones during Zipline
  dispatch), that's only 72 seconds of history. A single drone's full
  flight could roll off the buffer before an operator looked at it (this
  is what @iaincaradoc hit during the Mavic 4 Pro decoder investigation).

  Same byte-bounded ring pattern as the Forwarder (C.7), with a smaller
  default sized for "a few hours of recent local activity," not "weeks of
  outage forensics":

  - `DRONEAWARE_LOCAL_BUFFER_MAX_BYTES=10000000` (default 10 MB)
  - Covers ~2–3 hours at heaviest-node peak burst rates
  - Days of quieter-node history
  - ~10× the prior capacity at no meaningful RAM cost (tmpfs)

  Independent of `DRONEAWARE_BUFFER_MAX_BYTES` (the upstream forwarder
  cap) — operators on Pi Zeros can shrink one without shrinking the
  other. FIFO drop-oldest preserves the most recent events on overflow,
  which is what LAN consumers actually want to see.

- **Byte-bounded ring buffer in both feeders' Forwarders (WiFi parity catch-up
  + capacity upgrade).** Two changes shipped together:

  1. **WiFi feeder parity with BLE.** Pre-v1.3.0, `wifi_feeder.Forwarder`
     cleared its buffer BEFORE the POST and only counted failures —
     observations were lost on any HTTP failure, with zero outage
     resilience. `ble_feeder.Forwarder` had the proper re-queue-on-failure
     pattern. The WiFi side now mirrors BLE: failed batches are re-queued
     at the front of the buffer so transient connectivity blips no longer
     drop observations. WiFi-RID-heavy nodes (DJI-dense areas) were
     silently losing more data than BLE-heavy nodes during network blips.

  2. **Both feeders upgraded from event-count cap to byte cap.** The
     pre-v1.3.0 BLE cap (`MAX_BUFFER=1000` events) filled in 10 seconds
     under a 100/sec spoof flood. Bytes are the right unit: 50 MB
     (default) preserves ~33 minutes of spoof evidence in that scenario,
     and weeks of normal-traffic outage on the heaviest known node
     (dfw-drones, Zipline corridor). FIFO drop-oldest on overflow
     preserves recency for forensics — the server-side rate cap already
     trims spoof amplification post-decode, so dropping older events when
     a buffer fills is the operationally correct choice.

  New env vars (added to `config.env` via migrate, also written by fresh
  installs):

  - `DRONEAWARE_BUFFER_MAX_BYTES=50000000` — hard cap (default 50 MB)
  - `DRONEAWARE_BUFFER_WARN_PCT=75` — log threshold (default 75%)

  Safe on every supported Pi tier including Pi Zero 2 W (512 MB total)
  and well under the per-process OOM-killer threshold on default Pi OS.
  Operators can tune lower on memory-constrained hardware (`20000000` ≈
  20 MB) or higher on Pi 5 deployments that expect extended outages.

  Buffer state is surfaced via journalctl, not heartbeats. The buffer
  only fills when upstream is unreachable — which is precisely when
  heartbeats can't get through either. A `dropped_total` field in the
  heartbeat JSON would be invisible during the loss event itself and
  only historical after reconnect, so it was deliberately kept out of
  the wire format. Instead:

  - Heartbeat log line shows `dropped=N` (per-feeder, journalctl-readable)
  - Threshold-crossing WARNING when buffer first crosses
    `DRONEAWARE_BUFFER_WARN_PCT` — actionable signal an operator can see
    via `journalctl -u droneaware-wifi` during the outage itself
  - INFO when the buffer drains back below 10% after a reconnect (the
    "all caught up" signal)

- **`droneaware update` now applies the newly-installed release's migration
  blocks immediately**, instead of one release late. Previously `cmd_update`
  called `migrate_config_env` at the end of the update, but bash was still
  executing from the OLD CLI's open file descriptor (per the v1.2.1
  atomic-mv pattern), so the OLD migration code ran — meaning any new
  config keys added in the release being installed wouldn't appear in
  `config.env` until the NEXT update. The classic example: `WIFI_5G_ENABLED`
  was added in v1.2.2 but didn't actually land in operators' config.env
  files until v1.2.2.1.

  Fix: `cmd_update` now re-execs the newly-installed CLI via a hidden
  `__migrate` subcommand, so the new release's migration code runs right
  away. Wrapped in a fallback — if the re-exec fails for any reason (CLI
  missing, syntax error, migrate throws), the in-process call runs as
  before. Worst case = pre-v1.3.0 behavior; we never regress.

  All migration blocks are idempotent (each `if ! grep -q`-gated), so if
  both the new-CLI re-exec AND the fallback fire on an edge-case partial
  failure, no harm done — running migration twice produces the same
  result as running it once.

  Note (same limitation as v1.2.1's atomic-mv fix): this fix only takes
  effect starting from updates SHIPPED FROM a release that includes it.
  The v1.2.2.2 → v1.3.0 update will still have the original problem —
  v1.2.2.2's CLI doesn't know to re-exec. Users updating to v1.3.0 won't
  see new v1.3.0 config keys until their NEXT update.

- **BLE adapter self-recovery before FAULT.** When `ble_feeder` starts and
  finds `hci0` (or whichever adapter is configured) is DOWN or unhealthy, it
  now runs a standard recovery sequence before declaring FAULT mode:
  1. `rfkill unblock bluetooth` — clears any soft block
  2. `hciconfig <adapter> up` — brings the interface up
  3. (if still unhealthy) `systemctl restart hciuart` then retry once — last
     resort, cycles the UART driver for Pi onboard BT
  If the adapter is healthy after any step, the feeder proceeds normally.
  Only enters FAULT if all three steps fail.

  Auto-heals the Pi onboard-BT UART sync issue (the "Can't init device hci0:
  Connection timed out" boot failure that hit njpi-120hotfix on 2026-06-01)
  without requiring operator intervention. Pre-v1.3.0 behavior was to enter
  FAULT immediately on a DOWN adapter, requiring a manual reboot to recover.

  Each recovery step logs to the journal (`[Recovery] (1/3) ...`,
  `[Recovery] (2/3) ...`, etc.) so operators can see what was attempted and
  what worked. FAULT heartbeat reason now reads `adapter not present (recovery
  attempted)` to distinguish post-recovery FAULT from pre-recovery FAULT in
  server-side analysis.

- **GPS auto-discovery now checks GPIO / on-board UART paths.** Previously
  `find_gps_device()` only looked at USB paths (`/dev/ttyUSB*` and
  `/dev/ttyACM*`), so operators wiring a GPS module to the Pi's GPIO header
  (e.g. NEO-6M / GY-NEO6MV2 on `/dev/serial0`) had to manually set
  `GPS_DEVICE` in `config.env` to be detected. The candidate list now
  extends to `/dev/serial0` (Pi 3+/4/5 default mini UART), `/dev/ttyAMA0`
  (PL011, used on Pi 1/2/Zero or `dtoverlay=miniuart-bt` configs), and
  `/dev/ttyS0` (mini UART direct fallback), checked in that order after
  USB candidates. USB-first priority is preserved — nodes with a USB
  dongle plugged in behave identically. The `GPS_DEVICE` env var still
  wins over both. Triggered by Kbrooks's mobile-unit build with the
  NEO-6M on GPIO instead of USB.

  Installer-side enhancement (asking "USB or GPIO?" at install time) is
  scoped to v1.5.0 with the rest of pre-flight detection. v1.3.0 just gets
  the runtime auto-discovery, which closes 80% of the operator pain.

- **`droneaware status` now includes a GPS state line.** Operators can run
  `sudo droneaware status` and see — in one line — which device the feeder
  is using, the detected baud rate, and whether a satellite fix has been
  acquired. Renders one of:
  - `GPS: /dev/serial0 @ 9600 baud — fix acquired (lat=40.4577, lon=-74.3393)`
  - `GPS: /dev/serial0 @ 9600 baud — reading NMEA, no fix yet`
  - `GPS: /dev/serial0 — detecting baud rate...`
  - `GPS: /dev/serial0 — device exists but no valid NMEA detected`
  - `GPS: /dev/ttyUSB0 — configured but device not present`
  - `GPS: not configured`
  - `GPS: state stale (Ns old — wifi_feeder may have stopped)`
  - `GPS: state unknown (wifi_feeder not running, or pre-v1.3.0 binary)`

  Wifi_feeder writes a small JSON state file at `/run/droneaware/gps_state.json`
  (tmpfs — no SD card wear) on every GPS state transition and on each valid
  $GPRMC. CLI reads it without parsing journalctl, so the answer is current
  rather than "whatever was last logged." Pre-v1.3.0 binaries don't write the
  state file; CLI falls back gracefully.

  Triggered by Kbrooks's mobile-build "NO GPS dashboard badge" debug session
  on 2026-06-06, where the operator had no single command to learn whether
  their GPS had a satellite fix (the actual question that mattered).

- **CPU observability — `cpu_count`, `cpu_percent`, `load_1m`, `load_5m`,
  `load_15m` reported in heartbeats.** Both wifi_feeder and ble_feeder now
  report a full CPU picture alongside the existing `cpu_temp_c`:
  - `cpu_count` — number of logical CPU cores via `os.cpu_count()`. Required
    context for interpreting `load_*` correctly: `load_1m=2.0` means
    "saturated" on a 2-core Pi Zero 2 W but "comfortably half-loaded" on a
    4-core Pi 4 — same number, completely different operational meaning.
  - `cpu_percent` — instantaneous utilization computed from `/proc/stat`
    deltas across heartbeat cycles (same metric htop / top / psutil report,
    and what PiAware's dashboard surfaces). Distinct from load average:
    high cpu_percent directly predicts thermal throttle; high load with
    low cpu_percent indicates I/O wait (slow SD card, network).
  - `load_1m`, `load_5m`, `load_15m` — standard Linux load averages from
    `/proc/loadavg`. Trend indicator (1-min ≈ now, 15-min ≈ historical).
  - All metrics soft-fail to `null` on non-Linux / missing `/proc` paths;
    heartbeat payload stays well-formed. Helpers (`get_cpu_percent()`,
    `get_cpu_load()`) mirror the existing `get_cpu_temp()` defensive
    pattern.
  - Heartbeat log lines now show all three for at-a-glance journal
    reading: `temp=45.2°C  cpu=12.5%  load=0.42`, with `n/a` fallback
    when a metric is unavailable.
  - Server-side accommodation required (Pydantic model + dashboard
    surface) — node-side is wire-ready.

---

## [1.2.2.2] — 2026-06-02

### Fixed
- **WiFi Beacon local decoder — Message Counter byte was being misread
  as the message type.** ASTM F3411-22a §5.4.2 places a Message Counter
  byte between the Vendor Type and the ODID message in Wi-Fi Beacon and
  NAN transports. The node's local decoder was reading `raw_bytes[0]`
  directly as the message-type header, which means for any real-world
  Wi-Fi Beacon broadcast that included a counter, the counter byte's
  high nibble was being labeled as the message type (e.g., counter
  `0xB7` → "Unknown(0xB)"; `0x27` → "Authentication"). All position /
  ID fields came back null because the field parsers were reading from
  the wrong byte offsets.
- The fix mirrors the server's defensive shim in `api.py`: when the
  payload's byte 0 is non-Fx AND byte 1 is Fx (Message Pack header),
  strip the counter for local field extraction. `raw_hex` preserves the
  original wire bytes, so the payload forwarded to the server is
  unchanged. Server has its own identical shim and was always decoding
  correctly — this was strictly a local-decoder bug invisible from
  server-side data.
- Surfaced by `@iaincaradoc` on 2026-06-02 when his `nc -luk 9999`
  capture of a Mavic 4 Pro showed only `Authentication` and
  `Unknown(0x6)` / `Unknown(0xB)` events with null fields, while the
  server had the same drone's standard ASTM messages fully decoded.

### Notes on scope
- **BLE local decoder is unaffected.** `extract_rid_payload` in
  `ble_feeder.py` already strips the BLE counter (App Code + counter
  byte) at extraction time, so the BLE decoder operates on clean ODID
  bytes and never had this bug.
- **WiFi-NAN frames are forwarded to the server without local decoding**
  (`decoded=None`). That's a pre-existing feature gap, not a regression
  — NAN never produced local UDP/ring-buffer output. Local NAN
  decoding is tracked separately for v1.3.0.
- **No wire-format change.** The `payload_hex` sent to `/api/ingest` is
  byte-identical to v1.2.2.1. Existing server data and `gh attestation
  verify` workflows are unaffected.

---

## [1.2.2.1] — 2026-06-01

### Fixed
- **`droneaware test` per-channel detection breakdown** — the local check
  introduced in v1.2.2 read the wrong fields when parsing
  `/run/droneaware/detections.jsonl`. It expected a nested
  `decoded.uas_id`, but `LocalPublisher` writes a flat `id` field at the
  top level of each event. Result: tests were always reported as "No
  local detection found yet" even when 78+ events were sitting in the
  ring buffer. Fixed to read `e.get("id")` directly. End-to-end
  validation on a PAU0B AC600 with v1.2.2.1 shows the breakdown now
  correctly counts ch 6 and ch 149 captures.

---

## [1.2.2] — 2026-06-01

### Added
- **5 GHz Wi-Fi RID scanning for dual-band adapters.** New `DualBandHopper` runs a
  30-second cycle (20 s on channel 6, 10 s on channel 149 — the ASTM F3411
  channels for 1 Hz Remote ID broadcasts on 2.4 GHz and 5 GHz respectively).
  Auto-selects when the configured adapter advertises channel 149 in monitor
  mode; the existing 2.4-only `AdaptiveChannelHopper` continues to drive
  single-band setups unchanged.
- `WIFI_5G_ENABLED` config key (`auto` | `true` | `false`) for explicit
  override of the auto-detect heuristic.
- `WIFI_OFF_CHANNEL_SWEEP` config key — advanced opt-in for ch 1 and ch 11
  canary peeks. Off by default (see *Changed* below).
- **PHY capability verification at feeder startup.** Logs `Hopper channels: […]`
  reflecting the actual hopper plan and warns if any target channel isn't in
  the radio's supported set (catches regulatory restrictions, driver bugs, or
  hot-plug capability drift before the feeder hops blind).
- **Per-channel breakdown in `droneaware test` output** — confirms 2.4 GHz and
  5 GHz reception independently after a test transmission, with a "Both bands
  receiving" confirmation when both produce detections.
- **SHA256 checksums in release notes.** Lower-barrier verification path than
  `gh attestation verify`; verify downloads with `sha256sum -c` from any Unix
  shell.
- `GPS_BAUD` migration block in `droneaware update` — pre-v1.1.3 configs now
  pick up the field automatically on upgrade. Harmless when blank (auto-detect
  runs), but exposes the override for users wanting to pin the baud rate.

### Changed
- **Default scanning is compliant-channels-only.** Empirical fleet data shows
  channels 1 and 11 carry zero unique drones — all observed off-band captures
  are channel-6 adjacent-channel drift. The hopper now spends 100 % of cycle
  time on ASTM-compliant channels (ch 6, plus ch 149 on dual-band nodes).
  Operators wanting to chase non-standard transmitters can re-enable the
  ch 1 / ch 11 canary peeks via `WIFI_OFF_CHANNEL_SWEEP=true`. Net effect on
  existing v1.2.0+ deployments: ~10 % more ch 6 dwell per cycle, no unique
  drone loss.
- `droneaware status` now requires `sudo` (matches `update` and `test`). Fixes
  a long-standing silent failure where the Node ID line would display empty
  when run without root, because `config.env` is chmod 600.
- Startup log replaces the stale `Channels: [1, 2, …, 11]` line with
  `Hopper channels: […]` derived from the active hopper — accurate for both
  2.4-only and dual-band deployments.
- CI workflow `cpu` label corrected from `cortex-a7` to `cortex-a72` (cosmetic;
  binaries were already aarch64 via the 64-bit base image).

### Notes for operators upgrading from v1.2.0 / v1.2.1
- 2.4-only nodes: behavior shifts from `[6 → 1 → 11 → 6]` sweep to constant
  ch 6 dwell. To preserve previous behavior, set `WIFI_OFF_CHANNEL_SWEEP=true`
  in `/opt/droneaware/config.env` after updating.
- Nodes with dual-band USB adapters automatically enable 5 GHz scanning. No
  manual configuration required.

---

## [1.2.1] — 2026-05-27

### Added
- SAST scanning: CodeQL (Python + Actions) and Shellcheck on PRs, surfaced in
  the repository's Security tab.

### Fixed
- **Self-modifying update script crash.** `cmd_update` now writes the new CLI
  to a temp path and atomically `mv`s it into place instead of overwriting the
  running file in-place. Eliminates the `syntax error near unexpected token
  ';;'` reported on the v1.2.0 update (the_ninja, VirusPilot). Takes effect
  v1.2.1 → v1.2.2 onward — the v1.2.0 → v1.2.1 transition still shows the
  legacy error once because the buggy `cp` runs from the old CLI.
- **ASTM F3411-22a Location/Vector and System Message decoder offsets** (issue
  #18, iaincaradoc). The local UDP broadcast and ring-buffer events now decode
  to correct coordinates and operator fields; the server wire payload was
  already correct.
- **`config.env` additive merge on `droneaware update`** (issue #17,
  JeGoBE8900). New release fields are appended in idempotent blocks; existing
  user values (`NODE_ID`, location, etc.) are preserved untouched.
- All decoded Open Drone ID fields now surfaced in the local UDP and ring
  buffer streams (operator_lat/lon, area_count, id_type, ua_type, height_agl,
  etc.) — full data parity for offline consumers.

---

## [1.2.0.1] — 2026-05-26

### Fixed
- **GLIBC_2.38 regression on Pi OS Bookworm.** CI base image pinned to
  `raspi_3_bookworm:20231109` (glibc 2.36). The previous
  `raspios_lite_arm64:latest` had silently moved to Trixie (glibc 2.41),
  producing v1.2.0 binaries that failed at runtime on Bookworm nodes with
  `version GLIBC_2.38 not found`. Reported by chuck.meister.

---

## [1.2.0] — 2026-05-24

First release built end-to-end by the GitHub Actions CI/CD pipeline, with
Sigstore attestation on every artifact.

### Added
- **Adaptive channel hopper** biased to channel 6 (ASTM F3411 mandates 1 Hz
  Wi-Fi RID broadcasts on ch 6 in the 2.4 GHz band). Previous flat 1–11 hop
  spent ~91 % of time on channels where compliant RID cannot exist.
- `channel` field on detection payloads.
- Soft-fail on missing adapter — single-radio installations are supported,
  and a missing radio reports FAULT in the heartbeat with a structured reason
  string. Installer no longer aborts when only one of BLE / Wi-Fi is present.
- Per-feeder heartbeat routing — presence of `wifi_ok` or `ble_ok` in the
  heartbeat is the routing key; cross-radio fields no longer permitted.
- Service files (`droneaware-wifi.service`, `droneaware-ble.service`,
  `droneaware-bt-select.service`) bundled in every release artifact.
- May 2026 Contributor Agreement displayed at install time and shipped in the
  installer.

### Changed
- **Release pipeline:** binaries built and signed by GitHub Actions. Verify
  any artifact with `gh attestation verify <file> --owner fduflyer`.
- **One release = one version.** `SERVICE_VERSION` removed — service files,
  binaries, `install.sh`, and the CLI now all ship together in each release,
  with `install.sh` `sed`-stamped at build time to point at its own assets.

---

## Older releases (v1.0.0 – v1.1.3)

See the [GitHub Releases page](https://github.com/fduflyer/DroneAware-Node-Releases/releases)
for per-version notes. Highlights:

- **v1.1.x:** test-flight command (`sudo droneaware test`), WiFi NAN frame
  filtering by ODID Service ID (eliminates Apple Continuity / AirDrop false
  positives), runtime monitor-mode guard, GPS NMEA checksum-validated baud
  detection.
- **v1.0.x:** initial public release, stdlib AF_PACKET sockets (scapy
  removed), session-token enrollment, mobile / static location prompts,
  tmpfs ring buffer + UDP LAN broadcast, droneaware CLI introduction.
