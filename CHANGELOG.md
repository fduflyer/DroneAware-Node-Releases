# Changelog

All notable changes to DroneAware Node will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Full release artifacts and discussion notes live at the
[GitHub Releases page](https://github.com/fduflyer/DroneAware-Node-Releases/releases).

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
