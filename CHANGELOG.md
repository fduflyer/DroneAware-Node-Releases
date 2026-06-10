# Changelog

All notable changes to DroneAware Node will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Full release artifacts and discussion notes live at the
[GitHub Releases page](https://github.com/fduflyer/DroneAware-Node-Releases/releases).

---

## [1.3.0] — Unreleased

Reliability + Observability milestone. Scope intentionally narrowed from the
original "multi-radio" plan (which moved to v1.5.0) to focus on improvements
that emerged from real operator incidents during the v1.2.x cycle.

### Added
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
