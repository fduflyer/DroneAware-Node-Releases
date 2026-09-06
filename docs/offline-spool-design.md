# Offline detection spool — v1.6 design

**Problem.** Detections waiting to upload are held in RAM only and are lost
on power loss. v1.6 actively encourages fully offline operation, so this is
the release that has to fix it.

**Server dependency: resolved.** The ingest accepts old events and processes
them by *detection* timestamp, not upload timestamp. Replay is therefore
correct with no server change. The only open server question is the
acceptable **drain rate** (§4).

---

## 0. What is broken today

`Forwarder.buffer` is a `collections.deque()` with zero file writes —
`wifi_feeder.py:2124` and, separately, `ble_feeder.py:859`. **The class is
duplicated across the two feeders.**

`/run/droneaware/detections.jsonl` is on **tmpfs**, so the local ring is RAM
as well. Nothing survives a power cycle.

Measured on NJ001: **280 bytes/event**, so the 50 MB cap ≈ **178,000
events**.

Everything buffered is discarded by:

| event | loses buffer |
|---|---|
| power loss / unplug | yes |
| reboot | yes |
| `droneaware update` / `refresh` | yes — both restart feeders |
| `systemctl restart` | yes |
| feeder crash-loop | yes |
| **clean `systemctl stop`** | **yes — there is no SIGTERM handler at all** |

The last row is the one to notice: even an orderly shutdown loses data
today, because nothing flushes on the way down.

---

## 1. Write cadence — every 10 s, only when there is new data

**Rule: append-only, each event written exactly once, never rewritten.**

Write *amplification* is what kills SD cards, not write *volume*. If every
event is appended once and delivered segments are deleted whole rather than
rewritten, total bytes written equals total detection volume — the
theoretical floor.

- A timer fires every **10 s**. If no events have arrived since the last
  write it does nothing — no empty writes, no wake-up churn on an idle node.
- One `fsync` per write. **Never per event.**
- **Worst-case loss is therefore the last 10 seconds of detections**, and
  that is a number worth stating plainly in the UI and the release notes.

### Wear budget

| load | per 10 s write | per day |
|---|---|---|
| busy — 10 events/s | 28 KB | **242 MB** |
| moderate — 1 event/s | 2.8 KB | 24 MB |
| NJ001 as measured | 28 B | 0.2 MB |

For scale, a camera writing one 4 MB photo every 10 s does **34.6 GB/day** —
the busy node is **143× lighter**, and NJ001 in practice is five orders of
magnitude lighter. A 32 GB wear-levelled card absorbs the busy case for
decades.

Wear is a non-issue *provided* the no-rewrite rule holds. That is the design
constraint; the volume is not.

### Spool unconditionally, not only when offline

Because writing is this cheap, the spool runs **always** — not only during
an outage. This is the important simplification:

- One code path. There is no "am I offline" branch on the write side, so no
  mode that only executes during the failure it is meant to survive.
- A node that is **online** also stops losing its last few seconds to a
  power cut, which it currently does.
- Recovery stops being a special case (§2).

The cost is writing detections that were about to upload anyway — 242 MB/day
at the busy end, which the table above puts in perspective.

---

## 2. How does the node know to check the disk?

It never has to ask. **The spool is the queue.**

```
event -> RAM staging (≤10 s) -> spool segment on disk -> POST -> segment deleted
```

The forwarder always sends from the spool. The RAM deque shrinks to a
10-second staging buffer. Reading back what was just written is served from
the page cache, so this costs no real disk reads.

Startup is then not a recovery path at all — it is the ordinary path:

- Undelivered segments exist → send them, oldest first.
- No segments → nothing to send.

That is *identical* to the state a power loss leaves behind, which means
**the recovery code runs constantly rather than only after a crash**. This
is the whole argument for the design: a replay path that only executes after
an unexpected reboot is the path least likely to be tested and most likely
to be broken when it finally matters.

Ordering falls out for free — the spool is FIFO by detection time, so the
server receives detections in detection order even after a long outage.

### On-disk layout

```
/var/lib/droneaware/spool/<feeder>/
    seg-<epoch>-<seq>.jsonl     append-only, rolled at 4 MB
    cursor                      byte offset into the OLDEST segment
```

- Segments are **deleted whole** once fully delivered — no rewriting, which
  is what holds write amplification at 1×.
- `cursor` is a few bytes, rewritten per delivered batch. Cheap.
- Cap `DRONEAWARE_SPOOL_MAX_BYTES`, default **500 MB** (≈1.8 M events). On
  overflow, delete the **oldest** segment — matching existing drop-oldest
  semantics.
- **A truncated final line is expected, not exceptional** — it is exactly
  what power loss mid-append produces. On read, a last line that does not
  parse is discarded silently.

---

## 3. Shutdown

Two halves, and the handler matters more than the button.

**a. SIGTERM handler in both feeders (required).** On SIGTERM: stop
accepting, append the RAM staging buffer to the spool, `fsync`, exit.
systemd already sends SIGTERM, so this alone makes `reboot`, `poweroff`,
`systemctl stop`, `update` and `refresh` lossless — closing the last row of
the §0 table. Needs `TimeoutStopSec` in both units to comfortably exceed the
flush.

**b. Shutdown button in the offline UI (requested).** Settings → Node gains
**Shut down node**, behind a confirm, running `systemctl poweroff` — which
triggers the handler above. One more line in
`/etc/sudoers.d/droneaware-webui`.

Its purpose is to give someone carrying a node in a vehicle a way to stop it
without pulling power, protecting the filesystem as much as the buffer.

> ⚠️ On an unauthenticated LAN page this lets anyone on the network power the
> node off. More disruptive than refresh/swap/update, and the strongest
> argument yet for gating the settings panel.

---

## 4. Drain rate

Steady state is `BATCH_SIZE=200` / `FLUSH_INTERVAL=5.0`.

Draining 178,000 events at 200 per 5 s takes **74 minutes**; at 200 per 1 s,
**15 minutes**. A node returning from a weekend in the field holds more.

- Keep **200 per batch**. The server's ingest is tuned for it.
- Add `DRONEAWARE_SPOOL_DRAIN_INTERVAL_SEC`, default **1.0**, used *only*
  while a backlog exists. Steady state stays at 5.0.
- Honour **429** and **503** with `Retry-After`, exponential backoff, full
  jitter, cap 60 s. The existing code already treats 408/429 as retryable;
  this makes it respect the header instead of retrying on a fixed cadence.
- Never drop a spooled event on a *retryable* failure. Dropping permanent
  4xx stays correct.

**Open question for the server:** what sustained rate is acceptable from one
node draining a backlog, and is a slower steady stream preferred over a
burst? A fleet returning from an event converges at once. The 1.0 s default
is a placeholder pending that answer — one config key to change.

---

## 5. Scope

| item | where |
|---|---|
| `SpoolQueue` (segments, cursor, cap, corrupt-tail tolerance) | new, shared |
| Forwarder reads from spool instead of deque | `wifi_feeder.py` **and** `ble_feeder.py` |
| 10 s write timer | both feeders |
| SIGTERM handler | both feeders |
| `TimeoutStopSec` | both `.service` units |
| Drain pacing + `Retry-After` | `Forwarder.flush` |
| Spool state in heartbeat + `droneaware status` | feeders, CLI |
| Shutdown button + sudoers line | `web_ui.py`, `index.html`, sudoers |
| New config keys | CLI migrate block **and** `install.sh` write_config |

**The duplicated `Forwarder` is the main structural decision.** Implementing
the spool twice guarantees the copies drift. Extracting it to a shared
module is the right call but touches both feeders and the build.

The config keys need *both* writers — a reader without a writer is an
invisible feature, and this codebase has shipped that bug three times.

### New config keys

```
DRONEAWARE_SPOOL_DIR=/var/lib/droneaware/spool
DRONEAWARE_SPOOL_MAX_BYTES=524288000
DRONEAWARE_SPOOL_SEGMENT_BYTES=4194304
DRONEAWARE_SPOOL_WRITE_INTERVAL_SEC=10.0
DRONEAWARE_SPOOL_DRAIN_INTERVAL_SEC=1.0
```

### Must be observable

Silent success is this codebase's dominant failure mode, and a spool that
quietly fails to replay is indistinguishable from a quiet week of airspace.
Surface in the heartbeat and in `droneaware status`:

- spooled event count and bytes on disk
- whether a backlog exists, and estimated drain time
- oldest spooled detection timestamp
- count dropped to the cap, if any

### Test matrix

1. Unplug mid-outage → events present after boot, delivered in order.
2. `SIGKILL` mid-append → truncated tail discarded, the rest replays.
3. Spool exceeds cap → oldest segment dropped, node keeps running.
4. 429 with `Retry-After` → backoff honoured, nothing lost.
5. Permanent 4xx during drain → that batch dropped, drain continues.
6. **Disk full → feeder degrades to RAM-only, says so loudly, never wedges.**
7. Clean `systemctl stop` mid-outage → zero loss.
8. Power loss while *online* → at most 10 s lost, not the whole window.

Item 6 is the one that must not be got wrong: the spool must never be able
to stop a node detecting.

---

## 6. Out of scope, deliberately

`/run/droneaware/detections.jsonl` stays on tmpfs. That is intentional —
`ble_feeder.py:714` names "zero SD card wear" as the reason. The local ring
is a *view* for the web UI, not the delivery guarantee. The spool is the
durable path.
