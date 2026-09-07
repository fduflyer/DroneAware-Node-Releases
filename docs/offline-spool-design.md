# Offline detection spool — v1.6 design

**Problem.** Detections waiting to upload are held in RAM only and are lost
on power loss. v1.6 actively encourages fully offline operation, so this is
the release that has to fix it.

**Server dependencies.** The ingest accepts old events and processes them by
*detection* timestamp, not upload timestamp, so replay is correct. The drain
rate was answered on 2026-09-07 (§4) — and the answer changed the design:
the server caps a node at 1,500 rows/min and **sheds the excess silently
behind an HTTP 200**, so releasing a spool segment on status alone would
lose data permanently.

**Sequencing: server first.** The node side is not blocked. Ship the
durability work — segments, cursor, SIGTERM handler, truncated-tail
tolerance — independently. Only the drain pacing waits, and until the
server raises its ceiling the correct interval is 8.0 s per 200-event
batch.

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

## 1. Write cadence — every 15 s, only when there is new data

**Rule: append-only, each event written exactly once, never rewritten.**

- A timer fires every **15 s**. If no events have arrived since the last
  write it does nothing — no empty writes, no wake-up churn on an idle node.
- One `fsync` per write. **Never per event.**
- **Worst-case loss is the last 15 seconds of detections**, and that is a
  number worth stating plainly in the UI and the release notes.

### Why 15 s — and why NOT for SD wear

15 s is chosen for the **loss window**, not for card wear. Field use is
bursty: an aircraft passes, then nothing, and the node is unplugged long
after the flying stopped. The exposure rarely coincides with a detection.

**Wear was measured and is not a factor.** Do not "optimize" this to 30 or
60 s on endurance grounds — the grounds do not exist:

- Bytes written per day are **identical at any cadence**. Each event is
  written exactly once, so the timer cannot reduce volume, only the number
  of write operations.
- `preferred_erase_size` on a node's card is **8 MB**
  (`/sys/block/mmcblk0/device/preferred_erase_size`). At that granularity a
  36-byte batch and a 4 KB batch are indistinguishable — same erase block,
  and the FTL coalesces sequential appends regardless.
- Measured on NJ001: the card already absorbs **56.6 MB/day** from the OS
  alone — journald, logs, apt. The spool at that node's detection rate adds
  **0.2 MB/day**, about **0.35%** of what the card writes with DroneAware
  contributing nothing.
- SD cards report no wear at all. There is no `life_time` or
  `pre_eol_info` — those are eMMC fields. Any card-life figure is an
  estimate built on assumed endurance and assumed write amplification, and
  should be treated as such.

What the cadence *does* cost, linearly, is data:

| load | 10 s | 15 s | 30 s | 60 s |
|---|---|---|---|---|
| busy, 10 events/s | 100 events | 150 | 300 | 600 |
| moderate, 1 event/s | 10 | 15 | 30 | 60 |
| NJ001 as measured | 0.1 | 0.1 | 0.3 | 0.5 |

Past 15 s the trade is real detections lost in the exact scenario the spool
exists for, bought with a wear saving that does not register.

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
event -> RAM staging (≤15 s) -> spool segment on disk -> POST -> segment deleted
```

The forwarder always sends from the spool. The RAM deque shrinks to a
15-second staging buffer. Reading back what was just written is served from
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

## 4. Drain rate — answered by the server, 2026-09-07

**The earlier number in this section was 8x too high and would have caused
silent data loss.** It proposed 200 events per 1.0 s = 12,000 rows/min. The
server has enforced a hard per-node cap of **1,500 rows/min** since
2026-08-24, and excess is **dropped silently while still returning HTTP
200**. At the proposed rate roughly 87% of every backlog would have been
discarded, the node told it succeeded, and the segment deleted. Measured on
another node: ~10,000 rows attempted in one minute, 8,500 shed, 200 OK.

The cap is not being raised. It was sized against duplication-driven floods,
and every node hitting it today has a duplication factor of 1.00 — they are
backlog replays and spoof rigs, not duplicates. Raising it would double what
a spoof rig can inject without addressing what actually happens.

### Rates

| phase | rate | per 200-event batch |
|---|---|---|
| sustained floor | 1,500 rows/min | one batch per **8.0 s** |
| with surge credits | 2,800 rows/min | one batch per **4.3 s** |

**Until the server's step 3 ships, 8.0 s is the correct interval.** Credits
are computed but not granted before then.

### Surge credits — computed locally, never disclosed

```
credits  = min(CREDIT_MAX, offline_minutes * SUSTAINED)

SUSTAINED       1500 rows/min      guaranteed floor
CREDIT_MAX      45000              30 min of sustained
BURST_CEILING   3000 rows/min      hard ceiling, never exceed
```

Drain at the burst rate while credits remain, then fall back to sustained.
Both sides compute the same number from the same public formula and the
node's own offline duration; the server never reports a balance. This is not
an oracle because credits accrue only from silence at the sustained rate —
bursting at 2x for 30 minutes requires 30 minutes of silence first, so the
long-run average can never exceed sustained. A flooder gains nothing.

**Pace at 2,800/min, not 3,000.** Clock skew between node and server
otherwise pushes the last batch of each minute over the line, where it is
shed.

**Credits are lost if the server restarts.** The node is then held at 1,500
— slower, never lossy. Do not try to detect or compensate for this.

### The token bucket must be NODE-WIDE

A dual-adapter node runs `wifi-2g`, `wifi-5g` and `ble` — three processes,
one `node_id`, **one shared server-side budget**. Three feeders each pacing
themselves at the ceiling send 300% of it, each believing it is compliant,
and two thirds of the backlog is shed silently — on precisely the
dual-adapter nodes the split-feeder design exists to serve.

A per-feeder interval constant cannot fix this. The bucket lives in the
shared `SpoolQueue` (§5) and is coordinated across processes with a lock
file or small socket under `/run/droneaware/`.

### Declare the backlog

`RIDBatch` gains an optional `backlog_remaining: int` — rows still spooled
**after** this batch, so it decrements naturally and reaching 0 is a clean
"caught up" signal. It never increases what the node is allowed; it is
self-reported and unverifiable. It lets the server distinguish a node
catching up from a live flood, schedule shortest-backlog-first when many
nodes return at once, and give honest drain estimates. Report it honestly —
the server cross-checks it against silence it observed independently.

### Honour the pacing hint

The ingest response gains `next_batch_after_ms` (0-120,000): wait that long
before sending the **next** batch. The batch just sent is already banked.

It is deliberately **not a 429**. An error makes a node re-send its buffer,
which is the amplifier behind a previous incident; accepting the batch and
pacing the next one breaks that loop rather than feeding it. The value is
derived from fleet-wide throughput only and is identical for every node at a
given instant, which is what stops it being an oracle. With a spool, waiting
costs nothing.

### 🚨 Never delete a segment on HTTP status alone

`Forwarder.flush` currently calls `raise_for_status()` and **never reads the
response body**, so it treats 200 as "all rows stored". That is survivable
while the buffer is RAM-only and would be lost regardless. Once a segment is
deleted on the strength of that 200, a silent shed becomes silent permanent
loss — the spool would destroy exactly the data it exists to protect.

Segments must only be released when the rows are accounted for in the
response (`stored` + `deduped` covering what was sent), not on status alone.

**Open question for the server:** the response carries `stored`, so a node
can already compute `sent - stored - deduped` — which appears to be the shed
count that §5 of their handoff deliberately withholds. Either that
subtraction is a usable acknowledgement signal, in which case the spool
should use it, or `stored` does not mean what it appears to and we need an
explicit "all rows accounted for" flag. This needs answering before segment
deletion can be made safe.

## 5. Scope

| item | where |
|---|---|
| `SpoolQueue` (segments, cursor, cap, corrupt-tail tolerance) | new, shared |
| Forwarder reads from spool instead of deque | `wifi_feeder.py` **and** `ble_feeder.py` |
| 15 s write timer | both feeders |
| SIGTERM handler | both feeders |
| `TimeoutStopSec` | both `.service` units |
| **Node-wide token bucket** (lock file or socket under `/run/droneaware/`) | `SpoolQueue` — NOT per feeder |
| Surge-credit accounting from offline duration | `SpoolQueue` |
| Honour `next_batch_after_ms`; send `backlog_remaining` | `Forwarder.flush` |
| Release segments on accounted rows, not HTTP status | `Forwarder.flush` |
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
DRONEAWARE_SPOOL_WRITE_INTERVAL_SEC=15.0
DRONEAWARE_SPOOL_SUSTAINED_ROWS_PER_MIN=1500
DRONEAWARE_SPOOL_BURST_ROWS_PER_MIN=2800
DRONEAWARE_SPOOL_CREDIT_MAX=45000
```

### Must be observable

Silent success is this codebase's dominant failure mode, and a spool that
quietly fails to replay is indistinguishable from a quiet week of airspace.
Surface in the heartbeat and in `droneaware status`:

- spooled event count and bytes on disk
- whether a backlog exists, and estimated drain time
- oldest spooled detection timestamp
- count dropped to the cap, if any
- current drain rate, and whether surge credits are in use
- last `next_batch_after_ms` received, when non-zero

### Test matrix

1. Unplug mid-outage → events present after boot, delivered in order.
2. `SIGKILL` mid-append → truncated tail discarded, the rest replays.
3. Spool exceeds cap → oldest segment dropped, node keeps running.
4. 429 with `Retry-After` → backoff honoured, nothing lost.
5. Permanent 4xx during drain → that batch dropped, drain continues.
6. **Disk full → feeder degrades to RAM-only, says so loudly, never wedges.**
7. Clean `systemctl stop` mid-outage → zero loss.
8. Power loss while *online* → at most 15 s lost, not the whole window.
9. **Three feeders draining at once → combined rate stays under the
   ceiling.** The failure this catches is silent and only appears on
   dual-adapter nodes.
10. `next_batch_after_ms` honoured — a large value delays the next
    batch and does not trigger a retry.
11. A response that does not account for every row sent → segment is
    NOT deleted.

Item 6 is the one that must not be got wrong: the spool must never be able
to stop a node detecting.

---

## 6. Out of scope, deliberately

`/run/droneaware/detections.jsonl` stays on tmpfs. That is intentional —
`ble_feeder.py:714` names "zero SD card wear" as the reason. The local ring
is a *view* for the web UI, not the delivery guarantee. The spool is the
durable path.
