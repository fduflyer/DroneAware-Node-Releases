"""
Durable on-disk spool — the node's local flight history.

Before this module both feeders held undelivered detections in a bare
``collections.deque`` with zero file writes, so everything the node had
collected was lost on power loss, reboot, ``update``, ``refresh``, a crash
loop, and even a clean ``systemctl stop``. Store-and-forward only survived a
connectivity outage where the node stayed powered AND the process stayed up —
which is not the case it exists for.

The spool is not a queue that happens to persist. It is the node's detection
history, which happens to upload. Uploading is one thing that happens to a
record, not the reason it exists — so a record is removable only when it is
**past the retention window AND confirmed delivered**. Neither alone is
sufficient:

    delivered, inside retention   -> keep. This is the whole point.
    past retention, undelivered   -> keep. This is what the spool protects.

Layout, per feeder, under DRONEAWARE_SPOOL_DIR:

    <root>/<feeder>/seg-<epoch>-<seq>.jsonl   append-only, rolled at 4 MB
    <root>/<feeder>/cursor                    delivery watermark
    <root>/index/activity.log                 node-wide, append-only

Segments are appended to and deleted whole, never rewritten, so there is no
partial-file bookkeeping to get wrong. A truncated final line is *expected*
rather than exceptional — it is exactly what power loss mid-append produces —
and is discarded on read.

Everything here is stdlib only: both feeders and web_ui import it, and they do
not share a dependency set.
"""

import errno
import fcntl
import json
import logging
import os
import threading
import time

log = logging.getLogger(__name__)

DEFAULT_SPOOL_DIR = "/var/lib/droneaware/spool"
RUN_DIR = "/run/droneaware"

# Rolled at 4 MB: small enough that the cap and retention can free space at a
# useful granularity, large enough that a busy node is not opening a new file
# every few minutes.
DEFAULT_SEGMENT_BYTES = 4 * 1024 * 1024

# Worst-case data loss is one write interval. Chosen on the LOSS WINDOW, not
# on SD endurance: bytes/day are identical at any cadence because each event is
# written exactly once, and the card's erase block is 8 MB, so a 36-byte batch
# and a 4 KB batch are indistinguishable to the flash. Do not re-tune this on
# wear grounds; there are none.
DEFAULT_WRITE_INTERVAL_SEC = 15.0

DEFAULT_RETENTION_DAYS = 90          # "never" is permitted
DEFAULT_MAX_GB = 4.0                 # ceiling regardless of retention

# Last-resort event size, used only when nothing has been written this process
# AND no segment exists to sample. Any real spool measures itself instead.
DEFAULT_AVG_EVENT_BYTES = 320.0
# How much of the newest segment to read when seeding that measurement. Enough
# lines to be representative, small enough to stay inside one page-cache read.
AVG_SAMPLE_BYTES = 65536

# Occupancy/liveness bucket. 5 minutes over 90 days is 25,920 buckets — fine
# enough that a single short flight still registers, and far finer than any
# slider can draw.
DEFAULT_BUCKET_SEC = 300

# --- Drain pacing -----------------------------------------------------------
# Deliberately CONSERVATIVE defaults. The node's real pace comes from the
# server's advisory `next_batch_after_ms` once it has had one reply; these
# values only govern the very first batch after a restart and any period where
# the server sends no advice. They are set below any rate the server is known
# to accept, so the node is always safe-by-slow rather than optimistic. An
# operator or a future release can raise them through config.env.
DEFAULT_SUSTAINED_EVENTS_PER_MIN = 240
DEFAULT_BURST_EVENTS_PER_MIN = 600
DEFAULT_CREDIT_MAX_ROWS = 48000
DEFAULT_ROWS_PER_EVENT = 5

# Reads from a segment are chunked at this size so a small batch request does
# not pull the whole 4 MB tail off the card.
_READ_CHUNK = 65536

# Never let the spool take the card down to nothing. A node that stops logging
# detections because its own history filled the disk is strictly worse than one
# that lost old history — and the logs, an update download and the OS all need
# room. Held free regardless of what DRONEAWARE_SPOOL_MAX_GB says.
FREE_FLOOR_BYTES = 512 * 1024 * 1024

_SEG_PREFIX = "seg-"
_SEG_SUFFIX = ".jsonl"

# Activity-log record kinds.
KIND_DETECTIONS = "d"   # this bucket contains at least one detection
KIND_LIVE = "l"         # a feeder was up and recording during this bucket

# Track tones returned by track(). An empty bucket is AMBIGUOUS — "listening,
# heard nothing" and "the node was off" are both zero detections, and drawing
# them alike is wrong in exactly the case this release exists for: carry a node
# out, fly, drive home. The drive must not read as a quiet sky.
TONE_GAP = 0            # not recording — powered off, crashed, or feeder down
TONE_LIVE = 1           # recording, heard nothing
TONE_DETECTIONS = 2     # recording, and heard something


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(float(os.environ.get(name, "").strip() or default))
    except (TypeError, ValueError):
        return default


def spool_root() -> str:
    return os.environ.get("DRONEAWARE_SPOOL_DIR", "").strip() or DEFAULT_SPOOL_DIR


def bucket_sec() -> int:
    n = _env_int("DRONEAWARE_SPOOL_LIVENESS_TICK_SEC", DEFAULT_BUCKET_SEC)
    return n if n > 0 else DEFAULT_BUCKET_SEC


def retention_days():
    """Configured retention in days, or None for 'never delete'."""
    raw = os.environ.get("DRONEAWARE_SPOOL_RETENTION_DAYS", "").strip()
    if raw.lower() in ("never", "none", "0", "-1", "forever"):
        return None
    try:
        v = float(raw or DEFAULT_RETENTION_DAYS)
    except ValueError:
        return float(DEFAULT_RETENTION_DAYS)
    return v if v > 0 else None


def max_bytes() -> int:
    gb = _env_float("DRONEAWARE_SPOOL_MAX_GB", DEFAULT_MAX_GB)
    if gb <= 0:
        gb = DEFAULT_MAX_GB
    return int(gb * 1024 * 1024 * 1024)


def _seg_sort_key(name: str):
    """Sort segments chronologically by (epoch, seq) parsed from the name.

    Lexical sort on the zero-padded name gives the same order, but parsing
    keeps that from being load-bearing if the padding ever changes.
    """
    try:
        body = name[len(_SEG_PREFIX):-len(_SEG_SUFFIX)]
        epoch, seq = body.split("-", 1)
        return (int(epoch), int(seq))
    except (ValueError, IndexError):
        return (0, 0)


def _list_segments(d: str):
    try:
        names = [n for n in os.listdir(d)
                 if n.startswith(_SEG_PREFIX) and n.endswith(_SEG_SUFFIX)]
    except OSError:
        return []
    names.sort(key=_seg_sort_key)
    return names


def _feeder_dirs(root: str):
    """Every per-feeder spool directory under root, excluding the index."""
    try:
        return sorted(n for n in os.listdir(root)
                      if n != "index" and os.path.isdir(os.path.join(root, n)))
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Activity index — node-wide, append-only
# ---------------------------------------------------------------------------

class ActivityIndex:
    """Records which time buckets had detections, and which had a live feeder.

    Append-only by design. Rewriting a 25 KB bitmap every tick costs 7.4 MB/day
    against an append's 0.003 MB/day — 2,400x the bytes for a structure that
    can just as well be reduced at read time. Measured on a node's own card:
    the OS already writes 52 MB/day across 1,062,666 operations, so an append
    every five minutes is 0.027% of the write operations it absorbs anyway, and
    lands well inside the 8 MB erase block.

    Shared by all three feeder processes. Records are ~24 bytes and written
    with O_APPEND, far below PIPE_BUF, so interleaved writes cannot tear.
    Duplicate records are harmless: readers reduce to a set.
    """

    def __init__(self, root: str, feeder: str = "-"):
        self.dir = os.path.join(root, "index")
        self.path = os.path.join(self.dir, "activity.log")
        self.feeder = feeder
        self._seen = set()
        self._lock = threading.Lock()

    def mark(self, kind: str, when: float = None) -> None:
        """Record that `kind` applies to the bucket containing `when`.

        First observation per (bucket, kind) per process only — a busy node
        appends once per bucket, not once per detection.
        """
        b = int((when if when is not None else time.time()) // bucket_sec())
        key = (b, kind)
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
            # Bound the in-process set. Buckets are monotonic, so anything far
            # behind the newest will never be marked again.
            if len(self._seen) > 20000:
                cutoff = b - 4000
                self._seen = {k for k in self._seen if k[0] >= cutoff}
        try:
            os.makedirs(self.dir, exist_ok=True)
            line = f"{b} {kind} {self.feeder}\n".encode()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
        except OSError as e:
            # A full or read-only card must never stop a node detecting.
            log.debug(f"activity index append failed: {e}")

    def compact(self, cutoff_bucket: int) -> None:
        """Drop records older than cutoff_bucket. Rare — called from prune()."""
        try:
            with open(self.path, "r") as f:
                lines = f.readlines()
        except OSError:
            return
        keep = []
        for ln in lines:
            parts = ln.split()
            if len(parts) >= 2:
                try:
                    if int(parts[0]) >= cutoff_bucket:
                        keep.append(ln)
                except ValueError:
                    continue
        if len(keep) == len(lines):
            return
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                f.writelines(keep)
            os.replace(tmp, self.path)
            log.info(f"activity index compacted: {len(lines)} -> {len(keep)} records")
        except OSError as e:
            log.debug(f"activity index compaction failed: {e}")


def read_activity(root: str = None):
    """Return {bucket: tone} from the node-wide activity log.

    Detections win over liveness: a bucket recorded as both is a bucket where
    the node was up and heard something.
    """
    root = root or spool_root()
    path = os.path.join(root, "index", "activity.log")
    out = {}
    try:
        with open(path, "r") as f:
            for ln in f:
                parts = ln.split()
                if len(parts) < 2:
                    continue
                try:
                    b = int(parts[0])
                except ValueError:
                    continue
                kind = parts[1]
                if kind == KIND_DETECTIONS:
                    out[b] = TONE_DETECTIONS
                elif kind == KIND_LIVE and out.get(b, TONE_GAP) < TONE_LIVE:
                    out[b] = TONE_LIVE
    except OSError:
        return {}
    return out


# ---------------------------------------------------------------------------
# Node-wide drain pacing
# ---------------------------------------------------------------------------

class NodeRateLimiter:
    """One shared upload budget for every feeder process on this node.

    🚨 This CANNOT be a per-process constant. A dual-adapter node runs three
    feeders (wifi-2g, wifi-5g, ble) under ONE node_id, so three processes each
    pacing themselves correctly still send three times the intended rate, every
    one of them believing it complies. That failure appears only on exactly the
    dual-adapter nodes the split-feeder design exists to serve, and the node
    cannot detect it from its own side — hence one shared budget.

    State lives in a small flock'd JSON file on tmpfs, so coordination costs no
    SD writes. Two buckets:

      credits  refills steadily and is capped, so a node that has been quiet or
               merely below its own pace banks headroom for a backlog later.
      burst    a small fast bucket that stops a node with a large credit
               balance from emptying it as fast as the link allows.

    The operative pace comes from the server's advisory `next_batch_after_ms`
    once it has replied; the defaults above only govern the first batch after a
    restart and any period where no advice arrives.
    """

    def __init__(self, path: str = None):
        self.path = path or os.path.join(RUN_DIR, "spool_bucket")
        self.rows_per_event = max(1, _env_int("DRONEAWARE_SPOOL_ROWS_PER_EVENT",
                                              DEFAULT_ROWS_PER_EVENT))
        sustained_ev = _env_float("DRONEAWARE_SPOOL_SUSTAINED_EVENTS_PER_MIN",
                                  DEFAULT_SUSTAINED_EVENTS_PER_MIN)
        burst_ev = _env_float("DRONEAWARE_SPOOL_BURST_EVENTS_PER_MIN",
                              DEFAULT_BURST_EVENTS_PER_MIN)
        self.sustained_rps = sustained_ev * self.rows_per_event / 60.0
        self.burst_rps = max(burst_ev * self.rows_per_event / 60.0,
                             self.sustained_rps)
        self.credit_max = _env_float("DRONEAWARE_SPOOL_CREDIT_MAX_ROWS",
                                     DEFAULT_CREDIT_MAX_ROWS)
        # Enough headroom for one full batch so a single batch is never
        # permanently unaffordable, plus ten seconds of burst.
        self.burst_max = max(self.burst_rps * 10.0, 1000.0)

    def _load(self, fd):
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 4096).decode() or "{}"
            st = json.loads(raw)
        except (OSError, ValueError):
            st = {}
        now = time.time()
        last = float(st.get("ts", now))
        # A clock step backwards (NTP settling after boot, common on a Pi with
        # no RTC) must not hand out an unbounded refill or freeze the bucket.
        elapsed = max(0.0, min(now - last, 3600.0))
        credits = min(self.credit_max,
                      float(st.get("credits", self.credit_max)) + self.sustained_rps * elapsed)
        burst = min(self.burst_max,
                    float(st.get("burst", self.burst_max)) + self.burst_rps * elapsed)
        return credits, burst, now

    def _store(self, fd, credits, burst, now):
        raw = json.dumps({"credits": round(credits, 2),
                          "burst": round(burst, 2),
                          "ts": now}).encode()
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, raw)
        os.ftruncate(fd, len(raw))

    def take(self, events: int) -> float:
        """Reserve budget for `events`. Returns 0.0 if the batch may go now,
        otherwise the seconds to wait before asking again.

        Fails OPEN: if the state file cannot be opened at all, pacing is
        skipped rather than blocking delivery. Shedding a little is recoverable
        (the server dedupes a resend); wedging the uploader is not.
        """
        rows = events * self.rows_per_event
        try:
            os.makedirs(RUN_DIR, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError as e:
            log.debug(f"rate limiter unavailable, not pacing: {e}")
            return 0.0
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            credits, burst, now = self._load(fd)
            if credits >= rows and burst >= rows:
                self._store(fd, credits - rows, burst - rows, now)
                return 0.0
            need_c = (rows - credits) / self.sustained_rps if credits < rows else 0.0
            need_b = (rows - burst) / self.burst_rps if burst < rows else 0.0
            self._store(fd, credits, burst, now)
            return max(0.05, min(max(need_c, need_b), 300.0))
        except OSError as e:
            log.debug(f"rate limiter error, not pacing: {e}")
            return 0.0
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def snapshot(self) -> dict:
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError:
            return {}
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            credits, burst, _ = self._load(fd)
            return {"credits_rows": int(credits),
                    "credits_max_rows": int(self.credit_max),
                    "rows_per_event": self.rows_per_event}
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


# ---------------------------------------------------------------------------
# The spool itself
# ---------------------------------------------------------------------------

class SpoolQueue:
    """Per-feeder durable event queue and history store.

    add() stages in RAM; commit_staged() appends to disk. The staging buffer is
    a write-coalescing window, not the queue — the queue is the segment files,
    and read_batch() always reads from disk. That is deliberate: it means the
    replay-from-disk path is the ordinary path and runs constantly, rather than
    being recovery code that only executes after the crash it is meant to
    survive.
    """

    def __init__(self, feeder: str, root: str = None):
        self.feeder = feeder
        self.root = root or spool_root()
        self.dir = os.path.join(self.root, feeder)
        self.cursor_path = os.path.join(self.dir, "cursor")
        self.segment_bytes = _env_int("DRONEAWARE_SPOOL_SEGMENT_BYTES",
                                      DEFAULT_SEGMENT_BYTES)
        self.write_interval = _env_float("DRONEAWARE_SPOOL_WRITE_INTERVAL_SEC",
                                         DEFAULT_WRITE_INTERVAL_SEC)
        self.index = ActivityIndex(self.root, feeder)

        self._lock = threading.Lock()
        self._staged = []            # list[str] — serialized lines awaiting disk
        self._staged_bytes = 0
        self._seq = 0
        self._degraded = False       # disk unusable; RAM-only, loudly
        self._last_write = time.monotonic()
        self._last_prune = 0.0
        self._warned_space = False

        self.written_events = 0
        self.written_bytes = 0
        self.dropped_events = 0      # lost to the size ceiling
        self.dropped_undelivered = 0 # of those, never delivered — real loss
        self.corrupt_lines = 0
        self._avg_seed = None        # measured from disk; see avg_event_bytes

        try:
            os.makedirs(self.dir, exist_ok=True)
        except OSError as e:
            self._degraded = True
            log.error(f"spool: cannot create {self.dir} ({e}) — "
                      "running RAM-only, history will NOT survive a restart")

    # -- writing ------------------------------------------------------------

    def add(self, event: dict) -> None:
        line = json.dumps(event, separators=(",", ":")) + "\n"
        with self._lock:
            self._staged.append(line)
            self._staged_bytes += len(line)

    @property
    def staged_events(self) -> int:
        with self._lock:
            return len(self._staged)

    @property
    def staged_bytes(self) -> int:
        with self._lock:
            return self._staged_bytes

    def due(self) -> bool:
        with self._lock:
            if not self._staged:
                return False
        return time.monotonic() - self._last_write >= self.write_interval

    def commit_staged(self, fsync: bool = False) -> int:
        """Append everything staged to the active segment. Returns events written.

        `fsync` is used on the shutdown path only. In steady state the cost of
        an fsync every 15 s is not worth paying for a window the OS would have
        flushed anyway; on SIGTERM the process is about to exit and there is no
        later flush to rely on.
        """
        with self._lock:
            if not self._staged:
                self._last_write = time.monotonic()
                return 0
            lines = self._staged
            self._staged = []
            self._staged_bytes = 0
            self._last_write = time.monotonic()

        if self._degraded:
            return 0

        data = "".join(lines).encode()
        try:
            path = self._active_segment(len(data))
            with open(path, "ab") as f:
                f.write(data)
                if fsync:
                    f.flush()
                    os.fsync(f.fileno())
        except OSError as e:
            if e.errno in (errno.ENOSPC, errno.EROFS, errno.EDQUOT):
                # Item 6 of the test matrix, and the one that must not be got
                # wrong: the spool must never be able to stop a node detecting.
                if not self._degraded:
                    log.error(f"spool: disk unusable ({e}) — degrading to RAM-only. "
                              "Detection continues; history is NOT being saved.")
                self._degraded = True
            else:
                log.warning(f"spool: append failed ({e}) — {len(lines)} events lost")
            return 0

        self.written_events += len(lines)
        self.written_bytes += len(data)
        self.index.mark(KIND_DETECTIONS)
        return len(lines)

    @property
    def avg_event_bytes(self) -> float:
        """Measured, with a first-boot fallback. Used only to turn a backlog in
        bytes into an approximate event count for the heartbeat.

        🚨 written_* are PER-PROCESS counters starting at zero, so a feeder that
        has just started has nothing to measure — which is precisely the moment
        a backlog is largest and the number matters most. A node that rebooted
        holding 2589 undelivered events reported 2953 of them, because a
        hardcoded 280 stood in for a real average of ~319 bytes.

        Seed from the segments already on disk instead of guessing. One bounded
        read of the newest segment measures what THIS node's events actually
        cost. The live measurement takes over as soon as anything is written.
        """
        if self.written_events:
            return self.written_bytes / self.written_events
        if self._avg_seed is None:
            self._avg_seed = self._measure_avg_from_disk()
        return self._avg_seed or DEFAULT_AVG_EVENT_BYTES

    def _measure_avg_from_disk(self) -> float | None:
        """Bytes per event, sampled from the newest segment. None if unknowable.

        Deliberately returns None rather than the fallback on failure, so a
        transient error is retried instead of cached for the life of the
        process — the same reason the PHY probe does not cache failures.
        """
        try:
            names = _list_segments(self.dir)
            if not names:
                return None
            with open(os.path.join(self.dir, names[-1]), "rb") as f:
                chunk = f.read(AVG_SAMPLE_BYTES)
        except OSError:
            return None
        cut = chunk.rfind(b"\n")
        if cut < 0:
            return None                      # no complete line to measure
        lines = chunk.count(b"\n", 0, cut + 1)
        if lines < 1:
            return None
        return (cut + 1) / lines

    def tick_liveness(self) -> None:
        """Record that this feeder was up and recording right now.

        Called from the heartbeat loop, NOT from the spool write. The spool
        only writes when events exist, so keying liveness off it would once
        again make 'quiet' indistinguishable from 'off' — the exact ambiguity
        this fixes.
        """
        if not self._degraded:
            self.index.mark(KIND_LIVE)

    def _active_segment(self, incoming: int) -> str:
        names = _list_segments(self.dir)
        if names:
            path = os.path.join(self.dir, names[-1])
            try:
                if os.path.getsize(path) + incoming <= self.segment_bytes:
                    return path
            except OSError:
                pass
        self._seq = (self._seq + 1) % 10000
        name = f"{_SEG_PREFIX}{int(time.time()):010d}-{self._seq:04d}{_SEG_SUFFIX}"
        return os.path.join(self.dir, name)

    # -- cursor -------------------------------------------------------------

    def _read_cursor(self):
        try:
            with open(self.cursor_path, "r") as f:
                c = json.load(f)
            return str(c.get("segment") or ""), int(c.get("offset") or 0)
        except (OSError, ValueError, TypeError):
            return "", 0

    def _write_cursor(self, segment: str, offset: int) -> None:
        tmp = self.cursor_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump({"segment": segment, "offset": offset}, f)
            os.replace(tmp, self.cursor_path)
        except OSError as e:
            log.debug(f"spool: cursor write failed: {e}")

    # -- reading ------------------------------------------------------------

    def read_batch(self, max_events: int):
        """Return (events, mark) for the next undelivered batch, or ([], None).

        `mark` is opaque; pass it to commit() once the batch is delivered.
        """
        if self._degraded:
            return [], None
        names = _list_segments(self.dir)
        if not names:
            return [], None
        cur_seg, cur_off = self._read_cursor()
        if cur_seg not in names:
            # Cursor points at a segment that retention or the ceiling removed.
            # Restart from the oldest surviving one rather than guessing.
            cur_seg, cur_off = names[0], 0

        start = names.index(cur_seg)
        for i in range(start, len(names)):
            name = names[i]
            off = cur_off if i == start else 0
            is_active = (i == len(names) - 1)
            events, end = self._scan(name, off, max_events, is_active)
            if events:
                return events, (name, end)
            # Nothing usable left in this segment; step past it.
            if not is_active:
                cur_off = 0
                continue
            if end != off:
                # The tail was corrupt but skippable — record the advance so we
                # do not re-scan it forever.
                self._write_cursor(name, end)
        return [], None

    def _scan(self, name: str, offset: int, max_events: int, is_active: bool):
        """Read at most max_events from `name` starting at `offset`.

        Reads in bounded chunks rather than slurping the rest of the segment.
        The WiFi feeder asks for batches of ten; a segment holds four
        megabytes. Reading the whole tail to satisfy a ten-event request would
        put a multi-megabyte read on the flush path every couple of seconds,
        for data it then throws away.
        """
        path = os.path.join(self.dir, name)
        events = []
        pos = offset
        buf = b""
        at_eof = False
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                while len(events) < max_events:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        chunk = f.read(_READ_CHUNK)
                        if not chunk:
                            at_eof = True
                            break
                        buf += chunk
                        continue
                    raw, buf = buf[:nl], buf[nl + 1:]
                    pos += nl + 1
                    if not raw.strip():
                        continue
                    try:
                        events.append(json.loads(raw))
                    except ValueError:
                        self.corrupt_lines += 1
        except OSError:
            return [], offset

        # A leftover fragment with no terminator. On the active segment that is
        # a batch still being written, so stop short and pick it up next time.
        # On a closed segment it is a truncated tail from power loss
        # mid-append: expected, discarded silently, and stepped over so it
        # cannot block the queue forever.
        if at_eof and buf and not is_active:
            pos += len(buf)
        return events, pos

    def commit(self, mark) -> None:
        """Advance the delivery watermark. Deletes nothing.

        🚨 A 200 must NEVER remove a segment. The watermark says how far the
        node has got, so it does not re-send the whole history on every pass;
        removal is governed by retention and the size ceiling only. This is the
        distinction that keeps the spool a history rather than a queue, and it
        is the easiest thing in the design to regress.
        """
        if mark:
            self._write_cursor(mark[0], mark[1])

    def delivered_through(self):
        return self._read_cursor()

    # -- retention and the ceiling -----------------------------------------

    def prune(self, force: bool = False) -> None:
        """Apply retention, then the size ceiling. Never touches the active
        segment, and never removes anything that is both wanted and safe."""
        if self._degraded:
            return
        now = time.monotonic()
        if not force and now - self._last_prune < 300:
            return
        self._last_prune = now

        names = _list_segments(self.dir)
        if len(names) <= 1:
            return
        cur_seg, cur_off = self._read_cursor()
        cur_rank = names.index(cur_seg) if cur_seg in names else -1

        def delivered(idx: int) -> bool:
            if cur_rank < 0:
                return False
            if idx < cur_rank:
                return True
            if idx > cur_rank:
                return False
            try:
                return cur_off >= os.path.getsize(os.path.join(self.dir, names[idx]))
            except OSError:
                return False

        days = retention_days()
        survivors = []
        for idx, name in enumerate(names[:-1]):   # never the active segment
            path = os.path.join(self.dir, name)
            try:
                mtime = os.path.getmtime(path)
                size = os.path.getsize(path)
            except OSError:
                continue
            # mtime is the time of the LAST append, i.e. the segment's newest
            # record. Judging by the newest keeps a segment slightly longer
            # than strictly required, which is the right way to be wrong, and
            # avoids ever having to split one.
            expired = days is not None and (time.time() - mtime) > days * 86400
            if expired and delivered(idx):
                self._unlink(path, "past retention and delivered")
            else:
                survivors.append((idx, name, path, size))

        total = sum(s[3] for s in survivors)
        try:
            total += os.path.getsize(os.path.join(self.dir, names[-1]))
        except OSError:
            pass
        cap = self._effective_cap(total)
        if total <= cap:
            self._compact_index(days)
            return

        # The ceiling wins, but loses as little as possible: delivered
        # segments first (safe on the server, costs local convenience only),
        # then undelivered — which is real loss and must be loud. What is never
        # acceptable is to stop recording.
        for want_delivered in (True, False):
            for idx, name, path, size in list(survivors):
                if total <= cap:
                    break
                if delivered(idx) != want_delivered:
                    continue
                self._unlink(path, "size ceiling reached"
                             if want_delivered else "size ceiling reached — UNDELIVERED")
                if not want_delivered:
                    self.dropped_undelivered += 1
                    log.error(
                        f"spool: dropped UNDELIVERED segment {name} to stay under "
                        f"the {cap // (1024*1024)} MB ceiling. Detections in it were "
                        "never uploaded and are gone. Raise DRONEAWARE_SPOOL_MAX_GB "
                        "or check why uploads are failing.")
                total -= size
                survivors.remove((idx, name, path, size))
        self._compact_index(days)

    def _effective_cap(self, current_total: int) -> int:
        """The size ceiling, tightened when the card is running out of room.

        DRONEAWARE_SPOOL_MAX_GB is what the operator asked to keep. Free space
        is what the node actually has. When the second is smaller the second
        wins, loudly — the alternative is a card that fills with history and
        takes detection down with it.
        """
        cap = max_bytes()
        try:
            st = os.statvfs(self.dir)
            free = st.f_bavail * st.f_frsize
        except OSError:
            return cap
        room = current_total + max(0, free - FREE_FLOOR_BYTES)
        if room < cap:
            if not self._warned_space:
                log.warning(
                    f"spool: only {free // (1024*1024)} MB free on {self.dir} — "
                    f"holding history to {room // (1024*1024)} MB instead of the "
                    f"configured {cap // (1024*1024)} MB so the card keeps room "
                    "for logs and updates")
                self._warned_space = True
            return room
        self._warned_space = False
        return cap

    def _compact_index(self, days) -> None:
        if days is None:
            return
        cutoff = int((time.time() - days * 86400) // bucket_sec())
        self.index.compact(cutoff)

    def _unlink(self, path: str, why: str) -> None:
        try:
            os.unlink(path)
            log.info(f"spool: removed {os.path.basename(path)} — {why}")
        except OSError as e:
            log.debug(f"spool: could not remove {path}: {e}")

    # -- observability ------------------------------------------------------

    def stats(self) -> dict:
        """Everything the heartbeat and `droneaware status` need.

        Silent success is this codebase's dominant failure mode, and a spool
        that quietly fails to replay is indistinguishable from a quiet week of
        airspace.
        """
        names = _list_segments(self.dir)
        bytes_on_disk = 0
        oldest = None
        for n in names:
            p = os.path.join(self.dir, n)
            try:
                bytes_on_disk += os.path.getsize(p)
                mt = os.path.getmtime(p)
            except OSError:
                continue
            if oldest is None or mt < oldest:
                oldest = mt
        cur_seg, cur_off = self._read_cursor()
        pending = 0
        if cur_seg in names:
            pending = bytes_on_disk - sum(
                os.path.getsize(os.path.join(self.dir, n))
                for n in names[:names.index(cur_seg)]
                if os.path.exists(os.path.join(self.dir, n))
            ) - cur_off
        elif names:
            pending = bytes_on_disk
        return {
            "feeder": self.feeder,
            "degraded": self._degraded,
            "segments": len(names),
            "bytes": bytes_on_disk,
            "backlog_bytes": max(0, pending),
            "backlog_events": int(max(0, pending) / self.avg_event_bytes),
            "staged": self.staged_events,
            "written_events": self.written_events,
            "dropped_undelivered_segments": self.dropped_undelivered,
            "corrupt_lines": self.corrupt_lines,
            "oldest_epoch": oldest,
        }


# ---------------------------------------------------------------------------
# Read-side helpers — used by web_ui for the replay controls
# ---------------------------------------------------------------------------

def bounds(root: str = None) -> dict:
    """Oldest and newest record times, count and size across every feeder.

    The extent MUST reflect what is actually on disk, not the retention
    setting. If the ceiling trimmed history, the slider has to show the real
    bounds — that is the honest answer to a 'never delete' setting the node
    could not fully honour.
    """
    root = root or spool_root()
    oldest = newest = None
    total = 0
    segs = 0
    for feeder in _feeder_dirs(root):
        d = os.path.join(root, feeder)
        for n in _list_segments(d):
            p = os.path.join(d, n)
            try:
                total += os.path.getsize(p)
                mt = os.path.getmtime(p)
            except OSError:
                continue
            segs += 1
            start = _seg_sort_key(n)[0]
            if oldest is None or start < oldest:
                oldest = start
            if newest is None or mt > newest:
                newest = mt
    act = read_activity(root)
    if act:
        bs = bucket_sec()
        lo, hi = min(act) * bs, (max(act) + 1) * bs
        oldest = lo if oldest is None else min(oldest, lo)
        newest = hi if newest is None else max(newest, hi)
    return {
        "oldest": oldest,
        "newest": newest,
        "bytes": total,
        "segments": segs,
        "bucket_sec": bucket_sec(),
        "retention_days": retention_days(),
        "max_bytes": max_bytes(),
        # Which of the two knobs is actually governing right now. Without this
        # a "never delete" setting reads as a promise the node cannot make.
        "free_bytes": _free_bytes(root),
        "governed_by": ("none" if not segs
                        else "disk" if _free_bytes(root) < FREE_FLOOR_BYTES * 2
                        else "ceiling" if total >= max_bytes() * 0.95
                        else "retention" if retention_days() else "none"),
    }


def _free_bytes(root: str) -> int:
    """Free space on the filesystem that holds (or will hold) the spool.

    Walks up to the nearest existing ancestor: before the feeders have written
    anything the spool directory does not exist yet, and statvfs on a missing
    path would report zero free — which reads as "the disk is full" and is the
    opposite of the truth.
    """
    d = os.path.abspath(root)
    while True:
        try:
            st = os.statvfs(d)
            return st.f_bavail * st.f_frsize
        except OSError:
            parent = os.path.dirname(d)
            if parent == d:
                return 0
            d = parent


def track(t0: float, t1: float, columns: int = 600, root: str = None):
    """Downsample the activity index to `columns` tones for the replay slider.

    Reduced with max(), never mean(): one detection in an otherwise empty week
    must still light its pixel. Averaging would erase exactly the flights an
    operator is scrubbing to find.
    """
    root = root or spool_root()
    act = read_activity(root)
    columns = max(1, min(int(columns), 2000))
    out = [TONE_GAP] * columns
    if not act or t1 <= t0:
        return out
    bs = bucket_sec()
    span = t1 - t0
    for b, tone in act.items():
        # A bucket covers a RANGE of time, not an instant. Lighting only the
        # single column its start falls in is correct when the index is finer
        # than the display — 25,920 buckets over 90 days against 600 pixels —
        # and wrong the moment it is not. Over a six-hour window there are 73
        # buckets across ~900 pixels, and point-mapping drew each one as a
        # hairline with twelve empty columns after it: a solid afternoon of
        # recording rendered as a picket fence.
        ts0, ts1 = b * bs, (b + 1) * bs
        if ts1 <= t0 or ts0 >= t1:
            continue
        c0 = max(0, int((ts0 - t0) / span * columns))
        c1 = min(columns - 1, int((ts1 - t0) / span * columns - 1e-9))
        for c in range(c0, max(c0, c1) + 1):
            if tone > out[c]:
                out[c] = tone
    return out


def read_range(t0: float, t1: float, limit: int = 20000, root: str = None):
    """Events whose timestamp falls in [t0, t1), oldest first, across feeders.

    Cheap over the spool because segments are append-only and chronological: a
    time window is a seek to the right segment plus a scan, not a query engine.
    """
    root = root or spool_root()
    out = []
    for feeder in _feeder_dirs(root):
        d = os.path.join(root, feeder)
        names = _list_segments(d)
        for i, n in enumerate(names):
            # An event's observation time can never exceed the moment it was
            # appended, and everything in this segment was appended before the
            # next one was created — so a segment whose successor already
            # existed before the window opened cannot hold anything in it.
            #
            # The mirror-image test (skip segments created after the window
            # closes) looks equally obvious and is WRONG: a node that spent a
            # week offline writes week-old detections into a segment created
            # today, which is precisely the case this release exists for. There
            # is no lower bound on how old a segment's contents may be.
            nxt = _seg_sort_key(names[i + 1])[0] if i + 1 < len(names) else None
            if nxt is not None and nxt < t0:
                continue
            try:
                with open(os.path.join(d, n), "rb") as f:
                    for raw in f:
                        if not raw.endswith(b"\n"):
                            break          # truncated tail
                        try:
                            ev = json.loads(raw)
                        except ValueError:
                            continue
                        ts = _event_time(ev)
                        if ts is None or ts < t0 or ts >= t1:
                            continue
                        out.append(ev)
                        if len(out) >= limit:
                            break
            except OSError:
                continue
            if len(out) >= limit:
                break
        if len(out) >= limit:
            break
    out.sort(key=lambda e: _event_time(e) or 0)
    return out


def _event_time(ev: dict):
    for k in ("obs_time", "timestamp", "ts", "time"):
        v = ev.get(k)
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            try:
                from datetime import datetime
                return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
    return None
