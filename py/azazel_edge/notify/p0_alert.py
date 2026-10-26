"""P0 alert path: audit-chain decision record -> P0 alert -> durable queue.

Owner decisions on Edge#414 (2026-10-25):

* **P0** is an enforcement-bearing decision (throttle, redirect, isolate) or a
  decision taken on a SOC signal labelled ``critical``. The notify layer builds
  the alert from the decision's audit-chain record; :func:`classify_p0` is a
  deterministic function of that record (no model, no lookup, no clock).
* **Queue** (option A): one durable JSONL file in the Python notify layer.
  Visual and voice are the ``channel`` field of the alert entries. Rendering
  and speaking are downstream of the queue and are not done here.
* **Past decisions** (Edge#462 item 5, option (b)): a decision the startup
  reconcile found older than the core's lease (300 s) is still alerted, so an
  isolate applied while the agent was down reaches the operator, but never as
  a current alert. Its entries carry ``stale: true`` and ``presentation:
  historical``; :func:`render_p0_alert` (the one place the queue's wording is
  built) prefixes them with 「過去の判定」 and the event's time, and the voice
  entry is an announcement of a past decision, not an urgent alert
  (``voice_urgent: false``). A downstream renderer or speaker must use
  ``render_p0_alert`` or honour those fields. A decision this relay replays
  from the chain itself (in the chain, not in the queue) is judged the same
  way from the record's own time (``event_ts``, else the core's ingest stamp,
  else the record's ``ts``; past when none can be read). A time more than
  ``CLOCK_SKEW_TOLERANCE_S`` (60 s) in the future, or a non-finite number,
  is unreadable (core event times are not authenticated). Live alerts are
  never marked past.

Observation and notification only. Nothing here decides, enforces, approves or
changes a decision, and nothing reads the queue back into the decision path.
The audit logger hands each durable decision record to its listeners from a
dispatcher thread, never from the writer (see
``P0AuditLogger.add_durable_listener``); :meth:`P0AlertRelay.on_durable_record`
only puts it on a bounded hand-off. The relay's own thread classifies and
enqueues. Losses (a full hand-off, a failed enqueue) are counted and written
to the queue as standalone ``relay_status`` records; they never reach,
delay or alter the decision path.

Where the path is attached:

* the AI agent service (``systemd/azazel-edge-ai-agent.service``,
  ``py/azazel_edge_ai/agent.py``) is where the Rust core (the authoritative
  decision and enforcement path, Edge#412) forwards every decision event. At
  start (``_serve``) the agent opens the core decision chain
  ``core-decision-audit.jsonl`` and attaches this relay to it; each P0 core
  decision is written there as an ``action_decision`` record carrying the
  core's decision and what the core did with it (applied, dry run, gated).
  This is the path SO-03 measures.
* ``OpenCanaryRedirectController`` attaches it to its decision logger when
  the controller is built; no Edge service builds that controller yet.
"""

from __future__ import annotations

import errno
import json
import logging
import math
import os
import queue as _queue_mod
import stat
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from azazel_edge._util import iso_utc_now
from azazel_edge.audit.logger import _FSYNC_UNSUPPORTED, fsync_path

try:  # POSIX: serialise queue writers across processes too.
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX
    _fcntl = None

_LOG = logging.getLogger(__name__)

_O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
_O_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)

P0_CLASS = 'P0'
P0_RULE = 'edge-p0/v1:enforcement-bearing-or-soc-critical'
ENFORCEMENT_ACTIONS = ('throttle', 'redirect', 'isolate')
P0_BASIS_SOC_CRITICAL = 'soc_critical'

QUEUE_SCHEMA = 'azazel-edge/p0-alert-queue/v1'
CHANNEL_VISUAL = 'visual'
CHANNEL_VOICE = 'voice'
CHANNELS = (CHANNEL_VISUAL, CHANNEL_VOICE)

# Bounded queue. Appends never rewrite the file. When the file would exceed
# 2 x max_entries lines it is compacted once: the OLDEST decisions are evicted
# whole (both channels together, never the new P0 alert) until at most
# max_entries alert entries remain, and an ``overflow_alarm`` record naming
# what was evicted is written with them; every later alert carries the
# cumulative count. The file is never longer than 2 x max_entries lines.
DEFAULT_MAX_ENTRIES = 1000
OVERFLOW_POLICY = 'evict_oldest_whole_decisions_compact_at_2x'
RECORD_ALERT = 'alert'
RECORD_OVERFLOW_ALARM = 'overflow_alarm'
RECORD_RELAY_STATUS = 'relay_status'
# Startup reconcile replays at most this many missed P0 decisions (the
# newest); the rest are counted in the relay_status record.
DEFAULT_MAX_RECONCILE = 256

DURABILITY_FSYNCED = 'fsynced'
DURABILITY_UNSUPPORTED = 'fsync_unsupported'

# How an alert entry is to be presented (Edge#462 item 5). ``current``: a
# live alert, or a reconciled one still within the core's lease. ``historical``:
# a reconciled decision older than that (``stale``): shown as a past decision
# with its event time and never spoken as an urgent alert.
# A decision older than this is no longer a current alert (Edge#462 item 5).
# 300 s is the core's default enforcement lease (AZAZEL_DEFENSE_ACTION_TTL_SEC
# in systemd/azazel-edge-core.service). Shared with the core decision
# recorder's startup reconcile (core_decisions imports it).
STALE_AFTER_S = 300.0
# Core event times are not authenticated. A time more than this far in the
# future cannot be trusted to say the decision is current: it is treated as
# unreadable, i.e. past (Edge#462 item 5).
CLOCK_SKEW_TOLERANCE_S = 60.0
# Display bound for the free-text fields of an alert (they come from core
# events, which are not authenticated).
DISPLAY_FIELD_MAX = 200
PRESENTATION_CURRENT = 'current'
PRESENTATION_HISTORICAL = 'historical'
HISTORICAL_LABEL = '過去の判定'
EVENT_TIME_UNKNOWN = '時刻不明'


def event_ts_epoch(ts: Any) -> Optional[float]:
    """The epoch of a Suricata EVE timestamp (``...T..:..:..[.ffffff]+0000``
    or ``Z``), or None when it cannot be read."""

    if not isinstance(ts, str) or not ts:
        return None
    text = ts.strip()
    if text.endswith('Z'):
        text = text[:-1] + '+0000'
    for fmt in ('%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z'):
        try:
            return finite_epoch(datetime.strptime(text, fmt).timestamp())
        except (ValueError, OverflowError, OSError):
            continue
    return None


def finite_epoch(value: Any) -> Optional[float]:
    """``value`` as a float when it is a finite number, else None (bool,
    NaN, +/-inf and integers too large for a float are not readable
    times)."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        out = float(value)
    except OverflowError:
        return None
    return out if math.isfinite(out) else None


def is_past_decision(happened: Optional[float], now: float) -> bool:
    """Whether a decision whose event happened at ``happened`` is no longer a
    current alert at ``now``: its time is unreadable (None or not finite),
    more than CLOCK_SKEW_TOLERANCE_S in the future, or more than
    STALE_AFTER_S in the past. Used by the startup reconcile of the core
    decision recorder and by this relay's own reconcile; never by the live
    path."""

    if finite_epoch(happened) is None:
        return True
    if happened - now > CLOCK_SKEW_TOLERANCE_S:
        return True
    return now - happened > STALE_AFTER_S


def event_time_text(ts: Any) -> str:
    """The event time for display, in UTC (``2026-10-26 01:02:03 UTC``), or
    「時刻不明」 when the timestamp cannot be read. Never the raw log text."""

    epoch = event_ts_epoch(ts)
    if epoch is None:
        return EVENT_TIME_UNKNOWN
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError, OverflowError, OSError):
        return EVENT_TIME_UNKNOWN


def _display_field(value: Any) -> str:
    """One line of at most DISPLAY_FIELD_MAX characters: whitespace and
    control characters collapsed to single spaces."""

    text = ''.join(' ' if (ch.isspace() or not ch.isprintable()) else ch for ch in str(value or ''))
    text = ' '.join(text.split())
    if len(text) > DISPLAY_FIELD_MAX:
        text = text[:DISPLAY_FIELD_MAX - 1] + '…'
    return text


def _record_epoch(record: Mapping[str, Any]) -> Optional[float]:
    """When the decision's event happened, as far as the record says: its
    ``event_ts``, else the core's ingest stamp, else the record's own ``ts``."""

    epoch = event_ts_epoch(record.get('event_ts'))
    if epoch is None:
        epoch = finite_epoch(record.get('core_ingest_epoch'))
    if epoch is None:
        epoch = event_ts_epoch(record.get('ts'))
    return epoch


def render_p0_alert(entry: Mapping[str, Any]) -> Dict[str, Any]:
    """The wording of one queued alert entry, for the visual or voice channel.

    ``{'text': ..., 'urgent': bool, 'presentation': ...}``. A historical
    (stale reconciled) entry starts with 「過去の判定（<event time>）」 on both
    channels and is never urgent, so an old decision is not presented as a
    current alert. Presentation only: it reads the entry and changes nothing.
    """

    historical = entry.get('presentation') == PRESENTATION_HISTORICAL or entry.get('stale') is True
    action = _display_field(entry.get('action')) or '-'
    target = _display_field(entry.get('target')) or '-'
    reason = _display_field(entry.get('reason'))
    body = f'P0 {action} target={target}' + (f' reason={reason}' if reason else '')
    if historical:
        prefix = f"{HISTORICAL_LABEL}（{event_time_text(entry.get('event_ts'))}）"
        if entry.get('channel') == CHANNEL_VOICE:
            text = f'{prefix}です。現在の警報ではありません。{body}'
        else:
            text = f'【{prefix}】{body}'
        return {'text': text, 'urgent': False, 'presentation': PRESENTATION_HISTORICAL}
    return {'text': body, 'urgent': True, 'presentation': PRESENTATION_CURRENT}


def classify_p0(record: Any) -> str:
    """The P0 basis of one audit-chain decision record, or '' when not P0.

    ``'enforcement:<action>'`` for an ``action_decision`` whose action is
    throttle, redirect or isolate (the OpenCanary redirect record, which
    carries ``redirect: true`` and no ``action``, counts as redirect);
    ``'soc_critical'`` for any other ``action_decision`` whose arbiter trace
    labels the SOC suspicion ``critical``. Anything else is not P0.
    """

    if not isinstance(record, Mapping) or record.get('kind') != 'action_decision':
        return ''
    action = record.get('action')
    if isinstance(action, str) and action in ENFORCEMENT_ACTIONS:
        return f'enforcement:{action}'
    if 'action' not in record and record.get('redirect') is True:
        return 'enforcement:redirect'
    trace = record.get('decision_trace')
    if isinstance(trace, Mapping) and trace.get('suspicion_label') == 'critical':
        return P0_BASIS_SOC_CRITICAL
    return ''


def _boot_id() -> str:
    try:
        return Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip()
    except Exception:
        return ''


_LOCKS: Dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.Lock:
    key = os.path.abspath(str(path))
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class P0AlertQueue:
    """One durable JSONL queue for P0 alerts, visual and voice by ``channel``.

    Each write appends its lines in one write and fsyncs the file (and, for a
    new file, its directory) before returning. The file is opened with
    O_NOFOLLOW and created 0600; writers are serialised by an in-process lock
    and an exclusive flock on a sidecar ``.lock`` file (also O_NOFOLLOW,
    0600). A torn last line (a crash mid-append) is cut off before the next
    append and the cut is recorded in the new lines.
    """

    def __init__(self, path: str | Path, max_entries: int = DEFAULT_MAX_ENTRIES):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_entries = int(max_entries)
        if self.max_entries < len(CHANNELS):
            raise ValueError('max_entries must hold at least one alert per channel')
        # (dev, ino, size) of the file as this instance last left it, with its
        # line count, last seq and eviction total: an append that finds the
        # file unchanged does not read it again.
        self._cache: Optional[tuple] = None
        self.compactions = 0
        # Reads (read_entries) that met a partial trailing line / a complete
        # line that is not a JSON object; both are skipped, never raised.
        self.read_partial_tail_total = 0
        self.read_unparseable_total = 0
        self._counted: Dict[tuple, None] = {}

    @property
    def max_lines(self) -> int:
        return 2 * self.max_entries

    # ------------------------------------------------------------- locking
    class _Locked:
        def __init__(self, path: Path):
            self.path = path
            self.lock = _thread_lock(path)
            self.fd: Optional[int] = None

        def __enter__(self):
            self.lock.acquire()
            try:
                if _fcntl is not None:
                    self.fd = os.open(
                        str(self.path.with_name(self.path.name + '.lock')),
                        os.O_RDWR | os.O_CREAT | _O_NOFOLLOW | _O_CLOEXEC,
                        0o600,
                    )
                    _fcntl.flock(self.fd, _fcntl.LOCK_EX)
            except BaseException:
                if self.fd is not None:
                    os.close(self.fd)
                    self.fd = None
                self.lock.release()
                raise
            return self

        def __exit__(self, *exc):
            try:
                if self.fd is not None:
                    _fcntl.flock(self.fd, _fcntl.LOCK_UN)
                    os.close(self.fd)
                    self.fd = None
            finally:
                self.lock.release()
            return False

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _fsync_fd(fd: int) -> bool:
        try:
            os.fsync(fd)
            return True
        except OSError as exc:
            if exc.errno not in _FSYNC_UNSUPPORTED:
                raise
            return False

    @staticmethod
    def _read_all(fd: int) -> bytes:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
        return b''.join(chunks)

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]

    @staticmethod
    def _parse(lines: Sequence[bytes]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for line in lines:
            try:
                row = json.loads(line)
            except Exception:
                continue
            if isinstance(row, dict):
                out.append(row)
        return out

    @staticmethod
    def _encode(entry: Mapping[str, Any]) -> bytes:
        return json.dumps(entry, ensure_ascii=True, separators=(',', ':')).encode('ascii') + b'\n'

    def _rewrite(self, data: bytes) -> bool:
        """Durably replace the queue with ``data`` (temp, fsync, rename, dir fsync)."""

        tmp = self.path.with_name(f'{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp')
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o600)
            try:
                self._write_all(fd, data)
                synced = self._fsync_fd(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        return fsync_path(self.path.parent) and synced

    def _scan(self, fd: int) -> Dict[str, Any]:
        """Read the whole file: repair a torn tail, count lines, find the last seq."""

        data = self._read_all(fd)
        repaired = 0
        if data and not data.endswith(b'\n'):
            cut = data.rfind(b'\n') + 1
            repaired = len(data) - cut
            os.ftruncate(fd, cut)
            data = data[:cut]
        lines = [ln + b'\n' for ln in data.split(b'\n')[:-1]] if data else []
        seq, evicted_total = 0, 0
        for row in reversed(self._parse(lines)):
            if _int(row.get('seq')):
                seq = row['seq']
                if _int(row.get('overflow_evicted_total')):
                    evicted_total = row['overflow_evicted_total']
                break
        return {'lines': lines, 'line_count': len(lines), 'seq': seq, 'evicted_total': evicted_total, 'repaired': repaired}

    def _compact(self, lines: Sequence[bytes], incoming_alerts: int, seq: int, evicted_total: int, stamp: int) -> tuple:
        """Evict the oldest whole decisions; return (kept lines, alarm entry, evicted alerts)."""

        rows = self._parse(lines)
        alerts = [r for r in rows if r.get('record_type') == RECORD_ALERT]
        order: List[str] = []
        by_decision: Dict[str, List[Dict[str, Any]]] = {}
        for r in alerts:
            key = str(r.get('decision_id') or '') + '\x00' + str(r.get('decision_chain_hash') or '')
            if key not in by_decision:
                by_decision[key] = []
                order.append(key)
            by_decision[key].append(r)
        kept_count = len(alerts)
        evicted_ids: List[str] = []
        evicted_alerts = 0
        while order and kept_count + incoming_alerts > self.max_entries:
            key = order.pop(0)
            group = by_decision.pop(key)
            kept_count -= len(group)
            evicted_alerts += len(group)
            evicted_ids.append(str(group[0].get('decision_id') or ''))
        kept = [self._encode(r) for key in order for r in by_decision[key]]
        kept.sort(key=lambda b: json.loads(b).get('seq') or 0)
        alarm = {
            'schema': QUEUE_SCHEMA,
            'record_type': RECORD_OVERFLOW_ALARM,
            'seq': seq + 1,
            'enqueued_monotonic_ns': stamp,
            'boot_id': _boot_id(),
            'queued_at': iso_utc_now(),
            'overflow_policy': OVERFLOW_POLICY,
            'max_entries': self.max_entries,
            'evicted_alerts': evicted_alerts,
            'evicted_decisions': len(evicted_ids),
            'evicted_decision_ids': evicted_ids[:50],
            'dropped_status_records': len(rows) - len(alerts),
            'overflow_evicted_total': evicted_total + evicted_alerts,
        }
        return kept, alarm, evicted_alerts

    # --------------------------------------------------------------- write
    def _write(self, build: Callable[[int, int, int, int], List[Dict[str, Any]]], incoming_alerts: int) -> Dict[str, Any]:
        """Append the entries ``build(first_seq, stamp, evicted_now, evicted_total)`` returns."""

        with self._Locked(self.path):
            created = not os.path.lexists(self.path)
            fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT | _O_NOFOLLOW | _O_CLOEXEC, 0o600)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise OSError(errno.EINVAL, f'p0_alert_queue_not_a_regular_file:{self.path}')
                if stat.S_IMODE(st.st_mode) & 0o077:
                    os.fchmod(fd, 0o600)
                key = (st.st_dev, st.st_ino, st.st_size)
                if self._cache is not None and self._cache[0] == key:
                    _, line_count, seq, evicted_total = self._cache
                    scan = None
                    repaired = 0
                else:
                    scan = self._scan(fd)
                    line_count, seq, evicted_total, repaired = scan['line_count'], scan['seq'], scan['evicted_total'], scan['repaired']
                stamp = time.monotonic_ns()
                provisional = build(seq + 1, stamp, 0, evicted_total)
                if line_count + len(provisional) > self.max_lines:
                    if scan is None:
                        scan = self._scan(fd)
                    kept, alarm, evicted = self._compact(scan['lines'], incoming_alerts, seq, evicted_total, stamp)
                    entries = build(alarm['seq'] + 1, stamp, evicted, alarm['overflow_evicted_total'])
                    for e in entries:
                        e['torn_tail_repaired_bytes'] = repaired
                    out_lines = kept + [self._encode(alarm)] + [self._encode(e) for e in entries]
                    synced = self._rewrite(b''.join(out_lines))
                    self.compactions += 1
                    entries_written = [alarm] + entries
                    total_lines = len(out_lines)
                else:
                    entries = provisional
                    for e in entries:
                        e['torn_tail_repaired_bytes'] = repaired
                    os.lseek(fd, 0, os.SEEK_END)
                    self._write_all(fd, b''.join(self._encode(e) for e in entries))
                    synced = self._fsync_fd(fd)
                    if created:
                        synced = fsync_path(self.path.parent) and synced
                    entries_written = entries
                    evicted = 0
                    total_lines = line_count + len(entries)
            finally:
                os.close(fd)
            try:
                st = os.stat(self.path, follow_symlinks=False)
                last = entries_written[-1]
                self._cache = ((st.st_dev, st.st_ino, st.st_size), total_lines, last['seq'], last.get('overflow_evicted_total', evicted_total))
            except OSError:
                self._cache = None
        if not synced:
            _LOG.warning('p0 alert queue %s: file system cannot sync; entries written, not durable', self.path)
        return {
            'ok': True,
            'entries': entries,
            'records_written': entries_written,
            'durability': DURABILITY_FSYNCED if synced else DURABILITY_UNSUPPORTED,
            'evicted': evicted,
            'torn_tail_repaired_bytes': repaired,
        }

    def enqueue(self, alerts: Sequence[Mapping[str, Any]], extra: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Append ``alerts`` (one per channel of one decision) durably. Raises on failure."""

        alerts = [dict(a) for a in alerts]
        if not alerts:
            raise ValueError('nothing to enqueue')
        if len(alerts) > self.max_entries:
            raise ValueError('more alerts than the queue holds')

        def build(first_seq: int, stamp: int, evicted: int, evicted_total: int) -> List[Dict[str, Any]]:
            boot_id = _boot_id()
            queued_at = iso_utc_now()
            out = []
            for n, alert in enumerate(alerts):
                entry = dict(alert)
                entry.update(extra or {})
                entry.update(
                    {
                        'schema': QUEUE_SCHEMA,
                        'record_type': RECORD_ALERT,
                        'seq': first_seq + n,
                        'enqueued_monotonic_ns': stamp,
                        'boot_id': boot_id,
                        'queued_at': queued_at,
                        'overflow_policy': OVERFLOW_POLICY,
                        'overflow_evicted': evicted,
                        'overflow_evicted_total': evicted_total,
                    }
                )
                out.append(entry)
            return out

        return self._write(build, len(alerts))

    def append_status(self, status: Mapping[str, Any]) -> Dict[str, Any]:
        """Append one standalone ``relay_status`` record durably. Raises on failure."""

        def build(first_seq: int, stamp: int, evicted: int, evicted_total: int) -> List[Dict[str, Any]]:
            entry = dict(status)
            entry.update(
                {
                    'schema': QUEUE_SCHEMA,
                    'record_type': RECORD_RELAY_STATUS,
                    'seq': first_seq,
                    'enqueued_monotonic_ns': stamp,
                    'boot_id': _boot_id(),
                    'queued_at': iso_utc_now(),
                    'overflow_evicted_total': evicted_total,
                }
            )
            return [entry]

        return self._write(build, 0)

    def read_entries(self) -> List[Dict[str, Any]]:
        """The queue's complete entries, read without the writer lock.

        A reader can run while a writer is appending (or after a crash left a
        torn tail), so the file may end in a partial line. Only
        newline-terminated lines are entries: a trailing partial line is
        skipped and counted in ``read_partial_tail_total``, and a complete
        line that does not parse as a JSON object is skipped and counted in
        ``read_unparseable_total``. Nothing here raises on queue content.
        """

        try:
            fd = os.open(str(self.path), os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
        except FileNotFoundError:
            return []
        try:
            st = os.fstat(fd)
            data = self._read_all(fd)
        finally:
            os.close(fd)
        return self.parse_complete_lines(data, (st.st_dev, st.st_ino))

    def parse_complete_lines(self, data: bytes, file_id: Any = None) -> List[Dict[str, Any]]:
        """Complete lines as entries. Each partial tail and each unparseable
        line is counted once per (file, byte offset), not on every re-read."""

        rows: List[Dict[str, Any]] = []
        offset = 0
        parts = data.split(b'\n')
        for idx, line in enumerate(parts):
            if idx == len(parts) - 1:
                if line:
                    self._count_once('partial', file_id, offset)
                break
            if line:
                try:
                    row = json.loads(line)
                except Exception:
                    row = None
                if isinstance(row, dict):
                    rows.append(row)
                else:
                    self._count_once('unparseable', file_id, offset)
            offset += len(line) + 1
        return rows

    def _count_once(self, kind: str, file_id: Any, offset: int) -> None:
        key = (kind, file_id, offset)
        if key in self._counted:
            return
        self._counted[key] = None
        if len(self._counted) > 4096:
            self._counted.pop(next(iter(self._counted)))
        if kind == 'partial':
            self.read_partial_tail_total += 1
        else:
            self.read_unparseable_total += 1


def build_p0_alerts(record: Mapping[str, Any], basis: str, durability: str, durable_ns: Optional[int],
                    now: Optional[float] = None) -> List[Dict[str, Any]]:
    """One alert per channel, built only from the audit-chain decision record.

    A decision record that is in the chain but not durable (its fsync failed,
    or the file system cannot sync) is still alerted -- a P0 must not be
    suppressed by a disk error -- but its entries say so explicitly:
    ``decision_record_durable`` is false and ``decision_record_durability``
    names why. Only ``fsynced`` (or a reconciled record whose audit file the
    relay fsynced itself) counts as durable.
    """

    trace = record.get('decision_trace') if isinstance(record.get('decision_trace'), Mapping) else {}
    evidence = record.get('evidence_ids') if isinstance(record.get('evidence_ids'), list) else []
    action = record.get('action') if isinstance(record.get('action'), str) else ('redirect' if record.get('redirect') is True else '')
    chain_hash = str(record.get('chain_hash') or '')
    base = {
        'decision_id': str(record.get('trace_id') or ''),
        'decision_chain_hash': chain_hash,
        'audit_cursor_chain_hash': chain_hash,
        'decision_source': str(record.get('source') or ''),
        'decision_ts': str(record.get('ts') or ''),
        'decision_record_durability': str(durability or ''),
        'decision_record_durable': durability in (DURABILITY_FSYNCED, DURABILITY_RECONCILED_FSYNCED),
        'decision_durable_monotonic_ns': durable_ns if _int(durable_ns) else None,
        'p0_class': P0_CLASS,
        'p0_basis': basis,
        'p0_rule': P0_RULE,
        'action': action,
        'reason': str(record.get('reason') or ''),
        'suspicion_label': str(trace.get('suspicion_label') or ''),
        'target': str(record.get('target_ip') or record.get('target') or ''),
        'evidence_ids': [str(x) for x in evidence if str(x)],
        # What the deciding component did with the decision, as its record
        # says (the Rust core: applied, dry_run, policy_gated, ...); empty
        # when the record does not say. Copied, never inferred.
        'effective_action': str(record.get('effective_action') or ''),
        'enforcement_mode': str(record.get('enforcement_mode') or ''),
        'enforcement_result': str(record.get('enforcement_result') or ''),
        # Not a live alert: recorded by a startup reconcile (the core
        # decision recorder's, or this relay's own from the chain). The
        # event's own time says how old it is.
        'reconciled': record.get('recorded_by') == 'startup_reconcile'
        or durability in (DURABILITY_RECONCILED, DURABILITY_RECONCILED_FSYNCED),
        'recorded_by': str(record.get('recorded_by') or ''),
        'event_ts': str(record.get('event_ts') or ''),
    }
    # A reconciled decision older than the core's lease (Edge#462 item 5): a
    # past decision, presented as one -- never as a current alert.
    stale = base['reconciled'] is True and record.get('reconcile_stale') is True
    if not stale and durability in (DURABILITY_RECONCILED, DURABILITY_RECONCILED_FSYNCED):
        # Replayed by this relay's own reconcile from the chain (in the chain,
        # not in the queue): the record may be far older than the lease. Its
        # age is read from the record; a record whose time cannot be read is
        # treated as past. Never applied to the live path.
        stale = is_past_decision(_record_epoch(record), time.time() if now is None else now)
    base['stale'] = stale
    base['presentation'] = PRESENTATION_HISTORICAL if stale else PRESENTATION_CURRENT
    out = []
    for channel in CHANNELS:
        entry = dict(base, channel=channel)
        rendered = render_p0_alert(entry)
        entry['display_text'] = rendered['text']
        if channel == CHANNEL_VOICE:
            entry['voice_urgent'] = rendered['urgent']
        out.append(entry)
    return out


DURABILITY_RECONCILED_FSYNCED = 'reconciled_from_chain_fsynced'
DURABILITY_RECONCILED = 'reconciled_from_chain'


class P0AlertRelay:
    """Turns durable audit-chain decision records into P0 queue entries.

    :meth:`on_durable_record` is the audit logger's listener: it never blocks
    and never raises; it puts the record on a bounded hand-off. The relay
    thread first reconciles (see :meth:`reconcile`), then classifies and
    enqueues. Losses are written as standalone ``relay_status`` records as
    soon as the relay sees them, not only on the next P0.
    """

    def __init__(
        self,
        alert_queue: P0AlertQueue,
        *,
        audit_path: Optional[str | Path] = None,
        audit_logger: Any = None,
        max_pending: int = 1024,
        max_reconcile: int = DEFAULT_MAX_RECONCILE,
        on_relayed: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.queue = alert_queue
        self.audit_path = Path(audit_path) if audit_path is not None else None
        self.audit_logger = audit_logger
        self.max_reconcile = int(max_reconcile)
        self._pending: _queue_mod.Queue = _queue_mod.Queue(maxsize=max(1, int(max_pending)))
        self.on_relayed = on_relayed
        self._counters_lock = threading.Lock()
        self.handoff_dropped_total = 0
        self.enqueue_failed_total = 0
        self.enqueued_total = 0
        self.reconciled_total = 0
        self.reconcile_skipped_total = 0
        self._reported: tuple = (0, 0, 0)
        self._seen: Dict[str, None] = {}
        self._stop = threading.Event()
        self.ready = threading.Event()
        self._outstanding = 0  # handed to the relay, not yet relayed
        # Chain hash up to which reconcile reads (set by attach to the
        # listener's registration point); None reads the whole chain.
        self.reconcile_until: Optional[str] = None
        self._thread: Optional[threading.Thread] = None

    # Audit logger listener. Must stay cheap and must not raise.
    def on_durable_record(self, record: Dict[str, Any], durability: str, durable_ns: int) -> None:
        try:
            if not isinstance(record, dict) or record.get('kind') != 'action_decision':
                return
            with self._counters_lock:
                self._outstanding += 1
            self._pending.put_nowait((record, durability, durable_ns))
        except _queue_mod.Full:
            with self._counters_lock:
                self._outstanding -= 1
                self.handoff_dropped_total += 1
            _LOG.error('p0 alert hand-off full; decision %s not alerted', record.get('trace_id'))
        except Exception:  # pragma: no cover - defensive
            pass

    def metrics(self) -> Dict[str, int]:
        with self._counters_lock:
            out = {
                'enqueued_total': self.enqueued_total,
                'enqueue_failed_total': self.enqueue_failed_total,
                'handoff_dropped_total': self.handoff_dropped_total,
                'reconciled_total': self.reconciled_total,
                'reconcile_skipped_total': self.reconcile_skipped_total,
            }
        out['audit_listener_handoff_dropped_total'] = int(getattr(self.audit_logger, 'durable_handoff_dropped_total', 0) or 0)
        out['queue_read_partial_tail_total'] = int(getattr(self.queue, 'read_partial_tail_total', 0) or 0)
        out['queue_read_unparseable_total'] = int(getattr(self.queue, 'read_unparseable_total', 0) or 0)
        return out

    def _remember(self, chain_hash: str) -> bool:
        """False if this chain hash was already relayed by this relay."""

        if not chain_hash:
            return True
        if chain_hash in self._seen:
            return False
        self._seen[chain_hash] = None
        if len(self._seen) > 8192:
            self._seen.pop(next(iter(self._seen)))
        return True

    def relay(self, record: Mapping[str, Any], durability: str = '', durable_ns: Optional[int] = None) -> Dict[str, Any]:
        """Classify one decision record and, if P0, enqueue it on every channel."""

        basis = classify_p0(record)
        decision_id = str(record.get('trace_id') or '') if isinstance(record, Mapping) else ''
        if not basis:
            return self._report(decision_id, {'ok': True, 'p0': False, 'decision_id': decision_id})
        if not self._remember(str(record.get('chain_hash') or '')):
            return self._report(decision_id, {'ok': True, 'p0': True, 'duplicate': True, 'decision_id': decision_id})
        with self._counters_lock:
            extra = {
                'relay_handoff_dropped_total': self.handoff_dropped_total,
                'relay_enqueue_failed_total': self.enqueue_failed_total,
            }
        try:
            result = self.queue.enqueue(build_p0_alerts(record, basis, durability, durable_ns), extra)
        except Exception as exc:
            with self._counters_lock:
                self.enqueue_failed_total += 1
            self._seen.pop(str(record.get('chain_hash') or ''), None)
            _LOG.error('p0 alert for decision %s not enqueued: %s', decision_id, exc)
            result = {'ok': False, 'error': str(exc)}
        else:
            with self._counters_lock:
                self.enqueued_total += 1
        return self._report(decision_id, dict(result, p0=True, decision_id=decision_id, p0_basis=basis))

    def _report(self, decision_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
        # Called once per relayed record, after any enqueue (and its fsync)
        # has returned. Observation only; its failure is contained.
        if self.on_relayed is not None:
            try:
                self.on_relayed(decision_id, result)
            except Exception:
                pass
        return result

    # ------------------------------------------------------------ reconcile
    def _queue_cursor_and_hashes(self) -> tuple:
        """The queue's last cursor, and the chain hashes it already alerts on."""

        cursor = ''
        hashes: List[str] = []
        for row in self.queue.read_entries():
            c = row.get('audit_cursor_chain_hash')
            if isinstance(c, str) and c:
                cursor = c
            h = row.get('decision_chain_hash')
            if row.get('record_type') == RECORD_ALERT and isinstance(h, str) and h:
                hashes.append(h)
        return cursor, hashes

    def reconcile(self) -> Dict[str, Any]:
        """Enqueue P0 decisions in the audit chain that the queue does not have.

        The cursor is the last ``audit_cursor_chain_hash`` in the queue (every
        alert and every relay_status record carries one):

        * ``cursor_found`` -- the P0 records after the cursor were written
          while no relay was attached (a crash, a restart);
        * ``fresh_queue`` -- the queue has no cursor: every P0 record in the
          chain is a candidate;
        * ``cursor_not_in_chain`` -- the chain no longer has the cursor (it
          was rotated or replaced): which records were missed cannot be told,
          so nothing is replayed; the P0 records in the chain the queue does
          not alert on are counted as ``unreconcilable``.
        * ``registration_cut_not_found`` -- the chain no longer has the record
          the listener was registered after (it was replaced between attach
          and this read): nothing is replayed, and the P0 records in the
          chain as read are counted as ``unreconcilable``.

        Candidates are replayed newest first up to ``max_reconcile``, the rest
        counted as ``reconcile_skipped``. Decisions the queue already alerts
        on (by chain hash) are never enqueued again. A relay_status record
        with the outcome is written, and its cursor (the chain's tail as read)
        is where the next start resumes.
        """

        status: Dict[str, Any] = {
            'event': 'started', 'reconcile': 'no_audit_path', 'cursor_found': False,
            'reconciled': 0, 'reconcile_skipped': 0, 'unreconcilable': 0,
        }
        tail = ''
        if self.audit_path is not None:
            cursor, queued = self._queue_cursor_and_hashes()
            for h in queued:
                self._remember(h)
            lines: List[bytes] = []
            synced = False
            try:
                fd = os.open(str(self.audit_path), os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
            except FileNotFoundError:
                fd = None
            if fd is not None:
                try:
                    # Make what is read durable before alerting on it; the
                    # entries say whether that fsync happened.
                    synced = P0AlertQueue._fsync_fd(fd)
                    data = P0AlertQueue._read_all(fd)
                finally:
                    os.close(fd)
                lines = data.split(b'\n')[:-1]
            rows = P0AlertQueue._parse(lines)
            cut_missing_p0 = None
            if self.reconcile_until is not None:
                # Records after the listener's registration point reach the
                # relay through the listener (with their durable stamp); the
                # reconcile covers only what was written before it.
                cut = 0
                if self.reconcile_until:
                    cut = None
                    for idx, row in enumerate(rows):
                        if row.get('chain_hash') == self.reconcile_until:
                            cut = idx + 1
                    if cut is None:
                        # The chain was replaced between registration and this
                        # read: what was before the registration cannot be
                        # told from what the listener delivers. Read nothing
                        # and say so.
                        cut_missing_p0 = sum(1 for r in rows if classify_p0(r))
                        cut = 0
                rows = rows[:cut]
            if rows:
                tail = str(rows[-1].get('chain_hash') or '')
            start = None
            if cursor:
                for idx, row in enumerate(rows):
                    if row.get('chain_hash') == cursor:
                        start = idx + 1
            fresh = [r for r in rows if classify_p0(r) and str(r.get('chain_hash') or '') not in self._seen]
            if cut_missing_p0 is not None:
                status['reconcile'] = 'registration_cut_not_found'
                status['unreconcilable'] = cut_missing_p0
                missed = []
            elif start is not None:
                status.update(reconcile='cursor_found', cursor_found=True)
                missed = [r for r in rows[start:] if classify_p0(r) and str(r.get('chain_hash') or '') not in self._seen]
            elif not cursor:
                status['reconcile'] = 'fresh_queue'
                missed = fresh
            else:
                status['reconcile'] = 'cursor_not_in_chain'
                status['unreconcilable'] = len(fresh)
                missed = []
            skipped = max(0, len(missed) - self.max_reconcile)
            durability = DURABILITY_RECONCILED_FSYNCED if synced else DURABILITY_RECONCILED
            done = 0
            for r in missed[skipped:]:
                if self.relay(r, durability, None).get('ok'):
                    done += 1
            with self._counters_lock:
                self.reconciled_total += done
                self.reconcile_skipped_total += skipped
            status.update(reconciled=done, reconcile_skipped=skipped)
        status['audit_cursor_chain_hash'] = tail
        self._write_status(status)
        return status

    def pending(self) -> int:
        """Decision records handed to the relay and not yet relayed."""

        with self._counters_lock:
            return self._outstanding

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Wait until every record handed to the relay so far is relayed."""

        deadline = time.monotonic() + timeout
        while self.pending() and time.monotonic() < deadline:
            time.sleep(0.005)
        return not self.pending()

    def _write_status(self, status: Dict[str, Any]) -> None:
        metrics = self.metrics()
        record = dict(status)
        record.update(metrics)
        if not record.get('audit_cursor_chain_hash'):
            record.pop('audit_cursor_chain_hash', None)
        try:
            self.queue.append_status(record)
            self._reported = (metrics['handoff_dropped_total'], metrics['enqueue_failed_total'], metrics['audit_listener_handoff_dropped_total'])
        except Exception as exc:
            _LOG.error('p0 alert relay status not written: %s', exc)

    def _report_losses(self) -> None:
        m = self.metrics()
        now = (m['handoff_dropped_total'], m['enqueue_failed_total'], m['audit_listener_handoff_dropped_total'])
        if now != self._reported:
            self._write_status({'event': 'loss'})

    def _run(self) -> None:
        try:
            self.reconcile()
        except Exception as exc:
            _LOG.error('p0 alert relay reconcile failed: %s', exc)
        finally:
            self.ready.set()
        while not self._stop.is_set() or not self._pending.empty():
            try:
                item = self._pending.get(timeout=0.2)
            except _queue_mod.Empty:
                self._report_losses()
                continue
            try:
                self.relay(*item)
            except Exception as exc:  # pragma: no cover - relay() does not raise
                _LOG.error('p0 alert relay error: %s', exc)
            finally:
                with self._counters_lock:
                    self._outstanding -= 1
            self._report_losses()

    def start(self) -> 'P0AlertRelay':
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name='p0-alert-relay', daemon=True)
            self._thread.start()
        return self

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)


def attach_p0_alert_relay(audit_logger: Any, queue_path: str | Path, **kwargs: Any) -> P0AlertRelay:
    """Wire decision record -> P0 alert -> durable queue onto an audit logger.

    Idempotent per logger: a logger that already has a relay keeps it.
    ``kwargs`` go to :class:`P0AlertRelay` (``max_pending``, ``max_reconcile``,
    ``on_relayed``); ``max_entries`` goes to :class:`P0AlertQueue`. The relay
    listener is registered before the relay starts, so nothing written after
    this call is missed; the relay's startup reconcile covers what was
    written before it.
    """

    existing = getattr(audit_logger, '_p0_alert_relay', None)
    if isinstance(existing, P0AlertRelay):
        return existing
    max_entries = int(kwargs.pop('max_entries', DEFAULT_MAX_ENTRIES))
    relay = P0AlertRelay(
        P0AlertQueue(queue_path, max_entries=max_entries),
        audit_path=getattr(audit_logger, 'path', None),
        audit_logger=audit_logger,
        **kwargs,
    )
    registered_at = audit_logger.add_durable_listener(relay.on_durable_record)
    relay.reconcile_until = registered_at if isinstance(registered_at, str) else None
    audit_logger._p0_alert_relay = relay
    return relay.start()
