"""P0 alert path: audit-chain decision record -> P0 alert -> durable queue.

Owner decisions on Edge#414 (2026-10-25):

* **P0** is an enforcement-bearing decision (throttle, redirect, isolate) or a
  decision taken on a SOC signal labelled ``critical``. The notify layer builds
  the alert from the decision's audit-chain record; :func:`classify_p0` is a
  deterministic function of that record (no model, no lookup, no clock).
* **Queue** (option A): one durable JSONL file in the Python notify layer.
  Visual and voice are the ``channel`` field of the alert entries. Rendering
  and speaking are downstream of the queue and are not done here.

Observation and notification only. Nothing here decides, enforces, approves or
changes a decision, and nothing reads the queue back into the decision path.
The audit logger hands each durable decision record to its listeners from a
dispatcher thread, never from the writer (see
``P0AuditLogger.add_durable_listener``); :meth:`P0AlertRelay.on_durable_record`
only puts it on a bounded hand-off. The relay's own thread classifies and
enqueues. Losses (a full hand-off, a failed enqueue) are counted and written
to the queue as standalone ``relay_status`` records; they never reach,
delay or alter the decision path.

Where the path is attached: ``OpenCanaryRedirectController`` attaches it to
its decision logger. The Rust core's throttle/redirect/isolate decisions are
not written as ``action_decision`` records through ``P0AuditLogger`` at all,
so they do not reach this path (Edge#412 decides which path is
authoritative); SO-03 keeps the blocking gap
``SO03-P0-RELAY-NOT-WIRED-FOR-CORE-DECISIONS`` until that lands.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import queue as _queue_mod
import stat
import threading
import time
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
        try:
            fd = os.open(str(self.path), os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
        except FileNotFoundError:
            return []
        try:
            data = self._read_all(fd)
        finally:
            os.close(fd)
        return self._parse([ln for ln in data.split(b'\n') if ln])


def build_p0_alerts(record: Mapping[str, Any], basis: str, durability: str, durable_ns: Optional[int]) -> List[Dict[str, Any]]:
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
    }
    return [dict(base, channel=channel) for channel in CHANNELS]


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
        self._thread: Optional[threading.Thread] = None

    # Audit logger listener. Must stay cheap and must not raise.
    def on_durable_record(self, record: Dict[str, Any], durability: str, durable_ns: int) -> None:
        try:
            if not isinstance(record, dict) or record.get('kind') != 'action_decision':
                return
            self._pending.put_nowait((record, durability, durable_ns))
        except _queue_mod.Full:
            with self._counters_lock:
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
    def _queue_cursor(self) -> str:
        for row in reversed(self.queue.read_entries()):
            cursor = row.get('audit_cursor_chain_hash')
            if isinstance(cursor, str) and cursor:
                return cursor
        return ''

    def reconcile(self) -> Dict[str, Any]:
        """Enqueue P0 decisions the chain has after the queue's cursor.

        The cursor is the last ``audit_cursor_chain_hash`` in the queue (every
        alert and every relay_status record carries one). Records after it in
        the audit chain were written while no relay was attached (a crash, a
        restart); the newest ``max_reconcile`` P0 ones are enqueued now, the
        rest counted. With no cursor, or one the chain no longer has (a new
        queue, a rotated chain), nothing is replayed: the status record sets
        the cursor for the next start. Either way a relay_status record is
        written.
        """

        status: Dict[str, Any] = {'event': 'started', 'cursor_found': False, 'reconciled': 0, 'reconcile_skipped': 0}
        tail = ''
        if self.audit_path is not None:
            cursor = self._queue_cursor()
            lines: List[bytes] = []
            try:
                fd = os.open(str(self.audit_path), os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
            except FileNotFoundError:
                fd = None
            if fd is not None:
                try:
                    synced = P0AlertQueue._fsync_fd(fd)
                    data = P0AlertQueue._read_all(fd)
                finally:
                    os.close(fd)
                lines = data.split(b'\n')[:-1]
            else:
                synced = False
            rows = P0AlertQueue._parse(lines)
            if rows:
                tail = str(rows[-1].get('chain_hash') or '')
            start = None
            if cursor:
                for idx, row in enumerate(rows):
                    if row.get('chain_hash') == cursor:
                        start = idx + 1
            if start is not None:
                status['cursor_found'] = True
                missed = [r for r in rows[start:] if classify_p0(r)]
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
    audit_logger.add_durable_listener(relay.on_durable_record)
    audit_logger._p0_alert_relay = relay
    return relay.start()
