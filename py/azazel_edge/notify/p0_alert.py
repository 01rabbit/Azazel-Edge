"""P0 alert path: audit-chain decision record -> P0 alert -> durable queue.

Owner decisions on Edge#414 (2026-10-25):

* **P0** is an enforcement-bearing decision (throttle, redirect, isolate) or a
  decision taken on a SOC signal labelled ``critical``. The notify layer builds
  the alert from the decision's audit-chain record; :func:`classify_p0` is a
  deterministic function of that record (no model, no lookup, no clock).
* **Queue** (option A): one durable JSONL file in the Python notify layer.
  Visual and voice are the ``channel`` field of the entries. Rendering and
  speaking are downstream of the queue and are not done here.

Observation and notification only. Nothing here decides, enforces, approves or
changes a decision, and nothing reads the queue back into the decision path.
The audit logger hands each durable decision record to
:meth:`P0AlertRelay.on_durable_record`, which only puts it on a bounded
in-memory hand-off and returns; the relay's own thread classifies and
enqueues. A full hand-off, a failed enqueue or a broken queue file is counted
and logged, and never raised into, delays or alters the decision path.
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

# Bounded queue. When an enqueue would take it past max_entries, the OLDEST
# entries are evicted (never the new P0 alert), and the new entries record how
# many were evicted now and in total, so the loss is on disk, not silent.
DEFAULT_MAX_ENTRIES = 1000
OVERFLOW_POLICY = 'evict_oldest_record_counts'

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


class P0AlertQueue:
    """One durable JSONL queue for P0 alerts, visual and voice by ``channel``.

    Each enqueue appends all of its entries in one write and fsyncs the file
    (and, for a new file, its directory) before returning. The file is opened
    with O_NOFOLLOW and created 0600; writers are serialised by an in-process
    lock and an exclusive flock on a sidecar ``.lock`` file (also O_NOFOLLOW,
    0600). A torn last line (a crash mid-append) is cut off before the next
    append and the cut is recorded in the new entries.
    """

    def __init__(self, path: str | Path, max_entries: int = DEFAULT_MAX_ENTRIES):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_entries = int(max_entries)
        if self.max_entries < len(CHANNELS):
            raise ValueError('max_entries must hold at least one alert per channel')

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

    def _rewrite(self, lines: Sequence[bytes]) -> bool:
        """Durably replace the queue with ``lines`` (temp, fsync, rename, dir fsync)."""

        tmp = self.path.with_name(f'{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp')
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o600)
            try:
                self._write_all(fd, b''.join(lines))
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

    # ------------------------------------------------------------- enqueue
    def enqueue(self, alerts: Sequence[Mapping[str, Any]], extra: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Append ``alerts`` (one per channel) durably. Raises on failure."""

        alerts = [dict(a) for a in alerts]
        if not alerts:
            raise ValueError('nothing to enqueue')
        if len(alerts) > self.max_entries:
            raise ValueError('more alerts than the queue holds')
        with self._Locked(self.path):
            created = not os.path.lexists(self.path)
            fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT | _O_NOFOLLOW | _O_CLOEXEC, 0o600)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise OSError(errno.EINVAL, f'p0_alert_queue_not_a_regular_file:{self.path}')
                if stat.S_IMODE(st.st_mode) & 0o077:
                    os.fchmod(fd, 0o600)
                data = self._read_all(fd)
                repaired = 0
                if data and not data.endswith(b'\n'):
                    cut = data.rfind(b'\n') + 1
                    repaired = len(data) - cut
                    os.ftruncate(fd, cut)
                    data = data[:cut]
                lines = [ln + b'\n' for ln in data.split(b'\n')[:-1]] if data else []
                parsed = self._parse(lines)
                last = parsed[-1] if parsed else {}
                seq = int(last.get('seq') or 0) if isinstance(last.get('seq'), int) else 0
                evicted_total = int(last.get('overflow_evicted_total') or 0) if isinstance(last.get('overflow_evicted_total'), int) else 0
                evict = max(0, len(lines) + len(alerts) - self.max_entries)
                stamp = time.monotonic_ns()
                queued_at = iso_utc_now()
                boot_id = _boot_id()
                new_lines: List[bytes] = []
                entries: List[Dict[str, Any]] = []
                for alert in alerts:
                    seq += 1
                    entry = dict(alert)
                    entry.update(extra or {})
                    entry.update(
                        {
                            'schema': QUEUE_SCHEMA,
                            'seq': seq,
                            'enqueued_monotonic_ns': stamp,
                            'boot_id': boot_id,
                            'queued_at': queued_at,
                            'overflow_policy': OVERFLOW_POLICY,
                            'overflow_evicted': evict,
                            'overflow_evicted_total': evicted_total + evict,
                            'torn_tail_repaired_bytes': repaired,
                        }
                    )
                    entries.append(entry)
                    new_lines.append(json.dumps(entry, ensure_ascii=True, separators=(',', ':')).encode('ascii') + b'\n')
                if evict:
                    synced = self._rewrite(lines[evict:] + new_lines)
                else:
                    os.lseek(fd, 0, os.SEEK_END)
                    self._write_all(fd, b''.join(new_lines))
                    synced = self._fsync_fd(fd)
                    if created:
                        synced = fsync_path(self.path.parent) and synced
            finally:
                os.close(fd)
        if not synced:
            _LOG.warning('p0 alert queue %s: file system cannot sync; entries written, not durable', self.path)
        return {
            'ok': True,
            'entries': entries,
            'durability': DURABILITY_FSYNCED if synced else DURABILITY_UNSUPPORTED,
            'evicted': evict,
            'torn_tail_repaired_bytes': repaired,
        }

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
    """One alert per channel, built only from the audit-chain decision record."""

    trace = record.get('decision_trace') if isinstance(record.get('decision_trace'), Mapping) else {}
    evidence = record.get('evidence_ids') if isinstance(record.get('evidence_ids'), list) else []
    action = record.get('action') if isinstance(record.get('action'), str) else ('redirect' if record.get('redirect') is True else '')
    base = {
        'decision_id': str(record.get('trace_id') or ''),
        'decision_chain_hash': str(record.get('chain_hash') or ''),
        'decision_source': str(record.get('source') or ''),
        'decision_ts': str(record.get('ts') or ''),
        'decision_record_durability': str(durability or ''),
        'decision_durable_monotonic_ns': durable_ns if isinstance(durable_ns, int) and not isinstance(durable_ns, bool) else None,
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


class P0AlertRelay:
    """Turns durable audit-chain decision records into P0 queue entries.

    :meth:`on_durable_record` is the audit logger's listener: it never blocks
    and never raises; it puts the record on a bounded hand-off (overflow is
    counted). The relay thread classifies and enqueues. The counters of lost
    alerts ride along on every later queue entry.
    """

    def __init__(
        self,
        alert_queue: P0AlertQueue,
        *,
        max_pending: int = 1024,
        on_relayed: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.queue = alert_queue
        self._pending: _queue_mod.Queue = _queue_mod.Queue(maxsize=max(1, int(max_pending)))
        self.on_relayed = on_relayed
        self._counters_lock = threading.Lock()
        self.handoff_dropped_total = 0
        self.enqueue_failed_total = 0
        self.enqueued_total = 0
        self._stop = threading.Event()
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

    def relay(self, record: Mapping[str, Any], durability: str = '', durable_ns: Optional[int] = None) -> Dict[str, Any]:
        """Classify one decision record and, if P0, enqueue it on every channel."""

        basis = classify_p0(record)
        decision_id = str(record.get('trace_id') or '') if isinstance(record, Mapping) else ''
        if not basis:
            return self._report(decision_id, {'ok': True, 'p0': False, 'decision_id': decision_id})
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

    def _run(self) -> None:
        while not self._stop.is_set() or not self._pending.empty():
            try:
                item = self._pending.get(timeout=0.2)
            except _queue_mod.Empty:
                continue
            try:
                self.relay(*item)
            except Exception as exc:  # pragma: no cover - relay() does not raise
                _LOG.error('p0 alert relay error: %s', exc)

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

    ``kwargs`` go to :class:`P0AlertRelay` (``max_pending``, ``on_relayed``);
    ``max_entries`` goes to :class:`P0AlertQueue`.
    """

    max_entries = int(kwargs.pop('max_entries', DEFAULT_MAX_ENTRIES))
    relay = P0AlertRelay(P0AlertQueue(queue_path, max_entries=max_entries), **kwargs)
    audit_logger.add_durable_listener(relay.on_durable_record)
    return relay.start()
