from __future__ import annotations

import collections
import errno
import json
import hashlib
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .segments import chain_id_of, read_chain, segment_path

_LOG = logging.getLogger(__name__)


VALID_KINDS = {
    'event_receive',
    'evaluation',
    'action_decision',
    'notification',
    'ai_assist',
    'triage_session_started',
    'triage_step_answered',
    'triage_state_changed',
    'triage_runbook_proposed',
    'triage_handoff',
    'triage_completed',
}

# Kinds whose record must be on disk when log() returns: the arbiter's decision
# and the alert enqueued for it (Edge#414, SO-03: "the decision record is
# durable" and "a durable record naming the decision id"). These are written
# once per decision, not per event, so the fsync cost stays off the event path.
# The chain format is unchanged; only when log() returns is.
DURABLE_KINDS = frozenset({'action_decision', 'notification'})

# Bound of the hand-off from log() to the durable-record listeners.
DURABLE_HANDOFF_MAX = 4096
# How many chain hashes of durable records the hand-off dropped are kept for
# listeners to recover (see dropped_durable_since).
DURABLE_DROPPED_KEEP = 4096


# A file system that cannot sync at all answers fsync with one of these;
# there is nothing more to do there. Any other error (EIO, ENOSPC) raises.
_FSYNC_UNSUPPORTED = frozenset({errno.EINVAL, getattr(errno, 'ENOTSUP', errno.EINVAL), getattr(errno, 'EOPNOTSUPP', errno.EINVAL)})


# Durability of one log() call, as log_reporting_durability() returns it.
DURABILITY_FSYNCED = 'fsynced'
DURABILITY_UNSUPPORTED = 'fsync_unsupported'
DURABILITY_NOT_REQUIRED = 'not_required'


class AuditDurabilityError(OSError):
    """The record was appended to the chain but could not be made durable."""


def fsync_path(path: Path) -> bool:
    """fsync one path. True when synced; False when the file system cannot
    sync at all (logged at warning); any other error raises."""

    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
        return True
    except OSError as exc:
        if exc.errno not in _FSYNC_UNSUPPORTED:
            raise
        _LOG.warning('fsync_unsupported path=%s errno=%s: record is written but not durable', path, exc.errno)
        return False
    finally:
        os.close(fd)


class P0AuditLogger:
    def __init__(self, path: str | Path, *, max_bytes: Optional[int] = None, keep: int = 1):
        """``max_bytes`` (None: never) rotates the file on a chain boundary
        once it reaches that size, keeping one rotated file ``<name>.1``
        (Edge#462 item 1; see ``azazel_edge.audit.segments``). The chain
        continues across files: the first record of a new file has
        ``chain_prev`` = the last record of the previous one and carries
        ``chain_id``. Only ``keep=1`` is supported: with one rotated file a
        crash at any point of the rotation leaves either the active file or
        ``.1`` holding the chain's last record, so the chain is never
        restarted by a crash."""

        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if max_bytes is not None and int(max_bytes) <= 0:
            raise ValueError('max_bytes must be positive')
        if int(keep) != 1:
            raise ValueError('only keep=1 is supported')
        self.max_bytes = None if max_bytes is None else int(max_bytes)
        self.keep = int(keep)
        self.rotated_total = 0
        self.rotate_failed_total = 0
        self._lock = threading.Lock()
        self._last_chain_hash = self._read_last_chain_hash()
        self._chain_id = self._read_chain_id() if self._last_chain_hash else ''
        # Durable-kind records written where the file system could not sync.
        self.fsync_unsupported_count = 0
        # Observers of durable-kind records (Edge#414, SO-03: the P0 alert
        # path). See add_durable_listener.
        self._durable_listeners: list = []
        self._durable_handoff: collections.deque = collections.deque()
        self._durable_handoff_max = DURABLE_HANDOFF_MAX
        self._durable_seq = 0
        self._durable_wakeup = threading.Condition(threading.Lock())
        self._durable_dispatcher: threading.Thread | None = None
        self._durable_delivered_seq = 0
        self._durable_handed = 0
        self._durable_delivered = 0
        # Durable-kind records not handed to listeners because the hand-off
        # was full (listeners slower than the writers).
        self.durable_handoff_dropped_total = 0
        # (sequence, chain hash) of those records, the newest kept, so a
        # listener can recover them from the chain (Edge#462 item 4).
        self._durable_dropped: collections.deque = collections.deque(maxlen=DURABLE_DROPPED_KEEP)

    @property
    def chain_id(self) -> str:
        """Identity of this logger's chain (``segments.chain_id_of`` its
        oldest record); '' until the first record."""

        with self._lock:
            return self._chain_id

    def dropped_durable_since(self, seq: int) -> Tuple[int, List[str]]:
        """(newest sequence, chain hashes) of the durable records the
        listener hand-off dropped after ``seq``. Observation only."""

        with self._lock:
            items = [(s, h) for s, h in self._durable_dropped if s > seq]
            newest = self._durable_dropped[-1][0] if self._durable_dropped else seq
        return max(newest, seq), [h for _, h in items]

    def add_durable_listener(self, listener: Any) -> str:
        """Call ``listener(record_copy, durability, monotonic_ns)`` for each
        durable-kind record written after this call, and return the chain
        hash of the last record written before it ('' for an empty chain).

        * ``monotonic_ns`` is CLOCK_MONOTONIC read right after the fsync
          returned; ``durability`` is fsynced, fsync_unsupported or
          fsync_failed (the record is in the chain but not durable).
        * Writers never wait for a listener. Under the audit lock log() only
          appends (sequence number, the line as written, durability, stamp)
          to a bounded hand-off: O(1), no copy, no call. A dispatcher thread
          parses each line into a fresh dict outside the lock and calls the
          listeners in chain order (sequence order). If the hand-off is full
          the record is not handed on and durable_handoff_dropped_total
          counts it.
        * A listener's Exception is logged and contained. KeyboardInterrupt
          and SystemExit are not swallowed: they end the dispatcher thread
          (never a writer), so shutdown is not hidden; later records are then
          not handed to listeners.
        * Observation only: what log() writes, returns or raises is the same
          with or without listeners.
        """

        # Registered under the audit lock: every record after the returned
        # chain hash reaches this listener; every record up to it is already
        # in the file. A caller that also reads the file (the P0 relay's
        # startup reconcile) reads only up to it, so nothing is seen twice.
        with self._lock:
            self._durable_listeners.append(listener)
            registered_at = self._last_chain_hash
        with self._durable_wakeup:
            if self._durable_dispatcher is None or not self._durable_dispatcher.is_alive():
                self._durable_dispatcher = threading.Thread(
                    target=self._dispatch_durable, name='audit-durable-dispatch', daemon=True
                )
                self._durable_dispatcher.start()
        return registered_at

    def _handoff_durable(self, line: str, durability: str, chain_hash: str = '') -> None:
        # Called under self._lock: O(1) only.
        if not self._durable_listeners:
            return
        stamp = time.monotonic_ns()
        self._durable_seq += 1
        if len(self._durable_handoff) >= self._durable_handoff_max:
            self.durable_handoff_dropped_total += 1
            if chain_hash:
                self._durable_dropped.append((self._durable_seq, chain_hash))
            return
        self._durable_handoff.append((self._durable_seq, line, durability, stamp))
        self._durable_handed += 1
        with self._durable_wakeup:
            self._durable_wakeup.notify()

    def _dispatch_durable(self) -> None:
        while True:
            with self._durable_wakeup:
                while not self._durable_handoff:
                    self._durable_wakeup.wait(timeout=1.0)
            seq, line, durability, stamp = self._durable_handoff.popleft()
            for listener in list(self._durable_listeners):
                try:
                    listener(json.loads(line), durability, stamp)
                except Exception:
                    _LOG.exception('durable-record listener failed; the record is unaffected')
            self._durable_delivered_seq = seq
            self._durable_delivered += 1

    def wait_durable_listeners(self, timeout: float = 5.0) -> bool:
        """Wait until every record handed off so far has been delivered."""

        target = self._durable_handed
        deadline = time.monotonic() + timeout
        while self._durable_delivered < target and time.monotonic() < deadline:
            time.sleep(0.005)
        return self._durable_delivered >= target

    def _read_last_chain_hash(self) -> str:
        path = self.path
        try:
            empty = path.stat().st_size == 0
        except OSError:
            empty = True
        if empty:
            # Rotated and not written since: the chain continues from the
            # newest rotated file.
            rotated = segment_path(path, 1)
            if self.max_bytes is None or not rotated.exists():
                return ''
            path = rotated
        try:
            with open(path, 'rb') as fh:
                size = os.fstat(fh.fileno()).st_size
                # The last line, read from the end (the whole file is not read).
                step = 1 << 16
                data = b''
                pos = size
                while pos > 0:
                    start = max(0, pos - step)
                    fh.seek(start)
                    data = fh.read(pos - start) + data
                    pos = start
                    body = data[:-1] if data.endswith(b'\n') else data
                    if b'\n' in body or pos == 0:
                        break
                    step *= 2
        except Exception:
            return ''
        body = data[:-1] if data.endswith(b'\n') else data
        last_line = body.rsplit(b'\n', 1)[-1]
        if not last_line:
            return ''
        try:
            last = json.loads(last_line)
        except Exception:
            return ''
        return str(last.get('chain_hash') or '') if isinstance(last, dict) else ''

    def _read_chain_id(self) -> str:
        try:
            snapshot = read_chain(self.path, max_bytes=0)
        except Exception:
            return ''
        return str(snapshot.get('chain_id') or '')

    def _rotate(self) -> None:
        """Under self._lock, between two records: the active file becomes
        ``.1`` and the previous ``.1`` is removed. A crash between the two
        steps leaves the active file (no ``.1``); a crash after them leaves
        ``.1`` and no active file, which a new logger continues from. A
        failure is counted and logged; the record is appended to the active
        file as if no rotation had been asked for."""

        try:
            try:
                segment_path(self.path, 1).unlink()
            except FileNotFoundError:
                pass
            os.replace(self.path, segment_path(self.path, 1))
            self.rotated_total += 1
        except OSError as exc:
            self.rotate_failed_total += 1
            _LOG.error('audit chain rotation failed path=%s errno=%s; appending to the active file', self.path, exc.errno)
            return
        try:
            fsync_path(self.path.parent)
        except OSError as exc:
            _LOG.error('audit chain rotation not durable path=%s errno=%s', self.path, exc.errno)

    @staticmethod
    def _compute_chain_hash(record: Dict[str, Any]) -> str:
        canon = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(canon).hexdigest()

    @classmethod
    def verify_chain(cls, path: str | Path) -> Dict[str, Any]:
        log_path = Path(path)
        if not log_path.exists():
            return {'ok': True, 'entries': 0, 'error': ''}
        lines = log_path.read_text(encoding='utf-8').splitlines()
        return cls._verify_lines(lines, '')

    @classmethod
    def _verify_lines(cls, lines: List[str], prev: str) -> Dict[str, Any]:
        for idx, line in enumerate(lines, start=1):
            row = json.loads(line)
            if str(row.get('chain_prev') or '') != prev:
                return {'ok': False, 'entries': idx - 1, 'error': f'chain_prev_mismatch_at:{idx}'}
            row_for_hash = dict(row)
            actual = str(row_for_hash.pop('chain_hash', '') or '')
            expected = cls._compute_chain_hash(row_for_hash)
            if actual != expected:
                return {'ok': False, 'entries': idx - 1, 'error': f'chain_hash_mismatch_at:{idx}'}
            prev = actual
        return {'ok': True, 'entries': len(lines), 'error': ''}

    @classmethod
    def verify_rotated_chain(cls, path: str | Path) -> Dict[str, Any]:
        """verify_chain over the retained files of a rotated chain, oldest
        first, as one chain. When older files were rotated out the oldest
        retained record's ``chain_prev`` is taken as the start: ``anchored``
        says so, and what was before it is not verified."""

        snapshot = read_chain(path)
        lines = [line.decode('utf-8') for line in snapshot['lines']]
        prev = ''
        if snapshot['anchored'] and lines:
            prev = str(json.loads(lines[0]).get('chain_prev') or '')
        result = cls._verify_lines(lines, prev)
        result.update(anchored=bool(snapshot['anchored']), segments=snapshot['segments'],
                      chain_id=snapshot['chain_id'])
        return result

    def log(self, kind: str, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log_reporting_durability(kind, trace_id, source, **payload)[0]

    def log_reporting_durability(self, kind: str, trace_id: str, source: str, **payload: Any) -> Tuple[Dict[str, Any], str]:
        """log(), also saying whether the record is durable: DURABILITY_FSYNCED,
        DURABILITY_UNSUPPORTED (written; the file system cannot sync) or
        DURABILITY_NOT_REQUIRED (a kind outside DURABLE_KINDS). An fsync error
        raises AuditDurabilityError after the record is appended."""

        if kind not in VALID_KINDS:
            raise ValueError(f'invalid_audit_kind:{kind}')
        with self._lock:
            if self.max_bytes is not None:
                try:
                    full = os.stat(self.path).st_size >= self.max_bytes
                except FileNotFoundError:
                    full = False
                if full:
                    self._rotate()
            created = not self.path.exists()
            record = {
                'ts': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
                'kind': kind,
                'trace_id': str(trace_id),
                'source': str(source),
                'chain_prev': self._last_chain_hash,
            }
            record.update(payload)
            # ``chain_id`` names the chain (segments.chain_id_of); only the
            # logger sets it, never a caller's payload.
            record.pop('chain_id', None)
            if self.max_bytes is not None and created and self._last_chain_hash and self._chain_id:
                # The first record of a rotated chain's new file names the
                # chain (segments.chain_id_of).
                record['chain_id'] = self._chain_id
            record['chain_hash'] = self._compute_chain_hash(record)
            line = json.dumps(record, ensure_ascii=True, separators=(',', ':'))
            with self.path.open('a', encoding='utf-8') as fh:
                fh.write(line + '\n')
            self._last_chain_hash = str(record['chain_hash'])
            if not self._chain_id:
                self._chain_id = chain_id_of(record)
            durability = DURABILITY_NOT_REQUIRED
            if kind in DURABLE_KINDS:
                # After close, through a separate descriptor: fsync flushes the
                # file, not the descriptor, and the write/close sequence above
                # stays exactly what it was. A new file also needs its
                # directory entry on disk. A failure raises: the caller must
                # not be told a record is durable when it may not be.
                try:
                    synced = fsync_path(self.path)
                    if created:
                        synced = fsync_path(self.path.parent) and synced
                except OSError as exc:
                    self._handoff_durable(line, 'fsync_failed', self._last_chain_hash)
                    raise AuditDurabilityError(exc.errno, f'audit_record_not_durable:{exc}') from exc
                if synced:
                    durability = DURABILITY_FSYNCED
                else:
                    durability = DURABILITY_UNSUPPORTED
                    self.fsync_unsupported_count += 1
                self._handoff_durable(line, durability, self._last_chain_hash)
            # Emit-alongside: project into the shared Azazel-Fabric AuditEvent on a
            # SEPARATE, non-interleaved file. The chained log above is complete and
            # untouched; verify_chain() is unaffected (plan §3.3). Best-effort.
            try:
                from .fabric_adapter import project_audit_record

                project_audit_record(record, self.path)
            except Exception:  # pragma: no cover - defensive; projection is advisory-only
                pass
            return record, durability

    def log_event_receive(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('event_receive', trace_id=trace_id, source=source, **payload)

    def log_evaluation(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('evaluation', trace_id=trace_id, source=source, **payload)

    def log_action_decision(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        """Append the decision record and fsync it before returning.

        ``AuditDurabilityError`` is raised *after* the record has been appended
        to the chain (only its fsync failed). Retrying the call therefore
        writes the same decision a second time, as a new chained record; a
        caller that retries must expect, or check for, the duplicate.
        """

        return self.log('action_decision', trace_id=trace_id, source=source, **payload)

    def log_notification(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('notification', trace_id=trace_id, source=source, **payload)

    def log_ai_assist(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('ai_assist', trace_id=trace_id, source=source, **payload)

    def log_triage_session_started(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_session_started', trace_id=trace_id, source=source, **payload)

    def log_triage_step_answered(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_step_answered', trace_id=trace_id, source=source, **payload)

    def log_triage_state_changed(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_state_changed', trace_id=trace_id, source=source, **payload)

    def log_triage_runbook_proposed(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_runbook_proposed', trace_id=trace_id, source=source, **payload)

    def log_triage_handoff(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_handoff', trace_id=trace_id, source=source, **payload)

    def log_triage_completed(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_completed', trace_id=trace_id, source=source, **payload)
