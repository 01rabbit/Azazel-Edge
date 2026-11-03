"""Independent bounded loopback Knowledge timeline; no model or decision authority."""
from __future__ import annotations

import json
import queue
import threading
import time
from typing import Any, Callable, Mapping

from .mio_model_lane import KNOWLEDGE_STATUSES


def _empty(status: str, generation: str = '', trace_id: str = '') -> dict[str, Any]:
    return {'schema_version': 'azazel.mio_knowledge_analysis.v1', 'status': status,
            'authority': 'read_only_advisory', 'generation': generation,
            'trace_id': trace_id, 'frame_id': '', 'frame_generation': generation,
            'source_trace_id': '', 'duration_ms': 0, 'request_count': 0,
            'usage_status': 'not_applicable', 'is_current': False}


class LiveMioKnowledgeLane:
    """One latest-only queue and independent deadline, never waits on model consent."""

    def __init__(self, *, enabled: Callable[[], bool], query: Callable,
                 fast_snapshot: Callable, frame_snapshot: Callable,
                 knowledge_input_snapshot: Callable, project: Callable,
                 max_age_seconds: float = 10.0, current_generation: Callable | None = None):
        self._enabled, self._query, self._project = enabled, query, project
        self._fast_snapshot, self._frame_snapshot = fast_snapshot, frame_snapshot
        # Optional cheap scalar for the 10 ms cancellation watcher; without it stale() falls back to fast_snapshot.
        self._current_generation = current_generation
        self._knowledge_input_snapshot = knowledge_input_snapshot
        self.max_age_seconds = max(.1, min(float(max_age_seconds), 10.0))
        self._lock = threading.RLock()
        self._sequence = 0
        self._completed_at = 0.0
        self._result = _empty('starting' if enabled() else 'disabled')
        self._queue = queue.Queue(maxsize=1)
        self._thread = threading.Thread(target=self._run, name='mio-knowledge-context', daemon=True)
        self._thread.start()

    def snapshot(self):
        if not self._enabled():
            with self._lock:
                generation = self._result.get('generation', '')
            return _empty('disabled', generation)
        with self._lock:
            result = json.loads(json.dumps(self._result))
            age = max(0.0, time.monotonic() - self._completed_at)
        fresh = age <= self.max_age_seconds
        fast = self._fast_snapshot()
        generation = result['generation']
        # Same event: still the live generation and the very frame/trace/event the receipt was built for.
        # Independent of the fast frame's own expiry, so it can survive it as a historical report.
        same_event = (result['status'] == 'projected' and isinstance(result.get('projection'), dict)
            and bool(generation) and result.get('frame_generation') == generation
            and self._live_generation() == generation
            and str(fast.get('generation') or '') == generation
            and fast.get('trace_id') == result['source_trace_id']
            and (fast.get('source_context') or {}).get('event_key') == result.get('event_key')
            and (fast.get('advisory') or {}).get('trace_id') == result['trace_id']
            and (fast.get('advisory') or {}).get('frame_id') == result['frame_id'])
        result['is_current'] = bool(same_event and fresh and fast.get('is_current') is True)
        if same_event and not result['is_current'] and fresh:
            # At most this one retained result. Display-only: never an input to the fast scorer,
            # reasoning, model lane or action logic, and never labelled current.
            result['report_state'] = 'last_report'
            result['report_age_seconds'] = round(age, 3)
            result['max_age_seconds'] = self.max_age_seconds
            result['report_expires_at_ms'] = int((time.time() + self.max_age_seconds - age) * 1000)
        elif not result['is_current']:
            result.pop('projection', None)
        # The auxiliary callback may block while opt-in is revoked. Recheck
        # before publishing the copied receipt, including its projection.
        if not self._enabled():
            return _empty('disabled', result['generation'])
        return result

    def _live_generation(self) -> str:
        if self._current_generation is not None:
            return str(self._current_generation())
        return str(self._fast_snapshot().get('generation') or '')

    def submit(self, generation: Any, source_trace_id: str = ''):
        # Never calls snapshot/fast_snapshot: the receipt is built from lane-owned state only,
        # so the synchronous _handle_event caller cannot block on the auxiliary callback.
        with self._lock:
            self._sequence += 1
            enabled = self._enabled()
            self._result = _empty('queued' if enabled else 'disabled', str(generation or ''))
            if enabled:
                item = (self._sequence, time.monotonic(), str(generation or ''), str(source_trace_id)[:96])
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except queue.Empty:
                    pass
                self._queue.put_nowait(item)
            return json.loads(json.dumps(self._result))

    def _run(self):
        while True:
            sequence, queued_at, generation, source_trace_id = self._queue.get()
            started = time.monotonic()
            deadline = queued_at + self.max_age_seconds
            def stale():
                return (sequence != self._sequence or not self._enabled()
                    or self._live_generation() != generation)
            result = _empty('unavailable', generation)
            try:
                fast = {}
                while not stale() and time.monotonic() < deadline:
                    fast = self._fast_snapshot()
                    if fast.get('status') not in {'pending', 'starting', 'queued'}:
                        break
                    time.sleep(min(.02, max(0, deadline - time.monotonic())))
                frame = self._frame_snapshot(generation)
                if stale():
                    result['status'] = 'superseded'
                elif time.monotonic() >= deadline:
                    result['status'] = 'timeout'
                elif (fast.get('status') != 'complete' or fast.get('is_current') is not True
                      or not isinstance(frame, Mapping) or frame.get('trace_id') != (fast.get('advisory') or {}).get('trace_id')
                      or frame.get('frame_id') != (fast.get('advisory') or {}).get('frame_id')
                      or source_trace_id != fast.get('trace_id')
                      or not (fast.get('source_context') or {}).get('event_key')):
                    result['status'] = 'rejected'
                else:
                    result.update(trace_id=frame['trace_id'], frame_id=frame.get('frame_id', ''),
                                  source_trace_id=source_trace_id,
                                  event_key=str((fast.get('source_context') or {}).get('event_key') or '')[:96])
                    # Existing query deadline starts after frame capture, so time spent waiting
                    # for the fast frame is not charged to the bounded Knowledge lookup.
                    deadline = time.monotonic() + self.max_age_seconds
                    status, response = self._query(self._knowledge_input_snapshot(generation),
                                                   deadline=deadline, stale_check=stale)
                    result['request_count'] = int(status not in {'disabled', 'missing_token',
                        'invalid_configuration', 'superseded'})
                    result['status'] = status if status in KNOWLEDGE_STATUSES else 'unavailable'
                    if response is not None and not stale() and time.monotonic() < deadline:
                        projected = self._project(dict(frame), response, deadline, stale)
                        result['status'] = 'projected' if projected else 'rejected'
                        if isinstance(projected, Mapping) and len(json.dumps(projected)) <= 4096:
                            result['projection'] = dict(projected)
                            result['source_freshness_verification'] = 'reported_unverified_at_lookup'
                    if time.monotonic() >= deadline:
                        result['status'] = 'timeout'
                    if stale():
                        result['status'] = 'superseded'
            except Exception:
                result['status'] = 'unavailable'
            finally:
                result['duration_ms'] = min(600000, max(0, int((time.monotonic()-started)*1000)))
                with self._lock:
                    if sequence == self._sequence:
                        self._result = result
                        self._completed_at = time.monotonic()
                self._queue.task_done()
