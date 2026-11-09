"""Opt-in offline session buffer (#547), deliberately not registered with ingestion.

Only product-normalized booleans and safe references enter this memory-only
adapter. No IP/header/payload correlation, model, filesystem or network client.
The current product pin can lack the optional helper: that is unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import math

from azazel_mio.contracts import model_id_ok
from azazel_mio.id_grammar import second_layer_ok

FEATURES = frozenset({'burst_pause_pattern', 'error_followed_mutation', 'discovery_followed_access',
                      'declared_ai_client', 'local_canary_touch', 'sustained_scanner_pattern',
                      'legitimate_monitor_context', 'interactive_client_context', 'malicious_payload_evidence'})
SOURCE_FEATURES = {
    'flow': frozenset({'burst_pause_pattern', 'sustained_scanner_pattern'}),
    'http': FEATURES - {'local_canary_touch', 'legitimate_monitor_context', 'interactive_client_context'},
    'approved_deception_fact': frozenset({'local_canary_touch'}),
    'reviewed_context': frozenset({'legitimate_monitor_context', 'interactive_client_context'}),
}
MAX_WINDOWS = 16
MAX_CLOSED = 256
MAX_EVENTS = 64
MAX_REFS = 16
IDLE_SECONDS = 30
ABSOLUTE_SECONDS = 300


def _time(value):
    if type(value) is not str or len(value) > 64:
        raise ValueError('invalid observation time')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('observation time requires timezone')
    return parsed


def _tick(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid monotonic time')
    return float(value)


@dataclass(frozen=True)
class SessionObservation:
    boot_ref: str
    session_ref: str
    frame_id: str
    event_ref: str
    observed_at: str
    source: str
    features: tuple[tuple[str, bool], ...] = ()
    capture_complete: bool = False
    shared_source_ambiguity: bool = True
    clock_uncertain: bool = True

    def __post_init__(self):
        for ref in (self.boot_ref, self.session_ref, self.frame_id):
            if type(ref) is not str or not second_layer_ok(ref):
                raise ValueError('invalid or sensitive scope reference')
        if not model_id_ok(self.event_ref, 'evidence_ref'):
            raise ValueError('invalid or sensitive event reference')
        _time(self.observed_at)
        if self.source not in ('flow', 'http', 'approved_deception_fact', 'reviewed_context'):
            raise ValueError('unsupported observation source')
        if type(self.features) is not tuple or len(self.features) > len(FEATURES):
            raise ValueError('invalid bounded feature list')
        kinds = set()
        for item in self.features:
            if type(item) is not tuple or len(item) != 2 or type(item[0]) is not str or item[0] not in FEATURES or type(item[1]) is not bool or item[0] in kinds:
                raise ValueError('invalid normalized feature')
            if item[0] not in SOURCE_FEATURES[self.source]:
                raise ValueError('feature is unavailable from this source')
            kinds.add(item[0])
        if any(type(v) is not bool for v in (self.capture_complete, self.shared_source_ambiguity, self.clock_uncertain)):
            raise ValueError('coverage flags must be explicit booleans')


@dataclass
class _Window:
    first_tick: float
    last_tick: float
    start: str
    end: str
    events: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)
    complete: bool = True
    ambiguous: bool = False
    clock: bool = False


class SessionObservationBuffer:
    """No live hook. Explicitly enabled local replay consumers only.

    Closed scope IDs cannot reopen in this instance; exhausting tombstones seals
    it. There is no restart recovery; callers must withhold lost coverage after restart.
    """
    def __init__(self, boot_ref: str, *, enabled=False):
        if type(boot_ref) is not str or not second_layer_ok(boot_ref) or type(enabled) is not bool:
            raise ValueError('invalid buffer configuration')
        self.boot_ref, self.enabled = boot_ref, enabled
        self._windows, self._closed = {}, set()
        self._last_tick = 0.0
        self.sealed = False
        self.counters = {name: 0 for name in ('accepted', 'disabled', 'duplicate', 'dropped', 'expired', 'malformed', 'unavailable')}

    def _close(self, key):
        self._windows.pop(key, None)
        if len(self._closed) >= MAX_CLOSED:
            self.sealed = True
        else:
            self._closed.add(key)

    def expire(self, now):
        now = _tick(now)
        if now < self._last_tick:
            self.sealed = True
            self._windows.clear()
            self.counters['dropped'] += 1
            return
        self._last_tick = now
        for key, window in list(self._windows.items()):
            if now - window.last_tick >= IDLE_SECONDS or now - window.first_tick >= ABSOLUTE_SECONDS:
                self._close(key)
                self.counters['expired'] += 1

    def offer(self, observation, *, now):
        if not self.enabled:
            self.counters['disabled'] += 1
            return 'disabled'
        now = _tick(now)
        self.expire(now)
        try:
            if type(observation) is not SessionObservation:
                raise ValueError('normalized observation required')
            observation.__post_init__()
        except (ValueError, TypeError):
            self.counters['malformed'] += 1
            return 'malformed'
        key = (observation.session_ref, observation.frame_id)
        if self.sealed or observation.boot_ref != self.boot_ref or key in self._closed:
            self.counters['dropped'] += 1
            return 'unavailable'
        window = self._windows.get(key)
        if window is None:
            if len(self._windows) >= MAX_WINDOWS:
                self._close(key)
                self.counters['dropped'] += 1
                return 'capacity'
            window = _Window(now, now, observation.observed_at, observation.observed_at)
            self._windows[key] = window
        signature = (observation.observed_at, observation.source, observation.features, observation.capture_complete, observation.shared_source_ambiguity, observation.clock_uncertain)
        if observation.event_ref in window.events:
            if window.events[observation.event_ref] != signature:
                window.complete = False
                self.counters['dropped'] += 1
                return 'conflict'
            self.counters['duplicate'] += 1
            return 'duplicate'
        if len(window.events) >= MAX_EVENTS:
            window.complete = False
            self.counters['dropped'] += 1
            return 'capacity'
        if _time(observation.observed_at) < _time(window.end):
            window.clock = True  # reorder is retained, never silently repaired
        window.start = min(window.start, observation.observed_at, key=_time)
        window.end = max(window.end, observation.observed_at, key=_time)
        window.last_tick = now
        window.events[observation.event_ref] = signature
        window.complete &= observation.capture_complete
        window.ambiguous |= observation.shared_source_ambiguity
        window.clock |= observation.clock_uncertain
        for kind, value in observation.features:
            previous, refs = window.features.get(kind, (value, []))
            if previous != value:
                window.complete = False
                previous = None
            if len(refs) < MAX_REFS:
                refs.append(observation.event_ref)
            else:
                window.complete = False
                self.counters['dropped'] += 1
            window.features[kind] = (previous, refs)
        self.counters['accepted'] += 1
        return 'accepted'

    def assess(self, frame, *, session_ref, now, as_of):
        """Consume once after an existing decision; optional helper or no result.

        This method is never called by the Rust loop, scorer, web app or ingestion.
        It has no executor, writable receipt, severity or activation interface.
        """
        if not self.enabled:
            return {'status': 'disabled', 'authorized_actions': []}
        self.expire(now)
        key = (session_ref, getattr(frame, 'frame_id', None))
        window = self._windows.get(key)
        if window is None or self.sealed:
            return {'status': 'unavailable', 'authorized_actions': []}
        self._close(key)
        try:
            from azazel_mio.session_behavior import SessionFeature, SessionWindow, assess_session
            features = tuple(SessionFeature(kind, value, tuple(refs)) for kind, (value, refs) in sorted(window.features.items()))
            normalized = SessionWindow(frame.frame_id, session_ref, self.boot_ref, 'edge-session-observations-v1',
                                       window.start, window.end, features, window.complete, window.ambiguous, window.clock)
            return assess_session(frame, normalized, as_of=as_of)
        except (ImportError, ValueError, TypeError, AttributeError):
            self.counters['unavailable'] += 1
            return {'status': 'unavailable', 'authorized_actions': []}

    def status(self):
        return {'enabled': self.enabled, 'open_windows': len(self._windows), 'closed_windows': len(self._closed),
                'sealed': self.sealed, 'counters': dict(self.counters), 'durable': False,
                'authorized_actions': []}
