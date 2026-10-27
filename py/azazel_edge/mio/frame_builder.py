from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from .contracts import (
    _TOKEN_RE,
    DEFENSIVE_STATES,
    SITUATION_FRAME_ACTOR_CAPS,
    SITUATION_FRAME_CAPS,
    MioSituationFrame,
    _opaque_id,
    _safe_int,
    actor_key_for,
)


def _parse_ts(value: Any) -> datetime | None:
    text = str(value or '').strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _reason_code(value: Any) -> str:
    """Keep reason taxonomy while avoiding detailed subject/value retention."""
    text = str(value or '').strip()
    if not text:
        return ''
    return text.split(':', 1)[0][:96]


def _status(value: Any, default: str = 'unknown') -> str:
    text = str(value or '').strip().lower()
    return text or default


def _threat_level_from_soc(soc: Mapping[str, Any]) -> str:
    summary = _as_mapping(soc.get('summary'))
    status = _status(summary.get('status'), 'low')
    mapping = {
        'low': 'LOW',
        'medium': 'MEDIUM',
        'high': 'HIGH',
        'critical': 'CRITICAL',
    }
    return mapping.get(status, 'UNKNOWN')


def _event_payload(event: Any) -> Mapping[str, Any]:
    if hasattr(event, 'to_dict'):
        try:
            payload = event.to_dict()
        except Exception:
            return {}
        return payload if isinstance(payload, Mapping) else {}
    return event if isinstance(event, Mapping) else {}


def _best_unique(candidates: list[tuple[int, float, str]], keep: int) -> list[tuple[int, float, str]]:
    out: list[tuple[int, float, str]] = []
    seen: set[str] = set()
    for item in sorted(candidates):
        if item[2] in seen:
            continue
        seen.add(item[2])
        out.append(item)
        if len(out) >= keep:
            break
    return out


def _actor_source(subject: Any) -> str:
    """Source endpoint of a ``<src>-><dst>...`` subject (Suricata EVE and flow
    adapters). Other subjects (syslog host:tag, NOC probes, inventory) do not
    name an actor and yield ''. The value is only hashed, never copied."""
    text = str(subject or '')
    if '->' not in text:
        return ''
    src = text.split('->', 1)[0].strip()
    return '' if not src or src == '-' else src[:256]


def _iso(ts: datetime | None) -> str:
    return '' if ts is None else ts.strftime('%Y-%m-%dT%H:%M:%SZ')


def _top(counter: Counter, keep: int) -> list[Any]:
    return [value for value, _n in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:keep]]


class _ActorAccumulator:
    __slots__ = ('count', 'severity', 'first', 'last', 'ports', 'protocols', 'kinds', 'refs')

    def __init__(self) -> None:
        self.count = 0
        self.severity = 0
        self.first: datetime | None = None
        self.last: datetime | None = None
        self.ports: Counter = Counter()
        self.protocols: Counter = Counter()
        self.kinds: Counter = Counter()
        self.refs: list[tuple[int, float, str]] = []

    def add(self, payload: Mapping[str, Any], *, ts: datetime | None, severity: int, event_id: str) -> None:
        self.count += 1
        self.severity = max(self.severity, severity)
        if ts is not None:
            self.first = ts if self.first is None or ts < self.first else self.first
            self.last = ts if self.last is None or ts > self.last else self.last
        attrs = _as_mapping(payload.get('attrs'))
        port = attrs.get('target_port', attrs.get('dst_port'))
        if type(port) is int and 0 < port <= 65535:
            self.ports[port] += 1
        proto = str(attrs.get('protocol') or attrs.get('proto') or '').strip().lower()
        if _TOKEN_RE.match(proto):
            self.protocols[proto] += 1
        kind = str(payload.get('kind') or '').strip().lower()
        if _TOKEN_RE.match(kind):
            self.kinds[kind] += 1
        if _opaque_id(event_id):
            self.refs.append((-severity, -ts.timestamp() if ts is not None else float('inf'), event_id))
            if len(self.refs) >= 4 * SITUATION_FRAME_ACTOR_CAPS['evidence_refs']:
                self.refs = _best_unique(self.refs, SITUATION_FRAME_ACTOR_CAPS['evidence_refs'])

    def summary(self, actor_key: str) -> dict[str, Any]:
        caps = SITUATION_FRAME_ACTOR_CAPS
        return {
            'actor_key': actor_key,
            'first_seen': _iso(self.first),
            'last_seen': _iso(self.last),
            'event_count': self.count,
            'max_severity': self.severity,
            'protocols': _top(self.protocols, caps['protocols']),
            'target_ports': _top(self.ports, caps['target_ports']),
            'distinct_target_ports': len(self.ports),
            'event_kinds': _top(self.kinds, caps['event_kinds']),
            'evidence_refs': [ref for _s, _t, ref in _best_unique(self.refs, caps['evidence_refs'])],
        }


class MioSituationFrameBuilder:
    """Build a bounded M.I.O. world-state from deterministic Edge outputs.

    The builder deliberately does not copy raw event attrs/messages into the
    frame. Detailed evidence remains addressable by evidence ID through typed
    capabilities, keeping the small-model context compact and minimizing
    attacker-controlled/sensitive data exposure.
    """

    def __init__(self, *, max_event_refs: int = 32, stale_after_seconds: int = 300, future_clock_skew_seconds: int = 5):
        # The builder keeps only immutable configuration; every build() uses
        # call-local state so concurrent traces cannot cross-contaminate.
        self.max_event_refs = max(1, min(int(max_event_refs), 64))
        self.stale_after_seconds = max(1, int(stale_after_seconds))
        self.future_clock_skew_seconds = max(0, min(int(future_clock_skew_seconds), 60))

    def build(
        self,
        *,
        events: Iterable[Any],
        noc_evaluation: Mapping[str, Any],
        soc_evaluation: Mapping[str, Any],
        current_defensive_state: str,
        mission: str,
        trace_id: str,
        frame_id: str,
        created_at: str,
        knowledge_refs: Sequence[str] = (),
        knowledge_status: str | None = None,
        deception_status: str | None = None,
        explicit_unknowns: Sequence[str] = (),
        explicit_contradictions: Sequence[str] = (),
        action_history: Sequence[Mapping[str, Any]] = (),
        deception_context: Mapping[str, Any] | None = None,
    ) -> MioSituationFrame:
        """``action_history`` holds the current/previous actions Edge already
        selected, as normalized records from its decision audit (see
        ``MioActionRecord``). ``deception_context`` is the optional AZ-06 facts
        projection (``MioDeceptionContext``). Both are recorded, never decided."""
        state = str(current_defensive_state or '').upper()
        if state not in DEFENSIVE_STATES:
            raise ValueError('invalid_current_defensive_state')
        created = _parse_ts(created_at)
        if created is None:
            raise ValueError('invalid_frame_created_at')

        noc = _as_mapping(noc_evaluation)
        soc = _as_mapping(soc_evaluation)
        noc_summary = _as_mapping(noc.get('summary'))
        soc_summary = _as_mapping(soc.get('summary'))

        known_facts: list[str] = []
        # Builder-derived safety markers come before caller-supplied ones so
        # explicit_unknowns/contradictions can never crowd them out of the caps.
        unknowns: list[str] = []
        contradictions: list[str] = []

        noc_status = _status(noc_summary.get('status'))
        soc_status = _status(soc_summary.get('status'), 'low')
        # Ordered most- to least-important: tail trimming drops reasons first.
        known_facts.extend((f'NOC_STATUS={noc_status.upper()}', f'SOC_STATUS={soc_status.upper()}'))

        suspicion = _as_mapping(soc.get('suspicion'))
        confidence = _as_mapping(soc.get('confidence'))
        blast = _as_mapping(soc.get('blast_radius'))
        if suspicion:
            known_facts.append(f'SOC_SUSPICION={_status(suspicion.get("label"), "unknown").upper()}')
        if confidence:
            known_facts.append(f'SOC_CONFIDENCE={_status(confidence.get("label"), "unknown").upper()}')
        if blast:
            known_facts.append(f'SOC_BLAST={_status(blast.get("label"), "unknown").upper()}')

        # Interleave NOC/SOC reason codes so neither plane is starved by caps.
        reason_lists = [
            [f'{prefix}_REASON={code}' for code in (_reason_code(x) for x in _as_list(summary.get('reasons'))[:8]) if code]
            for prefix, summary in (('NOC', noc_summary), ('SOC', soc_summary))
        ]
        for i in range(max(len(r) for r in reason_lists)):
            for reasons in reason_lists:
                if i < len(reasons):
                    known_facts.append(reasons[i])

        visibility = _as_mapping(soc.get('security_visibility_state'))
        visibility_status = _status(visibility.get('status'))
        if visibility_status not in {'good', 'normal'}:
            unknowns.append(f'SOC_VISIBILITY={visibility_status.upper()}')

        if bool(noc_summary.get('degraded_mode')):
            unknowns.append('NOC_DEGRADED_MODE')

        if soc_status in {'high', 'critical'} and noc_status in {'poor', 'critical', 'unknown'}:
            contradictions.append('HIGH_SOC_RISK_WITH_FRAGILE_NOC')

        evidence_refs: list[str] = []
        evidence_sources: set[str] = set()
        for source_name, source in (('noc_evaluation', noc.get('evidence_ids')), ('soc_evaluation', soc.get('evidence_ids'))):
            for ref in _as_list(source):
                text = str(ref or '')
                if text:
                    evidence_refs.append(text)
                    evidence_sources.add(source_name)

        # One cheap O(n) pass with O(max_event_refs) memory: freshness uses the
        # newest timestamp of *all* events, and the referenced events are chosen
        # by (severity desc, recency desc, event_id) so input order never matters.
        newest_ts: datetime | None = None
        # Sort key: higher severity, then newer, then smaller event_id.
        candidates: list[tuple[int, float, str]] = []
        keep = self.max_event_refs
        # Actors are aggregated per source endpoint. Memory is O(distinct
        # actors and their ports/kinds), bounded by the caller's event window
        # like the pass itself; the frame keeps the top 8, so input volume never
        # grows the frame. Future-dated timestamps do not set first/last_seen.
        future_limit = created + timedelta(seconds=self.future_clock_skew_seconds)
        actor_acc: dict[str, _ActorAccumulator] = {}
        for event in events:
            payload = _event_payload(event)
            ts = _parse_ts(payload.get('ts'))
            if ts is not None and (newest_ts is None or ts > newest_ts):
                newest_ts = ts
            event_id = str(payload.get('event_id') or '')
            severity = max(0, min(_safe_int(payload.get('severity')), 100))
            source = _actor_source(payload.get('subject'))
            if source:
                acc = actor_acc.get(source)
                if acc is None:
                    acc = actor_acc[source] = _ActorAccumulator()
                acc.add(payload, ts=ts if ts is not None and ts <= future_limit else None, severity=severity, event_id=event_id)
            if not event_id:
                continue
            candidates.append((-severity, -ts.timestamp() if ts is not None else float('inf'), event_id))
            if len(candidates) >= 4 * keep:
                candidates = _best_unique(candidates, keep)
        selected = _best_unique(candidates, keep)
        if selected:
            evidence_sources.add('evidence_plane')
        evidence_refs.extend(event_id for _sev, _ts, event_id in selected)

        if newest_ts is None:
            freshness_seconds = self.stale_after_seconds + 1
            unknowns.append('NO_TIMESTAMPED_EVIDENCE')
        elif newest_ts > created + timedelta(seconds=self.future_clock_skew_seconds):
            freshness_seconds = self.stale_after_seconds + 1
            unknowns.append('EVIDENCE_TIMESTAMP_FUTURE')
        else:
            freshness_seconds = max(0, int((created - newest_ts).total_seconds()))
            if freshness_seconds > self.stale_after_seconds:
                unknowns.append('EVIDENCE_STALE')

        # Rank by severity, volume, recency, then the raw source (order-free);
        # only the kept actors are hashed into trace-scoped keys. One more than
        # the cap is passed so the frame marks the overflow as truncated.
        ranked = sorted(actor_acc.items(), key=lambda kv: (-kv[1].severity, -kv[1].count, -(kv[1].last.timestamp() if kv[1].last else float('-inf')), kv[0]))
        actors = [acc.summary(actor_key_for(trace_id, source)) for source, acc in ranked[: SITUATION_FRAME_CAPS['actors'] + 1]]

        unknowns.extend(str(x) for x in explicit_unknowns)
        contradictions.extend(str(x) for x in explicit_contradictions)

        noc_text = f"status={noc_status}; reasons={','.join(_reason_code(x) for x in _as_list(noc_summary.get('reasons'))[:6] if _reason_code(x))}"
        soc_text = f"status={soc_status}; reasons={','.join(_reason_code(x) for x in _as_list(soc_summary.get('reasons'))[:6] if _reason_code(x))}"

        provenance: dict[str, list[str]] = {
            'known_facts': ['noc_evaluation', 'soc_evaluation'],
            'unknowns': ['frame_builder'] + (['caller'] if explicit_unknowns else []),
            'evidence_refs': sorted(evidence_sources),
            'freshness_seconds': ['evidence_plane', 'frame_builder'],
        }
        if contradictions:
            provenance['contradictions'] = ['frame_builder'] + (['caller'] if explicit_contradictions else [])
        if knowledge_refs:
            provenance['knowledge_refs'] = ['knowledge']
        if actors:
            provenance['actors'] = ['evidence_plane', 'frame_builder']
        if action_history:
            provenance['actions'] = ['decision_audit']
        if deception_context is not None:
            provenance['deception_context'] = ['deception']

        return MioSituationFrame.build(
            frame_id=frame_id,
            trace_id=trace_id,
            created_at=created_at,
            mission=mission,
            current_defensive_state=state,
            threat_level=_threat_level_from_soc(soc),
            noc_summary=noc_text,
            soc_summary=soc_text,
            known_facts=known_facts,
            unknowns=unknowns,
            contradictions=contradictions,
            evidence_refs=evidence_refs,
            knowledge_refs=knowledge_refs,
            freshness_seconds=freshness_seconds,
            knowledge_status=knowledge_status,
            deception_status=deception_status,
            provenance=provenance,
            actors=actors,
            actions=list(action_history) if isinstance(action_history, (list, tuple)) else [],
            deception_context=deception_context,
        )
