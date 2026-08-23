from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from .contracts import DEFENSIVE_STATES, MioSituationFrame


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


class MioSituationFrameBuilder:
    """Build a bounded M.I.O. world-state from deterministic Edge outputs.

    The builder deliberately does not copy raw event attrs/messages into the
    frame. Detailed evidence remains addressable by evidence ID through typed
    capabilities, keeping the small-model context compact and minimizing
    attacker-controlled/sensitive data exposure.
    """

    def __init__(self, *, max_event_refs: int = 32, stale_after_seconds: int = 300):
        self.max_event_refs = max(1, min(int(max_event_refs), 64))
        self.stale_after_seconds = max(1, int(stale_after_seconds))

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
        explicit_unknowns: Sequence[str] = (),
        explicit_contradictions: Sequence[str] = (),
    ) -> MioSituationFrame:
        state = str(current_defensive_state or '').upper()
        if state not in DEFENSIVE_STATES:
            raise ValueError('invalid_current_defensive_state')

        noc = _as_mapping(noc_evaluation)
        soc = _as_mapping(soc_evaluation)
        noc_summary = _as_mapping(noc.get('summary'))
        soc_summary = _as_mapping(soc.get('summary'))

        known_facts: list[str] = []
        unknowns: list[str] = [str(x) for x in explicit_unknowns]
        contradictions: list[str] = [str(x) for x in explicit_contradictions]

        noc_status = _status(noc_summary.get('status'))
        soc_status = _status(soc_summary.get('status'), 'low')
        known_facts.extend((f'NOC_STATUS={noc_status.upper()}', f'SOC_STATUS={soc_status.upper()}'))

        for prefix, summary in (('NOC', noc_summary), ('SOC', soc_summary)):
            for raw_reason in _as_list(summary.get('reasons'))[:8]:
                code = _reason_code(raw_reason)
                if code:
                    known_facts.append(f'{prefix}_REASON={code}')

        suspicion = _as_mapping(soc.get('suspicion'))
        confidence = _as_mapping(soc.get('confidence'))
        blast = _as_mapping(soc.get('blast_radius'))
        if suspicion:
            known_facts.append(f'SOC_SUSPICION={_status(suspicion.get("label"), "unknown").upper()}')
        if confidence:
            known_facts.append(f'SOC_CONFIDENCE={_status(confidence.get("label"), "unknown").upper()}')
        if blast:
            known_facts.append(f'SOC_BLAST={_status(blast.get("label"), "unknown").upper()}')

        visibility = _as_mapping(soc.get('security_visibility_state'))
        visibility_status = _status(visibility.get('status'))
        if visibility_status not in {'good', 'normal'}:
            unknowns.append(f'SOC_VISIBILITY={visibility_status.upper()}')

        if bool(noc_summary.get('degraded_mode')):
            unknowns.append('NOC_DEGRADED_MODE')

        if soc_status in {'high', 'critical'} and noc_status in {'poor', 'critical', 'unknown'}:
            contradictions.append('HIGH_SOC_RISK_WITH_FRAGILE_NOC')

        evidence_refs: list[str] = []
        for source in (noc.get('evidence_ids'), soc.get('evidence_ids')):
            for ref in _as_list(source):
                text = str(ref or '')
                if text:
                    evidence_refs.append(text)

        newest_ts: datetime | None = None
        event_ref_count = 0
        for event in events:
            payload = _event_payload(event)
            event_id = str(payload.get('event_id') or '')
            if event_id and event_ref_count < self.max_event_refs:
                evidence_refs.append(event_id)
                event_ref_count += 1
            ts = _parse_ts(payload.get('ts'))
            if ts is not None and (newest_ts is None or ts > newest_ts):
                newest_ts = ts

        created = _parse_ts(created_at) or datetime.now(timezone.utc)
        if newest_ts is None:
            freshness_seconds = self.stale_after_seconds + 1
            unknowns.append('NO_TIMESTAMPED_EVIDENCE')
        else:
            freshness_seconds = max(0, int((created - newest_ts).total_seconds()))
            if freshness_seconds > self.stale_after_seconds:
                unknowns.append('EVIDENCE_STALE')

        noc_text = f"status={noc_status}; reasons={','.join(_reason_code(x) for x in _as_list(noc_summary.get('reasons'))[:6] if _reason_code(x))}"
        soc_text = f"status={soc_status}; reasons={','.join(_reason_code(x) for x in _as_list(soc_summary.get('reasons'))[:6] if _reason_code(x))}"

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
        )
