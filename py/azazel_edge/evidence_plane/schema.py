from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

REQUIRED_FIELDS = (
    'event_id',
    'ts',
    'source',
    'kind',
    'subject',
    'severity',
    'confidence',
    'attrs',
)


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def make_event_id(ts: str, source: str, kind: str, subject: str, attrs: Dict[str, Any]) -> str:
    payload = {
        'ts': str(ts or ''),
        'source': str(source or ''),
        'kind': str(kind or ''),
        'subject': str(subject or ''),
        'attrs': attrs if isinstance(attrs, dict) else {},
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest()
    return f'sha256:{digest}'


@dataclass(frozen=True)
class EvidenceEvent:
    event_id: str
    ts: str
    source: str
    kind: str
    subject: str
    severity: int
    confidence: float
    attrs: Dict[str, Any] = field(default_factory=dict)
    status: str = ''
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            'event_id': self.event_id,
            'ts': self.ts,
            'source': self.source,
            'kind': self.kind,
            'subject': self.subject,
            'severity': int(self.severity),
            'confidence': round(float(self.confidence), 4),
            'attrs': dict(self.attrs),
        }
        if self.status:
            payload['status'] = self.status
        if self.evidence_refs:
            payload['evidence_refs'] = list(self.evidence_refs)
        return payload

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> 'EvidenceEvent':
        missing = [field for field in REQUIRED_FIELDS if field not in payload]
        if missing:
            raise ValueError(f'missing_required_fields:{"|".join(missing)}')
        attrs = payload.get('attrs')
        if not isinstance(attrs, dict):
            raise ValueError('attrs_must_be_object')
        severity = max(0, min(int(payload.get('severity', 0)), 100))
        confidence = max(0.0, min(float(payload.get('confidence', 0.0)), 1.0))
        return cls(
            event_id=str(payload.get('event_id') or ''),
            ts=str(payload.get('ts') or ''),
            source=str(payload.get('source') or ''),
            kind=str(payload.get('kind') or ''),
            subject=str(payload.get('subject') or ''),
            severity=severity,
            confidence=confidence,
            attrs=attrs,
            status=str(payload.get('status') or ''),
            evidence_refs=[str(x) for x in payload.get('evidence_refs', [])] if isinstance(payload.get('evidence_refs'), list) else [],
        )

    @classmethod
    def build(
        cls,
        *,
        ts: str | None,
        source: str,
        kind: str,
        subject: str,
        severity: int,
        confidence: float,
        attrs: Dict[str, Any] | None = None,
        status: str = '',
        evidence_refs: List[str] | None = None,
    ) -> 'EvidenceEvent':
        attrs_norm = attrs if isinstance(attrs, dict) else {}
        ts_norm = str(ts or iso_utc_now())
        return cls(
            event_id=make_event_id(ts_norm, source, kind, subject, attrs_norm),
            ts=ts_norm,
            source=str(source or ''),
            kind=str(kind or ''),
            subject=str(subject or ''),
            severity=max(0, min(int(severity), 100)),
            confidence=max(0.0, min(float(confidence), 1.0)),
            attrs=attrs_norm,
            status=str(status or ''),
            evidence_refs=list(evidence_refs or []),
        )
