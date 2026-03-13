from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from .schema import EvidenceEvent


def build_config_drift_event(diff: Dict[str, Any], ts: str | None = None) -> EvidenceEvent:
    status = str(diff.get('status') or 'baseline_missing')
    severity = 0
    if status == 'drift':
        severity = 45
    elif status == 'baseline_invalid':
        severity = 35
    elif status == 'baseline_missing':
        severity = 20
    attrs = {
        'status': status,
        'baseline_state': str(diff.get('baseline_state') or 'missing'),
        'changed_fields': list(diff.get('changed_fields') or []),
        'baseline_values': dict(diff.get('baseline_values') or {}),
        'current_values': dict(diff.get('current_values') or {}),
        'rollback_hint': str(diff.get('rollback_hint') or ''),
    }
    return EvidenceEvent.build(
        ts=ts or datetime.now(timezone.utc).isoformat(timespec='seconds'),
        source='config_drift',
        kind='config_drift',
        subject='health_config',
        severity=severity,
        confidence=0.9 if status in {'drift', 'baseline_match'} else 0.75,
        attrs=attrs,
        status='warn' if severity > 0 else 'info',
    )
