from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .schema import EvidenceEvent


def adapt_suricata_record(record: Dict[str, object]) -> EvidenceEvent:
    normalized = record.get('normalized') if isinstance(record.get('normalized'), dict) else {}
    defense = record.get('defense') if isinstance(record.get('defense'), dict) else {}
    source_ts = str(normalized.get('ts') or '')
    src_ip = str(normalized.get('src_ip') or '-')
    dst_ip = str(normalized.get('dst_ip') or '-')
    proto = str(normalized.get('protocol') or '-')
    target_port = int(normalized.get('target_port') or 0)
    subject = f'{src_ip}->{dst_ip}:{target_port}/{proto}'
    attrs = {
        'sid': int(normalized.get('sid') or 0),
        'attack_type': str(normalized.get('attack_type') or ''),
        'suricata_severity': int(normalized.get('severity') or 0),
        'category': str(normalized.get('category') or ''),
        'event_type': str(normalized.get('event_type') or ''),
        'action': str(normalized.get('action') or ''),
        'protocol': proto,
        'target_port': target_port,
        'risk_score': int(normalized.get('risk_score') or 0),
        'confidence_raw': int(normalized.get('confidence') or 0),
        'ingest_epoch': float(normalized.get('ingest_epoch') or 0.0),
        'defense': defense,
        'pipeline': str(record.get('pipeline') or ''),
    }
    severity = int(normalized.get('risk_score') or 0)
    confidence = min(1.0, max(0.0, float(normalized.get('confidence') or 0) / 100.0))
    return EvidenceEvent.build(
        ts=source_ts,
        source='suricata_eve',
        kind=str(normalized.get('event_type') or 'alert'),
        subject=subject,
        severity=severity,
        confidence=confidence,
        attrs=attrs,
        status='alert',
        evidence_refs=[f"suricata_sid:{attrs['sid']}"] if attrs['sid'] else [],
    )


def iter_suricata_jsonl(path: Path) -> Iterable[EvidenceEvent]:
    if not path.exists():
        return []
    def _iter() -> Iterable[EvidenceEvent]:
        with path.open('r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                yield adapt_suricata_record(payload)
    return _iter()


def read_suricata_jsonl(path: Path, limit: Optional[int] = None) -> List[EvidenceEvent]:
    items = list(iter_suricata_jsonl(path))
    return items[-limit:] if isinstance(limit, int) and limit > 0 else items
