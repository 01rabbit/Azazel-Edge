from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .schema import EvidenceEvent


def adapt_flow_record(record: Dict[str, object]) -> EvidenceEvent:
    ts = str(record.get('ts') or '')
    src_ip = str(record.get('src_ip') or '-')
    dst_ip = str(record.get('dst_ip') or '-')
    proto = str(record.get('proto') or record.get('protocol') or '-')
    dst_port = int(record.get('dst_port') or record.get('target_port') or 0)
    subject = f'{src_ip}->{dst_ip}:{dst_port}/{proto}'
    flow_state = str(record.get('flow_state') or record.get('state') or 'observed')
    bytes_toserver = int(record.get('bytes_toserver') or 0)
    bytes_toclient = int(record.get('bytes_toclient') or 0)
    pkts_toserver = int(record.get('pkts_toserver') or 0)
    pkts_toclient = int(record.get('pkts_toclient') or 0)
    duration_sec = float(record.get('duration_sec') or 0.0)
    anomaly_score = 0
    if flow_state.lower() in {'failed', 'reset', 'timeout'}:
        anomaly_score = max(anomaly_score, 45)
    if bytes_toserver > 0 and bytes_toclient == 0:
        anomaly_score = max(anomaly_score, 20)
    if pkts_toserver >= 20 and pkts_toclient == 0:
        anomaly_score = max(anomaly_score, 35)
    attrs = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'proto': proto,
        'app_proto': str(record.get('app_proto') or ''),
        'flow_state': flow_state,
        'duration_sec': duration_sec,
        'bytes_toserver': bytes_toserver,
        'bytes_toclient': bytes_toclient,
        'pkts_toserver': pkts_toserver,
        'pkts_toclient': pkts_toclient,
        'community_id': str(record.get('community_id') or ''),
        'flow_id': str(record.get('flow_id') or ''),
    }
    return EvidenceEvent.build(
        ts=ts,
        source='flow_min',
        kind='flow_summary',
        subject=subject,
        severity=anomaly_score,
        confidence=0.7,
        attrs=attrs,
        status='warn' if anomaly_score > 0 else 'info',
        evidence_refs=[f"flow:{attrs['flow_id']}"] if attrs['flow_id'] else [],
    )


def iter_flow_jsonl(path: Path) -> Iterable[EvidenceEvent]:
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
                yield adapt_flow_record(payload)

    return _iter()


def read_flow_jsonl(path: Path, limit: Optional[int] = None) -> List[EvidenceEvent]:
    items = list(iter_flow_jsonl(path))
    return items[-limit:] if isinstance(limit, int) and limit > 0 else items
