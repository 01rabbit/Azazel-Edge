from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .schema import EvidenceEvent, iso_utc_now


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


def summarize_flow_events(events: Iterable[EvidenceEvent | Dict[str, object]]) -> Optional[EvidenceEvent]:
    flow_rows: List[Dict[str, object]] = []
    for event in events:
        payload = event.to_dict() if hasattr(event, 'to_dict') else (dict(event) if isinstance(event, dict) else {})
        if str(payload.get('kind') or '') != 'flow_summary':
            continue
        attrs = payload.get('attrs', {})
        if not isinstance(attrs, dict):
            continue
        flow_rows.append(attrs)
    if not flow_rows:
        return None

    total_bytes = 0
    total_packets = 0
    by_source: Dict[str, Dict[str, int]] = {}
    by_service: Dict[str, Dict[str, int]] = {}
    latest_ts = ''
    for row in flow_rows:
        src_ip = str(row.get('src_ip') or '-')
        proto = str(row.get('proto') or row.get('app_proto') or 'unknown').upper()
        service = f"{row.get('app_proto') or proto}:{int(row.get('dst_port') or 0)}/{proto}"
        bytes_total = int(row.get('bytes_toserver') or 0) + int(row.get('bytes_toclient') or 0)
        packets_total = int(row.get('pkts_toserver') or 0) + int(row.get('pkts_toclient') or 0)
        total_bytes += bytes_total
        total_packets += packets_total
        by_source.setdefault(src_ip, {'bytes': 0, 'packets': 0, 'flows': 0})
        by_source[src_ip]['bytes'] += bytes_total
        by_source[src_ip]['packets'] += packets_total
        by_source[src_ip]['flows'] += 1
        by_service.setdefault(service, {'bytes': 0, 'packets': 0, 'flows': 0})
        by_service[service]['bytes'] += bytes_total
        by_service[service]['packets'] += packets_total
        by_service[service]['flows'] += 1

    top_sources = [
        {'src_ip': key, **stats}
        for key, stats in sorted(by_source.items(), key=lambda item: (-item[1]['bytes'], item[0]))[:3]
    ]
    top_services = [
        {'service': key, **stats}
        for key, stats in sorted(by_service.items(), key=lambda item: (-item[1]['bytes'], item[0]))[:3]
    ]
    top_source_bytes = int(top_sources[0]['bytes']) if top_sources else 0
    top_service_bytes = int(top_services[0]['bytes']) if top_services else 0
    max_ratio = max(
        (top_source_bytes / total_bytes) if total_bytes > 0 else 0.0,
        (top_service_bytes / total_bytes) if total_bytes > 0 else 0.0,
    )
    severity = 0
    if max_ratio >= 0.8:
        severity = 55
    elif max_ratio >= 0.6:
        severity = 35
    attrs = {
        'total_flows': len(flow_rows),
        'total_bytes': total_bytes,
        'total_packets': total_packets,
        'top_sources': top_sources,
        'top_services': top_services,
        'source_concentration_ratio': round((top_source_bytes / total_bytes), 4) if total_bytes > 0 else 0.0,
        'service_concentration_ratio': round((top_service_bytes / total_bytes), 4) if total_bytes > 0 else 0.0,
        'max_concentration_ratio': round(max_ratio, 4),
        'high_concentration': max_ratio >= 0.6,
    }
    return EvidenceEvent.build(
        ts=latest_ts or iso_utc_now(),
        source='flow_min',
        kind='traffic_concentration',
        subject='flow-window',
        severity=severity,
        confidence=0.8,
        attrs=attrs,
        status='warn' if severity > 0 else 'info',
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
    items = items[-limit:] if isinstance(limit, int) and limit > 0 else items
    summary = summarize_flow_events(items)
    if summary is not None:
        items.append(summary)
    return items
