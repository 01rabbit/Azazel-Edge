from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, DefaultDict, Dict, Iterable, List, Set, Tuple


def _to_payloads(events: Iterable[Any]) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    for event in events:
        if hasattr(event, 'to_dict'):
            payload = event.to_dict()
        elif isinstance(event, dict):
            payload = dict(event)
        else:
            continue
        if isinstance(payload.get('attrs'), dict):
            payloads.append(payload)
    return payloads


def _parse_subject(subject: str) -> Tuple[str, str, int]:
    match = re.match(r'(?P<src>[^-]+)->(?P<dst>[^:]+):(?P<port>\d+)', str(subject or ''))
    if not match:
        return '', '', 0
    return match.group('src'), match.group('dst'), int(match.group('port') or 0)


def _parse_ts(ts: str) -> datetime:
    text = str(ts or '').strip()
    if text.endswith('Z'):
        text = f'{text[:-1]}+00:00'
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc)


class AdvancedCorrelator:
    """
    Lightweight cross-source correlator.

    This stays deterministic and intentionally small:
    - groups by src/dst/port and by per-IP participation
    - requires multi-source support
    - exposes cluster summary for SOC/explanation consumers
    """

    def correlate(self, events: Iterable[Any]) -> Dict[str, Any]:
        payloads = _to_payloads(events)
        pair_groups: DefaultDict[Tuple[str, str, int], List[Dict[str, Any]]] = defaultdict(list)
        ip_groups: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
        target_groups: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)

        for payload in payloads:
            src, dst, port = self._extract_endpoints(payload)
            if src and dst:
                pair_groups[(src, dst, port)].append(payload)
                target_groups[dst].append(payload)
            for ip in {src, dst} - {''}:
                ip_groups[ip].append(payload)

        clusters: List[Dict[str, Any]] = []
        for key, group in pair_groups.items():
            cluster = self._build_pair_cluster(key, group)
            if cluster:
                clusters.append(cluster)
        for ip, group in ip_groups.items():
            cluster = self._build_ip_cluster(ip, group)
            if cluster:
                clusters.append(cluster)
        for dst, group in target_groups.items():
            cluster = self._build_target_cluster(dst, group)
            if cluster:
                clusters.append(cluster)

        deduped: Dict[str, Dict[str, Any]] = {}
        for cluster in clusters:
            cluster_id = str(cluster.get('correlation_id') or '')
            current = deduped.get(cluster_id)
            if current is None or int(cluster.get('score') or 0) > int(current.get('score') or 0):
                deduped[cluster_id] = cluster

        merged = sorted(deduped.values(), key=lambda item: int(item.get('score') or 0), reverse=True)
        evidence_ids: List[str] = []
        reasons: List[str] = []
        for cluster in merged:
            evidence_ids.extend(str(x) for x in cluster.get('evidence_ids', []) if str(x))
            reasons.extend(str(x) for x in cluster.get('reasons', []) if str(x))
        top_score = max((int(cluster.get('score') or 0) for cluster in merged), default=0)
        status = 'none'
        if top_score >= 80:
            status = 'critical'
        elif top_score >= 50:
            status = 'high'
        elif top_score >= 40:
            status = 'medium'
        elif top_score > 0:
            status = 'low'

        return {
            'status': status,
            'cluster_count': len(merged),
            'top_score': top_score,
            'clusters': merged,
            'reasons': sorted(dict.fromkeys(reasons)),
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }

    def _extract_endpoints(self, payload: Dict[str, Any]) -> Tuple[str, str, int]:
        attrs = payload.get('attrs', {})
        src = str(attrs.get('src_ip') or '')
        dst = str(attrs.get('dst_ip') or '')
        port = int(attrs.get('dst_port') or attrs.get('target_port') or 0)
        if src and dst:
            return src, dst, port
        subj_src, subj_dst, subj_port = _parse_subject(str(payload.get('subject') or ''))
        return src or subj_src, dst or subj_dst, port or subj_port

    def _build_pair_cluster(self, key: Tuple[str, str, int], group: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        sources = {str(item.get('source') or '') for item in group if str(item.get('source') or '')}
        if len(group) < 2 or len(sources) < 2:
            return None
        src, dst, port = key
        reasons: List[str] = ['multi_source_pair']
        score = 20 + 5 * len(sources)
        kinds = {str(item.get('kind') or '') for item in group if str(item.get('kind') or '')}
        if {'suricata_eve', 'flow_min'}.issubset(sources):
            score += 15
            reasons.append('suricata_flow_alignment')
        if 'syslog_min' in sources:
            score += 8
            reasons.append('syslog_support')
        if 'noc_probe' in sources:
            score += 8
            reasons.append('noc_support')
        if len(kinds) > 1:
            score += 4
            reasons.append('multi_kind_alignment')
        if self._within_window(group, 300):
            score += 4
            reasons.append('time_proximity')
        seq_bonus, seq_reasons = self._sequence_bonus(group)
        score += seq_bonus
        reasons.extend(seq_reasons)
        return {
            'correlation_id': f'pair:{src}:{dst}:{port}',
            'scope': 'pair',
            'subject': f'{src}->{dst}:{port}',
            'score': min(100, score),
            'sources': sorted(sources),
            'kinds': sorted(kinds),
            'reasons': reasons,
            'evidence_ids': sorted(dict.fromkeys(str(item.get('event_id') or '') for item in group if str(item.get('event_id') or ''))),
        }

    def _build_ip_cluster(self, ip: str, group: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        sources = {str(item.get('source') or '') for item in group if str(item.get('source') or '')}
        if len(group) < 3 or len(sources) < 2:
            return None
        score = 15 + 5 * len(sources)
        reasons: List[str] = ['shared_ip_multi_source']
        if self._within_window(group, 300):
            score += 4
            reasons.append('time_proximity')
        if 'suricata_eve' in sources and 'flow_min' in sources:
            score += 8
            reasons.append('suricata_flow_same_ip')
        if 'syslog_min' in sources:
            score += 4
            reasons.append('syslog_same_ip')
        seq_bonus, seq_reasons = self._sequence_bonus(group)
        score += seq_bonus
        reasons.extend(seq_reasons)
        return {
            'correlation_id': f'ip:{ip}',
            'scope': 'ip',
            'subject': ip,
            'score': min(100, score),
            'sources': sorted(sources),
            'kinds': sorted({str(item.get('kind') or '') for item in group if str(item.get('kind') or '')}),
            'reasons': reasons,
            'evidence_ids': sorted(dict.fromkeys(str(item.get('event_id') or '') for item in group if str(item.get('event_id') or ''))),
        }

    def _build_target_cluster(self, dst: str, group: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        sources = {str(item.get('source') or '') for item in group if str(item.get('source') or '')}
        src_ips: Set[str] = set()
        for item in group:
            attrs = item.get('attrs', {}) if isinstance(item.get('attrs'), dict) else {}
            src = str(attrs.get('src_ip') or '')
            if not src:
                src, _subj_dst, _port = _parse_subject(str(item.get('subject') or ''))
            if src:
                src_ips.add(src)
        if len(src_ips) < 3 or len(sources) < 2:
            return None

        score = 30 + (len(src_ips) * 8) + (len(sources) * 4)
        reasons: List[str] = ['multi_source_single_target']
        if self._within_window(group, 300):
            score += 8
            reasons.append('distributed_scan_window')
        if 'suricata_eve' in sources and 'flow_min' in sources:
            score += 10
            reasons.append('suricata_flow_target_alignment')
        if 'syslog_min' in sources:
            score += 6
            reasons.append('syslog_target_support')
        seq_bonus, seq_reasons = self._sequence_bonus(group)
        score += seq_bonus
        reasons.extend(seq_reasons)
        return {
            'correlation_id': f'target:{dst}',
            'scope': 'target',
            'subject': dst,
            'score': min(100, score),
            'sources': sorted(sources),
            'src_ip_count': len(src_ips),
            'src_ips': sorted(src_ips)[:16],
            'kinds': sorted({str(item.get('kind') or '') for item in group if str(item.get('kind') or '')}),
            'reasons': reasons,
            'evidence_ids': sorted(dict.fromkeys(str(item.get('event_id') or '') for item in group if str(item.get('event_id') or ''))),
        }

    @staticmethod
    def _sequence_bonus(group: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
        stage_rank = {'observe': 1, 'notify': 2, 'throttle': 3, 'redirect': 3, 'isolate': 4}
        rows = sorted(group, key=lambda item: _parse_ts(str(item.get('ts') or '')))
        stages: List[str] = []
        for item in rows:
            attrs = item.get('attrs', {}) if isinstance(item.get('attrs'), dict) else {}
            raw = str(
                attrs.get('recommended_action')
                or attrs.get('action')
                or item.get('action')
                or ''
            ).strip().lower()
            if raw in stage_rank:
                if not stages or stages[-1] != raw:
                    stages.append(raw)
        if len(stages) < 2:
            return 0, []
        ranks = [stage_rank[s] for s in stages]
        if ranks == sorted(ranks) and len(set(ranks)) >= 3 and {'observe', 'notify'}.issubset(set(stages)):
            if 'throttle' in stages or 'redirect' in stages:
                return 15, ['sequence_escalation']
        if ranks == sorted(ranks) and len(set(ranks)) >= 2:
            return 6, ['sequence_progression']
        return 0, []

    @staticmethod
    def _within_window(group: List[Dict[str, Any]], seconds: int) -> bool:
        timestamps = sorted(_parse_ts(str(item.get('ts') or '')) for item in group if str(item.get('ts') or ''))
        if len(timestamps) < 2:
            return False
        delta = timestamps[-1] - timestamps[0]
        return delta.total_seconds() <= seconds
