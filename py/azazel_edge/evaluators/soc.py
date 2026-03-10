from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple

from azazel_edge.ti import ThreatIntelFeed


def _to_payloads(events: Iterable[Any]) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    for event in events:
        if hasattr(event, 'to_dict'):
            payload = event.to_dict()
        elif isinstance(event, dict):
            payload = dict(event)
        else:
            continue
        if str(payload.get('source') or '') in {'suricata_eve', 'flow_min'}:
            payloads.append(payload)
    return payloads


def _bucket(score: int) -> str:
    if score >= 80:
        return 'critical'
    if score >= 60:
        return 'high'
    if score >= 40:
        return 'medium'
    return 'low'


def _make_dimension(score: int, reasons: List[str], evidence_ids: List[str]) -> Dict[str, Any]:
    return {
        'score': max(0, min(100, int(score))),
        'label': _bucket(score),
        'reasons': reasons,
        'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
    }


def _parse_subject(subject: str) -> Tuple[str, str]:
    match = re.match(r'(?P<src>[^-]+)->(?P<dst>[^:]+):', str(subject or ''))
    if not match:
        return '', ''
    return match.group('src'), match.group('dst')


def _candidate_hits(text: str) -> List[str]:
    lowered = text.lower()
    mapping = {
        'T1595 Active Scanning': ['scan', 'scanner', 'recon'],
        'T1110 Brute Force': ['brute', 'password', 'login attempt', 'authentication'],
        'T1190 Exploit Public-Facing Application': ['exploit', 'injection', 'rce', 'web attack'],
        'T1071 Application Layer Protocol': ['dns', 'http', 'beacon', 'c2', 'command and control'],
        'T1021 Remote Services': ['smb', 'rdp', 'ssh', 'telnet'],
    }
    hits = [name for name, needles in mapping.items() if any(needle in lowered for needle in needles)]
    return hits


class SocEvaluator:
    """
    Deterministic SOC evaluator.

    Score semantics are threat-oriented: 100 is most concerning.
    """

    def __init__(self, ti_feed: ThreatIntelFeed | None = None):
        self.ti_feed = ti_feed

    def evaluate(self, events: Iterable[Any]) -> Dict[str, Any]:
        payloads = _to_payloads(events)
        soc_payloads = [item for item in payloads if str(item.get('source') or '') == 'suricata_eve']
        flow_payloads = [item for item in payloads if str(item.get('source') or '') == 'flow_min']
        evidence_ids = [str(item.get('event_id') or '') for item in payloads if str(item.get('event_id') or '')]
        ti_matches = self._match_ti(soc_payloads)

        suspicion = self._evaluate_suspicion(soc_payloads, flow_payloads, ti_matches)
        confidence = self._evaluate_confidence(soc_payloads)
        technique_likelihood, attack_candidates = self._evaluate_technique_likelihood(soc_payloads, flow_payloads, ti_matches)
        blast_radius = self._evaluate_blast_radius(soc_payloads, flow_payloads)

        worst = max(
            int(suspicion['score']),
            int(confidence['score']),
            int(technique_likelihood['score']),
            int(blast_radius['score']),
        ) if payloads else 0
        summary_reasons = []
        for name, dim in (
            ('suspicion', suspicion),
            ('confidence', confidence),
            ('technique_likelihood', technique_likelihood),
            ('blast_radius', blast_radius),
        ):
            if dim['label'] != 'low':
                summary_reasons.append(f'{name}:{dim["label"]}')

        return {
            'suspicion': suspicion,
            'confidence': confidence,
            'technique_likelihood': technique_likelihood,
            'blast_radius': blast_radius,
            'summary': {
                'status': _bucket(worst),
                'reasons': summary_reasons,
                'attack_candidates': attack_candidates,
                'ti_matches': [match.to_dict() for match in ti_matches],
                'event_count': len(payloads),
            },
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }

    def to_arbiter_input(self, evaluation: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'source': 'soc_evaluator',
            'summary': evaluation.get('summary', {}),
            'suspicion': evaluation.get('suspicion', {}),
            'confidence': evaluation.get('confidence', {}),
            'technique_likelihood': evaluation.get('technique_likelihood', {}),
            'blast_radius': evaluation.get('blast_radius', {}),
            'evidence_ids': evaluation.get('evidence_ids', []),
        }

    def _evaluate_suspicion(self, payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]], ti_matches: List[Any]) -> Dict[str, Any]:
        if not payloads:
            return _make_dimension(0, ['no_soc_events'], [])
        evidence_ids: List[str] = []
        reasons: List[str] = []
        top_risk = 0
        for payload in payloads:
            evidence_ids.append(str(payload.get('event_id') or ''))
            attrs = payload.get('attrs', {})
            risk = int(attrs.get('risk_score') or payload.get('severity') or 0)
            top_risk = max(top_risk, risk)
            if risk >= 80:
                reasons.append(f"high_risk_sid:{attrs.get('sid') or 0}")
        if len(payloads) >= 3:
            top_risk = min(100, top_risk + 10)
            reasons.append('repeated_soc_events')
        for payload in flow_payloads:
            attrs = payload.get('attrs', {})
            if str(attrs.get('flow_state') or '').lower() in {'failed', 'reset', 'timeout'}:
                evidence_ids.append(str(payload.get('event_id') or ''))
                top_risk = min(100, top_risk + 5)
                reasons.append('flow_anomaly_support')
        if ti_matches:
            top_risk = min(100, top_risk + 15)
            reasons.append('ti_match_support')
        return _make_dimension(top_risk, reasons, evidence_ids)

    def _evaluate_confidence(self, payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not payloads:
            return _make_dimension(0, ['no_soc_events'], [])
        evidence_ids: List[str] = []
        reasons: List[str] = []
        values: List[int] = []
        for payload in payloads:
            evidence_ids.append(str(payload.get('event_id') or ''))
            attrs = payload.get('attrs', {})
            raw = int(attrs.get('confidence_raw') or round(float(payload.get('confidence') or 0.0) * 100.0))
            values.append(max(0, min(100, raw)))
        score = int(sum(values) / len(values)) if values else 0
        if len(values) == 1:
            score = max(0, score - 10)
            reasons.append('single_event_confidence_penalty')
        if score >= 70:
            reasons.append('consistent_signal')
        return _make_dimension(score, reasons, evidence_ids)

    def _evaluate_technique_likelihood(self, payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]], ti_matches: List[Any]) -> Tuple[Dict[str, Any], List[str]]:
        if not payloads:
            return _make_dimension(0, ['no_soc_events'], []), []
        evidence_ids: List[str] = []
        reasons: List[str] = []
        candidates: List[str] = []
        score = 20
        for payload in payloads:
            evidence_ids.append(str(payload.get('event_id') or ''))
            attrs = payload.get('attrs', {})
            text = f"{attrs.get('attack_type') or ''} {attrs.get('category') or ''}"
            hits = _candidate_hits(text)
            if hits:
                candidates.extend(hits)
                score = max(score, 70)
                reasons.append('attack_keyword_match')
            if int(attrs.get('risk_score') or payload.get('severity') or 0) >= 80:
                score = max(score, 85)
                reasons.append('high_risk_signature')
        if not reasons and payloads:
            score = max(score, 35)
            reasons.append('generic_suricata_signal')
        for payload in flow_payloads:
            attrs = payload.get('attrs', {})
            app_proto = str(attrs.get('app_proto') or '').lower()
            if app_proto in {'dns', 'http', 'tls'}:
                evidence_ids.append(str(payload.get('event_id') or ''))
                score = max(score, 40)
                reasons.append('flow_app_proto_support')
        if ti_matches:
            score = max(score, 75)
            reasons.append('ti_match_support')
        return _make_dimension(score, reasons, evidence_ids), sorted(dict.fromkeys(candidates))

    def _evaluate_blast_radius(self, payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not payloads:
            return _make_dimension(0, ['no_soc_events'], [])
        evidence_ids: List[str] = []
        reasons: List[str] = []
        srcs = set()
        dsts = set()
        ports = set()
        for payload in payloads:
            evidence_ids.append(str(payload.get('event_id') or ''))
            src, dst = _parse_subject(str(payload.get('subject') or ''))
            if src:
                srcs.add(src)
            if dst:
                dsts.add(dst)
            port = int(payload.get('attrs', {}).get('target_port') or 0)
            if port:
                ports.add(port)
        for payload in flow_payloads:
            evidence_ids.append(str(payload.get('event_id') or ''))
            attrs = payload.get('attrs', {})
            src = str(attrs.get('src_ip') or '')
            dst = str(attrs.get('dst_ip') or '')
            port = int(attrs.get('dst_port') or 0)
            if src:
                srcs.add(src)
            if dst:
                dsts.add(dst)
            if port:
                ports.add(port)
        score = min(100, 20 + 10 * len(srcs) + 10 * len(dsts) + 5 * len(ports))
        if len(dsts) > 1:
            reasons.append('multiple_destinations')
        if len(srcs) > 1:
            reasons.append('multiple_sources')
        if len(ports) > 2:
            reasons.append('multiple_service_targets')
        return _make_dimension(score, reasons, evidence_ids)

    def _match_ti(self, payloads: List[Dict[str, Any]]) -> List[Any]:
        if not self.ti_feed or not payloads:
            return []
        ips: List[str] = []
        domains: List[str] = []
        for payload in payloads:
            attrs = payload.get('attrs', {})
            src, dst = _parse_subject(str(payload.get('subject') or ''))
            if src:
                ips.append(src)
            if dst:
                ips.append(dst)
            for key in ('domain', 'hostname', 'fqdn'):
                value = str(attrs.get(key) or '').strip()
                if value:
                    domains.append(value)
        return self.ti_feed.match(ips=ips, domains=domains)
