from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple

from azazel_edge.correlation import AdvancedCorrelator
from azazel_edge.sigma import MiniSigmaExecutor
from azazel_edge.ti import ThreatIntelFeed
from azazel_edge.yara import MiniYaraMatcher


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


def _parse_port(subject: str) -> int:
    match = re.search(r':(?P<port>\d+)(?:/|$)', str(subject or ''))
    if not match:
        return 0
    return int(match.group('port'))


def _parse_ts(value: Any) -> datetime | None:
    text = str(value or '').strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _is_external_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(value or '').strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


def _to_int_set(values: Any) -> set[int]:
    if not isinstance(values, list):
        return set()
    output: set[int] = set()
    for value in values:
        try:
            output.add(int(value))
        except (TypeError, ValueError):
            continue
    return output


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

    def __init__(
        self,
        ti_feed: ThreatIntelFeed | None = None,
        sigma_rules: Iterable[Dict[str, Any]] | None = None,
        yara_rules: Iterable[Dict[str, Any]] | None = None,
        max_entities: int = 64,
        max_entity_evidence_ids: int = 16,
        max_incidents: int = 32,
        suppression_policy: Dict[str, Any] | None = None,
        criticality: Dict[str, Any] | None = None,
    ):
        self.ti_feed = ti_feed
        self.correlator = AdvancedCorrelator()
        self.sigma = MiniSigmaExecutor(sigma_rules)
        self.yara = MiniYaraMatcher(yara_rules)
        self.max_entities = max(8, int(max_entities))
        self.max_entity_evidence_ids = max(4, int(max_entity_evidence_ids))
        self.max_incidents = max(8, int(max_incidents))
        policy = suppression_policy if isinstance(suppression_policy, dict) else {}
        self.suppression_policy = {
            'src_ips': {str(x) for x in policy.get('src_ips', []) if str(x)},
            'dst_ips': {str(x) for x in policy.get('dst_ips', []) if str(x)},
            'sid': _to_int_set(policy.get('sid', [])),
            'attack_types': {str(x).lower() for x in policy.get('attack_types', []) if str(x)},
            'categories': {str(x).lower() for x in policy.get('categories', []) if str(x)},
        }
        crit = criticality if isinstance(criticality, dict) else {}
        self.criticality = {
            'dst_ips': {str(x) for x in crit.get('dst_ips', []) if str(x)},
            'services': {str(x) for x in crit.get('services', []) if str(x)},
            'segments': {str(x) for x in crit.get('segments', []) if str(x)},
        }
        self._incident_store: Dict[str, Dict[str, Any]] = {}
        self._seen_service_targets: set[str] = set()
        self._seen_external_destinations: set[str] = set()

    def evaluate(self, events: Iterable[Any], sot_diff: Dict[str, Any] | None = None) -> Dict[str, Any]:
        payloads = _to_payloads(events)
        soc_payloads = [item for item in payloads if str(item.get('source') or '') == 'suricata_eve']
        flow_payloads = [item for item in payloads if str(item.get('source') or '') == 'flow_min']
        evidence_ids = [str(item.get('event_id') or '') for item in payloads if str(item.get('event_id') or '')]
        security_visibility_state = self._evaluate_security_visibility_state(soc_payloads, flow_payloads)
        suppression_exception_state, actionable_soc_payloads = self._evaluate_suppression_exception_state(soc_payloads)
        actionable_payloads = actionable_soc_payloads + flow_payloads
        ti_matches = self._match_ti(actionable_soc_payloads)
        correlation = self.correlator.correlate(actionable_payloads)
        sigma_hits = self.sigma.match(actionable_payloads)
        yara_hits = self.yara.match(actionable_payloads)

        suspicion = self._evaluate_suspicion(actionable_soc_payloads, flow_payloads, ti_matches, correlation, yara_hits, sot_diff=sot_diff)
        confidence = self._evaluate_confidence(actionable_soc_payloads)
        technique_likelihood, attack_candidates = self._evaluate_technique_likelihood(actionable_soc_payloads, flow_payloads, ti_matches, correlation, sigma_hits, sot_diff=sot_diff)
        asset_target_criticality = self._evaluate_asset_target_criticality(actionable_soc_payloads, flow_payloads)
        blast_radius = self._evaluate_blast_radius(actionable_soc_payloads, flow_payloads, criticality=asset_target_criticality)
        entity_risk_state = self._evaluate_entity_risk_state(actionable_payloads)
        incident_campaign_state = self._evaluate_incident_campaign_state(actionable_soc_payloads, flow_payloads)
        exposure_change_state = self._evaluate_exposure_change_state(actionable_soc_payloads, flow_payloads)
        behavior_sequence_state = self._evaluate_behavior_sequence_state(actionable_soc_payloads, flow_payloads)
        confidence_provenance = self._evaluate_confidence_provenance(
            confidence=confidence,
            ti_matches=ti_matches,
            correlation=correlation,
            sigma_hits=sigma_hits,
            yara_hits=yara_hits,
            suppression_state=suppression_exception_state,
            visibility_state=security_visibility_state,
            criticality_state=asset_target_criticality,
        )
        triage_priority_state = self._evaluate_triage_priority_state(
            suspicion=suspicion,
            confidence=confidence,
            blast_radius=blast_radius,
            entity_state=entity_risk_state,
            incident_state=incident_campaign_state,
            visibility_state=security_visibility_state,
            suppression_state=suppression_exception_state,
            criticality_state=asset_target_criticality,
            exposure_state=exposure_change_state,
        )

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
        if str(security_visibility_state.get('status') or '') != 'good':
            summary_reasons.append(f'visibility:{security_visibility_state.get("status")}')
        if str(suppression_exception_state.get('status') or '') != 'normal':
            summary_reasons.append(f'suppression:{suppression_exception_state.get("status")}')
        if int(incident_campaign_state.get('active_count') or 0) > 0:
            summary_reasons.append('incident:active')
        if str(triage_priority_state.get('status') or '') in {'now', 'watch'}:
            summary_reasons.append(f'triage:{triage_priority_state.get("status")}')

        return {
            'suspicion': suspicion,
            'confidence': confidence,
            'technique_likelihood': technique_likelihood,
            'blast_radius': blast_radius,
            'entity_risk_state': entity_risk_state,
            'incident_campaign_state': incident_campaign_state,
            'security_visibility_state': security_visibility_state,
            'suppression_exception_state': suppression_exception_state,
            'asset_target_criticality': asset_target_criticality,
            'exposure_change_state': exposure_change_state,
            'confidence_provenance': confidence_provenance,
            'behavior_sequence_state': behavior_sequence_state,
            'triage_priority_state': triage_priority_state,
            'summary': {
                'status': _bucket(worst),
                'reasons': summary_reasons,
                'attack_candidates': attack_candidates,
                'ti_matches': [match.to_dict() for match in ti_matches],
                'correlation': correlation,
                'sigma_hits': sigma_hits,
                'yara_hits': yara_hits,
                'top_risky_entities': [item.get('entity_id') for item in entity_risk_state.get('top_entities', [])[:5] if str(item.get('entity_id') or '')],
                'entity_count': int(entity_risk_state.get('entity_count') or 0),
                'top_incidents': [item.get('incident_id') for item in incident_campaign_state.get('top_incidents', [])[:5] if str(item.get('incident_id') or '')],
                'incident_count': int(incident_campaign_state.get('incident_count') or 0),
                'visibility_status': str(security_visibility_state.get('status') or 'unknown'),
                'suppressed_count': int(suppression_exception_state.get('suppressed_count') or 0),
                'triage_now_count': len(triage_priority_state.get('now', [])) if isinstance(triage_priority_state.get('now'), list) else 0,
                'event_count': len(actionable_payloads),
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
            'entity_risk_state': evaluation.get('entity_risk_state', {}),
            'incident_campaign_state': evaluation.get('incident_campaign_state', {}),
            'security_visibility_state': evaluation.get('security_visibility_state', {}),
            'suppression_exception_state': evaluation.get('suppression_exception_state', {}),
            'asset_target_criticality': evaluation.get('asset_target_criticality', {}),
            'exposure_change_state': evaluation.get('exposure_change_state', {}),
            'confidence_provenance': evaluation.get('confidence_provenance', {}),
            'behavior_sequence_state': evaluation.get('behavior_sequence_state', {}),
            'triage_priority_state': evaluation.get('triage_priority_state', {}),
            'evidence_ids': evaluation.get('evidence_ids', []),
        }

    def _evaluate_suspicion(self, payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]], ti_matches: List[Any], correlation: Dict[str, Any], yara_hits: List[Dict[str, Any]], sot_diff: Dict[str, Any] | None = None) -> Dict[str, Any]:
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
        if int(correlation.get('top_score') or 0) >= 50:
            top_risk = min(100, top_risk + 10)
            reasons.append('correlation_support')
            evidence_ids.extend(str(x) for x in correlation.get('evidence_ids', []) if str(x))
        if yara_hits:
            top_risk = min(100, top_risk + 10)
            reasons.append('yara_support')
            for hit in yara_hits:
                evidence_ids.extend(str(x) for x in hit.get('evidence_ids', []) if str(x))
        if sot_diff:
            if sot_diff.get('unauthorized_services'):
                top_risk = min(100, top_risk + 10)
                reasons.append('unauthorized_service_support')
            if sot_diff.get('path_deviations'):
                top_risk = min(100, top_risk + 5)
                reasons.append('path_deviation_support')
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

    def _evaluate_technique_likelihood(self, payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]], ti_matches: List[Any], correlation: Dict[str, Any], sigma_hits: List[Dict[str, Any]], sot_diff: Dict[str, Any] | None = None) -> Tuple[Dict[str, Any], List[str]]:
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
        if int(correlation.get('top_score') or 0) >= 50:
            score = max(score, 65)
            reasons.append('correlation_support')
            evidence_ids.extend(str(x) for x in correlation.get('evidence_ids', []) if str(x))
        if sigma_hits:
            score = max(score, 70)
            reasons.append('sigma_support')
            for hit in sigma_hits:
                evidence_ids.extend(str(x) for x in hit.get('evidence_ids', []) if str(x))
        if sot_diff and sot_diff.get('unauthorized_services'):
            score = max(score, 60)
            reasons.append('unauthorized_service_support')
        return _make_dimension(score, reasons, evidence_ids), sorted(dict.fromkeys(candidates))

    def _evaluate_blast_radius(self, payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]], criticality: Dict[str, Any] | None = None) -> Dict[str, Any]:
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
        criticality_targets = int((criticality or {}).get('critical_target_count') or 0)
        if criticality_targets > 0:
            score = min(100, score + (10 * min(3, criticality_targets)))
            reasons.append('critical_target_support')
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

    def _evaluate_entity_risk_state(self, payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        store: Dict[str, Dict[str, Any]] = {}
        for payload in payloads:
            subject = str(payload.get('subject') or '')
            attrs = payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {}
            src, dst = _parse_subject(subject)
            src = src or str(attrs.get('src_ip') or '')
            dst = dst or str(attrs.get('dst_ip') or '')
            port = int(attrs.get('dst_port') or attrs.get('target_port') or _parse_port(subject) or 0)
            event_id = str(payload.get('event_id') or '')
            ts = str(payload.get('ts') or '')
            risk = int(attrs.get('risk_score') or payload.get('severity') or 0)
            confidence_raw = int(attrs.get('confidence_raw') or round(float(payload.get('confidence') or 0.0) * 100.0))
            signal = str(attrs.get('attack_type') or attrs.get('category') or payload.get('kind') or 'event')
            weighted_risk = max(0, min(100, int((risk * 0.7) + (confidence_raw * 0.3))))

            entities: List[Tuple[str, str]] = []
            if src:
                entities.append(('src_ip', src))
                entities.append(('client', src))
            if dst:
                entities.append(('dst_ip', dst))
            if dst and port:
                entities.append(('service', f'{dst}:{port}'))
            segment = str(attrs.get('segment') or attrs.get('dst_segment') or attrs.get('src_segment') or '')
            if segment:
                entities.append(('segment', segment))

            for entity_type, entity_id in entities:
                key = f'{entity_type}:{entity_id}'
                row = store.setdefault(
                    key,
                    {
                        'entity_type': entity_type,
                        'entity_id': entity_id,
                        'max_score': 0,
                        'total_score': 0,
                        'event_count': 0,
                        'first_seen': ts,
                        'last_seen': ts,
                        'evidence_ids': [],
                        'signals': [],
                    },
                )
                row['max_score'] = max(int(row['max_score']), weighted_risk)
                row['total_score'] = int(row['total_score']) + weighted_risk
                row['event_count'] = int(row['event_count']) + 1
                row['last_seen'] = ts or row['last_seen']
                if event_id and event_id not in row['evidence_ids']:
                    row['evidence_ids'].append(event_id)
                    if len(row['evidence_ids']) > self.max_entity_evidence_ids:
                        row['evidence_ids'] = row['evidence_ids'][: self.max_entity_evidence_ids]
                if signal and signal not in row['signals']:
                    row['signals'].append(signal)
                    if len(row['signals']) > 5:
                        row['signals'] = row['signals'][:5]

        ranked = sorted(
            store.values(),
            key=lambda item: (int(item['max_score']), int(item['event_count']), str(item['last_seen'])),
            reverse=True,
        )
        bounded = ranked[: self.max_entities]
        top_entities: List[Dict[str, Any]] = []
        for item in bounded:
            score = int(item['max_score'])
            top_entities.append(
                {
                    'entity_type': str(item['entity_type']),
                    'entity_id': str(item['entity_id']),
                    'score': score,
                    'label': _bucket(score),
                    'event_count': int(item['event_count']),
                    'first_seen': str(item['first_seen'] or ''),
                    'last_seen': str(item['last_seen'] or ''),
                    'evidence_ids': list(item['evidence_ids']),
                    'signals': list(item['signals']),
                }
            )

        return {
            'entity_count': len(store),
            'bounded_entity_count': len(top_entities),
            'max_entities': self.max_entities,
            'top_entities': top_entities,
        }

    def _evaluate_security_visibility_state(self, soc_payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        evidence_ids: List[str] = []
        reasons: List[str] = []
        for payload in soc_payloads + flow_payloads:
            event_id = str(payload.get('event_id') or '')
            if event_id:
                evidence_ids.append(event_id)

        soc_count = len(soc_payloads)
        flow_count = len(flow_payloads)
        missing_sources: List[str] = []
        coverage_score = 100

        if soc_count == 0 and flow_count == 0:
            status = 'blind'
            coverage_score = 0
            missing_sources = ['suricata_eve', 'flow_min']
            reasons.append('no_soc_or_flow_evidence')
        elif soc_count == 0:
            status = 'partial'
            coverage_score = 45
            missing_sources = ['suricata_eve']
            reasons.append('missing_suricata_evidence')
        elif flow_count == 0:
            status = 'partial'
            coverage_score = 60
            missing_sources = ['flow_min']
            reasons.append('missing_flow_evidence')
        else:
            status = 'good'
            reasons.append('multi_source_visibility')

        return {
            'status': status,
            'coverage_score': max(0, min(100, int(coverage_score))),
            'soc_event_count': soc_count,
            'flow_event_count': flow_count,
            'missing_sources': missing_sources,
            'reasons': reasons,
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }

    def _evaluate_suppression_exception_state(self, payloads: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        policy = self.suppression_policy
        if not payloads:
            return {
                'status': 'normal',
                'suppressed_count': 0,
                'actionable_count': 0,
                'exception_count': 0,
                'suppressed_ratio': 0.0,
                'reasons': ['no_soc_events'],
                'top_suppressed': [],
                'top_exceptions': [],
                'evidence_ids': [],
            }, []

        actionable: List[Dict[str, Any]] = []
        suppressed: List[Dict[str, Any]] = []
        exceptions: List[Dict[str, Any]] = []
        for payload in payloads:
            attrs = payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {}
            src, dst = _parse_subject(str(payload.get('subject') or ''))
            src = src or str(attrs.get('src_ip') or '')
            dst = dst or str(attrs.get('dst_ip') or '')
            attack_type = str(attrs.get('attack_type') or '').lower()
            category = str(attrs.get('category') or '').lower()
            sid = int(attrs.get('sid') or 0)
            risk = int(attrs.get('risk_score') or payload.get('severity') or 0)
            evidence_id = str(payload.get('event_id') or '')
            matched_reasons: List[str] = []
            if src and src in policy['src_ips']:
                matched_reasons.append('src_ip')
            if dst and dst in policy['dst_ips']:
                matched_reasons.append('dst_ip')
            if sid and sid in policy['sid']:
                matched_reasons.append('sid')
            if attack_type and attack_type in policy['attack_types']:
                matched_reasons.append('attack_type')
            if category and category in policy['categories']:
                matched_reasons.append('category')

            if not matched_reasons:
                actionable.append(payload)
                continue

            if risk >= 90:
                exceptions.append({
                    'event_id': evidence_id,
                    'sid': sid,
                    'risk': risk,
                    'reason': sorted(dict.fromkeys(matched_reasons)),
                })
                actionable.append(payload)
            else:
                suppressed.append({
                    'event_id': evidence_id,
                    'sid': sid,
                    'risk': risk,
                    'reason': sorted(dict.fromkeys(matched_reasons)),
                })

        suppressed_count = len(suppressed)
        actionable_count = len(actionable)
        exception_count = len(exceptions)
        total = len(payloads)
        ratio = (suppressed_count / total) if total else 0.0
        reasons: List[str] = []
        if suppressed_count > 0:
            reasons.append('suppression_policy_applied')
        if exception_count > 0:
            reasons.append('high_risk_exception_escaped_suppression')
        if suppressed_count == 0:
            status = 'normal'
        elif actionable_count == 0:
            status = 'heavy'
            reasons.append('all_soc_events_suppressed')
        elif ratio >= 0.5:
            status = 'partial-heavy'
            reasons.append('majority_soc_events_suppressed')
        else:
            status = 'partial'

        state = {
            'status': status,
            'suppressed_count': suppressed_count,
            'actionable_count': actionable_count,
            'exception_count': exception_count,
            'suppressed_ratio': round(ratio, 3),
            'reasons': reasons or ['no_suppression_policy_hits'],
            'top_suppressed': suppressed[:8],
            'top_exceptions': exceptions[:8],
            'evidence_ids': sorted(dict.fromkeys(str(item.get('event_id') or '') for item in suppressed + exceptions if str(item.get('event_id') or ''))),
        }
        return state, actionable

    def _evaluate_asset_target_criticality(self, soc_payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        targets: Dict[str, Dict[str, Any]] = {}
        evidence_ids: List[str] = []
        for payload in soc_payloads + flow_payloads:
            attrs = payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {}
            src, dst = _parse_subject(str(payload.get('subject') or ''))
            dst = dst or str(attrs.get('dst_ip') or '')
            if not dst:
                continue
            port = int(attrs.get('target_port') or attrs.get('dst_port') or _parse_port(str(payload.get('subject') or '')) or 0)
            segment = str(attrs.get('segment') or attrs.get('dst_segment') or '')
            event_id = str(payload.get('event_id') or '')
            risk = int(attrs.get('risk_score') or payload.get('severity') or 0)
            key = f'{dst}:{port}' if port else dst
            row = targets.setdefault(
                key,
                {
                    'target': key,
                    'dst_ip': dst,
                    'port': port,
                    'segment': segment,
                    'event_count': 0,
                    'max_risk': 0,
                    'is_configured_critical': False,
                    'critical_reasons': [],
                    'evidence_ids': [],
                },
            )
            row['event_count'] = int(row['event_count']) + 1
            row['max_risk'] = max(int(row['max_risk']), risk)
            if event_id and event_id not in row['evidence_ids']:
                row['evidence_ids'].append(event_id)
            if event_id:
                evidence_ids.append(event_id)

            configured_reasons: List[str] = []
            if dst in self.criticality['dst_ips']:
                configured_reasons.append('dst_ip')
            if segment and segment in self.criticality['segments']:
                configured_reasons.append('segment')
            service_id = f'{dst}:{port}' if port else dst
            if service_id in self.criticality['services'] or str(port) in self.criticality['services']:
                configured_reasons.append('service')
            if configured_reasons:
                row['is_configured_critical'] = True
                for reason in configured_reasons:
                    if reason not in row['critical_reasons']:
                        row['critical_reasons'].append(reason)

        ranked: List[Dict[str, Any]] = []
        critical_target_count = 0
        max_score = 0
        for row in targets.values():
            target_score = int(row['max_risk'])
            if row['is_configured_critical']:
                target_score = min(100, target_score + 25)
                critical_target_count += 1
            max_score = max(max_score, target_score)
            ranked.append(
                {
                    'target': str(row['target']),
                    'dst_ip': str(row['dst_ip']),
                    'port': int(row['port']),
                    'segment': str(row['segment']),
                    'score': target_score,
                    'label': _bucket(target_score),
                    'event_count': int(row['event_count']),
                    'is_configured_critical': bool(row['is_configured_critical']),
                    'critical_reasons': list(row['critical_reasons']),
                    'evidence_ids': list(row['evidence_ids'])[: self.max_entity_evidence_ids],
                }
            )
        ranked.sort(key=lambda item: (int(item['score']), int(item['event_count'])), reverse=True)

        status = 'normal'
        reasons: List[str] = []
        if not ranked:
            status = 'no_targets'
            reasons.append('no_destination_evidence')
        elif critical_target_count > 0:
            status = 'critical_targets_observed'
            reasons.append('configured_critical_targets_hit')
        else:
            reasons.append('no_configured_critical_targets_hit')

        return {
            'status': status,
            'score': max_score,
            'label': _bucket(max_score),
            'target_count': len(ranked),
            'critical_target_count': critical_target_count,
            'top_targets': ranked[:10],
            'reasons': reasons,
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }

    def _evaluate_incident_campaign_state(self, soc_payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        now_ts = datetime.now(timezone.utc)
        for payload in soc_payloads:
            attrs = payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {}
            src, dst = _parse_subject(str(payload.get('subject') or ''))
            src = src or str(attrs.get('src_ip') or '')
            dst = dst or str(attrs.get('dst_ip') or '')
            port = int(attrs.get('target_port') or attrs.get('dst_port') or _parse_port(str(payload.get('subject') or '')) or 0)
            attack_type = str(attrs.get('attack_type') or attrs.get('category') or payload.get('kind') or 'alert').strip().lower()
            risk = int(attrs.get('risk_score') or payload.get('severity') or 0)
            event_id = str(payload.get('event_id') or '')
            ts = _parse_ts(payload.get('ts')) or now_ts

            fingerprint = f'{src}|{dst}|{port}|{attack_type}'
            incident_id = 'inc-' + hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()[:12]
            row = self._incident_store.setdefault(
                incident_id,
                {
                    'incident_id': incident_id,
                    'src': src,
                    'dst': dst,
                    'port': port,
                    'attack_type': attack_type,
                    'first_seen': ts.isoformat(),
                    'last_seen': ts.isoformat(),
                    'event_count': 0,
                    'max_score': 0,
                    'evidence_ids': [],
                    'supporting_flow_count': 0,
                },
            )
            row['last_seen'] = ts.isoformat()
            row['event_count'] = int(row['event_count']) + 1
            row['max_score'] = max(int(row['max_score']), risk)
            if event_id and event_id not in row['evidence_ids']:
                row['evidence_ids'].append(event_id)

        if flow_payloads and self._incident_store:
            for payload in flow_payloads:
                attrs = payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {}
                src = str(attrs.get('src_ip') or '')
                dst = str(attrs.get('dst_ip') or '')
                flow_eid = str(payload.get('event_id') or '')
                for row in self._incident_store.values():
                    if src and dst and src == str(row.get('src') or '') and dst == str(row.get('dst') or ''):
                        row['supporting_flow_count'] = int(row.get('supporting_flow_count') or 0) + 1
                        if flow_eid and flow_eid not in row['evidence_ids']:
                            row['evidence_ids'].append(flow_eid)

        ranked = sorted(
            self._incident_store.values(),
            key=lambda item: (int(item.get('max_score') or 0), int(item.get('event_count') or 0), str(item.get('last_seen') or '')),
            reverse=True,
        )
        if len(ranked) > self.max_incidents:
            kept = ranked[: self.max_incidents]
            keep_ids = {str(item.get('incident_id') or '') for item in kept}
            self._incident_store = {
                key: value for key, value in self._incident_store.items() if key in keep_ids
            }
            ranked = kept

        top_incidents: List[Dict[str, Any]] = []
        all_evidence_ids: List[str] = []
        for item in ranked:
            max_score = int(item.get('max_score') or 0)
            event_count = int(item.get('event_count') or 0)
            confidence = min(100, max_score + min(20, event_count * 4))
            top_incidents.append(
                {
                    'incident_id': str(item.get('incident_id') or ''),
                    'src': str(item.get('src') or ''),
                    'dst': str(item.get('dst') or ''),
                    'port': int(item.get('port') or 0),
                    'attack_type': str(item.get('attack_type') or ''),
                    'first_seen': str(item.get('first_seen') or ''),
                    'last_seen': str(item.get('last_seen') or ''),
                    'event_count': event_count,
                    'supporting_flow_count': int(item.get('supporting_flow_count') or 0),
                    'score': max_score,
                    'label': _bucket(max_score),
                    'confidence': confidence,
                    'evidence_ids': list(item.get('evidence_ids') or [])[: self.max_entity_evidence_ids],
                }
            )
            all_evidence_ids.extend(str(x) for x in item.get('evidence_ids', []) if str(x))

        active_count = len(top_incidents)
        return {
            'status': 'active' if active_count else 'none',
            'incident_count': len(self._incident_store),
            'active_count': active_count,
            'max_incidents': self.max_incidents,
            'top_incidents': top_incidents[: self.max_incidents],
            'evidence_ids': sorted(dict.fromkeys(all_evidence_ids)),
            'reasons': ['incident_clustered'] if active_count else ['no_soc_events'],
        }

    def _evaluate_exposure_change_state(self, soc_payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        current_services: set[str] = set()
        current_external_dsts: set[str] = set()
        evidence_ids: List[str] = []

        for payload in soc_payloads + flow_payloads:
            attrs = payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {}
            src, dst = _parse_subject(str(payload.get('subject') or ''))
            dst = dst or str(attrs.get('dst_ip') or '')
            if not dst:
                continue
            port = int(attrs.get('target_port') or attrs.get('dst_port') or _parse_port(str(payload.get('subject') or '')) or 0)
            if port:
                current_services.add(f'{dst}:{port}')
            if _is_external_ip(dst):
                current_external_dsts.add(dst)
            event_id = str(payload.get('event_id') or '')
            if event_id:
                evidence_ids.append(event_id)

        new_services = current_services.difference(self._seen_service_targets)
        new_external = current_external_dsts.difference(self._seen_external_destinations)
        self._seen_service_targets.update(current_services)
        self._seen_external_destinations.update(current_external_dsts)
        if len(self._seen_service_targets) > 2048:
            self._seen_service_targets = set(sorted(self._seen_service_targets)[-2048:])
        if len(self._seen_external_destinations) > 1024:
            self._seen_external_destinations = set(sorted(self._seen_external_destinations)[-1024:])

        score = min(100, (len(new_external) * 20) + (len(new_services) * 6))
        reasons: List[str] = []
        if new_external:
            reasons.append('new_external_destination')
        if new_services:
            reasons.append('new_service_target')
        if not reasons:
            reasons.append('no_new_exposure')

        return {
            'status': 'expanding' if (new_external or new_services) else 'stable',
            'score': score,
            'label': _bucket(score),
            'new_external_destinations': sorted(new_external)[:12],
            'new_service_targets': sorted(new_services)[:12],
            'seen_external_destination_count': len(self._seen_external_destinations),
            'seen_service_target_count': len(self._seen_service_targets),
            'reasons': reasons,
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }

    def _evaluate_behavior_sequence_state(self, soc_payloads: List[Dict[str, Any]], flow_payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        def infer_stage(payload: Dict[str, Any]) -> str:
            attrs = payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {}
            text = f"{attrs.get('attack_type') or ''} {attrs.get('category') or ''} {payload.get('kind') or ''}".lower()
            if any(term in text for term in ('scan', 'recon', 'discovery', 'probe')):
                return 'recon'
            if any(term in text for term in ('brute', 'auth', 'login', 'exploit', 'access')):
                return 'access'
            if any(term in text for term in ('lateral', 'rdp', 'smb', 'ssh', 'remote service')):
                return 'lateral'
            if any(term in text for term in ('c2', 'beacon', 'command and control', 'dns tunnel', 'exfil')):
                return 'command'
            if any(term in text for term in ('impact', 'ransom', 'destroy', 'wiper')):
                return 'impact'
            return 'unknown'

        rows: List[Tuple[datetime, str, str]] = []
        evidence_ids: List[str] = []
        for payload in soc_payloads + flow_payloads:
            stage = infer_stage(payload)
            ts = _parse_ts(payload.get('ts')) or datetime.now(timezone.utc)
            event_id = str(payload.get('event_id') or '')
            rows.append((ts, stage, event_id))
            if event_id:
                evidence_ids.append(event_id)

        if not rows:
            return {
                'status': 'none',
                'score': 0,
                'label': _bucket(0),
                'stage_sequence': [],
                'distinct_stage_count': 0,
                'reasons': ['no_soc_events'],
                'evidence_ids': [],
            }

        rows.sort(key=lambda row: row[0])
        ordered: List[str] = []
        for _, stage, _ in rows:
            if not ordered or ordered[-1] != stage:
                ordered.append(stage)
        distinct_non_unknown = [stage for stage in ordered if stage != 'unknown']
        distinct_count = len(distinct_non_unknown)
        score = min(100, 20 + (distinct_count * 20))
        if 'recon' in ordered and 'command' in ordered:
            score = min(100, score + 15)
        if 'access' in ordered and 'lateral' in ordered:
            score = min(100, score + 10)

        if distinct_count >= 3:
            status = 'multi_stage'
        elif distinct_count >= 1:
            status = 'single_stage'
        else:
            status = 'unknown_stage'

        reasons: List[str] = []
        if status == 'multi_stage':
            reasons.append('attack_progression_observed')
        elif status == 'single_stage':
            reasons.append('single_stage_signal')
        else:
            reasons.append('insufficient_stage_signal')

        return {
            'status': status,
            'score': score,
            'label': _bucket(score),
            'stage_sequence': ordered[:8],
            'distinct_stage_count': distinct_count,
            'reasons': reasons,
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }

    def _evaluate_confidence_provenance(
        self,
        confidence: Dict[str, Any],
        ti_matches: List[Any],
        correlation: Dict[str, Any],
        sigma_hits: List[Dict[str, Any]],
        yara_hits: List[Dict[str, Any]],
        suppression_state: Dict[str, Any],
        visibility_state: Dict[str, Any],
        criticality_state: Dict[str, Any],
    ) -> Dict[str, Any]:
        base_score = int(confidence.get('score') or 0)
        evidence_ids: List[str] = list(confidence.get('evidence_ids') or [])
        supports: List[str] = []
        weakens: List[str] = []
        adjusted_score = base_score

        if ti_matches:
            adjusted_score = min(100, adjusted_score + 10)
            supports.append('ti_match')
        if int(correlation.get('top_score') or 0) >= 50:
            adjusted_score = min(100, adjusted_score + 8)
            supports.append('correlation')
            evidence_ids.extend(str(x) for x in correlation.get('evidence_ids', []) if str(x))
        if sigma_hits:
            adjusted_score = min(100, adjusted_score + 6)
            supports.append('sigma')
            for hit in sigma_hits:
                evidence_ids.extend(str(x) for x in hit.get('evidence_ids', []) if str(x))
        if yara_hits:
            adjusted_score = min(100, adjusted_score + 6)
            supports.append('yara')
            for hit in yara_hits:
                evidence_ids.extend(str(x) for x in hit.get('evidence_ids', []) if str(x))
        if str(visibility_state.get('status') or '') in {'blind', 'partial'}:
            adjusted_score = max(0, adjusted_score - 15)
            weakens.append('limited_visibility')
        if str(suppression_state.get('status') or '') in {'heavy', 'partial-heavy'}:
            adjusted_score = max(0, adjusted_score - 10)
            weakens.append('heavy_suppression')
        if int(criticality_state.get('critical_target_count') or 0) > 0:
            supports.append('critical_targeting_context')

        if adjusted_score >= 75:
            quality = 'high'
        elif adjusted_score >= 50:
            quality = 'medium'
        else:
            quality = 'low'

        return {
            'status': quality,
            'base_score': base_score,
            'adjusted_score': adjusted_score,
            'supports': sorted(dict.fromkeys(supports)),
            'weakens': sorted(dict.fromkeys(weakens)),
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }

    def _evaluate_triage_priority_state(
        self,
        suspicion: Dict[str, Any],
        confidence: Dict[str, Any],
        blast_radius: Dict[str, Any],
        entity_state: Dict[str, Any],
        incident_state: Dict[str, Any],
        visibility_state: Dict[str, Any],
        suppression_state: Dict[str, Any],
        criticality_state: Dict[str, Any],
        exposure_state: Dict[str, Any],
    ) -> Dict[str, Any]:
        suspicion_score = int(suspicion.get('score') or 0)
        confidence_score = int(confidence.get('score') or 0)
        blast_score = int(blast_radius.get('score') or 0)
        critical_score = int(criticality_state.get('score') or 0)
        exposure_score = int(exposure_state.get('score') or 0)

        base = int(
            (suspicion_score * 0.35)
            + (confidence_score * 0.25)
            + (blast_score * 0.20)
            + (critical_score * 0.10)
            + (exposure_score * 0.10)
        )
        if str(visibility_state.get('status') or '') == 'blind':
            base = min(100, base + 10)
        if str(suppression_state.get('status') or '') in {'heavy', 'partial-heavy'}:
            base = min(100, base + 8)
        if int(incident_state.get('active_count') or 0) > 0:
            base = min(100, base + 6)
        base = max(0, min(100, base))

        rows: List[Dict[str, Any]] = []
        for incident in incident_state.get('top_incidents', []) if isinstance(incident_state.get('top_incidents'), list) else []:
            incident_score = int(incident.get('score') or 0)
            event_count = int(incident.get('event_count') or 0)
            rows.append(
                {
                    'id': str(incident.get('incident_id') or ''),
                    'kind': 'incident',
                    'score': min(100, int((incident_score * 0.7) + (event_count * 4) + (base * 0.3))),
                    'evidence_ids': list(incident.get('evidence_ids') or []),
                }
            )
        for entity in entity_state.get('top_entities', []) if isinstance(entity_state.get('top_entities'), list) else []:
            rows.append(
                {
                    'id': str(entity.get('entity_id') or ''),
                    'kind': 'entity',
                    'score': min(100, int((int(entity.get('score') or 0) * 0.7) + (base * 0.3))),
                    'evidence_ids': list(entity.get('evidence_ids') or []),
                }
            )
        rows.sort(key=lambda item: int(item['score']), reverse=True)
        rows = rows[:20]

        now: List[Dict[str, Any]] = []
        watch: List[Dict[str, Any]] = []
        later: List[Dict[str, Any]] = []
        evidence_ids: List[str] = []
        for row in rows:
            score = int(row['score'])
            item = {
                'id': str(row['id']),
                'kind': str(row['kind']),
                'score': score,
            }
            if score >= 75:
                now.append(item)
            elif score >= 50:
                watch.append(item)
            else:
                later.append(item)
            evidence_ids.extend(str(x) for x in row.get('evidence_ids', []) if str(x))

        if base >= 75:
            status = 'now'
        elif base >= 50:
            status = 'watch'
        elif base >= 25:
            status = 'later'
        else:
            status = 'idle'

        reasons: List[str] = []
        if now:
            reasons.append('high_priority_items_present')
        if str(visibility_state.get('status') or '') in {'blind', 'partial'}:
            reasons.append('visibility_gap_requires_operator_attention')
        if str(suppression_state.get('status') or '') in {'heavy', 'partial-heavy'}:
            reasons.append('suppression_risk_review_needed')
        if not reasons:
            reasons.append('no_immediate_triage_pressure')

        return {
            'status': status,
            'score': base,
            'label': _bucket(base),
            'now': now[:8],
            'watch': watch[:8],
            'later': later[:8],
            'reasons': reasons,
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }
