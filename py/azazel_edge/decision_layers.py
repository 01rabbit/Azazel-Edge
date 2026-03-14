from __future__ import annotations

from typing import Any, Dict, List

from azazel_edge.evaluators import SocEvaluator
from azazel_edge.evidence_plane import adapt_flow_record, adapt_suricata_record


def _normalized_confidence_from_risk(risk_score: int) -> int:
    score = max(0, min(100, int(risk_score)))
    if score >= 85:
        return 90
    if score >= 70:
        return 80
    if score >= 50:
        return 70
    if score >= 30:
        return 60
    return 50


def _build_suricata_record(event: Dict[str, Any], advisory: Dict[str, Any]) -> Dict[str, Any]:
    normalized = event.get('normalized') if isinstance(event.get('normalized'), dict) else {}
    if not isinstance(normalized, dict):
        normalized = {}
    risk_score = int(advisory.get('risk_score') or normalized.get('risk_score') or 0)
    confidence_raw = int(normalized.get('confidence') or _normalized_confidence_from_risk(risk_score))
    return {
        'normalized': {
            'ts': str(normalized.get('ts') or ''),
            'sid': int(normalized.get('sid') or advisory.get('suricata_sid') or 0),
            'severity': int(normalized.get('severity') or advisory.get('suricata_severity') or 0),
            'attack_type': str(normalized.get('attack_type') or advisory.get('attack_type') or ''),
            'category': str(normalized.get('category') or ''),
            'event_type': str(normalized.get('event_type') or 'alert'),
            'action': str(normalized.get('action') or ''),
            'protocol': str(normalized.get('protocol') or ''),
            'target_port': int(normalized.get('target_port') or advisory.get('target_port') or 0),
            'src_ip': str(normalized.get('src_ip') or advisory.get('src_ip') or ''),
            'dst_ip': str(normalized.get('dst_ip') or advisory.get('dst_ip') or ''),
            'risk_score': risk_score,
            'confidence': confidence_raw,
            'ingest_epoch': float(normalized.get('ingest_epoch') or 0.0),
        },
        'defense': event.get('defense') if isinstance(event.get('defense'), dict) else {},
        'pipeline': 'tactical_firstpass',
    }


def _extract_flow_records(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    flow_records: List[Dict[str, Any]] = []
    direct = event.get('flow_records')
    if isinstance(direct, list):
        flow_records.extend(item for item in direct if isinstance(item, dict))
    context = event.get('context')
    if isinstance(context, dict):
        nested = context.get('flow_records')
        if isinstance(nested, list):
            flow_records.extend(item for item in nested if isinstance(item, dict))
    return flow_records


class DecisionLayers:
    """
    Runtime decision layering helper.

    First-pass remains Tactical Engine driven.
    Second-pass enriches the advisory using Evidence Plane normalization and
    deterministic SOC evaluation without replacing the first-minute decision.
    """

    def __init__(self, soc_evaluator: SocEvaluator | None = None):
        self.soc_evaluator = soc_evaluator or SocEvaluator()

    def enrich_with_second_pass(self, event: Dict[str, Any], advisory: Dict[str, Any]) -> Dict[str, Any]:
        suricata_event = adapt_suricata_record(_build_suricata_record(event, advisory))
        evidence_events = [suricata_event]
        flow_records = _extract_flow_records(event)
        for record in flow_records:
            try:
                evidence_events.append(adapt_flow_record(record))
            except Exception:
                continue
        soc = self.soc_evaluator.evaluate(evidence_events)
        summary = soc.get('summary', {}) if isinstance(soc.get('summary'), dict) else {}
        return {
            'stage': 'second_pass',
            'engine': 'evidence_plane_soc_v1',
            'status': 'completed',
            'evidence_count': len(evidence_events),
            'flow_support_count': max(0, len(evidence_events) - 1),
            'soc': {
                'status': str(summary.get('status') or 'low'),
                'reasons': list(summary.get('reasons') or []),
                'attack_candidates': list(summary.get('attack_candidates') or []),
                'ti_matches': list(summary.get('ti_matches') or []),
                'sigma_hits': list(summary.get('sigma_hits') or []),
                'yara_hits': list(summary.get('yara_hits') or []),
                'correlation': summary.get('correlation', {}) if isinstance(summary.get('correlation'), dict) else {},
                'event_count': int(summary.get('event_count') or 0),
                'triage_status': str(summary.get('triage_status') or ''),
                'triage_now_count': int(summary.get('triage_now_count') or 0),
                'incident_count': int(summary.get('incident_count') or 0),
                'visibility_status': str(summary.get('visibility_status') or ''),
                'suppressed_count': int(summary.get('suppressed_count') or 0),
                'top_risky_entities': list(summary.get('top_risky_entities') or []),
                'top_incidents': list(summary.get('top_incidents') or []),
                'entity_risk_state': soc.get('entity_risk_state', {}) if isinstance(soc.get('entity_risk_state'), dict) else {},
                'incident_campaign_state': soc.get('incident_campaign_state', {}) if isinstance(soc.get('incident_campaign_state'), dict) else {},
                'security_visibility_state': soc.get('security_visibility_state', {}) if isinstance(soc.get('security_visibility_state'), dict) else {},
                'suppression_exception_state': soc.get('suppression_exception_state', {}) if isinstance(soc.get('suppression_exception_state'), dict) else {},
                'asset_target_criticality': soc.get('asset_target_criticality', {}) if isinstance(soc.get('asset_target_criticality'), dict) else {},
                'exposure_change_state': soc.get('exposure_change_state', {}) if isinstance(soc.get('exposure_change_state'), dict) else {},
                'confidence_provenance': soc.get('confidence_provenance', {}) if isinstance(soc.get('confidence_provenance'), dict) else {},
                'behavior_sequence_state': soc.get('behavior_sequence_state', {}) if isinstance(soc.get('behavior_sequence_state'), dict) else {},
                'triage_priority_state': soc.get('triage_priority_state', {}) if isinstance(soc.get('triage_priority_state'), dict) else {},
                'evidence_ids': list(soc.get('evidence_ids') or []),
            },
        }
