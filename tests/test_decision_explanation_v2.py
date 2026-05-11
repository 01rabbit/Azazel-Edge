from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.explanations import DecisionExplainer


class DecisionExplanationV2Tests(unittest.TestCase):
    def test_explanation_contains_structured_v2_fields(self) -> None:
        explainer = DecisionExplainer(output_path=Path('/tmp/unused-decision-explanations.jsonl'))
        result = explainer.explain(
            noc={
                'summary': {'status': 'good', 'blast_radius': {'affected_uplinks': ['eth1'], 'affected_segments': ['lan-a'], 'affected_client_count': 2}},
                'affected_scope': {'affected_uplinks': ['eth1'], 'affected_segments': ['lan-a'], 'affected_client_count': 2},
                'config_drift_health': {
                    'label': 'degraded',
                    'reasons': ['config_drift_detected', 'config_drift:uplink_preference.preferred_uplink'],
                    'rollback_hint': 'review_changed_fields_and_restore_last_known_good',
                },
                'incident_summary': {
                    'incident_id': 'incident:abc123',
                    'probable_cause': 'resolution_failure',
                    'confidence': 0.88,
                },
            },
            soc={
                'summary': {'status': 'critical', 'attack_candidates': ['T1071 Application Layer Protocol'], 'ai_attack_candidates': ['T1190 Exploit Public-Facing Application'], 'ti_matches': [{'indicator_type': 'ip', 'value': '10.0.0.5'}], 'visibility_status': 'partial', 'suppressed_count': 2, 'triage_now_count': 1},
                'security_visibility_state': {'status': 'partial', 'missing_sources': ['syslog_min']},
                'suppression_exception_state': {'status': 'partial', 'suppressed_count': 2, 'exception_count': 1},
                'asset_target_criticality': {'status': 'critical_targets_observed', 'critical_target_count': 1},
                'exposure_change_state': {'status': 'expanding'},
                'confidence_provenance': {'adjusted_score': 78, 'supports': ['ti_match']},
                'behavior_sequence_state': {'status': 'multi_stage'},
                'triage_priority_state': {'status': 'now', 'now': [{'id': 'inc-1', 'kind': 'incident', 'score': 90}]},
                'incident_campaign_state': {'status': 'active'},
                'entity_risk_state': {'entity_count': 3},
            },
            arbiter={
                'action': 'redirect',
                'reason': 'soc_high_confidence_redirect_is_preferred',
                'control_mode': 'opencanary_redirect',
                'client_impact': {'score': 25, 'affected_client_count': 1, 'critical_client_count': 0},
                'chosen_evidence_ids': ['ev-1'],
                'rejected_alternatives': [],
            },
            target='edge-uplink',
            trace_id='trace-23',
        )
        self.assertEqual(result['format_version'], 'v2')
        self.assertEqual(result['trace_id'], 'trace-23')
        self.assertIn('next_checks', result)
        self.assertIn('attack_candidates', result['why_chosen'])
        self.assertIn('ATT&CK candidates', result['operator_wording'])
        self.assertEqual(result['why_chosen']['affected_scope']['affected_segments'], ['lan-a'])
        self.assertIn('Affected scope: uplinks eth1, segments lan-a, estimated clients 2.', result['operator_wording'])
        self.assertEqual(result['why_chosen']['incident_summary']['incident_id'], 'incident:abc123')
        self.assertIn('Incident summary: incident:abc123 cause=resolution_failure.', result['operator_wording'])
        self.assertIn('Config drift indicators: config_drift_detected, config_drift:uplink_preference.preferred_uplink.', result['operator_wording'])
        self.assertEqual(result['why_chosen']['runbook_support']['runbook_candidate_id'], 'rb.noc.dns.failure.check')
        self.assertIn('Suggested NOC runbook', result['operator_wording'])
        self.assertIn('T1190 Exploit Public-Facing Application', result['why_chosen']['attack_candidates'])
        self.assertIn('soc_states', result['why_chosen'])
        self.assertEqual(result['why_chosen']['soc_states']['security_visibility_state']['status'], 'partial')
        self.assertIn('SOC triage priority: now', result['operator_wording'])
        self.assertIn('trust_capsule', result)
        capsule = result['trust_capsule']
        self.assertEqual(capsule['trace_id'], 'trace-23')
        self.assertEqual(capsule['action'], 'redirect')
        self.assertTrue(capsule['evidence_ids'])
        self.assertTrue(capsule['hmac_sig'])
        self.assertTrue(capsule['ai_contributed'])
        self.assertTrue(capsule['ai_advice_hash'])

    def test_explanation_can_be_persisted_as_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'decision-explanations.jsonl'
            explainer = DecisionExplainer(output_path=path)
            result = explainer.explain(
                noc={'summary': {'status': 'poor'}},
                soc={'summary': {'status': 'high', 'attack_candidates': [], 'ti_matches': []}},
                arbiter={
                    'action': 'notify',
                    'reason': 'soc_high_but_noc_fragile',
                    'control_mode': 'none',
                    'client_impact': {'score': 0, 'affected_client_count': 0, 'critical_client_count': 0},
                    'chosen_evidence_ids': ['ev-1'],
                    'rejected_alternatives': [],
                },
                persist=True,
            )
            rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['why_chosen']['action'], 'notify')
        self.assertEqual(rows[0]['evidence_ids'], result['evidence_ids'])
        self.assertIn('trust_capsule', rows[0])


if __name__ == '__main__':
    unittest.main()
