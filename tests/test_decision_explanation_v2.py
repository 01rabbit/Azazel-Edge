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
            noc={'summary': {'status': 'good'}},
            soc={'summary': {'status': 'critical', 'attack_candidates': ['T1071 Application Layer Protocol'], 'ti_matches': [{'indicator_type': 'ip', 'value': '10.0.0.5'}]}},
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


if __name__ == '__main__':
    unittest.main()
