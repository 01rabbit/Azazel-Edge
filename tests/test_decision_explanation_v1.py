from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.explanations import DecisionExplainer


class DecisionExplanationV1Tests(unittest.TestCase):
    def test_generates_required_fields(self) -> None:
        explainer = DecisionExplainer()
        result = explainer.explain(
            noc={'summary': {'status': 'good'}},
            soc={'summary': {'status': 'high'}},
            arbiter={
                'action': 'throttle',
                'reason': 'soc_high_and_reversible_control_is_safe',
                'chosen_evidence_ids': ['ev-1', 'ev-2'],
                'rejected_alternatives': [
                    {'action': 'observe', 'reason': 'insufficient_response_for_detected_threat'},
                    {'action': 'notify', 'reason': 'operator_notification_not_primary_choice'},
                ],
            },
            target='gateway',
        )
        for key in ('why_chosen', 'why_not_others', 'evidence_ids', 'operator_wording', 'machine', 'trust_capsule'):
            self.assertIn(key, result)

    def test_operator_wording_contains_action_and_rejected_reasons(self) -> None:
        explainer = DecisionExplainer()
        result = explainer.explain(
            noc={'summary': {'status': 'poor'}},
            soc={'summary': {'status': 'critical'}},
            arbiter={
                'action': 'notify',
                'reason': 'soc_high_but_noc_fragile',
                'chosen_evidence_ids': ['ev-1'],
                'rejected_alternatives': [
                    {'action': 'throttle', 'reason': 'availability_risk_too_high'},
                ],
            },
            target='edge-uplink',
        )
        wording = result['operator_wording']
        self.assertIn('notify', wording)
        self.assertIn('edge-uplink', wording)
        self.assertIn('throttle was rejected because availability_risk_too_high', wording)


if __name__ == '__main__':
    unittest.main()
