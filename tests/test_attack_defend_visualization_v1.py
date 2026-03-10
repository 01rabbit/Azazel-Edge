from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.explanations import DecisionExplainer
from azazel_edge.knowledge import AttackDefendKnowledge


class AttackDefendVisualizationV1Tests(unittest.TestCase):
    def test_builds_attack_to_d3fend_graph(self) -> None:
        graph = AttackDefendKnowledge().build_visualization(
            ['T1071 Application Layer Protocol', 'T1190 Exploit Public-Facing Application'],
            ti_matches=[{'indicator_type': 'ip', 'value': '10.0.0.5'}],
        )
        self.assertEqual(graph['format_version'], 'v1')
        self.assertGreaterEqual(graph['attack_count'], 2)
        self.assertGreaterEqual(graph['d3fend_count'], 2)
        self.assertTrue(any(edge['type'] == 'countermeasure' for edge in graph['edges']))
        self.assertTrue(any(edge['type'] == 'supports' for edge in graph['edges']))

    def test_decision_explanation_exposes_visualization_payload(self) -> None:
        result = DecisionExplainer(output_path=Path('/tmp/unused-attack-defend.jsonl')).explain(
            noc={'summary': {'status': 'good'}},
            soc={'summary': {'status': 'critical', 'attack_candidates': ['T1071 Application Layer Protocol'], 'ti_matches': [{'indicator_type': 'ip', 'value': '10.0.0.5'}]}},
            arbiter={
                'action': 'notify',
                'reason': 'soc_high_but_noc_fragile',
                'control_mode': 'none',
                'client_impact': {'score': 0, 'affected_client_count': 0, 'critical_client_count': 0},
                'chosen_evidence_ids': ['ev-1'],
                'rejected_alternatives': [],
            },
        )
        self.assertIn('visualization', result['why_chosen'])
        self.assertGreaterEqual(result['why_chosen']['visualization']['d3fend_count'], 1)


if __name__ == '__main__':
    unittest.main()
