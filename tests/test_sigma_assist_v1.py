from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evaluators import SocEvaluator
from azazel_edge.evidence_plane import EvidenceEvent
from azazel_edge.explanations import DecisionExplainer
from azazel_edge.sigma import MiniSigmaExecutor


def _event() -> EvidenceEvent:
    return EvidenceEvent.build(
        ts='2026-03-10T00:00:00Z',
        source='suricata_eve',
        kind='alert',
        subject='10.0.0.5->192.168.40.10:22/TCP',
        severity=82,
        confidence=0.88,
        attrs={
            'sid': 210020,
            'attack_type': 'SSH Brute Force',
            'category': 'Attempted Administrator Privilege Gain',
            'target_port': 22,
            'risk_score': 82,
            'confidence_raw': 88,
            'src_ip': '10.0.0.5',
            'dst_ip': '192.168.40.10',
        },
        status='alert',
    )


class SigmaAssistV1Tests(unittest.TestCase):
    def test_executor_matches_minimal_rule(self) -> None:
        rule = {
            'id': 'sigma.ssh.bruteforce',
            'title': 'SSH brute force support',
            'source': 'suricata_eve',
            'kind': 'alert',
            'subject_contains': '192.168.40.10',
            'attrs': {'target_port': 22},
            'min_severity': 70,
        }
        hits = MiniSigmaExecutor([rule]).match([_event()])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['rule_id'], 'sigma.ssh.bruteforce')

    def test_soc_evaluator_exposes_sigma_hits(self) -> None:
        evaluator = SocEvaluator(sigma_rules=[{
            'id': 'sigma.ssh.bruteforce',
            'title': 'SSH brute force support',
            'source': 'suricata_eve',
            'kind': 'alert',
            'attrs': {'target_port': 22},
            'min_severity': 70,
        }])
        result = evaluator.evaluate([_event()])
        self.assertIn('sigma_hits', result['summary'])
        self.assertEqual(result['summary']['sigma_hits'][0]['rule_id'], 'sigma.ssh.bruteforce')
        self.assertIn('sigma_support', result['technique_likelihood']['reasons'])

    def test_explanation_mentions_sigma_hits(self) -> None:
        evaluator = SocEvaluator(sigma_rules=[{
            'id': 'sigma.ssh.bruteforce',
            'title': 'SSH brute force support',
            'source': 'suricata_eve',
            'kind': 'alert',
            'attrs': {'target_port': 22},
            'min_severity': 70,
        }])
        soc = evaluator.evaluate([_event()])
        explanation = DecisionExplainer(output_path=Path('/tmp/unused-sigma.jsonl')).explain(
            noc={'summary': {'status': 'good'}},
            soc=soc,
            arbiter={
                'action': 'notify',
                'reason': 'soc_high_but_noc_fragile',
                'control_mode': 'none',
                'client_impact': {'score': 0, 'affected_client_count': 0, 'critical_client_count': 0},
                'chosen_evidence_ids': soc['evidence_ids'],
                'rejected_alternatives': [],
            },
        )
        self.assertIn('sigma_hits', explanation['why_chosen'])
        self.assertIn('Sigma', explanation['operator_wording'])


if __name__ == '__main__':
    unittest.main()
