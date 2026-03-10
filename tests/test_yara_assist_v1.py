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
from azazel_edge.yara import MiniYaraMatcher


def _event() -> EvidenceEvent:
    return EvidenceEvent.build(
        ts='2026-03-10T00:00:00Z',
        source='suricata_eve',
        kind='alert',
        subject='10.0.0.5->192.168.40.10:443/TCP',
        severity=84,
        confidence=0.9,
        attrs={
            'sid': 210030,
            'attack_type': 'Suspicious Loader Beacon',
            'category': 'Potentially Bad Traffic',
            'target_port': 443,
            'risk_score': 84,
            'confidence_raw': 90,
            'sample_name': 'loader_beacon_alpha',
        },
        status='alert',
        evidence_refs=['sample:loader_beacon_alpha'],
    )


class YaraAssistV1Tests(unittest.TestCase):
    def test_matcher_matches_artifact_tokens(self) -> None:
        hits = MiniYaraMatcher([{
            'id': 'yara.loader.alpha',
            'title': 'Loader alpha helper',
            'contains_any': ['loader_beacon_alpha'],
            'source': 'suricata_eve',
        }]).match([_event()])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['rule_id'], 'yara.loader.alpha')

    def test_soc_evaluator_exposes_yara_hits(self) -> None:
        evaluator = SocEvaluator(yara_rules=[{
            'id': 'yara.loader.alpha',
            'title': 'Loader alpha helper',
            'contains_any': ['loader_beacon_alpha'],
            'source': 'suricata_eve',
        }])
        result = evaluator.evaluate([_event()])
        self.assertIn('yara_hits', result['summary'])
        self.assertEqual(result['summary']['yara_hits'][0]['rule_id'], 'yara.loader.alpha')
        self.assertIn('yara_support', result['suspicion']['reasons'])

    def test_explanation_mentions_yara_hits(self) -> None:
        evaluator = SocEvaluator(yara_rules=[{
            'id': 'yara.loader.alpha',
            'title': 'Loader alpha helper',
            'contains_any': ['loader_beacon_alpha'],
            'source': 'suricata_eve',
        }])
        soc = evaluator.evaluate([_event()])
        explanation = DecisionExplainer(output_path=Path('/tmp/unused-yara.jsonl')).explain(
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
        self.assertIn('yara_hits', explanation['why_chosen'])
        self.assertIn('YARA', explanation['operator_wording'])


if __name__ == '__main__':
    unittest.main()
