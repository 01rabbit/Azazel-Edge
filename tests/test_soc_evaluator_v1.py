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


def _event(subject: str, risk: int, confidence_raw: int, attack_type: str, category: str, port: int, sid: int) -> EvidenceEvent:
    return EvidenceEvent.build(
        ts='2026-03-10T00:00:00Z',
        source='suricata_eve',
        kind='alert',
        subject=subject,
        severity=risk,
        confidence=confidence_raw / 100.0,
        attrs={
            'sid': sid,
            'attack_type': attack_type,
            'category': category,
            'target_port': port,
            'risk_score': risk,
            'confidence_raw': confidence_raw,
        },
        status='alert',
    )


class SocEvaluatorV1Tests(unittest.TestCase):
    def test_generates_required_sections_from_soc_events(self) -> None:
        evaluator = SocEvaluator()
        events = [
            _event('10.0.0.5->192.168.40.10:53/UDP', 72, 85, 'Suspicious DNS Beacon', 'Potentially Bad Traffic', 53, 210001),
            _event('10.0.0.5->192.168.40.20:80/TCP', 68, 80, 'Web Attack Attempt', 'Attempted Administrator Privilege Gain', 80, 210002),
        ]
        result = evaluator.evaluate(events)
        for key in ('suspicion', 'confidence', 'technique_likelihood', 'blast_radius', 'summary', 'evidence_ids'):
            self.assertIn(key, result)
        for key in ('suspicion', 'confidence', 'technique_likelihood', 'blast_radius'):
            self.assertIn('score', result[key])
            self.assertIn('label', result[key])

    def test_keeps_evidence_ids(self) -> None:
        evaluator = SocEvaluator()
        event = _event('10.0.0.5->192.168.40.10:53/UDP', 85, 90, 'Suspicious DNS Beacon', 'Potentially Bad Traffic', 53, 210001)
        result = evaluator.evaluate([event])
        for key in ('suspicion', 'confidence', 'technique_likelihood', 'blast_radius'):
            self.assertIn(event.event_id, result[key]['evidence_ids'])
        self.assertIn(event.event_id, result['evidence_ids'])

    def test_attack_candidates_are_supporting_information(self) -> None:
        evaluator = SocEvaluator()
        result = evaluator.evaluate([
            _event('10.0.0.5->192.168.40.10:53/UDP', 85, 90, 'DNS C2 Beacon', 'Potentially Bad Traffic', 53, 210001)
        ])
        self.assertIn('attack_candidates', result['summary'])
        self.assertTrue(result['summary']['attack_candidates'])
        self.assertIn('T1071 Application Layer Protocol', result['summary']['attack_candidates'])

    def test_handoff_payload_is_fixed_schema(self) -> None:
        evaluator = SocEvaluator()
        handoff = evaluator.to_arbiter_input(evaluator.evaluate([]))
        self.assertEqual(handoff['source'], 'soc_evaluator')
        for key in ('summary', 'suspicion', 'confidence', 'technique_likelihood', 'blast_radius', 'evidence_ids'):
            self.assertIn(key, handoff)


if __name__ == '__main__':
    unittest.main()
