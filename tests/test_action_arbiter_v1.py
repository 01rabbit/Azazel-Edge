from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.arbiter import ActionArbiter


def _dim(score: int, label: str, evidence_ids: list[str]) -> dict:
    return {'score': score, 'label': label, 'reasons': [], 'evidence_ids': evidence_ids}


def _noc(availability='good', path='good', device='good', client='good') -> dict:
    return {
        'availability': _dim(95, availability, ['noc-a']),
        'path_health': _dim(95, path, ['noc-p']),
        'device_health': _dim(95, device, ['noc-d']),
        'client_health': _dim(95, client, ['noc-c']),
        'summary': {'status': 'good', 'reasons': []},
        'evidence_ids': ['noc-a', 'noc-p', 'noc-d', 'noc-c'],
    }


def _soc(suspicion=20, suspicion_label='low', confidence=30, confidence_label='low', blast=20, blast_label='low') -> dict:
    return {
        'suspicion': _dim(suspicion, suspicion_label, ['soc-s']),
        'confidence': _dim(confidence, confidence_label, ['soc-c']),
        'technique_likelihood': _dim(40, 'medium', ['soc-t']),
        'blast_radius': _dim(blast, blast_label, ['soc-b']),
        'summary': {'status': suspicion_label, 'reasons': []},
        'evidence_ids': ['soc-s', 'soc-c', 'soc-t', 'soc-b'],
    }


class ActionArbiterV1Tests(unittest.TestCase):
    def test_observe_for_low_signal(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(_noc(), _soc())
        self.assertEqual(result['action'], 'observe')
        self.assertTrue(result['chosen_evidence_ids'])
        self.assertTrue(result['rejected_alternatives'])

    def test_throttle_for_high_soc_when_noc_is_stable(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(_noc(), _soc(suspicion=85, suspicion_label='critical', confidence=85, confidence_label='critical', blast=60, blast_label='high'))
        self.assertEqual(result['action'], 'throttle')
        self.assertEqual(result['reason'], 'soc_high_and_reversible_control_is_safe')

    def test_notify_when_soc_is_high_but_noc_is_fragile(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(availability='poor', path='poor'),
            _soc(suspicion=85, suspicion_label='critical', confidence=85, confidence_label='critical', blast=70, blast_label='high'),
        )
        self.assertEqual(result['action'], 'notify')
        self.assertEqual(result['reason'], 'soc_high_but_noc_fragile')

    def test_schema_validation_rejects_invalid_inputs(self) -> None:
        arbiter = ActionArbiter()
        with self.assertRaises(ValueError):
            arbiter.decide({}, _soc())


if __name__ == '__main__':
    unittest.main()
