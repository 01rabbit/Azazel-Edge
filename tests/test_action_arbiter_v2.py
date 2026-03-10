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


class ActionArbiterV2Tests(unittest.TestCase):
    def test_redirect_requires_high_confidence_soc_and_safe_noc(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(),
            _soc(suspicion=92, suspicion_label='critical', confidence=84, confidence_label='critical', blast=72, blast_label='high'),
            client_impact={'score': 20, 'critical_client_count': 0},
        )
        self.assertEqual(result['action'], 'redirect')
        self.assertEqual(result['control_mode'], 'opencanary_redirect')

    def test_isolate_for_extreme_signal_with_low_impact(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(),
            _soc(suspicion=96, suspicion_label='critical', confidence=92, confidence_label='critical', blast=82, blast_label='critical'),
            client_impact={'score': 15, 'critical_client_count': 0},
        )
        self.assertEqual(result['action'], 'isolate')
        self.assertEqual(result['control_mode'], 'segment_isolation')

    def test_high_client_impact_blocks_control_actions(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(),
            _soc(suspicion=96, suspicion_label='critical', confidence=92, confidence_label='critical', blast=82, blast_label='critical'),
            client_impact={'score': 90, 'critical_client_count': 1},
        )
        self.assertEqual(result['action'], 'notify')
        self.assertEqual(result['reason'], 'client_impact_too_high_for_control')


if __name__ == '__main__':
    unittest.main()
