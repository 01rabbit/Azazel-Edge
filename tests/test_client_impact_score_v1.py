from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.impact import ClientImpactScorer


def _noc() -> dict:
    dim = lambda score, label, ids: {'score': score, 'label': label, 'reasons': [], 'evidence_ids': ids}
    return {
        'availability': dim(95, 'good', ['noc-a']),
        'path_health': dim(95, 'good', ['noc-p']),
        'device_health': dim(95, 'good', ['noc-d']),
        'client_health': dim(95, 'good', ['noc-c']),
        'summary': {'status': 'good', 'reasons': []},
        'evidence_ids': ['noc-a', 'noc-p', 'noc-d', 'noc-c'],
    }


def _soc() -> dict:
    dim = lambda score, label, ids: {'score': score, 'label': label, 'reasons': [], 'evidence_ids': ids}
    return {
        'suspicion': dim(85, 'critical', ['soc-s']),
        'confidence': dim(85, 'critical', ['soc-c']),
        'technique_likelihood': dim(80, 'critical', ['soc-t']),
        'blast_radius': dim(70, 'high', ['soc-b']),
        'summary': {'status': 'critical', 'reasons': []},
        'evidence_ids': ['soc-s', 'soc-c', 'soc-t', 'soc-b'],
    }


class ClientImpactScoreV1Tests(unittest.TestCase):
    def test_scores_affected_and_critical_clients(self) -> None:
        scorer = ClientImpactScorer()
        sot = {
            'devices': [
                {'id': 'd1', 'hostname': 'ops-1', 'ip': '192.168.40.10', 'criticality': 'critical'},
                {'id': 'd2', 'hostname': 'staff-1', 'ip': '192.168.40.11', 'criticality': 'normal'},
            ]
        }
        result = scorer.score('throttle', [
            {
                'event_id': 'soc-1',
                'source': 'suricata_eve',
                'kind': 'alert',
                'subject': '10.0.0.5->192.168.40.10:443/TCP',
                'attrs': {'target_port': 443},
            },
            {
                'event_id': 'flow-1',
                'source': 'flow_min',
                'kind': 'flow_summary',
                'subject': '192.168.40.11->8.8.8.8:53/UDP',
                'attrs': {'dst_port': 53, 'app_proto': 'dns'},
            },
        ], sot=sot)

        self.assertEqual(result['affected_client_count'], 2)
        self.assertEqual(result['critical_client_count'], 1)
        self.assertIn(result['communication_scope'], {'segment', 'multi_client'})
        self.assertGreaterEqual(result['score'], 70)

    def test_arbiter_uses_client_impact_to_avoid_throttle(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(),
            _soc(),
            client_impact={
                'score': 85,
                'critical_client_count': 1,
                'affected_client_count': 2,
                'communication_scope': 'segment',
                'reasons': [],
                'evidence_ids': ['soc-1'],
            },
        )
        self.assertEqual(result['action'], 'notify')
        self.assertEqual(result['reason'], 'client_impact_too_high_for_throttle')

    def test_low_impact_keeps_throttle(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(),
            _soc(),
            client_impact={
                'score': 25,
                'critical_client_count': 0,
                'affected_client_count': 1,
                'communication_scope': 'single_client',
                'reasons': [],
                'evidence_ids': ['soc-1'],
            },
        )
        self.assertEqual(result['action'], 'throttle')


if __name__ == '__main__':
    unittest.main()
