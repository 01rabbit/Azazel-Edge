from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.decision_layers import DecisionLayers


class DecisionLayersV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.layers = DecisionLayers()

    def test_enriches_tactical_event_with_second_pass_soc_summary(self) -> None:
        event = {
            'normalized': {
                'ts': '2026-03-12T00:00:00Z',
                'sid': 210001,
                'severity': 2,
                'attack_type': 'DNS C2 Beacon',
                'category': 'Potentially Bad Traffic',
                'event_type': 'alert',
                'action': 'allowed',
                'protocol': 'UDP',
                'target_port': 53,
                'src_ip': '10.0.0.5',
                'dst_ip': '192.168.40.10',
            }
        }
        advisory = {
            'risk_score': 85,
            'suricata_sid': 210001,
            'suricata_severity': 2,
            'attack_type': 'DNS C2 Beacon',
            'src_ip': '10.0.0.5',
            'dst_ip': '192.168.40.10',
            'target_port': 53,
        }
        result = self.layers.enrich_with_second_pass(event, advisory)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['engine'], 'evidence_plane_soc_v1')
        self.assertIn('soc', result)
        self.assertIn('status', result['soc'])
        self.assertIn('attack_candidates', result['soc'])
        self.assertGreaterEqual(result['evidence_count'], 1)

    def test_uses_optional_flow_records_for_correlation_context(self) -> None:
        event = {
            'normalized': {
                'ts': '2026-03-12T00:00:00Z',
                'sid': 210002,
                'severity': 1,
                'attack_type': 'Suspicious DNS Beacon',
                'category': 'Potentially Bad Traffic',
                'event_type': 'alert',
                'action': 'allowed',
                'protocol': 'UDP',
                'target_port': 53,
                'src_ip': '10.0.0.5',
                'dst_ip': '192.168.40.10',
            },
            'flow_records': [
                {
                    'ts': '2026-03-12T00:00:01Z',
                    'src_ip': '10.0.0.5',
                    'dst_ip': '192.168.40.10',
                    'dst_port': 53,
                    'proto': 'UDP',
                    'flow_state': 'failed',
                    'app_proto': 'dns',
                    'flow_id': 'f-1',
                }
            ],
        }
        advisory = {
            'risk_score': 88,
            'suricata_sid': 210002,
            'suricata_severity': 1,
            'attack_type': 'Suspicious DNS Beacon',
            'src_ip': '10.0.0.5',
            'dst_ip': '192.168.40.10',
            'target_port': 53,
        }
        result = self.layers.enrich_with_second_pass(event, advisory)
        self.assertEqual(result['flow_support_count'], 1)
        correlation = result['soc'].get('correlation', {})
        self.assertIsInstance(correlation, dict)


if __name__ == '__main__':
    unittest.main()
