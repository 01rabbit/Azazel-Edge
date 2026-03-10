from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evaluators import NocEvaluator, SocEvaluator
from azazel_edge.sot import SoTConfig, SoTDiffInspector


SOT = SoTConfig.from_dict({
    'devices': [
        {'id': 'dev1', 'hostname': 'client-1', 'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff', 'criticality': 'normal', 'allowed_networks': ['lan-main']},
    ],
    'networks': [
        {'id': 'lan-main', 'cidr': '192.168.40.0/24', 'zone': 'lan', 'gateway': '192.168.40.1'},
    ],
    'services': [
        {'id': 'svc-dns', 'proto': 'udp', 'port': 53, 'owner': 'netops', 'exposure': 'internal'},
    ],
    'expected_paths': [
        {'src': 'lan-main', 'dst': 'wan', 'service_id': 'svc-dns', 'via': '192.168.40.1', 'policy': 'allow'},
    ],
})


class SoTV2Tests(unittest.TestCase):
    def test_detects_unauthorized_device_service_and_path_deviation(self) -> None:
        inspector = SoTDiffInspector()
        diff = inspector.inspect([
            {'event_id': 'dhcp-1', 'source': 'noc_probe', 'kind': 'dhcp_lease', 'subject': 'dhcp:192.168.40.99', 'severity': 40, 'confidence': 0.9, 'attrs': {'ip': '192.168.40.99'}},
            {'event_id': 'flow-1', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '192.168.40.10->8.8.8.8:443/TCP', 'severity': 60, 'confidence': 0.8, 'attrs': {'src_ip': '192.168.40.10', 'dst_ip': '8.8.8.8', 'dst_port': 443, 'app_proto': 'tcp'}},
        ], SOT)
        self.assertIn('192.168.40.99', diff['unauthorized_devices'])
        self.assertTrue(diff['unauthorized_services'])
        self.assertTrue(diff['path_deviations'])

    def test_noc_and_soc_can_consume_sot_diff(self) -> None:
        inspector = SoTDiffInspector()
        events = [
            {'event_id': 'dhcp-1', 'source': 'noc_probe', 'kind': 'dhcp_lease', 'subject': 'dhcp:192.168.40.99', 'severity': 40, 'confidence': 0.9, 'attrs': {'ip': '192.168.40.99'}},
            {'event_id': 'flow-1', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '192.168.40.10->8.8.8.8:443/TCP', 'severity': 60, 'confidence': 0.8, 'attrs': {'src_ip': '192.168.40.10', 'dst_ip': '8.8.8.8', 'dst_port': 443, 'app_proto': 'tcp'}},
            {'event_id': 'soc-1', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '192.168.40.10->8.8.8.8:443/TCP', 'severity': 70, 'confidence': 0.8, 'attrs': {'sid': 210001, 'attack_type': 'Suspicious TLS Beacon', 'category': 'Potentially Bad Traffic', 'target_port': 443, 'risk_score': 70, 'confidence_raw': 80}},
        ]
        diff = inspector.inspect(events, SOT)
        noc = NocEvaluator().evaluate(events, sot=SOT.to_dict(), sot_diff=diff)
        soc = SocEvaluator().evaluate(events, sot_diff=diff)
        self.assertIn('unauthorized_devices_present', noc['client_health']['reasons'])
        self.assertIn('path_deviation_detected', noc['path_health']['reasons'])
        self.assertIn('unauthorized_service_support', soc['suspicion']['reasons'])


if __name__ == '__main__':
    unittest.main()
