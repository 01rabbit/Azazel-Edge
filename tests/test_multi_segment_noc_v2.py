from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evaluators import NocEvaluator
from azazel_edge.sensors.noc_monitor import LightweightNocMonitor


class MultiSegmentNocV2Tests(unittest.TestCase):
    def test_monitor_can_probe_multiple_interfaces(self) -> None:
        def fake_probe(gateway_ip: str, interfaces):
            rows = []
            for iface in interfaces:
                iface = str(iface).strip()
                if not iface:
                    continue
                rows.append({'target': '192.168.40.1', 'scope': 'gateway', 'reachable': iface == 'eth1', 'interface': iface})
            return rows

        with patch('azazel_edge.sensors.noc_monitor.collect_icmp', return_value={'target': '192.168.40.1', 'reachable': True}), \
             patch('azazel_edge.sensors.noc_monitor.collect_path_probes_multi', side_effect=fake_probe), \
             patch('azazel_edge.sensors.noc_monitor.collect_iface_stats', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_cpu_mem_temp', return_value={}), \
             patch('azazel_edge.sensors.noc_monitor.collect_dhcp_leases', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_arp_table', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_service_health', return_value={}):
            snapshot = LightweightNocMonitor(up_interface='eth1', down_interface='usb0', extra_interfaces=['wlan0']).collect_snapshot()
        self.assertEqual(len(snapshot['path_probes']), 3)

    def test_noc_summary_marks_multi_segment_and_uplink_divergence(self) -> None:
        events = [
            {'event_id': 'probe-1', 'source': 'noc_probe', 'kind': 'path_probe', 'subject': '192.168.40.1', 'severity': 0, 'confidence': 0.95, 'attrs': {'scope': 'gateway', 'reachable': True, 'interface': 'eth1'}},
            {'event_id': 'probe-2', 'source': 'noc_probe', 'kind': 'path_probe', 'subject': '192.168.40.1', 'severity': 70, 'confidence': 0.95, 'attrs': {'scope': 'gateway', 'reachable': False, 'interface': 'usb0'}},
            {'event_id': 'flow-1', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '192.168.40.10->10.20.0.10:443/TCP', 'severity': 60, 'confidence': 0.8, 'attrs': {'src_ip': '192.168.40.10', 'dst_ip': '10.20.0.10', 'dst_port': 443}},
        ]
        sot = {
            'devices': [],
            'services': [],
            'expected_paths': [],
            'networks': [
                {'id': 'lan-a', 'cidr': '192.168.40.0/24', 'zone': 'lan', 'gateway': '192.168.40.1'},
                {'id': 'lan-b', 'cidr': '10.20.0.0/24', 'zone': 'lan', 'gateway': '10.20.0.1'},
            ],
        }
        result = NocEvaluator().evaluate(events, sot=sot)
        self.assertIn('uplink_divergence', result['path_health']['reasons'])
        self.assertTrue(result['summary']['segment_scope']['multi_segment'])
        self.assertEqual(result['summary']['segment_scope']['affected_segments'], ['lan-a', 'lan-b'])


if __name__ == '__main__':
    unittest.main()
