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
from azazel_edge.evidence_plane import NocProbeAdapter
from azazel_edge.sensors.noc_monitor import LightweightNocMonitor, SERVICE_TARGETS


class LightweightNocMonitorV2Tests(unittest.TestCase):
    def test_snapshot_contains_path_probes_and_service_detail(self) -> None:
        service_payload = {k: {'target': k, 'unit': v, 'state': 'ON', 'detail': 'active', 'substate': 'running', 'result': 'success'} for k, v in SERVICE_TARGETS.items()}
        with patch('azazel_edge.sensors.noc_monitor.collect_icmp', return_value={'target': '192.168.40.1', 'reachable': True}), \
             patch('azazel_edge.sensors.noc_monitor.collect_path_probes', return_value=[{'target': '192.168.40.1', 'scope': 'gateway', 'reachable': True}, {'target': '1.1.1.1', 'scope': 'external', 'reachable': False}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_iface_stats', return_value=[{'interface': 'eth1', 'operstate': 'up', 'carrier': 1}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_cpu_mem_temp', return_value={'cpu_percent': 10.0, 'memory': {'percent': 30}, 'temperature_c': 45.0}), \
             patch('azazel_edge.sensors.noc_monitor.collect_dhcp_leases', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_arp_table', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_service_health', return_value=service_payload):
            snapshot = LightweightNocMonitor(up_interface='eth1', down_interface='usb0', gateway_ip='192.168.40.1').collect_snapshot()
        self.assertIn('path_probes', snapshot)
        self.assertEqual(len(snapshot['path_probes']), 2)
        self.assertIn('substate', snapshot['service_health']['web'])

    def test_adapter_and_evaluator_reflect_path_and_service_detail(self) -> None:
        adapter = NocProbeAdapter(up_interface='eth1', down_interface='usb0', gateway_ip='192.168.40.1')
        snapshot = {
            'icmp': {'target': '192.168.40.1', 'reachable': True, 'latency_ms': 1.0},
            'path_probes': [
                {'target': '192.168.40.1', 'scope': 'gateway', 'reachable': True, 'latency_ms': 1.0},
                {'target': '1.1.1.1', 'scope': 'external', 'reachable': False, 'latency_ms': None},
            ],
            'iface_stats': [{'interface': 'eth1', 'operstate': 'up', 'carrier': 1, 'rx_bytes': 0, 'tx_bytes': 0}],
            'cpu_mem_temp': {'cpu_percent': 20.0, 'memory': {'percent': 30}, 'temperature_c': 40.0},
            'dhcp_leases': [],
            'arp_table': [],
            'service_health': {'web': {'target': 'web', 'unit': 'azazel-edge-web', 'state': 'ON', 'detail': 'active', 'substate': 'failed', 'result': 'exit-code'}},
            'collector_failures': [],
        }
        events = [event.to_dict() for event in adapter.collect(snapshot=snapshot)]
        self.assertIn('path_probe', {event['kind'] for event in events})
        result = NocEvaluator().evaluate(events)
        self.assertIn('path_probe_failed:external', result['path_health']['reasons'])
        self.assertIn('path_target_divergence', result['path_health']['reasons'])
        self.assertIn('service_degraded:web', result['availability']['reasons'])


if __name__ == '__main__':
    unittest.main()
