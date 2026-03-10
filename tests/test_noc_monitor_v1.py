from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evidence_plane import NocProbeAdapter
from azazel_edge.sensors.noc_monitor import LightweightNocMonitor, SERVICE_TARGETS


class LightweightNocMonitorV1Tests(unittest.TestCase):
    def test_snapshot_contains_issue_defined_collectors(self) -> None:
        with patch('azazel_edge.sensors.noc_monitor.collect_icmp', return_value={'target': '192.168.40.1', 'reachable': True}), \
             patch('azazel_edge.sensors.noc_monitor.collect_path_probes', return_value=[{'target': '192.168.40.1', 'scope': 'gateway', 'reachable': True}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_iface_stats', return_value=[{'interface': 'eth1', 'operstate': 'up', 'carrier': 1}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_cpu_mem_temp', return_value={'cpu_percent': 10.0, 'memory': {'percent': 30}, 'temperature_c': 45.0}), \
             patch('azazel_edge.sensors.noc_monitor.collect_dhcp_leases', return_value=[{'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff'}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_arp_table', return_value=[{'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff', 'dev': 'eth1', 'state': 'REACHABLE'}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_service_health', return_value={k: {'target': k, 'unit': v, 'state': 'ON'} for k, v in SERVICE_TARGETS.items()}):
            monitor = LightweightNocMonitor(up_interface='eth1', down_interface='usb0', gateway_ip='192.168.40.1')
            snapshot = monitor.collect_snapshot()

        self.assertEqual(
            set(snapshot.keys()),
            {'icmp', 'path_probes', 'iface_stats', 'cpu_mem_temp', 'dhcp_leases', 'arp_table', 'service_health', 'collector_failures'},
        )
        self.assertEqual(snapshot['collector_failures'], [])
        self.assertEqual(set(snapshot['service_health'].keys()), set(SERVICE_TARGETS.keys()))

    def test_collector_failure_is_not_silenced(self) -> None:
        with patch('azazel_edge.sensors.noc_monitor.collect_icmp', side_effect=RuntimeError('icmp disabled')), \
             patch('azazel_edge.sensors.noc_monitor.collect_path_probes', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_iface_stats', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_cpu_mem_temp', return_value={}), \
             patch('azazel_edge.sensors.noc_monitor.collect_dhcp_leases', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_arp_table', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_service_health', return_value={}):
            monitor = LightweightNocMonitor(up_interface='eth1', down_interface='usb0', gateway_ip='192.168.40.1')
            snapshot = monitor.collect_snapshot()

        self.assertEqual(len(snapshot['collector_failures']), 1)
        self.assertEqual(snapshot['collector_failures'][0]['collector'], 'icmp')

    def test_adapter_emits_evidence_plane_compatible_events(self) -> None:
        adapter = NocProbeAdapter(up_interface='eth1', down_interface='usb0', gateway_ip='192.168.40.1')
        snapshot = {
            'icmp': {'target': '192.168.40.1', 'reachable': False, 'latency_ms': None},
            'iface_stats': [{'interface': 'eth1', 'operstate': 'down', 'carrier': 0, 'rx_bytes': 0, 'tx_bytes': 0}],
            'cpu_mem_temp': {'cpu_percent': 92.0, 'memory': {'percent': 91}, 'temperature_c': 82.0},
            'dhcp_leases': [{'ip': '192.168.40.50', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'client-1'}],
            'arp_table': [{'ip': '192.168.40.50', 'mac': 'aa:bb:cc:dd:ee:ff', 'dev': 'eth1', 'state': 'STALE'}],
            'service_health': {'web': {'target': 'web', 'unit': 'azazel-edge-web', 'state': 'OFF'}},
            'collector_failures': [{'collector': 'dhcp_leases', 'error': 'permission denied'}],
        }
        events = [event.to_dict() for event in adapter.collect(snapshot=snapshot)]
        kinds = {event['kind'] for event in events}
        self.assertEqual(
            kinds,
            {'icmp_probe', 'iface_stats', 'cpu_mem_temp', 'dhcp_lease', 'arp_entry', 'service_health', 'collector_failure'},
        )
        for event in events:
            self.assertEqual(event['source'], 'noc_probe')
            self.assertIn('attrs', event)
            self.assertIn('event_id', event)


if __name__ == '__main__':
    unittest.main()
