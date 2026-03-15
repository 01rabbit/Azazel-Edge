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
from azazel_edge.sensors.noc_monitor import LightweightNocMonitor, SERVICE_TARGETS, collect_arp_table


class LightweightNocMonitorV1Tests(unittest.TestCase):
    def test_collect_arp_table_enriches_bridge_port(self) -> None:
        def _fake_run(cmd, timeout=3.0):
            if cmd[:3] == ['bridge', 'fdb', 'show']:
                return '00:e0:4c:8c:8f:92 dev eth0 master br0 \\n'
            if cmd[:4] == ['iw', 'dev', 'wlan0', 'station']:
                return ''
            if cmd[:3] == ['ip', 'neigh', 'show']:
                return '172.16.0.156 dev br0 lladdr 00:e0:4c:8c:8f:92 STALE\\n'
            return ''

        with patch('azazel_edge.sensors.noc_monitor._run', side_effect=_fake_run):
            rows = collect_arp_table()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['dev'], 'br0')
        self.assertEqual(rows[0]['bridge_port'], 'eth0')

    def test_collect_arp_table_falls_back_to_wlan_station_when_bridge_port_missing(self) -> None:
        def _fake_run(cmd, timeout=3.0):
            if cmd[:3] == ['bridge', 'fdb', 'show']:
                return ''
            if cmd[:4] == ['iw', 'dev', 'wlan0', 'station']:
                return 'Station 00:e0:4c:8c:8f:92 (on wlan0)\\n'
            if cmd[:3] == ['ip', 'neigh', 'show']:
                return '172.16.0.156 dev br0 lladdr 00:e0:4c:8c:8f:92 STALE\\n'
            return ''

        with patch('azazel_edge.sensors.noc_monitor._run', side_effect=_fake_run):
            rows = collect_arp_table()

        self.assertEqual(rows[0]['bridge_port'], 'wlan0')

    def test_snapshot_contains_issue_defined_collectors(self) -> None:
        with patch('azazel_edge.sensors.noc_monitor.collect_icmp', return_value={'target': '192.168.40.1', 'reachable': True}), \
             patch('azazel_edge.sensors.noc_monitor.collect_path_probes', return_value=[{'target': '192.168.40.1', 'scope': 'gateway', 'reachable': True}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_dns_resolution', side_effect=lambda name: {'name': name, 'resolved': True, 'answers': ['93.184.216.34'], 'latency_ms': 5.0, 'probe': 'dns'}), \
             patch('azazel_edge.sensors.noc_monitor.collect_service_probes', return_value=[{'name': 'resolver-tcp', 'target': '1.1.1.1:53', 'reachable': True, 'latency_ms': 8.0, 'probe': 'tcp'}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_iface_stats', return_value=[{'interface': 'eth1', 'operstate': 'up', 'carrier': 1}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_cpu_mem_temp', return_value={'cpu_percent': 10.0, 'memory': {'percent': 30}, 'temperature_c': 45.0}), \
             patch('azazel_edge.sensors.noc_monitor.collect_dhcp_leases', return_value=[{'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff'}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_arp_table', return_value=[{'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff', 'dev': 'eth1', 'state': 'REACHABLE'}]), \
             patch('azazel_edge.sensors.noc_monitor.collect_service_health', return_value={k: {'target': k, 'unit': v, 'state': 'ON'} for k, v in SERVICE_TARGETS.items()}):
            monitor = LightweightNocMonitor(up_interface='eth1', down_interface='usb0', gateway_ip='192.168.40.1')
            snapshot = monitor.collect_snapshot()

        self.assertEqual(
            set(snapshot.keys()),
            {
                'icmp', 'path_probes', 'path_probe_window', 'iface_stats', 'capacity_samples', 'capacity_pressure',
                'resolution_probes', 'resolution_probe_window', 'service_probes', 'service_probe_window',
                'cpu_mem_temp', 'dhcp_leases', 'arp_table', 'service_health', 'collector_failures',
            },
        )
        self.assertEqual(snapshot['collector_failures'], [])
        self.assertEqual(set(snapshot['service_health'].keys()), set(SERVICE_TARGETS.keys()))
        self.assertEqual(len(snapshot['capacity_samples']), 1)
        self.assertEqual(snapshot['capacity_pressure'][0]['state'], 'unknown')
        self.assertEqual(snapshot['resolution_probe_window'][0]['state'], 'healthy')
        self.assertEqual(snapshot['service_probe_window'][0]['state'], 'healthy')

    def test_collector_failure_is_not_silenced(self) -> None:
        with patch('azazel_edge.sensors.noc_monitor.collect_icmp', side_effect=RuntimeError('icmp disabled')), \
             patch('azazel_edge.sensors.noc_monitor.collect_path_probes', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_dns_resolution', side_effect=RuntimeError('dns disabled')), \
             patch('azazel_edge.sensors.noc_monitor.collect_service_probes', side_effect=RuntimeError('service probes disabled')), \
             patch('azazel_edge.sensors.noc_monitor.collect_iface_stats', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_cpu_mem_temp', return_value={}), \
             patch('azazel_edge.sensors.noc_monitor.collect_dhcp_leases', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_arp_table', return_value=[]), \
             patch('azazel_edge.sensors.noc_monitor.collect_service_health', return_value={}):
            monitor = LightweightNocMonitor(up_interface='eth1', down_interface='usb0', gateway_ip='192.168.40.1')
            snapshot = monitor.collect_snapshot()

        self.assertEqual({item['collector'] for item in snapshot['collector_failures']}, {'icmp', 'resolution_probes', 'service_probes'})

    def test_adapter_emits_evidence_plane_compatible_events(self) -> None:
        adapter = NocProbeAdapter(up_interface='eth1', down_interface='usb0', gateway_ip='192.168.40.1')
        snapshot = {
            'icmp': {'target': '192.168.40.1', 'reachable': False, 'latency_ms': None},
            'path_probe_window': [{'target': '1.1.1.1', 'interface': 'eth1', 'scope': 'external', 'state': 'down'}],
            'iface_stats': [{'interface': 'eth1', 'operstate': 'down', 'carrier': 0, 'rx_bytes': 0, 'tx_bytes': 0}],
            'resolution_probes': [{'name': 'example.com', 'resolved': False, 'answers': [], 'latency_ms': 10.0}],
            'resolution_probe_window': [{'name': 'example.com', 'state': 'failed', 'success_ratio_pct': 0.0}],
            'service_probes': [{'name': 'resolver-tcp', 'target': '1.1.1.1:53', 'reachable': False, 'latency_ms': 20.0, 'probe': 'tcp'}],
            'service_probe_window': [{'name': 'resolver-tcp', 'target': '1.1.1.1:53', 'state': 'down', 'success_ratio_pct': 0.0}],
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
            {
                'icmp_probe', 'path_probe_window', 'iface_stats', 'resolution_probe', 'resolution_probe_window',
                'service_probe', 'service_probe_window', 'cpu_mem_temp', 'dhcp_lease', 'arp_entry',
                'service_health', 'collector_failure',
            },
        )
        for event in events:
            self.assertEqual(event['source'], 'noc_probe')
            self.assertIn('attrs', event)
            self.assertIn('event_id', event)


if __name__ == '__main__':
    unittest.main()
