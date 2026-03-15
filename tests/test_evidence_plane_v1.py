from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evidence_plane import (
    REQUIRED_FIELDS,
    EvidenceBus,
    EvidenceEvent,
    EvidencePlaneService,
    NocProbeAdapter,
    adapt_suricata_record,
    build_config_drift_event,
    build_client_inventory,
    adapt_syslog_line,
    read_suricata_jsonl,
)


class EvidencePlaneV1Tests(unittest.TestCase):
    def test_schema_and_bus_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fanout = Path(tmp) / 'evidence.jsonl'
            bus = EvidenceBus(fanout_path=fanout, queue_max=8)
            event = EvidenceEvent.build(
                ts='2026-03-10T00:00:00Z',
                source='suricata_eve',
                kind='alert',
                subject='1.1.1.1->2.2.2.2:53/UDP',
                severity=78,
                confidence=0.91,
                attrs={'sid': 1234},
                status='alert',
            )
            bus.publish(event)
            drained = bus.drain()
            self.assertEqual(len(drained), 1)
            payload = drained[0]
            for field in REQUIRED_FIELDS:
                self.assertIn(field, payload)
            self.assertTrue(str(payload['event_id']).startswith('sha256:'))
            from_file = bus.read_fanout(limit=1)
            self.assertEqual(from_file[0]['subject'], '1.1.1.1->2.2.2.2:53/UDP')

    def test_suricata_adapter_from_rust_normalized_jsonl(self) -> None:
        sample = {
            'normalized': {
                'ts': '2026-03-10T00:00:00Z',
                'src_ip': '192.168.1.10',
                'dst_ip': '8.8.8.8',
                'attack_type': 'ET POLICY Suspicious DNS Query',
                'severity': 2,
                'target_port': 53,
                'protocol': 'UDP',
                'sid': 210001,
                'category': 'Potentially Bad Traffic',
                'event_type': 'alert',
                'action': 'allowed',
                'confidence': 90,
                'risk_score': 81,
                'ingest_epoch': 1773000000.0,
            },
            'defense': {'decision': 'observe'},
            'source': 'suricata_eve',
            'pipeline': 'rust_event_engine_v1',
        }
        event = adapt_suricata_record(sample)
        payload = event.to_dict()
        self.assertEqual(payload['source'], 'suricata_eve')
        self.assertEqual(payload['kind'], 'alert')
        self.assertEqual(payload['severity'], 81)
        self.assertAlmostEqual(payload['confidence'], 0.9)
        self.assertEqual(payload['attrs']['sid'], 210001)

    def test_suricata_jsonl_reader(self) -> None:
        sample = {
            'normalized': {
                'ts': '2026-03-10T00:00:00Z',
                'src_ip': '1.1.1.1',
                'dst_ip': '2.2.2.2',
                'attack_type': 'x',
                'severity': 3,
                'target_port': 80,
                'protocol': 'TCP',
                'sid': 1,
                'category': 'c',
                'event_type': 'alert',
                'action': 'allowed',
                'confidence': 80,
                'risk_score': 72,
                'ingest_epoch': 1.0,
            },
            'defense': {},
            'pipeline': 'rust_event_engine_v1',
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'normalized-events.jsonl'
            path.write_text(json.dumps(sample) + '\n', encoding='utf-8')
            items = read_suricata_jsonl(path)
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0].to_dict()['attrs']['risk_score'], 72)

    def test_noc_probe_adapter_generates_multiple_events(self) -> None:
        adapter = NocProbeAdapter(up_interface='eth1', down_interface='usb0', gateway_ip='192.168.40.1')
        snapshot = {
            'icmp': {
                'target': '192.168.40.1',
                'interface': 'eth1',
                'reachable': True,
                'latency_ms': 1.2,
            },
            'iface_stats': [
                {
                    'interface': 'eth1',
                    'operstate': 'up',
                    'carrier': 1,
                    'rx_bytes': 100,
                    'tx_bytes': 50,
                }
            ],
            'path_probe_window': [
                {'target': '1.1.1.1', 'interface': 'eth1', 'scope': 'external', 'state': 'down', 'success_ratio_pct': 0.0},
            ],
            'resolution_probes': [
                {'name': 'example.com', 'resolved': False, 'answers': [], 'latency_ms': 4.0, 'probe': 'dns'},
            ],
            'resolution_probe_window': [
                {'name': 'example.com', 'state': 'failed', 'success_ratio_pct': 0.0},
            ],
            'service_probes': [
                {'name': 'resolver-tcp', 'target': '1.1.1.1:53', 'reachable': False, 'latency_ms': 10.0, 'probe': 'tcp'},
            ],
            'service_probe_window': [
                {'name': 'resolver-tcp', 'target': '1.1.1.1:53', 'state': 'down', 'success_ratio_pct': 0.0},
            ],
            'cpu_mem_temp': {
                'cpu_percent': 12.0,
                'memory': {'percent': 38},
                'temperature_c': 51.2,
            },
            'service_health': {
                'control-daemon': {'target': 'control-daemon', 'unit': 'azazel-edge-control-daemon', 'state': 'ON'},
                'ai-agent': {'target': 'ai-agent', 'unit': 'azazel-edge-ai-agent', 'state': 'ON'},
                'web': {'target': 'web', 'unit': 'azazel-edge-web', 'state': 'OFF'},
            },
            'dhcp_leases': [
                {'ip': '172.16.0.100', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'client-1'},
            ],
            'arp_table': [
                {'ip': '172.16.0.100', 'mac': 'aa:bb:cc:dd:ee:ff', 'dev': 'eth0', 'state': 'REACHABLE'},
            ],
            'collector_failures': [
                {'collector': 'icmp', 'error': 'disabled_for_slice'}
            ],
        }
        events = adapter.collect(snapshot=snapshot)
        kinds = {item.to_dict()['kind'] for item in events}
        self.assertIn('icmp_probe', kinds)
        self.assertIn('path_probe_window', kinds)
        self.assertIn('iface_stats', kinds)
        self.assertIn('resolution_probe', kinds)
        self.assertIn('resolution_probe_window', kinds)
        self.assertIn('service_probe', kinds)
        self.assertIn('service_probe_window', kinds)
        self.assertIn('cpu_mem_temp', kinds)
        self.assertIn('service_health', kinds)
        self.assertIn('dhcp_lease', kinds)
        self.assertIn('arp_entry', kinds)
        self.assertIn('collector_failure', kinds)

    def test_syslog_min_adapter(self) -> None:
        event = adapt_syslog_line('<13>Mar 10 10:00:00 edgehost systemd[1]: Failed to start demo.service')
        payload = event.to_dict()
        self.assertEqual(payload['source'], 'syslog_min')
        self.assertEqual(payload['kind'], 'syslog_line')
        self.assertEqual(payload['attrs']['host'], 'edgehost')
        self.assertGreaterEqual(payload['severity'], 30)

    def test_mixed_source_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bus = EvidenceBus(fanout_path=Path(tmp) / 'evidence.jsonl', queue_max=32)
            service = EvidencePlaneService(bus)
            suri = EvidenceEvent.build(
                ts='2026-03-10T00:00:00Z',
                source='suricata_eve',
                kind='alert',
                subject='1.1.1.1->2.2.2.2:53/UDP',
                severity=80,
                confidence=0.9,
                attrs={'sid': 1},
            )
            noc = EvidenceEvent.build(
                ts='2026-03-10T00:00:01Z',
                source='noc_probe',
                kind='service_health',
                subject='azazel-edge-web',
                severity=70,
                confidence=0.95,
                attrs={'state': 'OFF'},
            )
            service.dispatch_events([suri, noc])
            service.dispatch_syslog_line('<13>Mar 10 10:00:00 edgehost dnsmasq[88]: warning example')
            items = bus.read_fanout()
            self.assertEqual(len(items), 3)
            for payload in items:
                for field in REQUIRED_FIELDS:
                    self.assertIn(field, payload)
                self.assertIsInstance(payload['attrs'], dict)

    def test_config_drift_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bus = EvidenceBus(fanout_path=Path(tmp) / 'evidence.jsonl', queue_max=8)
            service = EvidencePlaneService(bus)
            item = service.dispatch_config_drift({
                'status': 'drift',
                'baseline_state': 'present',
                'changed_fields': ['uplink_preference.preferred_uplink'],
                'baseline_values': {'uplink_preference.preferred_uplink': 'eth1'},
                'current_values': {'uplink_preference.preferred_uplink': 'usb0'},
                'rollback_hint': 'review_changed_fields_and_restore_last_known_good',
            })
        self.assertEqual(item['kind'], 'config_drift')
        self.assertEqual(item['source'], 'config_drift')
        self.assertEqual(item['attrs']['changed_fields'], ['uplink_preference.preferred_uplink'])

    def test_noc_probe_dispatch_derives_client_inventory_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bus = EvidenceBus(fanout_path=Path(tmp) / 'evidence.jsonl', queue_max=32)
            service = EvidencePlaneService(bus)
            snapshot = {
                'icmp': {'target': '192.168.40.1', 'reachable': True},
                'path_probes': [],
                'path_probe_window': [],
                'iface_stats': [],
                'capacity_samples': [],
                'capacity_pressure': [],
                'resolution_probes': [],
                'resolution_probe_window': [],
                'service_probes': [],
                'service_probe_window': [],
                'cpu_mem_temp': {},
                'service_health': {},
                'dhcp_leases': [{'ip': '172.16.0.20', 'mac': 'aa:bb:cc:dd:ee:01', 'hostname': 'client-a'}],
                'arp_table': [{'ip': '172.16.0.20', 'mac': 'aa:bb:cc:dd:ee:01', 'dev': 'eth0', 'state': 'REACHABLE'}],
                'collector_failures': [],
            }
            items = service.dispatch_noc_probe(snapshot=snapshot)
            kinds = {item['kind'] for item in items}
            self.assertIn('client_session', kinds)
            self.assertIn('client_inventory_summary', kinds)

    def test_client_inventory_merges_flow_with_existing_dhcp_arp_session(self) -> None:
        inventory = build_client_inventory([
            EvidenceEvent.build(
                ts='2026-03-10T00:00:00Z',
                source='noc_probe',
                kind='dhcp_lease',
                subject='172.16.0.20',
                severity=0,
                confidence=0.9,
                attrs={'ip': '172.16.0.20', 'mac': 'aa:bb:cc:dd:ee:01', 'hostname': 'client-a'},
            ),
            EvidenceEvent.build(
                ts='2026-03-10T00:00:05Z',
                source='noc_probe',
                kind='arp_entry',
                subject='172.16.0.20',
                severity=0,
                confidence=0.9,
                attrs={'ip': '172.16.0.20', 'mac': 'aa:bb:cc:dd:ee:01', 'dev': 'br0', 'bridge_port': 'eth0', 'state': 'REACHABLE'},
            ),
            EvidenceEvent.build(
                ts='2026-03-10T00:00:10Z',
                source='flow_min',
                kind='flow_summary',
                subject='172.16.0.20->8.8.8.8:443/TCP',
                severity=20,
                confidence=0.7,
                attrs={'src_ip': '172.16.0.20', 'dst_ip': '8.8.8.8', 'dst_port': 443, 'proto': 'TCP', 'app_proto': 'tls'},
            ),
        ])
        rows = [row for row in inventory['sessions'] if row['session_state'] != 'authorized_missing']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['sources_present'], ['arp', 'dhcp', 'flow'])
        self.assertEqual(rows[0]['interface_or_segment'], 'eth0')

    def test_client_inventory_ignores_flow_only_remote_peer(self) -> None:
        inventory = build_client_inventory([
            EvidenceEvent.build(
                ts='2026-03-10T00:00:10Z',
                source='flow_min',
                kind='flow_summary',
                subject='1.1.1.1->172.16.0.20:443/TCP',
                severity=20,
                confidence=0.7,
                attrs={'src_ip': '1.1.1.1', 'dst_ip': '172.16.0.20', 'dst_port': 443, 'proto': 'TCP', 'app_proto': 'tls'},
            ),
        ])
        rows = [row for row in inventory['sessions'] if row['session_state'] != 'authorized_missing']
        self.assertEqual(rows, [])
        self.assertEqual(inventory['summary']['current_client_count'], 0)
        self.assertEqual(inventory['summary']['unknown_client_count'], 0)

    def test_client_inventory_keeps_arp_only_peer_on_client_facing_interface(self) -> None:
        inventory = build_client_inventory(
            [
                EvidenceEvent.build(
                    ts='2026-03-10T00:00:05Z',
                    source='noc_probe',
                    kind='arp_entry',
                    subject='172.16.0.55',
                    severity=0,
                    confidence=0.9,
                    attrs={'ip': '172.16.0.55', 'mac': '18:34:af:cb:4f:d1', 'dev': 'eth0', 'state': 'REACHABLE'},
                ),
            ],
            now_ts='2026-03-10T00:00:30Z',
        )
        rows = [row for row in inventory['sessions'] if row['session_state'] != 'authorized_missing']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['session_origin'], 'arp_only')
        self.assertEqual(rows[0]['interface_family'], 'eth')
        self.assertEqual(inventory['summary']['current_client_count'], 1)

    def test_client_inventory_marks_wlan_bridge_port_as_wireless(self) -> None:
        inventory = build_client_inventory([
            EvidenceEvent.build(
                ts='2026-03-10T00:00:00Z',
                source='noc_probe',
                kind='dhcp_lease',
                subject='172.16.0.44',
                severity=0,
                confidence=0.9,
                attrs={'ip': '172.16.0.44', 'mac': 'aa:bb:cc:dd:ee:44', 'hostname': 'client-wlan'},
            ),
            EvidenceEvent.build(
                ts='2026-03-10T00:00:05Z',
                source='noc_probe',
                kind='arp_entry',
                subject='172.16.0.44',
                severity=0,
                confidence=0.9,
                attrs={'ip': '172.16.0.44', 'mac': 'aa:bb:cc:dd:ee:44', 'dev': 'br0', 'bridge_port': 'wlan0', 'state': 'REACHABLE'},
            ),
        ])
        rows = [row for row in inventory['sessions'] if row['session_state'] != 'authorized_missing']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['interface_or_segment'], 'wlan0')
        self.assertEqual(rows[0]['interface_family'], 'wlan')

    def test_client_inventory_skips_ignored_device_from_sot(self) -> None:
        inventory = build_client_inventory(
            [
                EvidenceEvent.build(
                    ts='2026-03-10T00:00:00Z',
                    source='noc_probe',
                    kind='arp_entry',
                    subject='172.16.0.88',
                    severity=0,
                    confidence=0.9,
                    attrs={'ip': '172.16.0.88', 'mac': 'aa:bb:cc:dd:ee:88', 'dev': 'eth0', 'state': 'REACHABLE'},
                ),
            ],
            sot={
                'devices': [
                    {
                        'id': 'ignored-arp',
                        'hostname': 'ignored-arp',
                        'ip': '172.16.0.88',
                        'mac': 'aa:bb:cc:dd:ee:88',
                        'criticality': 'standard',
                        'allowed_networks': [],
                        'authorized': False,
                        'monitoring_scope': 'ignore',
                    }
                ],
                'networks': [],
                'services': [],
                'expected_paths': [],
            },
            now_ts='2026-03-10T00:00:30Z',
        )
        rows = [row for row in inventory['sessions'] if row['session_state'] != 'authorized_missing']
        self.assertEqual(rows, [])
        self.assertEqual(inventory['summary']['ignored_client_count'], 1)
        self.assertEqual(inventory['summary']['current_client_count'], 0)

    def test_client_inventory_marks_expected_link_drift_as_mismatch(self) -> None:
        inventory = build_client_inventory(
            [
                EvidenceEvent.build(
                    ts='2026-03-10T00:00:00Z',
                    source='noc_probe',
                    kind='dhcp_lease',
                    subject='172.16.0.44',
                    severity=0,
                    confidence=0.9,
                    attrs={'ip': '172.16.0.44', 'mac': 'aa:bb:cc:dd:ee:44', 'hostname': 'client-wlan'},
                ),
                EvidenceEvent.build(
                    ts='2026-03-10T00:00:05Z',
                    source='noc_probe',
                    kind='arp_entry',
                    subject='172.16.0.44',
                    severity=0,
                    confidence=0.9,
                    attrs={'ip': '172.16.0.44', 'mac': 'aa:bb:cc:dd:ee:44', 'dev': 'br0', 'bridge_port': 'wlan0', 'state': 'REACHABLE'},
                ),
            ],
            sot={
                'devices': [
                    {
                        'id': 'client-wlan',
                        'hostname': 'client-wlan',
                        'ip': '172.16.0.44',
                        'mac': 'aa:bb:cc:dd:ee:44',
                        'criticality': 'standard',
                        'allowed_networks': ['managed-lan'],
                        'authorized': True,
                        'expected_interface_or_segment': 'eth0',
                    }
                ],
                'networks': [],
                'services': [],
                'expected_paths': [],
            },
            now_ts='2026-03-10T00:00:30Z',
        )
        rows = [row for row in inventory['sessions'] if row['ip'] == '172.16.0.44']
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['session_state'], 'inventory_mismatch')
        self.assertTrue(rows[0]['expected_link_mismatch'])
        self.assertEqual(inventory['summary']['expected_link_mismatch_count'], 1)

    def test_client_inventory_ignores_arp_only_peer_on_non_client_interface(self) -> None:
        inventory = build_client_inventory([
            EvidenceEvent.build(
                ts='2026-03-10T00:00:05Z',
                source='noc_probe',
                kind='arp_entry',
                subject='192.168.40.1',
                severity=0,
                confidence=0.9,
                attrs={'ip': '192.168.40.1', 'mac': '18:34:af:cb:4f:d1', 'dev': 'usb0', 'state': 'REACHABLE'},
            ),
        ])
        rows = [row for row in inventory['sessions'] if row['session_state'] != 'authorized_missing']
        self.assertEqual(rows, [])
        self.assertEqual(inventory['summary']['current_client_count'], 0)
