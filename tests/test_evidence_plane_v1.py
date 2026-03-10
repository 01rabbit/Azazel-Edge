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
            'network_health': {
                'status': 'SUSPECTED',
                'iface': 'eth1',
                'signals': ['dns_mismatch'],
                'internet_check': 'OK',
                'dns_mismatch': 2,
            },
            'system_metrics': {
                'cpu_percent': 12.0,
                'memory': {'percent': 38},
                'temperature_c': 51.2,
            },
            'service_health': {
                'azazel-edge-control-daemon': 'ON',
                'azazel-edge-ai-agent': 'ON',
                'azazel-edge-web': 'OFF',
            },
            'dhcp_leases': [
                {'ip': '192.168.40.100', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'client-1'},
            ],
            'arp_table': [
                {'ip': '192.168.40.100', 'mac': 'aa:bb:cc:dd:ee:ff', 'dev': 'eth1', 'state': 'REACHABLE'},
            ],
            'collector_failures': [
                {'collector': 'icmp', 'error': 'disabled_for_slice'}
            ],
        }
        events = adapter.collect(snapshot=snapshot)
        kinds = {item.to_dict()['kind'] for item in events}
        self.assertIn('network_health', kinds)
        self.assertIn('system_health', kinds)
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
