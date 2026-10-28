from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from azazel_edge.evidence_plane import (
    EvidenceBus,
    EvidencePlaneService,
    adapt_flow_record,
)
from azazel_edge.evaluators import NocEvaluator, SocEvaluator
from azazel_edge.evidence_plane.flow_min import TOP_SOURCES_LIMIT, summarize_flow_events


class FlowInputV1Tests(unittest.TestCase):
    def test_flow_record_is_normalized_into_evidence_plane(self) -> None:
        event = adapt_flow_record({
            'ts': '2026-03-10T00:00:00Z',
            'src_ip': '10.0.0.5',
            'dst_ip': '192.168.40.10',
            'dst_port': 443,
            'proto': 'TCP',
            'app_proto': 'tls',
            'flow_state': 'failed',
            'bytes_toserver': 1024,
            'bytes_toclient': 0,
            'pkts_toserver': 30,
            'pkts_toclient': 0,
            'flow_id': 'flow-1',
        }).to_dict()
        self.assertEqual(event['source'], 'flow_min')
        self.assertEqual(event['kind'], 'flow_summary')
        self.assertEqual(event['attrs']['flow_state'], 'failed')

    def test_flow_jsonl_can_coexist_with_p0_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bus = EvidenceBus(fanout_path=Path(tmp) / 'evidence.jsonl')
            service = EvidencePlaneService(bus)
            flow_path = Path(tmp) / 'flow.jsonl'
            flow_path.write_text(json.dumps({
                'ts': '2026-03-10T00:00:00Z',
                'src_ip': '10.0.0.5',
                'dst_ip': '192.168.40.10',
                'dst_port': 443,
                'proto': 'TCP',
                'app_proto': 'tls',
                'flow_state': 'failed',
                'bytes_toserver': 1024,
                'bytes_toclient': 0,
                'pkts_toserver': 30,
                'pkts_toclient': 0,
                'flow_id': 'flow-1',
            }) + '\n', encoding='utf-8')
            items = service.dispatch_flow_jsonl(flow_path)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]['source'], 'flow_min')
        self.assertEqual(items[1]['kind'], 'traffic_concentration')
        self.assertTrue(items[1]['attrs']['top_sources'])

    def test_flow_summary_keeps_more_than_three_sources(self) -> None:
        # Edge#344: the summary used to keep only three sources, which hid
        # most managed clients from the dashboard talker views.
        events = [
            {
                'kind': 'flow_summary',
                'attrs': {
                    'src_ip': f'172.16.0.{i}',
                    'dst_port': 443,
                    'proto': 'TCP',
                    'bytes_toserver': 100 * i,
                    'bytes_toclient': 0,
                },
            }
            for i in range(1, 16)
        ]
        summary = summarize_flow_events(events)
        self.assertIsNotNone(summary)
        attrs = summary.to_dict()['attrs']
        self.assertEqual(TOP_SOURCES_LIMIT, 12)
        self.assertEqual(len(attrs['top_sources']), 12)
        self.assertEqual(attrs['top_sources'][0]['src_ip'], '172.16.0.15')
        self.assertEqual(attrs['top_sources'][-1]['src_ip'], '172.16.0.4')
        self.assertEqual(len(attrs['top_services']), 1)
        total = sum(100 * i for i in range(1, 16))
        self.assertEqual(attrs['source_concentration_ratio'], round(1500 / total, 4))

    def test_flow_supports_noc_and_soc_scores(self) -> None:
        flow_event = adapt_flow_record({
            'ts': '2026-03-10T00:00:00Z',
            'src_ip': '10.0.0.5',
            'dst_ip': '192.168.40.10',
            'dst_port': 443,
            'proto': 'TCP',
            'app_proto': 'tls',
            'flow_state': 'failed',
            'bytes_toserver': 1024,
            'bytes_toclient': 0,
            'pkts_toserver': 30,
            'pkts_toclient': 0,
            'flow_id': 'flow-1',
        })
        soc_event = {
            'event_id': 'soc-1',
            'ts': '2026-03-10T00:00:01Z',
            'source': 'suricata_eve',
            'kind': 'alert',
            'subject': '10.0.0.5->192.168.40.10:443/TCP',
            'severity': 65,
            'confidence': 0.8,
            'attrs': {
                'sid': 210001,
                'attack_type': 'Suspicious TLS Beacon',
                'category': 'Potentially Bad Traffic',
                'target_port': 443,
                'risk_score': 65,
                'confidence_raw': 80,
            },
        }
        noc = NocEvaluator().evaluate([flow_event])
        soc = SocEvaluator().evaluate([soc_event, flow_event])
        self.assertIn('flow_path_instability', noc['path_health']['reasons'])
        self.assertIn('flow_anomaly_support', soc['suspicion']['reasons'])


if __name__ == '__main__':
    unittest.main()
