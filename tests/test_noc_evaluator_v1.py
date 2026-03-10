from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evaluators import NocEvaluator
from azazel_edge.evidence_plane import EvidenceEvent


def _event(kind: str, subject: str, severity: int, attrs: dict, status: str = 'ok') -> EvidenceEvent:
    return EvidenceEvent.build(
        ts='2026-03-10T00:00:00Z',
        source='noc_probe',
        kind=kind,
        subject=subject,
        severity=severity,
        confidence=0.9,
        attrs=attrs,
        status=status,
    )


class NocEvaluatorV1Tests(unittest.TestCase):
    def test_generates_required_sections_from_noc_events(self) -> None:
        evaluator = NocEvaluator()
        events = [
            _event('icmp_probe', '192.168.40.1', 0, {'target': '192.168.40.1', 'reachable': True}),
            _event('iface_stats', 'eth1', 0, {'interface': 'eth1', 'operstate': 'up', 'carrier': 1}),
            _event('cpu_mem_temp', 'edge', 0, {'cpu_percent': 20.0, 'memory': {'percent': 35}, 'temperature_c': 45.0}),
            _event('service_health', 'web', 0, {'target': 'web', 'state': 'ON'}),
            _event('dhcp_lease', '192.168.40.10', 0, {'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff'}),
            _event('arp_entry', '192.168.40.10', 0, {'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff', 'state': 'REACHABLE'}),
        ]

        result = evaluator.evaluate(events)

        self.assertIn('availability', result)
        self.assertIn('path_health', result)
        self.assertIn('device_health', result)
        self.assertIn('client_health', result)
        self.assertIn('summary', result)
        self.assertIn('evidence_ids', result)
        for key in ('availability', 'path_health', 'device_health', 'client_health'):
            self.assertIn('score', result[key])
            self.assertIn('label', result[key])

    def test_keeps_evidence_ids_in_dimensions_and_top_level(self) -> None:
        evaluator = NocEvaluator()
        icmp = _event('icmp_probe', '192.168.40.1', 70, {'target': '192.168.40.1', 'reachable': False}, status='fail')
        service = _event('service_health', 'web', 70, {'target': 'web', 'state': 'OFF'}, status='fail')

        result = evaluator.evaluate([icmp, service])

        self.assertIn(icmp.event_id, result['availability']['evidence_ids'])
        self.assertIn(service.event_id, result['availability']['evidence_ids'])
        self.assertIn(icmp.event_id, result['path_health']['evidence_ids'])
        self.assertIn(icmp.event_id, result['evidence_ids'])
        self.assertIn(service.event_id, result['evidence_ids'])

    def test_degraded_mode_without_sot(self) -> None:
        evaluator = NocEvaluator()
        result = evaluator.evaluate([])
        self.assertTrue(result['summary']['degraded_mode'])
        self.assertIn('sot_missing', result['summary']['reasons'])
        self.assertIn('sot_missing', result['client_health']['reasons'])

    def test_arbiter_handoff_payload_is_fixed_schema(self) -> None:
        evaluator = NocEvaluator()
        result = evaluator.evaluate([])
        handoff = evaluator.to_arbiter_input(result)
        self.assertEqual(handoff['source'], 'noc_evaluator')
        for key in ('summary', 'availability', 'path_health', 'device_health', 'client_health', 'evidence_ids'):
            self.assertIn(key, handoff)

    def test_sot_can_reduce_unknown_client_penalty(self) -> None:
        evaluator = NocEvaluator()
        events = [
            _event('dhcp_lease', '192.168.40.10', 0, {'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff'}),
            _event('arp_entry', '192.168.40.10', 0, {'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff', 'state': 'REACHABLE'}),
        ]
        with_sot = evaluator.evaluate(events, sot={'devices': [{'id': 'dev1', 'ip': '192.168.40.10'}]})
        without_sot = evaluator.evaluate(events)
        self.assertGreaterEqual(with_sot['client_health']['score'], without_sot['client_health']['score'])

    def test_thresholds_and_weights_are_configurable(self) -> None:
        base = NocEvaluator()
        tuned = NocEvaluator(config={'availability': {'icmp_unreachable_penalty': 20}})
        events = [_event('icmp_probe', '192.168.40.1', 70, {'target': '192.168.40.1', 'reachable': False}, status='fail')]
        base_score = base.evaluate(events)['availability']['score']
        tuned_score = tuned.evaluate(events)['availability']['score']
        self.assertGreater(tuned_score, base_score)


if __name__ == '__main__':
    unittest.main()
