from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evaluators import SocEvaluator
from azazel_edge.evidence_plane import EvidenceEvent, adapt_flow_record


def _event(subject: str, risk: int, confidence_raw: int, attack_type: str, category: str, port: int, sid: int) -> EvidenceEvent:
    return EvidenceEvent.build(
        ts='2026-03-10T00:00:00Z',
        source='suricata_eve',
        kind='alert',
        subject=subject,
        severity=risk,
        confidence=confidence_raw / 100.0,
        attrs={
            'sid': sid,
            'attack_type': attack_type,
            'category': category,
            'target_port': port,
            'risk_score': risk,
            'confidence_raw': confidence_raw,
        },
        status='alert',
    )


def _flow_event(src_ip: str, dst_ip: str, dst_port: int, flow_id: str = 'flow-1') -> EvidenceEvent:
    return adapt_flow_record({
        'ts': '2026-03-10T00:00:00Z',
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'proto': 'TCP',
        'app_proto': 'tls',
        'flow_state': 'failed',
        'bytes_toserver': 1024,
        'bytes_toclient': 0,
        'pkts_toserver': 30,
        'pkts_toclient': 0,
        'flow_id': flow_id,
    })


def _syslog_event(message: str, host: str = 'edge-gw') -> EvidenceEvent:
    return EvidenceEvent.build(
        ts='2026-03-10T00:00:00Z',
        source='syslog_min',
        kind='syslog_line',
        subject=f'{host}:kernel',
        severity=30,
        confidence=0.75,
        attrs={
            'host': host,
            'tag': 'kernel',
            'message': message,
        },
        status='warn',
    )


class SocEvaluatorV1Tests(unittest.TestCase):
    def test_generates_required_sections_from_soc_events(self) -> None:
        evaluator = SocEvaluator()
        events = [
            _event('10.0.0.5->192.168.40.10:53/UDP', 72, 85, 'Suspicious DNS Beacon', 'Potentially Bad Traffic', 53, 210001),
            _event('10.0.0.5->192.168.40.20:80/TCP', 68, 80, 'Web Attack Attempt', 'Attempted Administrator Privilege Gain', 80, 210002),
        ]
        result = evaluator.evaluate(events)
        for key in (
            'suspicion',
            'confidence',
            'technique_likelihood',
            'blast_radius',
            'entity_risk_state',
            'incident_campaign_state',
            'security_visibility_state',
            'suppression_exception_state',
            'asset_target_criticality',
            'exposure_change_state',
            'confidence_provenance',
            'behavior_sequence_state',
            'triage_priority_state',
            'summary',
            'evidence_ids',
        ):
            self.assertIn(key, result)
        for key in ('suspicion', 'confidence', 'technique_likelihood', 'blast_radius'):
            self.assertIn('score', result[key])
            self.assertIn('label', result[key])
        self.assertIn('top_entities', result['entity_risk_state'])

    def test_keeps_evidence_ids(self) -> None:
        evaluator = SocEvaluator()
        event = _event('10.0.0.5->192.168.40.10:53/UDP', 85, 90, 'Suspicious DNS Beacon', 'Potentially Bad Traffic', 53, 210001)
        result = evaluator.evaluate([event])
        for key in ('suspicion', 'confidence', 'technique_likelihood', 'blast_radius'):
            self.assertIn(event.event_id, result[key]['evidence_ids'])
        self.assertIn(event.event_id, result['evidence_ids'])

    def test_attack_candidates_are_supporting_information(self) -> None:
        evaluator = SocEvaluator()
        result = evaluator.evaluate([
            _event('10.0.0.5->192.168.40.10:53/UDP', 85, 90, 'DNS C2 Beacon', 'Potentially Bad Traffic', 53, 210001)
        ])
        self.assertIn('attack_candidates', result['summary'])
        self.assertTrue(result['summary']['attack_candidates'])
        self.assertIn('T1071 Application Layer Protocol', result['summary']['attack_candidates'])
        self.assertIn('attack_techniques', result['summary'])
        self.assertTrue(result['summary']['attack_techniques'])

    def test_handoff_payload_is_fixed_schema(self) -> None:
        evaluator = SocEvaluator()
        handoff = evaluator.to_arbiter_input(evaluator.evaluate([]))
        self.assertEqual(handoff['source'], 'soc_evaluator')
        for key in (
            'summary',
            'suspicion',
            'confidence',
            'technique_likelihood',
            'blast_radius',
            'entity_risk_state',
            'incident_campaign_state',
            'security_visibility_state',
            'suppression_exception_state',
            'asset_target_criticality',
            'exposure_change_state',
            'confidence_provenance',
            'behavior_sequence_state',
            'triage_priority_state',
            'evidence_ids',
        ):
            self.assertIn(key, handoff)

    def test_entity_risk_state_captures_top_entities(self) -> None:
        evaluator = SocEvaluator()
        events = [
            _event('10.0.0.5->192.168.40.10:53/UDP', 85, 90, 'DNS C2 Beacon', 'Potentially Bad Traffic', 53, 210001),
            _event('10.0.0.5->192.168.40.10:443/TCP', 92, 94, 'TLS Beacon', 'Trojan Activity', 443, 210020),
        ]
        result = evaluator.evaluate(events)
        state = result['entity_risk_state']
        self.assertGreaterEqual(state['entity_count'], 3)
        self.assertGreaterEqual(state['bounded_entity_count'], 1)
        top = state['top_entities'][0]
        self.assertIn('entity_type', top)
        self.assertIn('entity_id', top)
        self.assertIn('score', top)
        self.assertIn('label', top)
        self.assertTrue(top['evidence_ids'])

    def test_entity_risk_state_is_bounded(self) -> None:
        evaluator = SocEvaluator(max_entities=8)
        events = []
        for idx in range(30):
            events.append(
                _event(
                    f'10.0.0.{idx + 1}->192.168.40.{idx + 1}:80/TCP',
                    50 + (idx % 40),
                    60 + (idx % 30),
                    'Web Attack Attempt',
                    'Attempted Administrator Privilege Gain',
                    80,
                    210100 + idx,
                )
            )
        result = evaluator.evaluate(events)
        state = result['entity_risk_state']
        self.assertGreater(state['entity_count'], state['bounded_entity_count'])
        self.assertEqual(state['bounded_entity_count'], 8)
        self.assertEqual(len(state['top_entities']), 8)

    def test_suppression_policy_filters_events_but_keeps_high_risk_exception(self) -> None:
        evaluator = SocEvaluator(suppression_policy={'sid': [210001]})
        lower_risk = _event('10.0.0.5->192.168.40.10:53/UDP', 65, 80, 'Suspicious DNS Beacon', 'Potentially Bad Traffic', 53, 210001)
        higher_risk = _event('10.0.0.5->192.168.40.10:443/TCP', 95, 90, 'Suspicious TLS Beacon', 'Trojan Activity', 443, 210001)
        control = _event('10.0.0.6->192.168.40.20:80/TCP', 70, 75, 'Web Attack Attempt', 'Attempted Administrator Privilege Gain', 80, 210002)
        result = evaluator.evaluate([lower_risk, higher_risk, control])
        suppression = result['suppression_exception_state']
        self.assertEqual(suppression['suppressed_count'], 1)
        self.assertEqual(suppression['exception_count'], 1)
        self.assertEqual(suppression['actionable_count'], 2)
        self.assertIn('high_risk_exception_escaped_suppression', suppression['reasons'])

    def test_visibility_and_triage_include_flow_signal(self) -> None:
        evaluator = SocEvaluator()
        events = [
            _event('10.0.0.5->192.168.40.10:443/TCP', 88, 82, 'TLS Beacon', 'Trojan Activity', 443, 210020),
            _flow_event('10.0.0.5', '192.168.40.10', 443, flow_id='flow-visibility-1'),
        ]
        result = evaluator.evaluate(events)
        self.assertEqual(result['security_visibility_state']['status'], 'good')
        triage = result['triage_priority_state']
        self.assertIn(triage['status'], {'now', 'watch', 'later', 'idle'})
        self.assertIn('score', triage)
        self.assertIn('now', triage)

    def test_critical_target_increases_criticality_and_blast_radius(self) -> None:
        evaluator = SocEvaluator(criticality={'dst_ips': ['192.168.40.10']})
        result = evaluator.evaluate([
            _event('10.0.0.5->192.168.40.10:443/TCP', 72, 80, 'TLS Beacon', 'Trojan Activity', 443, 210020),
        ])
        criticality = result['asset_target_criticality']
        self.assertEqual(criticality['critical_target_count'], 1)
        self.assertEqual(criticality['status'], 'critical_targets_observed')
        self.assertGreaterEqual(result['blast_radius']['score'], 55)

    def test_exposure_change_transitions_to_stable_when_targets_repeat(self) -> None:
        evaluator = SocEvaluator()
        events = [_event('10.0.0.5->8.8.8.8:443/TCP', 65, 75, 'Suspicious TLS Beacon', 'Potentially Bad Traffic', 443, 210001)]
        first = evaluator.evaluate(events)
        second = evaluator.evaluate(events)
        self.assertEqual(first['exposure_change_state']['status'], 'expanding')
        self.assertEqual(second['exposure_change_state']['status'], 'stable')

    def test_incident_campaign_state_transitions_active_cooling_closed_and_recurrence(self) -> None:
        evaluator = SocEvaluator()
        event = _event('10.0.0.5->192.168.40.10:443/TCP', 90, 85, 'TLS Beacon', 'Trojan Activity', 443, 210020)
        first = evaluator.evaluate([event])
        self.assertEqual(first['incident_campaign_state']['status'], 'active')
        self.assertEqual(first['incident_campaign_state']['top_incidents'][0]['status'], 'active')

        second = evaluator.evaluate([])
        third = evaluator.evaluate([])
        fourth = evaluator.evaluate([])
        self.assertEqual(second['incident_campaign_state']['status'], 'cooling')
        self.assertEqual(third['incident_campaign_state']['status'], 'cooling')
        self.assertEqual(fourth['incident_campaign_state']['status'], 'closed')

        fifth = evaluator.evaluate([event])
        top = fifth['incident_campaign_state']['top_incidents'][0]
        self.assertEqual(top['status'], 'active')
        self.assertGreaterEqual(int(top.get('recurrence_count') or 0), 1)
        self.assertTrue(top.get('implicated_entities'))

    def test_visibility_state_tracks_syslog_and_stale_source(self) -> None:
        evaluator = SocEvaluator()
        soc_event = _event('10.0.0.5->192.168.40.10:443/TCP', 75, 80, 'TLS Beacon', 'Trojan Activity', 443, 210020)
        stale_flow = _flow_event('10.0.0.5', '192.168.40.10', 443, flow_id='flow-stale-1').to_dict()
        stale_flow['attrs']['collector_age_sec'] = 1200
        result = evaluator.evaluate([soc_event, stale_flow, _syslog_event('resolver timeout')])
        visibility = result['security_visibility_state']
        self.assertIn('syslog_event_count', visibility)
        self.assertIn('stale_sources', visibility)
        self.assertIn('flow_min', visibility['stale_sources'])
        self.assertGreater(int(visibility.get('trust_penalty') or 0), 0)

    def test_suppression_policy_supports_expected_scanner_and_lab_and_maintenance(self) -> None:
        evaluator = SocEvaluator(
            suppression_policy={
                'expected_scanners': ['10.0.0.9'],
                'lab_segments': ['lab-segment-a'],
                'maintenance_windows': [{'start_hour': 0, 'end_hour': 23}],
            }
        )
        scanner_event = _event('10.0.0.9->192.168.40.20:80/TCP', 60, 70, 'Web Probe', 'Potentially Bad Traffic', 80, 210101)
        lab_event = _event('10.0.0.10->192.168.40.30:443/TCP', 62, 70, 'TLS Probe', 'Potentially Bad Traffic', 443, 210102)
        maint_event = _event('10.0.0.11->192.168.40.31:53/UDP', 58, 72, 'DNS Query Burst', 'Potentially Bad Traffic', 53, 210103)
        lab_payload = lab_event.to_dict()
        lab_payload['attrs']['segment'] = 'lab-segment-a'
        result = evaluator.evaluate([scanner_event, lab_payload, maint_event])
        suppression = result['suppression_exception_state']
        self.assertEqual(suppression['suppressed_count'], 3)
        self.assertEqual(suppression['actionable_count'], 0)
        reasons = ' '.join(str(x) for x in suppression['reasons'])
        self.assertIn('suppression_policy_applied', reasons)

    def test_behavior_sequence_includes_chain_hits_and_implicated_entities(self) -> None:
        evaluator = SocEvaluator()
        events = [
            _event('10.0.0.5->192.168.40.10:22/TCP', 55, 70, 'Network Scan', 'Recon Activity', 22, 210200),
            _event('10.0.0.5->192.168.40.10:22/TCP', 68, 75, 'Auth Brute Attempt', 'Authentication Failure', 22, 210201),
            _event('10.0.0.5->192.168.40.10:443/TCP', 88, 80, 'DNS C2 Beacon', 'Trojan Activity', 443, 210202),
        ]
        result = evaluator.evaluate(events)
        sequence = result['behavior_sequence_state']
        self.assertIn(sequence['status'], {'single_stage', 'multi_stage'})
        self.assertTrue(sequence.get('chain_hits'))
        self.assertTrue(sequence.get('implicated_entities'))

    def test_confidence_provenance_includes_sot_diff_support(self) -> None:
        evaluator = SocEvaluator()
        result = evaluator.evaluate(
            [_event('10.0.0.5->192.168.40.10:443/TCP', 70, 80, 'TLS Beacon', 'Trojan Activity', 443, 210020)],
            sot_diff={
                'unauthorized_services': ['192.168.40.10:443'],
                'path_deviations': ['p1'],
                'unauthorized_devices': ['10.0.0.5'],
            },
        )
        provenance = result['confidence_provenance']
        supports = set(str(x) for x in provenance.get('supports', []))
        self.assertIn('sot_unauthorized_service_diff', supports)
        self.assertIn('sot_path_deviation_diff', supports)
        self.assertIn('sot_unauthorized_device_diff', supports)

    def test_triage_priority_uses_now_watch_backlog_buckets(self) -> None:
        evaluator = SocEvaluator()
        result = evaluator.evaluate([
            _event('10.0.0.5->192.168.40.10:443/TCP', 94, 92, 'TLS Beacon', 'Trojan Activity', 443, 210020),
        ])
        triage = result['triage_priority_state']
        self.assertIn('backlog', triage)
        self.assertIn('top_priority_ids', triage)
        self.assertIn(triage['status'], {'now', 'watch', 'backlog', 'idle'})


if __name__ == '__main__':
    unittest.main()
