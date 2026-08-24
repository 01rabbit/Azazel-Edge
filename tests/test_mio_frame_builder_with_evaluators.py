from __future__ import annotations

from azazel_edge.evaluators import NocEvaluator, SocEvaluator
from azazel_edge.evidence_plane import EvidenceEvent
from azazel_edge.mio import MioSituationFrameBuilder


def test_mio_frame_builder_accepts_real_evaluator_outputs():
    noc_event = EvidenceEvent.build(
        ts='2026-08-23T00:00:00Z',
        source='noc_probe',
        kind='icmp_probe',
        subject='gateway',
        severity=0,
        confidence=0.9,
        attrs={'target': 'gateway', 'reachable': True},
        status='ok',
    )
    soc_event = EvidenceEvent.build(
        ts='2026-08-23T00:00:01Z',
        source='suricata_eve',
        kind='alert',
        subject='10.0.0.5->192.168.40.10:22/TCP',
        severity=72,
        confidence=0.85,
        attrs={
            'sid': 210001,
            'attack_type': 'SSH Brute Force Attempt',
            'category': 'Attempted Administrator Privilege Gain',
            'target_port': 22,
            'risk_score': 72,
            'confidence_raw': 85,
        },
        status='alert',
    )
    events = [noc_event, soc_event]
    noc = NocEvaluator().evaluate(events)
    soc = SocEvaluator().evaluate(events)

    frame = MioSituationFrameBuilder().build(
        events=events,
        noc_evaluation=noc,
        soc_evaluation=soc,
        current_defensive_state='OBSERVE',
        mission='Investigate the current signal without compromising availability',
        trace_id='trace-evaluator-integration',
        frame_id='frame-evaluator-integration',
        created_at='2026-08-23T00:00:03Z',
    )

    assert frame.current_defensive_state == 'OBSERVE'
    assert frame.threat_level in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
    assert noc_event.event_id in frame.evidence_refs
    assert soc_event.event_id in frame.evidence_refs
    assert any(item.startswith('NOC_STATUS=') for item in frame.known_facts)
    assert any(item.startswith('SOC_STATUS=') for item in frame.known_facts)
    rendered = str(frame.to_dict())
    assert '10.0.0.5' not in rendered
    assert '192.168.40.10' not in rendered
