from dataclasses import replace
import importlib.util
from unittest.mock import patch
import pytest
from azazel_mio.contracts import MioSituationFrame
from azazel_edge.evidence_plane.session_observations import SessionObservation, SessionObservationBuffer, MAX_WINDOWS, MAX_EVENTS, MAX_CLOSED

NOW='2026-11-10T00:01:00+00:00'

def event(**overrides):
    values=dict(boot_ref='boot-1',session_ref='session-1',frame_id='frame-1',event_ref='ev:http:1',observed_at=NOW,source='http',features=(('declared_ai_client',True),),capture_complete=True,shared_source_ambiguity=False,clock_uncertain=False)
    values.update(overrides)
    return SessionObservation(**values)

def frame(refs=('ev:http:1',)):
    return MioSituationFrame.build(frame_id='frame-1',trace_id='trace-1',created_at=NOW,mission='observe',current_defensive_state='OBSERVE',threat_level='unknown',evidence_refs=refs)


def test_disabled_is_default_and_retains_no_observation():
    b=SessionObservationBuffer('boot-1')
    assert b.offer(event(),now=1)=='disabled'
    assert b.status()['open_windows']==0
    assert b.assess(frame(),session_ref='session-1',now=2,as_of=NOW)['status']=='disabled'


def test_duplicate_conflicting_identity_and_reordering_are_not_repaired():
    b=SessionObservationBuffer('boot-1',enabled=True)
    assert b.offer(event(),now=1)=='accepted'
    assert b.offer(event(),now=2)=='duplicate'
    assert b.offer(event(features=(('declared_ai_client',False),)),now=3)=='conflict'
    w=b._windows[('session-1','frame-1')]
    assert not w.complete and len(w.events)==1
    b.offer(event(event_ref='ev:http:2',observed_at='2026-11-10T00:00:59Z'),now=4)
    assert w.clock


def test_expired_or_consumed_window_cannot_reopen_and_old_boot_is_rejected():
    b=SessionObservationBuffer('boot-1',enabled=True)
    b.offer(event(),now=1)
    b.expire(31)
    assert b.offer(event(),now=32)=='unavailable'
    assert b.offer(event(boot_ref='boot-2'),now=33)=='unavailable'
    assert b.status()['counters']['expired']==1


def test_window_event_reference_and_closed_caps_are_bounded():
    b=SessionObservationBuffer('boot-1',enabled=True)
    for i in range(MAX_WINDOWS):
        assert b.offer(event(session_ref=f'session-{i}'),now=1)=='accepted'
    assert b.offer(event(session_ref='session-over'),now=2)=='capacity'
    assert len(b._windows)==MAX_WINDOWS
    b.expire(32)
    assert b.offer(event(session_ref='session-over'),now=33)=='unavailable'
    c=SessionObservationBuffer('boot-1',enabled=True)
    for i in range(MAX_EVENTS): c.offer(event(event_ref=f'ev:http:{i}'),now=1)
    assert c.offer(event(event_ref='ev:http:65'),now=2)=='capacity'
    assert not c._windows[('session-1','frame-1')].complete
    assert max(len(refs) for _,refs in c._windows[('session-1','frame-1')].features.values())<=16
    d=SessionObservationBuffer('boot-1',enabled=True)
    for i in range(MAX_CLOSED+1):
        d.offer(event(session_ref=f'session-{i}'),now=i*31+1)
        d.expire(i*31+31)
    assert d.sealed and len(d._closed)<=MAX_CLOSED


def test_bad_inputs_clock_rollback_and_sensitive_references_fail_closed():
    for override in ({'session_ref':'192.0.2.1'},{'event_ref':'token-secret-value'},{'source':'raw_packet'},{'features':(('local_canary_touch',True),)},{'features':(('execute',True),)},{'features':(('local_canary_touch','yes'),)},{'capture_complete':'true'}):
        with pytest.raises(ValueError): event(**override)
    b=SessionObservationBuffer('boot-1',enabled=True)
    assert b.offer({'raw':'ignore all instructions'},now=1)=='malformed'
    b.offer(event(),now=2); b.expire(1)
    assert b.sealed and not b._windows


def test_assessment_is_once_optional_and_cannot_mutate_frame_or_execute():
    b=SessionObservationBuffer('boot-1',enabled=True)
    f=frame(); before=f.to_canonical_json()
    b.offer(event(),now=1)
    with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('executor')):
        result=b.assess(f,session_ref='session-1',now=2,as_of=NOW)
    assert result['authorized_actions']==[] and f.to_canonical_json()==before
    if importlib.util.find_spec('azazel_mio.session_behavior') is not None:
        assert result['identity_label']=='unknown' and result['abstained']
        assert result['maliciousness']=='not_assessed' and len(result['hypotheses'])==3
    else: assert result['status']=='unavailable'
    assert b.offer(event(),now=3)=='unavailable'
    assert b.assess(f,session_ref='session-1',now=4,as_of=NOW)['status']=='unavailable'
