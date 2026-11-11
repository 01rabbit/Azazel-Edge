"""Actual separate-process AF_UNIX traffic, never a replay substitute."""
import copy
import os
from unittest.mock import patch

import pytest

from test_benefit_comparison import manifest
from azazel_edge.benchmark.benefit import BenefitInputError, SAFETY_FIELDS, manifest_digest
from azazel_edge.benchmark.benefit_receipt import build_receipt
from azazel_edge.benchmark.local_service_capture import (
    LocalCaptureError, MAX_TRANSACTIONS, capture_local_service, local_service_plan,
)


def local_manifest(**plan):
    value = manifest()
    value['horizon_seconds'] = .12
    value['evidence_kind'] = 'recorded_lab'
    value['arms'][0]['config_sha256'] = manifest_digest(local_service_plan(**plan))
    return value


def run(value=None, **kwargs):
    return capture_local_service(value or local_manifest(**kwargs), '0-block', run_id='actual-local-run',
        safety_observations=dict.fromkeys(SAFETY_FIELDS, 0), **kwargs)


def test_actual_child_objective_and_client_transactions_feed_unchanged_receipt():
    value = local_manifest(transactions=5)
    before = copy.deepcopy(value)
    result = run(value, transactions=5)
    assert value == before
    assert result['controller_pid'] == os.getpid() != result['service_pid']
    audit = result['service_audit']
    assert audit['pid'] == result['service_pid']
    assert result['service_audit_sha256'] == manifest_digest(audit)
    receipt = result['receipt']
    assert receipt == build_receipt(value, '0-block', result['capture'])
    assert receipt['horizon_verified']
    assert 0 < receipt['protected_goal_seconds'] < value['horizon_seconds']
    assert receipt['legitimate_transactions'] == 5 and receipt['legitimate_errors'] == 0
    assert 0 < receipt['legitimate_latency_p95_ms'] < value['horizon_seconds']*1000
    assert len(audit['completed']) == 6
    assert result['evidence_scope'] == 'local_synthetic_process_transport_only'


@pytest.mark.parametrize('profile,goal,errors', [
    ('goal_denied', False, 0), ('goal_ack_only', False, 0), ('legitimate_error', True, 4),
])
def test_real_denial_and_error_negative_controls(profile, goal, errors):
    result = run(profile=profile)
    receipt = result['receipt']
    assert receipt['horizon_verified']
    assert (receipt['protected_goal_seconds'] is not None) is goal
    assert (result['service_audit']['goal_ns'] is not None) is goal
    assert receipt['legitimate_transactions'] == 4
    assert receipt['legitimate_errors'] == errors
    if profile == 'goal_ack_only':
        assert result['service_audit']['completed'][0]['ok'] is True


def test_absent_final_service_audit_never_becomes_clean_censoring_or_receipt():
    with pytest.raises(LocalCaptureError, match='audit'):
        run(profile='audit_loss')


def test_forged_client_goal_success_cannot_replace_service_audit():
    from azazel_edge.benchmark import local_service_capture as capture
    real_receive = capture._receive

    def forged(wire):
        value = real_receive(wire)
        if value.get('sequence') == 0:
            value['ok'] = True
        return value

    with patch.object(capture, '_receive', side_effect=forged):
        with pytest.raises(LocalCaptureError, match='audit identity/transaction'):
            run(profile='goal_denied')


def test_lost_or_wrong_child_identity_is_rejected_and_child_reaped():
    from azazel_edge.benchmark import local_service_capture as capture
    spawned = []
    real_popen = capture.subprocess.Popen
    real_receive = capture._receive

    def start(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        spawned.append(child)
        return child

    def wrong_challenge(wire):
        value = real_receive(wire)
        value['nonce'] = 'wrong'
        return value

    with patch.object(capture.subprocess, 'Popen', side_effect=start), patch.object(
            capture, '_receive', side_effect=wrong_challenge):
        with pytest.raises(LocalCaptureError, match='readiness/challenge'):
            run()
    assert len(spawned) == 1 and spawned[0].poll() is not None
    assert spawned[0].stdout.closed


def test_actual_request_overrun_is_missing_not_truncated_success():
    from azazel_edge.benchmark import local_service_capture as capture
    real_receive = capture._receive

    def late_response(wire):
        value = real_receive(wire)
        if value.get('sequence') == 0:
            capture.time.sleep(.15)
        return value

    with patch.object(capture, '_receive', side_effect=late_response):
        with pytest.raises(LocalCaptureError, match='late'):
            run()


def test_no_safety_default_or_unbounded_target_or_budget_can_start_child():
    m = local_manifest()
    with patch('azazel_edge.benchmark.local_service_capture.subprocess.Popen',
               side_effect=AssertionError('must refuse before process creation')):
        for safety in (None, {}, dict.fromkeys(SAFETY_FIELDS, False)):
            with pytest.raises(BenefitInputError, match='safety'):
                capture_local_service(m, '0-block', run_id='run-a', safety_observations=safety)
        for kwargs in ({'transactions': MAX_TRANSACTIONS+1}, {'transactions': True},
                       {'profile': 'external-target'}):
            with pytest.raises((BenefitInputError, LocalCaptureError)):
                run(m, **kwargs)
        m['evidence_kind'] = 'hardware'
        with pytest.raises(BenefitInputError, match='recorded_lab'):
            run(m)
        m['evidence_kind'] = 'recorded_lab'
        m['horizon_seconds'] = 60
        with pytest.raises(BenefitInputError):
            run(m)


def test_explicit_safety_failure_is_preserved_without_defense_interpretation():
    safety = dict.fromkeys(SAFETY_FIELDS, 0)
    safety['protected_escape'] = 1
    result = capture_local_service(local_manifest(), '0-block', run_id='unsafe-run',
        safety_observations=safety)
    assert result['receipt']['safety_violations'] == safety


def test_changed_frozen_plan_is_refused_before_traffic():
    with patch('azazel_edge.benchmark.local_service_capture.subprocess.Popen',
               side_effect=AssertionError('no traffic on changed plan')):
        with pytest.raises(BenefitInputError, match='frozen arm'):
            run(local_manifest(), profile='goal_denied')
        with pytest.raises(BenefitInputError, match='frozen arm'):
            run(local_manifest(), transactions=5)


def test_four_actual_process_runs_feed_offline_analysis_without_a_replay_fixture():
    from azazel_edge.benchmark.benefit import analyze
    value = local_manifest()
    value['arms'][1]['config_sha256'] = value['arms'][0]['config_sha256']
    receipts = [capture_local_service(value, assignment['id'], run_id='process-run-' + str(index),
        safety_observations=dict.fromkeys(SAFETY_FIELDS, 0))['receipt']
        for index, assignment in enumerate(value['assignments'])]
    with patch('subprocess.Popen', side_effect=AssertionError('analysis must remain offline')):
        report = analyze(value, dict(manifest_sha256=manifest_digest(value), runs=receipts))
    assert report['assigned_runs'] == 4 and report['complete_pairs'] == 2
    assert report['claim_status'] == 'mechanical_only'
    assert report['protected_goals_completed'] == {'block': 2, 'candidate': 2}


@pytest.mark.parametrize('stage', ['readiness', 'response', 'teardown'])
def test_fragmented_test_child_cannot_extend_absolute_phase_deadline(stage):
    """Substitution is test-only; public capture accepts no child command."""
    import sys
    import time
    from azazel_edge.benchmark import local_service_capture as capture

    child_source = r'''
import json, os, socket, sys, time
fd, nonce, stage = int(sys.argv[1]), sys.argv[2], sys.argv[3]
sock = socket.socket(fileno=fd)
wire = sock.makefile('rwb', buffering=0)
protocol = 'azazel-local-service/v1'
def emit(value, drip=False):
    raw = json.dumps(value).encode() + b'\n'
    for fragment in ([bytes([item]) for item in raw] if drip else [raw]):
        wire.write(fragment)
        if drip: time.sleep(.03)
emit(dict(protocol=protocol, nonce=nonce, kind='ready', pid=os.getpid()), stage == 'readiness')
while True:
    request = json.loads(wire.readline())
    if request['operation'] == 'close':
        # Continue writing progress while deliberately withholding process exit.
        for _ in range(100):
            sys.stdout.buffer.write(b'{')
            sys.stdout.buffer.flush()
            time.sleep(.03)
        break
    emit(dict(protocol=protocol, nonce=nonce, sequence=request['sequence'], ok=True), stage == 'response')
'''
    real_popen = capture.subprocess.Popen
    spawned = []

    def start(command, **kwargs):
        # Keep the actual inherited socket/nonce. Only this test replaces the
        # fixed child so it can exercise hostile fragmented protocol delivery.
        process = real_popen([sys.executable, '-I', '-u', '-c', child_source,
                             command[-3], command[-2], stage], **kwargs)
        spawned.append(process)
        return process

    started = time.monotonic()
    with patch.object(capture.subprocess, 'Popen', side_effect=start):
        with pytest.raises(LocalCaptureError):
            run()
    elapsed = time.monotonic() - started
    # Bounds allow scheduler/startup/kill slack, but fragmented progress cannot
    # stretch a one-second phase into the child's multi-second drip sequence.
    assert elapsed < (1.0 if stage == 'response' else 2.0)
    assert len(spawned) == 1 and spawned[0].poll() is not None
    assert spawned[0].stdout.closed


def test_real_socket_fragments_share_one_absolute_receive_deadline():
    import socket
    import threading
    import time
    from azazel_edge.benchmark import local_service_capture as capture

    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    stop = threading.Event()

    def drip():
        try:
            for byte in b'{"fragmented":true}\n':
                if stop.is_set():
                    break
                sender.send(bytes([byte]))
                stop.wait(.02)
        except OSError:
            pass
        finally:
            sender.close()

    worker = threading.Thread(target=drip)
    worker.start()
    started = time.monotonic()
    try:
        with pytest.raises((LocalCaptureError, TimeoutError)):
            capture._receive(capture._Wire(receiver, time.monotonic_ns() + 80_000_000))
        assert time.monotonic() - started < .3
    finally:
        stop.set()
        receiver.close()
        worker.join(timeout=1)
    assert not worker.is_alive()
