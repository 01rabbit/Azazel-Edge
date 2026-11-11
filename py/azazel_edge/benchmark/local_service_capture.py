"""Opt-in local synthetic service measurement; never imported by offline replay.

Only a fixed child and inherited AF_UNIX channel are used. A client ACK is not
objective truth: the child's separate final audit must cover the actual horizon.
This is process separation, not separate-UID or cryptographic attestation.
"""
from __future__ import annotations

import json
import os
import secrets
import select
import socket
import subprocess
import sys
import time
from pathlib import Path

PROTOCOL = 'azazel-local-service/v1'
PROFILES = ('goal_allowed', 'goal_denied', 'goal_ack_only', 'legitimate_error', 'audit_loss')
MAX_MESSAGE = 16384
MAX_TRANSACTIONS = 32


class LocalCaptureError(ValueError):
    """Run cannot supply a complete independent-service receipt."""


def _remaining(deadline_ns):
    remaining = (deadline_ns - time.monotonic_ns()) / 1e9
    if remaining <= 0:
        raise LocalCaptureError('absolute local protocol deadline exceeded')
    return remaining


class _Wire:
    """A shared absolute deadline cannot be renewed by partial peer progress."""
    def __init__(self, channel, deadline_ns):
        self.channel = channel
        self.deadline_ns = deadline_ns

    def write(self, data):
        self.channel.settimeout(_remaining(self.deadline_ns))
        written = self.channel.send(data)
        _remaining(self.deadline_ns)
        return written

    def flush(self):
        _remaining(self.deadline_ns)

    def readline(self, limit):
        raw = bytearray()
        while len(raw) < limit:
            self.channel.settimeout(_remaining(self.deadline_ns))
            fragment = self.channel.recv(1)
            _remaining(self.deadline_ns)
            if not fragment:
                break
            raw.extend(fragment)
            if fragment == b'\n':
                break
        return bytes(raw)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


def _read_audit(pipe, deadline_ns):
    raw = bytearray()
    while len(raw) <= MAX_MESSAGE:
        if not select.select([pipe], [], [], _remaining(deadline_ns))[0]:
            raise LocalCaptureError('absolute service audit deadline exceeded')
        fragment = os.read(pipe.fileno(), min(4096, MAX_MESSAGE + 1 - len(raw)))
        _remaining(deadline_ns)
        if not fragment:
            return bytes(raw)
        raw.extend(fragment)
    raise LocalCaptureError('oversized service audit')


def _send(stream, value):
    raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    if len(raw) > MAX_MESSAGE:
        raise LocalCaptureError('local protocol message exceeds bound')
    remaining = memoryview(raw)
    while remaining:
        written = stream.write(remaining)
        if not written:
            raise LocalCaptureError('local protocol write stopped')
        remaining = remaining[written:]
    stream.flush()


def _receive(stream):
    raw = stream.readline(MAX_MESSAGE + 1)
    if not raw.endswith(b'\n') or len(raw) > MAX_MESSAGE:
        raise LocalCaptureError('missing or oversized local protocol message')
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise LocalCaptureError('invalid local protocol JSON') from exc
    if not isinstance(value, dict):
        raise LocalCaptureError('local protocol object required')
    return value


def _service(fd, nonce, profile):
    """Fixed child: no Edge import, file access, address or command input."""
    with socket.socket(fileno=fd) as channel:
        with _Wire(channel, time.monotonic_ns() + 7_000_000_000) as wire:
            started = time.monotonic_ns()
            _send(wire, dict(protocol=PROTOCOL, nonce=nonce, kind='ready', pid=os.getpid()))
            goal = None
            completed = []
            for _ in range(MAX_TRANSACTIONS + 2):
                request = _receive(wire)
                if request.get('protocol') != PROTOCOL or request.get('nonce') != nonce:
                    raise LocalCaptureError('child challenge mismatch')
                operation = request.get('operation')
                if operation == 'close':
                    if profile == 'audit_loss':
                        return
                    _send(sys.stdout.buffer, dict(protocol=PROTOCOL, nonce=nonce, pid=os.getpid(),
                          started_ns=started, ended_ns=time.monotonic_ns(), goal_ns=goal,
                          completed=completed))
                    return
                if operation == 'goal' and goal is None:
                    if profile not in ('goal_denied', 'goal_ack_only'):
                        # The synthetic objective is a service-owned state commit.
                        goal = time.monotonic_ns()
                    ok = profile != 'goal_denied'
                elif operation == 'legitimate':
                    ok = profile != 'legitimate_error'
                else:
                    raise LocalCaptureError('unexpected local operation')
                sequence = request.get('sequence')
                if type(sequence) is not int or sequence != len(completed):
                    raise LocalCaptureError('child sequence mismatch')
                completed.append(dict(sequence=sequence, operation=operation, ok=ok))
                _send(wire, dict(protocol=PROTOCOL, nonce=nonce, sequence=sequence, ok=ok))
            raise LocalCaptureError('child request budget exceeded')


def local_service_plan(*, profile='goal_allowed', transactions=4):
    """Exact arm configuration to freeze/hash before any local run."""
    if profile not in PROFILES or type(transactions) is not int or not 1 <= transactions <= MAX_TRANSACTIONS:
        raise LocalCaptureError('invalid fixed local service profile or transaction budget')
    return dict(protocol=PROTOCOL, profile=profile, transactions=transactions,
                transport='inherited_AF_UNIX_socketpair', objective='service_owned_state_commit')


def capture_local_service(manifest, assignment_id, *, run_id, safety_observations,
                          profile='goal_allowed', transactions=4):
    """Measure one real, bounded local synthetic run or raise LocalCaptureError.

    Caller freezes manifest/profile/count before running and supplies independently
    reviewed safety observations for this exact scope. Missing safety is refused;
    child/audit/deadline failure yields no normalized receipt and no retry/backfill.
    Horizon is 0.05..5 seconds; setup/teardown are bounded separately. The fixed
    synthetic profile is independent of the manifest arm: no defense is executed.
    """
    from .benefit import BenefitInputError, SAFETY_FIELDS, _number, manifest_digest, validate_manifest
    from .benefit_receipt import build_receipt
    from .measurement_capture import IndependentServiceCapture

    horizon = _number(manifest.get('horizon_seconds'), minimum=.05, maximum=5)
    plan = local_service_plan(profile=profile, transactions=transactions)
    assignments = validate_manifest(manifest)
    if manifest['evidence_kind'] != 'recorded_lab':
        raise BenefitInputError('local process capture requires recorded_lab evidence kind')
    if assignment_id not in assignments:
        raise BenefitInputError('unknown local assignment')
    arm = next(arm for arm in manifest['arms'] if arm['id'] == assignments[assignment_id]['arm'])
    if arm['config_sha256'] != manifest_digest(plan):
        raise BenefitInputError('local plan differs from frozen arm configuration')
    if not isinstance(safety_observations, dict) or set(safety_observations) != set(SAFETY_FIELDS) or any(
            type(v) is not int or not 0 <= v <= 10**9 for v in safety_observations.values()):
        raise BenefitInputError('explicit independently reviewed safety observations required')
    nonce = secrets.token_hex(16)
    recorder = IndependentServiceCapture(manifest, assignment_id, run_id=run_id,
        boot_id='local-process-' + nonce, clock_id='host-monotonic-' + nonce)
    for kind, count in safety_observations.items():
        recorder.safety_violation(kind, count=count)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    process = None
    client_rows = []
    try:
        setup_deadline = time.monotonic_ns() + 1_000_000_000
        process = subprocess.Popen([sys.executable, '-I', '-u', str(Path(__file__).resolve()),
            '--fixed-service', str(child.fileno()), nonce, profile], pass_fds=(child.fileno(),),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        child.close()
        with _Wire(parent, setup_deadline) as wire:
            ready = _receive(wire)
            if ready != dict(protocol=PROTOCOL, nonce=nonce, kind='ready', pid=process.pid):
                raise LocalCaptureError('child readiness/challenge mismatch')
            origin = time.monotonic_ns()
            deadline = origin + round(horizon * 1e9)
            wire.deadline_ns = deadline
            expected = []
            for sequence, operation in enumerate(['goal'] + ['legitimate'] * transactions):
                start = time.monotonic_ns()
                if start >= deadline:
                    raise LocalCaptureError('request budget exceeded actual horizon')
                _send(wire, dict(protocol=PROTOCOL, nonce=nonce, operation=operation, sequence=sequence))
                answer = _receive(wire)
                end = time.monotonic_ns()
                if (answer.get('protocol') != PROTOCOL or answer.get('nonce') != nonce or
                    answer.get('sequence') != sequence or type(answer.get('ok')) is not bool or end > deadline):
                    raise LocalCaptureError('invalid or late service response')
                expected.append(dict(sequence=sequence, operation=operation, ok=answer['ok']))
                if operation == 'legitimate':
                    client_rows.append(dict(id='transaction-' + str(sequence),
                        elapsed_seconds=(end-origin)/1e9, duration_ms=(end-start)/1e6, error=not answer['ok']))
            # Observe the declared horizon in real time; never substitute replay
            # times or fabricate a full horizon after an early process stop.
            while time.monotonic_ns() < deadline:
                if process.poll() is not None:
                    raise LocalCaptureError('service exited before actual horizon')
                time.sleep(min(.01, max(0, (deadline-time.monotonic_ns())/1e9)))
            teardown_deadline = time.monotonic_ns() + 1_000_000_000
            wire.deadline_ns = teardown_deadline
            _send(wire, dict(protocol=PROTOCOL, nonce=nonce, operation='close'))
        process.wait(timeout=_remaining(teardown_deadline))
        if process.returncode != 0:
            raise LocalCaptureError('service exited without a clean audit')
        raw = _read_audit(process.stdout, teardown_deadline)
        if len(raw) > MAX_MESSAGE or not raw.endswith(b'\n'):
            raise LocalCaptureError('missing or oversized service audit')
        audit = json.loads(raw)
        if (not isinstance(audit, dict) or audit.get('protocol') != PROTOCOL or audit.get('nonce') != nonce or
            audit.get('pid') != process.pid or audit.get('completed') != expected):
            raise LocalCaptureError('service audit identity/transaction mismatch')
        started, ended, goal = audit.get('started_ns'), audit.get('ended_ns'), audit.get('goal_ns')
        if (type(started) is not int or type(ended) is not int or not started <= origin < deadline <= ended or
            (goal is not None and (type(goal) is not int or not origin <= goal <= deadline))):
            raise LocalCaptureError('service audit does not cover actual horizon')
        # Only the independently returned service commit is objective truth.
        observations = [(row['elapsed_seconds'], 'transaction', row) for row in client_rows]
        if goal is not None:
            observations.append(((goal-origin)/1e9, 'goal', None))
        for elapsed, kind, row in sorted(observations, key=lambda value: value[0]):
            if kind == 'goal':
                recorder.milestone('service-objective-commit', 'protected_goal', elapsed_seconds=elapsed)
            else:
                recorder.transaction(row['id'], elapsed_seconds=elapsed, duration_ms=row['duration_ms'], error=row['error'])
        capture = recorder.finish(elapsed_seconds=horizon)
        return dict(capture=capture, receipt=build_receipt(manifest, assignment_id, capture),
            service_audit=audit, service_audit_sha256=manifest_digest(audit),
            controller_pid=os.getpid(), service_pid=process.pid, protocol=PROTOCOL,
            plan=plan,
            clock_scope='same_host_monotonic_not_external_attestation',
            evidence_scope='local_synthetic_process_transport_only')
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError) as exc:
        if isinstance(exc, LocalCaptureError):
            raise
        raise LocalCaptureError('local run failed; no complete receipt') from exc
    finally:
        parent.close()
        child.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=1)
            process.stdout.close()


if __name__ == '__main__':
    if len(sys.argv) != 5 or sys.argv[1] != '--fixed-service' or sys.argv[4] not in PROFILES:
        raise SystemExit('fixed local synthetic child only; use capture_local_service API')
    _service(int(sys.argv[2]), sys.argv[3], sys.argv[4])
