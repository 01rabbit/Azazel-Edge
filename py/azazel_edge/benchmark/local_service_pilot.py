"""Opt-in fixed local synthetic controls with durable no-resume accounting.

This runner executes only the fixed local service capture, never a product arm.
Stored checkpoints are colocated exports, not independent rollback witnesses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

from .benefit import BenefitInputError, MAX_BYTES, SAFETY_FIELDS, analyze, manifest_digest, validate_manifest
from .local_service_capture import capture_local_service, local_service_plan
from .run_ledger import RunLedger

SCOPE = 'local_synthetic_processes_only_no_edge_or_external_assets'
CONTROLS = ('goal_allowed', 'goal_denied', 'goal_ack_only', 'legitimate_error')
TRANSACTIONS = 4
MAX_ASSIGNMENTS = 16


class PilotRunError(RuntimeError):
    """Attempt failed; preserve its new directory and never automatically rerun."""


def _frozen_copy(value):
    try:
        raw = json.dumps(value, allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError) as exc:
        raise BenefitInputError('finite local pilot registration JSON required') from exc
    if len(raw) > MAX_BYTES:
        raise BenefitInputError('pilot registration exceeds byte bound')
    return json.loads(raw)


def _validate(manifest, safety_by_assignment, scope_acknowledgment):
    assignments = validate_manifest(manifest)
    if (scope_acknowledgment != SCOPE or manifest['phase'] != 'pilot' or
        manifest['evidence_kind'] != 'recorded_lab' or not .05 <= manifest['horizon_seconds'] <= 5 or
        not 8 <= len(assignments) <= MAX_ASSIGNMENTS):
        raise BenefitInputError('fixed recorded_lab local pilot scope/budget required')
    arms = manifest['arms']
    if (len(arms) != 4 or {arm['id'] for arm in arms} != set(CONTROLS) or
        manifest['baseline'] != 'goal_allowed' or manifest['candidate'] != 'goal_denied'):
        raise BenefitInputError('exact local synthetic control arms required')
    for arm in arms:
        if (set(arm) != {'id', 'role', 'source_commit', 'config_sha256', 'environment_id'} or
            arm['role'] != 'local_synthetic_control' or
            arm['config_sha256'] != manifest_digest(local_service_plan(profile=arm['id'], transactions=TRANSACTIONS))):
            raise BenefitInputError('local synthetic role/frozen control plan mismatch')
    pairs = {}
    for assignment in assignments.values():
        pairs.setdefault(assignment['pair_id'], []).append(assignment)
    if any({a['arm'] for a in group} != set(CONTROLS) for group in pairs.values()):
        raise BenefitInputError('every local pair must include all four controls')
    if (not isinstance(safety_by_assignment, dict) or set(safety_by_assignment) != set(assignments) or
        any(not isinstance(safety, dict) or set(safety) != set(SAFETY_FIELDS) or
            any(type(v) is not int or not 0 <= v <= 10**9 for v in safety.values())
            for safety in safety_by_assignment.values())):
        raise BenefitInputError('explicit reviewed safety for every local assignment required')
    # Pair identifiers determine only execution order, never filesystem paths.
    return [a for pair in sorted(pairs) for a in sorted(pairs[pair], key=lambda a: a['order'])]


def _write_new(directory_fd, name, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    if len(raw) > MAX_BYTES:
        raise BenefitInputError('pilot artifact exceeds byte bound')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError('pilot artifact write made no progress')
            remaining = remaining[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)


def _checkpoint(directory_fd, ledger, number):
    _write_new(directory_fd, f'checkpoint-{number:03d}.json', dict(
        manifest_sha256=manifest_digest(ledger.manifest), head_sha256=ledger.head_sha256,
        checkpoint_scope='colocated_export_not_independent_rollback_witness',
        operator_action='retain_exact_head_outside_this_store_before_any_separate_reopen'))


def _summary(ledger, status):
    snapshot = ledger.snapshot()
    report = analyze(ledger.manifest, snapshot['observations'])
    if report['claim_status'] != 'mechanical_only':
        raise BenefitInputError('local synthetic pilot cannot promote a defense claim')
    return dict(schema_version='azazel-local-service-pilot/v1', status=status,
        evidence_scope='local_synthetic_process_transport_only', scope_acknowledgment=SCOPE,
        authorized_actions=[], snapshot=snapshot, comparison=report,
        limitations=['fixed synthetic service controls execute no advertised defense arm',
                    'caller-supplied safety applies only to the acknowledged closed local scope',
                    'no external network, provider, C0-C6, hardware or causal acceptance',
                    'colocated checkpoint exports require independent operator retention',
                    'no resume, retry, recovery, missing-receipt backfill or overwrite'])


def run_local_pilot(manifest, output_dir, *, safety_by_assignment, scope_acknowledgment):
    """Create a fresh private store and execute fixed controls once in frozen order.

    Caller must independently establish the acknowledged closed scope and review
    supplied safety observations. Unobserved product safety is never zero-filled.
    Any failure retains the used directory and running/pending ledger states.
    """
    # Bound/freeze before validation or execution: caller mutations cannot alter
    # subsequent runs or safety/configuration bindings in this invocation.
    manifest = _frozen_copy(manifest)
    safety_by_assignment = _frozen_copy(safety_by_assignment)
    order = _validate(manifest, safety_by_assignment, scope_acknowledgment)
    output = Path(output_dir)
    os.mkdir(output, mode=0o700)  # Existing directories, including symlinks, fail.
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        info = os.fstat(directory_fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise BenefitInputError('pilot store must be caller-owned and private')
        _write_new(directory_fd, 'registration.json', dict(manifest=manifest,
            manifest_sha256=manifest_digest(manifest), safety_by_assignment=safety_by_assignment,
            scope_acknowledgment=scope_acknowledgment,
            execution_order=[a['id'] for a in order]))
        with RunLedger(output / 'runs.jsonl', manifest=manifest) as ledger:
            checkpoint = 0
            current = None
            try:
                _checkpoint(directory_fd, ledger, checkpoint)
                for assignment in order:
                    current = assignment['id']
                    run_id = 'local-run-' + secrets.token_hex(16)
                    ledger.start(current, run_id)
                    checkpoint += 1
                    _checkpoint(directory_fd, ledger, checkpoint)
                    result = capture_local_service(manifest, current, run_id=run_id,
                        safety_observations=safety_by_assignment[current],
                        profile=assignment['arm'], transactions=TRANSACTIONS)
                    name = 'capture-' + hashlib.sha256(current.encode()).hexdigest() + '.json'
                    # Full evidence is durable before its receipt can be admitted.
                    _write_new(directory_fd, name, result)
                    ledger.finish(result['receipt'])
                    checkpoint += 1
                    _checkpoint(directory_fd, ledger, checkpoint)
                summary = _summary(ledger, 'complete')
                _write_new(directory_fd, 'report.json', summary)
                return summary
            except BaseException as exc:
                # Never fill missing capture/safety with successful zero values.
                # Failure export is best effort; the durable ledger is primary.
                try:
                    failure = _summary(ledger, 'failed')
                    failure['failure'] = dict(assignment_id=current, exception_type=type(exc).__name__)
                    _write_new(directory_fd, 'failure.json', failure)
                except (OSError, ValueError, TypeError):
                    pass
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise PilotRunError('local pilot failed; preserve used directory, no automatic resume or retry') from exc
    finally:
        os.close(directory_fd)


def _read_json(path):
    with open(path, 'rb') as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise BenefitInputError('pilot input exceeds byte bound')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BenefitInputError('duplicate pilot input key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(BenefitInputError('nonfinite pilot input')))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest')
    parser.add_argument('safety_by_assignment')
    parser.add_argument('new_output_directory')
    parser.add_argument('--acknowledge-local-synthetic-scope', action='store_true', required=True)
    args = parser.parse_args(argv)
    summary = run_local_pilot(_read_json(args.manifest), args.new_output_directory,
        safety_by_assignment=_read_json(args.safety_by_assignment), scope_acknowledgment=SCOPE)
    print(json.dumps(dict(status=summary['status'], evidence_scope=summary['evidence_scope'],
                          claim_status=summary['comparison']['claim_status']), sort_keys=True))


if __name__ == '__main__':
    main()
