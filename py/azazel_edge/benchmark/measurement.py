"""Offline measurement join for #400/#393. Recorded input, no execution authority.

Service truth stays separate from Edge evidence. This adapter reuses the G5
readback/release/telemetry replay and benefit calculator; it never changes a
canonical Outcome, infers an actor from an address, or promotes causal support.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from collections.abc import Mapping

from .benefit import BenefitInputError, SAFETY_FIELDS, _load, _number, analyze, manifest_digest, validate_manifest
from .benefit_receipt import build_receipt
from ..outcome.golden_replay import GoldenReplayError, run_golden_replay

LIMITS = dict(max_runs=128, max_boots=8, max_steps=1024, max_decisions=64,
              clock_uncertainty_ms_max=5, min_pre_samples=2, min_post_samples=2, min_sample_ratio=1)
MAX_BYTES = 8 * 1024 * 1024
CONFOUNDERS = {'artificial_actor_pause', 'unrelated_background_load', 'capture_loss', 'clock_uncertain'}


def _bounded(value):
    try: raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc: raise BenefitInputError('invalid finite bounded JSON') from exc
    if len(raw.encode()) > MAX_BYTES: raise BenefitInputError('measurement input exceeds byte bound')


def _ref(value):
    if type(value) is not str or re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,127}', value) is None or re.search(r'(?i)(password|secret|token|bearer|api.?key)', value):
        raise BenefitInputError('invalid or sensitive measurement reference')
    return value


def _safety(capture):
    raw = capture.get('safety_violations') if isinstance(capture, Mapping) else None
    if not isinstance(raw, Mapping) or set(raw) != set(SAFETY_FIELDS) or any(type(v) is not int or not 0 <= v <= 10**9 for v in raw.values()):
        return None
    return dict(raw)


def _recording(recording):
    if not isinstance(recording, Mapping): raise BenefitInputError('recorded Edge timeline required')
    boots = recording.get('boots')
    if not isinstance(boots, list) or not 1 <= len(boots) <= LIMITS['max_boots']:
        raise BenefitInputError('recorded boot budget exceeded')
    steps, decisions, seen_boots = 0, set(), set()
    for boot in boots:
        if not isinstance(boot, Mapping): raise BenefitInputError('invalid recorded boot')
        name = _ref(boot.get('boot'))
        if name in seen_boots: raise BenefitInputError('duplicate recorded boot')
        seen_boots.add(name)
        events = boot.get('steps')
        if not isinstance(events, list): raise BenefitInputError('recorded steps required')
        steps += len(events)
        if steps > LIMITS['max_steps']: raise BenefitInputError('recorded step budget exceeded')
        last = -1
        for step in events:
            if not isinstance(step, Mapping): raise BenefitInputError('invalid recorded step')
            epoch = _number(step.get('epoch'))
            if epoch < last: raise BenefitInputError('recorded clock moved backwards')
            last = epoch
            event = step.get('event') or {}
            if not isinstance(event, Mapping): raise BenefitInputError('invalid recorded event')
            if step.get('op') == 'event' and event.get('pipeline') == 'rust_event_engine_v1':
                enforcement = event.get('enforcement') or {}
                decision = (event.get('defense') or {}).get('action')
                if decision in ('throttle', 'redirect', 'isolate'):
                    decisions.add(_ref(enforcement.get('trace_id')))
            if len(decisions) > LIMITS['max_decisions']: raise BenefitInputError('recorded decision budget exceeded')
    return recording


def _join(manifest, assignment, record):
    capture, linkage, recording = record['capture'], record['linkage'], record['edge_recording']
    source_receipt = build_receipt(manifest, assignment['id'], capture)
    for name in ('run_id', 'boot_id', 'clock_id'): _ref(capture.get(name))
    # Completion timestamps and durations must describe transactions wholly
    # inside the independently observed common horizon, including timeouts.
    for tx in capture['legitimate_transactions']:
        if tx['duration_ms'] > tx['elapsed_seconds'] * 1000:
            raise BenefitInputError('transaction starts before the run horizon')
    if not isinstance(linkage, Mapping) or linkage.get('capture_sha256') != manifest_digest(capture):
        raise BenefitInputError('service capture binding mismatch')
    reasons = []
    _ref(linkage.get('session_ref'))
    if linkage.get('scope') not in ('controlled_session', 'shared_source_ambiguous'):
        raise BenefitInputError('explicit session attribution required')
    if linkage['scope'] != 'controlled_session': reasons.append('shared_source_not_session_identity')
    confounders = linkage.get('confounders')
    if not isinstance(confounders, list) or len(confounders) > len(CONFOUNDERS) or any(type(c) is not str or c not in CONFOUNDERS for c in confounders) or len(set(confounders)) != len(confounders):
        raise BenefitInputError('invalid closed confounders')
    reasons.extend(confounders)
    clock = linkage.get('clock')
    if not isinstance(clock, Mapping) or set(clock) != {'edge_epoch_origin','controller_epoch_origin','uncertainty_ms'}:
        raise BenefitInputError('explicit minimized clock mapping required')
    edge_origin = _number(clock.get('edge_epoch_origin'))
    controller_origin = _number(clock.get('controller_epoch_origin'))
    uncertainty = _number(clock.get('uncertainty_ms'))
    if uncertainty > LIMITS['clock_uncertainty_ms_max'] or abs(edge_origin-controller_origin)*1000 > LIMITS['clock_uncertainty_ms_max']:
        reasons.append('clock_alignment_uncertain')
    if recording is None and assignment['arm'] == manifest['baseline']:
        role = next(a['role'] for a in manifest['arms'] if a['id'] == assignment['arm'])
        if role != 'observe_only' or linkage.get('recording_sha256') is not None:
            raise BenefitInputError('missing Edge evidence is not an observe-only baseline')
        edge = {'status': 'not_applicable_observe_only', 'causal_support': 'inconclusive'}
        replay_sha = None
        identity = None
    else:
        _recording(recording)
        if linkage.get('recording_sha256') != manifest_digest(recording):
            raise BenefitInputError('Edge recording binding mismatch')
        if manifest['provenance']['policy_sha256'] != manifest_digest(recording.get('policy')):
            raise BenefitInputError('recording policy differs from frozen experiment')
        for name in ('edge_boot_id', 'decision_id', 'execution_id', 'mechanism_id', 'objective_id'): _ref(linkage.get(name))
        replay = run_golden_replay(recording)
        traces = [t for t in replay['decisions'] if t['decision_id'] == linkage['decision_id']]
        if len(traces) != 1: raise BenefitInputError('unknown or ambiguous decision binding')
        trace = traces[0]; stages = trace['stages']; correlation = stages['correlation']
        if trace['first_boot'] != linkage['edge_boot_id'] or any(correlation.get(k) != linkage[k] for k in ('decision_id', 'execution_id', 'mechanism_id')):
            raise BenefitInputError('cross-boot/decision/execution/mechanism binding')
        objective = stages.get('objective')
        # An absent Outcome (e.g. lost restart window) must not prevent checking
        # the objective against the original frozen policy.
        from ..outcome.telemetry import OutcomeTelemetryPolicy
        expected = OutcomeTelemetryPolicy.from_mapping(recording['policy'], source_ref='golden-replay').objective_for(trace['action'], trace['decision_id'])
        if expected is None or expected.objective_id != linkage['objective_id']:
            raise BenefitInputError('cross-objective binding')
        initial, final = stages['execution'], stages.get('execution_final') or stages['execution']
        postcondition = stages.get('mechanism_postcondition') or stages['mechanism']
        if initial['status'] != 'applied': reasons.append('execution_not_applied')
        if postcondition['status'] != 'observed': reasons.append('mechanism_not_independently_observed')
        outcome = stages.get('outcome')
        if any(g['decision_id'] == trace['decision_id'] for g in replay['restart_gaps']): reasons.append('observation_window_lost_at_restart')
        if not outcome: reasons.append('outcome_unavailable')
        coverage = outcome['telemetry_coverage'] if outcome else {}
        if outcome:
            if any(outcome.get(k) != linkage[k] for k in ('decision_id','execution_id','mechanism_id','objective_id')):
                raise BenefitInputError('cross-Outcome binding')
            if not objective or objective['objective_id'] != outcome['objective_id']:
                raise BenefitInputError('missing or different policy objective')
            if coverage.get('pre_sample_count',0) < LIMITS['min_pre_samples'] or coverage.get('post_sample_count',0) < LIMITS['min_post_samples']:
                reasons.append('insufficient_telemetry_samples')
            ratios = [coverage.get('pre_sample_ratio'),coverage.get('post_sample_ratio')]
            ratios += [(coverage.get('sources') or {}).get(k) for k in ('proc_net_dev_sample_ratio','proc_loadavg_sample_ratio','proc_meminfo_sample_ratio')]
            if any(type(v) not in (int,float) or v < LIMITS['min_sample_ratio'] for v in ratios): reasons.append('telemetry_coverage_incomplete')
            window = outcome['observation_window']
            if any(not 0 <= _number(window.get(k))-edge_origin <= manifest['horizon_seconds'] for k in ('baseline_start_epoch','action_observed_epoch','effective_end_epoch')):
                reasons.append('edge_window_outside_trial_horizon')
        releases = [r['evidence']['release_task_id'] for r in stages.get('release',[]) if r['reconciliation']=='released']
        if final['status'] != 'released' or not releases: reasons.append('release_absence_not_verified')
        edge = {k:correlation[k] for k in ('incident_id','decision_id','execution_id','mechanism_id')}
        edge.update(edge_boot_id=trace['first_boot'], objective_id=linkage['objective_id'], outcome_id=outcome['outcome_id'] if outcome else None,
            execution_status=initial['status'],mechanism_status=postcondition['status'],final_execution_status=final['status'],
            release_ids=[_ref(r) for r in releases], scope_kind=initial['scope'].get('scope_kind'),
            causal_support=outcome['causal_support'] if outcome else 'inconclusive',
            telemetry_coverage={k:coverage.get(k) for k in ('pre_sample_count','post_sample_count','pre_sample_ratio','post_sample_ratio')})
        for key in ('incident_id','decision_id','execution_id','mechanism_id','objective_id'):_ref(edge[key])
        if edge['outcome_id'] is not None:_ref(edge['outcome_id'])
        replay_sha = manifest_digest(replay)
        identity = (trace['first_boot'], correlation['execution_id'], linkage['objective_id'])
    if not source_receipt['horizon_verified']: reasons.append('controller_capture_incomplete')
    comparison = dict(source_receipt)
    if reasons: comparison.update(status='missing',horizon_verified=False)
    # The comparison's integrity digest includes all three recorded producers;
    # the original independent-service receipt and canonical facts are unchanged.
    comparison['evidence_sha256'] = manifest_digest({'capture':capture,'recording':recording,'linkage':linkage})
    latencies = sorted(t['duration_ms'] for t in capture['legitimate_transactions'])
    detections = [e['elapsed_seconds'] for e in capture['milestones'] if e['kind']=='actionable_detection']
    detection = min(detections) if detections else None
    goal = source_receipt['protected_goal_seconds']
    margin = dict(seconds=(manifest['horizon_seconds'] if goal is None else goal)-detection if detection is not None else None,
                  detection_elapsed_seconds=detection, goal_censored=goal is None,
                  reason='recorded_detection_to_goal_or_horizon' if detection is not None else 'actionable_detection_not_recorded')
    return {'assignment_id':assignment['id'], 'status':'qualified' if not reasons else 'withheld', 'reasons':sorted(set(reasons)),
            'session_ref':linkage['session_ref'], 'attribution':linkage['scope'],
            'controller_boot_id':capture['boot_id'], 'controller_clock_id':capture['clock_id'],
            'clock_mapping':dict(clock), 'capture_sha256':manifest_digest(capture), 'replay_sha256':replay_sha,
            'edge_evidence':edge, 'recorded_service_receipt':source_receipt, 'comparison_receipt':comparison,
            'legitimate_latency_p50_ms':latencies[math.ceil(.5*len(latencies))-1],
            'legitimate_completion_rate':1-source_receipt['legitimate_errors']/source_receipt['legitimate_transactions'],
            'safe_response_margin':margin, '_identity':identity}


def measure_experiment(manifest, inputs):
    _bounded(manifest); _bounded(inputs)
    assignments = validate_manifest(manifest)
    _ref(manifest['experiment_id'])
    for arm in manifest['arms']:
        if set(arm) != {'id','role','source_commit','config_sha256','environment_id'}:
            raise BenefitInputError('unexpected arm metadata cannot enter minimized reports')
        for field in ('id','role','environment_id'): _ref(arm[field])
    for assignment in assignments.values():
        for field in ('id','pair_id','arm','scenario'): _ref(assignment[field])
    if len(assignments) > LIMITS['max_runs']:
        raise BenefitInputError('measurement run budget exceeded')
    if not isinstance(inputs, Mapping) or inputs.get('manifest_sha256') != manifest_digest(manifest):
        raise BenefitInputError('measurement manifest binding mismatch')
    records = inputs.get('records')
    if not isinstance(records,list) or len(records) > len(assignments): raise BenefitInputError('bounded unique run records required')
    seen, run_ids, evidence_scopes, ledger, receipts = set(), set(), set(), [], []
    for record in records:
        if not isinstance(record,Mapping): raise BenefitInputError('invalid run record')
        key = record.get('assignment_id')
        if type(key) is not str or key not in assignments or key in seen: raise BenefitInputError('unknown or duplicate assignment')
        seen.add(key)
        capture = record.get('capture')
        run_id = None
        try:
            run_id = _ref(capture.get('run_id')) if isinstance(capture,Mapping) else None
            if run_id is None or run_id in run_ids: raise BenefitInputError('missing/duplicate run identity')
            run_ids.add(run_id)
            row = _join(manifest,assignments[key],record)
            identity = row.pop('_identity')
            if identity is not None and identity in evidence_scopes: raise BenefitInputError('cross-run reuse of Edge execution evidence')
            if identity is not None: evidence_scopes.add(identity)
            receipts.append(row['comparison_receipt'])
        except (BenefitInputError,GoldenReplayError,ValueError,TypeError,KeyError,AttributeError,OverflowError):
            row = {'assignment_id':key,'status':'rejected','reasons':['invalid_capture_or_linkage']}
            safety = _safety(capture)
            if safety is not None:
                # This is a local rejected-assignment key, never a fabricated
                # source run identity. Preserve measured safety even if the
                # reported run ID is absent, invalid or reused.
                rejected_id = 'rejected-' + manifest_digest({'assignment_id':key})[:24]
                receipt = dict(assignment_id=key,run_id=rejected_id,status='failed',horizon_verified=False,
                               safety_violations=safety,evidence_sha256=manifest_digest(record))
                receipts.append(receipt)
                row['receipt_identity_basis'] = 'local_rejected_assignment_not_source_run'
        ledger.append(row)
    for key in assignments.keys()-seen: ledger.append({'assignment_id':key,'status':'not_received','reasons':['assigned_run_missing']})
    report = analyze(manifest,{'manifest_sha256':manifest_digest(manifest),'runs':receipts})
    rejected = sum(r['status']=='rejected' for r in ledger)
    if rejected and report['measurement_gate'] != 'safety_failed': report['measurement_gate']='measurement_integrity_failed'
    return {'schema_version':'edge-measurement-bundle/v1','manifest_sha256':manifest_digest(manifest),
            'inputs_sha256':manifest_digest(inputs),'limits':dict(LIMITS),'assigned_runs':len(assignments),
            'received_runs':len(records),'measurement_mode':'recorded_replay','ledger':sorted(ledger,key=lambda r:r['assignment_id']), 'integrity_rejections':rejected,
            'comparison':report,'canonical_records_mutated':False,'authorized_actions':[],
            'limitations':['recorded replay is not live enforcement, independent source authentication or a counterfactual trial',
                           'session and clock bindings are controller declarations requiring independent review',
                           'no source address or canary touch establishes actor identity',
                           'runtime causal support is not upgraded by scientific comparison results']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest');parser.add_argument('inputs');args=parser.parse_args()
    try: result=measure_experiment(_load(args.manifest),_load(args.inputs))
    except (BenefitInputError,OSError,ValueError,TypeError,KeyError,RecursionError) as exc:parser.exit(2,f'invalid measurement input: {exc}\n')
    print(json.dumps(result,sort_keys=True,indent=2,allow_nan=False))
    return 0 if not result['integrity_rejections'] else 1


if __name__=='__main__':raise SystemExit(main())
