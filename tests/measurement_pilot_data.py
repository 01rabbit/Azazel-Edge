"""Frozen synthetic recording recipes; no traffic, process, model or actuator."""
import copy
import json
from pathlib import Path
from azazel_edge.benchmark.benefit import SAFETY_FIELDS, manifest_digest
from azazel_edge.outcome.adapter import from_rust_event
from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy

ROOT = Path(__file__).parent/'fixtures/measurement_pilot_v1'
TIMELINE = Path(__file__).parent/'fixtures/outcome/g5_golden_replay_input_v1.json'


def inputs(protocol, case):
    source = json.loads(TIMELINE.read_text())
    if manifest_digest(source) != protocol['timeline_template_sha256']:
        raise ValueError('recording template changed')
    manifest = copy.deepcopy(protocol['experiment_template'])
    manifest['experiment_id'] = case['id']
    manifest['provenance']['corpus_sha256'] = protocol['cases_sha256']
    manifest['assignments'] = [dict(id=f'{case["id"]}-p{p}-{arm}', pair_id=f'pair-{p}', arm=arm,
        scenario=case['id'], seed=100+p, order=(p+i)%2) for p in range(2) for i,arm in enumerate(('reference','candidate'))]
    records = []
    for a in manifest['assignments']:
        ns = a['id']; candidate = a['arm']=='candidate'
        recording = json.loads(json.dumps(source).replace('trace-golden', 'trace-'+ns))
        steps = recording['boots'][0]['steps']
        target = next(s['event'] for s in steps if s['op']=='event' and s['event'].get('enforcement', {}).get('trace_id') == 'trace-'+ns+'-throttle-1')
        if case['fault']=='restart' and candidate:
            target = next(s['event'] for s in steps if s['op']=='event' and s['event'].get('enforcement', {}).get('trace_id') == 'trace-'+ns+'-redirect-3')
        bundle = from_rust_event(target)
        policy = OutcomeTelemetryPolicy.from_mapping(recording['policy'], source_ref='golden-replay')
        objective = policy.objective_for(bundle.execution.action_kind, bundle.execution.decision_id)
        goals = case['goal_seconds']
        goal = goals[1 if candidate else 0]
        milestones = [{'id':'start','kind':'run_start','elapsed_seconds':0}]
        if goal is not None: milestones.append({'id':'goal','kind':'protected_goal','elapsed_seconds':goal})
        if case['fault']=='gap' and candidate: milestones.append({'id':'gap','kind':'sensor_gap','elapsed_seconds':40})
        milestones.append({'id':'end','kind':'run_end','elapsed_seconds':60})
        capture = dict(manifest_sha256=manifest_digest(manifest), assignment_id=a['id'], scenario=a['scenario'], seed=a['seed'],
            source='isolated_scenario_controller', run_id='run-'+ns, boot_id='controller-boot-'+ns,
            clock_id='controller-clock-'+ns, clock_kind='monotonic_elapsed', milestones=milestones,
            legitimate_transactions=[dict(id='transaction-'+str(i),elapsed_seconds=i+1,duration_ms=case['latency_ms'][1 if candidate else 0],error=bool(case['errors'] and candidate and i==0)) for i in range(10)],
            safety_violations=dict.fromkeys(SAFETY_FIELDS,0))
        linkage = dict(edge_boot_id='boot-1', session_ref='session-'+ns, decision_id=bundle.execution.decision_id,
            execution_id=bundle.execution.execution_id, mechanism_id=bundle.mechanism.mechanism_id, objective_id=objective.objective_id,
            recording_sha256=manifest_digest(recording), capture_sha256=manifest_digest(capture),
            clock=dict(controller_epoch_origin=1777001000, edge_epoch_origin=1777001000,
                       uncertainty_ms=50 if candidate and case['fault']=='clock' else 0),
            scope='shared_source_ambiguous' if candidate and case['fault']=='shared' else 'controlled_session',
            confounders=['artificial_actor_pause'] if candidate and case['fault']=='pause' else [])
        records.append(dict(assignment_id=a['id'],capture=capture,edge_recording=recording,linkage=linkage))
    return manifest,records
