import copy
import io
import json
import os
from pathlib import Path
from unittest.mock import patch
import pytest

from measurement_pilot_data import ROOT, inputs
from azazel_edge.benchmark.benefit import BenefitInputError, manifest_digest
from azazel_edge.benchmark.measurement import LIMITS, measure_experiment
from azazel_edge.benchmark.measurement_capture import IndependentServiceCapture
from azazel_edge.outcome.golden_replay import run_golden_replay


def data(case_id='gain'):
    protocol=json.loads((ROOT/'protocol.json').read_text());cases=json.loads((ROOT/'cases.json').read_text())
    case=next(c for c in cases if c['id']==case_id);m,rs=inputs(protocol,case)
    return m,dict(manifest_sha256=manifest_digest(m),records=rs)


def test_frozen_protocol_all_scenarios_expected_gates_and_linkage():
    protocol=json.loads((ROOT/'protocol.json').read_text());cases=json.loads((ROOT/'cases.json').read_text())
    assert manifest_digest(protocol)==(ROOT/'protocol.sha256').read_text().strip()
    assert protocol['cases_sha256']==manifest_digest(cases) and protocol['measurement_limits']==LIMITS
    for case in cases:
        m,rs=inputs(protocol,case)
        for r in rs:
            pin=protocol['bindings'][r['assignment_id']]
            assert pin['capture_sha256']==manifest_digest(r['capture'])
            assert pin['recording_sha256']==manifest_digest(r['edge_recording'])
            assert pin['linkage_sha256']==manifest_digest(r['linkage'])
        before=copy.deepcopy((m,rs))
        result=measure_experiment(m,{'manifest_sha256':manifest_digest(m),'records':rs})
        assert (m,rs)==before
        assert result['comparison']['measurement_gate']==case['expected_gate']
        assert result['comparison']['claim_status']=='mechanical_only'
        assert not result['integrity_rejections'] and result['assigned_runs']==4
        for row in result['ledger']:
            assert row['edge_evidence']['causal_support']=='inconclusive'
            assert not result['authorized_actions'] and not result['canonical_records_mutated']
            assert '10.0.' not in json.dumps(row)
            assert 'owner_token' not in json.dumps(row) and 'command_plan' not in json.dumps(row)
            assert row['comparison_receipt']['horizon_verified']==(row['status']=='qualified')


def test_service_receipt_remains_true_when_edge_join_is_withheld():
    m,rs=data('shared_source');report=measure_experiment(m,rs)
    withheld=next(r for r in report['ledger'] if r['status']=='withheld')
    assert withheld['recorded_service_receipt']['horizon_verified']
    assert withheld['recorded_service_receipt']['protected_goal_seconds']==30
    assert not withheld['comparison_receipt']['horizon_verified']
    assert report['comparison']['incomplete_pairs']==2


@pytest.mark.parametrize('field,value',[('decision_id','other-decision'),('execution_id','other-execution'),('mechanism_id','other-mechanism'),('objective_id','other-objective'),('edge_boot_id','other-boot'),('capture_sha256','0'*64),('recording_sha256','0'*64)])
def test_wrong_bindings_are_rejected_without_dropping_denominator(field,value):
    m,rs=data();rs['records'][0]['linkage'][field]=value
    report=measure_experiment(m,rs)
    assert report['assigned_runs']==4 and len(report['ledger'])==4
    assert report['integrity_rejections']==1 and report['comparison']['measurement_gate']=='measurement_integrity_failed'
    assert report['comparison']['run_status_counts']['failed']==1


def test_duplicate_run_and_missing_safety_are_not_success():
    m,rs=data();rs['records'][1]['capture']['run_id']=rs['records'][0]['capture']['run_id']
    result=measure_experiment(m,rs);assert result['integrity_rejections']==1
    assert result['comparison']['measurement_gate']=='measurement_integrity_failed'
    m,rs=data();rs['records'][0]['capture'].pop('safety_violations')
    result=measure_experiment(m,rs);assert result['integrity_rejections']==1
    assert result['comparison']['missing_runs']==1
    m,rs=data();rs['records'].pop()
    result=measure_experiment(m,rs);assert result['received_runs']==3 and result['assigned_runs']==4
    assert result['ledger'][-1]['status']=='not_received' or any(r['status']=='not_received' for r in result['ledger'])
    assert result['comparison']['measurement_gate']=='inconclusive_missing_or_insufficient_pairs'


def test_safety_failure_is_preserved_even_with_an_invalid_link():
    m,rs=data();r=rs['records'][0];r['capture']['safety_violations']['protected_escape']=1
    r['linkage']['capture_sha256']=manifest_digest(r['capture']);r['linkage']['execution_id']='wrong-execution'
    result=measure_experiment(m,rs)
    assert result['comparison']['measurement_gate']=='safety_failed'


def test_boot_clock_step_and_size_caps_fail_before_replay():
    m,rs=data();r=rs['records'][0]
    r['edge_recording']['boots'][0]['steps']*=200
    r['linkage']['recording_sha256']=manifest_digest(r['edge_recording'])
    with patch('azazel_edge.benchmark.measurement.run_golden_replay',side_effect=AssertionError('unbounded replay')):
        limited=copy.deepcopy(rs);limited['records']=limited['records'][:1]
        assert measure_experiment(m,limited)['integrity_rejections']==1
    m,rs=data();rs['records'][0]['edge_recording']['boots'][0]['steps'][1]['epoch']=0
    rs['records'][0]['linkage']['recording_sha256']=manifest_digest(rs['records'][0]['edge_recording'])
    assert measure_experiment(m,rs)['integrity_rejections']==1
    m,rs=data();rs['padding']='x'*(8*1024*1024)
    with pytest.raises(BenefitInputError,match='byte'):measure_experiment(m,rs)


def test_no_live_boundary_or_canonical_change_and_deterministic_reproduction():
    m,rs=data();canonical=run_golden_replay(rs['records'][0]['edge_recording']);before=copy.deepcopy(rs)
    def denied(*a,**k):raise AssertionError('live I/O or executor called')
    with patch('builtins.open',denied),patch('io.open',denied),patch('os.open',denied),patch('socket.socket',denied),patch('subprocess.run',denied),patch('subprocess.Popen',denied),patch('time.time',denied),patch('time.monotonic',denied):
        a=measure_experiment(m,rs);b=measure_experiment(m,json.loads(json.dumps(rs)))
    assert a==b and rs==before
    assert run_golden_replay(rs['records'][0]['edge_recording'])==canonical


def test_independent_recorder_round_trip_and_no_alert_substitution():
    m,rs=data();a=m['assignments'][0]
    recorder=IndependentServiceCapture(m,a['id'],run_id='run-observed',boot_id='controller-boot-a',clock_id='controller-clock-a')
    assert recorder.transaction('transaction-one',elapsed_seconds=1,duration_ms=20,error=False)
    assert not recorder.transaction('transaction-one',elapsed_seconds=1,duration_ms=20,error=False)
    recorder.milestone('goal-one','protected_goal',elapsed_seconds=10)
    cap=recorder.finish(elapsed_seconds=60)
    rs['records'][0]['capture']=cap;rs['records'][0]['linkage']['capture_sha256']=manifest_digest(cap)
    assert measure_experiment(m,rs)['ledger'][0]['status']=='qualified'
    with pytest.raises(BenefitInputError):recorder.milestone('late','protected_goal',elapsed_seconds=60)
    r=IndependentServiceCapture(m,a['id'],run_id='run-other',boot_id='controller-boot-a',clock_id='controller-clock-a')
    with pytest.raises(BenefitInputError):r.milestone('alert-one','IDS_alert',elapsed_seconds=1)


def test_recorder_early_stop_and_overflow_never_create_a_complete_horizon():
    m,rs=data();a=m['assignments'][0]
    r=IndependentServiceCapture(m,a['id'],run_id='run-early',boot_id='controller-boot-a',clock_id='controller-clock-a')
    r.transaction('transaction-one',elapsed_seconds=1,duration_ms=10,error=False)
    early=r.finish(elapsed_seconds=10)
    rs['records'][0]['capture']=early;rs['records'][0]['linkage']['capture_sha256']=manifest_digest(early)
    assert measure_experiment(m,rs)['integrity_rejections']==1
    r=IndependentServiceCapture(m,a['id'],run_id='run-overflow',boot_id='controller-boot-a',clock_id='controller-clock-a')
    r.transaction('transaction-one',elapsed_seconds=1,duration_ms=10,error=False)
    with patch('azazel_edge.benchmark.measurement_capture.MAX_ITEMS',4):
        r.milestone('fact-one','discovery',elapsed_seconds=2)
        assert not r.milestone('fact-two','protected_reach',elapsed_seconds=3)
        cap=r.finish(elapsed_seconds=60)
    assert len(cap['milestones'])==4 and any(e['kind']=='sensor_gap' for e in cap['milestones'])
    rs['records'][0]['capture']=cap;rs['records'][0]['linkage']['capture_sha256']=manifest_digest(cap)
    result=measure_experiment(m,rs)
    assert result['comparison']['measurement_gate']=='inconclusive_missing_or_insufficient_pairs'


def test_invalid_capture_attempt_taints_coverage_and_cannot_be_ignored():
    m,rs=data();a=m['assignments'][0]
    r=IndependentServiceCapture(m,a['id'],run_id='run-invalid',boot_id='controller-boot-a',clock_id='controller-clock-a')
    r.transaction('transaction-one',elapsed_seconds=1,duration_ms=10,error=False)
    with pytest.raises(BenefitInputError):r.transaction('bad-time',elapsed_seconds=float('nan'),duration_ms=1,error=False)
    cap=r.finish(elapsed_seconds=60)
    assert any(e['kind']=='sensor_gap' for e in cap['milestones'])
    rs['records'][0]['capture']=cap;rs['records'][0]['linkage']['capture_sha256']=manifest_digest(cap)
    assert measure_experiment(m,rs)['comparison']['measurement_gate']=='inconclusive_missing_or_insufficient_pairs'


def test_no_action_baseline_is_explicit_not_fabricated_execution():
    m,rs=data();m['arms'][0]['role']='observe_only';rs['manifest_sha256']=manifest_digest(m)
    for row in rs['records']:
        row['capture']['manifest_sha256']=manifest_digest(m)
        row['linkage']['capture_sha256']=manifest_digest(row['capture'])
        if row['assignment_id'].endswith('reference'):
            row['edge_recording']=None;row['linkage']['recording_sha256']=None
    report=measure_experiment(m,rs)
    assert not report['integrity_rejections']
    baseline=next(row for row in report['ledger'] if row['assignment_id'].endswith('reference'))
    assert baseline['edge_evidence']=={'status':'not_applicable_observe_only','causal_support':'inconclusive'}


def test_executable_pilot_exports_replayable_set_and_disk_failure_is_visible(tmp_path):
    from run_measurement_pilot import run
    root=tmp_path/'pilot';report=run(root)
    assert report['assigned_runs']==36 and report['scenarios']==9 and report['claim_status']=='mechanical_only'
    m=json.loads((root/'gain-manifest.json').read_text());rs=json.loads((root/'gain-inputs.json').read_text())
    assert measure_experiment(m,rs)==json.loads((root/'gain-bundle.json').read_text())
    with pytest.raises(FileExistsError):run(root)
    original=Path.open
    def disk_full(path, mode='r', *args, **kwargs):
        if mode=='x':raise OSError(28,'No space left on device')
        return original(path,mode,*args,**kwargs)
    with patch('pathlib.Path.open',disk_full):
        with pytest.raises(OSError):run(tmp_path/'disk-full')
    assert not (tmp_path/'disk-full/report.json').exists()


@pytest.mark.parametrize('detection,goal,expected',[(2,10,8),(12,10,-2),(2,None,58)])
def test_safe_margin_uses_controller_detection_not_alert_or_ttl(detection,goal,expected):
    m,rs=data();r=rs['records'][0];cap=r['capture']
    cap['milestones']=[dict(id='start',kind='run_start',elapsed_seconds=0),dict(id='detection',kind='actionable_detection',elapsed_seconds=detection)]
    if goal is not None:cap['milestones'].append(dict(id='goal',kind='protected_goal',elapsed_seconds=goal))
    cap['milestones'].sort(key=lambda x:x['elapsed_seconds'])
    cap['milestones'].append(dict(id='end',kind='run_end',elapsed_seconds=60))
    r['linkage']['capture_sha256']=manifest_digest(cap)
    out=measure_experiment(m,rs)
    assert not out['integrity_rejections']
    row=next(row for row in out['ledger'] if row['assignment_id']==r['assignment_id'])
    assert row['safe_response_margin']['seconds']==expected
    assert row['safe_response_margin']['goal_censored']==(goal is None)


def test_unsafe_capture_with_missing_run_id_still_fails_safety():
    m,rs=data();r=rs['records'][0];r['capture'].pop('run_id')
    r['capture']['safety_violations']['protected_escape']=1
    out=measure_experiment(m,rs)
    assert out['integrity_rejections']==1 and out['comparison']['measurement_gate']=='safety_failed'
    rejected=next(row for row in out['ledger'] if row['status']=='rejected')
    assert rejected['receipt_identity_basis']=='local_rejected_assignment_not_source_run'


def test_metadata_cannot_echo_secrets_into_minimized_bundle():
    m,rs=data();m['arms'][0]['raw_owner_token']='not-for-public-output'
    rs['manifest_sha256']=manifest_digest(m)
    with pytest.raises(BenefitInputError,match='metadata'):measure_experiment(m,rs)
    m,rs=data();rs['records'][0]['linkage']['clock']['raw_payload']='not-for-public-output'
    result=measure_experiment(m,rs)
    assert result['integrity_rejections']==1 and 'not-for-public-output' not in json.dumps(result)
    m,rs=data();m['assignments'][0]['scenario']='secret-account';rs['manifest_sha256']=manifest_digest(m)
    # Pair validation or safe-reference validation refuses the secret-shaped ID.
    with pytest.raises(BenefitInputError):measure_experiment(m,rs)
