from copy import deepcopy
from unittest.mock import patch
import pytest
from azazel_edge.benchmark.benefit import BenefitInputError, manifest_digest
from azazel_edge.benchmark.operator_study import analyze, validate_plan


def fixture():
    plan=dict(schema_version='azazel-operator-study/v1',phase='pilot',evidence_kind='synthetic',rubric_sha256='a'*64,holdout_corpus_sha256='b'*64,sample_size_plan_sha256='c'*64,registration_sha256='d'*64,render_sha256={'classic':'e'*64,'overview':'f'*64},task_horizon_seconds=60,task_cards={f'case-{i}':{'prompt':'Identify the current state and safe next step.','options':[{'id':'choice-unknown','label':'Unknown; verify evidence'},{'id':'choice-executed','label':'Executed action is proven'}]} for i in range(2)},analysis=dict(minimum_participants=2,bootstrap_repeats=100,seed=42,max_correctness_loss=0,max_handoff_loss=0,minimum_time_gain_seconds=5),assignments=[])
    for p in range(4):
        for case in range(2):
            for arm in ('classic','overview'):
                plan['assignments'].append(dict(id=f't-{p}-{case}-{arm}',participant=f'p-{p:016x}',case=f'case-{case}',arm=arm,order=1+((p+(arm=='overview'))%2),snapshot_sha256=str(case)*64))
    observations={'plan_sha256':manifest_digest(plan),'receipts':[]}
    for a in plan['assignments']:
        observations['receipts'].append(dict(assignment_id=a['id'],consented=True,blinded_scoring=True,correct=True,unsafe_choice=False,timed_out=False,elapsed_seconds=30 if a['arm']=='classic' else 20,handoff_score=1,rubric_sha256=plan['rubric_sha256'],render_sha256=plan['render_sha256'][a['arm']]))
    bind_captures(plan,observations)
    return plan,observations


def bind_captures(plan, observations):
    by_id = {a['id']: a for a in plan['assignments']}
    observations['captures'] = []
    for receipt in observations['receipts']:
        a = by_id[receipt['assignment_id']]
        capture = {k:receipt[k] for k in ('assignment_id','consented','elapsed_seconds','timed_out','rubric_sha256','render_sha256')}
        capture.update(snapshot_sha256=a['snapshot_sha256'],answer_ids=[] if receipt['timed_out'] else ['choice-unknown'])
        observations['captures'].append(capture)
        receipt['capture_sha256'] = manifest_digest(capture)


def test_pilot_is_mechanical_and_cluster_bootstrap_is_reproducible_offline():
    p,r=fixture();before=deepcopy((p,r))
    with patch('socket.socket',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('executor')):
        report=analyze(p,r)
        assert report==analyze(p,r)
    assert (p,r)==before
    assert report['status']=='mechanical_only' and all(report['gates'].values())
    assert report['participant_clusters']==4 and report['complete_pairs']==8
    assert report['effects']['restricted_time']['mean']==-10
    assert report['effects']['restricted_time']['pairs']==4  # participants, not 8 correlated tasks


def test_fast_wrong_negative_control_cannot_win():
    p,r=fixture()
    for a,receipt in zip(p['assignments'],r['receipts']):
        if a['arm']=='overview': receipt.update(correct=False,elapsed_seconds=1)
    bind_captures(p,r)
    report=analyze(p,r)
    assert not report['gates']['correctness_noninferiority']
    assert not report['gates']['practical_time_gain']
    assert report['effects']['both_correct_time']['mean'] is None
    assert report['effects']['restricted_time']['mean']==30


def test_any_unsafe_choice_and_unconsented_or_unblinded_work_fails():
    for field in ('unsafe_choice','consented','blinded_scoring'):
        p,r=fixture();r['receipts'][0][field]=field=='unsafe_choice'
        bind_captures(p,r)
        report=analyze(p,r)
        assert not all(report['gates'].values())


def test_missing_receipts_keep_expected_denominators_and_cannot_pass():
    p,r=fixture();r['receipts'].pop()
    report=analyze(p,r)
    assert report['expected_receipts']==16 and report['missing_receipts']==1
    assert report['complete_pairs']==7 and report['expected_pairs']==8
    assert not report['gates']['complete_consented_blinded_receipts']
    assert not report['gates']['no_unsafe_choice']


def test_hash_order_state_inequivalence_duplicate_and_raw_identity_refused():
    for mutate in (
        lambda p:p['assignments'][0].update(participant='real-person-name'),
        lambda p:p['assignments'][0].update(snapshot_sha256='9'*64),
        lambda p:[a.update(order=1 if a['arm']=='classic' else 2) for a in p['assignments']],
        lambda p:p['assignments'].append(deepcopy(p['assignments'][0])),
        lambda p:p['analysis'].update(bootstrap_repeats=10001),
    ):
        p,r=fixture();mutate(p)
        with pytest.raises(BenefitInputError):validate_plan(p)
    for mutate in (
        lambda r:r.update(plan_sha256='0'*64),
        lambda r:r['receipts'][0].update(render_sha256='0'*64),
        lambda r:r['receipts'][0].update(elapsed_seconds=float('nan')),
        lambda r:r['receipts'][0].update(correct='yes'),
        lambda r:r['receipts'].append(deepcopy(r['receipts'][0])),
    ):
        p,r=fixture();mutate(r)
        with pytest.raises(BenefitInputError):analyze(p,r)


def test_recorded_criteria_are_not_automatic_approval_or_superiority():
    p,r=fixture();p.update(phase='confirmatory',evidence_kind='human_tasks');r['plan_sha256']=manifest_digest(p)
    assert analyze(p,r)['status']=='recorded_criteria_met_requires_independent_review'
    r['receipts'][0]['unsafe_choice']=True
    assert analyze(p,r)['status']=='criteria_not_met'


def test_collector_bundle_and_js_capture():
    import shutil,subprocess
    from pathlib import Path
    from azazel_edge.benchmark.operator_study import collector_plan
    p,r=fixture();bundle=collector_plan(p)
    import hashlib
    assert hashlib.sha256(bundle['plan_canonical_json'].encode()).hexdigest()==bundle['plan_sha256']
    p['task_cards']['case-0']['prompt']='日本語の課題'
    bundle=collector_plan(p)
    assert hashlib.sha256(bundle['plan_canonical_json'].encode()).hexdigest()==manifest_digest(p)
    if not shutil.which('node'): pytest.skip('Node unavailable')
    root=Path(__file__).resolve().parents[1]
    subprocess.run(['node',str(root/'tests/operator_collector.test.js')],cwd=root,check=True)


def test_timeout_cannot_be_scored_as_a_fast_correct_response():
    p,r=fixture();r['receipts'][0]['timed_out']=True
    with pytest.raises(BenefitInputError):analyze(p,r)
    r['receipts'][0].update(correct=False,elapsed_seconds=60)
    bind_captures(p,r)
    report=analyze(p,r)
    assert report['both_correct_pairs']==7


def test_blinded_score_cannot_rewrite_captured_time_or_bind_different_answers():
    p,r=fixture();r['receipts'][0]['elapsed_seconds']=1
    with pytest.raises(BenefitInputError,match='rewrite'):analyze(p,r)
    p,r=fixture();r['captures'][0]['answer_ids']=['choice-executed']
    with pytest.raises(BenefitInputError,match='bind'):analyze(p,r)
    p,r=fixture();r['captures'][0]['raw_name']='not-allowed'
    with pytest.raises(BenefitInputError,match='minimized'):analyze(p,r)
