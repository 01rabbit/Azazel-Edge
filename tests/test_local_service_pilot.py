"""Bounded actual local pilots; no fixture replaces successful service traffic."""
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from test_benefit_comparison import manifest
from azazel_edge.benchmark.benefit import BenefitInputError, SAFETY_FIELDS, manifest_digest
from azazel_edge.benchmark.local_service_capture import LocalCaptureError, local_service_plan
from azazel_edge.benchmark.local_service_pilot import (
    CONTROLS, SCOPE, PilotRunError, run_local_pilot,
)
from azazel_edge.benchmark.run_ledger import RunLedger


def registration():
    value = manifest()
    value.update(evidence_kind='recorded_lab', horizon_seconds=.06,
                 baseline='goal_allowed', candidate='goal_denied')
    value['arms'] = [dict(id=control, role='local_synthetic_control', source_commit='a'*40,
        config_sha256=manifest_digest(local_service_plan(profile=control)), environment_id='isolated-local-test')
        for control in CONTROLS]
    value['assignments'] = [dict(id=f'p{pair}-{control}', pair_id=f'pair-{pair}', arm=control,
        scenario='fixed-local-synthetic-service', seed=pair, order=(index+pair) % 4)
        for pair in range(2) for index, control in enumerate(CONTROLS)]
    safety = {a['id']: dict.fromkeys(SAFETY_FIELDS, 0) for a in value['assignments']}
    return value, safety


def execute(value, safety, output):
    return run_local_pilot(value, output, safety_by_assignment=safety, scope_acknowledgment=SCOPE)


def test_actual_pilot_starts_before_child_and_persists_full_result_before_finish(tmp_path):
    from azazel_edge.benchmark import local_service_pilot as pilot
    value, safety = registration()
    output = tmp_path / 'new-pilot'
    real_capture, real_finish = pilot.capture_local_service, RunLedger.finish
    executed = []
    synced = []
    real_fsync = os.fsync

    def fsync(fd):
        real_fsync(fd)
        synced.append(os.fstat(fd).st_ino)

    def capture(m, assignment_id, **kwargs):
        rows = [json.loads(row) for row in (output/'runs.jsonl').read_text().splitlines()]
        assert rows[-1]['event'] == dict(op='start', assignment_id=assignment_id, run_id=kwargs['run_id'])
        executed.append(assignment_id)
        return real_capture(m, assignment_id, **kwargs)

    def finish(ledger, receipt):
        filename = 'capture-' + hashlib.sha256(receipt['assignment_id'].encode()).hexdigest() + '.json'
        artifact = json.loads((output/filename).read_text())
        assert artifact['receipt'] == receipt
        assert artifact['capture'] and artifact['service_audit']
        assert artifact['service_pid'] != artifact['controller_pid']
        file_sync = synced.index((output/filename).stat().st_ino)
        assert output.stat().st_ino in synced[file_sync+1:]
        return real_finish(ledger, receipt)

    with patch.object(pilot, 'capture_local_service', side_effect=capture), patch.object(
            RunLedger, 'finish', new=finish), patch.object(os, 'fsync', side_effect=fsync):
        report = execute(value, safety, output)
    assert executed == [a['id'] for a in sorted(value['assignments'], key=lambda a: (a['pair_id'], a['order']))]
    assert report['status'] == 'complete' and report['comparison']['claim_status'] == 'mechanical_only'
    assert report['comparison']['assigned_runs'] == 8
    assert report['comparison']['complete_pairs'] == 2
    assert len(report['snapshot']['observations']['runs']) == 8
    assert len(list(output.glob('capture-*.json'))) == 8
    assert len(list(output.glob('checkpoint-*.json'))) == 17
    assert report['authorized_actions'] == []
    assert (output.stat().st_mode & 0o777) == 0o700
    assert all((path.stat().st_mode & 0o777) == 0o600 for path in output.iterdir())
    checkpoint = json.loads((output/'checkpoint-016.json').read_text())
    assert checkpoint['head_sha256'] == report['snapshot']['head_sha256']
    assert 'not_independent' in checkpoint['checkpoint_scope']
    with RunLedger(output/'runs.jsonl', expected_head=checkpoint['head_sha256']) as ledger:
        assert ledger.snapshot() == report['snapshot']
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    with pytest.raises(FileExistsError):
        execute(value, safety, output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before


def test_unknown_safety_or_changed_controls_refused_before_directory_or_work(tmp_path):
    from azazel_edge.benchmark import local_service_pilot as pilot
    with patch.object(pilot, 'capture_local_service', side_effect=AssertionError('no workload')):
        for fault in ('unknown', 'missing', 'role', 'plan', 'hardware', 'budget'):
            value, safety = registration()
            if fault == 'unknown': safety[next(iter(safety))] = None
            elif fault == 'missing': safety.pop(next(iter(safety)))
            elif fault == 'role': value['arms'][0]['role'] = 'bounded_block'
            elif fault == 'plan': value['arms'][0]['config_sha256'] = 'f'*64
            elif fault == 'hardware': value['evidence_kind'] = 'hardware'
            elif fault == 'budget': value['horizon_seconds'] = 60
            output = tmp_path/fault
            with pytest.raises(BenefitInputError): execute(value, safety, output)
            assert not output.exists()
        value, safety = registration()
        with pytest.raises(BenefitInputError):
            run_local_pilot(value, tmp_path/'scope', safety_by_assignment=safety, scope_acknowledgment='')
        assert not (tmp_path/'scope').exists()


def test_capture_failure_retains_running_pending_and_no_safety_receipt(tmp_path):
    from azazel_edge.benchmark import local_service_pilot as pilot
    value, safety = registration()
    output = tmp_path/'failed'
    with patch.object(pilot, 'capture_local_service', side_effect=LocalCaptureError('lost monitor')) as capture:
        with pytest.raises(PilotRunError): execute(value, safety, output)
    assert capture.call_count == 1
    failure = json.loads((output/'failure.json').read_text())
    assert failure['comparison']['assigned_runs'] == 8
    assert failure['snapshot']['observations']['runs'] == []
    states = [row['status'] for row in failure['snapshot']['assignments']]
    assert states.count('running') == 1 and states.count('pending') == 7
    assert not list(output.glob('capture-*.json')) and not (output/'report.json').exists()
    with pytest.raises(FileExistsError): execute(value, safety, output)


def test_artifact_export_failure_cannot_admit_receipt_or_start_next_child(tmp_path):
    from azazel_edge.benchmark import local_service_pilot as pilot
    value, safety = registration()
    output = tmp_path/'export-failure'
    real_write = pilot._write_new

    def write(directory_fd, name, artifact):
        if name.startswith('capture-'):
            raise OSError('test full storage')
        return real_write(directory_fd, name, artifact)

    with patch.object(pilot, '_write_new', side_effect=write), patch.object(
            RunLedger, 'finish', side_effect=AssertionError('must not admit unexported receipt')):
        with pytest.raises(PilotRunError): execute(value, safety, output)
    failure = json.loads((output/'failure.json').read_text())
    assert failure['snapshot']['observations']['runs'] == []
    assert sum(row['status'] == 'running' for row in failure['snapshot']['assignments']) == 1


def test_hostile_assignment_filename_is_hashed_without_path_interpretation(tmp_path):
    value, safety = registration()
    original = value['assignments'][0]['id']
    hostile = '../../arbitrary-name'
    value['assignments'][0]['id'] = hostile
    safety[hostile] = safety.pop(original)
    output = tmp_path/'hashed'
    report = execute(value, safety, output)
    assert report['status'] == 'complete'
    assert (output/('capture-'+hashlib.sha256(hostile.encode()).hexdigest()+'.json')).is_file()
    assert not (tmp_path.parent/'arbitrary-name').exists()


def test_report_analysis_does_not_launch_any_additional_service(tmp_path):
    from azazel_edge.benchmark import local_service_pilot as pilot
    real_analyze = pilot.analyze
    analyzed = []

    def offline(*args):
        with patch('subprocess.Popen', side_effect=AssertionError('analysis is offline')):
            analyzed.append(True)
            return real_analyze(*args)

    value, safety = registration()
    with patch.object(pilot, 'analyze', side_effect=offline):
        report = execute(value, safety, tmp_path/'offline-analysis')
    assert report['status'] == 'complete' and analyzed == [True]
