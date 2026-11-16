"""Import-only and synthetic child/control tests; no supplemental workload."""

import json
import os
from copy import deepcopy
from types import SimpleNamespace
import subprocess
import sys

import pytest

import p0_handoff_attribution_lab as lab
import run_notification_timing_supplement as supplement


def test_fresh_import_uses_owned_scratch_and_restores_environment_without_production_mkdir():
    script = r'''
import gc,json,os,pathlib,sys
attempts=[]
def audit(event,args):
 if event in ('os.mkdir','open') and isinstance(args[0],(str,bytes,os.PathLike)):attempts.append((event,os.fsdecode(args[0])))
sys.addaudithook(audit)
prior='/var/lib/notification-import-must-not-be-used'
os.environ['AZAZEL_DECISION_LOG_DIR']=prior
prior_audit='/var/log/notification-import-must-not-be-used/ai-audit.jsonl'
os.environ['AZAZEL_AI_AUDIT_LOG']=prior_audit
import p0_handoff_attribution_lab as lab
scratch=pathlib.Path(lab._FIXTURE_IMPORT_SCRATCH.name)
gc.collect()
assert os.environ['AZAZEL_DECISION_LOG_DIR']==prior
assert os.environ['AZAZEL_AI_AUDIT_LOG']==prior_audit
assert scratch.exists() and scratch.stat().st_uid==os.geteuid()
assert lab.original.agent_mod.DECISION_LOGGER.output_dir==scratch
assert lab.original.agent_mod.AI_AUDIT.path==scratch/'ai-audit.jsonl'
protected=[(event,path) for event,path in attempts if path.startswith(('/var/lib/','/var/log/','/run/azazel','/etc/'))]
assert protected==[],protected
print(json.dumps({'import_only':True,'workloads':0,'protected_mkdir_open_attempts':protected,'private_scratch_retained':True,'environment_restored':True}))
'''
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join([str(lab.ROOT / "py"), str(lab.ROOT / "tests")]),
                       PYTHONDONTWRITEBYTECODE="1")
    process = subprocess.run([sys.executable, "-c", script], env=environment, cwd="/", capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stdout + process.stderr
    assert json.loads(process.stdout.splitlines()[-1])["protected_mkdir_open_attempts"] == []


@pytest.mark.parametrize("raises", [False, True])
def test_global_mock_requests50ms_and_delegates_exact_original_once(monkeypatch, raises):
    calls, waits = [], []
    returned, failure = object(), OSError(5, "SYNTHETIC original fsync error")

    def actual(fd):
        calls.append(fd)
        if raises:
            raise failure
        return returned

    monkeypatch.setattr(lab, "time", SimpleNamespace(sleep=waits.append, monotonic_ns=lambda: 1,
                                                    thread_time_ns=lambda: 2))
    control = lab.Control({"id": lab.SUPPLEMENT_CASES[0], "control": "SYNTHETIC"})
    wrapped = lab.GlobalSlowFsync(actual, control)
    if raises:
        with pytest.raises(OSError) as caught:
            wrapped(123)
        assert caught.value is failure
    else:
        assert wrapped(123) is returned
    assert calls == [123] and waits == [0.050]
    assert control.data["global_fsync_calls"][0]["outcome"] == ("raised" if raises else "returned")


def test_global_mock_probe_failure_cannot_skip_original_fsync(monkeypatch):
    calls = []

    def denied():
        raise OSError("SYNTHETIC probe failure")

    monkeypatch.setattr(lab, "time", SimpleNamespace(sleep=lambda seconds: None, monotonic_ns=denied, thread_time_ns=denied))
    control = lab.Control({"id": lab.SUPPLEMENT_CASES[0], "control": "SYNTHETIC"})
    assert lab.GlobalSlowFsync(lambda fd: calls.append(fd), control)(99) is None
    assert calls == [99]
    assert control.data["global_fsync_calls"][0]["start_ns"] is None
    assert control.data["global_fsync_calls"][0]["probe_errors"]


@pytest.mark.parametrize("timeout", [False, True])
def test_child_pipes_are_drained_and_failure_outputs_retained(tmp_path, monkeypatch, timeout):
    calls = []
    parent_marker = os.environ.get("EDGE_NOTIFICATION_SUPPLEMENT_CHILD")

    class Child:
        pid = 77
        returncode = -9 if timeout else 0

    def launch(command, **kwargs):
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.PIPE
        assert kwargs["env"]["EDGE_NOTIFICATION_SUPPLEMENT_CHILD"] == lab.SUPPLEMENT_CASES[0]
        return Child()

    monkeypatch.setattr(supplement, "subprocess", SimpleNamespace(Popen=launch, PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired))
    def drain(process):
        calls.append("bounded_drain")
        retained = dict(stdout=b'{"kind":"bootstrap","boundary":{"SYNTHETIC":true}}\n', stderr=b"SYNTHETIC overflow logs\n")
        streams = {name: dict(bytes_observed=len(raw), bytes_retained=len(raw), truncated=False,
                              capture_error=None, retained_sha256=lab.sha(raw)) for name, raw in retained.items()}
        return retained, streams, timeout, None
    monkeypatch.setattr(supplement, "drain_child", drain)
    result = supplement.launch_child(tmp_path, {"id": lab.SUPPLEMENT_CASES[0]}, {})
    assert calls == ["bounded_drain"]
    assert result["timed_out"] is timeout
    assert result["completion"] is None
    assert (tmp_path / (lab.SUPPLEMENT_CASES[0] + ".child-stderr.raw")).read_bytes() == b"SYNTHETIC overflow logs\n"
    assert os.environ.get("EDGE_NOTIFICATION_SUPPLEMENT_CHILD") == parent_marker


def test_bounded_drain_handles_both_real_flooding_pipes_without_accumulating_outputs():
    code = "import os;[(os.write(1,b'a'*4096),os.write(2,b'b'*4096)) for _ in range(256)]"
    process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    retained, streams, timed_out, error = supplement.drain_child(process, maximum=257, timeout=5)
    assert process.returncode == 0 and timed_out is False and error is None
    assert retained == {"stdout": b"a" * 257, "stderr": b"b" * 257}
    assert all(row["bytes_observed"] == 1_048_576 and row["bytes_retained"] == 257 and row["truncated"] is True for row in streams.values())


def test_bounded_drain_times_out_and_preserves_available_prefix():
    process = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    retained, streams, timed_out, error = supplement.drain_child(process, maximum=99, timeout=0.1)
    assert timed_out is True and process.returncode != 0
    assert all(len(raw) <= 99 for raw in retained.values())
    assert set(streams) == {"stdout", "stderr"}


def reply_fixture():
    metadata = dict(run_id="SYNTHETIC-run", case_id=lab.SUPPLEMENT_CASES[0], protocol_sha256=lab.SUPPLEMENT_SHA256,
                    source_inventory_sha256="a" * 64, fixture_sha256="b" * 64, interpreter_sha256="c" * 64)
    identity = dict(pid=77, process_start_ticks=123, boot_id="00000000-0000-4000-8000-000000000001",
                    clock_domain=dict(time_namespace_device=1, time_namespace_inode=2, timens_offsets=None, established=False))
    bootstrap = dict(kind="bootstrap", boundary=dict(identity=identity))
    completion = dict(kind="completion", expected=dict(header=dict(metadata, **identity)))
    return metadata, bootstrap, completion


@pytest.mark.parametrize("field", sorted(supplement.PARENT_PINS))
def test_completion_must_match_every_parent_pin(field):
    metadata, bootstrap, completion = reply_fixture()
    completion["expected"]["header"][field] = "SWAPPED"
    header, errors = supplement.bind_child_header(77, metadata["case_id"], metadata, bootstrap, completion)
    assert header[field] == metadata[field]
    assert "completion_header_differs_from_parent_pins_and_bootstrap" in errors


@pytest.mark.parametrize("swap", ["bootstrap_pid", "completion_pid", "bootstrap_start", "completion_boot"])
def test_pid_and_bootstrap_identity_swaps_are_not_accepted(swap):
    metadata, bootstrap, completion = reply_fixture()
    if swap == "bootstrap_pid":
        bootstrap["boundary"]["identity"]["pid"] = 88
    elif swap == "completion_pid":
        completion["expected"]["header"]["pid"] = 88
    elif swap == "bootstrap_start":
        bootstrap["boundary"]["identity"]["process_start_ticks"] = 456
    else:
        completion["expected"]["header"]["boot_id"] = "SWAPPED"
    _, errors = supplement.bind_child_header(77, metadata["case_id"], metadata, bootstrap, completion)
    assert errors


def test_valid_bootstrap_keeps_external_header_when_completion_missing():
    metadata, bootstrap, completion = reply_fixture()
    before = deepcopy(bootstrap)
    header, errors = supplement.bind_child_header(77, metadata["case_id"], metadata, bootstrap, None)
    assert header == completion["expected"]["header"] and errors == ["completion_unavailable"]
    assert bootstrap == before


def test_valid_bootstrap_prefix_survives_incomplete_completion():
    metadata, bootstrap, _ = reply_fixture()
    with pytest.raises(ValueError) as caught:
        supplement.parse_child_rows(lab.canonical(bootstrap) + b'{"kind":"completion"')
    assert caught.value.valid_prefix_rows == [bootstrap]
    header, errors = supplement.bind_child_header(77, metadata["case_id"], metadata, caught.value.valid_prefix_rows[0], None)
    assert header is not None and errors == ["completion_unavailable"]


@pytest.mark.parametrize("raw", [b'{"kind":"bootstrap"}\n'*5, b'{"kind":"bootstrap","kind":"completion"}\n',
    b'{"kind":"bootstrap","extra":"'+b'x'*65536+b'"}\n', b'{"kind":"bootstrap"}'])
def test_child_reply_parser_has_row_and_line_bounds(raw):
    with pytest.raises(ValueError):
        supplement.parse_child_rows(raw)


def test_parent_assigns_only_two_supplement_children_and_keeps_original_first(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(supplement, "require_authority", lambda: {"uid": 1000, "SYNTHETIC": True})
    monkeypatch.setenv("EDGE_NOTIFICATION_SOURCE_HEAD", "a" * 40)
    monkeypatch.setenv("EDGE_NOTIFICATION_SOURCE_TREE", "b" * 40)

    def launch(output, recipe, metadata):
        called.append(recipe["id"])
        assert metadata["protocol_sha256"] == lab.SUPPLEMENT_SHA256
        value = {"assigned_events": 120, "completed_submissions": 1,
            "control": {"legacy_intervals": [{"index": 0, "start_monotonic_seconds": 0.0,
                "end_monotonic_seconds": 0.123, "elapsed_seconds": 0.123}]}, "SYNTHETIC": True}
        lab.save(output / (recipe["id"] + ".original-result.json"), lab.canonical(value))
        lab.save(output / (recipe["id"] + ".event-index.json"), lab.canonical({"events": []}))
        identity = reply_fixture()[1]["boundary"]["identity"]
        header = dict(metadata, **identity)
        return {"expected_header": header, "completion": {"expected": dict(header=header,
            event_index_sha256="e" * 64, original_result_sha256="f" * 64)}, "returncode": 0, "timed_out": False, "streams": {}}

    def analyze(trace, *, original_result_raw, event_index_raw, expected):
        original = json.loads(original_result_raw)
        assert original["SYNTHETIC"] is True
        assert expected["event_index_sha256"] == lab.sha(event_index_raw)
        assert expected["original_result_sha256"] == lab.sha(original_result_raw)
        return dict(original_result=original, historical_cause="UNKNOWN", **supplement.FLAGS)

    monkeypatch.setattr(supplement, "launch_child", launch)
    monkeypatch.setattr(supplement, "analyze_notification_timing", analyze)
    result = supplement.run(tmp_path / "public")
    assert tuple(called) == lab.SUPPLEMENT_CASES
    assert result["base_pilot_reruns"] == 0 and result["performance_acceptance"] is False
    assert all(case["summary"]["original_intervals_over_50ms"] is None for case in result["cases"])
    assert all(case["summary"]["original_intervals_positive_observed_lower_bound"] == 1 for case in result["cases"])
    assert all(case["summary"]["max_original_elapsed_seconds"] == 0.123 for case in result["cases"])
    assert result["historical_cause"] == "UNKNOWN"
    assert all(case["case_id"] + ":completion_pins_differ_from_closed_originals" in result["blockers"] for case in result["cases"])
    manifest = json.loads((tmp_path / "public/manifest.json").read_bytes())
    assert "tests/run_notification_timing_supplement.py" in json.loads((tmp_path / "public/source-inventory.json").read_bytes())["files"]
    assert all("/" not in name for name in manifest["files"])
    with pytest.raises(FileExistsError):
        supplement.run(tmp_path / "public")


@pytest.mark.parametrize("original", [None, {}, {"control": {}}, {"control": {"legacy_intervals": []}}])
def test_missing_original_or_timers_never_become_zero_adverse_intervals(original):
    result = supplement.legacy_timer_summary(original)
    assert result["original_intervals_over_50ms"] is None
    assert result["max_original_elapsed_seconds"] is None
    assert result["original_intervals_positive_observed_lower_bound"] is None
    assert result["original_timer_observations_complete"] is False


def test_full_adverse_total_requires_all120_indexed_valid_timers():
    original = {"assigned_events": 120, "completed_submissions": 120, "control": {"legacy_intervals": [
        dict(index=index, start_monotonic_seconds=0.0, end_monotonic_seconds=0.123 if index == 0 else 0.001,
             elapsed_seconds=0.123 if index == 0 else 0.001) for index in range(120)]}}
    assert supplement.legacy_timer_summary(original)["original_intervals_over_50ms"] == 1
    original["control"]["legacy_intervals"].pop()
    partial = supplement.legacy_timer_summary(original)
    assert partial["original_intervals_over_50ms"] is None
    assert partial["original_intervals_observed_count"] == 119
    assert partial["original_intervals_positive_observed_lower_bound"] == 1


def test_valid_reply_prefix_with_invalid_tail_retains_facts_but_blocks_gate(tmp_path, monkeypatch):
    metadata, bootstrap, completion = reply_fixture()
    raw = lab.canonical(bootstrap) + lab.canonical(completion) + b"invalid-third-tail"
    with pytest.raises(ValueError) as caught:
        supplement.parse_child_rows(raw)
    assert caught.value.valid_prefix_rows == [bootstrap, completion]
    header, errors = supplement.bind_child_header(77, metadata["case_id"], metadata, bootstrap, completion)
    assert not errors and header == completion["expected"]["header"]
    monkeypatch.setattr(supplement, "require_authority", lambda: {"uid": 1000, "SYNTHETIC": True})
    monkeypatch.setenv("EDGE_NOTIFICATION_SOURCE_HEAD", "a" * 40)
    monkeypatch.setenv("EDGE_NOTIFICATION_SOURCE_TREE", "b" * 40)

    def launch(output, recipe, parent_metadata):
        original = lab.canonical({"SYNTHETIC": "retained original"})
        index = lab.canonical({"events": []})
        lab.save(output / (recipe["id"] + ".original-result.json"), original)
        lab.save(output / (recipe["id"] + ".event-index.json"), index)
        actual_header = dict(parent_metadata, **bootstrap["boundary"]["identity"])
        expected = dict(header=actual_header, original_result_sha256=lab.sha(original), event_index_sha256=lab.sha(index))
        return dict(expected_header=actual_header, completion=dict(expected=expected), returncode=0, timed_out=False,
                    streams={}, binding_errors=[], stdout_decode_error="ValueError")

    def analyze(trace, *, original_result_raw, **kwargs):
        assert json.loads(original_result_raw)["SYNTHETIC"] == "retained original"
        return dict(original_result=None, historical_cause="UNKNOWN", **supplement.FLAGS)

    monkeypatch.setattr(supplement, "launch_child", launch)
    monkeypatch.setattr(supplement, "analyze_notification_timing", analyze)
    result = supplement.run(tmp_path / "public")
    assert all(case["case_id"] + ":child_stdout_decode_failed" in result["blockers"] for case in result["cases"])
    assert all(case["expected"] is not None for case in result["cases"])
    assert (tmp_path / "public" / (lab.SUPPLEMENT_CASES[0] + ".original-result.json")).read_bytes() == lab.canonical({"SYNTHETIC": "retained original"})
