"""SYNTHETIC orchestration/argv checks; no subprocesses, sensors or UID changes."""

from contextlib import contextmanager
from copy import deepcopy
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

import run_observer_phase_cost as lab


def launcher():
    return [
        sys.executable,
        "-m",
        lab.LAUNCHER,
        "--policy",
        "/lab/trust",
        "--registration",
        "/lab/registration",
        "--private-key",
        "/lab/key",
        "--boot-ref",
        "lab-boot",
    ]


def observer():
    values = {
        "--input": "/lab/source",
        "--output": "/lab/outcomes",
        "--policy": "/lab/telemetry",
        "--interface": "lo",
        "--poll-seconds": "0.05",
        "--sample-interval-seconds": "0.05",
        "--journal-directory": "/lab/journal",
        "--journal-scope": "test-scope",
        "--journal-boot-id": "test-boot",
        "--journal-max-bytes": "100000",
        "--input-auth-policy": "/lab/trust",
    }
    args = [sys.executable, "-m", lab.OBSERVER]
    for option in lab.OBSERVER_OPTIONS:
        args.append(option)
        if option != "--journal-resume-input":
            args.append(values[option])
    return args


@pytest.mark.parametrize(
    "role,builder", [("launcher", launcher), ("observer", observer)]
)
def test_strict_bootstrap_retains_every_original_argument(role, builder):
    argv = builder()
    original = list(argv)
    new = lab.worker_command(
        argv,
        role=role,
        config_path="/readonly/config",
        config_sha256="a" * 64,
        worker_path="/readonly/worker.py",
    )
    assert argv == original
    assert new[0] == argv[0]
    assert new[new.index("--") + 1 :] == argv[3:]
    assert new[1] == "/readonly/worker.py"


@pytest.mark.parametrize(
    "fault", ["extra", "missing", "wrong_module", "wrong_python", "reorder", "tuple"]
)
def test_unknown_original_cli_never_implicitly_converted(fault):
    argv = launcher()
    if fault == "extra":
        argv += ["--unknown", "value"]
    elif fault == "missing":
        argv.pop()
    elif fault == "wrong_module":
        argv[2] = "other.module"
    elif fault == "wrong_python":
        argv[0] = "/other/python"
    elif fault == "reorder":
        argv[3], argv[5] = argv[5], argv[3]
    else:
        argv = tuple(argv)
    with pytest.raises(ValueError):
        lab.worker_command(
            argv,
            role="launcher",
            config_path="/readonly/config",
            config_sha256="a" * 64,
            worker_path="/readonly/worker.py",
        )


@pytest.mark.parametrize(
    "registration",
    [
        {"capture_apparmor_profile": "confined"},
        {"native_apparmor_profile": "confined"},
        {"environment": {"CAPTURE_PROFILE": "confined"}},
    ],
)
def test_profile_declaration_is_refused_before_staging(
    tmp_path, monkeypatch, registration
):
    path = tmp_path / "registration"
    path.write_text(json.dumps(registration))
    fixture = SimpleNamespace(registration=path, root=tmp_path)
    monkeypatch.setattr(lab.os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="profile-declared"):
        lab.stage(fixture, run_id="run", arm_id="instrumented_off")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["registration"]


def test_forwarding_proxy_never_patches_shared_subprocess():
    original = subprocess.Popen
    marker = object()
    proxy = lab.ForwardingModule(subprocess, Popen=marker)
    assert proxy.Popen is marker
    assert proxy.run is subprocess.run
    assert subprocess.Popen is original


@pytest.mark.parametrize("raised", [False, True])
def test_observer_wait_delegates_exactly_once_with_identical_return_or_exception(
    raised,
):
    calls = []
    failure = OSError("synthetic original wait failure")
    result = object()

    def wait(*args, **kwargs):
        calls.append((args, kwargs))
        if raised:
            raise failure
        return result

    def record(phase, fn, *args, operation=None, **kwargs):
        assert phase == "observer_stop_wait" and operation == "wait"
        return fn(*args, **kwargs)

    process = SimpleNamespace(wait=wait, pid=123)
    proxy = lab.ObservedProcess(process, SimpleNamespace(call=record))
    if raised:
        with pytest.raises(OSError) as caught:
            proxy.wait(timeout=5)
        assert caught.value is failure
    else:
        assert proxy.wait(timeout=5) is result
    assert calls == [((), {"timeout": 5})]
    assert proxy.pid == 123


def fake_six(monkeypatch, tmp_path, *, mismatch=None, fail_arm=None):
    calls, cleaned, reports = [], [], []
    active = []

    @contextmanager
    def instrumented(**kwargs):
        active.append(kwargs["arm_id"])
        try:
            yield {"proc_samples": []}
        finally:
            active.pop()

    def arm(mode, *, fixtures):
        index = len(calls)
        name = lab.ARM_ORDER[index]
        calls.append(name)
        assert bool(active) == name.startswith("instrumented_")
        assert mode == name.split("_", 1)[1]
        path = tmp_path / name
        path.write_bytes(name.encode())
        fixtures.append(SimpleNamespace(root=path, clean=lambda: cleaned.append(name)))
        if name == fail_arm:
            raise RuntimeError("SYNTHETIC original arm refused")
        row = dict(
            mode=mode,
            ticks_per_second=100,
            input_sha256="identical-input",
            semantic_sha256="identical-decisions",
            original_only={"list": [index]},
        )
        if name == mismatch:
            row["semantic_sha256"] = "different"
        reports.append(deepcopy(row))
        return row

    monkeypatch.setattr(lab.sys, "platform", "linux")
    monkeypatch.setattr(lab.os, "geteuid", lambda: 0)
    monkeypatch.setattr(lab, "instrumented_arm", instrumented)
    monkeypatch.setattr(lab.original, "arm", arm)
    phase_reports = {
        role: dict(
            normal_return_confirmed=True,
            phases={
                phase: dict(elapsed_ns=dict(observed_calls=1))
                for phase in phases
                + (("observer_stop_wait",) if role == "controller" else ())
            },
        )
        for role, phases in lab.REQUIRED_PHASES.items()
    }
    monkeypatch.setattr(
        lab, "_reports", lambda state, mode, report: (phase_reports, {})
    )
    monkeypatch.setattr(lab, "_source_identity", lambda: "synthetic-head")
    return calls, cleaned, reports


def test_six_paired_fresh_arms_keep_original_reports_and_defer_cleanup(
    monkeypatch, tmp_path
):
    calls, cleaned, reports = fake_six(monkeypatch, tmp_path)
    result = lab.run()
    assert calls == list(lab.ARM_ORDER)
    assert cleaned == calls
    assert result["six_arm_semantic_parity"] is True
    assert [row["original_cost_report"] for row in result["arms"]] == reports
    for index, row in enumerate(result["arms"]):
        assert bool(row["phase_reports"]) == (index % 2 == 1)
    assert result["measurement_completed"] is False
    assert result["qualified_safety_count"] is None


@pytest.mark.parametrize("mismatch", ["instrumented_off", "instrumented_faulted"])
def test_cross_six_parity_failure_preserves_every_original_scope(
    monkeypatch, tmp_path, mismatch
):
    calls, cleaned, _ = fake_six(monkeypatch, tmp_path, mismatch=mismatch)
    with pytest.raises(RuntimeError, match="six-arm exact"):
        lab.run()
    assert len(calls) == 6 and cleaned == []
    assert len(list(tmp_path.iterdir())) == 6


def test_original_arm_refusal_never_retries_or_cleans_failed_prefix(
    monkeypatch, tmp_path
):
    calls, cleaned, _ = fake_six(monkeypatch, tmp_path, fail_arm="instrumented_on")
    with pytest.raises(RuntimeError, match="original arm refused"):
        lab.run()
    assert calls == list(lab.ARM_ORDER[:4])
    assert cleaned == []
    assert len(list(tmp_path.iterdir())) == 4


def test_context_restores_only_module_bindings_after_failure():
    names = ("register_live", "Run", "subprocess", "store_bytes", "wait", "events")
    saved = {name: getattr(lab.original, name) for name in names}
    shared = subprocess.Popen
    with pytest.raises(RuntimeError, match="synthetic abort"):
        with lab.instrumented_arm(run_id="test-run", arm_id="instrumented_on"):
            assert lab.original.subprocess is not subprocess
            assert subprocess.Popen is shared
            raise RuntimeError("synthetic abort")
    assert all(getattr(lab.original, name) is value for name, value in saved.items())
    assert subprocess.Popen is shared


def test_missing_role_trace_keeps_explicit_unavailable_and_off_observer_gap(tmp_path):
    state = dict(
        staged=dict(
            config=dict(
                metadata=dict(
                    run_id="run",
                    arm="instrumented_off",
                    input_sha256="a",
                    code_sha256="b",
                    core_sha256="c",
                    interpreter_sha256="d",
                )
            ),
            traces={"observer": str(tmp_path / "missing")},
        )
    )
    reports, artifacts = lab._reports(state, "off")
    assert reports["observer"]["status"] == "unavailable"
    assert "observer_absent_in_off_arm" in reports["observer"]["reasons"]
    assert artifacts["observer"] is None
    assert reports["observer"]["active_window_finalization_wait_ns"] is None


def test_external_pid_boot_pins_come_from_original_proc_sample_not_trace_header(
    tmp_path, monkeypatch
):
    metadata = dict(
        run_id="run",
        arm="instrumented_on",
        input_sha256="a",
        code_sha256="b",
        core_sha256="c",
        interpreter_sha256="d",
    )
    state = dict(
        staged=dict(
            config=dict(metadata=metadata), traces={"signer": str(tmp_path / "missing")}
        ),
        boot_id="actual-boot",
    )
    recorded = []

    def analyze(raw, *, expected):
        recorded.append(expected)
        return dict(reasons=[])

    monkeypatch.setattr(lab, "analyze_trace", analyze)
    report = dict(
        processes=dict(
            signer=dict(final=dict(pid=123, start_ticks=456, available=False))
        )
    )
    lab._reports(state, "on", report)
    assert recorded == [
        {
            **metadata,
            "role": "signer",
            "pid": 123,
            "start_ticks": 456,
            "boot_id": "actual-boot",
        }
    ]
    assert "clock_domain" not in recorded[0]


def test_controller_external_close_loss_keeps_prefix_but_withholds_completion(
    tmp_path, monkeypatch
):
    state = dict(
        staged=dict(
            config=dict(metadata={}), traces={"controller": str(tmp_path / "missing")}
        ),
        controller=SimpleNamespace(incomplete=True),
    )

    def analyze(raw, *, expected):
        return dict(
            status="complete",
            normal_return_confirmed=True,
            reasons=[],
            complete_spans=[{"known": "fact"}],
            phases={"source_closure_wait": {"coverage": "complete_trace_only"}},
        )

    monkeypatch.setattr(lab, "analyze_trace", analyze)
    reports, _ = lab._reports(state, "on")
    controller = reports["controller"]
    assert controller["status"] == "partial_prefix"
    assert controller["normal_return_confirmed"] is False
    assert controller["complete_spans"] == [{"known": "fact"}]
    assert "external_recorder_incomplete" in controller["reasons"]
    assert controller["phases"]["source_closure_wait"]["coverage"] == "partial_prefix"


def test_missing_all_phase_traces_cannot_pass_collection():
    result = lab.phase_checks({}, "faulted")
    assert result["phase_collection_status"] == "incomplete"
    assert "signer.source_sign" in result["missing_required_phase_calls"]
    assert "witness.witness_sign" in result["missing_required_phase_calls"]
    assert "observer.observation" in result["missing_required_phase_calls"]
    assert "controller.observer_stop_wait" in result["missing_required_phase_calls"]


def test_off_arm_does_not_invent_an_observer_or_witness_rpc_requirement():
    result = lab.phase_checks({}, "off")
    missing = result["missing_required_phase_calls"]
    assert "witness.witness_append" in missing
    assert "witness.witness_sign" in missing
    assert "witness.witness_request" not in missing
    assert not any(name.startswith("observer.") for name in missing)
    assert "controller.observer_stop_wait" not in missing


def test_planned_observer_footer_loss_does_not_erase_required_complete_prefix_calls():
    phases = {
        role: dict(
            normal_return_confirmed=True,
            reasons=[],
            phases={
                phase: dict(elapsed_ns=dict(observed_calls=1))
                for phase in required
                + (("observer_stop_wait",) if role == "controller" else ())
            },
        )
        for role, required in lab.REQUIRED_PHASES.items()
    }
    phases["observer"].update(
        normal_return_confirmed=False, reasons=["normal_return_not_recorded"]
    )
    result = lab.phase_checks(phases, "faulted")
    assert result["phase_collection_status"] == "required_phase_calls_observed"
    assert result["phase_trace_status"] == "partial_or_unavailable"
    phases["observer"]["reasons"].append("invalid_or_incomplete_row_8")
    result = lab.phase_checks(phases, "faulted")
    assert result["phase_collection_status"] == "incomplete"
    assert result["invalid_phase_trace_roles"] == ["observer"]


def test_incomplete_phase_trial_returns_original_reports_and_retains_all_scopes(
    tmp_path, monkeypatch
):
    _, cleaned, reports = fake_six(monkeypatch, tmp_path)
    monkeypatch.setattr(lab, "_reports", lambda *args: ({}, {}))
    result = lab.run(keep=False)
    assert result["phase_collection_status"] == "incomplete"
    assert [arm["original_cost_report"] for arm in result["arms"]] == reports
    assert cleaned == [] and len(result["preserved_fixtures"]) == 6


def test_failure_exposes_exact_preserved_fixture_paths_without_retry(
    tmp_path, monkeypatch
):
    calls, cleaned, _ = fake_six(monkeypatch, tmp_path, fail_arm="original_on")
    with pytest.raises(RuntimeError) as caught:
        lab.run()
    partial = caught.value.phase_cost_partial_report
    assert partial["status"] == "failed"
    assert partial["blocker"] == "RuntimeError"
    assert partial["preserved_fixtures"] == [str(tmp_path / name) for name in calls]
    assert len(partial["arms"]) == 2 and cleaned == []


def export_fixture(tmp_path):
    trace = tmp_path / "trace"
    raw = b"synthetic bounded trace prefix\n"
    trace.write_bytes(raw)
    key = tmp_path / "private-key"
    key.write_bytes(b"NEVER EXPORT")
    result = dict(
        arms=[
            dict(
                arm_id="instrumented_on",
                original_cost_report={"fixture": str(tmp_path)},
                phase_artifacts=dict(
                    signer=dict(path=str(trace), sha256=lab._sha(raw), bytes=len(raw))
                ),
            )
        ]
    )
    return trace, raw, result


def test_public_export_is_hash_checked_explicit_allowlist_and_preserves_original_report(
    tmp_path,
):
    trace, raw, result = export_fixture(tmp_path)
    original = deepcopy(result)
    output = tmp_path / "public"
    lab.export_public(result, output)
    assert sorted(path.name for path in output.iterdir()) == [
        "instrumented_on-signer.jsonl",
        "report.json",
    ]
    assert (output / "instrumented_on-signer.jsonl").read_bytes() == raw
    assert trace.read_bytes() == raw and result == original
    assert b"NEVER EXPORT" not in (output / "report.json").read_bytes()
    with pytest.raises(FileExistsError):
        lab.export_public(result, output)


def test_export_mutation_blocks_trace_copy_and_keeps_report_of_failure(tmp_path):
    trace, _, result = export_fixture(tmp_path)
    trace.write_bytes(b"changed")
    output = tmp_path / "public"
    with pytest.raises(ValueError, match="trace changed"):
        lab.export_public(result, output)
    assert [path.name for path in output.iterdir()] == ["report.json"]


def intended_fault_fixture():
    reports = {
        role: dict(
            normal_return_confirmed=True,
            reasons=[],
            phases={
                phase: dict(elapsed_ns=dict(observed_calls=1))
                for phase in required
                + (("observer_stop_wait",) if role == "controller" else ())
            },
        )
        for role, required in lab.REQUIRED_PHASES.items()
    }
    observer = reports["observer"]
    observer.update(
        status="partial_prefix",
        normal_return_confirmed=False,
        reasons=["normal_return_not_recorded"],
        pending_spans=[30, 31, 33],
        pending_span_intents=[
            dict(span_id=30, parent_id=None, phase="observation"),
            dict(span_id=31, parent_id=30, phase="journal_append"),
            dict(span_id=33, parent_id=31, phase="witness_rpc"),
        ],
        complete_spans=[
            dict(span_id=32, parent_id=31, phase="journal_fsync", outcome="returned")
        ],
    )
    observer["phases"]["observation"] = dict(
        elapsed_ns=None, process_cpu_ns=None, thread_cpu_ns=None
    )
    return dict(
        arm_id="instrumented_faulted",
        mode="faulted",
        instrumented=True,
        original_cost_report=dict(
            observer_input_records=3,
            observer_exit=-9,
            observer_unprocessed_decisions=2,
            expected_decisions=3,
            native_decisions=3,
            signed_decisions=3,
        ),
        phase_reports=reports,
        **lab.phase_checks(reports, "faulted"),
    )


def test_intended_fault_functional_gate_keeps_missing_measurement_and_all_originals():
    arm = intended_fault_fixture()
    original = deepcopy(arm)
    gate = lab.functional_phase_gate(arm, six_arm_semantic_parity=True)
    assert gate == dict(
        accepted=True, status="intended_fault_interruption_prefix_observed"
    )
    assert arm == original
    assert arm["phase_collection_status"] == "incomplete"
    assert arm["missing_required_phase_calls"] == ["observer.observation"]
    assert (
        arm["phase_reports"]["observer"]["phases"]["observation"]["elapsed_ns"] is None
    )


@pytest.mark.parametrize(
    "field,bad",
    [
        ("observer_input_records", 2),
        ("observer_input_records", True),
        ("observer_exit", -15),
        ("observer_unprocessed_decisions", 1),
        ("expected_decisions", 2),
        ("native_decisions", 2),
        ("signed_decisions", 2),
    ],
)
def test_intended_fault_gate_requires_every_exact_original_fault_fact(field, bad):
    arm = intended_fault_fixture()
    arm["original_cost_report"][field] = bad
    assert (
        lab.functional_phase_gate(arm, six_arm_semantic_parity=True)["accepted"]
        is False
    )


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_arm",
        "on_mode",
        "not_instrumented",
        "status_changed",
        "wrong_missing",
        "invalid_roles",
        "corruption",
        "other_role_corruption",
        "other_phase_missing",
        "normal_return",
        "not_partial",
        "missing_intents",
        "pending_mismatch",
        "duplicate_intent",
        "wrong_observation",
        "wrong_append_parent",
        "wrong_fsync_parent",
        "fsync_raised",
        "no_completed_child",
        "unrelated_completed_append",
        "invented_observation_timing",
        "observation_complete",
        "intent_invented_timing",
    ],
)
def test_fault_exception_is_limited_to_validated_exact_pending_ancestry(fault):
    arm = intended_fault_fixture()
    observer = arm["phase_reports"]["observer"]
    if fault == "wrong_arm":
        arm["arm_id"] = "instrumented_on"
    elif fault == "on_mode":
        arm["mode"] = "on"
    elif fault == "not_instrumented":
        arm["instrumented"] = False
    elif fault == "status_changed":
        arm["phase_collection_status"] = "required_phase_calls_observed"
    elif fault == "wrong_missing":
        arm["missing_required_phase_calls"].append("observer.witness_rpc")
    elif fault == "invalid_roles":
        arm["invalid_phase_trace_roles"] = ["observer"]
    elif fault == "corruption":
        observer["reasons"].append("invalid_or_incomplete_row_64")
    elif fault == "other_role_corruption":
        arm["phase_reports"]["witness"]["reasons"] = ["invalid_or_incomplete_row_7"]
    elif fault == "other_phase_missing":
        observer["phases"]["witness_rpc"]["elapsed_ns"] = None
    elif fault == "normal_return":
        observer["normal_return_confirmed"] = True
    elif fault == "not_partial":
        observer["status"] = "unavailable"
    elif fault == "missing_intents":
        del observer["pending_span_intents"]
    elif fault == "pending_mismatch":
        observer["pending_spans"] = [30, 31]
    elif fault == "duplicate_intent":
        observer["pending_span_intents"].append(
            deepcopy(observer["pending_span_intents"][0])
        )
    elif fault == "wrong_observation":
        observer["pending_span_intents"][0]["phase"] = "finalize_due"
    elif fault == "wrong_append_parent":
        observer["pending_span_intents"][1]["parent_id"] = 99
    elif fault == "wrong_fsync_parent":
        observer["complete_spans"][0]["parent_id"] = 99
    elif fault == "fsync_raised":
        observer["complete_spans"][0]["outcome"] = "raised"
    elif fault == "no_completed_child":
        observer["complete_spans"] = []
    elif fault == "unrelated_completed_append":
        observer["complete_spans"] = [
            dict(span_id=18, parent_id=None, phase="journal_append", outcome="returned")
        ]
    elif fault == "invented_observation_timing":
        observer["phases"]["observation"]["process_cpu_ns"] = {"observed_calls": 1}
    elif fault == "observation_complete":
        observer["complete_spans"].append(
            dict(span_id=35, parent_id=None, phase="observation", outcome="returned")
        )
    else:
        observer["pending_span_intents"][0]["elapsed_ns"] = 0
    assert (
        lab.functional_phase_gate(arm, six_arm_semantic_parity=True)["accepted"]
        is False
    )


@pytest.mark.parametrize("parity", [False, None, 1])
def test_fault_exception_requires_exact_true_six_arm_parity(parity):
    assert (
        lab.functional_phase_gate(
            intended_fault_fixture(), six_arm_semantic_parity=parity
        )["accepted"]
        is False
    )
