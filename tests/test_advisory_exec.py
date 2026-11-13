"""SYNTHETIC kernel metadata/entries, real unchanged Governance and P0 logger.

No kernel capture, command execution or general safety absence is simulated.
"""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_edge.benchmark import advisory_exec as a
from azazel_edge.benchmark import advisory_exec_collection as intake
from azazel_edge.benchmark import safety_collection
from azazel_edge.ai_governance import AIGovernance
from azazel_edge.audit import P0AuditLogger
from azazel_edge.outcome.journal import _json

BOOT = "00000000-0000-4000-8000-000000000001"
CORPUS = Path(__file__).parent / "fixtures/advisory-exec/v1/governance.json"


def wire(value):
    return _json(value) + b"\n"


def build(directory, case_id="execve_failed"):
    config = dict(
        pidns_device=4,
        pidns_inode=42,
        actor_start_ticks=5,
        started_ns=100,
        deadline_ns=1000,
        actor_tgid=12,
        actor_uid=1000,
        user_hz=100,
        max_events=64,
    )
    calibration = dict(
        calibrated_at_ns=120,
        start_boottime_ns=50_000_001,
        tgid=12,
        tid=12,
        uid=1000,
        native_abi=1,
    )
    event = dict(
        monotonic_ns=120,
        start_boottime_ns=50_000_001,
        syscall_id=172,
        tgid=12,
        tid=12,
        uid=1000,
        event_kind=0,
        native_abi=1,
        reserved=0,
    )
    events = [event]
    if case_id in ("execve_success", "execve_failed", "execveat_failed", "link_loss"):
        events.append(
            dict(
                event,
                monotonic_ns=300,
                syscall_id=281 if case_id == "execveat_failed" else 221,
                event_kind=1,
            )
        )
    elif case_id == "creation_attempt":
        events.append(dict(event, monotonic_ns=300, syscall_id=220, event_kind=2))
    counters = {key: 0 for key in a.COUNTERS.split()}
    counters.update(
        observed=len(events),
        emitted=len(events),
        creation_attempts=1 if case_id == "creation_attempt" else 0,
    )
    probe = dict(
        schema_version="edge-advisory-exec-probe/v1",
        architecture="aarch64",
        started_ns=100,
        finished_ns=1100,
        configuration=config,
        calibration=calibration,
        events=events,
        counters=counters,
        partial_reasons=[],
        link_identity=dict(
            fd=7,
            link_id=8,
            prog_id=9,
            link_type=1,
            tp_name="sys_enter",
            prog_tag="a" * 16,
        ),
    )
    if case_id == "link_loss":
        probe["partial_reasons"] = ["observer_link_lost"]
        probe["link_identity"] = None
    governance = audit = None
    if case_id in a.GOVERNANCE_CASES:
        input_value = json.loads(CORPUS.read_bytes())[case_id]
        calls = []

        def invoker(sanitized):
            calls.append(sanitized)
            return deepcopy(input_value["invoker_output"])

        logger = P0AuditLogger(directory / "audit.jsonl")
        output = AIGovernance(logger).invoke(
            input_value["context"], input_value["raw_payload"], invoker
        )
        governance = dict(
            input_value,
            result=output,
            invoker_calls=len(calls),
            call_started_ns=200,
            call_finished_ns=250,
        )
        audit = (directory / "audit.jsonl").read_bytes()
    else:
        input_value = {"case_id": case_id}
    plan = dict(
        schema_version="edge-advisory-exec-plan/v1",
        capture_id="SYNTHETIC-capture",
        case_id=case_id,
        kernel_boot_id=BOOT,
        architecture="aarch64",
        actor=dict(
            tgid=12,
            uid=1000,
            start_ticks=5,
            pidns_device=4,
            pidns_inode=42,
            user_hz=100,
            code_sha256="c" * 64,
            input_sha256=a._sha(wire(input_value)),
        ),
        configuration=config,
        go=dict(release_before_ns=150, release_after_ns=160),
        worker=dict(
            started_ns=50, exited_ns=800, returncode=0, forced=False, error=None
        ),
        observer_source_sha256="a" * 64,
        observer_object_sha256="b" * 64,
        probe_sha256=a._sha(wire(probe)),
        governance_sha256=a._sha(wire(governance)) if governance else None,
        audit_sha256=a._sha(audit) if audit else None,
    )
    return dict(plan=plan, probe=probe, governance=governance, audit=audit)


def evaluate(case):
    plan = wire(case["plan"])
    return a.verify_advisory_exec_observation(
        plan,
        expected_plan_sha256=a._sha(plan),
        probe_raw=wire(case["probe"]) if case["probe"] is not None else None,
        governance_raw=wire(case["governance"])
        if case["governance"] is not None
        else None,
        audit_raw=case["audit"],
    )


def refresh(case):
    for name in ("probe", "governance"):
        case["plan"][name + "_sha256"] = (
            a._sha(wire(case[name])) if case[name] is not None else None
        )
    case["plan"]["audit_sha256"] = (
        a._sha(case["audit"]) if case["audit"] is not None else None
    )


@pytest.mark.parametrize("case_id", sorted(a.CASES))
def test_nine_closed_synthetic_probe_cases_real_governance(tmp_path, case_id):
    case = build(tmp_path, case_id)
    original = deepcopy(case)
    result = evaluate(case)
    assert case == original
    assert result["governance_boundary_consistent"] is (
        True if case_id in a.GOVERNANCE_CASES else None
    )
    positive = case_id in (
        "execve_success",
        "execve_failed",
        "execveat_failed",
        "link_loss",
    )
    assert result["kernel_exec_attempt_count"] == (1 if positive else None)
    assert result["coverage_disposition"] == (
        "unknown"
        if case_id in ("creation_attempt", "link_loss")
        else "single_task_window_consistent"
    )
    assert result["qualified_safety_count"] is None
    assert all(result[k] is False for k in a.safety.FLAGS)


@pytest.mark.parametrize(
    "fault",
    [
        "loss",
        "cleanup",
        "overflow",
        "missing_stats",
        "bad_stats",
        "missing_link",
        "unknown_link",
        "bad_audit",
        "bad_governance",
        "malformed_sibling",
        "duplicate",
    ],
)
def test_known_attempt_survives_later_uncertainty(tmp_path, fault):
    case = build(tmp_path)
    probe = case["probe"]
    if fault == "loss":
        probe["partial_reasons"] = ["observer_link_lost"]
    elif fault == "cleanup":
        probe["partial_reasons"] = ["observer_cleanup_unverified"]
    elif fault == "overflow":
        probe["counters"]["overflow"] = 1
    elif fault == "missing_stats":
        probe["counters"] = None
    elif fault == "bad_stats":
        probe["counters"]["emitted"] = False
    elif fault == "missing_link":
        probe["link_identity"] = None
    elif fault == "unknown_link":
        probe["link_identity"]["link_type"] = 2
    elif fault == "bad_audit":
        case["audit"] = b"malformed\n"
    elif fault == "bad_governance":
        case["governance"] = {"wrong": True}
    elif fault == "malformed_sibling":
        probe["events"].append({"wrong": True})
    elif fault == "duplicate":
        probe["events"].append(deepcopy(probe["events"][-1]))
    refresh(case)
    result = evaluate(case)
    assert result["kernel_exec_attempt_count"] == 1
    if fault not in ("bad_audit", "bad_governance"):
        assert result["coverage_disposition"] == "unknown"


@pytest.mark.parametrize(
    "fault",
    [
        "calibration_none",
        "exact_start",
        "uid",
        "tgid",
        "namespace",
        "native_abi",
        "reserved",
        "before_go",
        "after_deadline",
        "after_worker_exit",
        "syscall_kind",
        "probe_start",
        "no_calibration_event",
    ],
)
def test_identity_or_clock_never_becomes_zero(tmp_path, fault):
    case = build(tmp_path)
    p = case["probe"]
    e = p["events"][-1]
    if fault == "calibration_none":
        p["calibration"] = None
    elif fault == "exact_start":
        e["start_boottime_ns"] += 1
    elif fault == "uid":
        e["uid"] = 1001
    elif fault == "tgid":
        e["tgid"] = 13
    elif fault == "namespace":
        p["configuration"] = dict(p["configuration"], pidns_inode=43)
    elif fault == "native_abi":
        e["native_abi"] = 2
    elif fault == "reserved":
        e["reserved"] = 1
    elif fault == "before_go":
        e["monotonic_ns"] = 149
    elif fault == "after_deadline":
        e["monotonic_ns"] = 1001
    elif fault == "after_worker_exit":
        e["monotonic_ns"] = 801
    elif fault == "syscall_kind":
        e["syscall_id"] = 172
    elif fault == "probe_start":
        p["started_ns"] = 101
    elif fault == "no_calibration_event":
        p["events"] = p["events"][1:]
    refresh(case)
    result = evaluate(case)
    assert result["kernel_exec_attempt_count"] is (
        1 if fault == "no_calibration_event" else None
    )
    assert result["coverage_disposition"] == "unknown"


@pytest.mark.parametrize("syscall", [220, 435])
def test_any_creation_withholds_consistency_but_keeps_exec(tmp_path, syscall):
    case = build(tmp_path)
    p = case["probe"]
    p["events"].append(
        dict(p["events"][-1], monotonic_ns=350, syscall_id=syscall, event_kind=2)
    )
    p["counters"].update(observed=3, emitted=3)
    refresh(case)
    result = evaluate(case)
    assert result["kernel_exec_attempt_count"] == 1
    assert result["coverage_disposition"] == "unknown"
    assert "task_creation_observed" in result["reasons"]


@pytest.mark.parametrize(
    "fault",
    [
        "result",
        "calls",
        "inputhash",
        "stage",
        "hash",
        "extra_row",
        "missing",
        "callclock",
    ],
)
def test_governance_artifact_not_self_approval(tmp_path, fault):
    case = build(tmp_path, "extra_keys")
    if fault == "result":
        case["governance"]["result"]["advice"] = "execute"
    elif fault == "calls":
        case["governance"]["invoker_calls"] = False
    elif fault == "inputhash":
        case["plan"]["actor"]["input_sha256"] = "a" * 64
    elif fault == "missing":
        case["audit"] = None
    elif fault == "callclock":
        case["governance"]["call_started_ns"] = 149
    else:
        rows = case["audit"].splitlines(keepends=True)
        if fault == "extra_row":
            rows.append(rows[-1])
        elif fault == "stage":
            rows[1] = rows[1].replace(b'"review"', b'"output"')
        else:
            rows[0] = rows[0].replace(b'"ai_assist"', b'"not_valid"')
        case["audit"] = b"".join(rows)
    # A bad governance sibling cannot erase this separately bound kernel fact.
    case["probe"]["events"].append(
        dict(case["probe"]["events"][0], monotonic_ns=300, syscall_id=221, event_kind=1)
    )
    case["probe"]["counters"].update(observed=2, emitted=2)
    refresh(case)
    result = evaluate(case)
    assert result["governance_boundary_consistent"] is None
    assert result["kernel_exec_attempt_count"] == 1


@pytest.mark.parametrize(
    "fault",
    ["x86", "abi", "bool", "duplicate", "depth", "oversize", "nonfinite", "pin"],
)
def test_strict_global_plan(tmp_path, fault):
    case = build(tmp_path)
    if fault == "x86":
        case["plan"]["architecture"] = "x86_64"
    elif fault == "abi":
        case["plan"]["actor"]["user_hz"] = 1000
    elif fault == "bool":
        case["plan"]["worker"]["started_ns"] = False
    plan = wire(case["plan"])
    if fault == "duplicate":
        plan = b'{"case_id":"duplicate",' + plan[1:]
    elif fault == "depth":
        plan = b'{"x":' + b"[" * 34 + b"0" + b"]" * 34 + b"}\n"
    elif fault == "oversize":
        plan = b" " * 32769
    elif fault == "nonfinite":
        plan = plan.replace(b'"started_ns":100', b'"started_ns":1e400', 1)
    pin = "a" * 64 if fault == "pin" else a._sha(plan)
    with pytest.raises(a.AdvisoryExecInputError):
        a.verify_advisory_exec_observation(
            plan,
            expected_plan_sha256=pin,
            probe_raw=None,
            governance_raw=None,
            audit_raw=None,
        )


def test_missing_probe_and_healthy_absence_both_null(tmp_path):
    case = build(tmp_path, "ordinary_advice")
    assert evaluate(case)["kernel_exec_attempt_count"] is None
    case["probe"] = None
    refresh(case)
    result = evaluate(case)
    assert result["kernel_exec_attempt_count"] is None
    assert result["governance_boundary_consistent"] is True


def test_pure_path_no_file_process_or_audit_writes(tmp_path, monkeypatch):
    import builtins
    import subprocess

    case = build(tmp_path, "ordinary_advice")

    def forbidden(*args, **kwargs):
        raise AssertionError("pure verifier attempted I/O")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(P0AuditLogger, "log", forbidden)
    assert evaluate(case)["governance_boundary_consistent"] is True


@pytest.mark.parametrize(
    "fault", [None, "root", "actor", "boot", "unsafe", "alias", "close", "race"]
)
def test_synthetic_held_intake(tmp_path, monkeypatch, fault):
    case = build(tmp_path, "ordinary_advice")
    files = {
        "/sealed/plan": wire(case["plan"]),
        "/sealed/probe": wire(case["probe"]),
        "/sealed/governance": wire(case["governance"]),
        "/sealed/audit": case["audit"],
    }
    enrollment = dict(
        schema_version="edge-advisory-exec-enrollment/v1",
        plan_sha256=a._sha(files["/sealed/plan"]),
        reader_uid=65533,
        kernel_boot_id=BOOT,
        paths={k: "/sealed/" + k for k in ("plan", "probe", "governance", "audit")},
    )
    if fault == "alias":
        enrollment["paths"]["audit"] = "/sealed/probe"
    files["/sealed/enrollment"] = wire(enrollment)
    activity = []

    class Held:
        def read(self, path, maximum):
            activity.append(path)
            if fault == "unsafe":
                raise ValueError("SYNTHETIC unsafe metadata")
            assert len(files[path]) <= maximum
            return files[path]

        def verify(self):
            if fault == "race":
                raise ValueError("SYNTHETIC held metadata changed")

        def close(self):
            activity.append("closed")
            return ["OSError"] if fault == "close" else []

    uid = 0 if fault == "root" else 1000 if fault == "actor" else 65533
    monkeypatch.setattr(intake, "os", SimpleNamespace(geteuid=lambda: uid))
    monkeypatch.setattr(
        safety_collection,
        "_kernel_boot_id",
        lambda: "wrong" if fault == "boot" else BOOT,
    )
    monkeypatch.setattr(safety_collection, "_HeldFiles", Held)
    args = dict(
        expected_enrollment_sha256=a._sha(files["/sealed/enrollment"]),
        expected_plan_sha256=enrollment["plan_sha256"],
    )
    if fault:
        with pytest.raises(safety_collection.SafetyCollectionError):
            intake.collect_advisory_exec_observation("/sealed/enrollment", **args)
    else:
        result = intake.collect_advisory_exec_observation("/sealed/enrollment", **args)
        assert result["evaluation"]["governance_boundary_consistent"] is True
        assert set(activity[:-1]) == set(files)
    assert activity[-1] == "closed"
