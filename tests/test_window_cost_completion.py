"""SYNTHETIC lifecycle/orchestration checks, never an actual APPLIED trial."""

from copy import deepcopy
import json

import pytest

import window_cost_completion_analysis as a
import run_window_cost_completion as runner
from window_cost_completion_lab import run_synthetic_window_cases, wire, sha
from observer_normal_stop_analysis import verify_normal_end
from test_observer_normal_stop_analysis import fixture as normal_fixture


@pytest.fixture
def synthetic(tmp_path):
    result = run_synthetic_window_cases(tmp_path / "synthetic-cases")
    return result, runner.collect_synthetic_raw(result)


def actual_fixture(tmp_path, *, slow=False):
    arms, raw_by_arm, normal_rows = [], {}, []
    for identifier in a.ARM_ORDER:
        mode, instrumented = (
            identifier.split("_", 1)[1],
            identifier.startswith("instrumented_"),
        )
        arm = dict(
            arm_id=identifier,
            mode=mode,
            instrumented=instrumented,
            original_cost_report=dict(
                processes={}, input_sha256="same", semantic_sha256="same"
            ),
            phase_reports={},
            phase_artifacts={},
            hostile_process_metrics={},
        )
        raw = {}
        if mode == "on":
            (tmp_path / identifier).mkdir()
            values = normal_fixture(
                tmp_path / identifier,
                profile="phase_and_clock" if instrumented else "stop_only",
                slow=slow,
            )
            raw = {
                key[:-4]: value for key, value in values.items() if key.endswith("_raw")
            }
            raw.update(
                observer=values["sidecars"]["phase"],
                calls=values["sidecars"]["calls"],
                context=values["sidecars"]["context"],
            )
            arm.update(values["original"])
            control = deepcopy(values["control_context"])
            control["artifacts"] = {
                name: None
                if raw[name] is None
                else dict(bytes=len(raw[name]), sha256=sha(raw[name]))
                for name in ("completion", "request", "journal", "anchors")
            }
            arm["normal_stop"] = control
            arm["raw_artifacts"] = {
                name: dict(bytes=len(raw[name]), sha256=sha(raw[name]))
                for name in ("trust", "source")
            }
            arm["clock_artifacts"] = {
                name: None
                if raw[name] is None
                else dict(bytes=len(raw[name]), sha256=sha(raw[name]))
                for name in ("calls", "context")
            }
            arm["phase_artifacts"] = dict(
                observer=None
                if raw["observer"] is None
                else dict(bytes=len(raw["observer"]), sha256=sha(raw["observer"]))
            )
            metadata = dict(control["expected_metadata"])
            del metadata["role"]
            arm["bootstrap_provenance"] = dict(metadata=metadata)
            arm["original_cost_report"]["processes"]["observer"] = dict(
                final=control["request_record"]["observer_initial"]
            )
            normal_rows.append(
                dict(
                    arm_id=identifier,
                    artifact_read_failures=[],
                    **verify_normal_end(**values),
                )
            )
        else:
            arm["normal_stop"] = dict(request_record=dict(controller_identity={}))
            normal_rows.append(
                dict(
                    arm_id=identifier,
                    status="expected_uncatchable_fault_prefix"
                    if mode == "faulted"
                    else "not_exercised_observer_absent",
                    normal_end_verified=False,
                )
            )
        metrics = dict(
            coverage="complete",
            cpu_seconds=0.25,
            read_bytes_delta=0,
            write_bytes_delta=100,
            sampled_peak_rss_kib=1000,
            kernel_hwm_kib=2000,
        )
        root = arm["normal_stop"]["request_record"]["controller_identity"]
        if not root:
            root.update(pid=999, start_ticks=456, boot_id="test-boot")
            arm["clock_context"] = dict(controller_boot_id="test-boot")
        identities = {
            "native": dict(pid=777, start_ticks=700),
            "signer": dict(pid=888, start_ticks=800),
            "controller": dict(pid=root["pid"], start_ticks=root["start_ticks"]),
            "observer": dict(pid=123, start_ticks=456),
        }
        if mode == "on":
            identities["observer"] = {
                key: arm["original_cost_report"]["processes"]["observer"]["final"][key]
                for key in ("pid", "start_ticks")
            }
        for role, identity in identities.items():
            arm["original_cost_report"]["processes"][role] = dict(
                final=dict(identity, available=True)
            )
        arm["hostile_process_metrics"] = {
            role: dict(deepcopy(metrics), final=dict(identities[role], available=True))
            for role in ("native", "signer", "controller")
        }
        if mode != "off":
            arm["hostile_process_metrics"]["observer"] = dict(
                deepcopy(metrics), final=dict(identities["observer"], available=True)
            )
        arms.append(arm)
        raw_by_arm[identifier] = raw
    return dict(
        original_load_evaluation=dict(original_arm_inputs=arms),
        normal_end_evaluations=normal_rows,
        instrumented_on_five_ms_status="withheld"
        if slow
        else "qualified_sampled_anchors",
        comparison_qualified=False,
    ), raw_by_arm


def analyze(actual, raw, synthetic):
    source, synthetic_raw = synthetic
    return a.analyze_window_cost_completion(
        actual,
        source,
        actual_phase_raw_by_arm_role=raw,
        synthetic_artifact_raw_by_case=synthetic_raw,
    )


def test_original_expiry_and_pending_loss_are_distinct_and_only_synthetic(synthetic):
    result = analyze({}, {}, synthetic)
    cases = {case["id"]: case for case in result["synthetic_window_cases"]}
    assert set(cases) == set(a.EXPECTED)
    assert cases["expiry_commit"]["observed_lifecycle"] == "normal_expiry_commit"
    assert (
        cases["expiry_commit"]["journal_summary"]["committed"]
        == len(cases["expiry_commit"]["outcomes"])
        == 1
    )
    stopped = cases["stop_pending_loss"]
    assert stopped["observed_lifecycle"] == "explicit_pending_stop_loss"
    assert (
        stopped["journal_summary"]["committed"] == 0
        and stopped["journal_summary"]["lost"] == 1
    )
    assert (
        stopped["outcomes"] == []
        and stopped["control_receipt"]["pending_windows_lost"] == 1
    )
    assert cases["pre_deadline_not_committed"]["outcomes"] == []
    assert cases["duplicate_does_not_reopen"]["journal_summary"]["committed"] == 1
    assert cases["commit_failure_loss"]["journal_summary"]["lost"] == 1
    assert cases["witness_close_failure"]["control_receipt"] is None
    assert cases["witness_close_failure"]["journal_summary"]["normal_close_rows"] == 0
    assert cases["recording_failure_prefix"]["status"] == "partial_prefix"
    assert (
        cases["recording_failure_prefix"]["phase_report"]["normal_return_confirmed"]
        is False
    )
    assert cases["recording_failure_prefix"]["journal_summary"]["committed"] == 1
    assert all(
        case["evidence_kind"] == a.EVIDENCE and case["applied_premise"] == a.PREMISE
        for case in cases.values()
    )
    assert result["actual_applied_window_status"] == a.ACTUAL_STATUS
    assert result["actual_lifecycle"]["expiry_commit_cost"] is None
    assert all(flag is False for flag in result["authority_flags"].values())


def test_actual_raw_replay_costs_preserve_original_without_promoting_windows(
    tmp_path, synthetic
):
    actual, raw = actual_fixture(tmp_path)
    before = deepcopy(actual)
    result = analyze(actual, raw, synthetic)
    assert result["original_normal_clock_evaluation"] == actual == before
    assert len(result["actual_cost_by_arm_role"]) == 30
    stops = {row["arm_id"]: row for row in result["actual_lifecycle"]["normal_stops"]}
    assert stops["instrumented_on"]["replay"]["normal_end_verified"] is True
    assert stops["instrumented_on"]["published_evaluation_matches"] is True
    item = next(
        row
        for row in result["actual_cost_by_arm_role"]
        if row["arm_id"] == "instrumented_on" and row["role"] == "observer"
    )
    assert item["phase_report"]["complete_spans"]
    assert (
        item["full_interval_cpu_seconds"] == 0.25
        and item["full_interval_read_bytes"] == 0
    )
    assert item["window_specific_cost"] is None
    witness = next(
        row for row in result["actual_cost_by_arm_role"] if row["role"] == "witness"
    )
    assert (
        witness["full_interval_cpu_seconds"]
        is witness["full_interval_read_bytes"]
        is None
    )
    assert (
        result["whole_measurement_qualified"] is result["comparison_qualified"] is False
    )
    assert result["qualified_safety_count"] is None


def test_original_slow_clock_withheld_after_true_normal_closure(tmp_path, synthetic):
    actual, raw = actual_fixture(tmp_path, slow=True)
    result = analyze(actual, raw, synthetic)
    on = next(
        row
        for row in result["actual_lifecycle"]["normal_stops"]
        if row["arm_id"] == "instrumented_on"
    )
    assert on["replay"]["normal_end_verified"] is True
    assert on["replay"]["five_ms_status"] == "withheld"
    assert (
        result["original_normal_clock_evaluation"]["instrumented_on_five_ms_status"]
        == "withheld"
    )


@pytest.mark.parametrize(
    "fault",
    [
        "missing_phase",
        "phase_hash",
        "missing_source",
        "published_eligible",
        "published_normal",
        "wrong_pid",
    ],
)
def test_optional_actual_failures_preserve_main_and_synthetic_siblings(
    tmp_path, synthetic, fault
):
    actual, raw = actual_fixture(tmp_path)
    arm = actual["original_load_evaluation"]["original_arm_inputs"][3]
    if fault == "missing_phase":
        raw["instrumented_on"]["observer"] = None
    elif fault == "phase_hash":
        raw["instrumented_on"]["observer"] += b" "
    elif fault == "missing_source":
        raw["instrumented_on"]["source"] = None
    elif fault == "published_eligible":
        arm["clock_report"]["eligible"] = not arm["clock_report"]["eligible"]
    elif fault == "published_normal":
        actual["normal_end_evaluations"][3]["normal_end_verified"] = False
    else:
        arm["original_cost_report"]["processes"]["observer"]["final"]["pid"] = 9999
    before = deepcopy(actual)
    result = analyze(actual, raw, synthetic)
    assert result["original_normal_clock_evaluation"] == before
    assert (
        next(
            case
            for case in result["synthetic_window_cases"]
            if case["id"] == "expiry_commit"
        )["journal_summary"]["committed"]
        == 1
    )
    assert result["actual_lifecycle"]["expiry_commit_cost"] is None
    assert result["comparison_qualified"] is False


@pytest.mark.parametrize(
    "fault", ["incomplete", "negative_cpu", "bool_io", "missing_metrics"]
)
def test_missing_cpu_io_not_zero_and_partial_known_peaks_remain(
    tmp_path, synthetic, fault
):
    actual, raw = actual_fixture(tmp_path)
    arm = actual["original_load_evaluation"]["original_arm_inputs"][3]
    metrics = arm["hostile_process_metrics"]["observer"]
    if fault == "incomplete":
        metrics["coverage"] = "incomplete"
    elif fault == "negative_cpu":
        metrics["cpu_seconds"] = -1
    elif fault == "bool_io":
        metrics["read_bytes_delta"] = False
    else:
        del arm["hostile_process_metrics"]["observer"]
    result = analyze(actual, raw, synthetic)
    cost = next(
        row
        for row in result["actual_cost_by_arm_role"]
        if row["arm_id"] == "instrumented_on" and row["role"] == "observer"
    )
    assert (
        cost["full_interval_cpu_seconds"]
        is cost["full_interval_read_bytes"]
        is cost["full_interval_write_bytes"]
        is None
    )
    assert cost["sampled_peak_rss_kib"] == (
        None if fault == "missing_metrics" else 1000
    )


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "hash",
        "duplicate",
        "kind",
        "expectation",
        "bool_count",
        "fake_actual",
        "not_applied",
        "loss_to_commit",
    ],
)
def test_synthetic_bad_inputs_preserve_valid_siblings_without_actual_upgrade(
    synthetic, fault
):
    source, raw = deepcopy(synthetic)
    case = source["cases"][0]
    identifier = case["id"]
    if fault == "missing":
        raw[identifier]["journal"] = None
    elif fault == "hash":
        raw[identifier]["journal"] += b" "
    elif fault == "duplicate":
        source["cases"].append(deepcopy(case))
    elif fault == "kind":
        case["evidence_kind"] = "ACTUAL_APPLIED"
    elif fault == "expectation":
        case["expected_lifecycle"] = "normal_expiry_commit"
    elif fault == "fake_actual":
        case["applied_premise"] = "real_native_action"
    elif fault == "not_applied":
        event = json.loads(raw[identifier]["event"])
        event["enforcement"]["mode"] = "dry_run"
        raw[identifier]["event"] = wire(event)
        case["artifacts"]["event"].update(
            sha256=sha(raw[identifier]["event"]), bytes=len(raw[identifier]["event"])
        )
    else:
        observations = json.loads(raw[identifier]["observations"])
        if fault == "loss_to_commit":
            observations["control_receipt"]["committed_outcomes"] = 1
        else:
            observations["callback_log"][-1]["returned_count"] = False
        raw[identifier]["observations"] = wire(observations)
        case["artifacts"]["observations"].update(
            sha256=sha(raw[identifier]["observations"]),
            bytes=len(raw[identifier]["observations"]),
        )
    result = a.analyze_window_cost_completion(
        {}, source, actual_phase_raw_by_arm_role={}, synthetic_artifact_raw_by_case=raw
    )
    assert (
        next(
            row for row in result["synthetic_window_cases"] if row["id"] == identifier
        )["status"]
        == "withheld"
    )
    assert (
        next(
            row
            for row in result["synthetic_window_cases"]
            if row["id"] == "expiry_commit"
        )["observed_lifecycle"]
        == "normal_expiry_commit"
    )
    assert result["actual_applied_window_status"] == a.ACTUAL_STATUS


def test_pure_analyzer_performs_no_io_or_process_calls(synthetic, monkeypatch):
    import builtins
    import subprocess

    source, raw = synthetic
    monkeypatch.setattr(
        builtins, "open", lambda *args, **kwargs: pytest.fail("analyzer opened file")
    )
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("analyzer spawned process"),
    )
    result = a.analyze_window_cost_completion(
        {}, source, actual_phase_raw_by_arm_role={}, synthetic_artifact_raw_by_case=raw
    )
    assert len(result["synthetic_window_cases"]) == 7


def test_wrapper_executes_actual_once_and_separates_original_export(
    tmp_path, monkeypatch
):
    calls = []
    actual = dict(schema_version="SYNTHETIC actual-matrix stand-in")
    monkeypatch.setattr(
        runner.original, "run", lambda: calls.append("actual") or actual
    )

    def export(value, destination):
        assert value is actual
        destination.mkdir()
        (destination / "report.json").write_bytes(wire(value))
        calls.append("export")

    monkeypatch.setattr(runner.original, "export_public", export)
    result = runner.run(tmp_path / "result")
    assert calls == ["actual", "export"]
    assert (
        json.loads((tmp_path / "result/original-normal-clock/report.json").read_bytes())
        == actual
    )
    assert (tmp_path / "result/window-cost-completion.json").exists()
    assert result["original_normal_clock_evaluation"] == actual
    with pytest.raises(FileExistsError):
        runner.run(tmp_path / "result")
    assert calls == ["actual", "export"]


def test_actual_failure_retained_without_retry(tmp_path, monkeypatch):
    calls = []
    error = RuntimeError("SYNTHETIC actual-matrix failure")
    error.normal_stop_partial_report = dict(
        schema_version="retained-failure", original_load_evaluation={}
    )

    def fail():
        calls.append("actual")
        raise error

    monkeypatch.setattr(runner.original, "run", fail)
    monkeypatch.setattr(
        runner.original, "export_public", lambda value, destination: destination.mkdir()
    )
    result = runner.run(tmp_path / "result")
    assert calls == ["actual"]
    assert (
        result["original_normal_clock_evaluation"] == error.normal_stop_partial_report
    )
    assert "actual_matrix_failed_RuntimeError" in result["blockers"]


@pytest.mark.parametrize(
    "fault",
    [
        "pid",
        "start",
        "pid_bool",
        "start_bool",
        "available_false",
        "available_int",
        "original_pid",
        "original_available",
        "root_boot",
        "clock_boot",
    ],
)
def test_cost_identity_mismatch_never_publishes_full_or_peak_cost(
    tmp_path, synthetic, fault
):
    actual, raw = actual_fixture(tmp_path)
    arm = next(
        row
        for row in actual["original_load_evaluation"]["original_arm_inputs"]
        if row["arm_id"] == "instrumented_on"
    )
    final = arm["hostile_process_metrics"]["observer"]["final"]
    if fault == "pid":
        final["pid"] += 1
    elif fault == "start":
        final["start_ticks"] += 1
    elif fault == "pid_bool":
        final["pid"] = True
    elif fault == "start_bool":
        final["start_ticks"] = True
    elif fault == "available_false":
        final["available"] = False
    elif fault == "available_int":
        final["available"] = 1
    elif fault == "original_pid":
        arm["original_cost_report"]["processes"]["observer"]["final"]["pid"] += 1
    elif fault == "original_available":
        arm["original_cost_report"]["processes"]["observer"]["final"]["available"] = 1
    elif fault == "root_boot":
        arm["normal_stop"]["request_record"]["controller_identity"]["boot_id"] = (
            "other-boot"
        )
    else:
        arm["clock_context"]["controller_boot_id"] = "other-boot"
    before = deepcopy(actual)
    result = analyze(actual, raw, synthetic)
    item = next(
        row
        for row in result["actual_cost_by_arm_role"]
        if row["arm_id"] == "instrumented_on" and row["role"] == "observer"
    )
    assert all(
        item[name] is None
        for name in (
            "full_interval_cpu_seconds",
            "full_interval_read_bytes",
            "full_interval_write_bytes",
            "sampled_peak_rss_kib",
            "kernel_hwm_kib",
        )
    )
    assert "process_identity_missing_invalid_or_mismatched" in item["reasons"]
    assert (
        item["process_metrics"]["hostile_window"]
        == arm["hostile_process_metrics"]["observer"]
    )
    assert result["original_normal_clock_evaluation"] == actual == before


def test_witness_injected_process_metrics_remain_shared_and_unavailable(
    tmp_path, synthetic
):
    actual, raw = actual_fixture(tmp_path)
    arm = actual["original_load_evaluation"]["original_arm_inputs"][3]
    arm["hostile_process_metrics"]["witness"] = deepcopy(
        arm["hostile_process_metrics"]["controller"]
    )
    result = analyze(actual, raw, synthetic)
    item = next(
        row
        for row in result["actual_cost_by_arm_role"]
        if row["arm_id"] == arm["arm_id"] and row["role"] == "witness"
    )
    assert item["full_interval_cpu_seconds"] is item["sampled_peak_rss_kib"] is None
    assert "witness_process_not_isolated_from_controller" in item["reasons"]


def test_bad_optional_arm_map_does_not_abort_following_arms(tmp_path, synthetic):
    actual, raw = actual_fixture(tmp_path)
    raw["original_off"] = None
    result = analyze(actual, raw, synthetic)
    assert len(result["actual_cost_by_arm_role"]) == 30
    on = next(
        row
        for row in result["actual_lifecycle"]["normal_stops"]
        if row["arm_id"] == "instrumented_on"
    )
    assert on["replay"]["normal_end_verified"] is True
    assert "original_off_raw_map_missing_or_invalid" in result["blockers"]


@pytest.mark.parametrize("bad", [None, [], {"id": []}, {"id": {"bad": "id"}}])
def test_bad_synthetic_case_is_local_and_keeps_later_valid_siblings(synthetic, bad):
    source, raw = deepcopy(synthetic)
    source["cases"].insert(0, bad)
    result = a.analyze_window_cost_completion(
        {}, source, actual_phase_raw_by_arm_role={}, synthetic_artifact_raw_by_case=raw
    )
    assert len(result["synthetic_window_cases"]) == 8
    assert result["synthetic_window_cases"][0]["status"] == "withheld"
    expiry = next(
        row for row in result["synthetic_window_cases"] if row["id"] == "expiry_commit"
    )
    assert expiry["status"] == "recorded_synthetic_case"


def _replace_synthetic_raw(case, raw, slot, value):
    raw[case["id"]][slot] = wire(value)
    case["artifacts"][slot] = dict(
        bytes=len(raw[case["id"]][slot]), sha256=sha(raw[case["id"]][slot])
    )


@pytest.mark.parametrize(
    "fault",
    [
        "phase_summary",
        "outcomes",
        "status_count",
        "status_bool",
        "status_head",
        "deadline",
        "event_epoch",
        "objective_window",
        "finalize_missing",
        "finalize_zero",
        "finalize_bool",
        "finalize_early",
    ],
)
def test_synthetic_rebound_summary_cannot_replace_original_evidence(synthetic, fault):
    source, raw = deepcopy(synthetic)
    case = next(row for row in source["cases"] if row["id"] == "expiry_commit")
    observed = json.loads(raw[case["id"]]["observations"])
    if fault == "phase_summary":
        case["phase_report"]["normal_return_confirmed"] = False
    elif fault == "outcomes":
        observed["outcomes"] = []
    elif fault == "status_count":
        observed["final_journal_status"]["committed"] = 999
    elif fault == "status_bool":
        observed["final_journal_status"]["committed"] = True
    elif fault == "status_head":
        observed["final_journal_status"]["chain_head"] = "0" * 64
    elif fault == "deadline":
        observed["synthetic_deadline_epoch"] = 112.0
    elif fault == "event_epoch":
        event = json.loads(raw[case["id"]]["event"])
        event["normalized"]["ts"] = "1970-01-01T00:01:49+00:00"
        _replace_synthetic_raw(case, raw, "event", event)
    elif fault == "objective_window":
        policy = json.loads(raw[case["id"]]["policy"])
        policy["actions"]["throttle"]["observation_window"]["post_seconds"] = 2.0
        _replace_synthetic_raw(case, raw, "policy", policy)
    elif fault == "finalize_missing":
        observed["callback_log"].pop()
    elif fault == "finalize_zero":
        observed["callback_log"][-1]["returned_count"] = 0
    elif fault == "finalize_bool":
        observed["callback_log"][-1]["returned_count"] = True
    else:
        observed["callback_log"][-1]["supplied_epoch"] = 112.999
    _replace_synthetic_raw(case, raw, "observations", observed)
    result = a.analyze_window_cost_completion(
        {}, source, actual_phase_raw_by_arm_role={}, synthetic_artifact_raw_by_case=raw
    )
    bad = next(
        row for row in result["synthetic_window_cases"] if row["id"] == case["id"]
    )
    assert bad["status"] == "withheld"
    assert (
        next(
            row
            for row in result["synthetic_window_cases"]
            if row["id"] == "stop_pending_loss"
        )["status"]
        == "recorded_synthetic_case"
    )


@pytest.mark.parametrize(
    "fault", ["header", "header_bool", "session_open", "session_close", "post_close"]
)
def test_rehashed_synthetic_journal_still_requires_valid_header_and_session(
    synthetic, fault
):
    source, raw = deepcopy(synthetic)
    case = next(row for row in source["cases"] if row["id"] == "expiry_commit")
    rows = [json.loads(line) for line in raw[case["id"]]["journal"].splitlines()]
    if fault == "header":
        rows[0]["data"] = {}
    elif fault == "header_bool":
        rows[0]["data"]["max_identities"] = True
    elif fault == "session_open":
        rows[1]["data"]["extra"] = "bad"
    elif fault == "session_close":
        rows[-1]["data"]["boot_id"] = "other-boot"
    else:
        rows.append(deepcopy(rows[-1]))
    previous = "0" * 64
    for index, row in enumerate(rows, 1):
        row.update(seq=index, prev=previous)
        row["sha256"] = sha(
            a._json({key: row[key] for key in ("seq", "prev", "kind", "data")})
        )
        previous = row["sha256"]
    raw[case["id"]]["journal"] = b"".join(wire(row) for row in rows)
    case["artifacts"]["journal"] = dict(
        bytes=len(raw[case["id"]]["journal"]), sha256=sha(raw[case["id"]]["journal"])
    )
    result = a.analyze_window_cost_completion(
        {}, source, actual_phase_raw_by_arm_role={}, synthetic_artifact_raw_by_case=raw
    )
    bad = next(
        row for row in result["synthetic_window_cases"] if row["id"] == case["id"]
    )
    assert bad["status"] == "withheld"
    assert "journal" in " ".join(bad["reasons"]) or "session" in " ".join(
        bad["reasons"]
    )


def test_recording_failure_needs_actual_partial_phase_prefix(synthetic):
    source, raw = deepcopy(synthetic)
    case = next(
        row for row in source["cases"] if row["id"] == "recording_failure_prefix"
    )
    case["artifacts"]["phase"] = None
    raw[case["id"]]["phase"] = None
    result = a.analyze_window_cost_completion(
        {}, source, actual_phase_raw_by_arm_role={}, synthetic_artifact_raw_by_case=raw
    )
    bad = next(
        row for row in result["synthetic_window_cases"] if row["id"] == case["id"]
    )
    assert bad["status"] == "withheld"
    assert (
        next(
            row
            for row in result["synthetic_window_cases"]
            if row["id"] == "expiry_commit"
        )["status"]
        == "recorded_synthetic_case"
    )


@pytest.mark.parametrize(
    "fault", ["controller_pid", "controller_start", "controller_bool"]
)
def test_controller_metrics_bind_actual_root_request_identity(
    tmp_path, synthetic, fault
):
    actual, raw = actual_fixture(tmp_path)
    arm = actual["original_load_evaluation"]["original_arm_inputs"][2]
    final = arm["hostile_process_metrics"]["controller"]["final"]
    if fault == "controller_pid":
        final["pid"] += 1
    elif fault == "controller_start":
        final["start_ticks"] += 1
    else:
        final["available"] = 1
    result = analyze(actual, raw, synthetic)
    item = next(
        row
        for row in result["actual_cost_by_arm_role"]
        if row["arm_id"] == arm["arm_id"] and row["role"] == "controller"
    )
    assert item["full_interval_cpu_seconds"] is item["sampled_peak_rss_kib"] is None
    assert "process_identity_missing_invalid_or_mismatched" in item["reasons"]


def test_complete_trace_cannot_be_relabelled_as_recording_failure(synthetic):
    source, raw = deepcopy(synthetic)
    case = next(
        row for row in source["cases"] if row["id"] == "recording_failure_prefix"
    )
    other = next(row for row in source["cases"] if row["id"] == "expiry_commit")
    raw[case["id"]]["phase"] = raw[other["id"]]["phase"]
    case["artifacts"]["phase"] = deepcopy(other["artifacts"]["phase"])
    case["phase_pins"] = deepcopy(other["phase_pins"])
    case["phase_report"] = deepcopy(other["phase_report"])
    case["phase_report"].update(status="partial_prefix", normal_return_confirmed=False)
    case["phase_report"]["reasons"].append("external_recorder_incomplete")
    result = a.analyze_window_cost_completion(
        {}, source, actual_phase_raw_by_arm_role={}, synthetic_artifact_raw_by_case=raw
    )
    bad = next(
        row for row in result["synthetic_window_cases"] if row["id"] == case["id"]
    )
    assert bad["status"] == "withheld"
    assert bad["phase_report"]["complete_spans"]
