"""Bounded pure replay of declared test evidence; never actual APPLIED qualification."""

from copy import deepcopy
from dataclasses import fields
from datetime import datetime
import hashlib
import math

from azazel_edge.benchmark.timing_cost_attribution import analyze_trace, ARM_ORDER
from azazel_edge.outcome.journal import _json, _parse, _outcome
from azazel_edge.outcome.adapter import from_rust_event
from azazel_edge.outcome.contracts import ExecutionStatus
from azazel_edge.outcome.input_control_stop import ObserverControlStop
from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy, persistence_context
from observer_normal_stop_analysis import verify_normal_end

EVIDENCE = "SYNTHETIC_RECORDED_TEST_ONLY"
PREMISE = "synthetic_fixture_not_observed_native_action"
ACTUAL_STATUS = "unavailable_under_existing_authority"
ROLES = ("native", "signer", "observer", "witness", "controller")
FLAGS = dict(
    authorizes_transition=False,
    experiment=False,
    measurement_completed=False,
    production_admission=False,
    resume_authorized=False,
)
EXPECTED = {
    "pre_deadline_not_committed": "pending_not_committed",
    "expiry_commit": "normal_expiry_commit",
    "stop_pending_loss": "explicit_pending_stop_loss",
    "duplicate_does_not_reopen": "retained_identity_not_reopened",
    "commit_failure_loss": "commit_unavailable_loss_retained",
    "witness_close_failure": "close_unverified_no_control_receipt",
    "recording_failure_prefix": "recording_partial_prefix_only",
}
MAX_BYTES = 4 * 1024 * 1024
ERRORS = (
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    OSError,
    OverflowError,
    RecursionError,
    UnicodeError,
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def same(left, right):
    return _json(left) == _json(right)


def _bound(raw, descriptor, maximum):
    if raw is None and descriptor is None:
        return None
    if not (
        type(raw) is bytes
        and len(raw) <= maximum
        and type(descriptor) is dict
        and type(descriptor.get("bytes")) is int
        and descriptor["bytes"] == len(raw)
        and descriptor.get("sha256") == sha(raw)
    ):
        raise ValueError("missing_invalid_or_unbound_original")
    return raw


def _phase_pins(original, role):
    pins = dict(original.get("bootstrap_provenance", {}).get("metadata", {}), role=role)
    initial = (
        original.get("normal_stop", {})
        .get("request_record", {})
        .get("controller_identity")
        or {}
    )
    point = (
        original.get("original_cost_report", {})
        .get("processes", {})
        .get(role, {})
        .get("final")
    )
    if role in ("witness", "controller"):
        point = initial
    if (
        point
        and type(point.get("pid")) is int
        and type(point.get("start_ticks")) is int
        and initial.get("boot_id")
    ):
        pins.update(
            pid=point["pid"],
            start_ticks=point["start_ticks"],
            boot_id=initial["boot_id"],
        )
    return pins


def _cost(original, role, raw):
    reasons = []
    descriptor = original.get("phase_artifacts", {}).get(role)
    report = None
    try:
        trusted = _bound(raw, descriptor, MAX_BYTES)
        if trusted is not None:
            report = analyze_trace(trusted, expected=_phase_pins(original, role))
            published = original.get("phase_reports", {}).get(role)
            # An externally known descriptor-close error may only reduce closure.
            if published and published.get("reasons") == report.get("reasons", []) + [
                "external_recorder_incomplete"
            ]:
                report["normal_return_confirmed"] = False
                report["status"] = "partial_prefix"
                report["reasons"].append("external_recorder_incomplete")
                for value in report["phases"].values():
                    value["coverage"] = "partial_prefix"
            if not same(report, published):
                reasons.append("published_phase_report_differs_from_original_replay")
    except ERRORS:
        reasons.append("phase_original_missing_invalid_or_unbound")
    metrics = original.get("hostile_process_metrics", {}).get(role)
    loop = original.get("original_cost_report", {}).get("processes", {}).get(role)
    cpu = read = write = None
    peak = hwm = None
    root_identity = (
        original.get("normal_stop", {})
        .get("request_record", {})
        .get("controller_identity")
        or {}
    )
    boot = original.get("clock_context", {}).get("controller_boot_id")
    point = (
        root_identity
        if role == "controller"
        else (loop.get("final") if type(loop) is dict else None)
    )
    final = metrics.get("final") if type(metrics) is dict else None
    identity_bound = (
        role != "witness"
        and type(point) is dict
        and type(final) is dict
        and type(boot) is str
        and bool(boot)
        and all(
            type(point.get(key)) is int
            and point[key] > 0
            and type(final.get(key)) is int
            and final[key] == point[key]
            for key in ("pid", "start_ticks")
        )
        and final.get("available") is True
        and (role == "controller" or point.get("available") is True)
        and (not root_identity or root_identity.get("boot_id") == boot)
    )
    if (
        identity_bound
        and original.get("instrumented")
        and role in ("signer", "observer", "controller")
    ):
        header = report.get("header") if type(report) is dict else None
        identity_bound = (
            type(header) is dict
            and header.get("boot_id") == boot
            and all(
                type(header.get(key)) is int and header[key] == final[key]
                for key in ("pid", "start_ticks")
            )
            and not reasons
        )
    if role == "witness":
        reasons.append("witness_process_not_isolated_from_controller")
    elif type(metrics) is dict:
        values = (
            metrics.get("cpu_seconds"),
            metrics.get("read_bytes_delta"),
            metrics.get("write_bytes_delta"),
        )
        valid = (
            type(values[0]) in (int, float)
            and math.isfinite(values[0])
            and values[0] >= 0
            and all(type(value) is int and value >= 0 for value in values[1:])
        )
        if not identity_bound:
            reasons.append("process_identity_missing_invalid_or_mismatched")
        if metrics.get("coverage") == "complete" and valid and identity_bound:
            cpu, read, write = values
        else:
            reasons.append(
                "process_interval_incomplete_or_invalid_full_cpu_io_unavailable"
            )
        if identity_bound:
            peak = metrics.get("sampled_peak_rss_kib")
            hwm = metrics.get("kernel_hwm_kib")
            peak = peak if type(peak) is int and peak >= 0 else None
            hwm = hwm if type(hwm) is int and hwm >= 0 else None
    else:
        reasons.append("process_interval_unavailable")
    if role == "observer" and original.get("mode") == "off":
        status = "not_exercised_observer_absent"
        reasons.append("observer_absent_not_zero_cost")
    elif report is not None:
        status = (
            "partial_prefix"
            if reasons or not report.get("normal_return_confirmed")
            else "replayed_descriptive_phase_calls"
        )
    else:
        status = (
            ("partial_prefix" if reasons else "process_metrics_only")
            if metrics
            else "unavailable"
        )
    return dict(
        arm_id=original["arm_id"],
        role=role,
        evidence_kind="actual_existing_unconfined_software_lab",
        raw_sha256=sha(raw) if type(raw) is bytes else None,
        status=status,
        phase_report=report,
        process_metrics=dict(
            original_loop=deepcopy(loop), hostile_window=deepcopy(metrics)
        ),
        cost_scope="declared_background_writer_interval_not_entire_lifecycle; inclusive_spans_not_additive; controller_mixes_harness_witness_drainer_recording"
        if role != "witness"
        else "witness_thread_spans_only_shared_controller_process",
        full_interval_cpu_seconds=cpu,
        full_interval_read_bytes=read,
        full_interval_write_bytes=write,
        sampled_peak_rss_kib=peak,
        kernel_hwm_kib=hwm,
        window_specific_cost=None,
        reasons=reasons,
    )


def _normal(original, raw):
    control = original["normal_stop"]
    descriptors = {
        **original.get("raw_artifacts", {}),
        **control.get("artifacts", {}),
        **original.get("clock_artifacts", {}),
    }
    limits = dict(
        trust=65536,
        source=2 * 1024 * 1024,
        journal=MAX_BYTES,
        anchors=MAX_BYTES,
        request=16384,
        completion=65536,
        calls=MAX_BYTES,
        context=16384,
    )
    bound = {
        name: _bound(raw.get(name), descriptors.get(name), maximum)
        for name, maximum in limits.items()
    }
    observer = _bound(
        raw.get("observer"),
        original.get("phase_artifacts", {}).get("observer"),
        MAX_BYTES,
    )
    return verify_normal_end(
        completion_raw=bound["completion"],
        control_context=control,
        original=original,
        sidecars=dict(phase=observer, calls=bound["calls"], context=bound["context"]),
        **{
            name + "_raw": bound[name]
            for name in ("trust", "source", "journal", "anchors", "request")
        },
    )


def _journal(raw):
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > MAX_BYTES
        or not raw.endswith(b"\n")
    ):
        raise ValueError("bounded original journal required")
    lines = raw.splitlines(keepends=True)
    if len(lines) > 4096:
        raise ValueError("synthetic journal row bound")
    previous = "0" * 64
    states, outcomes, counts, metas = {}, [], {}, {}
    header, boot, ready, closed = None, None, False, False
    for sequence, line in enumerate(lines, 1):
        row = _parse(line)
        if (
            type(row) is not dict
            or set(row) != {"seq", "prev", "kind", "data", "sha256"}
            or _json(row) + b"\n" != line
        ):
            raise ValueError("journal envelope")
        core = {key: row[key] for key in ("seq", "prev", "kind", "data")}
        if (
            type(row["seq"]) is not int
            or row["seq"] != sequence
            or row["prev"] != previous
            or row["sha256"] != sha(_json(core))
        ):
            raise ValueError("journal chain")
        previous = row["sha256"]
        kind, data = row["kind"], row["data"]
        if type(kind) is not str or type(data) is not dict or closed:
            raise ValueError("journal row shape or post-close transition")
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "header":
            if sequence != 1 or set(data) != {
                "schema_version",
                "scope_ref",
                "policy_sha256",
                "max_identities",
                "max_bytes",
                "input_config",
            }:
                raise ValueError("synthetic journal header shape")
            config = data["input_config"]
            auth = config.get("authentication") if type(config) is dict else None
            if (
                data["schema_version"] != "outcome-observation-journal/v3"
                or type(data["scope_ref"]) is not str
                or not data["scope_ref"]
                or type(data["max_identities"]) is not int
                or not 1 <= data["max_identities"] <= 16384
                or type(data["max_bytes"]) is not int
                or not 65536 <= data["max_bytes"] <= 64 * 1024 * 1024
                or type(config) is not dict
                or set(config)
                != {
                    "authentication",
                    "path_sha256",
                    "device",
                    "inode",
                    "uid",
                    "max_bytes",
                    "max_records",
                }
                or any(
                    type(config[key]) is not int or config[key] < 0
                    for key in ("device", "inode", "uid", "max_bytes", "max_records")
                )
                or type(auth) is not dict
                or set(auth) != {"schema_version", "trust_sha256"}
                or auth["schema_version"] != "outcome-input-auth/v1"
                or any(
                    type(value) is not str
                    or len(value) != 64
                    or any(char not in "0123456789abcdef" for char in value)
                    for value in (
                        data["policy_sha256"],
                        config["path_sha256"],
                        auth["trust_sha256"],
                    )
                )
            ):
                raise ValueError("synthetic journal header values")
            header = data
        elif header is None:
            raise ValueError("synthetic journal header missing")
        elif kind == "session_open":
            if (
                boot is not None
                or sequence != 2
                or set(data) != {"boot_id"}
                or type(data["boot_id"]) is not str
                or not data["boot_id"]
            ):
                raise ValueError("synthetic session start")
            boot = data["boot_id"]
        elif kind == "input_ready":
            if (
                boot is None
                or ready
                or sequence != 3
                or not same(data, {"offset": 0, "sha256": sha(b"")})
            ):
                raise ValueError("synthetic input readiness")
            ready = True
        elif kind == "session_close":
            if (
                not ready
                or not same(data, {"boot_id": boot})
                or "pending" in states.values()
            ):
                raise ValueError("synthetic session close")
            closed = True
        elif kind not in ("begin", "commit", "lost"):
            raise ValueError("unsupported synthetic journal transition")
        if kind in ("begin", "commit", "lost"):
            meta_names = {"decision_id", "execution_id", "objective_id", "boot_id"}
            extras = (
                {"outcome"}
                if kind == "commit"
                else {"reason"}
                if kind == "lost"
                else set()
            )
            if (
                not ready
                or set(data) != meta_names | extras
                or any(
                    type(data[name]) is not str or not data[name] for name in meta_names
                )
                or data["boot_id"] != boot
            ):
                raise ValueError("synthetic journal transition shape")
            key = (data["decision_id"], data["execution_id"], data["objective_id"])
            meta = {name: data[name] for name in meta_names}
            if kind == "begin":
                metas[key] = meta
                if key in states:
                    raise ValueError("retained synthetic identity reopened")
                states[key] = "pending"
            else:
                if states.get(key) != "pending" or not same(metas[key], meta):
                    raise ValueError("synthetic transition without pending window")
                if kind == "lost" and data["reason"] != "explicit_window_loss":
                    raise ValueError("synthetic loss reason")
                states[key] = kind
                if kind == "commit":
                    record = _outcome(data["outcome"])
                    if (
                        record.decision_id,
                        record.execution_id,
                        record.objective_id,
                    ) != key:
                        raise ValueError("synthetic outcome identity")
                    outcomes.append(record.to_dict())
    return dict(
        rows=len(lines),
        kinds=counts,
        pending=sum(value == "pending" for value in states.values()),
        committed=counts.get("commit", 0),
        lost=counts.get("lost", 0),
        normal_close_rows=counts.get("session_close", 0),
        bytes=len(raw),
        head=previous,
    ), outcomes


def _synthetic(case, supplied, duplicate=False):
    identifier = case.get("id") if type(case) is dict else None
    if type(identifier) is not str:
        identifier = None
    result = dict(
        id=identifier,
        evidence_kind=EVIDENCE,
        applied_premise=PREMISE,
        status="withheld",
        expected_lifecycle=EXPECTED.get(identifier),
        observed_lifecycle="unavailable",
        journal_summary=None,
        outcomes=None,
        control_receipt=None,
        phase_report=None,
        process_metrics=None,
        raw_sha256={},
        reasons=[],
    )
    try:
        if (
            type(case) is not dict
            or duplicate
            or identifier not in EXPECTED
            or case.get("evidence_kind") != EVIDENCE
            or case.get("applied_premise") != PREMISE
        ):
            raise ValueError("invalid_or_duplicate_synthetic_case")
        if case.get("expected_lifecycle") != EXPECTED[identifier]:
            raise ValueError("synthetic_expected_lifecycle_changed")
        slots = {"event", "policy", "observations", "journal", "phase"}
        if (
            type(supplied) is not dict
            or set(supplied) != slots
            or set(case["artifacts"]) != slots
        ):
            raise ValueError("synthetic_slots_missing_or_extra")
        raw = {
            name: _bound(supplied[name], case["artifacts"][name], MAX_BYTES)
            for name in slots
        }
        result["raw_sha256"] = {name: sha(value) for name, value in raw.items()}
        observed = _parse(raw["observations"])
        if type(observed) is not dict or _json(observed) + b"\n" != raw["observations"]:
            raise ValueError("canonical_synthetic_observations_required")
        event = _parse(raw["event"])
        execution = from_rust_event(event).execution
        policy = OutcomeTelemetryPolicy.from_mapping(
            _parse(raw["policy"]), source_ref=observed["policy_source_ref"]
        )
        if (
            execution.status is not ExecutionStatus.APPLIED
            or execution.action_kind not in ("throttle", "redirect", "isolate")
            or policy.objective_for(execution.action_kind, execution.decision_id)
            is None
        ):
            raise ValueError("synthetic_APPLIED_objective_premise_missing")
        summary, outcomes = _journal(raw["journal"])
        objective = policy.objective_for(execution.action_kind, execution.decision_id)
        expected_policy = sha(persistence_context(policy, "lo", 0.05).encode())
        journal_rows = [_parse(line) for line in raw["journal"].splitlines()]
        if (
            journal_rows[0]["data"]["policy_sha256"] != expected_policy
            or summary["kinds"].get("begin") != 1
            or any(
                not same(row["data"][name], value)
                for row in journal_rows
                if row["kind"] in ("begin", "commit", "lost")
                for name, value in dict(
                    decision_id=execution.decision_id,
                    execution_id=execution.execution_id,
                    objective_id=objective.objective_id,
                ).items()
            )
        ):
            raise ValueError(
                "synthetic_journal_policy_or_event_objective_identity_differs"
            )
        result.update(
            journal_summary=summary,
            outcomes=outcomes,
            control_receipt=deepcopy(observed["control_receipt"]),
        )
        report = analyze_trace(raw["phase"], expected=case["phase_pins"])
        result["phase_report"] = report
        published = case.get("phase_report")
        raw_phase_partial = (
            report.get("status") == "partial_prefix"
            and report.get("normal_return_confirmed") is False
        )
        if (
            observed.get("recorder_incomplete") is True
            and published
            and (
                published.get("reasons")
                == report.get("reasons", []) + ["external_recorder_incomplete"]
            )
        ):
            report["normal_return_confirmed"] = False
            report["status"] = "partial_prefix"
            report["reasons"].append("external_recorder_incomplete")
        if not same(report, published):
            raise ValueError(
                "synthetic_published_phase_report_differs_from_original_replay"
            )
        if (
            report.get("header") is None
            or report.get("valid_prefix_rows", 0) <= 1
            or not report.get("complete_spans")
            or (
                identifier not in ("recording_failure_prefix", "witness_close_failure")
                and report.get("normal_return_confirmed") is not True
            )
        ):
            raise ValueError("synthetic_phase_original_not_valid_for_fixed_case")
        if not same(observed.get("outcomes"), outcomes):
            raise ValueError("synthetic_observed_outcomes_differ_from_original_journal")
        status = observed["final_journal_status"]
        status_values = dict(
            sequence=summary["rows"],
            chain_head=summary["head"],
            bytes=summary["bytes"],
            committed=summary["committed"],
            lost=summary["lost"],
            pending=summary["pending"],
            identities=summary["kinds"].get("begin", 0),
            sessions=1,
        )
        if type(status) is not dict or any(
            not same(status.get(key), value) for key, value in status_values.items()
        ):
            raise ValueError("synthetic_final_journal_status_differs_from_original")
        event_epoch = datetime.fromisoformat(
            event["normalized"]["ts"].replace("Z", "+00:00")
        ).timestamp()
        deadline = event_epoch + float(objective.observation_window["post_seconds"])
        log = observed["callback_log"]
        if (
            type(log) is not list
            or len(log) > 64
            or any(type(row) is not dict for row in log)
            or type(observed.get("synthetic_deadline_epoch")) not in (int, float)
            or observed["synthetic_deadline_epoch"] != deadline
            or not any(
                row.get("operation") == "observe_event"
                and row.get("returned") is True
                and type(row.get("supplied_epoch")) in (int, float)
                and row["supplied_epoch"] == event_epoch
                for row in log
            )
        ):
            raise ValueError(
                "synthetic_deadline_or_observe_receipt_differs_from_event_objective"
            )
        if outcomes and any(
            not same(
                outcome["observation_window"],
                dict(
                    action_observed_epoch=event_epoch,
                    baseline_start_epoch=event_epoch
                    - float(objective.observation_window["pre_seconds"]),
                    effective_end_epoch=deadline,
                    planned_end_epoch=deadline,
                ),
            )
            for outcome in outcomes
        ):
            raise ValueError("synthetic_outcome_window_differs_from_event_objective")
        if identifier in ("expiry_commit", "duplicate_does_not_reopen") and not any(
            row.get("operation") == "finalize_at_deadline"
            and type(row.get("returned_count")) is int
            and row["returned_count"] == len(outcomes) == summary["committed"] == 1
            and type(row.get("supplied_epoch")) in (int, float)
            and math.isfinite(row["supplied_epoch"])
            and row["supplied_epoch"] >= deadline
            for row in log
        ):
            raise ValueError("synthetic_expiry_finalize_not_bound_to_journal_deadline")
        error = observed["exception_type"]
        receipt = observed["control_receipt"]
        if receipt is not None:
            control = ObserverControlStop(
                **{
                    field.name: receipt[field.name]
                    for field in fields(ObserverControlStop)
                }
            )
            if (
                not same(control.to_dict(), receipt)
                or receipt["committed_outcomes"] != summary["committed"]
                or receipt["lost_after"] != summary["lost"]
            ):
                raise ValueError("synthetic_control_receipt_types_or_counters_differ")
            expected_policy = sha(persistence_context(policy, "lo", 0.05).encode())
            if receipt["journal_policy_sha256"] != expected_policy:
                raise ValueError("synthetic_control_policy_differs")
        if identifier == "witness_close_failure":
            valid = (
                error is not None
                and receipt is None
                and summary["normal_close_rows"] == 0
            )
        elif identifier == "recording_failure_prefix":
            valid = (
                raw_phase_partial
                and report.get("header") is not None
                and report.get("valid_prefix_rows", 0) > 1
                and report.get("complete_spans")
                and report["status"] == "partial_prefix"
                and not report["normal_return_confirmed"]
                and observed["recorder_incomplete"] is True
            )
        else:
            valid = (
                error is None
                and type(receipt) is dict
                and summary["normal_close_rows"] == 1
            )
            valid = (
                valid
                and receipt["journal_sequence_after"] == summary["rows"]
                and receipt["journal_head_after"] == summary["head"]
                and receipt["journal_bytes_after"] == summary["bytes"]
            )
            if identifier in ("expiry_commit", "duplicate_does_not_reopen"):
                valid = (
                    valid
                    and summary["committed"] == 1
                    and summary["lost"] == 0
                    and len(outcomes) == 1
                )
            else:
                valid = (
                    valid
                    and summary["committed"] == 0
                    and summary["lost"] == 1
                    and not outcomes
                )
            log = observed["callback_log"]
            valid = valid and any(
                row["operation"] == "finalize_before_deadline"
                and type(row["returned_count"]) is int
                and row["returned_count"] == 0
                and type(row["supplied_epoch"]) in (int, float)
                and row["supplied_epoch"] < observed["synthetic_deadline_epoch"]
                for row in log
            )
            if identifier == "duplicate_does_not_reopen":
                valid = valid and any(
                    row["operation"] == "duplicate_observe_event"
                    and row["returned"] is False
                    for row in log
                )
        if not valid:
            raise ValueError("original_synthetic_lifecycle_does_not_match_fixed_case")
        result.update(
            status="recorded_synthetic_case"
            if identifier != "recording_failure_prefix"
            else "partial_prefix",
            observed_lifecycle=EXPECTED[identifier],
        )
        if identifier == "pre_deadline_not_committed":
            result["reasons"].append(
                "subsequent_control_close_loss_is_not_deadline_commit"
            )
        result["reasons"].extend(
            (
                "synthetic_authentication_and_APPLIED_premises_not_native_evidence",
                "synthetic_process_interval_not_independently_measured",
            )
        )
    except ERRORS as exc:
        result["reasons"].append(
            str(exc) if type(exc) is ValueError else type(exc).__name__
        )
    return result


def analyze_window_cost_completion(
    actual_result,
    synthetic_result,
    *,
    actual_phase_raw_by_arm_role,
    synthetic_artifact_raw_by_case,
):
    """Never mutate originals or treat a published approval flag as fresh evidence."""
    original = deepcopy(actual_result)
    lifecycle = dict(
        evidence_kind="actual_existing_unconfined_software_lab",
        normal_stops=[],
        fault_prefixes=[],
        applied_window_exercised=False,
        expiry_commit_cost=None,
        pending_stop_loss_cost=None,
        active_deadline_wait=None,
        reasons=[ACTUAL_STATUS],
    )
    costs, blockers = (
        [],
        [
            "actual_applied_window_unavailable",
            "synthetic_premise_not_native_execution",
            "mixed_controller_witness_accounting",
            "causal_benefit_unestablished",
        ],
    )
    try:
        arms = actual_result["original_load_evaluation"]["original_arm_inputs"]
        if type(arms) is not list or [arm["arm_id"] for arm in arms] != list(ARM_ORDER):
            raise ValueError("actual_six_arm_order_missing_or_changed")
        published = {
            row["arm_id"]: row
            for row in actual_result.get("normal_end_evaluations", [])
        }
        for arm in arms:
            raw = (
                actual_phase_raw_by_arm_role.get(arm["arm_id"])
                if type(actual_phase_raw_by_arm_role) is dict
                else None
            )
            if type(raw) is not dict:
                blockers.append(arm["arm_id"] + "_raw_map_missing_or_invalid")
                raw = {}
            for role in ROLES:
                try:
                    costs.append(_cost(arm, role, raw.get(role)))
                except ERRORS:
                    blockers.append(arm["arm_id"] + "_" + role + "_cost_invalid")
            if arm["mode"] == "on":
                try:
                    replay = _normal(arm, raw)
                    prior = published.get(arm["arm_id"], {})
                    mismatch = not same(replay, {key: prior.get(key) for key in replay})
                    lifecycle["normal_stops"].append(
                        dict(
                            arm_id=arm["arm_id"],
                            replay=replay,
                            published_evaluation_matches=not mismatch,
                        )
                    )
                    if mismatch:
                        blockers.append(
                            arm["arm_id"] + "_published_normal_result_mismatch"
                        )
                except ERRORS:
                    lifecycle["normal_stops"].append(
                        dict(
                            arm_id=arm["arm_id"],
                            replay=None,
                            published_evaluation_matches=None,
                        )
                    )
                    blockers.append(
                        arm["arm_id"] + "_normal_originals_missing_invalid_or_unbound"
                    )
            elif arm["mode"] == "faulted":
                lifecycle["fault_prefixes"].append(
                    dict(
                        arm_id=arm["arm_id"],
                        original=deepcopy(published.get(arm["arm_id"])),
                        normal_end_verified=False,
                    )
                )
    except ERRORS as exc:
        blockers.append(
            str(exc) if type(exc) is ValueError else "actual_evaluation_unavailable"
        )
    cases = []
    try:
        supplied_cases = synthetic_result["cases"]
        if (
            synthetic_result["schema_version"] != "edge-synthetic-window-lifecycle/v1"
            or synthetic_result["data_kind"] != "SYNTHETIC"
            or type(supplied_cases) is not list
            or len(supplied_cases) > 16
        ):
            raise ValueError("synthetic_bundle_schema_or_case_bound")
        total = sum(
            len(raw)
            for item in synthetic_artifact_raw_by_case.values()
            if type(item) is dict
            for raw in item.values()
            if type(raw) is bytes
        )
        if total > 64 * 1024 * 1024:
            raise ValueError("synthetic_bundle_byte_bound")
        ids = [
            case.get("id")
            if type(case) is dict and type(case.get("id")) is str
            else None
            for case in supplied_cases
        ]
        for case, identifier in zip(supplied_cases, ids):
            cases.append(
                _synthetic(
                    case,
                    synthetic_artifact_raw_by_case.get(identifier),
                    duplicate=ids.count(identifier) != 1,
                )
            )
        if set(ids) != set(EXPECTED):
            blockers.append("synthetic_fixed_case_coverage_incomplete_or_changed")
    except ERRORS as exc:
        blockers.append(
            str(exc) if type(exc) is ValueError else "synthetic_bundle_invalid"
        )
    if any(item["status"] in ("unavailable", "partial_prefix") for item in costs):
        blockers.append("actual_cost_coverage_partial_or_unavailable")
    return dict(
        schema_version="edge-window-cost-completion/v1",
        actual_applied_window_status=ACTUAL_STATUS,
        original_normal_clock_evaluation=original,
        actual_lifecycle=lifecycle,
        actual_cost_by_arm_role=costs,
        synthetic_window_cases=cases,
        blockers=blockers,
        authority_flags=dict(FLAGS),
        whole_measurement_qualified=False,
        comparison_qualified=False,
        qualified_safety_count=None,
    )
