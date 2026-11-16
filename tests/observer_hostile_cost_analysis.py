"""Read-only lab evaluation; missing clocks/load never become qualification.

This module is deliberately test infrastructure. It reuses the original SO11
and clock rules rather than defining a second 98% or 5ms acceptance rule.
"""

from copy import deepcopy
import hashlib
import json
import math
import re
from pathlib import Path

from azazel_edge.service_objectives import so11_quota_load as so11
from azazel_edge.benchmark.timing_cost_attribution import PINS, ARM_ORDER
from azazel_edge.benchmark.timing_cost_attribution import _header_metadata
from azazel_edge.outcome import input_live
from real_systemd import signed_network_clock as clock
from real_systemd.signed_network_recording import decode_calls_prefix

MAX_EVE_BYTES = 16 * 1024 * 1024
MAX_EVE_ROWS = 32768
MIN_WINDOW_NS = 6_000_000_000
MAX_CONTEXT_BYTES = 16384
CONTEXT_SCHEMA = "edge-load-clock-context/v1"
EXIT_BASIS = "trusted_launcher_conjunctive_return"
ENTRY_SHA256 = hashlib.sha256(Path(input_live.__file__).read_bytes()).hexdigest()


def _canonical(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def _uint(value):
    return type(value) is int and 0 <= value < 2**63


def recount_eve(raw, *, prefix, marker_lines):
    """Count only exact original writer bytes, excluding the retained old prefix.

    Erroring attempted writer counts are not treated as successful file writes.
    No partial line or missing marker is filled. Earlier counts survive errors.
    """
    result = dict(
        status="unavailable",
        error=None,
        raw_sha256=None,
        raw_bytes=None,
        prefix_sha256=None,
        written_by_class=None,
        observed_prefix_counts=None,
        count_coverage="unavailable",
        marker_count=None,
        marker_offsets=[],
        complete=False,
    )
    try:
        if not isinstance(raw, bytes) or not isinstance(prefix, bytes):
            raise ValueError("missing_original_bytes")
        result.update(
            raw_sha256=hashlib.sha256(raw).hexdigest(),
            raw_bytes=len(raw),
            prefix_sha256=hashlib.sha256(prefix).hexdigest(),
        )
        if (
            len(raw) > MAX_EVE_BYTES
            or len(prefix) > 65536
            or not raw.startswith(prefix)
            or not prefix.endswith(b"\n")
        ):
            raise ValueError("eve_bound_or_original_prefix_changed")
        if (
            not isinstance(marker_lines, (list, tuple))
            or len(marker_lines) != 3
            or any(
                not isinstance(v, bytes) or not v.endswith(b"\n") for v in marker_lines
            )
        ):
            raise ValueError("three_original_marker_lines_required")
        suffix = raw[len(prefix) :]
        if not suffix.endswith(b"\n") or raw.count(b"\n") > MAX_EVE_ROWS:
            raise ValueError("incomplete_or_overbound_eve")
        result.update(
            observed_prefix_counts={k: 0 for k in so11.NON_ALERT_KINDS},
            marker_count=0,
            count_coverage="validated_prefix_only",
        )
        offset = len(prefix)
        for line in suffix.splitlines(keepends=True):
            marker = result["marker_count"]
            if marker < 3 and line == marker_lines[marker]:
                result["marker_count"] += 1
                result["marker_offsets"].append(offset)
            else:
                row = json.loads(line)
                kind = row.get("event_type") if isinstance(row, dict) else None
                if kind not in so11.NON_ALERT_KINDS or line != so11._line(
                    kind, result["observed_prefix_counts"][kind]
                ):
                    raise ValueError("unexpected_or_reordered_original_input")
                result["observed_prefix_counts"][kind] += 1
            offset += len(line)
        if result["marker_count"] != 3:
            raise ValueError("missing_original_marker")
        result.update(
            status="verified_original_input",
            complete=True,
            written_by_class=dict(result["observed_prefix_counts"]),
            count_coverage="complete_original_suffix",
        )
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        result["error"] = "original_input_missing_invalid_or_incomplete"
    return result


def decode_clock_context(raw, *, expected):
    """Retain valid begin context on a missing/malformed end, without inventing it."""
    result = dict(
        begin=None,
        end=None,
        closed=False,
        error=None,
        raw_sha256=hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None,
    )
    try:
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_CONTEXT_BYTES:
            raise ValueError("context_missing_or_overbound")
        previous = "0" * 64
        lines = raw.splitlines(keepends=True)
        for sequence, line in enumerate(lines[:2], 1):
            row = json.loads(line)
            if (
                not line.endswith(b"\n")
                or _canonical(row) != line
                or set(row) != {"schema_version", "seq", "prev", "kind", "data"}
                or row["schema_version"] != CONTEXT_SCHEMA
                or type(row["seq"]) is not int
                or row["seq"] != sequence
                or row["prev"] != previous
            ):
                raise ValueError("context_chain_or_shape")
            data = row["data"]
            if not isinstance(data, dict):
                raise ValueError("context_data")
            if sequence == 1:
                if row["kind"] != "begin" or set(data) != {
                    "metadata",
                    "identity",
                    "anchor",
                }:
                    raise ValueError("context_begin")
                metadata, identity = data["metadata"], data["identity"]
                if (
                    not isinstance(metadata, dict)
                    or set(metadata) != set(PINS)
                    or any(
                        key not in expected or metadata[key] != expected[key]
                        for key in PINS
                    )
                    or metadata["role"] != "observer"
                ):
                    raise ValueError("context_metadata_pins")
                if (
                    not isinstance(identity, dict)
                    or set(identity)
                    != {
                        "pid",
                        "start_ticks",
                        "native_tid",
                        "boot_id",
                        "clock_domain",
                        "clock_ticks_per_second",
                        "clock_resolutions",
                    }
                    or any(
                        not _uint(identity.get(key)) or identity[key] == 0
                        for key in ("pid", "start_ticks", "native_tid")
                    )
                ):
                    raise ValueError("context_incarnation")
                _header_metadata(
                    dict(metadata, **identity, unallocated_footer_flush_overhead=True)
                )
                if any(
                    key in expected and identity.get(key) != expected[key]
                    for key in ("pid", "start_ticks", "boot_id", "clock_domain")
                ):
                    raise ValueError("external_context_identity_mismatch")
                clock._anchor(data["anchor"])
                result["begin"] = deepcopy(data)
            else:
                if (
                    row["kind"] != "end"
                    or set(data) != {"anchor", "normal_return"}
                    or data["normal_return"] is not True
                ):
                    raise ValueError("context_end")
                clock._anchor(data["anchor"])
                if (
                    result["begin"]["anchor"]["monotonic_after_ns"]
                    > data["anchor"]["monotonic_before_ns"]
                ):
                    raise ValueError("context_time_reversal")
                result.update(end=deepcopy(data), closed=True)
            previous = hashlib.sha256(line).hexdigest()
        if len(lines) > 2:
            raise ValueError("context_row_bound")
    except (
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        AttributeError,
        RecursionError,
    ):
        result.update(closed=False, error="clock_context_missing_invalid_or_incomplete")
    return result


def evaluate_clock(
    *,
    calls_raw,
    context_raw,
    expected,
    controller_start=None,
    controller_end=None,
    controller_samples=(),
    kernel_boot_id=None,
    controller_boot_id=None,
    controller_clock_domain=None,
    recording_binding=None,
):
    context = decode_clock_context(context_raw, expected=expected)
    prefix, error = None, None
    try:
        prefix = decode_calls_prefix(calls_raw)
    except (
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        AttributeError,
        RecursionError,
    ):
        error = "clock_calls_missing_invalid_or_incomplete"
    begin, end = context["begin"], context["end"]
    evidence = dict(
        kernel_boot_id=kernel_boot_id,
        observer_boot_id=begin["identity"].get("boot_id") if begin else None,
        controller_boot_id=controller_boot_id,
        observer_start=begin["anchor"] if begin else None,
        observer_end=end["anchor"] if end else None,
        controller_start=controller_start,
        controller_end=controller_end,
        recorded=dict(calls=prefix["calls"]) if prefix else None,
        controller_samples=controller_samples,
    )
    qualification = clock.qualify_clock(**evidence)
    domain = begin["identity"].get("clock_domain") if begin else None
    same_domain = (
        isinstance(domain, dict)
        and domain.get("established") is True
        and domain == controller_clock_domain
    )
    complete = (
        context["closed"]
        and context["error"] is None
        and prefix is not None
        and prefix["closed"]
        and not prefix["partial_tail"]
        and error is None
    )
    reasons = []
    binding_valid = (
        isinstance(recording_binding, dict)
        and set(recording_binding)
        == {"calls_sha256", "context_sha256", "policy_context", "scope_pins"}
        and isinstance(calls_raw, bytes)
        and isinstance(context_raw, bytes)
        and recording_binding["calls_sha256"] == hashlib.sha256(calls_raw).hexdigest()
        and recording_binding["context_sha256"]
        == hashlib.sha256(context_raw).hexdigest()
        and prefix is not None
        and recording_binding["policy_context"] == prefix["context"]
        and begin is not None
        and recording_binding["scope_pins"] == begin["metadata"]
    )
    if not binding_valid:
        reasons.append("external_recording_pair_policy_binding_unavailable")
    if not complete:
        reasons.append("complete_observer_clock_closure_unavailable")
    if not same_domain:
        reasons.append("external_common_clock_domain_unavailable")
    if qualification["status"] != "qualified":
        reasons.append("original_5ms_qualification_withheld")
    return dict(
        original_qualification=qualification,
        qualification_inputs=deepcopy(evidence),
        original_call_context=deepcopy(prefix["context"]) if prefix else None,
        recording_binding=deepcopy(recording_binding),
        external_controller_clock_domain=deepcopy(controller_clock_domain),
        eligible=complete and same_domain and not reasons,
        reasons=reasons,
        context=context,
        calls_error=error,
        calls_closed=prefix["closed"] if prefix else False,
        partial_tail_bytes=len(prefix["partial_tail"]) if prefix else None,
        observed_calls=len(prefix["calls"]) if prefix else None,
        observed_body_over_5ms=[
            r["seq"]
            for r in prefix["calls"]
            if r["data"]["end_ns"] - r["data"]["start_ns"] > clock.BUDGET_NS
        ]
        if prefix
        else None,
        observed_calls_sha256=hashlib.sha256(calls_raw).hexdigest()
        if isinstance(calls_raw, bytes)
        else None,
        measurement_completed=False,
        authorizes_transition=False,
    )


def _exit_problems(arm, observed):
    """Recheck the explicit launcher derivation, never a caller's verified flag."""
    errors = []
    proof = arm.get("exit_provenance", {})
    try:
        if (
            proof["process_role"] != "launcher"
            or proof["native_exit_basis"] != EXIT_BASIS
            or proof["native_exit_independently_waited"] is not False
            or proof["entry_source_sha256"] != ENTRY_SHA256
        ):
            raise ValueError("unbound_launcher_entry")
        launcher, native = proof["launcher"], proof["native"]
        if any(
            not _uint(item.get(key)) or item[key] == 0
            for item in (launcher, native)
            for key in ("pid", "start_ticks")
        ):
            raise ValueError("missing_incarnation")
        original_native = arm["original_cost_report"]["processes"]["native"]["final"]
        if launcher["pid"] == native["pid"] or any(
            type(original_native[key]) is not int or original_native[key] != native[key]
            for key in ("pid", "start_ticks")
        ):
            raise ValueError("native_child_process_binding")
        if (
            type(launcher["returncode"]) is not int
            or launcher["returncode"] != 0
            or launcher["exit_confirmed"] is not True
            or native["before_stop_start_ticks"] != native["start_ticks"]
            or type(native["before_stop_start_ticks"]) is not int
            or native["after_stop_disposition"] != "absent"
        ):
            raise ValueError("unverified_exit_or_native_identity")
        final, pre = (
            observed["ingress_audit_finalization"],
            observed["ingress_audit_pre_stop"],
        )
        times = (
            final["writer_joined_ns"],
            pre["read_ended_ns"],
            launcher["requested_ns"],
            launcher["exited_ns"],
            native["checked_ns"],
            final["read_started_ns"],
        )
        if not all(_uint(v) for v in times) or list(times) != sorted(times):
            raise ValueError("unverified_stop_read_order")
        stop = final["stop"]
        if (
            stop.get("process_role") != "launcher"
            or stop.get("native_exit_basis") != EXIT_BASIS
            or stop.get("native_exit_independently_waited") is not False
            or stop.get("returncode") != launcher["returncode"]
            or stop.get("requested_ns") != launcher["requested_ns"]
            or stop.get("exited_ns") != launcher["exited_ns"]
        ):
            raise ValueError("stop_adapter_mismatch")
    except (ValueError, TypeError, KeyError, AttributeError):
        errors.append("signed_launcher_exit_provenance_unverified")
    stderr = arm.get("stderr_capture", proof.get("stderr_capture", {}))
    try:
        if (
            stderr["complete"] is not True
            or stderr["joined"] is not True
            or stderr["eof"] is not True
            or stderr["error"] is not None
            or stderr["coverage"] != "mixed_launcher_native_from_start_to_EOF"
            or not _uint(stderr["bytes"])
            or stderr["bytes"] == 0
            or stderr["bytes"] > MAX_EVE_BYTES
            or stderr["sha256"] != stderr["diagnostic_sha256"]
            or stderr["bytes"] != stderr["diagnostic_bytes"]
            or not isinstance(stderr["sha256"], str)
            or not re.fullmatch("[0-9a-f]{64}", stderr["sha256"])
        ):
            raise ValueError("stderr_coverage")
        diagnostic = arm["ingress_diagnostics"]["core_stderr"]
        if (
            diagnostic.get("sha256") != stderr["sha256"]
            or diagnostic.get("bytes") != stderr["bytes"]
            or diagnostic.get("error") is not None
        ):
            raise ValueError("unbound_final_diagnostic")
        identity = stderr["file_identity"]
        if (
            not _uint(identity["device"])
            or not _uint(identity["inode"])
            or identity["inode"] == 0
        ):
            raise ValueError("stderr_identity")
    except (ValueError, TypeError, KeyError, AttributeError):
        errors.append("complete_original_mixed_stderr_unavailable")
    return errors


def _clock_ready(report):
    """Recompute the original verdict rather than trusting an imported flag."""
    try:
        original = clock.qualify_clock(**report["qualification_inputs"])
        context = report["context"]
        binding = report["recording_binding"]
        return (
            report.get("eligible") is True
            and original["status"] == "qualified"
            and _canonical(original) == _canonical(report["original_qualification"])
            and context["closed"] is True
            and context["error"] is None
            and context["end"]["normal_return"] is True
            and context["end"]["anchor"]
            == report["qualification_inputs"]["observer_end"]
            and context["begin"]["anchor"]
            == report["qualification_inputs"]["observer_start"]
            and context["begin"]["identity"]["clock_domain"].get("established") is True
            and context["begin"]["identity"]["clock_domain"]
            == report["external_controller_clock_domain"]
            and report["calls_closed"] is True
            and report["calls_error"] is None
            and type(report["partial_tail_bytes"]) is int
            and report["partial_tail_bytes"] == 0
            and binding["calls_sha256"] == report["observed_calls_sha256"]
            and binding["context_sha256"] == context["raw_sha256"]
            and binding["scope_pins"] == context["begin"]["metadata"]
            and binding["policy_context"] == report["original_call_context"]
            and report["reasons"] == []
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def _callbacks_inside_load(report, start, end):
    """Count a validated retained callback prefix; malformed siblings stay unknown."""
    try:
        begin = report["context"]["begin"]
        domain = begin["identity"]["clock_domain"]
        if (
            not isinstance(domain, dict)
            or domain.get("established") is not True
            or domain != report["external_controller_clock_domain"]
            or not _uint(start)
            or not _uint(end)
        ):
            return None
        rows = report["qualification_inputs"]["recorded"]["calls"]
        if not isinstance(rows, list) or not 0 < len(rows) <= 900:
            return None
        last, count = begin["anchor"]["monotonic_after_ns"], 0
        for seq, row in enumerate(rows, 1):
            data = row["data"]
            if (
                type(row["seq"]) is not int
                or row["seq"] != seq
                or row["kind"] not in ("sample", "event", "finalize")
                or not _uint(data["start_ns"])
                or not _uint(data["end_ns"])
            ):
                return None
            before, after = (
                clock._anchor(data["clock_before"]),
                clock._anchor(data["clock_after"]),
            )
            clock._epoch_interval(data["epoch"])
            if (
                not last
                <= before[0]
                <= before[2]
                <= data["start_ns"]
                <= data["end_ns"]
                <= after[0]
                <= after[2]
            ):
                return None
            count += start + 3_000_000_000 <= data["start_ns"] <= data["end_ns"] <= end
            last = after[2]
        return count
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return None


def analyze_arm(arm):
    """Keep declared load, final accounting, timing and functional gates separate."""
    observed, samples = arm.get("quota_load"), arm.get("marker_samples", [])
    if not isinstance(samples, list):
        samples = []
    try:
        problems = so11.quota_load_problems(samples, observed, 1.2)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        problems = {"original_so11_evaluation": ["malformed_or_missing_load_evidence"]}
    local = []
    recount = arm.get("eve_evidence", {})
    if not isinstance(observed, dict):
        observed = {}
    if recount.get("complete") is not True or recount.get(
        "written_by_class"
    ) != observed.get("written"):
        local.append("original_eve_recount_missing_or_mismatched")
    start, end = (
        observed.get("window_start_monotonic_ns"),
        observed.get("window_end_monotonic_ns"),
    )
    duration = end - start if _uint(start) and _uint(end) and end >= start else None
    if duration is None or duration < MIN_WINDOW_NS:
        local.append("minimum_actual_six_second_load_window_unavailable")
    if len(samples) != 3:
        local.append("three_marker_windows_required")
    provenance = arm.get("exit_provenance", {})
    stderr = arm.get("stderr_capture", provenance.get("stderr_capture", {}))
    local.extend(_exit_problems(arm, observed))
    original = deepcopy(arm.get("original_cost_report"))
    clock_report = deepcopy(arm.get("clock_report"))
    clock_ready = _clock_ready(clock_report)
    measured = arm.get("instrumented") is True
    load_ok = not local and all(not reasons for reasons in problems.values())
    written = observed.get("written")
    counted = (
        isinstance(written, dict)
        and set(written) == set(so11.NON_ALERT_KINDS)
        and all(_uint(v) for v in written.values())
    )
    callbacks_inside_load = _callbacks_inside_load(clock_report, start, end)
    return dict(
        schema_version="edge-hostile-phase-cost-arm/v1",
        arm_id=arm.get("arm_id"),
        original_cost_report=original,
        quota_load=deepcopy(observed),
        marker_samples=deepcopy(samples),
        eve_evidence=deepcopy(recount),
        load_prerequisites=problems,
        local_load_blockers=local,
        load_status="valid_declared_120_percent_load" if load_ok else "withheld",
        actual_written_rate_per_second=sum(written.values()) / (duration / 1e9)
        if duration and recount.get("complete") and counted
        else None,
        clock_report=clock_report,
        observed_completed_callbacks_inside_load_after_warmup=callbacks_inside_load,
        callback_window_scope="completed_retained_prefix_only_not_full_coverage",
        clock_status="qualified_sampled_anchors"
        if measured and clock_ready
        else "withheld"
        if arm.get("mode") != "off"
        else "not_exercised_observer_absent",
        phase_reports=deepcopy(arm.get("phase_reports", {})),
        phase_collection_status=arm.get("phase_collection_status"),
        functional_phase_gate=deepcopy(arm.get("functional_phase_gate")),
        hostile_process_metrics=deepcopy(arm.get("hostile_process_metrics")),
        exit_provenance=deepcopy(provenance),
        stderr_capture=deepcopy(stderr),
        whole_measurement_qualified=False,
        comparison_qualified=False,
        production_admission=False,
        authorizes_transition=False,
        qualified_safety_count=None,
    )


def analyze_run(arms):
    if not isinstance(arms, list) or [arm.get("arm_id") for arm in arms] != list(
        ARM_ORDER
    ):
        raise ValueError("exact_six_arm_order_required")
    reports = [analyze_arm(arm) for arm in arms]
    originals = [arm.get("original_cost_report", {}) for arm in arms]
    parity = (
        all(
            isinstance(r.get(key), str) and r[key]
            for r in originals
            for key in ("input_sha256", "semantic_sha256")
        )
        and len({r["input_sha256"] for r in originals}) == 1
        and len({r["semantic_sha256"] for r in originals}) == 1
    )

    def delta(left, right):
        return (
            right - left
            if all(
                type(value) in (int, float) and math.isfinite(value)
                for value in (left, right)
            )
            else None
        )

    pairs = []
    for index in (0, 2, 4):
        left, right = arms[index : index + 2]
        left_metrics, right_metrics = (
            left.get("hostile_process_metrics", {}),
            right.get("hostile_process_metrics", {}),
        )
        roles = sorted(set(left_metrics) | set(right_metrics))
        pairs.append(
            dict(
                original_arm=left["arm_id"],
                instrumented_arm=right["arm_id"],
                marker_loop_elapsed_seconds_delta=delta(
                    left["original_cost_report"].get("elapsed_seconds"),
                    right["original_cost_report"].get("elapsed_seconds"),
                ),
                full_load_process_deltas={
                    role: {
                        key: delta(
                            left_metrics.get(role, {}).get(key),
                            right_metrics.get(role, {}).get(key),
                        )
                        for key in (
                            "cpu_seconds",
                            "read_bytes_delta",
                            "write_bytes_delta",
                            "sampled_peak_rss_kib",
                        )
                    }
                    for role in roles
                },
                causal_effect_established=False,
                scope="descriptive_fixed_sequential_trial_including_instrumentation",
            )
        )
    return dict(
        schema_version="edge-hostile-phase-cost-lab/v1",
        arms=reports,
        fixed_conditions=dict(
            load_factor=1.2,
            clock_budget_ns=clock.BUDGET_NS,
            examined_min_fraction=1 - so11.EXAMINED_TOLERANCE,
            minimum_window_ns=MIN_WINDOW_NS,
        ),
        marker_semantic_parity=parity,
        paired_cost_deltas=pairs,
        all_load_gates_valid=all(
            r["load_status"] == "valid_declared_120_percent_load" for r in reports
        ),
        measurement_verdict="withheld",
        whole_measurement_qualified=False,
        comparison_qualified=False,
        production_admission=False,
        authorizes_transition=False,
        qualified_safety_count=None,
    )
