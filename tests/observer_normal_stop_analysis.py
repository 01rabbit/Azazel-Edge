"""Read-only prospective normal-end evidence; no time substitutes or admission."""

from copy import deepcopy
from dataclasses import fields
import hashlib

from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
from azazel_edge.outcome.input_control_stop import ObserverControlStop
from azazel_edge.outcome.journal import _json, _parse
from azazel_edge.benchmark.forged_input_refusal import _journal
from azazel_edge.benchmark.source_witness import _source_tips, _verify_anchors
from azazel_edge.benchmark.timing_cost_attribution import PINS, ARM_ORDER, _header_metadata, analyze_trace
from real_systemd import signed_network_clock as clock
from observer_hostile_cost_analysis import _clock_ready, evaluate_clock, decode_clock_context

SCHEMA = "edge-observer-normal-stop-completion/v1"
MAX_COMPLETION = 65536


def _need(ok, message):
    if not ok:
        raise ValueError(message)


def _same(left, right):
    return _json(left) == _json(right)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode_completion(raw):
    _need(
        type(raw) is bytes
        and 0 < len(raw) <= MAX_COMPLETION
        and raw.endswith(b"\n")
        and raw.count(b"\n") == 1,
        "bounded original completion required",
    )
    value = _parse(raw)
    _need(
        type(value) is dict and _json(value) + b"\n" == raw,
        "canonical completion required",
    )
    _need(
        set(value)
        == {
            "schema_version",
            "metadata",
            "identity",
            "policy_context",
            "control_stop",
            "api_return_anchor",
            "sidecars",
            "completion_anchor",
        }
        and value["schema_version"] == SCHEMA,
        "unknown completion schema",
    )
    return value


def verify_normal_end(
    *,
    completion_raw,
    control_context,
    original,
    sidecars,
    trust_raw,
    source_raw,
    journal_raw,
    anchors_raw,
    request_raw,
):
    """Verify finite retained evidence, not production custody or whole input coverage."""
    report = dict(
        status="withheld",
        reasons=[],
        completion=None,
        authenticated_source_closed=False,
        journal_close_verified=False,
        normal_end_verified=False,
        five_ms_status="withheld",
        published_clock_qualification=deepcopy(
            (original.get("clock_report") or {}).get("original_qualification")
        ),
        original_clock_qualification=None,
        replayed_phase_report=None,
        replayed_clock_report=None,
        sidecar_blockers=[],
        input_coverage_complete=False,
        source_producer_termination_proven=False,
        measurement_completed=False,
        comparison_qualified=False,
        authorizes_transition=False,
        production_admission=False,
        resume_authorized=False,
        qualified_safety_count=None,
    )
    stage = "completion"
    try:
        completion = decode_completion(completion_raw)
        report["completion"] = completion
        expected = control_context["expected_metadata"]
        stage = "metadata"
        _need(
            set(completion["metadata"]) == set(PINS)
            and _same(completion["metadata"], expected)
            and expected["role"] == "observer",
            "enrolled metadata differs",
        )
        identity = completion["identity"]
        _need(
            type(identity) is dict
            and set(identity)
            == {
                "pid",
                "start_ticks",
                "native_tid",
                "boot_id",
                "clock_domain",
                "clock_ticks_per_second",
                "clock_resolutions",
            },
            "identity fields differ",
        )
        _header_metadata(
            dict(expected, **identity, unallocated_footer_flush_overhead=True)
        )
        request = control_context["request_record"]
        stage = "request_and_process"
        _need(type(request_raw) is bytes and len(request_raw) <= 16384 and _json(_parse(request_raw))+b"\n" == request_raw and _same(_parse(request_raw), request), "retained Root request record differs")
        _need(
            request["schema_version"] == "edge-observer-stop-request/v1"
            and request["arm_id"] == original["arm_id"],
            "request scope differs",
        )
        sent, waited = request["requests"], request["wait_result"]
        _need(
            type(sent) is list
            and len(sent) == 1
            and sent[0]["signal"] == 15
            and type(sent[0]["signal"]) is int
            and sent[0]["delivery_time"] is None,
            "one actual SIGTERM bracket required",
        )
        initial = request["observer_initial"]
        _need(
            identity["pid"]
            != original["original_cost_report"]["processes"]["native"]["final"]["pid"],
            "observer/native identity alias",
        )
        for record in (initial, sent[0], waited):
            _need(
                all(
                    type(record[key]) is int
                    and record[key] > 0
                    and record[key] == identity[key]
                    for key in ("pid", "start_ticks")
                ),
                "observer incarnation differs",
            )
        _need(
            type(waited["returncode"]) is int
            and waited["returncode"] == 0
            and waited["view"]["disposition"] == "absent",
            "actual normal observer exit unavailable",
        )
        controller = request["controller_identity"]
        _need(
            identity["boot_id"] == controller["boot_id"]
            and _same(identity["clock_domain"], controller["clock_domain"])
            and identity["clock_domain"]["established"] is True,
            "common actual boot/domain unavailable",
        )
        before, after = (
            clock._anchor(sent[0]["before"]),
            clock._anchor(sent[0]["after"]),
        )
        api, completed, parent = map(
            clock._anchor,
            (
                completion["api_return_anchor"],
                completion["completion_anchor"],
                waited["after"],
            ),
        )
        # Sender may be descheduled after kill(2); its AFTER bracket need not
        # precede API return. Never turn that bracket into receiver delivery time.
        _need(
            before[2] <= after[0]
            and before[2]
            <= api[0]
            <= api[2]
            <= completed[0]
            <= completed[2]
            <= parent[0],
            "actual request/return/completion order differs",
        )
        _need(
            _same(completion["policy_context"], control_context["policy_context"]),
            "enrolled objective policy differs",
        )
        body = completion["control_stop"]
        stage = "control_scope"
        _need(type(body) is dict, "actual control receipt missing")
        receipt = ObserverControlStop(
            **{field.name: body[field.name] for field in fields(ObserverControlStop)}
        )
        _need(_same(receipt.to_dict(), body), "control receipt fields/types differ")
        stage = "sidecar_replay"
        mode = control_context["profile"]
        if mode == "phase_and_clock":
            try:
                _replay_sidecars(report, completion, control_context, original, sidecars, identity)
            except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError,
                    RecursionError, OSError, UnicodeError):
                report["sidecar_blockers"].append("sidecar_replay_inputs_missing_invalid_or_incomplete")
        stage = "control_scope"
        _need(type(trust_raw) is bytes and 0 < len(trust_raw) <= 65536, "bounded trust required")
        policy = TrustPolicy(_parse(trust_raw))
        _need(
            receipt.scope_ref == policy.data["scope_ref"]
            and receipt.trust_sha256 == policy.digest
            and receipt.journal_boot_id == identity["boot_id"]
            and receipt.journal_policy_sha256
            == control_context["expected_journal_policy_sha256"],
            "actual control policy/trust/boot differs",
        )
        verifier = SourceVerifier(policy)
        stage = "source_authentication"
        _need(type(source_raw) is bytes and 0 < len(source_raw) <= 2 * 1024 * 1024,
              "bounded original Source required")
        verifier.verify(source_raw)
        _need(verifier.live_state.closed, "final independent Source closure missing")
        report["authenticated_source_closed"] = True
        offset = receipt.input_offset
        _need(
            type(offset) is int
            and 0 < offset <= len(source_raw)
            and _sha(source_raw[:offset]) == receipt.input_sha256
            and source_raw[offset - 1 : offset] == b"\n",
            "retained unread cursor prefix differs",
        )
        # This actual pilot has an empty objective policy. Pending-window
        # lifecycle is tested at the runtime layer, not invented in this corpus.
        _need(
            receipt.pending_windows_before
            == receipt.pending_windows_lost
            == receipt.committed_outcomes
            == receipt.lost_before
            == receipt.lost_after
            == 0,
            "unexercised objective profile differs",
        )
        journal_lines = journal_raw.splitlines(keepends=True)
        stage = "journal_and_witness"
        _need(
            0 < len(journal_raw) <= 4 * 1024 * 1024
            and 0 < len(journal_lines) <= 4096
            and all(len(line) <= 65536 for line in journal_lines),
            "bounded original journal required",
        )
        header, last = _parse(journal_lines[0]), _parse(journal_lines[-1])
        _need(
            header["data"]["policy_sha256"] == receipt.journal_policy_sha256
            and last["kind"] == "session_close"
            and last["seq"] == receipt.journal_sequence_after
            and last["sha256"] == receipt.journal_head_after
            and len(journal_raw) == receipt.journal_bytes_after,
            "actual session-close boundary differs",
        )
        _need(type(anchors_raw) is bytes and 0 < len(anchors_raw) <= 4 * 1024 * 1024
              and anchors_raw.endswith(b"\n") and len(anchors_raw.splitlines()) <= 4096
              and all(len(line) <= 65536 for line in anchors_raw.splitlines(keepends=True)),
              "bounded original anchors required")
        tips = _source_tips(source_raw)
        anchor_last = _parse(anchors_raw.splitlines()[-1])["state"]
        _need(anchor_last["source_size"] in tips, "anchor Source prefix unavailable")
        _verify_anchors(policy, anchors_raw, tips, tips[anchor_last["source_size"]])
        _journal(
            journal_raw,
            policy,
            control_context["source_identity"],
            source_raw[:offset],
            anchors_raw,
            control_context["journal_identity"],
        )
        report["journal_close_verified"] = True
        mode = control_context["profile"]
        stage = "closed_sidecars"
        _need(not control_context.get("collection_errors"), "Root original collection failed")
        _need(
            set(completion["sidecars"]) == {"phase", "calls", "context"},
            "unknown sidecar inventory",
        )
        if mode == "stop_only":
            _need(
                all(value is None for value in completion["sidecars"].values())
                and all(value is None for value in sidecars.values()),
                "baseline invented a recording",
            )
        elif mode == "phase_and_clock":
            _need(not report["sidecar_blockers"], "closed sidecar binding differs")
            phase_report = report["replayed_phase_report"]
            clock_report = report["replayed_clock_report"]
            _need(_same(phase_report, original["phase_reports"]["observer"]),
                  "published phase report differs from original replay")
            _need(_same(clock_report, original["clock_report"]),
                  "published clock report differs from original replay")
            _need(phase_report["normal_return_confirmed"] is True
                  and phase_report["reasons"] == []
                  and _same(phase_report["header"]["clock_domain"], identity["clock_domain"]),
                  "phase close not confirmed")
            context = clock_report["context"]
            _need(context["closed"] is True and context["error"] is None
                  and clock_report["calls_closed"] is True
                  and clock_report["calls_error"] is None
                  and clock_report["partial_tail_bytes"] == 0
                  and _same(context["begin"]["identity"], identity),
                  "original clock sidecar closure unavailable")
            end = clock._anchor(context["end"]["anchor"])
            _need(
                api[2] <= end[0] <= end[2] <= completed[0],
                "observer end anchor is not actual post-return work",
            )
            # Original sampled consistency may legitimately withhold even though
            # genuine normal closure is now available. Never drop a slow row.
            report["five_ms_status"] = (
                "qualified_sampled_anchors"
                if _clock_ready(clock_report)
                else "withheld"
            )
        else:
            raise ValueError("unknown explicit stop profile")
        report.update(status="verified_normal_control_stop", normal_end_verified=True)
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        IndexError,
        OverflowError,
        RecursionError,
        OSError,
        UnicodeError,
    ):
        report["reasons"].append(stage+"_evidence_missing_invalid_or_incomplete")
    return report


def _replay_sidecars(report, completion, control, original, sidecars, identity):
    """Derive fresh reports from bound original bytes, preserving independent facts."""
    _need(type(completion["sidecars"]) is dict
          and set(completion["sidecars"]) == {"phase", "calls", "context"}, "sidecar inventory")
    trusted = {}
    for name in ("phase", "calls", "context"):
        raw, descriptor = sidecars.get(name), completion["sidecars"][name]
        maximum = 16384 if name == "context" else 4 * 1024 * 1024
        valid = (type(raw) is bytes and len(raw) <= maximum
                 and type(descriptor) is dict and set(descriptor) == {"sha256", "bytes"}
                 and type(descriptor["bytes"]) is int and descriptor["bytes"] == len(raw)
                 and descriptor["sha256"] == _sha(raw))
        trusted[name] = raw if valid else None
        if not valid:
            report["sidecar_blockers"].append(name + "_original_missing_invalid_or_unbound")
    expected = dict(control["expected_metadata"], pid=identity["pid"],
                    start_ticks=identity["start_ticks"], boot_id=identity["boot_id"])
    report["replayed_phase_report"] = analyze_trace(trusted["phase"], expected=expected)
    anchors = original["clock_context"]
    _need(type(anchors) is dict and set(anchors) == {
        "controller_start", "controller_end", "controller_boot_id"}, "controller anchor fields")
    start, end = map(clock._anchor, (anchors["controller_start"], anchors["controller_end"]))
    request = control["request_record"]
    sent = clock._anchor(request["requests"][0]["before"])
    waited = clock._anchor(request["wait_result"]["after"])
    _need(start[2] <= sent[0] and waited[2] <= end[0]
          and anchors["controller_boot_id"] == request["controller_identity"]["boot_id"]
          == identity["boot_id"], "controller anchor enclosure differs")
    binding = dict(calls_sha256=_sha(trusted["calls"]) if trusted["calls"] is not None else None,
                   context_sha256=_sha(trusted["context"]) if trusted["context"] is not None else None,
                   policy_context=deepcopy(control["policy_context"]),
                   scope_pins=deepcopy(control["expected_metadata"]))
    report["replayed_clock_report"] = evaluate_clock(
        calls_raw=trusted["calls"], context_raw=trusted["context"], expected=expected,
        controller_start=anchors["controller_start"], controller_end=anchors["controller_end"],
        kernel_boot_id=identity["boot_id"], controller_boot_id=anchors["controller_boot_id"],
        controller_clock_domain=request["controller_identity"]["clock_domain"],
        recording_binding=binding,
    )
    report["original_clock_qualification"] = deepcopy(
        report["replayed_clock_report"]["original_qualification"])


def _read(descriptor, maximum):
    from run_observer_hostile_cost import read_original

    if descriptor is None:
        return None
    raw = read_original(descriptor["path"], maximum)
    _need(
        type(raw) is bytes and len(raw) <= maximum
        and type(descriptor["bytes"]) is int
        and len(raw) == descriptor["bytes"]
        and _sha(raw) == descriptor["sha256"],
        "Root retained original changed",
    )
    return raw


def evaluate_run(load_result):
    """Per-arm failures preserve all prior/sibling evaluations and original input."""
    rows = []
    for original in load_result["original_arm_inputs"]:
        arm_id = original.get("arm_id")
        failures = []

        def read(name, descriptor, maximum):
            try:
                return _read(descriptor, maximum)
            except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, UnicodeError):
                failures.append(name + "_read_failed_or_changed")
                return None

        try:
            mode, control = original["mode"], original["normal_stop"]
            if mode == "off":
                rows.append(dict(arm_id=arm_id, status="not_exercised_observer_absent",
                                 five_ms_status="not_exercised", normal_end_verified=False))
                continue
            completion = read("completion", control["artifacts"].get("completion"), MAX_COMPLETION)
            if mode == "faulted":
                context = None
                if original["instrumented"]:
                    raw = read("context", original["clock_artifacts"].get("context"), 16384)
                    context = decode_clock_context(raw, expected=control["expected_metadata"])
                valid = (completion is None and not failures
                         and original["original_cost_report"]["observer_exit"] == -9
                         and original["original_cost_report"]["observer_input_records"] == 3
                         and original["original_cost_report"]["observer_unprocessed_decisions"] == 2
                         and (context is None or context["begin"] is not None
                              and context["end"] is None and context["error"] is None))
                rows.append(dict(arm_id=arm_id, status="expected_uncatchable_fault_prefix" if valid else "withheld",
                                 five_ms_status="withheld", normal_end_verified=False,
                                 artifact_read_failures=failures, replayed_fault_context=context))
                continue
            sidecars = dict(phase=None, calls=None, context=None)
            if original["instrumented"]:
                sidecars["phase"] = read("phase", original["phase_artifacts"].get("observer"), 4 * 1024 * 1024)
                for key in ("calls", "context"):
                    sidecars[key] = read(key, original["clock_artifacts"].get(key),
                                         16384 if key == "context" else 4 * 1024 * 1024)
            raw = original["raw_artifacts"]
            values = dict(
                trust_raw=read("trust", raw.get("trust"), 65536),
                source_raw=read("source", raw.get("source"), 2 * 1024 * 1024),
                journal_raw=read("journal", control["artifacts"].get("journal"), 4 * 1024 * 1024),
                anchors_raw=read("anchors", control["artifacts"].get("anchors"), 4 * 1024 * 1024),
                request_raw=read("request", control["artifacts"].get("request"), 16384),
            )
            result = verify_normal_end(completion_raw=completion, control_context=control,
                                       original=original, sidecars=sidecars, **values)
            if failures:
                result.update(status="withheld", normal_end_verified=False, five_ms_status="withheld")
                result["reasons"].extend(failures)
            rows.append(dict(arm_id=arm_id, artifact_read_failures=failures, **result))
        except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError, UnicodeError):
            rows.append(dict(arm_id=arm_id, status="withheld", normal_end_verified=False,
                             five_ms_status="withheld", artifact_read_failures=failures,
                             reasons=["arm_originals_missing_invalid_or_incomplete"]))
    on = next((row for row in rows if row["arm_id"] == "instrumented_on"), {})
    on_rows = [row for row in rows if row["arm_id"] in ("original_on", "instrumented_on")]
    return dict(
        schema_version="edge-observer-normal-stop-clock-lab/v1",
        original_load_evaluation=load_result,
        normal_end_evaluations=rows,
        both_on_stops_verified=(len(on_rows) == 2
                                and {row["arm_id"] for row in on_rows} == {"original_on", "instrumented_on"}
                                and all(row["normal_end_verified"] for row in on_rows)),
        instrumented_on_five_ms_status=on.get("five_ms_status", "withheld"),
        arm_order_valid=[row["arm_id"] for row in rows] == list(ARM_ORDER),
        scope="prospective_normal_on_sampled_clock_not_whole_system",
        whole_measurement_qualified=False, comparison_qualified=False,
        authorizes_transition=False, production_admission=False, resume_authorized=False,
        qualified_safety_count=None,
    )
