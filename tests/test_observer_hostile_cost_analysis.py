"""Synthetic parser/threshold/lifecycle data, never a real load observation."""

from copy import deepcopy
import hashlib

import pytest

import observer_hostile_cost_analysis as analysis
from azazel_edge.service_objectives import so11_quota_load as so11
from real_systemd.signed_network_recording import CallRecording
from test_service_objectives_so11_v1 import _obs, _summary, WIN0
from test_signed_network_clock import evidence

MARKERS = [
    b'{"SYNTHETIC_MARKER":1}\n',
    b'{"SYNTHETIC_MARKER":2}\n',
    b'{"SYNTHETIC_MARKER":3}\n',
]
PREFIX = b'{"event_type":"stats"}\n'
META = dict(
    run_id="synthetic",
    arm="instrumented_on",
    role="observer",
    input_sha256="1" * 64,
    code_sha256="2" * 64,
    core_sha256="3" * 64,
    interpreter_sha256="4" * 64,
)
DOMAIN = dict(
    time_namespace_device=1,
    time_namespace_inode=2,
    established=True,
    timens_offsets=[
        dict(clock=name, seconds=0, nanoseconds=0) for name in ("monotonic", "boottime")
    ],
)


def eve():
    return (
        PREFIX
        + b"".join(so11._line(kind, 0) for kind in so11.NON_ALERT_KINDS)
        + b"".join(MARKERS)
    )


def test_recount_exact_writer_bytes_not_attempted_counts_and_no_prefix_denominator():
    result = analysis.recount_eve(eve(), prefix=PREFIX, marker_lines=MARKERS)
    assert result["complete"]
    assert result["written_by_class"] == dict.fromkeys(so11.NON_ALERT_KINDS, 1)
    assert result["marker_count"] == 3


@pytest.mark.parametrize(
    "fault",
    [
        "partial",
        "marker_missing",
        "marker_duplicate",
        "marker_order",
        "nonalert_duplicate",
        "prefix",
        "overbound",
        "extra_field",
    ],
)
def test_recount_rejects_invalid_originals_without_backfill(fault):
    raw, prefix = eve(), PREFIX
    if fault == "partial":
        raw = raw[:-1]
    elif fault == "marker_missing":
        raw = raw.replace(MARKERS[2], b"")
    elif fault == "marker_duplicate":
        raw += MARKERS[1]
    elif fault == "marker_order":
        raw = raw.replace(b"".join(MARKERS), b"".join(MARKERS[::-1]))
    elif fault == "nonalert_duplicate":
        raw += so11._line("flow", 0)
    elif fault == "prefix":
        prefix = b"wrong\n"
    elif fault == "overbound":
        raw = b"x" * (analysis.MAX_EVE_BYTES + 1)
    else:
        raw = raw.replace(b'"flow":{"n":0}', b'"flow":{"n":0,"extra":1}')
    result = analysis.recount_eve(raw, prefix=prefix, marker_lines=MARKERS)
    assert result["complete"] is False
    assert result["error"]


def clock_bytes(tmp_path, *, closed=True, slow=False):
    value = evidence()
    if slow:
        value["recorded"]["calls"][0]["data"]["epoch"] -= 0.010
    data = dict(value["recorded"]["calls"][0]["data"], sample=None)
    path = tmp_path / "calls"
    recorder = CallRecording(
        path,
        metadata=dict(
            policy_sha256="a" * 64, policy_source_ref="synthetic", policy_ref="b" * 64
        ),
    )
    recorder.append("sample", data)
    recorder.close(complete=closed)
    identity = dict(
        pid=123,
        start_ticks=456,
        native_tid=123,
        boot_id=value["kernel_boot_id"],
        clock_domain=DOMAIN,
        clock_ticks_per_second=100,
        clock_resolutions=dict.fromkeys(
            ("monotonic", "process_time", "thread_time"), 1e-9
        ),
    )
    rows = [
        (
            "begin",
            dict(metadata=META, identity=identity, anchor=value["observer_start"]),
        )
    ]
    if closed:
        rows.append(("end", dict(anchor=value["observer_end"], normal_return=True)))
    raw, previous = b"", "0" * 64
    for seq, (kind, body) in enumerate(rows, 1):
        line = analysis._canonical(
            dict(
                schema_version=analysis.CONTEXT_SCHEMA,
                seq=seq,
                prev=previous,
                kind=kind,
                data=body,
            )
        )
        raw += line
        previous = hashlib.sha256(line).hexdigest()
    return value, path.read_bytes(), raw


def evaluate(value, calls, context, *, domain=DOMAIN, expected=META):
    return analysis.evaluate_clock(
        calls_raw=calls,
        context_raw=context,
        expected=expected,
        controller_start=value["controller_start"],
        controller_end=value["controller_end"],
        kernel_boot_id=value["kernel_boot_id"],
        controller_boot_id=value["controller_boot_id"],
        controller_clock_domain=domain,
        recording_binding=dict(
            calls_sha256=hashlib.sha256(calls).hexdigest(),
            context_sha256=hashlib.sha256(context).hexdigest()
            if isinstance(context, bytes)
            else None,
            scope_pins=META,
            policy_context=dict(
                policy_sha256="a" * 64,
                policy_source_ref="synthetic",
                policy_ref="b" * 64,
            ),
        ),
    )


def test_original_5ms_result_preserved_without_phase_body_substitution(tmp_path):
    value, calls, context = clock_bytes(tmp_path, slow=True)
    result = evaluate(value, calls, context)
    assert result["original_qualification"] == analysis.clock.qualify_clock(**value)
    assert result["original_qualification"]["status"] == "withheld"
    assert result["observed_body_over_5ms"] == []  # Earlier supplied epoch still fails.
    assert result["eligible"] is False


def test_valid_synthetic_clock_is_only_sampled_consistency(tmp_path):
    value, calls, context = clock_bytes(tmp_path)
    result = evaluate(value, calls, context)
    assert result["eligible"] is True
    assert result["original_qualification"] == analysis.clock.qualify_clock(**value)
    assert result["measurement_completed"] is False


@pytest.mark.parametrize(
    "fault", ["open", "missing", "tail", "bad_chain", "wrong_pid", "wrong_domain"]
)
def test_clock_loss_retains_unknown_not_pass(tmp_path, fault):
    value, calls, context = clock_bytes(tmp_path, closed=fault != "open")
    expected, domain = dict(META), DOMAIN
    if fault == "missing":
        context = None
    elif fault == "tail":
        context += b"{"
    elif fault == "bad_chain":
        context = context.replace(b'"seq":2', b'"seq":3')
    elif fault == "wrong_pid":
        expected["pid"] = 124
    elif fault == "wrong_domain":
        domain = {**DOMAIN, "time_namespace_inode": 99}
    result = evaluate(value, calls, context, expected=expected, domain=domain)
    assert not result["eligible"]
    assert result["reasons"]
    if fault in ("open", "tail"):
        assert result["observed_calls"] == 1


def arm():
    observed = _obs(1.2, seconds=6)
    final = observed["ingress_audit_finalization"]
    end = observed["window_end_monotonic_ns"]
    final["stop"].update(
        process_role="launcher",
        native_exit_basis=analysis.EXIT_BASIS,
        native_exit_independently_waited=False,
    )
    stderr = dict(
        complete=True,
        joined=True,
        eof=True,
        error=None,
        bytes=50,
        sha256="a" * 64,
        diagnostic_sha256="a" * 64,
        diagnostic_bytes=50,
        coverage="mixed_launcher_native_from_start_to_EOF",
        file_identity=dict(device=1, inode=3),
    )
    proof = dict(
        process_role="launcher",
        native_exit_basis=analysis.EXIT_BASIS,
        native_exit_independently_waited=False,
        entry_source_sha256=analysis.ENTRY_SHA256,
        launcher=dict(
            pid=100,
            start_ticks=123,
            requested_ns=end + 4,
            exited_ns=end + 5,
            returncode=0,
            exit_confirmed=True,
        ),
        native=dict(
            pid=101,
            start_ticks=124,
            before_stop_start_ticks=124,
            after_stop_disposition="absent",
            checked_ns=end + 6,
        ),
    )
    return dict(
        arm_id="instrumented_on",
        mode="on",
        instrumented=True,
        quota_load=observed,
        marker_samples=[
            dict(
                start_monotonic_ns=WIN0 + 3_100_000_000 + i * 100_000_000,
                end_monotonic_ns=WIN0 + 3_150_000_000 + i * 100_000_000,
            )
            for i in range(3)
        ],
        eve_evidence=dict(
            complete=True, written_by_class=deepcopy(observed["written"])
        ),
        exit_provenance=proof,
        stderr_capture=stderr,
        ingress_diagnostics=dict(
            core_stderr=dict(sha256="a" * 64, bytes=50, error=None)
        ),
        original_cost_report=dict(
            input_sha256="a" * 64,
            semantic_sha256="b" * 64,
            processes=dict(native=dict(final=dict(pid=101, start_ticks=124))),
        ),
        clock_report=None,
    )


def test_valid_load_does_not_complete_missing_clock_or_global_measurement():
    value = arm()
    before = deepcopy(value)
    report = analysis.analyze_arm(value)
    assert report["load_status"] == "valid_declared_120_percent_load"
    assert report["clock_status"] == "withheld"
    assert report["whole_measurement_qualified"] is False
    assert report["qualified_safety_count"] is None
    assert value == before


@pytest.mark.parametrize(
    "fault",
    [
        "rate",
        "class_missing",
        "writer_error",
        "short",
        "sample_early",
        "recount",
        "stderr_lost",
        "stderr_suffix",
        "stderr_hash",
        "native_reused",
        "native_gone_only",
        "wrong_entry",
        "stop_before_join",
        "nonzero",
        "bool_exit",
    ],
)
def test_load_and_exit_unknowns_block_despite_success_flags(fault):
    value = arm()
    obs, proof = value["quota_load"], value["exit_provenance"]
    proof["verified"] = True  # This untrusted assertion never replaces evidence.
    if fault == "rate":
        obs["written"] = dict.fromkeys(so11.NON_ALERT_KINDS, 3750)
        value["eve_evidence"]["written_by_class"] = deepcopy(obs["written"])
    elif fault == "class_missing":
        del obs["written"]["http"]
    elif fault == "writer_error":
        obs["writer_error"] = "synthetic write loss"
    elif fault == "short":
        obs["window_end_monotonic_ns"] = (
            obs["window_start_monotonic_ns"] + 2_000_000_000
        )
    elif fault == "sample_early":
        value["marker_samples"][0]["start_monotonic_ns"] = WIN0 + 1
    elif fault == "recount":
        value["eve_evidence"]["complete"] = False
    elif fault == "stderr_lost":
        value["stderr_capture"]["complete"] = False
    elif fault == "stderr_suffix":
        value["stderr_capture"]["coverage"] = "suffix_only"
    elif fault == "stderr_hash":
        value["stderr_capture"]["diagnostic_sha256"] = "c" * 64
    elif fault == "native_reused":
        proof["native"]["after_stop_disposition"] = "different_incarnation"
    elif fault == "native_gone_only":
        proof["native_exit_basis"] = "pid_absence"
    elif fault == "wrong_entry":
        proof["entry_source_sha256"] = "d" * 64
    elif fault == "stop_before_join":
        proof["launcher"]["requested_ns"] = 0
    elif fault == "nonzero":
        proof["launcher"]["returncode"] = 1
    else:
        proof["launcher"]["returncode"] = False
    result = analysis.analyze_arm(value)
    assert result["load_status"] == "withheld"
    assert result["whole_measurement_qualified"] is False


@pytest.mark.parametrize("examined,expected", [(17640, True), (17639, False)])
def test_original_98_percent_floor_is_unchanged(examined, expected):
    value = arm()
    obs = value["quota_load"]
    rows = [_summary(100, 100, examined=examined)]
    raw = b"".join(analysis._canonical(row) for row in rows)
    obs.update(ingress_audit=rows, ingress_audit_records_read=1)
    obs["ingress_audit_pre_stop"].update(
        disposition="observed_absent",
        records=None,
        records_read=None,
        raw_bytes=None,
        raw_sha256=None,
        raw_utf8=None,
        file_identity=None,
    )
    obs["ingress_audit_finalization"].update(
        raw_utf8=raw.decode(),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_bytes=len(raw),
        pre_stop_binding="created_after_observed_absence",
    )
    report = analysis.analyze_arm(value)
    assert (report["load_status"] == "valid_declared_120_percent_load") is expected


@pytest.mark.parametrize(
    "fault",
    [
        "flag_only",
        "withheld",
        "inputs_missing",
        "closure_missing",
        "wrong_policy",
        "unbound_calls",
        "wrong_scope",
    ],
)
def test_imported_eligible_flag_never_overrides_original_or_pairing(tmp_path, fault):
    value, calls, context = clock_bytes(tmp_path)
    report = evaluate(value, calls, context)
    if fault == "flag_only":
        report = dict(eligible=True)
    elif fault == "withheld":
        report["qualification_inputs"]["observer_end"] = None
    elif fault == "inputs_missing":
        del report["qualification_inputs"]
    elif fault == "closure_missing":
        report["context"]["closed"] = False
    elif fault == "wrong_policy":
        report["recording_binding"]["policy_context"]["policy_sha256"] = "0" * 64
    elif fault == "unbound_calls":
        report["recording_binding"]["calls_sha256"] = "0" * 64
    elif fault == "wrong_scope":
        report["recording_binding"]["scope_pins"]["run_id"] = "other-synthetic"
    report["eligible"] = True
    data = arm()
    data["clock_report"] = report
    assert analysis.analyze_arm(data)["clock_status"] == "withheld"


def test_missing_originals_never_report_zero_input_counts():
    report = analysis.recount_eve(None, prefix=PREFIX, marker_lines=MARKERS)
    assert report["written_by_class"] is None
    assert report["observed_prefix_counts"] is None
    assert report["marker_count"] is None


def test_later_context_tail_retains_begin_but_withholds(tmp_path):
    value, calls, context = clock_bytes(tmp_path)
    result = evaluate(value, calls, context + b"{broken")
    assert result["context"]["begin"] is not None
    assert result["context"]["closed"] is False
    assert result["eligible"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "same_pid",
        "native_sample_mismatch",
        "stderr_diagnostic_mismatch",
        "stderr_invalid_hash",
    ],
)
def test_exit_evidence_consistency_negatives(fault):
    data = arm()
    if fault == "same_pid":
        data["exit_provenance"]["launcher"]["pid"] = 101
    elif fault == "native_sample_mismatch":
        data["original_cost_report"]["processes"]["native"]["final"]["start_ticks"] = (
            125
        )
    elif fault == "stderr_diagnostic_mismatch":
        data["ingress_diagnostics"]["core_stderr"]["sha256"] = "0" * 64
    else:
        data["stderr_capture"]["sha256"] = "not-a-hash"
    assert analysis.analyze_arm(data)["load_status"] == "withheld"


def test_malformed_clock_sibling_cannot_erase_valid_load(tmp_path):
    value, calls, context = clock_bytes(tmp_path)
    report = evaluate(value, calls, context)
    report["qualification_inputs"]["recorded"]["calls"] = [{}]
    data = arm()
    data["clock_report"] = report
    result = analysis.analyze_arm(data)
    assert result["load_status"] == "valid_declared_120_percent_load"
    assert result["clock_status"] == "withheld"
    assert result["observed_completed_callbacks_inside_load_after_warmup"] is None
