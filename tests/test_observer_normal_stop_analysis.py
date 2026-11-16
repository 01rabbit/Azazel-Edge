"""SYNTHETIC lifecycle/clock assertions with real original Source/anchor signatures."""

from copy import deepcopy
import json

import pytest

import observer_normal_stop_analysis as a
from observer_hostile_cost_analysis import evaluate_clock
from azazel_edge.outcome.input_control_stop import ObserverControlStop
from azazel_edge.outcome.journal import _json
from azazel_edge.benchmark.timing_cost_attribution import analyze_trace
from safety_observation_data import wire, digest
from source_witness_data import sign_anchors
import test_forged_input_refusal as forged
from test_observer_hostile_cost_analysis import clock_bytes, DOMAIN, META
from test_signed_network_clock import anchor
from test_timing_cost_attribution import trace, encode


def fixture(tmp_path, *, profile="phase_and_clock", slow=False):
    signed = forged.build(tmp_path / "signed", closed_prefix=True)
    source = signed["source"]["valid_source"]
    policy = signed["source"]["trust"]
    value, calls, context = clock_bytes(tmp_path, slow=slow)
    boot = value["kernel_boot_id"]
    context_rows = [json.loads(line) for line in context.splitlines()]
    identity = context_rows[0]["data"]["identity"]
    metadata = dict(META)
    if profile == "stop_only":
        metadata["arm"] = "original_on"
    journal_rows = deepcopy(signed["rows"])
    journal_rows[0]["data"]["policy_sha256"] = "c" * 64
    for row in journal_rows:
        if row["kind"] in ("session_open", "session_close"):
            row["data"]["boot_id"] = boot
    journals, head, journal = [(0, "0" * 64, 0, digest(b""))], "0" * 64, b""
    for row in journal_rows:
        core = dict(seq=row["seq"], prev=head, kind=row["kind"], data=row["data"])
        head = digest(_json(core))
        journal += wire(dict(core, sha256=head))
        journals.append((row["seq"], head, len(journal), digest(journal)))
    anchors = [json.loads(line) for line in signed["before"]["anchors"].splitlines()]
    for row, (seq, head_at, size, sha) in zip(anchors, journals):
        row["state"].update(journal_seq=seq, journal_head=head_at, journal_size=size, journal_sha256=sha)
    anchors_raw = sign_anchors(anchors)
    receipt = ObserverControlStop(
        scope_ref=policy.data["scope_ref"], trust_sha256=policy.digest,
        journal_policy_sha256="c" * 64, journal_boot_id=boot,
        input_offset=len(source), input_sha256=digest(source),
        journal_sequence_before=4, journal_sequence_after=5,
        journal_head_after=head, journal_bytes_after=len(journal),
        pending_windows_before=0, pending_windows_lost=0,
        committed_outcomes=0, lost_before=0, lost_after=0,
    )
    phase_rows = trace(elapsed=100_000)
    phase_rows[0][1].update(metadata, **identity)
    phase_raw = encode(phase_rows)
    expected = dict(metadata, pid=identity["pid"], start_ticks=identity["start_ticks"], boot_id=boot)
    clock_context = dict(controller_start=anchor(0), controller_end=anchor(30_000_000), controller_boot_id=boot)
    policy_context = dict(policy_sha256="a" * 64, policy_source_ref="synthetic", policy_ref="b" * 64)
    raw_sidecars = dict(phase=phase_raw, calls=calls, context=context)
    request = dict(schema_version="edge-observer-stop-request/v1", arm_id=metadata["arm"],
                   observer_initial=dict(pid=123, start_ticks=456),
                   requests=[dict(signal=15, pid=123, start_ticks=456, before=anchor(18_000_000),
                                  after=anchor(18_100_000), delivery_time=None)],
                   wait_result=dict(pid=123, start_ticks=456, returncode=0,
                                    after=anchor(22_000_000), view=dict(disposition="absent")),
                   controller_identity=dict(identity, pid=999, native_tid=999))
    replayed_clock = evaluate_clock(
        calls_raw=calls, context_raw=context, expected=expected,
        controller_start=clock_context["controller_start"], controller_end=clock_context["controller_end"],
        kernel_boot_id=boot, controller_boot_id=boot, controller_clock_domain=DOMAIN,
        recording_binding=dict(calls_sha256=digest(calls), context_sha256=digest(context),
                               policy_context=policy_context, scope_pins=metadata),
    )
    original = dict(arm_id=metadata["arm"], mode="on", instrumented=profile == "phase_and_clock",
                    original_cost_report=dict(processes=dict(native=dict(final=dict(pid=777)))),
                    phase_reports=dict(observer=analyze_trace(phase_raw, expected=expected)),
                    clock_report=replayed_clock, clock_context=clock_context)
    completion = dict(schema_version=a.SCHEMA, metadata=metadata, identity=identity,
                      policy_context=policy_context, control_stop=receipt.to_dict(),
                      api_return_anchor=anchor(19_000_000), completion_anchor=anchor(21_000_000),
                      sidecars={name: dict(sha256=digest(raw), bytes=len(raw)) for name, raw in raw_sidecars.items()})
    if profile == "stop_only":
        completion["sidecars"] = raw_sidecars = dict(phase=None, calls=None, context=None)
    control = dict(expected_metadata=metadata, request_record=request,
                   policy_context=policy_context, profile=profile,
                   expected_journal_policy_sha256="c" * 64,
                   source_identity=dict(device=2, inode=3, uid=61001),
                   journal_identity=dict(device=2, inode=4, uid=61002), collection_errors={})
    return dict(completion_raw=wire(completion), control_context=control, original=original,
                sidecars=raw_sidecars, trust_raw=signed["source"]["trust_raw"], source_raw=source,
                journal_raw=journal, anchors_raw=anchors_raw, request_raw=wire(request))


def test_real_signed_originals_and_replayed_sidecars_qualify_only_sampled_clock(tmp_path):
    value = fixture(tmp_path)
    before = deepcopy(value)
    report = a.verify_normal_end(**value)
    assert report["status"] == "verified_normal_control_stop", report["reasons"]
    assert report["authenticated_source_closed"] is report["journal_close_verified"] is True
    assert report["five_ms_status"] == "qualified_sampled_anchors"
    assert report["replayed_clock_report"] == value["original"]["clock_report"]
    assert report["replayed_phase_report"] == value["original"]["phase_reports"]["observer"]
    assert value == before
    assert report["measurement_completed"] is report["comparison_qualified"] is False
    assert report["input_coverage_complete"] is False


def test_baseline_has_real_close_but_no_clock(tmp_path):
    report = a.verify_normal_end(**fixture(tmp_path, profile="stop_only"))
    assert report["normal_end_verified"] is True, report["reasons"]
    assert report["five_ms_status"] == "withheld"
    assert report["replayed_clock_report"] is None


@pytest.mark.parametrize("which", ["phase", "clock", "raw_clock", "raw_phase"])
def test_published_summaries_cannot_replace_original_replay(tmp_path, which):
    value = fixture(tmp_path)
    if which == "phase":
        value["original"]["phase_reports"]["observer"]["status"] = "forged"
    elif which == "clock":
        value["original"]["clock_report"]["eligible"] = False
    else:
        name = "calls" if which == "raw_clock" else "phase"
        value["sidecars"][name] += b" "
    report = a.verify_normal_end(**value)
    assert report["normal_end_verified"] is False
    assert report["five_ms_status"] == "withheld"
    assert report["authenticated_source_closed"] is report["journal_close_verified"] is True
    assert report["replayed_phase_report"] is not None
    assert report["replayed_clock_report"] is not None


def test_genuine_normal_close_does_not_relax_original_slow_clock(tmp_path):
    report = a.verify_normal_end(**fixture(tmp_path, slow=True))
    assert report["normal_end_verified"] is True, report["reasons"]
    assert report["five_ms_status"] == "withheld"
    assert report["original_clock_qualification"]["status"] == "withheld"


def test_forged_empty_profile_historical_loss_counters_cannot_pass(tmp_path):
    value = fixture(tmp_path)
    completion = json.loads(value["completion_raw"])
    completion["control_stop"].update(lost_before=999, lost_after=999)
    value["completion_raw"] = wire(completion)
    report = a.verify_normal_end(**value)
    assert report["normal_end_verified"] is False
    assert report["five_ms_status"] == "withheld"


@pytest.mark.parametrize("where", ["controller_start", "controller_end", "request_before", "api", "completed"])
def test_invalid_or_unenclosed_anchor_withholds_without_losing_valid_replays(tmp_path, where):
    value = fixture(tmp_path)
    if where in ("controller_start", "controller_end"):
        value["original"]["clock_context"][where]["monotonic_before_ns"] = True
    elif where == "request_before":
        value["control_context"]["request_record"]["requests"][0]["before"]["epoch_ns"] = 2**63
        value["request_raw"] = wire(value["control_context"]["request_record"])
    else:
        completion = json.loads(value["completion_raw"])
        key = "api_return_anchor" if where == "api" else "completion_anchor"
        completion[key]["monotonic_after_ns"] = -1
        value["completion_raw"] = wire(completion)
    report = a.verify_normal_end(**value)
    assert report["normal_end_verified"] is False
    assert report["five_ms_status"] == "withheld"


def test_independent_known_facts_survive_missing_clock_and_collection_error(tmp_path):
    value = fixture(tmp_path)
    value["sidecars"]["calls"] = None
    value["control_context"]["collection_errors"] = {"unrelated": "SYNTHETIC read failure"}
    report = a.verify_normal_end(**value)
    assert report["authenticated_source_closed"] is report["journal_close_verified"] is True
    assert report["replayed_phase_report"]["normal_return_confirmed"] is True
    assert report["normal_end_verified"] is False


def test_source_signature_is_verified_without_bypass_and_sidecar_facts_survive(tmp_path):
    value = fixture(tmp_path)
    value["source_raw"] = value["source_raw"].replace(b'"signature":"', b'"signature":"0', 1)
    report = a.verify_normal_end(**value)
    assert report["authenticated_source_closed"] is False
    assert report["normal_end_verified"] is False
    assert report["replayed_phase_report"]["normal_return_confirmed"] is True


def test_completion_exact_counter_type_is_required(tmp_path):
    value = fixture(tmp_path)
    completion = json.loads(value["completion_raw"])
    completion["control_stop"]["committed_outcomes"] = False
    value["completion_raw"] = wire(completion)
    assert a.verify_normal_end(**value)["normal_end_verified"] is False


def staged(tmp_path, value):
    original = deepcopy(value["original"])
    control = deepcopy(value["control_context"])
    paths = {}

    def write(name, raw):
        if raw is None:
            return None
        path = tmp_path / name
        path.write_bytes(raw)
        paths[name] = path
        return dict(path=str(path), sha256=digest(raw), bytes=len(raw), max_bytes=len(raw))

    original["raw_artifacts"] = {name: write(name, value[name + "_raw"]) for name in ("trust", "source")}
    control["artifacts"] = {name: write(name, value[name + "_raw"]) for name in ("completion", "journal", "anchors", "request")}
    original["phase_artifacts"] = dict(observer=write("phase", value["sidecars"]["phase"]))
    original["clock_artifacts"] = {name: write(name, value["sidecars"][name]) for name in ("calls", "context")}
    original["normal_stop"] = control
    return original, paths


def test_one_original_read_failure_preserves_prior_and_sibling_evidence(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    value = fixture(first)
    valid, _ = staged(first, value)
    failed, paths = staged(second, value)
    paths["calls"].unlink()
    original = dict(original_arm_inputs=[valid, failed, deepcopy(valid)])
    before = deepcopy(original)
    report = a.evaluate_run(original)
    rows = report["normal_end_evaluations"]
    assert rows[0]["normal_end_verified"] is rows[2]["normal_end_verified"] is True
    assert rows[1]["normal_end_verified"] is False
    assert rows[1]["artifact_read_failures"] == ["calls_read_failed_or_changed"]
    assert rows[1]["authenticated_source_closed"] is rows[1]["journal_close_verified"] is True
    assert rows[1]["replayed_phase_report"]["normal_return_confirmed"] is True
    assert original == before
    assert report["both_on_stops_verified"] is False


def test_missing_on_arms_never_vacuously_verifies_both():
    report = a.evaluate_run(dict(original_arm_inputs=[]))
    assert report["both_on_stops_verified"] is False
    assert report["instrumented_on_five_ms_status"] == "withheld"
    assert report["arm_order_valid"] is False


@pytest.mark.parametrize("declared", [9, True])
def test_read_rejects_overbound_sentinel_and_bool_descriptor(monkeypatch, declared):
    import run_observer_hostile_cost

    raw = b"x" * 9
    monkeypatch.setattr(run_observer_hostile_cost, "read_original", lambda *args: raw)
    descriptor = dict(path="/synthetic", bytes=declared, sha256=digest(raw))
    with pytest.raises(ValueError):
        a._read(descriptor, 8)
