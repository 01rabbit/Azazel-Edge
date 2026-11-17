"""SYNTHETIC receipts/public keys; no real Source process or native execution."""

from copy import deepcopy
import json
import stat
from pathlib import Path

import pytest

from azazel_edge.benchmark import real_source_close as c
from azazel_edge.benchmark.capture_close import _wire as wire, _sha as sha
from azazel_edge.benchmark.source_authentication import verify_source_bytes
from azazel_edge.benchmark.source_witness import verify_witnessed_source_prefix
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier, public_hex
from auth_input_helpers import make_policy
from test_outcome_live_origin import frame
from test_outcome_input_auth import signed
from source_witness_data import sign_anchors, anchor_checkpoint
from safety_observation_data import KEYS
from test_capture_close_collection import DOMAIN

BOOT = "00000000-0000-4000-8000-000000000001"
SESSION = "0123456789abcdef0123456789abcdef"
ROOT = Path(__file__).parent / "fixtures/real-source-close/v1"


def make_bundle(tmp_path, case="clean", *, boot_ref=None, producer_uid=1000):
    base, *_ = make_policy(tmp_path, producer=1000, observer=65534, witness=0)
    policy = TrustPolicy(
        dict(
            base.data,
            schema_version="outcome-input-trust/v3",
            producer_uid=producer_uid,
            producer_public_key=public_hex(KEYS[1]),
            witness_public_key=public_hex(KEYS[2]),
            origin_registration_sha256="f" * 64,
            input_max_bytes=c.MAXIMUM,
            anchor_max_bytes=c.MAXIMUM,
        )
    )
    trust_raw = wire(dict(policy.data))
    context = {
        key: policy.data[key]
        for key in (
            "scope_ref",
            "producer_ref",
            "stream_ref",
            "producer_public_key",
            "witness_public_key",
            "producer_uid",
            "observer_uid",
        )
    }
    context.update(
        registration_sha256="f" * 64,
        session_ref=SESSION,
        boot_ref=boot_ref or BOOT.replace("-", ""),
    )
    protocol = json.loads((ROOT / "protocol.json").read_bytes())
    template = protocol["decision_template"]
    native_seq = (
        [0, 1, 2, 3, None, 4, 5, 6] if case == "explicit_loss" else list(range(8))
    )
    events = []
    for index, kind in enumerate(c.KINDS):
        ordinal = native_seq[index] if native_seq[index] is not None else index
        event = (
            frame(kind, ordinal, SESSION)["event"]
            if kind != "decision_execution"
            else deepcopy(template)
        )
        if kind == "decision_execution":
            event["enforcement"]["trace_id"] = "SYNTHETIC-" + c.IDS[index]
        event["capture_origin"] = dict(
            schema_version="outcome-registered-origin/v2",
            registration_sha256="f" * 64,
            mode="live-core",
            session_ref=SESSION,
            seq=ordinal,
            kind=kind,
        )
        events.append(event)
    source_raw = b""
    verifier = SourceVerifier(policy)
    prefix = None
    indices = (
        range(4)
        if case == "abrupt_writer"
        else [i for i in range(8) if not (case == "explicit_loss" and i == 4)]
    )
    for index in indices:
        source_raw += signed(
            policy,
            KEYS[1],
            seq=verifier.seq + 1,
            prev=verifier.head,
            event=events[index],
            boot_ref=context["boot_ref"],
        )
        final = verifier.verify(source_raw)
        if verifier.seq == 4:
            prefix = deepcopy(final)
    assert prefix is not None
    empty = dict(seq=0, head="0" * 64, size=0, sha256=sha(b""))
    anchor_rows = []
    for counter, tip in enumerate((empty, prefix), 1):
        state = {"source_" + name: value for name, value in tip.items()}
        state.update(
            journal_seq=counter - 1,
            journal_head="0" * 64 if counter == 1 else "a" * 64,
            journal_size=0 if counter == 1 else 100,
            journal_sha256=sha(b"") if counter == 1 else "b" * 64,
            journal_device=0 if counter == 1 else 2,
            journal_inode=0 if counter == 1 else 3,
        )
        anchor_rows.append(
            dict(
                schema_version="outcome-input-anchor/v1",
                counter=counter,
                prev="0" * 64,
                trust_sha256=policy.digest,
                state=state,
            )
        )
    anchors_raw = sign_anchors(anchor_rows)
    anchor = anchor_checkpoint(anchors_raw)
    source_args = dict(
        expected_trust_sha256=sha(trust_raw),
        expected_context=deepcopy(context),
        expected_prefix_checkpoint=prefix,
        expected_final_checkpoint=final,
    )
    witness_args = dict(
        expected_trust_sha256=sha(trust_raw),
        expected_context=deepcopy(context),
        expected_source_checkpoint=prefix,
        expected_anchor_checkpoint=anchor,
    )

    def actor(pid, uid, start):
        return dict(
            pid=pid,
            uid=uid,
            process_start_ticks=start,
            boot_id=BOOT,
            clock_domain=deepcopy(DOMAIN),
        )

    controller_id, producer_id, collector_id = (
        actor(101, 0, 11),
        actor(202, 1000, 22),
        actor(303, 61002, 33),
    )
    source_id = dict(device=11, inode=22, owner_uid=1000)
    plan = dict(
        schema_version="edge-real-source-close-plan/v1",
        run_id="SYNTHETIC",
        capture_id="test-capture",
        case_id=case,
        protocol_sha256=c.PROTOCOL_SHA256,
        source_inventory_sha256="1" * 64,
        trust_sha256=sha(trust_raw),
        expected_context=context,
        controller_identity=controller_id,
        producer_identity=producer_id,
        collector_identity=collector_id,
        source_identity=source_id,
        gate_id="gate",
        gate_token="2" * 64,
        attempts=[
            dict(
                id=identifier,
                kind=c.KINDS[i],
                event_sha256=sha(wire(events[i])),
                native_seq=native_seq[i],
            )
            for i, identifier in enumerate(c.IDS)
        ],
        late_ids=list(c.LATE_IDS),
        maximum_bytes=c.MAXIMUM,
    )
    attempts = [
        dict(
            id=identifier,
            decision="admitted",
            started_ns=4 + i * 2,
            finished_ns=5 + i * 2,
        )
        for i, identifier in enumerate(c.IDS)
    ]
    late = []
    for i, identifier in enumerate(c.LATE_IDS):
        t = 50 + i * 10
        attempts.append(
            dict(
                id=identifier,
                decision="rejected_closed",
                started_ns=t + 2,
                finished_ns=t + 3,
            )
        )
        late.append(
            dict(
                id=identifier,
                gate_id="gate",
                gate_token="2" * 64,
                started_ns=t + 1,
                finished_ns=t + 4,
                poll_before_ns=t,
                poll_after_ns=t + 5,
                poll_before_returncode=None,
                poll_after_returncode=None,
            )
        )
    plan_raw = wire(plan)
    controller = dict(
        schema_version="edge-real-source-close-controller/v1",
        run_id="SYNTHETIC",
        capture_id="test-capture",
        controller_identity=controller_id,
        producer_identity=producer_id,
        gate_id="gate",
        gate_token="2" * 64,
        enrollment=dict(
            started_ns=1,
            finished_ns=2,
            plan_sha256=sha(plan_raw),
            plan_bytes_read=len(plan_raw),
            source_inventory_sha256="1" * 64,
            source_inventory_bytes_read=300,
            source_identity=source_id,
        ),
        attempts=attempts,
        C=dict(
            started_ns=40,
            finished_ns=41,
            gate_id="gate",
            gate_token="2" * 64,
            admitted_ids=list(c.IDS),
        ),
        late_controls=late,
        prefix_selection=dict(
            started_ns=30,
            finished_ns=31,
            source_checkpoint=prefix,
            anchor_checkpoint=anchor,
        ),
        final_selection=dict(started_ns=90, finished_ns=91, source_checkpoint=final),
        writer_close=None
        if case == "abrupt_writer"
        else dict(started_ns=70, finished_ns=71, returned=True),
        post_close_append=dict(
            attempted=case != "abrupt_writer",
            started_ns=None if case == "abrupt_writer" else 72,
            finished_ns=None if case == "abrupt_writer" else 73,
            outcome=None if case == "abrupt_writer" else "raised",
            exception_type=None if case == "abrupt_writer" else "OutcomeJournalError",
            source_unchanged=None if case == "abrupt_writer" else True,
        ),
        W=dict(
            started_ns=80,
            finished_ns=81,
            pid=202,
            process_start_ticks=22,
            returncode=7 if case == "abrupt_writer" else 0,
            waited=True,
        ),
        test_loss_ids=None
        if case == "abrupt_writer"
        else ["a04"]
        if case == "explicit_loss"
        else [],
    )
    source_stat = dict(
        source_id,
        mode=stat.S_IFREG | 0o600,
        nlink=1,
        size=len(source_raw),
        mtime_ns=5,
        ctime_ns=6,
    )
    read = dict(
        schema_version="edge-real-source-close-read/v1",
        collector_identity=collector_id,
        source_before=source_stat,
        source_after=deepcopy(source_stat),
        access_mode=0,
        read_started_ns=100,
        read_finished_ns=101,
        bytes_read=len(source_raw),
        sha256=sha(source_raw),
        complete=True,
        errors=[],
    )
    return dict(
        trust=trust_raw,
        source=source_raw,
        anchors=anchors_raw,
        plan=plan_raw,
        controller=wire(controller),
        read=wire(read),
        source_arguments=source_args,
        witness_arguments=witness_args,
    )


def pins(bundle):
    return {
        name + "_sha256": sha(wire(value))
        if name.endswith("_arguments")
        else sha(value)
        if value is not None
        else None
        for name, value in bundle.items()
    }


def evaluate(bundle, expected=None):
    return c.evaluate_real_source_close(
        bundle["trust"],
        bundle["source"],
        bundle["anchors"],
        source_arguments=bundle["source_arguments"],
        witness_arguments=bundle["witness_arguments"],
        plan_raw=bundle["plan"],
        controller_raw=bundle["controller"],
        read_raw=bundle["read"],
        expected=pins(bundle) if expected is None else expected,
    )


def mutate(bundle, name, callback):
    value = json.loads(bundle[name])
    callback(value)
    bundle[name] = wire(value)


def original_replays(bundle):
    return (
        verify_source_bytes(
            bundle["trust"], bundle["source"], **bundle["source_arguments"]
        ),
        verify_witnessed_source_prefix(
            bundle["trust"],
            bundle["source"],
            bundle["anchors"],
            **bundle["witness_arguments"],
        ),
    )


@pytest.mark.parametrize(
    "case,records,missing",
    [("clean", 8, 0), ("explicit_loss", 7, 1), ("abrupt_writer", 4, None)],
)
def test_signed_mechanics_expected_accounting_preserves_exact_original_types(
    tmp_path, case, records, missing
):
    bundle = make_bundle(tmp_path, case)
    before = deepcopy(bundle)
    oldsource, oldwitness = original_replays(bundle)
    result = evaluate(bundle)
    assert (
        result["original_source_evaluation"] == oldsource
        and result["original_witness_evaluation"] == oldwitness
    )
    assert len(result["known_signed_ids"]) == records
    assert result["test_gate_missing_count"] == missing, result["reasons"]
    assert result["finite_test_gate_accounting_complete"] is (
        case != "abrupt_writer"
    ), result["reasons"]
    assert result["complete_assigned_test_capture"] is (case == "clean")
    assert result["native_registry_authentication"] == "not_exercised"
    assert (
        result["actual_native_terminal_verified"]
        is result["upstream_produced"]
        is result["runtime_inflight"]
        is None
    )
    assert (
        result["actual_native_execution"]
        is result["source_immutability"]
        is result["whole_window_coverage"]
        is False
    )
    assert result["witnessed_prefix_equals_final"] is (case == "abrupt_writer")
    assert result["qualified_safety_count"] is None and not any(
        result["authority_flags"].values()
    )
    assert bundle == before and result == evaluate(bundle)


def test_bad_suffix_keeps_original_signed_and_witnessed_prefix4(tmp_path):
    bundle = make_bundle(tmp_path)
    bundle["source"] += b'{"corrupt":'
    before = original_replays(bundle)
    result = evaluate(bundle)
    assert (
        result["original_source_evaluation"],
        result["original_witness_evaluation"],
    ) == before
    assert (
        before[0]["authenticated_prefix"]
        is before[1]["witness_prefix_authenticated"]
        is True
    )
    assert result["known_signed_ids"] == list(c.IDS[:4])
    assert (
        result["test_gate_missing_count"] is None
        and result["finite_test_gate_accounting_complete"] is False
    )


@pytest.mark.parametrize("name", ["controller", "read"])
@pytest.mark.parametrize("fault", ["missing", "unknown", "pin"])
def test_optional_receipt_does_not_erase_trusted_prefix_or_old_reports(
    tmp_path, name, fault
):
    bundle = make_bundle(tmp_path)
    expected = pins(bundle)
    old = original_replays(bundle)
    if fault == "missing":
        bundle[name] = None
        expected[name + "_sha256"] = None
    elif fault == "unknown":
        mutate(bundle, name, lambda v: v.update(unexpected=True))
        expected[name + "_sha256"] = sha(bundle[name])
    else:
        expected[name + "_sha256"] = "a" * 64
    result = evaluate(bundle, expected)
    assert result["known_signed_ids"] == list(c.IDS)
    assert (
        result["original_source_evaluation"],
        result["original_witness_evaluation"],
    ) == old
    assert (
        result["test_gate_missing_count"] is None
        and result["finite_test_gate_accounting_complete"] is False
    )


@pytest.mark.parametrize(
    "name", ["source", "trust", "source_arguments", "witness_arguments", "plan"]
)
def test_bad_required_pin_preserves_old_results_but_no_new_ID_or_trusted_derived_claim(
    tmp_path, name
):
    bundle = make_bundle(tmp_path)
    expected = pins(bundle)
    expected[name + "_sha256"] = "a" * 64
    old = original_replays(bundle)
    result = evaluate(bundle, expected)
    assert (
        result["original_source_evaluation"],
        result["original_witness_evaluation"],
    ) == old
    assert (
        result["known_signed_ids"] == [] and result["test_gate_missing_count"] is None
    )
    if name in ("source", "trust", "source_arguments"):
        assert result["legs"]["source_authentication"] is False
        assert (
            result["original_replay_provenance"]["source"][
                "required_raw_and_argument_pins_verified"
            ]
            is False
        )
    if name in ("source", "trust", "witness_arguments"):
        assert result["legs"]["witness_prefix"] is False
    if name in ("source", "trust", "source_arguments", "witness_arguments"):
        assert result["witnessed_prefix_equals_final"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "gate",
        "actor",
        "FD",
        "mode",
        "read_bool",
        "read_reverse",
        "domain",
        "wait_bool",
        "wait_pid",
        "close",
        "post_refusal",
        "late_poll",
        "prefix_late",
        "final_early",
        "lost_extra",
        "native_seq",
        "event_hash",
        "unknown",
        "bool_clock",
    ],
)
def test_repinned_adversarial_context_and_receipts_never_grant_accounting(
    tmp_path, fault
):
    bundle = make_bundle(tmp_path)
    if fault == "gate":
        mutate(bundle, "controller", lambda v: v["C"].update(gate_token="a" * 64))
    elif fault == "actor":
        mutate(
            bundle,
            "controller",
            lambda v: v["producer_identity"].update(process_start_ticks=999),
        )
    elif fault == "FD":
        mutate(bundle, "read", lambda v: v["source_after"].update(inode=999))
    elif fault == "mode":
        mutate(bundle, "read", lambda v: v.update(access_mode=2))
    elif fault == "read_bool":
        mutate(bundle, "read", lambda v: v.update(bytes_read=True))
    elif fault == "read_reverse":
        mutate(bundle, "read", lambda v: v.update(read_finished_ns=99))
    elif fault == "domain":
        mutate(
            bundle,
            "plan",
            lambda v: v["collector_identity"]["clock_domain"].update(established=False),
        )
    elif fault == "wait_bool":
        mutate(bundle, "controller", lambda v: v["W"].update(returncode=False))
    elif fault == "wait_pid":
        mutate(bundle, "controller", lambda v: v["W"].update(pid=999))
    elif fault == "close":
        mutate(bundle, "controller", lambda v: v["writer_close"].update(returned=False))
    elif fault == "post_refusal":
        mutate(
            bundle,
            "controller",
            lambda v: v["post_close_append"].update(source_unchanged=False),
        )
    elif fault == "late_poll":
        mutate(
            bundle,
            "controller",
            lambda v: v["late_controls"][0].update(poll_after_returncode=0),
        )
    elif fault == "prefix_late":
        mutate(
            bundle, "controller", lambda v: v["prefix_selection"].update(finished_ns=42)
        )
    elif fault == "final_early":
        mutate(
            bundle, "controller", lambda v: v["final_selection"].update(started_ns=79)
        )
    elif fault == "lost_extra":
        mutate(bundle, "controller", lambda v: v.update(test_loss_ids=["a04"]))
    elif fault == "native_seq":
        mutate(bundle, "plan", lambda v: v["attempts"][5].update(native_seq=4))
    elif fault == "event_hash":
        mutate(bundle, "plan", lambda v: v["attempts"][5].update(event_sha256="a" * 64))
    elif fault == "unknown":
        mutate(bundle, "read", lambda v: v.update(eligible=True))
    else:
        mutate(bundle, "controller", lambda v: v["C"].update(started_ns=True))
    result = evaluate(bundle)
    assert (
        result["finite_test_gate_accounting_complete"] is False
        and result["test_gate_missing_count"] is None
    )
    assert result["original_source_evaluation"]["authenticated_prefix"] is True
    assert result["actual_native_execution"] is False


@pytest.mark.parametrize(
    "fault", ["duplicate", "nonfinite", "deep", "overbound", "null_pin_present"]
)
def test_strict_new_receipt_parser_does_not_mutate_original_signature_replay(
    tmp_path, fault
):
    bundle = make_bundle(tmp_path)
    expected = None
    old = original_replays(bundle)
    if fault == "duplicate":
        bundle["controller"] = bundle["controller"].replace(
            b'"schema_version":', b'"schema_version":"bad","schema_version":', 1
        )
    elif fault == "nonfinite":
        bundle["controller"] = b'{"bad":NaN}\n'
    elif fault == "deep":
        value = 0
        for _ in range(17):
            value = [value]
        bundle["controller"] = wire(value)
    elif fault == "overbound":
        bundle["controller"] = b" " * (c.MAXIMUM + 1)
    else:
        expected = pins(bundle)
        expected["controller_sha256"] = None
    result = evaluate(bundle, expected)
    assert (
        result["original_source_evaluation"],
        result["original_witness_evaluation"],
    ) == old
    assert (
        result["known_signed_ids"] == list(c.IDS)
        and result["test_gate_missing_count"] is None
    )


def test_pure_annex_has_no_path_read_or_process_execution(tmp_path, monkeypatch):
    import subprocess

    bundle = make_bundle(tmp_path)

    def forbidden(*a, **k):
        raise AssertionError("I/O in pure annex")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert evaluate(bundle)["finite_test_gate_accounting_complete"] is True


@pytest.mark.parametrize("field", ["boot_ref", "producer_uid"])
def test_valid_original_signatures_cannot_join_wrong_actor_context(tmp_path, field):
    bundle = make_bundle(tmp_path, **{field: "1" * 32 if field == "boot_ref" else 1001})
    originals = original_replays(bundle)
    assert originals[0]["authenticated_full_source"] is True
    assert originals[1]["witness_prefix_authenticated"] is True
    result = evaluate(bundle)
    assert (
        result["original_source_evaluation"],
        result["original_witness_evaluation"],
    ) == originals
    assert result["finite_test_gate_accounting_complete"] is False
    assert result["known_signed_ids"] == []
    assert any(
        "source_context_actor_boot_or_UID" in reason for reason in result["reasons"]
    )


def test_argument_depth_checked_before_encoding_and_delegation(tmp_path, monkeypatch):
    bundle = make_bundle(tmp_path)
    expected = pins(bundle)
    nested = 0
    for _ in range(18):
        nested = {"child": nested}
    bundle["source_arguments"]["expected_context"] = nested
    original_wire = c._wire

    def guarded_wire(value):
        assert value is not bundle["source_arguments"], "encoded malformed arguments"
        return original_wire(value)

    def forbidden(*args, **kwargs):
        raise AssertionError("delegated malformed arguments")

    monkeypatch.setattr(c, "_wire", guarded_wire)
    monkeypatch.setattr(c, "verify_source_bytes", forbidden)
    result = evaluate(bundle, expected)
    assert "argument_depth_bound" in result["original_errors"]["source"]["reason"]
    assert result["original_witness_evaluation"]["witness_prefix_authenticated"] is True


def test_annex_row_cap_preserves_original_verifiers_larger_valid_stream(tmp_path):
    bundle = make_bundle(tmp_path)
    events = [json.loads(line)["event"] for line in bundle["source"].splitlines()]
    expanded = events[:7]
    for ordinal in range(7, 129):
        event = deepcopy(events[6])
        event["capture_origin"]["seq"] = ordinal
        event["enforcement"]["trace_id"] = "SYNTHETIC-extra-" + str(ordinal)
        expanded.append(event)
    end = deepcopy(events[7])
    end["capture_origin"]["seq"] = 129
    expanded.append(end)
    policy = TrustPolicy(json.loads(bundle["trust"]))
    verifier = SourceVerifier(policy)
    raw = b""
    for event in expanded:
        raw += signed(
            policy,
            KEYS[1],
            seq=verifier.seq + 1,
            prev=verifier.head,
            event=event,
            boot_ref=bundle["source_arguments"]["expected_context"]["boot_ref"],
        )
        tip = verifier.verify(raw)
    bundle["source"] = raw
    bundle["source_arguments"]["expected_final_checkpoint"] = tip
    originals = original_replays(bundle)
    assert originals[0]["authenticated_full_source"] is True
    assert originals[0]["normal_terminal_verified"] is True
    result = evaluate(bundle)
    assert (
        result["original_source_evaluation"],
        result["original_witness_evaluation"],
    ) == originals
    assert result["known_signed_ids"] == list(c.IDS[:7])
    assert result["finite_test_gate_accounting_complete"] is False
    assert any("annex_Source_row_bound" in reason for reason in result["reasons"])


@pytest.mark.parametrize(
    "fault", ["a01_before_enrollment", "attempt_overlap", "prefix_before_admission"]
)
def test_controller_order_is_prospective_for_every_admission(tmp_path, fault):
    bundle = make_bundle(tmp_path)
    originals = original_replays(bundle)

    def change(controller):
        if fault == "a01_before_enrollment":
            controller["attempts"][1].update(started_ns=0, finished_ns=1)
        elif fault == "attempt_overlap":
            controller["attempts"][1].update(started_ns=4, finished_ns=7)
        else:
            controller["prefix_selection"].update(started_ns=18)

    mutate(bundle, "controller", change)
    result = evaluate(bundle)
    assert (
        result["original_source_evaluation"],
        result["original_witness_evaluation"],
    ) == originals
    assert result["known_signed_ids"] == list(c.IDS)
    assert result["finite_test_gate_accounting_complete"] is False
    expected_reason = {
        "a01_before_enrollment": "enrollment_not_prospective",
        "attempt_overlap": "test_gate_attempts_not_serial",
        "prefix_before_admission": "prospective_prefix4_selection",
    }[fault]
    assert any(expected_reason in reason for reason in result["reasons"])


@pytest.mark.parametrize("fault", ["values", "keys", "giant_integer"])
def test_argument_aggregate_budget_precedes_encoding_and_original_call(
    tmp_path, monkeypatch, fault
):
    bundle = make_bundle(tmp_path)
    expected = pins(bundle)
    if fault == "values":
        bundle["source_arguments"]["expected_context"] = {
            str(i): "x" * 40000 for i in range(10)
        }
    elif fault == "keys":
        bundle["source_arguments"]["expected_context"] = {
            "x" * 40000 + str(i): 0 for i in range(10)
        }
    else:
        bundle["source_arguments"]["expected_context"] = {"bad": 1 << 100000}
    original_wire = c._wire

    def guarded_wire(value):
        assert value is not bundle["source_arguments"], "encoded overbound arguments"
        return original_wire(value)

    def forbidden(*args, **kwargs):
        raise AssertionError("delegated overbound arguments")

    monkeypatch.setattr(c, "_wire", guarded_wire)
    monkeypatch.setattr(c, "verify_source_bytes", forbidden)
    result = evaluate(bundle, expected)
    reason = (
        "argument_integer_bound"
        if fault == "giant_integer"
        else "argument_aggregate_byte_bound"
    )
    assert reason in result["original_errors"]["source"]["reason"]
    assert result["original_witness_evaluation"]["witness_prefix_authenticated"] is True
