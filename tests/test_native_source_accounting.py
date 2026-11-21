"""PUBLIC TEST keys/signatures and SYNTHETIC receipts; no real native attestation."""

from copy import deepcopy
import json
import stat
from pathlib import Path

import pytest

from azazel_edge.benchmark import native_source_accounting as annex
from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy, public_hex
from azazel_edge.outcome.journal import _json
from auth_input_helpers import make_policy
from safety_observation_data import KEYS, digest
from source_witness_data import sign_anchors, anchor_checkpoint
from test_outcome_input_auth import signed
from test_outcome_live_origin import frame

BOOT = "12345678-1234-1234-1234-123456789abc"
SESSION = "b" * 32
ZERO = "0" * 64


def actor(pid, uid, label, *, parent=10):
    return dict(
        pid=pid,
        ppid=parent,
        start_ticks=100 + pid,
        uid=uid,
        gid=uid,
        groups=[],
        apparmor_label=label,
        cap_eff=0,
        cap_prm=0,
        cap_bnd=0,
        cap_amb=0,
        no_new_privs=True,
    )


def source_bytes(policy, events):
    raw, head = b"", ZERO
    for seq, event in enumerate(events, 1):
        line = signed(
            policy,
            KEYS[1],
            seq=seq,
            prev=head,
            event=event,
            boot_ref=BOOT.replace("-", ""),
        )
        raw += line
        head = digest(_json(json.loads(line)))
    return raw


def anchors(policy, tip):
    rows = []
    empty = SourceVerifier(policy).tip()
    for counter, checkpoint in enumerate((empty, tip), 1):
        state = {"source_" + k: v for k, v in checkpoint.items()}
        state.update(
            journal_seq=counter - 1,
            journal_head=ZERO if counter == 1 else "a" * 64,
            journal_size=0 if counter == 1 else 100,
            journal_sha256=digest(b"") if counter == 1 else "c" * 64,
            journal_device=0 if counter == 1 else 2,
            journal_inode=0 if counter == 1 else 3,
        )
        rows.append(
            dict(
                schema_version="outcome-input-anchor/v1",
                counter=counter,
                prev=ZERO,
                trust_sha256=policy.digest,
                state=state,
            )
        )
    return sign_anchors(rows)


def fixture(case="normal-four", *, legacy=False, registered_profile="v1"):
    base, *_ = make_policy(
        Path("/synthetic/native-accounting"), producer=61001, observer=61002, witness=0
    )
    env = dict(
        AZAZEL_EVE_PATH="/synthetic/eve",
        AZAZEL_NORMALIZED_EVENT_LOG="/synthetic/normalized",
        AZAZEL_FORWARD_AI="0",
        AZAZEL_FORWARD_LOG="0",
        AZAZEL_EVENT_STDOUT="off",
        AZAZEL_DEFENSE_ENFORCE="0",
        AZAZEL_DEFENSE_DRY_RUN="1",
        AZAZEL_DEFENSE_RELEASE_LEDGER="/synthetic/releases",
        AZAZEL_REDIRECT_POLICY_PATH="/synthetic/policy",
        AZAZEL_PROTECTED_FLOWS_PATH="/synthetic/protected",
        AZAZEL_EVE_FROM_START="0",
    )
    if registered_profile is not None:
        env["AZAZEL_LIVE_ORIGIN_ACCOUNTING"] = registered_profile
    registration = dict(
        schema_version="outcome-live-origin-registration/v4",
        mode="live-core",
        scope_ref=base.data["scope_ref"],
        producer_ref=base.data["producer_ref"],
        stream_ref=base.data["stream_ref"],
        producer_public_key=public_hex(KEYS[1]),
        binary_path="/synthetic/azazel-edge-core",
        binary_sha256="a" * 64,
        launcher_uid=0,
        environment=env,
        ai_socket_uid=1003,
        native_apparmor_profile="edge400-native",
        capture_apparmor_profile="edge400-capture",
    )
    registration_raw = _json(registration)
    policy = TrustPolicy(
        {
            **dict(base.data),
            "schema_version": "outcome-input-trust/v3",
            "producer_public_key": public_hex(KEYS[1]),
            "witness_public_key": public_hex(KEYS[2]),
            "origin_registration_sha256": digest(registration_raw),
        }
    )
    sids, excluded, planned, outcome = annex.CASES[case]
    events = []
    kinds = ["session_prepare", "session_start"] + ["decision_execution"] * len(sids)
    if outcome == "clean":
        kinds.append("session_end")
    for position, kind in enumerate(kinds):
        native_seq = position
        event = deepcopy(frame(kind, native_seq, SESSION)["event"])
        if kind == "decision_execution":
            event["normalized"]["sid"] = sids[position - 2]
            event["enforcement"].update(
                mode="disabled",
                result="no_disruptive_action",
                executed_count=0,
                failed_count=0,
                command_plan=[],
                rollback_plan=[],
            )
            event["enforcement_status"].update(enforce_enabled=False, dry_run=True)
        elif kind != "session_prepare" and not legacy:
            event["capture_lifecycle"].update(
                schema_version="outcome-live-origin-lifecycle/v2",
                accounting_profile="v1",
            )
            if kind == "session_end":
                event["capture_lifecycle"]["counts"] = dict(
                    produced=len(sids),
                    admitted=len(sids),
                    enqueued=len(sids),
                    written=len(sids),
                    dropped=0,
                    inflight=0,
                )
        event["capture_origin"] = dict(
            schema_version="outcome-registered-origin/v2",
            registration_sha256=policy.data["origin_registration_sha256"],
            mode="live-core",
            session_ref=SESSION,
            seq=native_seq,
            kind=kind,
        )
        events.append(event)
    raw = source_bytes(policy, events)
    tip = SourceVerifier(policy).verify(raw)
    prefix_raw = (
        b"".join(raw.splitlines(keepends=True)[:-1]) if outcome == "clean" else raw
    )
    prefix_tip = SourceVerifier(policy).verify(prefix_raw)
    anchor_raw = anchors(policy, tip)
    identity = dict(
        device=8, inode=200, owner_uid=61001, mode=stat.S_IFREG | 0o644, nlink=1
    )
    obj = dict(**identity, size=len(raw), mtime_ns=100, ctime_ns=100)
    native = actor(11, 0, "edge400-native (enforce)")
    native["image"] = dict(
        sha256=registration["binary_sha256"],
        owner_uid=0,
        mode=stat.S_IFREG | 0o500,
        nlink=0,
        seals=15,
    )
    control = dict(
        schema_version="edge-native-source-accounting-controller/v1",
        case_id=case,
        protocol_sha256=annex.PROTOCOL_SHA256,
        source_revision="d" * 40,
        core_image_sha256=registration["binary_sha256"],
        registration_sha256=digest(registration_raw),
        trust_sha256=policy.digest,
        boot_id=BOOT,
        source_boot_ref=BOOT.replace("-", ""),
        session_ref=SESSION,
        source_identity=identity,
        prefix_checkpoint=prefix_tip,
        checkpoint=tip,
        native=native,
        launcher=actor(10, 0, "edge400-launcher (enforce)", parent=1),
        receiver=actor(12, 61001, "edge400-capture (enforce)"),
        wait=dict(unit_state="inactive", exec_main_code=1, exec_main_status=0),
        reader=dict(
            actor=actor(13, 61002, "edge400-observer (enforce)"),
            source_before=obj,
            source_after=deepcopy(obj),
            access_mode=0,
            started_ns=100,
            finished_ns=200,
            bytes_read=len(raw),
            sha256=digest(raw),
            complete=True,
            errors=[],
        ),
        challenge_sids=list(sids),
        observed_sids=list(sids),
        excluded_sids=list(excluded),
        planned_activity_count=planned,
        witness_boundary=dict(
            source_checkpoint=tip, anchor_checkpoint=anchor_checkpoint(anchor_raw)
        ),
        outcome=outcome,
        local_finish_acknowledged=None,
    )
    value = dict(
        trust=_json(dict(policy.data)),
        registration=registration_raw,
        source=raw,
        anchors=anchor_raw,
        controller=_json(control) + b"\n",
    )
    return value, policy, events, control


def evaluate(value, *, expected=None):
    pins = {
        k + "_sha256": digest(v) if type(v) is bytes else None for k, v in value.items()
    }
    return annex.evaluate_native_source_accounting(
        *(
            value[k]
            for k in ("trust", "registration", "source", "anchors", "controller")
        ),
        expected=pins if expected is None else expected,
    )


def rewrite_control(value, control):
    value["controller"] = _json(control) + b"\n"


def unqualified(result):
    assert result["finite_accounting_verified"] is False
    assert result["qualified_counts"] is None
    assert result["local_finish_acknowledged"] is None
    assert result["overall_capture_completion_verified"] is None
    assert result["upstream_ingress_count"] is None
    assert result["full_lifetime_loss"] is None
    assert not any(result["authority_flags"].values())
    for name in (
        "whole_window_coverage",
        "comparison_qualified",
        "performance_acceptance",
        "production_activation",
        "resume_authorized",
        "old_evaluation_modified",
        "source_immutable",
    ):
        assert result[name] is False


@pytest.mark.parametrize("case,count", [("normal-four", 4), ("restart-one", 1)])
def test_synthetic_finite_receipts_preserve_original_tips_and_no_authority(case, count):
    value, policy, _, control = fixture(case)
    original = deepcopy(value)
    result = evaluate(value)
    assert result["finite_accounting_verified"] is True, result["reasons"]
    assert result["status"] == "verified_finite_native_cohort"
    assert result["qualified_counts"]["produced"] == count
    assert result["known_activity_count"] == count
    assert result["original_source_tip"] == SourceVerifier(policy).verify(
        value["source"]
    )
    assert (
        result["original_anchor_tip"]
        == control["witness_boundary"]["anchor_checkpoint"]
    )
    assert (
        result["local_finish_acknowledged"]
        is result["overall_capture_completion_verified"]
        is None
    )
    assert not any(result["authority_flags"].values())
    assert value == original and evaluate(value) == result
    assert not value["trust"].endswith(b"\n") and not value["registration"].endswith(
        b"\n"
    )


def test_interrupted_prefix_retains_known_facts_but_final_totals_unknown():
    value, _, _, _ = fixture("interrupted-prefix")
    result = evaluate(value)
    unqualified(result)
    assert result["authenticated_prefix"] is True
    assert result["known_activity_count"] == 1
    assert result["known_sids"] == [90121007]
    assert result["authenticated_declared_counts"] is None
    assert result["selected_end_present"] is False


@pytest.mark.parametrize(
    "legacy,profile", [(True, "v1"), (True, None), (False, None), (False, "v2")]
)
def test_legacy_missing_or_unknown_registered_profile_never_qualifies(legacy, profile):
    value, _, _, _ = fixture(legacy=legacy, registered_profile=profile)
    result = evaluate(value)
    unqualified(result)
    assert result["authenticated_full_source"] is True
    if legacy:
        assert result["known_activity_count"] is None
        assert any("legacy_unmeasured" in reason for reason in result["reasons"])


@pytest.mark.parametrize(
    "key,bad",
    [
        ("produced", True),
        ("admitted", -1),
        ("written", 2**63),
        ("enqueued", 3),
        ("dropped", 1),
        ("inflight", 1),
        ("unknown", 0),
    ],
)
def test_bad_resigned_terminal_preserves_preterminal_signed_prefix(key, bad):
    value, policy, events, _ = fixture()
    events[-1]["capture_lifecycle"]["counts"][key] = bad
    value["source"] = source_bytes(policy, events)
    result = evaluate(value)
    unqualified(result)
    assert result["authenticated_full_source"] is False
    assert result["authenticated_prefix"] is True
    assert result["known_activity_count"] == 4
    assert result["authenticated_declared_counts"] is None


@pytest.mark.parametrize("suffix", [b'{"broken":', b"extra\n", b"\n"])
def test_bad_source_suffix_does_not_erase_checkpointed_facts(suffix):
    value, _, _, _ = fixture()
    value["source"] += suffix
    result = evaluate(value)
    unqualified(result)
    assert result["authenticated_prefix"] is True
    assert result["known_activity_count"] == 4
    assert result["authenticated_declared_counts"] is None


@pytest.mark.parametrize(
    "leg", ["trust", "registration", "source", "anchors", "controller"]
)
def test_independently_pinned_input_cannot_be_substituted(leg):
    value, _, _, _ = fixture()
    pins = {k + "_sha256": digest(raw) for k, raw in value.items()}
    pins[leg + "_sha256"] = "f" * 64
    result = evaluate(value, expected=pins)
    unqualified(result)
    assert result["pins"][leg] is False
    if leg in ("registration", "source", "anchors"):
        assert result["authenticated_full_source"] is True
        assert result["known_activity_count"] == 4


@pytest.mark.parametrize(
    "fault",
    [
        "image_hash",
        "image_seals",
        "image_mode",
        "image_permission_only",
        "native_profile",
        "receiver_profile",
        "native_parent",
        "receiver_parent",
        "receiver_caps",
        "reader_caps",
        "reader_mode",
        "reader_incomplete",
        "reader_changed",
        "wait",
        "protocol",
        "case",
        "sids",
        "planned",
        "boot",
        "source_identity",
        "extra",
        "ack",
    ],
)
def test_bad_synthetic_receipt_leg_quarantines_qualification_only(fault):
    value, _, _, c = fixture()
    if fault == "image_hash":
        c["native"]["image"]["sha256"] = "e" * 64
    elif fault == "image_seals":
        c["native"]["image"]["seals"] = 7
    elif fault == "image_mode":
        c["native"]["image"]["mode"] = stat.S_IFREG | 0o700
    elif fault == "image_permission_only":
        c["native"]["image"]["mode"] = 0o500
    elif fault == "native_profile":
        c["native"]["apparmor_label"] = "unconfined"
    elif fault == "receiver_profile":
        c["receiver"]["apparmor_label"] = "edge400-capture (complain)"
    elif fault == "native_parent":
        c["native"]["ppid"] = 999
    elif fault == "receiver_parent":
        c["receiver"]["ppid"] = 999
    elif fault == "receiver_caps":
        c["receiver"]["cap_eff"] = 4
    elif fault == "reader_caps":
        c["reader"]["actor"]["cap_bnd"] = 4
    elif fault == "reader_mode":
        c["reader"]["access_mode"] = 1
    elif fault == "reader_incomplete":
        c["reader"]["complete"] = False
    elif fault == "reader_changed":
        c["reader"]["source_after"]["mtime_ns"] += 1
    elif fault == "wait":
        c["wait"]["exec_main_status"] = 1
    elif fault == "protocol":
        c["protocol_sha256"] = "e" * 64
    elif fault == "case":
        c["case_id"] = "self-selected-case"
    elif fault == "sids":
        c["observed_sids"] = [1, 2, 3, 4]
    elif fault == "planned":
        c["planned_activity_count"] = 0
    elif fault == "boot":
        c["source_boot_ref"] = BOOT
    elif fault == "source_identity":
        c["source_identity"]["mode"] = 0o644
    elif fault == "extra":
        c["derived_qualified"] = True
    elif fault == "ack":
        c["local_finish_acknowledged"] = True
    rewrite_control(value, c)
    result = evaluate(value)
    unqualified(result)
    assert result["authenticated_full_source"] is True
    if result["legs"].get("controller"):
        assert result["known_activity_count"] == 4
        assert result["authenticated_declared_counts"]["written"] == 4


def test_short_authentic_witness_is_positive_prefix_not_final_coverage():
    value, policy, _, c = fixture()
    tip = c["prefix_checkpoint"]
    value["anchors"] = anchors(policy, tip)
    c["witness_boundary"] = dict(
        source_checkpoint=tip, anchor_checkpoint=anchor_checkpoint(value["anchors"])
    )
    rewrite_control(value, c)
    result = evaluate(value)
    unqualified(result)
    assert result["witnessed_source_checkpoint"] == tip
    assert result["original_anchor_tip"] == c["witness_boundary"]["anchor_checkpoint"]
    assert result["authenticated_declared_counts"]["produced"] == 4
    assert result["legs"]["end_witnessed"] is False


@pytest.mark.parametrize("leg", ["trust", "registration", "controller"])
@pytest.mark.parametrize(
    "fault", ["duplicate", "nonfinite", "noncanonical", "missing", "bounds"]
)
def test_json_originals_are_strict_bounded_and_never_repaired(leg, fault):
    value, _, _, _ = fixture()
    if fault == "duplicate":
        value[leg] = b'{"schema_version":"a","schema_version":"b"}'
    elif fault == "nonfinite":
        value[leg] = b'{"x":NaN}'
    elif fault == "noncanonical":
        value[leg] += b"\n"
    elif fault == "missing":
        value[leg] = None
    elif fault == "bounds":
        value[leg] = b"x" * (annex.MAXIMUM + 1)
    unqualified(evaluate(value))


def test_pure_analysis_does_no_io_and_leaves_all_originals_immutable(monkeypatch):
    import builtins
    import os
    import socket
    import subprocess

    value, _, _, _ = fixture()
    before = deepcopy(value)

    def forbidden(*args, **kwargs):
        raise AssertionError("pure evaluation attempted I/O")

    for target, name in (
        (builtins, "open"),
        (Path, "open"),
        (Path, "read_bytes"),
        (os, "open"),
        (os, "write"),
        (os, "fsync"),
        (socket, "socket"),
        (subprocess, "Popen"),
    ):
        monkeypatch.setattr(target, name, forbidden)
    result = evaluate(value)
    assert result["finite_accounting_verified"] is True, result["reasons"]
    assert value == before


@pytest.mark.parametrize(
    "fault",
    [
        "missing_counter",
        "removed_end_profile",
        "switched_end_profile",
        "missing_start_profile",
        "wrong_key",
        "wrong_scope",
        "sequence_gap",
    ],
)
def test_invalid_signed_session_never_supplies_final_accounting(fault):
    value, policy, events, _ = fixture()
    if fault == "missing_counter":
        del events[-1]["capture_lifecycle"]["counts"]["produced"]
    elif fault == "removed_end_profile":
        events[-1]["capture_lifecycle"] = {"state": "end"}
    elif fault == "switched_end_profile":
        events[-1]["capture_lifecycle"]["accounting_profile"] = "v2"
    elif fault == "missing_start_profile":
        events[1]["capture_lifecycle"] = {"state": "start"}
    value["source"] = source_bytes(policy, events)
    if fault in ("wrong_key", "wrong_scope", "sequence_gap"):
        lines = value["source"].splitlines(keepends=True)
        row = json.loads(lines[-1])
        core = {k: v for k, v in row.items() if k != "signature"}
        if fault == "wrong_scope":
            core["scope_ref"] = "other-scope"
        if fault == "sequence_gap":
            core["seq"] += 1
        lines[-1] = signed(policy, KEYS[0] if fault == "wrong_key" else KEYS[1], **core)
        value["source"] = b"".join(lines)
    result = evaluate(value)
    unqualified(result)
    assert result["authenticated_full_source"] is False
    if fault != "missing_start_profile":
        assert result["authenticated_prefix"] is True
        assert result["known_activity_count"] == 4


@pytest.mark.parametrize(
    "field,bad",
    [
        ("producer_public_key", "e" * 64),
        ("scope_ref", "other"),
        ("stream_ref", "other"),
        ("binary_sha256", "not-a-hash"),
        ("schema_version", "outcome-live-origin-registration/v1"),
        ("native_apparmor_profile", "edge400-capture"),
    ],
)
def test_repinning_replaced_registration_cannot_replace_original_policy_binding(
    field, bad
):
    value, _, _, _ = fixture()
    registration = json.loads(value["registration"])
    registration[field] = bad
    value["registration"] = _json(registration)
    result = evaluate(value)
    unqualified(result)
    assert result["legs"]["registration"] is False
    assert result["authenticated_full_source"] is True
    assert result["original_source_tip"] is not None


@pytest.mark.parametrize("bad", [None, {}, {"source_sha256": "f" * 64}, "pins"])
def test_external_exact_pin_envelope_is_mandatory(bad):
    value, _, _, _ = fixture()
    result = annex.evaluate_native_source_accounting(
        *(
            value[k]
            for k in ("trust", "registration", "source", "anchors", "controller")
        ),
        expected=bad,
    )
    unqualified(result)
    assert "expected_pin_envelope" in result["reasons"]


@pytest.mark.parametrize("leg", ["source", "anchors"])
@pytest.mark.parametrize("fault", ["rows", "bytes"])
def test_source_and_anchor_bounds_precede_unbounded_replay(leg, fault):
    value, _, _, _ = fixture()
    value[leg] = (
        b"\n" * (annex.ROWS + 1) if fault == "rows" else b"x" * (annex.MAXIMUM + 1)
    )
    result = evaluate(value)
    unqualified(result)
    if fault == "bytes":
        assert result["raw_sha256"][leg] is None


def test_prior_clean_history_remains_intact_when_selecting_restart_session():
    value, policy, events, c = fixture("restart-one")
    _, _, earlier, _ = fixture("normal-four")
    earlier = deepcopy(earlier)
    for event in earlier:
        event["capture_origin"]["session_ref"] = "a" * 32
    value["source"] = source_bytes(policy, earlier + events)
    tip = SourceVerifier(policy).verify(value["source"])
    c["checkpoint"] = tip
    prefix = b"".join(value["source"].splitlines(keepends=True)[:-1])
    c["prefix_checkpoint"] = SourceVerifier(policy).verify(prefix)
    value["anchors"] = anchors(policy, tip)
    c["witness_boundary"] = dict(
        source_checkpoint=tip, anchor_checkpoint=anchor_checkpoint(value["anchors"])
    )
    for key in ("source_before", "source_after"):
        c["reader"][key]["size"] = len(value["source"])
    c["reader"].update(bytes_read=len(value["source"]), sha256=digest(value["source"]))
    rewrite_control(value, c)
    result = evaluate(value)
    assert result["finite_accounting_verified"] is True, result["reasons"]
    assert result["known_activity_count"] == 1
    assert result["known_sids"] == [90121006]
    assert result["original_source_tip"] == tip


def rebind_synthetic_chain(
    value, policy, events, control, *, registration=None, roles=None
):
    """Re-sign every affected fixture binding so a target validation leg is reached."""
    registration = (
        json.loads(value["registration"]) if registration is None else registration
    )
    value["registration"] = _json(registration)
    data = {
        **dict(policy.data),
        "origin_registration_sha256": digest(value["registration"]),
    }
    if roles:
        data.update(roles)
    policy = TrustPolicy(data)
    value["trust"] = _json(dict(policy.data))
    for event in events:
        event["capture_origin"]["registration_sha256"] = policy.data[
            "origin_registration_sha256"
        ]
    value["source"] = source_bytes(policy, events)
    tip = SourceVerifier(policy).verify(value["source"])
    prefix = b"".join(value["source"].splitlines(keepends=True)[:-1])
    control.update(
        registration_sha256=digest(value["registration"]),
        trust_sha256=policy.digest,
        prefix_checkpoint=SourceVerifier(policy).verify(prefix),
        checkpoint=tip,
    )
    producer, observer = policy.data["producer_uid"], policy.data["observer_uid"]
    control["source_identity"]["owner_uid"] = producer
    control["receiver"].update(
        uid=producer,
        gid=producer,
        apparmor_label=registration["capture_apparmor_profile"] + " (enforce)",
    )
    control["native"]["apparmor_label"] = (
        registration["native_apparmor_profile"] + " (enforce)"
    )
    control["reader"]["actor"].update(uid=observer, gid=observer)
    for key in ("source_before", "source_after"):
        control["reader"][key].update(owner_uid=producer, size=len(value["source"]))
    control["reader"].update(
        bytes_read=len(value["source"]), sha256=digest(value["source"])
    )
    value["anchors"] = anchors(policy, tip)
    control["witness_boundary"] = dict(
        source_checkpoint=tip, anchor_checkpoint=anchor_checkpoint(value["anchors"])
    )
    rewrite_control(value, control)
    return policy


@pytest.mark.parametrize(
    "fault",
    [
        "applied",
        "enforced",
        "executed",
        "dry_run_off",
        "enforce_on",
        "high_impact_on",
        "wrong_mode_result",
    ],
)
def test_authentic_provider_action_or_unsafe_posture_is_not_the_frozen_no_action_case(
    fault,
):
    value, policy, events, control = fixture()
    event = events[2]
    if fault == "applied":
        event["enforcement"]["result"] = "applied"
    elif fault == "enforced":
        event["enforcement"]["mode"] = "enforced"
    elif fault == "executed":
        event["enforcement"]["executed_count"] = 1
    elif fault == "dry_run_off":
        event["enforcement_status"]["dry_run"] = False
    elif fault == "enforce_on":
        event["enforcement_status"]["enforce_enabled"] = True
    elif fault == "high_impact_on":
        event["enforcement_status"]["high_impact_auto"] = True
    elif fault == "wrong_mode_result":
        event["enforcement"]["result"] = "planned_not_applied"
    policy = rebind_synthetic_chain(value, policy, events, control)
    result = evaluate(value)
    unqualified(result)
    assert result["authenticated_full_source"] is True
    assert result["original_source_tip"] == SourceVerifier(policy).verify(
        value["source"]
    )
    assert result["known_activity_count"] == 4
    assert result["authenticated_declared_counts"]["produced"] == 4
    assert result["legs"]["finite_counts"] is False
    assert any(
        "no_action_case_provider_controls" in reason for reason in result["reasons"]
    )


@pytest.mark.parametrize(
    "fault",
    [
        "unconfined",
        "dot_profile",
        "dash_profile",
        "other_profile",
        "same_profiles",
        "binary_NUL",
        "binary_relative",
        "binary_dotdot",
        "env_relative",
        "env_dotdot",
        "env_Source_alias",
        "env_journal_alias",
        "env_anchor_alias",
        "env_NUL",
    ],
)
def test_resigned_exact_registration_still_requires_fixed_profiles_and_safe_recorded_paths(
    fault,
):
    value, policy, events, control = fixture()
    registration = json.loads(value["registration"])
    if fault in ("unconfined", "dot_profile", "dash_profile", "other_profile"):
        registration["native_apparmor_profile"] = {
            "unconfined": "unconfined",
            "dot_profile": ".edge400-native",
            "dash_profile": "-edge400-native",
            "other_profile": "other-native",
        }[fault]
    elif fault == "same_profiles":
        registration["capture_apparmor_profile"] = registration[
            "native_apparmor_profile"
        ]
    elif fault == "binary_NUL":
        registration["binary_path"] = "/synthetic/core\x00hidden"
    elif fault == "binary_relative":
        registration["binary_path"] = "synthetic/core"
    elif fault == "binary_dotdot":
        registration["binary_path"] = "/synthetic/../core"
    else:
        registration["environment"]["AZAZEL_EVE_PATH"] = {
            "env_relative": "synthetic/eve",
            "env_dotdot": "/synthetic/../eve",
            "env_Source_alias": policy.data["source_path"],
            "env_journal_alias": str(
                Path(policy.data["journal_directory"]) / "observations.journal"
            ),
            "env_anchor_alias": str(
                Path(policy.data["anchor_directory"]) / "anchors.journal"
            ),
            "env_NUL": "/synthetic/eve\x00hidden",
        }[fault]
    policy = rebind_synthetic_chain(
        value, policy, events, control, registration=registration
    )
    result = evaluate(value)
    unqualified(result)
    assert result["legs"]["registration"] is False
    assert result["legs"]["controller"] is True
    assert result["authenticated_full_source"] is True
    assert result["original_source_tip"] == SourceVerifier(policy).verify(
        value["source"]
    )
    assert result["known_activity_count"] == 4
    assert result["authenticated_declared_counts"]["written"] == 4


@pytest.mark.parametrize("role", ["producer_uid", "observer_uid"])
def test_self_consistent_forged_role_receipts_cannot_replace_fixed_ci_roles(role):
    value, policy, events, control = fixture()
    policy = rebind_synthetic_chain(value, policy, events, control, roles={role: 61011})
    # The independently valid original Source verifier still knows its facts.
    assert SourceVerifier(policy).verify(value["source"]) == control["checkpoint"]
    result = evaluate(value)
    unqualified(result)
    assert result["legs"]["trust"] is False
    assert any("live_Root_CI_roles_required" in reason for reason in result["reasons"])


@pytest.mark.parametrize("mode", ["dry_run", "policy_gated"])
def test_other_actual_no_action_provider_mode_result_pairs_keep_finite_accounting(mode):
    value, policy, events, control = fixture()
    for event in events:
        if event["capture_origin"]["kind"] == "decision_execution":
            event["enforcement"].update(mode=mode, result="planned_not_applied")
    rebind_synthetic_chain(value, policy, events, control)
    result = evaluate(value)
    assert result["finite_accounting_verified"] is True, result["reasons"]
    assert result["qualified_counts"]["produced"] == 4
    assert result["local_finish_acknowledged"] is None
    assert not any(result["authority_flags"].values())
