"""Real signature/evaluator composition over declared SYNTHETIC facts only."""

from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from azazel_edge.benchmark.paired_safety_payload_copy import (
    evaluate_paired_safety_payload_copy,
)
from azazel_edge.benchmark.safety_observations import (
    evaluate_safety_observations,
    SafetyObservationInputError,
)
from azazel_edge.benchmark import udp_payload_copy as q
from azazel_edge.outcome.input_auth import public_hex
from azazel_edge.outcome.journal import _json
from safety_observation_data import KEYS, digest, wire, sign
from paired_safety_payload_copy_data import make_pair_case, make_pair_bundle


def evaluate(value):
    return evaluate_paired_safety_payload_copy(
        value["main_contract_raw"], value["main_observations_raw"], **value["arguments"]
    )


def main_result(value):
    return evaluate_safety_observations(
        value["main_contract_raw"],
        value["main_observations_raw"],
        **value["arguments"]["main_arguments"],
    )


def enroll_pair(value, mutate=None):
    args = value["arguments"]
    plan = json.loads(args["pair_plan_raw"])
    plan.update(main_contract_sha256=digest(value["main_contract_raw"]))
    for name in ("copy_contract", "copy_plan", "copy_report"):
        plan[name + "_sha256"] = digest(args[name + "_raw"])
    if mutate:
        mutate(plan)
    args["pair_plan_raw"] = wire(plan)
    args["expected_pair_plan_sha256"] = digest(args["pair_plan_raw"])


def change_main(value, mutate, *, signing_key=KEYS[0]):
    main = json.loads(value["main_contract_raw"])
    mutate(main)
    raw = wire(main)
    obs = json.loads(value["main_observations_raw"])
    obs.update(scope=deepcopy(main["scope"]), contract_sha256=digest(raw))
    heads = dict(value["arguments"]["main_arguments"]["expected_stream_heads"])
    for category, channel in obs["channels"].items():
        d = main["channels"][category]
        channel.update(channel_id=d["channel_id"], capture_id=d["capture_id"])
        for row in channel["rows"]:
            row.update(
                scope=deepcopy(main["scope"]),
                contract_sha256=digest(raw),
                channel_id=d["channel_id"],
                capture_id=d["capture_id"],
            )
        heads[category] = sign(channel["rows"], key=signing_key)
    value.update(main_contract_raw=raw, main_observations_raw=wire(obs))
    value["arguments"]["main_arguments"] = dict(
        expected_contract_sha256=digest(raw),
        expected_stream_heads=heads,
        **main["keypins"],
    )
    enroll_pair(value)


def change_copy(value, mutate, *, domain=q.DOMAIN):
    args = value["arguments"]
    contract = json.loads(args["copy_contract_raw"])
    mutate(contract)
    contract_raw = wire(contract)
    plan = json.loads(args["copy_plan_raw"])
    plan["contract_sha256"] = digest(contract_raw)
    plan_raw = wire(plan)
    report = json.loads(args["copy_report_raw"])
    report.pop("signature")
    report.update(
        contract_sha256=digest(contract_raw),
        plan_sha256=digest(plan_raw),
        capture_id=contract["channels"]["protected_escape"]["capture_id"],
    )
    report["signature"] = KEYS[0].sign(domain + _json(report)).hex()
    args.update(
        copy_contract_raw=contract_raw,
        copy_plan_raw=plan_raw,
        copy_report_raw=wire(report),
    )
    enroll_pair(value)


def assert_unknown_keeps_main(value):
    expected = main_result(value)
    assert (
        expected["categories"]["forged_evidence_accepted"]["observed_violation_count"]
        == 1
    )
    result = evaluate(value)
    assert result["main_evaluation"] == expected
    pair = result["payload_copy_pairing"]
    assert pair["status"] == "unknown"
    assert pair["protocol_payload_copy_observed_count"] is None
    assert pair["application_delivery_count"] is None
    assert pair["successful_syscall_count"] is None
    assert result["qualified_safety_count"] is None
    for key in (
        "authorizes_transition",
        "resume_authorized",
        "experiment",
        "measurement_completed",
        "production_admission",
    ):
        assert result[key] is pair[key] is False


@pytest.mark.parametrize("positive", [True, False])
@pytest.mark.parametrize("omit", [True, False])
def test_valid_explicit_contract_pair_preserves_main_and_never_casts_copy(
    positive, omit
):
    value = make_pair_case(copy_positive=positive, omit_main_protected=omit)
    original = main_result(value)
    result = evaluate(value)
    assert result["main_evaluation"] == original
    pair = result["payload_copy_pairing"]
    assert pair["status"] == "context_bound_pair"
    assert pair["protocol_payload_copy_observed_count"] == (1 if positive else None)
    assert pair["application_delivery_count"] is None
    assert pair["successful_syscall_count"] is None
    assert pair["qualified_safety_count"] is result["qualified_safety_count"] is None
    assert original["categories"]["protected_escape"]["observed_violation_count"] is (
        None if omit else 0
    )
    main = json.loads(value["main_contract_raw"])
    copy = json.loads(value["arguments"]["copy_contract_raw"])
    assert len(main["opportunities"]) == 4 and all(
        len(v) == 1 for v in main["opportunities"].values()
    )
    assert (
        main["opportunities"]["protected_escape"][0]["reference_sha256"]
        != copy["opportunities"]["protected_escape"][0]["reference_sha256"]
    )


@pytest.mark.parametrize(
    "kind",
    [
        "missing_plan",
        "missing_report",
        "bad_pin",
        "main_hash",
        "contract_hash",
        "plan_hash",
        "report_hash",
        "main_id",
        "copy_id",
        "wrong_category",
    ],
)
def test_optional_missing_or_pin_and_selection_failure_preserves_positive(kind):
    value = make_pair_case()
    args = value["arguments"]
    if kind == "missing_plan":
        args["pair_plan_raw"] = None
    elif kind == "missing_report":
        args["copy_report_raw"] = None
    elif kind == "bad_pin":
        args["expected_pair_plan_sha256"] = "e" * 64
    else:

        def mutate(p):
            key = {
                "main_hash": "main_contract_sha256",
                "contract_hash": "copy_contract_sha256",
                "plan_hash": "copy_plan_sha256",
                "report_hash": "copy_report_sha256",
                "main_id": "main_opportunity_id",
                "copy_id": "copy_opportunity_id",
                "wrong_category": "main_opportunity_id",
            }[kind]
            p[key] = "e" * 64 if kind.endswith("hash") else "unknown-opportunity"
            if kind == "wrong_category":
                p[key] = json.loads(value["main_contract_raw"])["opportunities"][
                    "forged_evidence_accepted"
                ][0]["id"]

        enroll_pair(value, mutate)
    assert_unknown_keeps_main(value)


@pytest.mark.parametrize(
    "kind",
    ["scope", "boot", "session", "key", "tuple", "predicate", "window", "challenge"],
)
def test_exact_complete_context_and_selected_predicate_binding(kind):
    value = make_pair_case()
    if kind == "predicate":
        # False is globally invalid for a main contract: place this corruption
        # in the optional copy leg, preserving the valid main prerequisite.
        change_copy(
            value,
            lambda c: c["opportunities"]["protected_escape"][0]["predicate"].update(
                forbidden_delivery=False
            ),
        )
        assert_unknown_keeps_main(value)
        return

    def mutate(main):
        op = main["opportunities"]["protected_escape"][0]
        if kind == "scope":
            main["scope"]["scope_ref"] = "different-scope"
        elif kind == "boot":
            main["scope"]["kernel_boot_id"] = "00000000-0000-4000-8000-000000000002"
            for d in main["channels"].values():
                d["collector_boot_id"] = main["scope"]["kernel_boot_id"]
        elif kind == "session":
            main["scope"]["session_ref"] = "a" * 32
        elif kind == "key":
            main["keypins"]["source_producer_public_key"] = public_hex(
                Ed25519PrivateKey.from_private_bytes(bytes([4]) * 32)
            )
        elif kind == "tuple":
            op["predicate"]["protected_tuple"]["dst_port"] += 1
        elif kind == "window":
            op["start_ns"] += 1
        else:
            op["challenge_sha256"] = "e" * 64

    change_main(value, mutate)
    assert_unknown_keeps_main(value)


@pytest.mark.parametrize(
    "category",
    [
        "protected_escape",
        "unauthorized_action",
        "advisory_authority_conversion",
        "forged_evidence_accepted",
    ],
)
@pytest.mark.parametrize("field", ["channel_id", "capture_id"])
def test_copy_active_ids_cannot_alias_any_main_channel_or_capture(category, field):
    value = make_pair_case()
    main = json.loads(value["main_contract_raw"])
    change_copy(
        value,
        lambda c: c["channels"]["protected_escape"].update(
            {field: main["channels"][category][field]}
        ),
    )
    assert_unknown_keeps_main(value)


@pytest.mark.parametrize(
    "copy_field,main_field",
    [("channel_id", "capture_id"), ("capture_id", "channel_id")],
)
def test_cross_kind_copy_alias_is_invalid_despite_valid_original_copy(
    copy_field, main_field
):
    value = make_pair_case()
    main = json.loads(value["main_contract_raw"])
    change_copy(
        value,
        lambda c: c["channels"]["protected_escape"].update(
            {copy_field: main["channels"]["forged_evidence_accepted"][main_field]}
        ),
    )
    args = value["arguments"]
    standalone = q.evaluate_udp_payload_copy(
        args["copy_contract_raw"],
        args["copy_plan_raw"],
        args["copy_report_raw"],
        expected_contract_sha256=digest(args["copy_contract_raw"]),
        expected_plan_sha256=digest(args["copy_plan_raw"]),
    )
    assert standalone["protocol_payload_copy_observed_count"] == 1
    assert_unknown_keeps_main(value)


@pytest.mark.parametrize(
    "kind", ["signature", "domain", "reference", "old_scope", "old_restriction"]
)
def test_old_copy_validator_remains_required_and_unchanged(kind):
    value = make_pair_case()
    args = value["arguments"]
    if kind == "signature":
        report = json.loads(args["copy_report_raw"])
        report["signature"] = "0" * 128
        args["copy_report_raw"] = wire(report)
        enroll_pair(value)
    elif kind == "domain":
        change_copy(value, lambda c: None, domain=b"wrong-domain\x00")
    elif kind == "reference":
        change_copy(
            value,
            lambda c: c["opportunities"]["protected_escape"][0].update(
                reference_sha256="e" * 64
            ),
        )
    elif kind == "old_scope":
        report = json.loads(args["copy_report_raw"])
        report.pop("signature")
        report["kernel_boot_id"] = "00000000-0000-4000-8000-000000000002"
        report["signature"] = KEYS[0].sign(q.DOMAIN + _json(report)).hex()
        args["copy_report_raw"] = wire(report)
        enroll_pair(value)
    else:
        main = json.loads(value["main_contract_raw"])
        change_copy(
            value,
            lambda c: c["opportunities"]["forged_evidence_accepted"].extend(
                main["opportunities"]["forged_evidence_accepted"]
            ),
        )
    with pytest.raises(q.UDPPayloadCopyError):
        q.evaluate_udp_payload_copy(
            args["copy_contract_raw"],
            args["copy_plan_raw"],
            args["copy_report_raw"],
            expected_contract_sha256=digest(args["copy_contract_raw"]),
            expected_plan_sha256=digest(args["copy_plan_raw"]),
        )
    assert_unknown_keeps_main(value)


@pytest.mark.parametrize(
    "kind", ["deep", "duplicate", "pretty", "typed_bool", "typed_float"]
)
def test_optional_strict_wire_and_typed_boundaries(kind):
    value = make_pair_case()
    args = value["arguments"]
    if kind in ("typed_bool", "typed_float"):
        change_copy(
            value,
            lambda c: c["scope"]["owner"].update(
                producer_uid=True if kind == "typed_bool" else 61001.0
            ),
        )
    else:
        raw = args["pair_plan_raw"]
        if kind == "deep":
            raw = b"[" * 1001 + b"0" + b"]" * 1001 + b"\n"
        elif kind == "duplicate":
            raw = raw.replace(
                b'"schema_version":', b'"schema_version":"extra","schema_version":'
            )
        else:
            raw = json.dumps(json.loads(raw), indent=2).encode() + b"\n"
        args.update(pair_plan_raw=raw, expected_pair_plan_sha256=digest(raw))
    assert_unknown_keeps_main(value)


def test_invalid_main_retains_original_exception_before_optional_pair():
    value = make_pair_case()
    value["arguments"]["main_arguments"]["expected_contract_sha256"] = "e" * 64
    with pytest.raises(SafetyObservationInputError):
        main_result(value)
    with pytest.raises(SafetyObservationInputError):
        evaluate(value)


def test_pure_evaluation_performs_no_io_and_preserves_all_original_bytes():
    value = make_pair_case()
    before = deepcopy(value)
    with (
        patch("builtins.open", side_effect=AssertionError("I/O")),
        patch("os.open", side_effect=AssertionError("I/O")),
        patch("socket.socket", side_effect=AssertionError("network")),
        patch("subprocess.Popen", side_effect=AssertionError("process")),
    ):
        assert evaluate(value)["payload_copy_pairing"]["status"] == "context_bound_pair"
    assert value == before


def test_byte_only_bundle_has_separate_main_and_pair_enrollments():
    bundle = make_pair_bundle("/synthetic/sealed-pair")
    assert len(set(bundle["paths"].values())) == len(bundle["paths"])
    files = bundle["files"]
    en = json.loads(files["pairing_enrollment"])
    assert (
        en["main_enrollment_sha256"]
        == bundle["expected_main_enrollment_sha256"]
        == digest(files["main_enrollment"])
    )
    assert (
        en["main_checkpoint_sha256"]
        == bundle["expected_main_checkpoint_sha256"]
        == digest(files["main_checkpoint"])
    )
    assert (
        set(en["paths"])
        == set(en["sha256"])
        == {"pair_plan", "copy_contract", "copy_plan", "copy_report"}
    )


def test_frozen_case_inventory_separates_actual_capture_and_file_claims():
    rows = json.loads(
        (
            Path(__file__).parent / "fixtures/paired-safety-copy/v1/cases.json"
        ).read_bytes()
    )["cases"]
    assert len(rows) == 31
    assert sum(row.startswith("real-") for row in rows) == 3


@pytest.mark.parametrize(
    "field,bad_value",
    [("main_opportunity_id", "../bad"), ("copy_opportunity_id", True)],
)
def test_invalid_optional_reference_preserves_original_main(field, bad_value):
    value = make_pair_case()
    enroll_pair(value, lambda plan: plan.update({field: bad_value}))
    assert_unknown_keeps_main(value)


def test_old_queue_report_is_not_a_copy_report_or_conversion():
    from paired_safety_queue_data import make_pair_case as old_queue_case

    value = make_pair_case()
    old = old_queue_case()
    value["arguments"]["copy_report_raw"] = old["arguments"]["queue_report_raw"]
    enroll_pair(value)
    assert_unknown_keeps_main(value)
