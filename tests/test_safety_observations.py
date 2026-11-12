"""Frozen real-signature synthetic recipes; no independent sensor/runtime claim."""

from copy import deepcopy
import hashlib
import json
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from azazel_edge.benchmark.safety_observations import (
    SafetyObservationInputError,
    evaluate_safety_observations,
)
from azazel_edge.outcome.input_auth import verify_signature
from azazel_edge.outcome.journal import _json
from safety_observation_data import (
    ROOT,
    HASHES,
    DOMAIN,
    KEYS,
    build,
    digest,
    frozen,
    sign,
    wire,
)

CONTRACT, CORPUS, EXPECTED = frozen()


def evaluate(case_id):
    contract, observations, arguments = build(case_id)
    return evaluate_safety_observations(contract, observations, **arguments)


@pytest.mark.parametrize("expected", EXPECTED["cases"], ids=lambda row: row["id"])
def test_all_frozen_recipes_match_independent_fixed_expectations(expected):
    contract, observations, arguments = build(expected["id"])
    originals = contract, observations, deepcopy(arguments)
    if expected["outcome"] == "input_rejected":
        with pytest.raises(SafetyObservationInputError):
            evaluate_safety_observations(contract, observations, **arguments)
    else:
        result = evaluate_safety_observations(contract, observations, **arguments)
        assert result["status"] == expected["outcome"]
        for field in (
            "independently_measured",
            "qualified_safety_count",
            "source_authentication_performed",
            "cleanup_status",
            "authority_flags",
        ):
            assert result[field] == expected[field]
        for category, fields in expected["categories"].items():
            actual = result["categories"][category]
            assert {key: actual[key] for key in fields} == fields
            assert actual["qualified_safety_count"] is None
            assert actual["independently_measured"] is False
            if fields["observed_violation_count"]:
                assert actual["observed_violation_rows"]
        assert result == evaluate_safety_observations(
            contract, observations, **arguments
        )
    assert (contract, observations, arguments) == originals


def test_frozen_bytes_public_test_keypins_and_canonical_signature_domains():
    for name, expected in HASHES.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected
    assert (ROOT / "contract.json").read_bytes() == wire(CONTRACT)
    names = (
        "observer_public_key",
        "source_producer_public_key",
        "source_witness_public_key",
    )
    assert len(set(CONTRACT["keypins"].values())) == 3
    for name, key in zip(names, KEYS):
        assert (
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            == CONTRACT["keypins"][name]
        )
    _, raw, arguments = build("all-four-complete-finite-zero")
    channels = json.loads(raw)["channels"]
    for category, channel in channels.items():
        assert arguments["expected_stream_heads"][category] == digest(
            _json(channel["rows"][-1])
        )
        for row in channel["rows"]:
            verify_signature(
                CONTRACT["keypins"]["observer_public_key"],
                row["signature"],
                DOMAIN,
                {k: v for k, v in row.items() if k != "signature"},
            )


@pytest.mark.parametrize(
    "fault",
    [
        "pretty",
        "second-lf",
        "missing-lf",
        "duplicate-key",
        "utf8",
        "depth",
        "float",
        "string",
        "rows",
        "opportunities",
        "contract-hash",
        "colliding-source-witness",
    ],
)
def test_global_invalid_input_cannot_produce_a_count_or_score(fault):
    contract, observations, arguments = build("all-four-complete-finite-zero")
    if fault == "pretty":
        observations = json.dumps(json.loads(observations), indent=2).encode() + b"\n"
    elif fault == "second-lf":
        observations += b"\n"
    elif fault == "missing-lf":
        observations = observations[:-1]
    elif fault == "duplicate-key":
        observations = observations.replace(
            b'{"channels":', b'{"schema_version":"duplicate","channels":', 1
        )
    elif fault == "utf8":
        observations = b"\xff" + observations
    elif fault == "contract-hash":
        arguments["expected_contract_sha256"] = "f" * 64
    elif fault == "colliding-source-witness":
        arguments["source_witness_public_key"] = arguments["source_producer_public_key"]
    elif fault == "rows":
        value = json.loads(observations)
        channel = value["channels"]["protected_escape"]
        channel["rows"] = [channel["rows"][0]] * 4097
        observations = wire(value)
    else:
        value = json.loads(contract)
        if fault == "depth":
            nested = 0
            for _ in range(14):
                nested = [nested]
            value["unknown"] = nested
        elif fault == "float":
            value["scope"]["interval"]["start_ns"] = 1000000000.0
        elif fault == "string":
            value["scope"]["run_id"] = "a" * 257
        else:
            base = value["opportunities"]["protected_escape"][0]
            value["opportunities"]["protected_escape"] = [
                {**deepcopy(base), "id": "synthetic-many-" + str(i)} for i in range(129)
            ]
        contract = wire(value)
        arguments["expected_contract_sha256"] = digest(contract)
    with pytest.raises(SafetyObservationInputError):
        evaluate_safety_observations(contract, observations, **arguments)


def test_pure_readonly_no_execution_or_filesystem_and_caller_flags_cannot_upgrade():
    contract, observations, arguments = build("all-four-complete-finite-zero")
    with (
        patch("builtins.open", side_effect=AssertionError("file IO")),
        patch("socket.socket", side_effect=AssertionError("network")),
        patch("subprocess.Popen", side_effect=AssertionError("execution")),
        patch("os.system", side_effect=AssertionError("execution")),
    ):
        result = evaluate_safety_observations(contract, observations, **arguments)
    assert (
        result["independently_measured"] is False
        and result["qualified_safety_count"] is None
    )
    with pytest.raises(TypeError):
        evaluate_safety_observations(
            contract, observations, independently_measured=True, **arguments
        )


def test_forbidden_failed_attempt_is_known_violation_not_synthetic_success_zero():
    _, raw, _ = build("violation-unauthorized_action")
    fact = json.loads(raw)["channels"]["unauthorized_action"]["rows"][2]["data"]
    assert fact["attempt_count"] == fact["failed_count"] == 1
    result = evaluate("violation-unauthorized_action")
    assert result["categories"]["unauthorized_action"]["observed_violation_count"] == 1


def test_postgap_and_duplicate_known_facts_are_lower_bound_not_repaired_coverage():
    for case_id in (
        "gap-known-violation",
        "duplicate-conflicting-facts",
        "known-violation-partial-siblings",
    ):
        result = evaluate(case_id)["categories"]["protected_escape"]
        assert result["claimed_structural_status"] == "violations_observed"
        assert result["observed_violation_count"] == 1
        assert result["opportunities_structurally_covered"] == 0
        assert result["qualified_safety_count"] is None


@pytest.mark.parametrize("change", ["cursor", "journal", "anchor"])
def test_forged_error_with_any_persistent_change_remains_known_violation(change):
    contract, raw, arguments = build("forged-verifier-error")
    value = json.loads(raw)
    rows = value["channels"]["forged_evidence_accepted"]["rows"]
    if change == "cursor":
        rows[2]["data"]["cursor_after"] = 1
    elif change == "journal":
        rows[2]["data"]["journal_after_sha256"] = "3" * 64
    else:
        rows[2]["data"]["anchor_after_sha256"] = "3" * 64
    sign(rows)
    # This is a separately defined synthetic observation, enrolled before submission.
    arguments["expected_stream_heads"]["forged_evidence_accepted"] = digest(
        _json(rows[-1])
    )
    result = evaluate_safety_observations(contract, wire(value), **arguments)
    assert (
        result["categories"]["forged_evidence_accepted"]["observed_violation_count"]
        == 1
    )


@pytest.mark.parametrize(
    "case_id",
    [
        "wrong-signature-domain",
        "wrong-observer-signature-key",
        "wrong-scope-session-bindings",
        "replayed-other-capture",
    ],
)
def test_post_checkpoint_corruptions_never_reenroll_the_mutated_close_head(case_id):
    _, base_raw, baseline_arguments = build("all-four-complete-finite-zero")
    _, mutated_raw, arguments = build(case_id)
    assert (
        arguments["expected_stream_heads"]
        == baseline_arguments["expected_stream_heads"]
    )
    assert mutated_raw != base_raw
    mutated_close = json.loads(mutated_raw)["channels"]["protected_escape"]["rows"][-1]
    assert (
        digest(_json(mutated_close))
        != arguments["expected_stream_heads"]["protected_escape"]
    )


def test_scenario_loss_is_signed_before_heads_but_invalid_contract_is_never_repinned():
    _, raw, arguments = build("loss")
    rows = json.loads(raw)["channels"]["protected_escape"]["rows"]
    assert any(row["kind"] == "loss" for row in rows)
    assert (
        digest(_json(rows[-1]))
        == arguments["expected_stream_heads"]["protected_escape"]
    )
    for case_id in ("wrong-independent-role", "bool-as-integer"):
        corrupted_contract, _, arguments = build(case_id)
        assert digest(corrupted_contract) != arguments["expected_contract_sha256"]


@pytest.mark.parametrize("fault", ["role", "bool"])
def test_independently_pinned_but_invalid_contract_still_fails_schema(fault):
    contract, observations, arguments = build("all-four-complete-finite-zero")
    value = json.loads(contract)
    if fault == "role":
        value["channels"]["protected_escape"]["collector_uid"] = 61001
    else:
        value["opportunities"]["protected_escape"][0]["start_ns"] = True
    invalid_contract = wire(value)
    arguments["expected_contract_sha256"] = digest(invalid_contract)
    with pytest.raises(
        SafetyObservationInputError,
        match="independent role" if fault == "role" else "integer",
    ):
        evaluate_safety_observations(invalid_contract, observations, **arguments)


@pytest.mark.parametrize(
    "fault", ["extra-field", "wrong-channel-id", "wrong-capture-id"]
)
def test_unsigned_bad_channel_wrapper_cannot_erase_signed_known_violation(fault):
    contract, original, arguments = build("violation-protected_escape")
    value = json.loads(original)
    channel = value["channels"]["protected_escape"]
    signed_rows_before = _json(channel["rows"])
    if fault == "extra-field":
        channel["unsigned_extra"] = True
    elif fault == "wrong-channel-id":
        channel["channel_id"] = "synthetic-wrong-channel"
    else:
        channel["capture_id"] = "synthetic-wrong-capture"
    malformed = wire(value)
    retained_arguments = deepcopy(arguments)
    result = evaluate_safety_observations(contract, malformed, **arguments)
    category = result["categories"]["protected_escape"]
    assert category["claimed_structural_status"] == "violations_observed"
    assert category["observed_violation_count"] == 1
    assert category["observed_violation_rows"]
    assert category["opportunities_structurally_covered"] == 0
    assert category["verified_authentication"] == "partial_signed_rows"
    assert category["qualified_safety_count"] is None
    assert category["independently_measured"] is False
    assert result["status"] == "unqualified_diagnostic"
    assert all(flag is False for flag in result["authority_flags"].values())
    assert arguments == retained_arguments
    assert (
        _json(json.loads(malformed)["channels"]["protected_escape"]["rows"])
        == signed_rows_before
    )
