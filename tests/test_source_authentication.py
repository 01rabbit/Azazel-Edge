"""Real synthetic Source signatures and checkpoints; no execution/recovery proof."""

from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from azazel_edge.benchmark.source_authentication import (
    verify_source_bytes,
    SourceAuthenticationInputError,
)
from azazel_edge.outcome.input_auth import SourceVerifier
from safety_observation_data import digest, wire
from source_recovery_data import make_source_case

FROZEN = json.loads(
    (Path(__file__).parent / "fixtures/source-recovery/v1/cases.json").read_bytes()
)["cases"]
SOURCE_CASES = [row for row in FROZEN if row["id"].startswith("source_")]


def verify(value):
    return verify_source_bytes(
        value["trust_raw"], value["source_raw"], **value["arguments"]
    )


@pytest.mark.parametrize("expected", SOURCE_CASES, ids=lambda row: row["id"])
def test_frozen_source_cases_real_existing_verifier_and_external_checkpoints(
    tmp_path, expected
):
    fixture = make_source_case(tmp_path, expected["id"])
    originals = (
        fixture["trust_raw"],
        fixture["source_raw"],
        deepcopy(fixture["arguments"]),
    )
    if expected["expected"] == "input_error":
        with pytest.raises(SourceAuthenticationInputError):
            verify(fixture)
    else:
        result = verify(fixture)
        assert result["schema_version"] == "edge-source-byte-diagnostic/v1"
        assert result["qualified_safety_count"] is None
        assert all(
            result[key] is False
            for key in (
                "authorizes_transition",
                "resume_authorized",
                "experiment",
                "measurement_completed",
                "production_admission",
            )
        )
        if expected["expected"] in (
            "full_and_terminal",
            "full_no_terminal",
            "full_auth",
        ):
            assert (
                result["authenticated_prefix"]
                is result["authenticated_full_source"]
                is True
            )
            assert result["normal_terminal_verified"] is (
                expected["expected"] != "full_no_terminal"
            )
            assert (
                result["prefix_tip"]
                == fixture["arguments"]["expected_prefix_checkpoint"]
            )
            assert (
                result["final_tip"] == fixture["arguments"]["expected_final_checkpoint"]
            )
        elif expected["expected"] == "no_auth":
            assert (
                result["authenticated_prefix"]
                is result["authenticated_full_source"]
                is result["normal_terminal_verified"]
                is False
            )
        else:
            assert (
                result["authenticated_full_source"]
                is result["normal_terminal_verified"]
                is False
            )
            assert result["authenticated_prefix"] is True
            assert (
                result["prefix_tip"]
                == fixture["arguments"]["expected_prefix_checkpoint"]
            )
            assert result["final_tip"] is None
        if expected["id"] == "source_finite_float":
            event = json.loads(fixture["source_raw"].splitlines()[2])["event"]
            assert isinstance(
                event["enforcement"]["metadata"]["release_due_epoch"], float
            )
        assert result == verify(fixture)
    assert (
        fixture["trust_raw"],
        fixture["source_raw"],
        fixture["arguments"],
    ) == originals


@pytest.mark.parametrize(
    "fault",
    [
        "trust-pin",
        "trust-duplicate",
        "trust-pretty",
        "trust-extra",
        "legacy-policy",
        "context-extra",
        "context-bool",
        "context-session-format",
        "context-boot-format",
        "prefix-bool",
        "final-extra",
        "source-type",
    ],
)
def test_malformed_global_inputs_never_produce_an_authentication_result(
    tmp_path, fault
):
    fixture = make_source_case(tmp_path)
    arguments = fixture["arguments"]
    if fault == "trust-pin":
        arguments["expected_trust_sha256"] = "x" * 64
    elif fault in ("trust-duplicate", "trust-pretty", "trust-extra", "legacy-policy"):
        value = json.loads(fixture["trust_raw"])
        if fault == "trust-extra":
            value["unexpected"] = True
        elif fault == "legacy-policy":
            value.pop("origin_registration_sha256")
            value["schema_version"] = "outcome-input-trust/v1"
        raw = wire(value)
        if fault == "trust-pretty":
            raw = json.dumps(value, indent=2).encode() + b"\n"
        elif fault == "trust-duplicate":
            raw = raw.replace(
                b'{"anchor_directory":',
                b'{"schema_version":"duplicate","anchor_directory":',
                1,
            )
        fixture["trust_raw"] = raw
        arguments["expected_trust_sha256"] = digest(raw)
    elif fault == "context-extra":
        arguments["expected_context"]["approved"] = True
    elif fault == "context-bool":
        arguments["expected_context"]["producer_uid"] = True
    elif fault == "context-session-format":
        arguments["expected_context"]["session_ref"] = "invalid"
    elif fault == "context-boot-format":
        arguments["expected_context"]["boot_ref"] = "INVALID"
    elif fault == "prefix-bool":
        arguments["expected_prefix_checkpoint"]["seq"] = True
    elif fault == "final-extra":
        arguments["expected_final_checkpoint"]["approved"] = True
    else:
        fixture["source_raw"] = "not-bytes"
    with pytest.raises(SourceAuthenticationInputError):
        verify(fixture)


@pytest.mark.parametrize("missing", ["prefix", "final", "both"])
def test_missing_external_checkpoint_never_promotes_old_signed_bytes(tmp_path, missing):
    fixture = make_source_case(tmp_path)
    if missing in ("prefix", "both"):
        fixture["arguments"]["expected_prefix_checkpoint"] = None
    if missing in ("final", "both"):
        fixture["arguments"]["expected_final_checkpoint"] = None
    result = verify(fixture)
    assert (
        result["authenticated_full_source"] is False
        and result["normal_terminal_verified"] is False
    )
    assert result["authenticated_prefix"] is (missing == "final")
    assert result["final_tip"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "prefix-head",
        "prefix-size",
        "prefix-empty",
        "prefix-signature",
        "first-boot",
        "first-session",
        "key-pin",
    ],
)
def test_unverified_prefix_cannot_supply_full_authentication_even_with_final_pin(
    tmp_path, fault
):
    fixture = make_source_case(tmp_path)
    if fault == "prefix-head":
        fixture["arguments"]["expected_prefix_checkpoint"]["head"] = "e" * 64
    elif fault == "prefix-size":
        fixture["arguments"]["expected_prefix_checkpoint"]["size"] -= 1
    elif fault == "prefix-empty":
        fixture["arguments"]["expected_prefix_checkpoint"] = SourceVerifier(
            fixture["trust"]
        ).tip()
    elif fault == "prefix-signature":
        fixture["source_raw"] = fixture["source_raw"].replace(
            b'"signature":"', b'"signature":"0', 1
        )
    elif fault == "first-boot":
        fixture["arguments"]["expected_context"]["boot_ref"] = "a" * 32
    elif fault == "first-session":
        fixture["arguments"]["expected_context"]["session_ref"] = "a" * 32
    else:
        # Well-shaped expected context differing from policy is a global enrollment error.
        fixture["arguments"]["expected_context"]["producer_public_key"] = "a" * 64
        with pytest.raises(SourceAuthenticationInputError):
            verify(fixture)
        return
    result = verify(fixture)
    assert (
        result["authenticated_prefix"]
        is result["authenticated_full_source"]
        is result["normal_terminal_verified"]
        is False
    )
    assert result["prefix_tip"] is result["final_tip"] is None


def test_byte_authentication_performs_no_files_processes_network_or_witness_access(
    tmp_path,
):
    fixture = make_source_case(tmp_path)
    before = fixture["trust_raw"], fixture["source_raw"], deepcopy(fixture["arguments"])
    with (
        patch("builtins.open", side_effect=AssertionError("file access")),
        patch("socket.socket", side_effect=AssertionError("endpoint")),
        patch("subprocess.Popen", side_effect=AssertionError("execution")),
        patch("os.open", side_effect=AssertionError("file access")),
    ):
        result = verify(fixture)
    assert result["authenticated_full_source"] is True
    assert result["normal_terminal_verified"] is True
    assert (fixture["trust_raw"], fixture["source_raw"], fixture["arguments"]) == before
