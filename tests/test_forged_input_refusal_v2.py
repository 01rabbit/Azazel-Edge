"""SYNTHETIC finite fault premises and metadata, real public TEST signatures."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from azazel_edge.benchmark import forged_input_refusal as f
from azazel_edge.benchmark import forged_refusal_collection as intake
from azazel_edge.benchmark import safety_collection
from azazel_edge.outcome.input_auth import public_hex, crypto
from azazel_edge.outcome.journal import _json
from safety_observation_data import KEYS
from test_forged_input_refusal import build, raw, refresh, sealed
from source_recovery_data import BOOT


def make_case(directory, kind):
    case = build(directory)
    reference = case["source"]["valid_source"].splitlines(keepends=True)[1]
    row = json.loads(reference)
    prefix = case["source"]["valid_prefix"]
    if kind == "wrong_key":
        key = KEYS[0]
    else:
        key = KEYS[1]
    if kind == "scope_mismatch":
        row["scope_ref"] = "synthetic-wrong-scope"
    elif kind == "chain_corruption":
        row["prev"] = "0" * 64
    if kind in ("wrong_key", "scope_mismatch", "chain_corruption"):
        row["signature"] = key.sign(
            f.SOURCE_DOMAIN + _json({k: v for k, v in row.items() if k != "signature"})
        ).hex()
        suffix = raw(row)
    elif kind == "replay":
        suffix = prefix.splitlines(keepends=True)[-1]
    else:
        suffix = reference[:-17]
    for phase in ("before", "after"):
        case[phase]["source"] = prefix + suffix
        refresh(case, phase, "source")
    case["reference_frame_raw"] = reference
    case["plan"]["schema_version"] = "edge-forged-input-refusal-plan/v2"
    case["plan"]["challenge"] = dict(
        kind=kind,
        reference_frame_sha256=f._sha(reference),
        challenge_public_key=public_hex(KEYS[0]) if kind == "wrong_key" else None,
        partial_bytes=len(reference) - 17 if kind == "partial_frame" else None,
    )
    case["stderr_raw"] = (
        "azazel_edge.outcome.journal.OutcomeJournalError: " + f.REASONS[kind] + "\n"
    ).encode()
    case["plan"]["worker"]["stderr_sha256"] = f._sha(case["stderr_raw"])
    return case


def evaluate(case, version=2):
    wire = raw(case["plan"])
    kwargs = {
        k: case[k] for k in ("trust_raw", "before", "after", "stdout_raw", "stderr_raw")
    }
    if version == 2:
        kwargs["reference_frame_raw"] = case["reference_frame_raw"]
    method = (
        f.verify_forged_input_refusal_v2
        if version == 2
        else f.verify_forged_input_refusal
    )
    return method(wire, expected_plan_sha256=f._sha(wire), **kwargs)


@pytest.mark.parametrize("kind", f.REASONS)
def test_each_exact_finite_challenge(tmp_path, kind):
    case = make_case(tmp_path, kind)
    original = deepcopy({k: v for k, v in case.items() if k != "source"})
    result = evaluate(case)
    assert result["status"] == "recorded_refusal_consistent"
    assert result["challenge_verified"] is True
    assert result["reference_frame_authenticated"] is True
    assert result["expected_refusal_reason"] == f.REASONS[kind]
    assert result["sampled_state_unchanged"] is True
    assert result["journal_cursor_structurally_verified"] is True
    assert "invalid_signature_verified" not in result
    assert result["qualified_safety_count"] is None
    assert all(result[k] is False for k in f.safety.FLAGS)
    assert {k: v for k, v in case.items() if k != "source"} == original


@pytest.mark.parametrize("kind", f.REASONS)
@pytest.mark.parametrize(
    "fault",
    ["missing_reference", "reference_pin", "wrong_ref_bytes", "wrong_worker_reason"],
)
def test_unverified_premise_not_refusal(tmp_path, kind, fault):
    case = make_case(tmp_path, kind)
    if fault == "missing_reference":
        case["reference_frame_raw"] = None
    elif fault == "reference_pin":
        case["plan"]["challenge"]["reference_frame_sha256"] = "a" * 64
    elif fault == "wrong_ref_bytes":
        case["reference_frame_raw"] = case["reference_frame_raw"][:-1]
    else:
        case["stderr_raw"] = (
            b"azazel_edge.outcome.journal.OutcomeJournalError: different failure\n"
        )
        case["plan"]["worker"]["stderr_sha256"] = f._sha(case["stderr_raw"])
    result = evaluate(case)
    assert result["status"] == "unknown"
    assert result["sampled_state_unchanged"] is True


@pytest.mark.parametrize("kind", f.REASONS)
def test_cross_case_same_runtime_reason_cannot_establish_mutation(tmp_path, kind):
    case = make_case(tmp_path, kind)
    # Keep a globally well-typed declaration while changing the actual suffix to
    # an unrelated canonical frame; the error string alone must never qualify.
    for phase in ("before", "after"):
        case[phase]["source"] = (
            case["source"]["valid_prefix"] + case["source"]["valid_prefix"]
        )
        refresh(case, phase, "source")
    result = evaluate(case)
    assert result["status"] == (
        "recorded_refusal_consistent" if kind == "replay" else "unknown"
    )


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_key",
        "extra_mutation",
        "signature_invalid",
        "wrong_cut",
        "bool_cut",
        "role_key",
    ],
)
def test_isolated_signed_mutation_required(tmp_path, fault):
    kind = "partial_frame" if fault in ("wrong_cut", "bool_cut") else "wrong_key"
    case = make_case(tmp_path, kind)
    if fault == "wrong_key":
        case["plan"]["challenge"]["challenge_public_key"] = public_hex(
            crypto()[0].from_private_bytes(b"z" * 32)
        )
    elif fault == "role_key":
        case["plan"]["challenge"]["challenge_public_key"] = public_hex(KEYS[2])
    elif fault == "wrong_cut":
        case["plan"]["challenge"]["partial_bytes"] -= 1
    elif fault == "bool_cut":
        case["plan"]["challenge"]["partial_bytes"] = True
    else:
        prefix = case["source"]["valid_prefix"]
        row = json.loads(case["before"]["source"][len(prefix) :])
        if fault == "extra_mutation":
            row["stream_ref"] = "other-stream"
        else:
            row["signature"] = "0" * 128
        for phase in ("before", "after"):
            case[phase]["source"] = prefix + raw(row)
            refresh(case, phase, "source")
    if fault in ("bool_cut", "role_key"):
        with pytest.raises(f.ForgedInputRefusalInputError):
            evaluate(case)
    else:
        assert evaluate(case)["status"] == "unknown"


@pytest.mark.parametrize("kind", f.REASONS)
def test_bound_change_retained_without_reference_or_worker(tmp_path, kind):
    case = make_case(tmp_path, kind)
    case["after"]["anchors"] += b"observed-change"
    refresh(case, "after", "anchors")
    case["after"]["journal"] = None
    case["plan"]["samples"]["after"]["journal"] = None
    case["reference_frame_raw"] = None
    case["stderr_raw"] = None
    result = evaluate(case)
    assert result["status"] == "unknown"
    assert result["observed_persistent_change"] is True
    assert result["changes"]["anchors"] is True


def test_versions_never_silently_adopt_plans(tmp_path):
    case = make_case(tmp_path, "wrong_key")
    with pytest.raises(f.ForgedInputRefusalInputError):
        evaluate(case, version=1)
    case["plan"].pop("challenge")
    case["plan"]["schema_version"] = "edge-forged-input-refusal-plan/v1"
    with pytest.raises(f.ForgedInputRefusalInputError):
        evaluate(case, version=2)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "v1_api",
        "v1_enrollment",
        "reference_alias",
        "unsafe_reference",
        "close",
        "final_race",
    ],
)
def test_synthetic_v2_sealed_reference_held_through_evaluation(
    tmp_path, monkeypatch, fault
):
    case = make_case(tmp_path, "partial_frame")
    files, enrollment = sealed(case)
    enrollment["schema_version"] = "edge-forged-input-refusal-enrollment/v2"
    enrollment["paths"]["reference_frame"] = "/sealed/reference"
    files["/sealed/reference"] = case["reference_frame_raw"]
    if fault == "v1_enrollment":
        enrollment["schema_version"] = "edge-forged-input-refusal-enrollment/v1"
    if fault == "reference_alias":
        enrollment["paths"]["reference_frame"] = "/sealed/plan"
    files["/sealed/enrollment"] = raw(enrollment)
    activity = []

    class Held:
        checks = 0

        def read(self, path, maximum):
            activity.append(path)
            if fault == "unsafe_reference" and path == "/sealed/reference":
                raise ValueError("SYNTHETIC unsafe reference")
            assert len(files[path]) <= maximum
            return files[path]

        def verify(self):
            self.checks += 1
            if fault == "final_race" and self.checks == 2:
                raise ValueError("SYNTHETIC final metadata race")

        def close(self):
            activity.append("closed")
            return ["OSError"] if fault == "close" else []

    monkeypatch.setattr(intake, "os", SimpleNamespace(geteuid=lambda: 65533))
    monkeypatch.setattr(safety_collection, "_kernel_boot_id", lambda: BOOT)
    monkeypatch.setattr(safety_collection, "_HeldFiles", Held)
    method = (
        intake.collect_forged_input_refusal
        if fault == "v1_api"
        else intake.collect_forged_input_refusal_v2
    )
    args = dict(
        expected_enrollment_sha256=f._sha(files["/sealed/enrollment"]),
        expected_plan_sha256=enrollment["plan_sha256"],
    )
    if fault:
        with pytest.raises(safety_collection.SafetyCollectionError):
            method("/sealed/enrollment", **args)
    else:
        result = method("/sealed/enrollment", **args)
        assert result["schema_version"] == "edge-forged-input-refusal-collection/v2"
        assert result["evaluation"]["status"] == "recorded_refusal_consistent"
        assert "/sealed/reference" in activity
    assert activity[-1] == "closed"
