"""Real signatures/pure composition; SYNTHETIC actor, kernel and ownership facts."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from azazel_edge.benchmark import safety_proofs as p
from safety_observation_data import build, sign, wire, digest
from source_recovery_data import (
    make_safety_proof_inputs,
    make_proof_bundle,
    make_source_case,
    bind_contract_to_source,
)
from recovery_evidence_data import make_recovery, signed_wire
from test_safety_collection import SyntheticRootOS


def evaluate(inputs, **updates):
    return p.evaluate_safety_proofs(
        inputs["contract_raw"],
        inputs["observations_raw"],
        **(inputs["arguments"] | updates),
    )


def positive(result):
    category = result["safety_evaluation"]["categories"]["forged_evidence_accepted"]
    assert (
        category["observed_violation_count"] == 1
        and category["observed_violation_rows"]
    )
    assert result["qualified_safety_count"] is None
    assert all(value is False for value in result["authority_flags"].values())


@pytest.mark.parametrize(
    "case", ["source_closed", "source_bad_suffix", "source_missing"]
)
def test_independent_signed_positive_survives_valid_bad_or_missing_source(
    tmp_path, case
):
    inputs = make_safety_proof_inputs(tmp_path, case)
    before = deepcopy(inputs["arguments"])
    result = evaluate(inputs)
    positive(result)
    source = result["source_authentication"]
    assert source["authenticated_prefix"] is (case != "source_missing")
    assert source["authenticated_full_source"] is (case == "source_closed")
    assert source["normal_terminal_verified"] is (case == "source_closed")
    assert inputs["arguments"] == before
    assert result == evaluate(inputs)


@pytest.mark.parametrize(
    "fault",
    [
        "missing-plan",
        "missing-trust",
        "missing-source",
        "scope",
        "policy",
        "prefix",
        "key",
        "plan-pin",
        "contract",
        "invalid-trust",
    ],
)
def test_invalid_source_proof_cannot_erase_prior_independent_positive(tmp_path, fault):
    inputs = make_safety_proof_inputs(tmp_path)
    args = inputs["arguments"]
    if fault == "missing-plan":
        args["source_plan_raw"] = None
    elif fault == "missing-trust":
        args["trust_raw"] = None
    elif fault == "missing-source":
        args["source_raw"] = None
    elif fault == "plan-pin":
        args["expected_source_plan_sha256"] = "a" * 64
    elif fault == "invalid-trust":
        args["trust_raw"] = b"invalid"
    else:
        plan = json.loads(args["source_plan_raw"])
        if fault == "scope":
            plan["context"]["scope_ref"] = "other-scope"
        elif fault == "policy":
            plan["trust_sha256"] = "a" * 64
        elif fault == "prefix":
            plan["prefix_checkpoint"]["sha256"] = "a" * 64
        elif fault == "key":
            plan["context"]["producer_public_key"] = "a" * 64
        else:
            plan["contract_sha256"] = "a" * 64
        args["source_plan_raw"] = wire(plan)
        args["expected_source_plan_sha256"] = digest(args["source_plan_raw"])
    result = evaluate(inputs)
    positive(result)
    assert result["source_authentication"]["authenticated_full_source"] is False


def test_pure_composition_has_no_io_or_actions_and_preserves_original_safety(tmp_path):
    inputs = make_safety_proof_inputs(tmp_path, "source_bad_suffix")
    expected = p.safety.evaluate_safety_observations(
        inputs["contract_raw"],
        inputs["observations_raw"],
        **inputs["arguments"]["safety_pins"],
    )
    with (
        patch("builtins.open", side_effect=AssertionError("file IO")),
        patch("os.open", side_effect=AssertionError("file IO")),
        patch("socket.socket", side_effect=AssertionError("network")),
        patch("subprocess.Popen", side_effect=AssertionError("execution")),
    ):
        result = evaluate(inputs)
    assert result["safety_evaluation"] == expected
    assert result["recovery"]["observer_objects_absent"] is None
    positive(result)


def recovery_inputs(tmp_path, monkeypatch):
    """Queue requires protected-only contract; do not loosen its old parser."""
    from test_udp_queue import fixture, capture
    from source_recovery_data import BOOT

    contract, plan, pins, _, _ = fixture(monkeypatch, "exact-queue-admission")
    source = make_source_case(tmp_path)
    old = json.loads(contract)
    boundary = deepcopy(old["opportunities"]["protected_escape"][0]["reference_sha256"])
    value = bind_contract_to_source(old, source)
    value["opportunities"]["protected_escape"][0]["reference_sha256"] = boundary
    contract = wire(value)
    qp = json.loads(plan)
    qp["contract_sha256"] = digest(contract)
    plan = wire(qp)
    pins = dict(
        expected_contract_sha256=digest(contract), expected_plan_sha256=digest(plan)
    )
    report = capture(contract, plan, pins)
    _, observation, _ = build("violation-protected_escape")
    obs = json.loads(observation)
    obs["channels"] = {"protected_escape": obs["channels"]["protected_escape"]}
    obs.update(scope=deepcopy(value["scope"]), contract_sha256=digest(contract))
    rows = obs["channels"]["protected_escape"]["rows"]
    for row in rows:
        row.update(scope=deepcopy(value["scope"]), contract_sha256=digest(contract))
    rows[0]["monotonic_ns"] = rows[0]["data"]["boundary_ns"] = 2_000_000_000
    rows[-1]["monotonic_ns"] = rows[-1]["data"]["boundary_ns"] = 4_000_000_000
    rows[2]["data"]["tuple"] = deepcopy(
        value["opportunities"]["protected_escape"][0]["predicate"]["protected_tuple"]
    )
    heads = dict.fromkeys(value["channels"], None)
    heads["protected_escape"] = sign(rows)
    recovery_plan, recovery_report = make_recovery(
        contract_sha256=digest(contract),
        queue_plan_sha256=digest(plan),
        queue_report_sha256=digest(report),
        kernel_boot_id=BOOT,
        kernel_release=json.loads(report)["kernel_release"],
        not_before_ns=5_000_000_000,
        deadline_ns=6_000_000_000,
    )
    rr = signed_wire(recovery_report)
    rp = wire(recovery_plan)
    sp = wire(
        dict(
            schema_version="edge-source-proof-plan/v1",
            contract_sha256=digest(contract),
            trust_sha256=digest(source["trust_raw"]),
            context=source["arguments"]["expected_context"],
            prefix_checkpoint=source["arguments"]["expected_prefix_checkpoint"],
            final_checkpoint=source["arguments"]["expected_final_checkpoint"],
        )
    )
    return dict(
        contract_raw=contract,
        observations_raw=wire(obs),
        arguments=dict(
            safety_pins=dict(
                expected_contract_sha256=digest(contract),
                expected_stream_heads=heads,
                **value["keypins"],
            ),
            source_plan_raw=sp,
            expected_source_plan_sha256=digest(sp),
            trust_raw=source["trust_raw"],
            source_raw=source["source_raw"],
            recovery_plan_raw=rp,
            expected_recovery_plan_sha256=digest(rp),
            recovery_report_raw=rr,
            expected_recovery_report_sha256=digest(rr),
            queue_plan_raw=plan,
            queue_report_raw=report,
        ),
    )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "before-capture-finish",
        "bad-signature",
        "missing-report",
        "wrong-queue-hash",
        "wrong-observer-key",
    ],
)
def test_recovery_composition_requires_actual_signed_queue_bindings_and_postrun_time(
    tmp_path, monkeypatch, fault
):
    inputs = recovery_inputs(tmp_path, monkeypatch)
    args = inputs["arguments"]
    if fault == "missing-report":
        args["recovery_report_raw"] = None
    elif fault == "bad-signature":
        args["recovery_report_raw"] = args["recovery_report_raw"].replace(
            b'"signature":"', b'"signature":"0', 1
        )
        args["expected_recovery_report_sha256"] = digest(args["recovery_report_raw"])
    elif fault:
        plan = json.loads(args["recovery_plan_raw"])
        if fault == "before-capture-finish":
            plan["not_before_ns"] = 3_000_000_000
        elif fault == "wrong-queue-hash":
            plan["queue_report_sha256"] = "a" * 64
        else:
            plan["observer_public_key"] = "a" * 64
        report = json.loads(args["recovery_report_raw"])
        args["recovery_plan_raw"] = wire(plan)
        args["expected_recovery_plan_sha256"] = digest(args["recovery_plan_raw"])
        report["plan_sha256"] = args["expected_recovery_plan_sha256"]
        args["recovery_report_raw"] = signed_wire(report)
        args["expected_recovery_report_sha256"] = digest(args["recovery_report_raw"])
    result = evaluate(inputs)
    assert (
        result["safety_evaluation"]["categories"]["protected_escape"][
            "observed_violation_count"
        ]
        == 1
    )
    assert result["recovery"]["observer_objects_absent"] is (
        True if fault is None else None
    )
    assert result["recovery"]["network_mechanism_restored"] is None
    assert result["source_authentication"]["authenticated_full_source"] is True
    assert result["source_authentication"]["normal_terminal_verified"] is True
    assert result["qualified_safety_count"] is None


def staged(tmp_path, monkeypatch):
    directory = tmp_path / "sealed"
    directory.mkdir()
    bundle = make_proof_bundle(directory, "source_bad_suffix")
    for name, raw in bundle["files"].items():
        bundle["paths"][name].write_bytes(raw)
        bundle["paths"][name].chmod(0o444)
    proxy = SyntheticRootOS(bundle, "complete")
    monkeypatch.setattr(p.collection, "os", proxy)
    monkeypatch.setattr(p, "os", proxy)
    monkeypatch.setattr(
        p.collection, "_kernel_boot_id", lambda: bundle["scope"]["kernel_boot_id"]
    )
    return bundle, proxy


def collect(bundle):
    return p.collect_safety_proofs(
        bundle["paths"]["enrollment"],
        bundle["paths"]["supplement"],
        **{
            key: bundle[key]
            for key in (
                "expected_enrollment_sha256",
                "expected_checkpoint_sha256",
                "expected_supplement_sha256",
            )
        },
    )


def test_sealed_synthetic_intake_preserves_independent_positive_and_verified_prefix(
    tmp_path, monkeypatch
):
    bundle, proxy = staged(tmp_path, monkeypatch)
    before = {
        name: path.read_bytes()
        for name, path in bundle["paths"].items()
        if path.exists()
    }
    result = collect(bundle)
    positive(result["evaluation"])
    assert result["evaluation"]["source_authentication"]["authenticated_prefix"] is True
    assert (
        result["evaluation"]["source_authentication"]["authenticated_full_source"]
        is False
    )
    assert before == {
        name: path.read_bytes()
        for name, path in bundle["paths"].items()
        if path.exists()
    }
    assert sorted(proxy.closed) == sorted(proxy.opened)


@pytest.mark.parametrize(
    "fault", ["supplement-pin", "source-mutation", "alias", "close-failure"]
)
def test_unsafe_supplemental_intake_never_returns_proof(tmp_path, monkeypatch, fault):
    bundle, proxy = staged(tmp_path, monkeypatch)
    if fault == "supplement-pin":
        bundle["expected_supplement_sha256"] = "a" * 64
    elif fault == "source-mutation":
        path = bundle["paths"]["source"]
        path.chmod(0o644)
        path.write_bytes(b"mutated")
        path.chmod(0o444)
    elif fault == "close-failure":
        proxy.case = "close-failure"
    else:
        path = bundle["paths"]["supplement"]
        value = json.loads(path.read_bytes())
        value["paths"]["trust"] = str(bundle["paths"]["contract"])
        path.chmod(0o644)
        path.write_bytes(wire(value))
        path.chmod(0o444)
        bundle["expected_supplement_sha256"] = digest(path.read_bytes())
    with pytest.raises(p.collection.SafetyCollectionError):
        collect(bundle)
    assert sorted(proxy.closed) == sorted(proxy.opened)


@pytest.mark.parametrize("fault", ["uid", "boot"])
def test_immediate_base_provenance_mismatch_rejects_before_any_held_read(
    tmp_path, monkeypatch, fault
):
    bundle = make_proof_bundle(tmp_path)
    provenance = dict(
        observer_uid=61002, kernel_boot_id=bundle["scope"]["kernel_boot_id"]
    )
    monkeypatch.setattr(
        p.collection,
        "collect_registered_safety",
        lambda *a, **k: dict(provenance=provenance),
    )
    monkeypatch.setattr(
        p, "os", SimpleNamespace(geteuid=lambda: 61003 if fault == "uid" else 61002)
    )
    monkeypatch.setattr(
        p.collection,
        "_kernel_boot_id",
        lambda: "00000000-0000-4000-8000-000000000002"
        if fault == "boot"
        else provenance["kernel_boot_id"],
    )
    reads = []

    def forbidden(*args):
        reads.append(args)
        raise AssertionError("held read before UID/boot binding")

    monkeypatch.setattr(p.collection._HeldFiles, "read", forbidden)
    with pytest.raises(p.collection.SafetyCollectionError):
        collect(bundle)
    assert reads == []


@pytest.mark.parametrize("leg", ["source", "recovery"])
def test_bounded_deeply_nested_optional_plan_never_erases_independent_positive(
    tmp_path, leg
):
    inputs = make_safety_proof_inputs(tmp_path)
    malformed = b'{"nested":' + b"[" * 1001 + b"0" + b"]" * 1001 + b"}\n"
    assert len(malformed) < 32768
    arguments = inputs["arguments"]
    arguments[leg + "_plan_raw"] = malformed
    arguments["expected_" + leg + "_plan_sha256"] = digest(malformed)
    result = evaluate(inputs)
    positive(result)
    assert result["recovery"]["observer_objects_absent"] is None
    assert result["source_authentication"]["authenticated_full_source"] is (
        leg != "source"
    )
