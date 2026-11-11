"""Pure synthetic cross-run shape checks; these flags are not authentication."""

from copy import deepcopy
from pathlib import Path
import sys
import uuid

import pytest
from azazel_edge.benchmark.benefit import BenefitInputError, manifest_digest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_freshness as fresh

CORE = "b" * 64


def fixture():
    manifest, _ = fresh.plan.planned("a" * 40, CORE)
    results = []
    for index, assignment in enumerate(manifest["assignments"]):
        raw_boot = str(uuid.UUID(int=index + 1))
        session = f"{index + 1:032x}"
        capture = dict(
            assignment_id=assignment["id"],
            scenario=assignment["scenario"],
            seed=assignment["seed"],
            run_id=f"run-{index}",
            boot_id=fresh.plan.n.boot_reference(raw_boot),
            manifest_sha256=manifest_digest(manifest),
        )
        linkage = dict(
            session_ref=fresh.native_session_reference(session),
            capture_sha256=manifest_digest(capture),
        )
        record = dict(
            assignment_id=assignment["id"],
            capture=capture,
            linkage=linkage,
            edge_recording=None if assignment["arm"] == "c0" else {},
        )
        results.append(
            dict(
                status="calculation_available",
                reasons=[],
                measurement_record=record,
                authenticated_origin=dict(
                    assignment_id=assignment["id"],
                    kernel_boot_id=raw_boot,
                    session_ref=session,
                    scope_ref=f"scope-{index}",
                    registration_sha256=f"{index + 10:064x}",
                    producer_public_key=f"{index * 2 + 100:064x}",
                    witness_public_key=f"{index * 2 + 101:064x}",
                ),
            )
        )
    return manifest, results


def test_original_records_return_in_frozen_order_without_any_mutation():
    manifest, results = fixture()
    before = deepcopy((manifest, results))
    indexed = {
        r["authenticated_origin"]["assignment_id"]: r["measurement_record"]
        for r in results
    }
    output = fresh.validate_fresh_records(
        manifest, list(reversed(results)), core_sha256=CORE
    )
    assert (manifest, results) == before
    assert all(
        row is indexed[a["id"]] for row, a in zip(output, fresh.plan.order(manifest))
    )
    assert [r["assignment_id"] for r in output] == [
        "pair-0-c0",
        "pair-0-flow_throttle",
        "pair-1-flow_throttle",
        "pair-1-c0",
    ]


@pytest.mark.parametrize(
    "field", ["kernel_boot_id", "scope_ref", "session_ref", "registration_sha256"]
)
def test_reused_actual_origin_refuses_without_repair(field):
    manifest, results = fixture()
    results[1]["authenticated_origin"][field] = results[0]["authenticated_origin"][
        field
    ]
    # Preserve all cross-bindings so the global reuse gate must catch it.
    if field == "kernel_boot_id":
        results[1]["measurement_record"]["capture"]["boot_id"] = (
            fresh.plan.n.boot_reference(results[0]["authenticated_origin"][field])
        )
    if field == "session_ref":
        results[1]["measurement_record"]["linkage"]["session_ref"] = (
            fresh.native_session_reference(results[0]["authenticated_origin"][field])
        )
    capture = results[1]["measurement_record"]["capture"]
    results[1]["measurement_record"]["linkage"]["capture_sha256"] = manifest_digest(
        capture
    )
    before = deepcopy(results)
    with pytest.raises(BenefitInputError):
        fresh.validate_fresh_records(manifest, results, core_sha256=CORE)
    assert results == before


@pytest.mark.parametrize(
    "a,b",
    [
        ("producer_public_key", "producer_public_key"),
        ("witness_public_key", "witness_public_key"),
        ("producer_public_key", "witness_public_key"),
        ("witness_public_key", "producer_public_key"),
    ],
)
def test_any_cross_role_or_cross_run_key_reuse_refuses(a, b):
    manifest, results = fixture()
    results[1]["authenticated_origin"][a] = results[0]["authenticated_origin"][b]
    with pytest.raises(BenefitInputError):
        fresh.validate_fresh_records(manifest, results, core_sha256=CORE)


def test_same_run_producer_witness_key_reuse_refuses():
    manifest, results = fixture()
    o = results[0]["authenticated_origin"]
    o["witness_public_key"] = o["producer_public_key"]
    with pytest.raises(BenefitInputError):
        fresh.validate_fresh_records(manifest, results, core_sha256=CORE)


@pytest.mark.parametrize(
    "fault",
    [
        "partial",
        "duplicate",
        "unknown",
        "withheld",
        "reason",
        "missingrecord",
        "originassignment",
        "captureassignment",
        "recordassignment",
        "sessionmapping",
        "rawsession",
        "runreuse",
        "bootuppercase",
        "bootbool",
        "scopebool",
        "sessioncase",
        "digestbool",
        "keycase",
        "keylength",
        "manifesthash",
        "capturehash",
        "scenario",
        "boolseed",
        "nan",
        "unknownoriginfield",
        "unknownrecordfield",
        "edgeboot",
    ],
)
def test_partial_malformed_or_cross_bound_results_refuse(fault):
    manifest, results = fixture()
    result = results[0]
    origin, record = result["authenticated_origin"], result["measurement_record"]
    capture, linkage = record["capture"], record["linkage"]
    if fault == "partial":
        results.pop()
    elif fault == "duplicate":
        results[1] = deepcopy(result)
    elif fault == "unknown":
        origin["assignment_id"] = "unknown"
    elif fault == "withheld":
        result["status"] = "withheld"
    elif fault == "reason":
        result["reasons"] = ["coverage_gap"]
    elif fault == "missingrecord":
        result["measurement_record"] = None
    elif fault == "originassignment":
        origin["assignment_id"] = results[1]["authenticated_origin"]["assignment_id"]
    elif fault == "captureassignment":
        capture["assignment_id"] = results[1]["authenticated_origin"]["assignment_id"]
    elif fault == "recordassignment":
        record["assignment_id"] = True
    elif fault == "sessionmapping":
        linkage["session_ref"] = "native-session-" + "f" * 32
    elif fault == "rawsession":
        linkage["session_ref"] = origin["session_ref"]
    elif fault == "runreuse":
        capture["run_id"] = results[1]["measurement_record"]["capture"]["run_id"]
    elif fault == "bootuppercase":
        origin["kernel_boot_id"] = "AAAAAAAA-AAAA-4AAA-AAAA-AAAAAAAAAAAA"
    elif fault == "bootbool":
        origin["kernel_boot_id"] = True
    elif fault == "scopebool":
        origin["scope_ref"] = True
    elif fault == "sessioncase":
        origin["session_ref"] = "A" * 32
    elif fault == "digestbool":
        origin["registration_sha256"] = True
    elif fault == "keycase":
        origin["producer_public_key"] = "A" * 64
    elif fault == "keylength":
        origin["producer_public_key"] = "a" * 63
    elif fault == "manifesthash":
        capture["manifest_sha256"] = "f" * 64
    elif fault == "capturehash":
        linkage["capture_sha256"] = "f" * 64
    elif fault == "scenario":
        capture["scenario"] = "other"
    elif fault == "boolseed":
        capture["seed"] = False
    elif fault == "nan":
        capture["unused"] = float("nan")
    elif fault == "unknownoriginfield":
        origin["trusted"] = True
    elif fault == "unknownrecordfield":
        record["trusted"] = True
    elif fault == "edgeboot":
        linkage["edge_boot_id"] = "kernel-boot-other"
    # Re-bind changed capture where needed to exercise other exact checks.
    if fault not in ("capturehash", "nan"):
        linkage["capture_sha256"] = manifest_digest(capture)
    with pytest.raises(BenefitInputError):
        fresh.validate_fresh_records(manifest, results, core_sha256=CORE)


@pytest.mark.parametrize("core", [True, "a" * 64, "B" * 64, "b" * 63])
def test_required_external_frozen_core_pin_refuses_mismatch(core):
    manifest, results = fixture()
    with pytest.raises(BenefitInputError):
        fresh.validate_fresh_records(manifest, results, core_sha256=core)


def test_numerically_equal_but_differently_typed_manifest_refuses():
    manifest, results = fixture()
    manifest["horizon_seconds"] = 5.0
    with pytest.raises(BenefitInputError):
        fresh.validate_fresh_records(manifest, results, core_sha256=CORE)
