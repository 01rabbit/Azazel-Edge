"""SYNTHETIC prerequisite controls; no live experiment or safety qualification."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from azazel_edge.benchmark import comparison_preflight as c
from azazel_edge.benchmark.benefit import manifest_digest, SAFETY_FIELDS
from azazel_edge.benchmark.measurement import measure_experiment
from measurement_pilot_data import inputs as pilot_inputs, ROOT as PILOT
from run_measurement_pilot import run as historical_run

ROOT = Path(__file__).parent / "fixtures" / "comparison-preflight" / "v1"


def wire(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(*, records=None):
    plan = json.loads((ROOT / "plan.json").read_bytes())
    manifest = json.loads((ROOT / "manifest.json").read_bytes())
    incoming = dict(
        schema_version=c.INPUT_SCHEMA,
        manifest_sha256=manifest_digest(manifest),
        records=[] if records is None else records,
    )
    return plan, manifest, incoming


def evaluate(plan, manifest, incoming, **extra):
    pr, mr, ir = map(wire, (plan, manifest, incoming))
    return c.evaluate_comparison_preflight(
        pr,
        mr,
        ir,
        expected_plan_sha256=digest(pr),
        expected_manifest_sha256=digest(mr),
        **extra,
    )


def test_frozen_36_assignments_missing_remain_unmeasured_and_inputs_immutable():
    value = fixture()
    before = deepcopy(value)
    r = evaluate(*value)
    assert r["assigned_runs"] == len(r["missing_assignments"]) == 36
    assert r["received_attempts"] == 0
    assert r["comparison_result"] is r["mechanical_evaluation"] is None
    assert r["actual_comparison_started"] is r["comparison_qualified"] is False
    assert r["qualified_safety_count"] is None
    assert not any(r["authority_flags"].values())
    assert len(r["blockers"]) == 8
    assert value == before
    assert r == evaluate(*value)


def test_real_unknowns_and_positive_survive_duplicate_bad_sibling(monkeypatch):
    plan, manifest, incoming = fixture()
    first = manifest["assignments"][0]
    record = dict(
        assignment_id=first["id"],
        capture=dict(
            assignment_id=first["id"],
            scenario=first["scenario"],
            seed=first["seed"],
            safety_violations=dict.fromkeys(SAFETY_FIELDS),
        ),
        edge_recording={},
        linkage={},
    )
    record["capture"]["safety_violations"]["unauthorized_action"] = 2
    incoming["records"] = [record, deepcopy(record), {"assignment_id": "foreign"}, None]

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "real/unmeasured input must not enter original numeric engine"
        )

    monkeypatch.setattr(c, "measure_experiment", forbidden)
    result = evaluate(plan, manifest, incoming)
    assert len(result["attempts"]) == 4
    assert len(result["reported_positive_attempts"]) == 2
    assert result["duplicate_assignments"] == [first["id"]]
    assert len(result["missing_assignments"]) == 35
    assert result["attempts"][0]["reported_safety"] == {"unauthorized_action": 2}
    assert len(result["attempts"][0]["unknown_safety_categories"]) == 3
    assert result["mechanical_evaluation"] is result["comparison_result"] is None


@pytest.mark.parametrize("value", [False, True, -1, 0.0, "0", None])
def test_bool_or_invalid_safety_is_not_zero(value):
    plan, manifest, incoming = fixture()
    a = manifest["assignments"][0]
    incoming["records"] = [
        dict(
            assignment_id=a["id"],
            capture=dict(
                assignment_id=a["id"],
                scenario=a["scenario"],
                seed=a["seed"],
                safety_violations=dict.fromkeys(SAFETY_FIELDS, value),
            ),
            edge_recording={},
            linkage={},
        )
    ]
    r = evaluate(plan, manifest, incoming)
    assert r["attempts"][0]["reported_safety"] == {}
    assert len(r["attempts"][0]["unknown_safety_categories"]) == 4


def test_pinned_references_cannot_qualify_and_bad_sibling_is_isolated():
    good = b'{"comparison_qualified":true}\n'
    r = evaluate(
        *fixture(),
        reference_artifacts=dict(event_binding=good, window_cost=b"bad"),
        expected_reference_sha256=dict(
            event_binding=digest(good), window_cost="0" * 64
        ),
    )
    assert r["references"][0]["status"] == "pinned_reference"
    assert r["references"][1]["status"] == "pin_mismatch"
    assert r["comparison_qualified"] is False
    assert r["prerequisite_diagnostics"]["event_binding"] == "unqualified"


@pytest.mark.parametrize(
    "fault",
    [
        "plan_pin",
        "manifest_pin",
        "order",
        "threshold",
        "extra",
        "schema",
        "seed_bool",
        "config",
        "duplicate_key",
        "nan",
        "depth",
        "overbound",
        "none_bytes",
    ],
)
def test_invalid_globals_or_changed_freeze_refuse(fault):
    p, m, i = fixture()
    pr, mr, ir = map(wire, (p, m, i))
    pp, mp = digest(pr), digest(mr)
    if fault == "plan_pin":
        pp = "0" * 64
    elif fault == "manifest_pin":
        mp = "0" * 64
    elif fault == "order":
        m["assignments"][0]["order"] = 999
        mr = wire(m)
    elif fault == "threshold":
        p["fixed_gates"]["clock_budget_ns"] = 6_000_000
        pr = wire(p)
        pp = digest(pr)
    elif fault == "extra":
        i["approved"] = True
        ir = wire(i)
    elif fault == "schema":
        i["schema_version"] = "legacy"
        ir = wire(i)
    elif fault == "seed_bool":
        p["allocation_seed"] = False
        pr = wire(p)
        pp = digest(pr)
    elif fault == "config":
        p["arm_descriptions"]["reference"]["observer_mode"] = "forged"
        pr = wire(p)
        pp = digest(pr)
    elif fault == "duplicate_key":
        ir = ir.replace(b'"records":[]', b'"records":[],"records":[]')
    elif fault == "nan":
        ir = ir.replace(b'"records":[]', b'"records":[NaN]')
    elif fault == "depth":
        deep = None
        for _ in range(26):
            deep = [deep]
        i["records"] = [deep]
        ir = wire(i)
    elif fault == "overbound":
        ir = b" " * (8 * 1024 * 1024 + 1)
    else:
        pr = None
    with pytest.raises(c.ComparisonPreflightInputError):
        c.evaluate_comparison_preflight(
            pr, mr, ir, expected_plan_sha256=pp, expected_manifest_sha256=mp
        )


def test_historical_nine_cases_remain_original_mechanical_only():
    before = {
        name: (PILOT / name).read_bytes()
        for name in ("protocol.json", "cases.json", "protocol.sha256")
    }
    report = historical_run()
    assert report["scenarios"] == 9 and report["assigned_runs"] == 36
    assert report["claim_status"] == "mechanical_only"
    assert report["canonical_causal_promotions"] == 0
    assert before == {name: (PILOT / name).read_bytes() for name in before}


def test_exact_json_node_depth_boundary():
    value = 0
    for _ in range(24):
        value = [value]
    assert c._decode(wire(value), 4096) == value
    with pytest.raises(c.ComparisonPreflightInputError):
        c._decode(wire([value]), 4096)


def test_synthetic_harm_and_gap_reuse_original_engine_without_success_filter():
    protocol = json.loads((PILOT / "protocol.json").read_bytes())
    cases = json.loads((PILOT / "cases.json").read_bytes())
    for case in (
        case_data
        for case_data in cases
        if case_data["id"] in ("protection_harm", "capture_gap", "restart_lost")
    ):
        manifest, records = pilot_inputs(protocol, case)
        plan, _, _ = fixture()
        descriptions = {
            arm["id"]: dict(arm=arm["id"], declared="SYNTHETIC-regression")
            for arm in manifest["arms"]
        }
        for arm in manifest["arms"]:
            arm["config_sha256"] = manifest_digest(descriptions[arm["id"]])
        plan["arm_descriptions"] = descriptions
        plan["manifest_sha256"] = digest(wire(manifest))
        # A new explicitly SYNTHETIC recipe, not modification of old originals.
        for record in records:
            record["capture"]["manifest_sha256"] = manifest_digest(manifest)
            record["linkage"]["capture_sha256"] = manifest_digest(record["capture"])
        inner = dict(manifest_sha256=manifest_digest(manifest), records=records)
        result = evaluate(plan, manifest, dict(schema_version=c.INPUT_SCHEMA, **inner))
        assert result["mechanical_evaluation"] == measure_experiment(manifest, inner)
        assert (
            result["mechanical_evaluation"]["comparison"]["measurement_gate"]
            == case["expected_gate"]
        )
        assert result["received_attempts"] == 4
        assert result["comparison_result"] is None
        assert result["comparison_qualified"] is False


def repin(plan, manifest, incoming):
    plan["manifest_sha256"] = digest(wire(manifest))
    incoming["manifest_sha256"] = manifest_digest(manifest)
    return plan, manifest, incoming


@pytest.mark.parametrize("field,replacement", [
    ("analysis_seed", 18), ("bootstrap_repeats", 501), ("minimum_pairs", 3),
    ("minimum_gain_seconds", 4), ("max_latency_increase_ms", 3),
    ("max_error_rate_increase", 0.02),
])
def test_repinned_nested_thresholds_cannot_change_the_frozen_analysis(field, replacement):
    plan, manifest, incoming = fixture()
    manifest["plan"][field] = replacement
    with pytest.raises(c.ComparisonPreflightInputError, match="nested analysis"):
        evaluate(*repin(plan, manifest, incoming))


@pytest.mark.parametrize("fault", ["horizon", "horizon_float", "allocation", "pair_order", "array_order", "assignment_seed", "assignment_id",
                                    "source", "provenance", "description", "arm_extra"])
def test_repinned_container_profile_and_full36_allocation_are_fixed(fault):
    plan, manifest, incoming = fixture()
    if fault.startswith("horizon"):
        manifest["horizon_seconds"] = 61 if fault == "horizon" else 60.0
    elif fault == "allocation":
        plan["allocation_seed"] += 1
    elif fault == "pair_order":
        for row in manifest["assignments"][:2]:
            row["order"] = 1 - row["order"]
    elif fault == "array_order":
        manifest["assignments"][0], manifest["assignments"][1] = manifest["assignments"][1], manifest["assignments"][0]
    elif fault == "assignment_seed":
        for row in manifest["assignments"][:2]:
            row["seed"] += 1
    elif fault == "assignment_id":
        manifest["assignments"][0]["id"] = "different-reference"
    elif fault == "source":
        for arm in manifest["arms"]:
            arm["source_commit"] = "f" * 40
        manifest["provenance"]["repo_commits"]["01rabbit/Azazel-Edge"] = "f" * 40
    elif fault == "provenance":
        manifest["provenance"]["corpus_sha256"] = "f" * 64
    elif fault == "description":
        plan["arm_descriptions"]["reference"]["observer_mode"] = "on"
        manifest["arms"][0]["config_sha256"] = manifest_digest(plan["arm_descriptions"]["reference"])
    else:
        manifest["arms"][0]["extra"] = True
    with pytest.raises(c.ComparisonPreflightInputError):
        evaluate(*repin(plan, manifest, incoming))


@pytest.mark.parametrize("fault", ["protocol", "hash_type", "cases", "scenarios", "scenario_type", "gates", "gate_type"])
def test_repinned_historical_metadata_requires_exact_hashes_ids_and_gate_mapping(fault):
    plan, manifest, incoming = fixture()
    historical = plan["historical_pilot"]
    if fault == "protocol":
        historical["protocol_sha256"] = "f" * 64
    elif fault == "hash_type":
        historical["protocol_sha256"] = True
    elif fault == "cases":
        historical["cases_sha256"] = "f" * 64
    elif fault == "scenarios":
        historical["scenario_ids"].reverse()
    elif fault == "scenario_type":
        historical["scenario_ids"][0] = 0
    elif fault == "gates":
        historical["expected_gates"]["gain"] = "practical_time_gain_not_demonstrated"
    else:
        historical["expected_gates"]["gain"] = True
    with pytest.raises(c.ComparisonPreflightInputError):
        evaluate(*repin(plan, manifest, incoming))


def real_profile_records(case_id):
    protocol = json.loads((PILOT / "protocol.json").read_bytes())
    cases = json.loads((PILOT / "cases.json").read_bytes())
    case = next(item for item in cases if item["id"] == case_id)
    _, records = pilot_inputs(protocol, case)
    plan, manifest, incoming = fixture()
    # These remain SYNTHETIC receipt controls, merely passed through the new
    # container-typed boundary to verify its strict diagnostic join.
    for record in records:
        record["capture"]["manifest_sha256"] = manifest_digest(manifest)
        record["linkage"]["capture_sha256"] = manifest_digest(record["capture"])
    incoming["records"] = records
    return plan, manifest, incoming


@pytest.mark.parametrize("case_id", c.SCENARIOS)
def test_every_authored_case_uses_original_strict_join_for_real_typed_diagnostics_only(case_id, monkeypatch):
    from azazel_edge.benchmark.measurement import _join

    plan, manifest, incoming = real_profile_records(case_id)
    before = deepcopy(incoming)
    monkeypatch.setattr(c, "measure_experiment", lambda *a: pytest.fail("real comparison was started"))
    result = evaluate(plan, manifest, incoming)
    assignments = {row["id"]: row for row in manifest["assignments"]}
    assert len(result["attempts"]) == len(incoming["records"]) == 4
    for row, record in zip(result["attempts"], incoming["records"]):
        expected = _join(manifest, assignments[record["assignment_id"]], record)
        expected.pop("_identity")
        assert row["original_join"] == expected
        assert row["status"] == "withheld"
        assert all("original_join:" + reason in row["reasons"] for reason in expected["reasons"])
    assert result["comparison_result"] is result["mechanical_evaluation"] is None
    assert result["actual_comparison_started"] is result["comparison_qualified"] is False
    assert incoming == before


def test_four_zeros_and_empty_linkage_do_not_hide_missing_strict_evidence():
    plan, manifest, incoming = fixture()
    assignment = manifest["assignments"][0]
    incoming["records"] = [dict(assignment_id=assignment["id"], capture=dict(
        assignment_id=assignment["id"], scenario=assignment["scenario"], seed=assignment["seed"],
        safety_violations=dict.fromkeys(SAFETY_FIELDS, 0)), edge_recording={}, linkage={})]
    result = evaluate(plan, manifest, incoming)
    row = result["attempts"][0]
    assert row["reported_safety"] == dict.fromkeys(SAFETY_FIELDS, 0)
    assert row["original_join"]["status"] == "rejected"
    assert row["original_join"]["reasons"] == ["invalid_capture_or_linkage"]
    assert "original_measurement_join_rejected_inputs" in row["reasons"]


def test_unknown_safety_never_enters_the_original_strict_join(monkeypatch):
    plan, manifest, incoming = real_profile_records("gain")
    incoming["records"][0]["capture"]["safety_violations"]["protected_escape"] = None
    calls = []
    original = c._join

    def strict(*args):
        calls.append(args[2]["assignment_id"])
        return original(*args)

    monkeypatch.setattr(c, "_join", strict)
    result = evaluate(plan, manifest, incoming)
    assert len(calls) == 3
    assert result["attempts"][0]["original_join"] is None
    assert result["attempts"][0]["unknown_safety_categories"] == ["protected_escape"]


def test_rejected_positive_and_malformed_siblings_do_not_erase_valid_join():
    plan, manifest, incoming = real_profile_records("gain")
    bad = deepcopy(incoming["records"][0])
    bad["capture"]["safety_violations"]["unauthorized_action"] = 3
    bad["linkage"] = {}
    incoming["records"] = [incoming["records"][0], bad, None, *incoming["records"][1:]]
    result = evaluate(plan, manifest, incoming)
    assert result["attempts"][0]["original_join"]["status"] == "qualified"
    assert result["attempts"][1]["original_join"]["status"] == "rejected"
    assert result["reported_positive_attempts"][0]["reported_safety"]["unauthorized_action"] == 3
    assert len(result["attempts"]) == 6
    assert result["duplicate_assignments"] == [bad["assignment_id"]]
    assert result["comparison_result"] is None


def test_original_golden_replay_exception_is_rejected_without_losing_positive(monkeypatch):
    from azazel_edge.outcome.golden_replay import GoldenReplayError

    plan, manifest, incoming = real_profile_records("gain")
    incoming["records"][0]["capture"]["safety_violations"]["protected_escape"] = 2
    monkeypatch.setattr(c, "_join", lambda *a: (_ for _ in ()).throw(GoldenReplayError("SYNTHETIC invalid timeline")))
    result = evaluate(plan, manifest, incoming)
    assert result["attempts"][0]["original_join_error"] == "GoldenReplayError"
    assert result["reported_positive_attempts"][0]["reported_safety"]["protected_escape"] == 2
    assert len(result["attempts"]) == 4
