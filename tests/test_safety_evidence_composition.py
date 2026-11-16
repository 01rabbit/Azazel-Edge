"""Synthetic historical joins with real original pure evaluators, never kernel evidence."""

from copy import deepcopy
import builtins
import json

import pytest

from azazel_edge.benchmark import safety_evidence_composition as c
from azazel_edge.benchmark import safety_observations as safety
from safety_observation_data import build as main_build, wire, digest
import test_forged_input_refusal as f1
import test_forged_input_refusal_v2 as f2
import test_advisory_exec as advisory
import test_authority_ingress as ingress
import test_postconnect_refusal as refusal
import test_postconnect_authorization as authorization
import test_natural_close_recv as natural


def bundle(kind, case, evaluate):
    result = {slot: None for slot in c.SLOTS[kind]}
    result["plan"] = wire(case["plan"])
    result["evaluation"] = wire(evaluate(case))
    if kind.startswith("forged_refusal_"):
        result.update(trust=case["trust_raw"], stdout=case["stdout_raw"], stderr=case["stderr_raw"])
        for phase in ("before", "after"):
            for slot, raw in case[phase].items():
                result[phase + "_" + slot] = raw
        if kind.endswith("v2"):
            result["reference_frame"] = case["reference_frame_raw"]
    elif kind == "advisory_exec":
        for slot in ("probe", "governance"):
            result[slot] = wire(case[slot]) if case[slot] is not None else None
        result["audit"] = case["audit"]
    else:
        result["probe"] = wire(case["probe"]) if case["probe"] is not None else None
        result.update({slot[:-4]: raw for slot, raw in case.items() if slot.endswith("_raw")})
    return result


def make_original_bundles(tmp_path):
    return {
        "forged_refusal_v1": bundle("forged_refusal_v1", f1.build(tmp_path / "v1"), f1.evaluate),
        "forged_refusal_v2": bundle("forged_refusal_v2", f2.make_case(tmp_path / "v2", "wrong_key"), f2.evaluate),
        "advisory_exec": bundle("advisory_exec", advisory.build(tmp_path / "exec"), advisory.evaluate),
        "authority_ingress": bundle("authority_ingress", ingress.build(), ingress.evaluate),
        "postconnect_refusal": bundle("postconnect_refusal", refusal.build(), refusal.evaluate),
        "postconnect_authorization": bundle("postconnect_authorization", authorization.build(), authorization.evaluate),
        "natural_close_recv": bundle("natural_close_recv", natural.build(), natural.evaluate),
    }


@pytest.fixture
def original_bundles(tmp_path):
    return make_original_bundles(tmp_path)


def build_composition(tmp_path, main_case="violation-protected_escape"):
    """Synthetic helper for staging original bytes under a separate real reader."""
    bundles = make_original_bundles(tmp_path)
    contract, observations, pins = main_build(main_case)
    value = inputs(bundles)
    plan = json.loads(value[2]["composition_plan_raw"])
    plan["main_contract_sha256"] = digest(contract)
    return dict(contract_raw=contract, observations_raw=observations, safety_pins=pins,
                composition_plan_raw=wire(plan), supplements=bundles)


def inputs(bundles):
    contract, observations, pins = main_build("violation-unauthorized_action")
    plan = dict(schema_version="edge-safety-evidence-composition-plan/v1",
                main_contract_sha256=digest(contract), entries=[
                    dict(id=kind, kind=kind, sha256={s: digest(v) if v is not None else None for s, v in raw.items()})
                    for kind, raw in bundles.items()
                ])
    return contract, observations, dict(safety_pins=pins, composition_plan_raw=wire(plan),
                                      expected_composition_plan_sha256=digest(wire(plan)), supplements=bundles)


def run(value):
    return c.evaluate_safety_evidence_composition(value[0], value[1], **value[2])


def assert_main(result, value):
    main = safety.evaluate_safety_observations(value[0], value[1], **value[2]["safety_pins"])
    assert result["main_evaluation"] == main
    assert main["categories"]["unauthorized_action"]["observed_violation_count"] == 1
    assert result["comparison_eligibility"] is False
    assert result["comparison_status"] == "WITHHELD"
    assert result["qualified_safety_count"] is None
    assert all(flag is False for flag in result["authority_flags"].values())
    for key, diagnostic in result["category_diagnostics"].items():
        assert diagnostic["main_category"] == main["categories"][key]
        assert diagnostic["qualified_safety_count"] is None


def test_all_seven_exact_original_replays_preserve_inputs(original_bundles):
    value = inputs(original_bundles)
    before = deepcopy(value)
    result = run(value)
    assert value == before
    assert_main(result, value)
    assert len(result["supplemental_items"]) == 7
    for item in result["supplemental_items"]:
        assert item["replayed_evaluation"] == json.loads(original_bundles[item["kind"]]["evaluation"])
        assert item["published_evaluation_matches"] is True
        assert item["status"] == "historical_replay_consistent"
        assert item["evidence_relation"] == "historical_reference_only"
    natural_result = result["supplemental_items"][-1]["replayed_evaluation"]
    assert natural_result["reciprocal_pair_verified"] is None
    assert natural_result["root_only_refusal_response_consistent"] is None


@pytest.mark.parametrize("fault", ["missing", "mismatch", "invalid", "wrong_pin"])
def test_published_failure_keeps_replay_and_siblings(original_bundles, fault):
    value = inputs(original_bundles)
    original = json.loads(original_bundles["natural_close_recv"]["evaluation"])
    raw = original_bundles["natural_close_recv"]
    if fault == "missing":
        raw["evaluation"] = None
    elif fault == "wrong_pin":
        raw["evaluation"] += b" "
    else:
        raw["evaluation"] = wire({"pretend_qualified": True}) if fault == "mismatch" else b"\xff"
        plan = json.loads(value[2]["composition_plan_raw"])
        plan["entries"][-1]["sha256"]["evaluation"] = digest(raw["evaluation"])
        value[2]["composition_plan_raw"] = wire(plan)
        value[2]["expected_composition_plan_sha256"] = digest(wire(plan))
    result = run(value)
    assert_main(result, value)
    assert result["supplemental_items"][-1]["replayed_evaluation"] == original
    assert result["supplemental_items"][-1]["status"] == "unknown"
    assert all(i["published_evaluation_matches"] for i in result["supplemental_items"][:-1])


@pytest.mark.parametrize("fault", ["wrong_kind", "duplicate", "extra_slot", "main_pin", "bad_json", "bad_pin"])
def test_invalid_optional_manifest_preserves_main(original_bundles, fault):
    value = inputs(original_bundles)
    plan = json.loads(value[2]["composition_plan_raw"])
    if fault == "wrong_kind":
        plan["entries"][0]["kind"] = "invented"
    elif fault == "duplicate":
        plan["entries"].append(plan["entries"][0])
    elif fault == "extra_slot":
        plan["entries"][0]["sha256"]["extra"] = None
    elif fault == "main_pin":
        plan["main_contract_sha256"] = "0" * 64
    raw = b"\xff" if fault == "bad_json" else wire(plan)
    value[2].update(composition_plan_raw=raw, expected_composition_plan_sha256=("0" * 64 if fault == "bad_pin" else digest(raw)))
    result = run(value)
    assert_main(result, value)
    assert result["supplemental_items"] == []
    assert result["reasons"]


def test_missing_all_and_invalid_item_preserve_positive(original_bundles):
    value = inputs(original_bundles)
    value[2]["supplements"] = {}
    result = run(value)
    assert_main(result, value)
    assert all(i["status"] == "unknown" for i in result["supplemental_items"])
    value[2]["supplements"] = original_bundles
    original_bundles["authority_ingress"]["invented"] = b"unexpected"
    result = run(value)
    assert_main(result, value)
    assert result["supplemental_items"][3]["replayed_evaluation"] is None
    assert result["supplemental_items"][-1]["published_evaluation_matches"] is True


@pytest.mark.parametrize("case", ["partial_read_close", "actor_death", "observer_stop_after_copy", "missing_after_sot"])
def test_natural_original_partial_diagnostics_are_exact(case):
    raw = bundle("natural_close_recv", natural.build(case), natural.evaluate)
    value = inputs({"natural_close_recv": raw})
    result = run(value)
    assert_main(result, value)
    replay = result["supplemental_items"][0]["replayed_evaluation"]
    assert replay == json.loads(raw["evaluation"])
    assert replay["reciprocal_pair_verified"] is None
    if case == "missing_after_sot":
        assert replay["object_changes"]["audit"] is True
        assert replay["object_changes"]["sot"] is None


def test_bad_measurement_pin_preserves_known_audit_change():
    raw = bundle("natural_close_recv", natural.build("own_uid_patch"), natural.evaluate)
    value = inputs({"natural_close_recv": raw})
    raw["sot_after"] += b"untrusted"
    result = run(value)
    replay = result["supplemental_items"][0]["replayed_evaluation"]
    assert replay["object_changes"]["audit"] is True
    assert replay["object_changes"]["sot"] is None
    assert result["supplemental_items"][0]["status"] == "unknown"


def test_main_invalid_still_raises_before_optional_plan(monkeypatch):
    monkeypatch.setattr(c, "_plan", lambda *args: pytest.fail("optional plan evaluated first"))
    with pytest.raises(safety.SafetyObservationInputError):
        c.evaluate_safety_evidence_composition(b"invalid", b"invalid", safety_pins={
            "expected_contract_sha256": "0" * 64, "observer_public_key": "1" * 64,
            "source_producer_public_key": "2" * 64, "source_witness_public_key": "3" * 64,
            "expected_stream_heads": {key: None for key in safety.CATEGORIES},
        })


def test_no_io_and_total_bound(original_bundles, monkeypatch):
    value = inputs(original_bundles)
    monkeypatch.setattr(builtins, "open", lambda *a, **k: pytest.fail("pure wrapper did I/O"))
    assert_main(run(value), value)
    monkeypatch.setattr(c, "MAX_TOTAL_BYTES", 1)
    result = run(value)
    assert_main(result, value)
    assert result["supplemental_items"] == []


@pytest.mark.parametrize("mutation", ["false_zero", "nested_false_zero", "one_true", "one_float"])
def test_published_typed_aliases_never_match(original_bundles, mutation):
    kind = "natural_close_recv" if mutation == "nested_false_zero" else "advisory_exec"
    raw = original_bundles[kind]
    original = json.loads(raw["evaluation"])
    published = deepcopy(original)
    if mutation == "nested_false_zero":
        assert original["object_changes"]["sot"] is False
        published["object_changes"]["sot"] = 0
    elif mutation == "false_zero":
        assert original["production_admission"] is False
        published["production_admission"] = 0
    elif mutation == "one_true":
        assert original["kernel_exec_attempt_count"] == 1
        published["kernel_exec_attempt_count"] = True
    else:
        assert original["kernel_exec_attempt_count"] == 1
        published["kernel_exec_attempt_count"] = 1.0
    raw["evaluation"] = wire(published)
    value = inputs({kind: raw})
    result = run(value)
    assert_main(result, value)
    item = result["supplemental_items"][0]
    assert safety._same(item["replayed_evaluation"], original)
    assert item["status"] == "unknown"
    assert item["published_evaluation_matches"] is False
    assert "published_evaluation_mismatch" in item["reasons"]


def test_full_256_byte_copy_report_is_preserved_and_matches():
    case = natural.build()
    full_copy = b"x" * 255 + b"\n"
    for event in case["probe"]["events"]:
        if event["role"] == 1 and event["kind"] == 1:
            authorization.data(event, full_copy)
        elif event["role"] == 1 and event["kind"] == 2:
            event["ret"] = 256
    natural.recount(case)
    raw = bundle("natural_close_recv", case, natural.evaluate)
    original = json.loads(raw["evaluation"])
    assert any(row["data_hex"] == full_copy.hex() for row in original["raw_protocol_copy_events"])
    result = run(inputs({"natural_close_recv": raw}))
    item = result["supplemental_items"][0]
    assert item["published_evaluation_matches"] is True
    assert item["status"] == "historical_replay_consistent"
    assert safety._same(item["published_evaluation"], original)
    assert safety._same(item["replayed_evaluation"], original)


@pytest.mark.parametrize("malformed", [b'{"x":NaN}\n', b'{"x":Infinity}\n', b'{"x":1,"x":1}\n'])
def test_published_nonfinite_or_duplicate_refuses_but_keeps_replay(original_bundles, malformed):
    raw = original_bundles["advisory_exec"]
    original = json.loads(raw["evaluation"])
    raw["evaluation"] = malformed
    value = inputs({"advisory_exec": raw})
    result = run(value)
    assert_main(result, value)
    item = result["supplemental_items"][0]
    assert safety._same(item["replayed_evaluation"], original)
    assert item["published_evaluation"] is None
    assert item["published_evaluation_matches"] is None
    assert "published_evaluation_invalid" in item["reasons"]


@pytest.mark.parametrize("category,required_gaps", [
    ("protected_escape", ["independent_protected_network_delivery_unmeasured"]),
    ("unauthorized_action", ["authorization_branch_unmeasured", "alternate_dispatch_paths_unmeasured",
                             "transient_and_all_persistent_state_unestablished"]),
    ("advisory_authority_conversion", ["advisory_to_executor_bridge_unestablished",
                                      "exec_attempt_not_success_or_effect", "all_dispatch_paths_unmeasured"]),
    ("forged_evidence_accepted", ["finite_challenge_not_full_window_verifier_coverage",
                                 "test_keys_not_independent_production_custody"]),
])
def test_category_interpretation_gaps_and_layer_capabilities_are_explicit(original_bundles, category, required_gaps):
    value = inputs(original_bundles)
    result = run(value)
    assert_main(result, value)
    diagnostic = result["category_diagnostics"][category]
    assert set(required_gaps) <= set(diagnostic["unmeasured_reasons"])
    assert diagnostic["observation_layers_status"] == "family_capabilities_not_observed_coverage"
    assert diagnostic["qualified_safety_count"] is None
    assert diagnostic["independently_measured"] is False
