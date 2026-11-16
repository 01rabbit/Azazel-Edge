"""SYNTHETIC enrolled captures with original real-signature replay; no actual trial."""

from copy import deepcopy
import json

import pytest

from azazel_edge.benchmark import common_event_binding as binding
from azazel_edge.benchmark import safety_evidence_composition as composition
from azazel_edge.benchmark import safety_observations as safety
from safety_observation_data import build, wire, digest, sign
from test_forged_input_refusal_v2 import make_case, evaluate as evaluate_forged
from test_safety_evidence_composition import bundle

CATEGORY = "forged_evidence_accepted"


def make_inputs(tmp_path, *, case=None, positive=False):
    case = case or make_case(tmp_path / "challenge", "wrong_key")
    original = bundle("forged_refusal_v2", case, evaluate_forged)
    plan = case["plan"]
    contract = json.loads(build("all-four-complete-finite-zero")[0])
    context = plan["expected_context"]
    contract["scope"].update(
        run_id="synthetic-enrolled-run",
        scope_ref=context["scope_ref"],
        session_ref=context["session_ref"],
        registration_sha256=context["registration_sha256"],
        kernel_boot_id=plan["kernel_boot_id"],
        policy_sha256=plan["expected_trust_sha256"],
        source_sha256=plan["expected_source_checkpoint"]["sha256"],
        owner=dict(
            producer_uid=context["producer_uid"], observer_uid=context["observer_uid"]
        ),
        interval=dict(start_ns=0, end_ns=100),
    )
    contract["keypins"].update(
        source_producer_public_key=context["producer_public_key"],
        source_witness_public_key=context["witness_public_key"],
    )
    for channel in contract["channels"].values():
        channel.update(
            collector_boot_id=plan["kernel_boot_id"],
            source_actor_uid=context["producer_uid"],
        )
    contract["channels"][CATEGORY]["capture_id"] = plan["capture_id"]
    opportunity = deepcopy(contract["opportunities"][CATEGORY][0])
    opportunity.update(
        start_ns=5,
        end_ns=80,
        challenge_sha256=digest(original["before_source"]),
        reference_sha256=digest(original["reference_frame"]),
        predicate=dict(
            invalid_input_sha256=digest(original["before_source"]),
            expected_disposition="refused_without_commit",
        ),
    )
    contract["opportunities"] = {
        category: [opportunity] if category == CATEGORY else []
        for category in safety.CATEGORIES
    }
    cursor = plan["expected_source_checkpoint"]["size"]
    data = dict(
        input_sha256=digest(original["before_source"]),
        disposition="accepted" if positive else "refused",
        cursor_before=cursor,
        cursor_after=cursor,
        journal_before_sha256=digest(original["before_journal"]),
        journal_after_sha256=digest(original["after_journal"]),
        anchor_before_sha256=digest(original["before_anchors"]),
        anchor_after_sha256=digest(original["after_anchors"]),
    )
    definitions = [
        ("open", 0, None, dict(boundary_ns=0)),
        (
            "challenge_begin",
            5,
            opportunity["id"],
            dict(challenge_sha256=opportunity["challenge_sha256"]),
        ),
        ("verifier_disposition", 60, opportunity["id"], data),
        (
            "challenge_end",
            80,
            opportunity["id"],
            dict(challenge_sha256=opportunity["challenge_sha256"]),
        ),
        ("close", 100, None, dict(boundary_ns=100)),
    ]
    channel = contract["channels"][CATEGORY]
    rows = [
        dict(
            schema_version="edge-finite-safety-row/v1",
            category=CATEGORY,
            channel_id=channel["channel_id"],
            capture_id=channel["capture_id"],
            kind=kind,
            monotonic_ns=at,
            opportunity_id=oid,
            data=datum,
            raw_ref_sha256=digest(original["plan"]),
        )
        for kind, at, oid, datum in definitions
    ]
    enrollment = dict(
        schema_version="edge-common-event-enrollment/v1",
        capture_group_id="synthetic-group",
        main_contract_sha256="0" * 64,
        entries=[
            dict(
                id="challenge",
                kind="forged_refusal_v2",
                category=CATEGORY,
                channel_id=channel["channel_id"],
                capture_id=channel["capture_id"],
                opportunity_id=opportunity["id"],
                fact_seq=3,
                required_layers=list(binding.REQUIRED_LAYERS),
            )
        ],
    )
    value = dict(
        contract=contract,
        rows=rows,
        enrollment=enrollment,
        supplements=dict(challenge=original),
    )
    return refresh(value)


def refresh(value):
    contract_raw = wire(value["contract"])
    contract_hash = digest(contract_raw)
    for row in value["rows"]:
        row.update(
            contract_sha256=contract_hash, scope=deepcopy(value["contract"]["scope"])
        )
    head = sign(value["rows"])
    channel = value["contract"]["channels"][CATEGORY]
    observations = dict(
        schema_version="edge-finite-safety-observations/v1",
        contract_sha256=contract_hash,
        scope=deepcopy(value["contract"]["scope"]),
        channels={
            CATEGORY: dict(
                channel_id=channel["channel_id"],
                capture_id=channel["capture_id"],
                rows=value["rows"],
            )
        },
    )
    composition_plan = dict(
        schema_version="edge-safety-evidence-composition-plan/v1",
        main_contract_sha256=contract_hash,
        entries=[
            dict(
                id=key,
                kind="forged_refusal_v2",
                sha256={
                    slot: digest(raw) if raw is not None else None
                    for slot, raw in raw_bundle.items()
                },
            )
            for key, raw_bundle in value["supplements"].items()
        ],
    )
    value["enrollment"]["main_contract_sha256"] = contract_hash
    value.update(
        contract_raw=contract_raw,
        observations_raw=wire(observations),
        safety_pins=dict(
            expected_contract_sha256=contract_hash,
            observer_public_key=value["contract"]["keypins"]["observer_public_key"],
            source_producer_public_key=value["contract"]["keypins"][
                "source_producer_public_key"
            ],
            source_witness_public_key=value["contract"]["keypins"][
                "source_witness_public_key"
            ],
            expected_stream_heads={
                c: head if c == CATEGORY else None for c in safety.CATEGORIES
            },
        ),
        composition_plan_raw=wire(composition_plan),
        expected_composition_plan_sha256=digest(wire(composition_plan)),
        event_enrollment_raw=wire(value["enrollment"]),
        expected_event_enrollment_sha256=digest(wire(value["enrollment"])),
    )
    return value


def arguments(value):
    return {
        key: value[key]
        for key in (
            "safety_pins",
            "composition_plan_raw",
            "expected_composition_plan_sha256",
            "supplements",
            "event_enrollment_raw",
            "expected_event_enrollment_sha256",
        )
    }


def evaluate(value):
    return binding.evaluate_common_event_binding(
        value["contract_raw"], value["observations_raw"], **arguments(value)
    )


def assert_original(result, value):
    args = arguments(value)
    args.pop("event_enrollment_raw")
    args.pop("expected_event_enrollment_sha256")
    original = composition.evaluate_safety_evidence_composition(
        value["contract_raw"], value["observations_raw"], **args
    )
    assert safety._same(result["composition_evaluation"], original)
    assert result["comparison_eligibility"] is False
    assert result["comparison_status"] == "WITHHELD"
    assert result["qualified_safety_count"] is None
    assert all(flag is False for flag in result["authority_flags"].values())


def test_exact_enrolled_originals_preserve_all_evaluations_and_inputs(tmp_path):
    value = make_inputs(tmp_path)
    before = deepcopy(value)
    result = evaluate(value)
    assert_original(result, value)
    item = result["bindings"][0]
    assert item["status"] == "verified_enrolled_finite_artifact_consistency", item[
        "reasons"
    ]
    assert item["identity_binding"] == "matched"
    assert item["main_assertion_consistency"] == "consistent"
    assert all(
        layer["verified"] is True for layer in item["finite_layer_coverage"].values()
    )
    assert item["source_input_completeness"] is item["whole_window_coverage"] is False
    assert value == before


@pytest.mark.parametrize(
    "kind",
    ["wrong_key", "scope_mismatch", "replay", "chain_corruption", "partial_frame"],
)
def test_all_original_v2_recipes_use_the_same_strict_adapter(tmp_path, kind):
    value = make_inputs(tmp_path, case=make_case(tmp_path / "original", kind))
    result = evaluate(value)
    assert_original(result, value)
    assert (
        result["bindings"][0]["status"]
        == "verified_enrolled_finite_artifact_consistency"
    )


def test_zero_entries_and_missing_enrollment_never_vacuously_bind(tmp_path):
    value = make_inputs(tmp_path)
    value["enrollment"]["entries"] = []
    result = evaluate(refresh(value))
    assert_original(result, value)
    assert result["status"] == "not_exercised" and result["bindings"] == []
    value["event_enrollment_raw"] = None
    assert evaluate(value)["status"] == "unknown"


@pytest.mark.parametrize(
    "fault", ["pin", "duplicate", "subset", "reordered", "bool_seq", "extra", "kind"]
)
def test_invalid_optional_enrollment_cannot_erase_originals(tmp_path, fault):
    value = make_inputs(tmp_path)
    entry = value["enrollment"]["entries"][0]
    if fault == "duplicate":
        value["enrollment"]["entries"].append(deepcopy(entry))
    elif fault == "subset":
        entry["required_layers"].pop()
    elif fault == "reordered":
        entry["required_layers"].reverse()
    elif fault == "bool_seq":
        entry["fact_seq"] = True
    elif fault == "extra":
        entry["approved"] = True
    elif fault == "kind":
        entry["kind"] = "invented"
    refresh(value)
    if fault == "pin":
        value["expected_event_enrollment_sha256"] = "0" * 64
    result = evaluate(value)
    assert_original(result, value)
    assert result["bindings"] == []
    assert result["reasons"] == ["event_enrollment_invalid_or_unbound"]


@pytest.mark.parametrize(
    "fault",
    [
        "capture",
        "scope",
        "session",
        "boot",
        "uid",
        "key",
        "baseline",
        "trust",
        "input",
        "reference",
        "plan_ref",
        "fact",
    ],
)
def test_exact_identity_and_byte_conflicts_are_not_timestamp_matches(tmp_path, fault):
    value = make_inputs(tmp_path)
    scope = value["contract"]["scope"]
    if fault == "capture":
        value["enrollment"]["entries"][0]["capture_id"] = "other"
    elif fault == "scope":
        scope["scope_ref"] = "other"
    elif fault == "session":
        scope["session_ref"] = "a" * 32
    elif fault == "boot":
        scope["kernel_boot_id"] = "11111111-2222-3333-4444-555555555555"
        for channel in value["contract"]["channels"].values():
            channel["collector_boot_id"] = scope["kernel_boot_id"]
    elif fault == "uid":
        scope["owner"]["producer_uid"] += 2
        for channel in value["contract"]["channels"].values():
            channel["source_actor_uid"] = scope["owner"]["producer_uid"]
    elif fault == "key":
        value["contract"]["keypins"]["source_producer_public_key"] = "9" * 64
    elif fault == "baseline":
        scope["source_sha256"] = "9" * 64
    elif fault == "trust":
        scope["policy_sha256"] = "9" * 64
    elif fault == "input":
        value["contract"]["opportunities"][CATEGORY][0]["predicate"][
            "invalid_input_sha256"
        ] = "9" * 64
        value["rows"][2]["data"]["input_sha256"] = "9" * 64
    elif fault == "reference":
        value["contract"]["opportunities"][CATEGORY][0]["reference_sha256"] = "9" * 64
    elif fault == "plan_ref":
        value["rows"][2]["raw_ref_sha256"] = "9" * 64
    else:
        value["enrollment"]["entries"][0]["fact_seq"] = 4
    result = evaluate(refresh(value))
    assert_original(result, value)
    assert result["bindings"][0]["status"] == "conflict", result["bindings"][0]


def test_main_positive_and_contradiction_are_preserved(tmp_path):
    value = make_inputs(tmp_path, positive=True)
    result = evaluate(value)
    assert_original(result, value)
    assert (
        result["composition_evaluation"]["main_evaluation"]["categories"][CATEGORY][
            "observed_violation_count"
        ]
        == 1
    )
    assert result["bindings"][0]["main_assertion_consistency"] == "conflict"
    assert result["bindings"][0]["status"] == "conflict"


def test_positive_after_missing_main_row_survives_unknown_binding(tmp_path):
    value = make_inputs(tmp_path, positive=True)
    observations = json.loads(value["observations_raw"])
    del observations["channels"][CATEGORY]["rows"][1]
    value["observations_raw"] = wire(observations)
    result = evaluate(value)
    assert_original(result, value)
    assert (
        result["composition_evaluation"]["main_evaluation"]["categories"][CATEGORY][
            "observed_violation_count"
        ]
        == 1
    )
    assert result["bindings"][0]["status"] == "unknown"
    assert (
        result["bindings"][0]["original_evaluation"]["status"]
        == "recorded_refusal_consistent"
    )


def test_missing_reference_keeps_original_known_state_change(tmp_path):
    from test_forged_input_refusal import refresh as refresh_sample

    case = make_case(tmp_path / "changed", "wrong_key")
    case["after"]["source"] += b"X"
    refresh_sample(case, "after", "source")
    value = make_inputs(tmp_path, case=case)
    value["supplements"]["challenge"]["reference_frame"] = None
    result = evaluate(refresh(value))
    assert_original(result, value)
    item = result["bindings"][0]
    assert item["status"] == "unknown"
    assert item["original_evaluation"]["changes"]["source"] is True
    assert item["finite_layer_coverage"]["sampled_source"]["verified"] is True
    assert item["finite_layer_coverage"]["sampled_source"]["original_value"] is True


def test_timing_enclosure_does_not_become_scheduling_or_gap_zero(tmp_path):
    value = make_inputs(tmp_path)
    value["rows"][2]["monotonic_ns"] = 35
    result = evaluate(refresh(value))
    assert_original(result, value)
    item = result["bindings"][0]
    assert item["status"] == "unknown"
    assert item["reasons"] == ["fact_not_after_original_sample_reads"]
    assert item["whole_window_coverage"] is False


def test_recognized_unsupported_family_never_has_vacuous_coverage(tmp_path):
    value = make_inputs(tmp_path)
    value["enrollment"]["entries"][0].update(
        kind="forged_refusal_v1", required_layers=[]
    )
    result = evaluate(refresh(value))
    assert_original(result, value)
    item = result["bindings"][0]
    assert item["status"] == "unknown"
    assert item["reasons"] == ["binding_adapter_unsupported_for_original_family"]
    assert all(
        layer["verified"] is None for layer in item["finite_layer_coverage"].values()
    )


def test_invalid_main_is_rejected_before_optional_enrollment(tmp_path, monkeypatch):
    value = make_inputs(tmp_path)
    monkeypatch.setattr(
        binding, "_enrollment", lambda *a: pytest.fail("optional enrollment ran first")
    )
    with pytest.raises(safety.SafetyObservationInputError):
        binding.evaluate_common_event_binding(
            b"invalid", b"invalid", safety_pins=value["safety_pins"]
        )


def test_all_seven_original_apis_and_their_positives_remain_exact(tmp_path):
    from test_safety_evidence_composition import make_original_bundles, inputs

    original_bundles = make_original_bundles(tmp_path)
    contract_raw, observations_raw, args = inputs(original_bundles)
    contract = json.loads(contract_raw)
    entries = []
    for index, kind in enumerate(composition.KINDS, 1):
        category = binding.CATEGORY_BY_KIND[kind]
        channel = contract["channels"][category]
        entries.append(
            dict(
                id=kind,
                kind=kind,
                category=category,
                channel_id=channel["channel_id"],
                capture_id=channel["capture_id"],
                opportunity_id="unsupported-selector-" + str(index),
                fact_seq=index,
                required_layers=list(binding.REQUIRED_LAYERS)
                if kind == "forged_refusal_v2"
                else [],
            )
        )
    enrollment = wire(
        dict(
            schema_version="edge-common-event-enrollment/v1",
            capture_group_id="synthetic-group",
            main_contract_sha256=digest(contract_raw),
            entries=entries,
        )
    )
    result = binding.evaluate_common_event_binding(
        contract_raw,
        observations_raw,
        **args,
        event_enrollment_raw=enrollment,
        expected_event_enrollment_sha256=digest(enrollment),
    )
    expected = composition.evaluate_safety_evidence_composition(
        contract_raw, observations_raw, **args
    )
    assert safety._same(result["composition_evaluation"], expected)
    assert len(result["composition_evaluation"]["supplemental_items"]) == 7
    assert (
        result["composition_evaluation"]["main_evaluation"]["categories"][
            "unauthorized_action"
        ]["observed_violation_count"]
        == 1
    )
    for item in result["bindings"]:
        if item["kind"] != "forged_refusal_v2":
            assert item["status"] == "unknown"
            assert all(
                layer["verified"] is None
                for layer in item["finite_layer_coverage"].values()
            )


def test_binding_path_is_pure_and_enrollment_bound_is_explicit(tmp_path, monkeypatch):
    import builtins

    value = make_inputs(tmp_path)
    monkeypatch.setattr(
        builtins, "open", lambda *a, **k: pytest.fail("binding performed file I/O")
    )
    assert (
        evaluate(value)["bindings"][0]["status"]
        == "verified_enrolled_finite_artifact_consistency"
    )
    value["event_enrollment_raw"] = b"x" * (binding.MAX_ENROLLMENT_BYTES + 1)
    value["expected_event_enrollment_sha256"] = digest(value["event_enrollment_raw"])
    result = evaluate(value)
    assert_original(result, value)
    assert result["bindings"] == []


def test_capture_snapshot_proxy_preserves_target_and_sealed_copy_calls():
    from common_event_binding_lab import Capture

    capture = object.__new__(Capture)
    capture.samples, capture.raw = {}, {}
    calls = []
    result = (
        {"source": b"source", "journal": b"journal", "anchors": b"anchors"},
        {"source": {"identity": "SYNTHETIC"}},
    )

    def original(paths):
        calls.append(paths)
        return result

    target = dict(source="s", journal="j", anchors="a")
    public = dict(plan="p", before_source="bs", after_source="as")
    assert capture.snapshot(original, target) is result
    assert capture.snapshot(original, target) is result
    assert capture.snapshot(original, public) is result
    assert capture.snapshot(original, public) is result
    assert calls == [target, target, public, public]
    assert set(capture.samples) == {"before", "after"}
    assert (
        capture.raw["before-source.raw"] == capture.raw["after-source.raw"] == b"source"
    )
