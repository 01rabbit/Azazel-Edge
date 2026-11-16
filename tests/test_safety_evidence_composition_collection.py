"""SYNTHETIC Root/reader/boot fences; real signed main and original replay APIs.

These tests create no permissions, actors, sockets or kernel observations.
Actual descriptor and Linux ownership checks remain the unchanged base tests.
"""

from copy import deepcopy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_edge.benchmark import safety_evidence_composition_collection as c
from safety_collection_data import BOOT, build_bundle
from safety_observation_data import digest, wire
from test_natural_close_recv import build, evaluate


def setup(monkeypatch, *, case_id="root_only_refused", present=True):
    uid = 65533
    bundle = build_bundle(Path("/sealed/main"), "violation", observer_uid=uid)
    files = {str(bundle["paths"][name]): raw for name, raw in bundle["files"].items()}
    artifacts = {}
    if present:
        case = build(case_id)
        artifacts = dict(
            plan=wire(case["plan"]),
            probe=wire(case["probe"]),
            evaluation=wire(evaluate(case)),
            **{
                name: case[name + "_raw"]
                for name in ("sot_before", "sot_after", "audit_before", "audit_after")
            },
        )
    plan = dict(
        schema_version="edge-safety-evidence-composition-plan/v1",
        main_contract_sha256=digest(bundle["files"]["contract"]),
        entries=[
            dict(
                id="natural-1",
                kind="natural_close_recv",
                sha256={
                    k: None if v is None else digest(v) for k, v in artifacts.items()
                },
            )
        ]
        if present
        else [],
    )
    paths = {
        name: None if raw is None else "/sealed/supplement/" + name
        for name, raw in artifacts.items()
    }
    files.update(
        {paths[name]: raw for name, raw in artifacts.items() if raw is not None}
    )
    files["/sealed/composition-plan"] = wire(plan)
    enrollment = dict(
        schema_version="edge-safety-evidence-composition-enrollment/v1",
        reader_uid=uid,
        kernel_boot_id=BOOT,
        safety=dict(
            enrollment_path=str(bundle["paths"]["enrollment"]),
            enrollment_sha256=bundle["expected_enrollment_sha256"],
            checkpoint_sha256=bundle["expected_checkpoint_sha256"],
        ),
        composition_plan_path="/sealed/composition-plan",
        supplements={"natural-1": paths} if present else {},
    )
    files["/sealed/composition-enrollment"] = wire(enrollment)
    state = SimpleNamespace(
        files=files,
        bundle=bundle,
        plan=plan,
        enrollment=enrollment,
        uid=uid,
        boot=BOOT,
        fail_read=None,
        fail_verify=None,
        fail_close=None,
        instances=[],
        trace=[],
    )

    class Held:
        def __init__(self):
            self.number = len(state.instances)
            self.paths, self.closed = [], []
            self.verifications = 0
            state.instances.append(self)

        def read(self, path, maximum):
            path = str(path)
            self.paths.append(path)
            state.trace.append(("read", self.number, path))
            if path == state.fail_read:
                raise OSError("SYNTHETIC unsafe metadata or missing enrolled file")
            raw = files[path]
            assert len(raw) <= maximum
            return raw

        def verify(self):
            self.verifications += 1
            state.trace.append(("verify", self.number, self.verifications))
            if state.fail_verify == (self.number, self.verifications):
                raise OSError("SYNTHETIC held metadata changed")

        def close(self):
            self.closed.extend(self.paths)
            state.trace.append(("close", self.number))
            return ["OSError"] if state.fail_close == self.number else []

    monkeypatch.setattr(c.collection, "_HeldFiles", Held)
    monkeypatch.setattr(c.collection, "_kernel_boot_id", lambda: state.boot)
    monkeypatch.setattr(c, "os", SimpleNamespace(geteuid=lambda: state.uid))
    monkeypatch.setattr(
        c.collection,
        "os",
        SimpleNamespace(geteuid=lambda: state.uid, fspath=os.fspath),
    )
    return state


def invoke(state, *, enrollment_pin=None, plan_pin=None):
    return c.collect_safety_evidence_composition(
        "/sealed/composition-enrollment",
        expected_composition_enrollment_sha256=enrollment_pin
        or digest(state.files["/sealed/composition-enrollment"]),
        expected_composition_plan_sha256=plan_pin
        or digest(state.files["/sealed/composition-plan"]),
    )


def reseal(state):
    state.files["/sealed/composition-enrollment"] = wire(state.enrollment)
    state.files["/sealed/composition-plan"] = wire(state.plan)


def assert_closed(state):
    assert all(held.paths == held.closed for held in state.instances)


@pytest.mark.parametrize(
    "case_id",
    [
        "root_only_refused",
        "partial_read_close",
        "actor_death",
        "observer_stop_after_copy",
        "missing_after_sot",
    ],
)
def test_real_main_and_original_natural_close_replay_with_synthetic_intake(
    monkeypatch, case_id
):
    state = setup(monkeypatch, case_id=case_id)
    originals = deepcopy(state.files)
    result = invoke(state)
    base = result["base_collection"]
    composed = result["composition"]
    assert composed["main_evaluation"] == base["evaluation"]
    assert (
        base["evaluation"]["categories"]["protected_escape"]["observed_violation_count"]
        == 1
    )
    item = composed["supplemental_items"][0]
    assert item["replayed_evaluation"] == evaluate(build(case_id))
    assert item["replayed_evaluation"]["reciprocal_pair_verified"] is None
    assert item["replayed_evaluation"]["root_only_refusal_response_consistent"] is None
    assert composed["comparison_eligibility"] is False
    assert composed["qualified_safety_count"] is None
    assert all(result[flag] is False for flag in c.safety.FLAGS)
    outer, main = state.instances
    assert set(outer.paths) == set(originals)
    assert set(main.paths) == {str(p) for p in state.bundle["paths"].values()}
    assert state.trace[-1] == ("close", 0)
    assert state.files == originals
    assert_closed(state)


def test_empty_optional_registry_preserves_signed_main(monkeypatch):
    state = setup(monkeypatch, present=False)
    result = invoke(state)
    assert result["composition"]["supplemental_items"] == []
    assert (
        result["composition"]["main_evaluation"]
        == result["base_collection"]["evaluation"]
    )
    assert_closed(state)


def test_explicit_missing_published_path_retains_pin_main_and_original_replay(
    monkeypatch,
):
    state = setup(monkeypatch)
    pin = state.plan["entries"][0]["sha256"]["evaluation"]
    state.enrollment["supplements"]["natural-1"]["evaluation"] = None
    reseal(state)
    originals = deepcopy(state.files)
    result = invoke(state)
    item = result["composition"]["supplemental_items"][0]
    assert item["status"] == "unknown"
    assert item["expected_sha256"]["evaluation"] == pin
    assert item["published_evaluation"] is None
    assert item["replayed_evaluation"] == evaluate(build())
    assert (
        result["composition"]["main_evaluation"]
        == result["base_collection"]["evaluation"]
    )
    assert "/sealed/supplement/evaluation" not in state.instances[0].paths
    assert state.files == originals
    assert_closed(state)


@pytest.mark.parametrize(
    "published", [b"malformed\n", wire({"self_reported_approval": True})]
)
def test_pinned_published_diagnostic_is_compared_never_trusted(monkeypatch, published):
    state = setup(monkeypatch)
    state.files["/sealed/supplement/evaluation"] = published
    state.plan["entries"][0]["sha256"]["evaluation"] = digest(published)
    reseal(state)
    result = invoke(state)
    item = result["composition"]["supplemental_items"][0]
    assert item["status"] == "unknown"
    assert item["replayed_evaluation"] == evaluate(build())
    assert (
        result["composition"]["main_evaluation"]
        == result["base_collection"]["evaluation"]
    )
    assert result["composition"]["comparison_eligibility"] is False
    assert_closed(state)


def test_all_outer_originals_remain_held_during_public_evaluation(monkeypatch):
    state = setup(monkeypatch)
    original = c.composition.evaluate_safety_evidence_composition
    evaluated = []

    def evaluate_held(*args, **kwargs):
        outer, base = state.instances
        assert set(outer.paths) == set(state.files)
        assert outer.closed == []
        assert base.closed == base.paths
        evaluated.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        c.composition, "evaluate_safety_evidence_composition", evaluate_held
    )
    invoke(state)
    assert evaluated == [True]
    assert_closed(state)


def test_aggregate_budget_refuses_before_public_evaluation(monkeypatch):
    state = setup(monkeypatch)
    monkeypatch.setattr(c.composition, "MAX_TOTAL_BYTES", 1)

    def forbidden(*args, **kwargs):
        pytest.fail("over-budget enrolled artifacts must not reach public evaluation")

    monkeypatch.setattr(
        c.composition, "evaluate_safety_evidence_composition", forbidden
    )
    with pytest.raises(c.collection.SafetyCollectionError, match="total byte bound"):
        invoke(state)
    assert_closed(state)


@pytest.mark.parametrize(
    "fault", ["root", "bool", "reader", "boot", "actor", "server", "historical_boot"]
)
def test_current_reader_boot_and_original_actor_roles_are_mandatory(monkeypatch, fault):
    state = setup(monkeypatch)
    if fault in ("root", "bool", "reader"):
        state.uid = {"root": 0, "bool": True, "reader": 65532}[fault]
    elif fault == "boot":
        state.boot = "00000000-0000-4000-8000-000000000002"
    else:
        raw = json.loads(state.files["/sealed/supplement/plan"])
        if fault == "historical_boot":
            raw["kernel_boot_id"] = "00000000-0000-4000-8000-000000000002"
        else:
            raw[fault]["uid"] = state.uid
        state.files["/sealed/supplement/plan"] = wire(raw)
        state.plan["entries"][0]["sha256"]["plan"] = digest(wire(raw))
        reseal(state)
    originals = deepcopy(state.files)
    with pytest.raises(c.collection.SafetyCollectionError):
        invoke(state)
    assert state.files == originals
    assert_closed(state)


@pytest.mark.parametrize(
    "slot", ["plan", "probe", "sot_before", "audit_after", "evaluation"]
)
@pytest.mark.parametrize("fault", ["unsafe", "pin"])
def test_present_optional_file_failure_refuses_new_collection_without_touching_main(
    monkeypatch, slot, fault
):
    state = setup(monkeypatch)
    path = state.enrollment["supplements"]["natural-1"][slot]
    if fault == "unsafe":
        state.fail_read = path
    else:
        state.files[path] += b" "
    originals = deepcopy(state.files)
    with pytest.raises(c.collection.SafetyCollectionError):
        invoke(state)
    assert len(state.instances) == 2  # unchanged main intake already ran
    assert state.files == originals
    assert_closed(state)


@pytest.mark.parametrize(
    "fault", ["enrollment_pin", "plan_pin", "alias", "null", "extra", "bad_main"]
)
def test_external_registration_exact_paths_and_null_binding(monkeypatch, fault):
    state = setup(monkeypatch)
    kwargs = {}
    if fault == "enrollment_pin":
        kwargs["enrollment_pin"] = "f" * 64
    elif fault == "plan_pin":
        kwargs["plan_pin"] = "f" * 64
    elif fault == "alias":
        state.enrollment["supplements"]["natural-1"]["evaluation"] = (
            "/sealed/supplement/plan"
        )
    elif fault == "null":
        state.enrollment["supplements"]["natural-1"]["probe"] = None
    elif fault == "extra":
        state.enrollment["supplements"]["undeclared"] = {}
    else:
        state.enrollment["safety"]["checkpoint_sha256"] = "f" * 64
        state.fail_read = "/sealed/supplement/probe"
    reseal(state)
    with pytest.raises(c.collection.SafetyCollectionError):
        invoke(state, **kwargs)
    if fault == "bad_main":
        assert not any(
            "supplement" in path for held in state.instances for path in held.paths
        )
    assert_closed(state)


@pytest.mark.parametrize("phase", [1, 2, 3])
def test_outer_metadata_fences_refuse_and_close_all_owned_files(monkeypatch, phase):
    state = setup(monkeypatch)
    state.fail_verify = (0, phase)
    with pytest.raises(c.collection.SafetyCollectionError):
        invoke(state)
    assert_closed(state)


@pytest.mark.parametrize("instance", [0, 1])
def test_close_failure_refuses_after_attempting_all_owned_closes(monkeypatch, instance):
    state = setup(monkeypatch)
    state.fail_close = instance
    with pytest.raises(c.collection.SafetyCollectionError, match="close"):
        invoke(state)
    assert_closed(state)


@pytest.mark.parametrize("fault", ["reader", "boot", "different_main"])
def test_public_evaluation_still_has_final_reader_and_original_main_fences(
    monkeypatch, fault
):
    state = setup(monkeypatch)
    original = c.composition.evaluate_safety_evidence_composition

    def evaluate_then_change(*args, **kwargs):
        result = original(*args, **kwargs)
        if fault == "reader":
            state.uid += 1
        elif fault == "boot":
            state.boot = "00000000-0000-4000-8000-000000000002"
        else:
            result["main_evaluation"] = {}
        return result

    monkeypatch.setattr(
        c.composition, "evaluate_safety_evidence_composition", evaluate_then_change
    )
    with pytest.raises(c.collection.SafetyCollectionError):
        invoke(state)
    assert_closed(state)


def test_forged_reader_roles_use_original_trust_producer_and_consumer(tmp_path):
    from test_forged_input_refusal import build as forge

    case = forge(tmp_path)
    artifacts = dict(plan=wire(case["plan"]), trust=case["trust_raw"])
    trust = json.loads(artifacts["trust"])
    for role in ("producer_uid", "observer_uid"):
        with pytest.raises(c.collection.SafetyCollectionError, match="role overlaps"):
            c._reader_roles("forged_refusal_v1", artifacts, trust[role], BOOT)
    c._reader_roles("forged_refusal_v1", artifacts, 65533, BOOT)


def test_original_natural_close_plan_unicode_metadata_uses_original_parser(monkeypatch):
    state = setup(monkeypatch)
    case = build()
    # Original worker grammar bounds characters, allowing this 384-byte string.
    case["plan"]["actor"]["error"] = "失" * 128
    expected = evaluate(case)
    assert expected["clean_lifecycle_verified"] is None
    plan_raw = wire(case["plan"])
    state.files["/sealed/supplement/plan"] = plan_raw
    state.files["/sealed/supplement/evaluation"] = wire(expected)
    pins = state.plan["entries"][0]["sha256"]
    pins["plan"] = digest(plan_raw)
    pins["evaluation"] = digest(wire(expected))
    reseal(state)
    originals = deepcopy(state.files)
    result = invoke(state)
    assert (
        result["composition"]["supplemental_items"][0]["replayed_evaluation"]
        == expected
    )
    assert (
        result["composition"]["main_evaluation"]
        == result["base_collection"]["evaluation"]
    )
    assert state.files == originals
    assert_closed(state)


def test_original_forged_trust_long_path_uses_original_parser(tmp_path):
    from test_forged_input_refusal import build as forge, evaluate as replay

    case = forge(tmp_path)
    trust = json.loads(case["trust_raw"])
    # Original trust grammar permits physical paths up to 1024 characters.
    trust["source_path"] = "/synthetic/" + "/".join(["segment" * 10] * 5)
    assert len(trust["source_path"]) > 256
    case["trust_raw"] = wire(trust)
    case["plan"]["expected_trust_sha256"] = digest(case["trust_raw"])
    artifacts = dict(plan=wire(case["plan"]), trust=case["trust_raw"])
    originals = deepcopy(artifacts)
    c._reader_roles("forged_refusal_v1", artifacts, 65533, BOOT)
    result = replay(case)
    assert result["qualified_safety_count"] is None
    assert artifacts == originals
    assert wire(case["plan"]) == originals["plan"]
    assert case["trust_raw"] == originals["trust"]
