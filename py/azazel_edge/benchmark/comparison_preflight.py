"""Bounded offline readiness diagnostics; no real-comparison admission path."""

from copy import deepcopy
import hashlib
import json
import random
import re

from .benefit import SAFETY_FIELDS, manifest_digest, validate_manifest
from .measurement import measure_experiment, _join
from ..outcome.golden_replay import GoldenReplayError

SCHEMA = "edge-comparison-preflight-plan/v1"
INPUT_SCHEMA = "edge-comparison-preflight-input/v1"
GATES = dict(load_factor=1.2, examined_floor=0.98, clock_budget_ns=5_000_000)
PREREQUISITES = (
    "event_binding",
    "finite_coverage",
    "clock",
    "assignments",
    "independent_safety",
    "service_cost",
    "execution_mechanism_release",
    "independent_review",
)
REFERENCES = ("event_binding", "window_cost")
PLAN_FIELDS = {
    "schema_version",
    "manifest_sha256",
    "data_kind",
    "hypothesis",
    "fixed_gates",
    "allocation_seed",
    "arm_descriptions",
    "exclusions",
    "required_prerequisites",
    "historical_pilot",
}
MANIFEST_FIELDS = {
    "schema_version",
    "experiment_id",
    "phase",
    "evidence_kind",
    "horizon_seconds",
    "provenance",
    "plan",
    "arms",
    "baseline",
    "candidate",
    "assignments",
}
ATTEMPT_FIELDS = {"assignment_id", "capture", "edge_recording", "linkage"}
FLAGS = dict(
    authorizes_transition=False,
    experiment=False,
    measurement_completed=False,
    production_admission=False,
    resume_authorized=False,
)


ALLOCATION_SEED = 20261116
ANALYSIS_PLAN = dict(analysis_seed=17, bootstrap_repeats=500, minimum_pairs=2,
                     minimum_gain_seconds=5, max_latency_increase_ms=2, max_error_rate_increase=0.01)
SCENARIOS = ("gain", "neutral", "service_harm", "protection_harm", "actor_pause",
             "shared_source", "clock_uncertain", "capture_gap", "restart_lost")
EXPECTED_GATES = {
    "gain": "recorded_thresholds_met_requires_independent_review",
    "neutral": "practical_time_gain_not_demonstrated",
    "service_harm": "legitimate_service_gate_failed",
    "protection_harm": "protected_goal_regression",
    **{name: "inconclusive_missing_or_insufficient_pairs" for name in SCENARIOS[4:]},
}
HISTORICAL_HASHES = dict(
    protocol_sha256="bba8034f1f58986a71386dc1805a1114ddc33563dfde168466cd46fdfcca485a",
    cases_sha256="0f29a0025ebf931e4ce107d02a209b796563780b7de0f539c64eb6b463cd7ce8",
)
SOURCE_COMMIT = "190750e3a5c872609b4b6ee5a93e62954b1602d0"
PROSPECTIVE_DESCRIPTIONS = {
    arm: dict(arm=arm, effective_profile="not_enrolled", network="none",
              observer_mode="off" if arm == "reference" else "on",
              purpose="prospective_readonly_virtual_pilot")
    for arm in ("reference", "candidate")
}
PROSPECTIVE_PROVENANCE = dict(
    repo_commits={"01rabbit/Azazel-Edge": SOURCE_COMMIT},
    corpus_sha256="ac872b73662abb27ac5489c4da30d0b53549030c43639b2734121b3b0de914a9",
    policy_sha256="3470a33f8fb442c230488c8632e5dcb02d686e5745e4240bfe207e882b19c3e0",
)


def _frozen_assignments():
    generator = random.Random(ALLOCATION_SEED)
    values = []
    for scenario in SCENARIOS:
        for pair in range(2):
            order = ["reference", "candidate"]
            generator.shuffle(order)
            values.extend(dict(id=f"{scenario}-p{pair}-{arm}", pair_id=f"{scenario}-pair-{pair}",
                               arm=arm, scenario=scenario, seed=100 + pair, order=order.index(arm))
                          for arm in ("reference", "candidate"))
    return values


def _frozen_prospective(plan, manifest):
    """The fixed table describes an un-enrolled future software profile only."""
    _need(_same(plan["arm_descriptions"], PROSPECTIVE_DESCRIPTIONS), "prospective arm descriptions changed")
    expected_arms = [dict(id=arm, role="prospective_readonly_" + arm,
                          source_commit=SOURCE_COMMIT,
                          config_sha256=manifest_digest(PROSPECTIVE_DESCRIPTIONS[arm]),
                          environment_id="future-offline-linux-not-enrolled")
                     for arm in ("reference", "candidate")]
    _need(_same(manifest["arms"], expected_arms), "prospective arm source/config/profile changed")
    _need(_same(manifest["provenance"], PROSPECTIVE_PROVENANCE), "prospective source provenance changed")
    _need(manifest["experiment_id"] == "edge-virtual-prerequisite-pilot-v1"
          and manifest["baseline"] == "reference" and manifest["candidate"] == "candidate",
          "prospective experiment identity changed")
    _need(_same(manifest["assignments"], _frozen_assignments()), "frozen 36-assignment allocation changed")


class ComparisonPreflightInputError(ValueError):
    """An invalid global input cannot describe the frozen assigned population."""


def _need(condition, reason):
    if not condition:
        raise ComparisonPreflightInputError(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _wire(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        _need(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def _depth(value, level=0):
    _need(level <= 24, "JSON depth exceeds 24")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, level + 1)


def _decode(raw, maximum):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, "original byte bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        _depth(value)
        _need(_wire(value) == raw, "canonical JSON plus LF required")
        return value
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ComparisonPreflightInputError("invalid canonical bounded JSON") from exc


def _same(left, right):
    return _wire(left) == _wire(right)


def _global(plan_raw, manifest_raw, inputs_raw, plan_pin, manifest_pin):
    _need(
        type(plan_raw) is bytes and type(manifest_raw) is bytes,
        "original plan and manifest bytes required",
    )
    _need(type(plan_pin) is str and _sha(plan_raw) == plan_pin, "plan pin differs")
    _need(
        type(manifest_pin) is str and _sha(manifest_raw) == manifest_pin,
        "manifest file pin differs",
    )
    plan = _decode(plan_raw, 128 * 1024)
    manifest = _decode(manifest_raw, 8 * 1024 * 1024)
    inputs = _decode(inputs_raw, 8 * 1024 * 1024)
    _need(type(plan) is dict and set(plan) == PLAN_FIELDS, "plan fields")
    _need(
        plan["schema_version"] == SCHEMA
        and plan["manifest_sha256"] == manifest_pin
        and plan["data_kind"] == "FROZEN_SOFTWARE_PROTOCOL_NOT_MEASUREMENT",
        "plan identity",
    )
    _need(_same(plan["fixed_gates"], GATES), "fixed gates changed")
    _need(
        plan["required_prerequisites"] == list(PREREQUISITES), "prerequisites changed"
    )
    _need(
        type(plan["allocation_seed"]) is int and plan["allocation_seed"] == ALLOCATION_SEED,
        "allocation seed changed",
    )
    _need(
        type(plan["hypothesis"]) is str and 0 < len(plan["hypothesis"]) <= 1024,
        "bounded hypothesis",
    )
    _need(
        type(plan["exclusions"]) is list
        and 0 < len(plan["exclusions"]) <= 32
        and all(type(x) is str and 0 < len(x) <= 1024 for x in plan["exclusions"]),
        "explicit exclusion rules",
    )
    _need(
        type(manifest) is dict and set(manifest) == MANIFEST_FIELDS, "manifest fields"
    )
    try:
        assignments = validate_manifest(manifest)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ComparisonPreflightInputError(
            "invalid original benefit manifest"
        ) from exc
    _need(
        len(assignments) <= 128 and manifest["phase"] == "pilot",
        "pilot assignment bound",
    )
    _need(_same(manifest["horizon_seconds"], 60), "frozen horizon changed")
    _need(_same(manifest["plan"], ANALYSIS_PLAN), "frozen nested analysis thresholds changed")
    _need(
        type(inputs) is dict
        and set(inputs) == {"schema_version", "manifest_sha256", "records"}
        and inputs["schema_version"] == INPUT_SCHEMA
        and inputs["manifest_sha256"] == manifest_digest(manifest),
        "input envelope",
    )
    _need(
        type(inputs["records"]) is list and len(inputs["records"]) <= 128,
        "attempt bound",
    )
    descriptions = plan["arm_descriptions"]
    _need(
        type(descriptions) is dict
        and set(descriptions) == {arm["id"] for arm in manifest["arms"]},
        "frozen arm descriptions",
    )
    for arm in manifest["arms"]:
        _need(
            arm["config_sha256"] == manifest_digest(descriptions[arm["id"]]),
            "arm config description pin differs",
        )
    historical = plan["historical_pilot"]
    _need(
        type(historical) is dict
        and set(historical)
        == {
            "protocol_sha256",
            "cases_sha256",
            "scenario_ids",
            "expected_gates",
            "data_kind",
            "confirmatory",
        },
        "historical reference fields",
    )
    _need(
        historical["data_kind"] == "SYNTHETIC_MECHANICAL_REGRESSION"
        and historical["confirmatory"] is False,
        "historical status",
    )
    for name, expected in HISTORICAL_HASHES.items():
        _need(type(historical[name]) is str and re.fullmatch("[0-9a-f]{64}", historical[name])
              and historical[name] == expected, "historical original hash changed")
    _need(_same(historical["scenario_ids"], list(SCENARIOS)), "historical scenario IDs changed")
    _need(_same(historical["expected_gates"], EXPECTED_GATES), "historical expected gates changed")
    if manifest["evidence_kind"] != "synthetic":
        _frozen_prospective(plan, manifest)
    return plan, manifest, inputs, assignments


def _attempt(record, index, assignments, manifest):
    reasons = []
    row = dict(
        index=index,
        assignment_id=None,
        status="withheld",
        reported_safety={},
        unknown_safety_categories=list(SAFETY_FIELDS),
        reasons=reasons,
        original_join=None,
        original_join_error=None,
    )
    if type(record) is not dict:
        reasons.append("attempt_object_invalid")
        return row
    key = record.get("assignment_id")
    row["assignment_id"] = key if type(key) is str else None
    if type(key) is not str or key not in assignments:
        reasons.append("unknown_or_missing_assignment")
    if set(record) != ATTEMPT_FIELDS:
        reasons.append("attempt_fields_invalid")
    capture = record.get("capture")
    if type(capture) is not dict:
        reasons.append("service_capture_unavailable")
    else:
        raw_safety = capture.get("safety_violations")
        if type(raw_safety) is dict:
            for category in SAFETY_FIELDS:
                value = raw_safety.get(category)
                if type(value) is int and 0 <= value <= 10**9:
                    row["reported_safety"][category] = value
                    row["unknown_safety_categories"].remove(category)
            if set(raw_safety) != set(SAFETY_FIELDS):
                reasons.append("safety_fields_missing_or_unknown")
        if type(key) is str and key in assignments:
            declared = assignments[key]
            for name in ("assignment_id", "scenario", "seed"):
                if not _same(
                    capture.get(name),
                    declared["id" if name == "assignment_id" else name],
                ):
                    reasons.append("capture_" + name + "_binding_differs")
    for field in ("edge_recording", "linkage"):
        if type(record.get(field)) is not dict:
            reasons.append(field + "_unavailable")
    if row["unknown_safety_categories"]:
        reasons.append("safety_unmeasured_or_invalid")
    if any(value > 0 for value in row["reported_safety"].values()):
        reasons.append("reported_safety_violation_retained")
    if not row["unknown_safety_categories"] and type(key) is str and key in assignments:
        try:
            # Never manufacture missing counts or run a real benefit comparison.
            joined = _join(manifest, assignments[key], record)
            row["original_join"] = {name: value for name, value in joined.items() if name != "_identity"}
            reasons.extend("original_join:" + reason for reason in joined["reasons"])
            reasons.append("original_join_is_diagnostic_not_prerequisite_qualification")
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError, OSError, GoldenReplayError) as exc:
            row["original_join"] = dict(assignment_id=key, status="rejected", reasons=["invalid_capture_or_linkage"])
            row["original_join_error"] = type(exc).__name__
            reasons.append("original_measurement_join_rejected_inputs")
    return row


def _references(artifacts, pins):
    artifacts = {} if artifacts is None else artifacts
    pins = {} if pins is None else pins
    rows = []
    for name in REFERENCES:
        row = dict(
            name=name,
            status="unavailable",
            sha256=None,
            qualification="diagnostic_reference_not_prerequisite_proof",
        )
        if type(artifacts) is not dict or type(pins) is not dict:
            row["reason"] = "reference_envelope_invalid"
        else:
            raw, pin = artifacts.get(name), pins.get(name)
            if raw is not None:
                if type(raw) is bytes and len(raw) <= 64 * 1024 * 1024:
                    row["sha256"] = _sha(raw)
                    row["status"] = (
                        "pinned_reference"
                        if type(pin) is str and pin == row["sha256"]
                        else "pin_mismatch"
                    )
                else:
                    row["status"] = "invalid_or_overbound"
            if set(artifacts) - set(REFERENCES) or set(pins) - set(REFERENCES):
                row["envelope_reason"] = "unknown_reference_slots"
        rows.append(row)
    return rows


def evaluate_comparison_preflight(
    plan_raw,
    manifest_raw,
    inputs_raw,
    *,
    expected_plan_sha256,
    expected_manifest_sha256,
    reference_artifacts=None,
    expected_reference_sha256=None,
):
    """Preserve reported positives and unknowns, without starting real comparison."""
    plan, manifest, inputs, assignments = _global(
        plan_raw,
        manifest_raw,
        inputs_raw,
        expected_plan_sha256,
        expected_manifest_sha256,
    )
    rows = [
        _attempt(record, index, assignments, manifest)
        for index, record in enumerate(inputs["records"])
    ]
    counts = {}
    for row in rows:
        key = row["assignment_id"]
        if key in assignments:
            counts[key] = counts.get(key, 0) + 1
    duplicates = sorted(key for key, count in counts.items() if count > 1)
    for row in rows:
        if row["assignment_id"] in duplicates:
            row["reasons"].append("duplicate_attempt_not_selected")
    mechanical, mechanical_error = None, None
    if manifest["evidence_kind"] == "synthetic":
        # Never filter out harmful, failed, censored or incomplete cases. Nulls
        # cannot cross the old boundary, whose counts require exact integers.
        if any(row["unknown_safety_categories"] for row in rows):
            mechanical_error = "synthetic_safety_unavailable_not_coerced"
        else:
            try:
                mechanical = measure_experiment(
                    manifest,
                    {
                        "manifest_sha256": manifest_digest(manifest),
                        "records": inputs["records"],
                    },
                )
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OverflowError,
                RecursionError,
            ):
                mechanical_error = "original_measurement_rejected_inputs"
    return dict(
        schema_version="edge-comparison-preflight-report/v1",
        status="preflight_complete_measurement_withheld",
        plan_sha256=_sha(plan_raw),
        manifest_file_sha256=_sha(manifest_raw),
        manifest_sha256=manifest_digest(manifest),
        inputs_sha256=_sha(inputs_raw),
        evidence_kind=manifest["evidence_kind"],
        frozen_plan=deepcopy(plan),
        original_manifest=deepcopy(manifest),
        original_inputs=deepcopy(inputs),
        assigned_runs=len(assignments),
        received_attempts=len(rows),
        attempts=rows,
        missing_assignments=sorted(set(assignments) - set(counts)),
        duplicate_assignments=duplicates,
        reported_positive_attempts=[
            deepcopy(row)
            for row in rows
            if any(v > 0 for v in row["reported_safety"].values())
        ],
        references=_references(reference_artifacts, expected_reference_sha256),
        prerequisite_diagnostics={name: "unqualified" for name in PREREQUISITES},
        blockers=[name + "_qualification_unavailable" for name in PREREQUISITES],
        mechanical_evaluation=mechanical,
        mechanical_error=mechanical_error,
        comparison_result=None,
        actual_comparison_started=False,
        comparison_qualified=False,
        qualified_safety_count=None,
        whole_measurement_qualified=False,
        authority_flags=dict(FLAGS),
        **FLAGS,
    )
