"""Offline paired benefit analysis (#393 / Azazel#67), never runtime authority.

Administrative censoring at a verified common horizon is handled as min(T, H).
Earlier loss is missing evidence, never a successful censored attack. The input
manifest must be frozen before collecting receipts; a matching hash proves
binding only, not independent registration, source truth or hardware readiness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import statistics
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "azazel-benefit-experiment/v1"
REPORT_SCHEMA = "azazel-benefit-report/v1"
MAX_BYTES = 8 * 1024 * 1024
MAX_RUNS = 10000
SAFETY_FIELDS = ("unauthorized_action", "protected_escape", "forged_evidence_accepted", "advisory_authority_conversion")


class BenefitInputError(ValueError):
    pass


def _number(value: Any, *, minimum: float = 0, maximum: float = 1e12) -> float:
    if type(value) not in (int, float) or not minimum <= value <= maximum or not math.isfinite(value):
        raise BenefitInputError("invalid finite numeric measurement")
    return float(value)


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise BenefitInputError("invalid bounded identifier")
    return value


def _digest(value: Any, length: int = 64) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{%d}" % length, value) is None:
        raise BenefitInputError("invalid pinned digest")
    return value


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def validate_manifest(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(manifest, Mapping) or manifest.get("schema_version") != SCHEMA:
        raise BenefitInputError("unsupported experiment schema")
    _text(manifest.get("experiment_id"))
    if manifest.get("phase") not in ("pilot", "confirmatory"):
        raise BenefitInputError("experiment phase must be explicit")
    if manifest.get("evidence_kind") not in ("synthetic", "recorded_lab", "container", "hardware"):
        raise BenefitInputError("evidence kind must be explicit")
    _number(manifest.get("horizon_seconds"), minimum=0.001, maximum=86400)
    provenance = manifest.get("provenance")
    if not isinstance(provenance, Mapping) or not provenance.get("repo_commits"):
        raise BenefitInputError("missing pinned provenance")
    if not isinstance(provenance["repo_commits"], Mapping) or len(provenance["repo_commits"]) > 32:
        raise BenefitInputError("invalid source pins")
    for repo, commit in provenance["repo_commits"].items():
        _text(repo)
        _digest(commit, 40)
    _digest(provenance.get("corpus_sha256"))
    _digest(provenance.get("policy_sha256"))
    plan = manifest.get("plan")
    if not isinstance(plan, Mapping):
        raise BenefitInputError("missing preregistered analysis plan")
    for name in ("minimum_gain_seconds", "max_latency_increase_ms", "max_error_rate_increase"):
        _number(plan.get(name), maximum=1 if name == "max_error_rate_increase" else 1e9)
    for name, lower, upper in (("minimum_pairs", 2, MAX_RUNS // 2), ("bootstrap_repeats", 100, 10000), ("analysis_seed", 0, 2**32 - 1)):
        value = plan.get(name)
        if type(value) is not int or not lower <= value <= upper:
            raise BenefitInputError("invalid bounded analysis plan")
    arms = manifest.get("arms")
    if not isinstance(arms, list) or not 2 <= len(arms) <= 16:
        raise BenefitInputError("invalid comparator arms")
    arm_ids = set()
    for arm in arms:
        if not isinstance(arm, Mapping):
            raise BenefitInputError("invalid arm object")
        name = _text(arm.get("id"))
        if name in arm_ids:
            raise BenefitInputError("duplicate arm")
        arm_ids.add(name)
        _text(arm.get("role"))
        _text(arm.get("environment_id"))
        _digest(arm.get("config_sha256"))
        _digest(arm.get("source_commit"), 40)
    baseline, candidate = manifest.get("baseline"), manifest.get("candidate")
    if baseline == candidate or baseline not in arm_ids or candidate not in arm_ids:
        raise BenefitInputError("invalid comparison")
    assignments = manifest.get("assignments")
    if not isinstance(assignments, list) or not 1 <= len(assignments) <= MAX_RUNS:
        raise BenefitInputError("invalid bounded assignments")
    indexed = {}
    pair_arms = set()
    pair_context = {}
    pair_orders = set()
    for assignment in assignments:
        if not isinstance(assignment, Mapping):
            raise BenefitInputError("invalid assignment object")
        key = _text(assignment.get("id"))
        pair = _text(assignment.get("pair_id"))
        arm = assignment.get("arm")
        scenario = _text(assignment.get("scenario"))
        seed = assignment.get("seed")
        order = assignment.get("order")
        if type(seed) is not int or not 0 <= seed < 2**32 or type(order) is not int or not 0 <= order < len(arms):
            raise BenefitInputError("invalid workload/order")
        if key in indexed or arm not in arm_ids or (pair, arm) in pair_arms or (pair, order) in pair_orders:
            raise BenefitInputError("duplicate or unknown assignment")
        if pair in pair_context and pair_context[pair] != (scenario, seed):
            raise BenefitInputError("unpaired scenario/seed")
        pair_context[pair] = (scenario, seed)
        pair_arms.add((pair, arm))
        pair_orders.add((pair, order))
        indexed[key] = dict(assignment)
    if len(pair_context) * plan["bootstrap_repeats"] > 2_000_000:
        raise BenefitInputError("analysis resampling budget exceeded")
    return indexed


def _receipt(raw: Mapping[str, Any], horizon: float) -> dict[str, float | bool | None]:
    if not isinstance(raw, Mapping) or raw.get("status") not in ("complete", "failed", "missing"):
        raise BenefitInputError("invalid run status")
    safety = raw.get("safety_violations")
    if not isinstance(safety, Mapping) or set(safety) != set(SAFETY_FIELDS):
        raise BenefitInputError("missing safety measurements")
    for value in safety.values():
        if type(value) is not int or not 0 <= value <= 10**9:
            raise BenefitInputError("invalid safety measurement")
    unsafe = any(safety.values())
    _digest(raw.get("evidence_sha256"))
    if raw["status"] != "complete" or raw.get("horizon_verified") is not True:
        return {"usable": False, "unsafe": unsafe, "status": raw["status"]}
    goal = raw.get("protected_goal_seconds")
    time = horizon if goal is None else _number(goal, maximum=horizon)
    latency = _number(raw.get("legitimate_latency_p95_ms"))
    transactions, errors = raw.get("legitimate_transactions"), raw.get("legitimate_errors")
    if type(transactions) is not int or type(errors) is not int or not 1 <= transactions <= 10**9 or not 0 <= errors <= transactions:
        raise BenefitInputError("invalid legitimate transaction denominator")
    return {"usable": True, "unsafe": unsafe, "status": raw["status"], "restricted_seconds": time,
            "goal_completed": goal is not None, "latency_ms": latency, "error_rate": errors / transactions}


def _estimate(deltas: list[float], *, repeats: int, seed: int) -> dict[str, Any]:
    if not deltas:
        return {"mean": None, "interval_95": None, "pairs": 0}
    rng = random.Random(seed)
    samples = sorted(statistics.fmean(rng.choices(deltas, k=len(deltas))) for _ in range(repeats))
    return {"mean": statistics.fmean(deltas), "interval_95": [samples[int(.025 * (repeats - 1))], samples[int(.975 * (repeats - 1))]], "pairs": len(deltas)}


def analyze(manifest: Mapping[str, Any], observations: Mapping[str, Any]) -> dict[str, Any]:
    assignments = validate_manifest(manifest)
    digest = manifest_digest(manifest)
    if not isinstance(observations, Mapping) or observations.get("manifest_sha256") != digest:
        raise BenefitInputError("receipts are not bound to this frozen manifest")
    runs = observations.get("runs")
    if not isinstance(runs, list) or len(runs) > MAX_RUNS:
        raise BenefitInputError("invalid bounded run ledger")
    horizon = float(manifest["horizon_seconds"])
    indexed = {}
    run_ids = set()
    for raw in runs:
        if not isinstance(raw, Mapping):
            raise BenefitInputError("invalid run object")
        key = raw.get("assignment_id")
        run_id = _text(raw.get("run_id"))
        if key not in assignments or key in indexed or run_id in run_ids:
            raise BenefitInputError("unknown or duplicate run")
        indexed[key] = _receipt(raw, horizon)
        run_ids.add(run_id)
    baseline, candidate = manifest["baseline"], manifest["candidate"]
    pair_scenarios = {}
    pairs: dict[str, dict[str, Any]] = {}
    strata: dict[str, dict[str, Any]] = {}
    for key, assignment in assignments.items():
        pair_scenarios[assignment["pair_id"]] = assignment["scenario"]
        if assignment["arm"] in (baseline, candidate):
            pairs.setdefault(assignment["pair_id"], {})[assignment["arm"]] = indexed.get(key)
    deltas: list[float] = []
    latencies: list[float] = []
    errors: list[float] = []
    completion = {baseline: 0, candidate: 0}
    incomplete = 0
    for pair, arms in pairs.items():
        b, c = arms.get(baseline), arms.get(candidate)
        if not b or not c or not b["usable"] or not c["usable"]:
            incomplete += 1
            continue
        delta = c["restricted_seconds"] - b["restricted_seconds"]
        deltas.append(delta)
        latencies.append(c["latency_ms"] - b["latency_ms"])
        errors.append(c["error_rate"] - b["error_rate"])
        completion[baseline] += int(b["goal_completed"])
        completion[candidate] += int(c["goal_completed"])
        scenario = pair_scenarios[pair]
        stratum = strata.setdefault(scenario, {"pairs": 0, "time_deltas_seconds": []})
        stratum["pairs"] += 1
        stratum["time_deltas_seconds"].append(delta)
    plan = manifest["plan"]
    estimates = [_estimate(values, repeats=plan["bootstrap_repeats"], seed=plan["analysis_seed"]) for values in (deltas, latencies, errors)]
    unsafe = any(r["unsafe"] for r in indexed.values())
    missing = len(assignments) - len(indexed)
    sufficient = not incomplete and not missing and len(deltas) >= plan["minimum_pairs"]
    if unsafe:
        gate = "safety_failed"
    elif not sufficient:
        gate = "inconclusive_missing_or_insufficient_pairs"
    elif estimates[1]["interval_95"][1] > plan["max_latency_increase_ms"] or estimates[2]["interval_95"][1] > plan["max_error_rate_increase"]:
        gate = "legitimate_service_gate_failed"
    elif completion[candidate] > completion[baseline]:
        gate = "protected_goal_regression"
    elif estimates[0]["interval_95"][0] <= plan["minimum_gain_seconds"]:
        gate = "practical_time_gain_not_demonstrated"
    else:
        gate = "recorded_thresholds_met_requires_independent_review"
    return {"schema_version": REPORT_SCHEMA, "experiment_id": manifest["experiment_id"],
            "baseline": baseline, "candidate": candidate, "arms": manifest["arms"],
            "run_status_counts": {s: sum(r["status"] == s for r in indexed.values()) for s in ("complete", "failed", "missing")},
            "manifest_sha256": digest, "phase": manifest["phase"], "evidence_kind": manifest["evidence_kind"],
            "assigned_runs": len(assignments), "received_runs": len(indexed), "missing_runs": missing,
            "incomplete_pairs": incomplete, "complete_pairs": len(deltas), "protected_goals_completed": completion,
            "time_gain_seconds": estimates[0], "legitimate_p95_delta_ms": estimates[1], "legitimate_error_rate_delta": estimates[2],
            "scenario_strata": strata, "measurement_gate": gate,
            "claim_status": "mechanical_only" if manifest["phase"] == "pilot" or manifest["evidence_kind"] == "synthetic" else "independent_review_required",
            "limitations": ["manifest binding is not independent preregistration", "receipt hashes do not prove source truth", "no runtime causal/effect/authority record is modified", "administrative censoring only at fully observed common horizon", "bootstrap intervals require independent sample-size and multiplicity review", "no universal or unexecuted external-comparator superiority claim"]}


def _load(path: str) -> dict[str, Any]:
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise BenefitInputError("input exceeds byte bound")
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise BenefitInputError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(BenefitInputError("non-finite JSON")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("observations")
    args = parser.parse_args()
    try:
        report = analyze(_load(args.manifest), _load(args.observations))
    except (BenefitInputError, OSError, TypeError, KeyError, RecursionError, json.JSONDecodeError) as exc:
        parser.exit(2, f"invalid benefit input: {exc}\n")
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
