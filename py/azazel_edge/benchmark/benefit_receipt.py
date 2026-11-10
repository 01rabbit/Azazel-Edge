"""Normalize recorded isolated-scenario ground truth, never defense authority.

The scenario-controller tag is provenance supplied by the capture, not
cryptographic proof. Independent review must establish actual source identity.
No function sends traffic, invokes a provider, starts a decoy or calls a model.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping

from .benefit import BenefitInputError, SAFETY_FIELDS, _number, _text, manifest_digest, validate_manifest


def build_receipt(manifest: Mapping[str, Any], assignment_id: str, capture: Mapping[str, Any]) -> dict[str, Any]:
    assignments = validate_manifest(manifest)
    if assignment_id not in assignments:
        raise BenefitInputError("unknown assignment")
    assignment = assignments[assignment_id]
    if capture.get("manifest_sha256") != manifest_digest(manifest) or capture.get("assignment_id") != assignment_id:
        raise BenefitInputError("capture manifest/assignment binding mismatch")
    if capture.get("scenario") != assignment["scenario"] or capture.get("seed") != assignment["seed"]:
        raise BenefitInputError("capture scenario/seed mismatch")
    if capture.get("source") != "isolated_scenario_controller":
        raise BenefitInputError("milestones require independent scenario provenance")
    _text(capture.get("run_id"))
    for name in ("boot_id", "clock_id"):
        _text(capture.get(name))
    if capture.get("clock_kind") != "monotonic_elapsed":
        raise BenefitInputError("milestones require one declared elapsed-time clock")
    horizon = float(manifest["horizon_seconds"])
    events = capture.get("milestones")
    transactions = capture.get("legitimate_transactions")
    if not isinstance(events, list) or not 2 <= len(events) <= 10000 or not isinstance(transactions, list) or not 1 <= len(transactions) <= 10000:
        raise BenefitInputError("invalid bounded capture")
    seen = set()
    starts, ends, goals = [], [], []
    gap = False
    last = -1.0
    for event in events:
        if not isinstance(event, Mapping):
            raise BenefitInputError("invalid milestone")
        if any(event.get(name, capture[name]) != capture[name] for name in ("boot_id", "clock_id")):
            raise BenefitInputError("cross-boot or cross-clock milestone")
        key = _text(event.get("id"))
        if key in seen:
            raise BenefitInputError("duplicate milestone")
        seen.add(key)
        elapsed = _number(event.get("elapsed_seconds"), maximum=horizon)
        if elapsed < last:
            raise BenefitInputError("non-monotonic milestones")
        last = elapsed
        kind = event.get("kind")
        if kind == "run_start":
            starts.append(elapsed)
        elif kind == "run_end":
            ends.append(elapsed)
        elif kind == "protected_goal":
            goals.append(elapsed)
        elif kind == "sensor_gap":
            gap = True
        elif kind not in ("discovery", "protected_reach", "authentication_attempt", "verified_containment", "actionable_detection"):
            raise BenefitInputError("unknown milestone kind")
    if starts != [0.0] or len(ends) != 1 or ends[0] != horizon:
        raise BenefitInputError("capture does not verify the full declared horizon")
    latencies = []
    errors = 0
    tx_ids = set()
    for tx in transactions:
        if not isinstance(tx, Mapping):
            raise BenefitInputError("invalid transaction")
        tx_id = _text(tx.get("id"))
        if tx_id in tx_ids:
            raise BenefitInputError("duplicate transaction")
        tx_ids.add(tx_id)
        _number(tx.get("elapsed_seconds"), maximum=horizon)
        latencies.append(_number(tx.get("duration_ms"), maximum=horizon * 1000))
        if type(tx.get("error")) is not bool:
            raise BenefitInputError("unknown transaction result")
        errors += int(tx["error"])
    safety = capture.get("safety_violations")
    if not isinstance(safety, Mapping) or set(safety) != set(SAFETY_FIELDS) or any(type(v) is not int or not 0 <= v <= 10**9 for v in safety.values()):
        raise BenefitInputError("invalid independent safety observation")
    latencies.sort()
    digest = hashlib.sha256(json.dumps(capture, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    return {"assignment_id": assignment_id, "run_id": capture["run_id"],
            "status": "complete", "horizon_verified": not gap,
            "protected_goal_seconds": min(goals) if goals else None,
            "legitimate_latency_p95_ms": latencies[math.ceil(.95 * len(latencies)) - 1],
            "legitimate_transactions": len(latencies), "legitimate_errors": errors,
            "safety_violations": dict(safety), "evidence_sha256": digest}
