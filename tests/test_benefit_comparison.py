"""Independent ground-truth/censoring and negative controls for benefit analysis."""
import copy
import json
from unittest import mock

import pytest

from azazel_edge.benchmark.benefit import BenefitInputError, SAFETY_FIELDS, analyze, manifest_digest, validate_manifest


def manifest():
    return {
        "schema_version": "azazel-benefit-experiment/v1", "experiment_id": "mechanical-pilot",
        "phase": "pilot", "evidence_kind": "synthetic", "horizon_seconds": 60,
        "provenance": {"repo_commits": {"01rabbit/Azazel-Edge": "a" * 40}, "corpus_sha256": "b" * 64, "policy_sha256": "c" * 64},
        "arms": [{"id": arm, "role": role, "source_commit": "a" * 40, "config_sha256": "d" * 64, "environment_id": "synthetic"}
                 for arm, role in (("block", "bounded_block"), ("candidate", "fixed_friction"))],
        "baseline": "block", "candidate": "candidate",
        "plan": {"minimum_pairs": 2, "minimum_gain_seconds": 5, "max_latency_increase_ms": 2,
                 "max_error_rate_increase": .01, "bootstrap_repeats": 500, "analysis_seed": 17},
        "assignments": [{"id": f"{pair}-{arm}", "pair_id": str(pair), "arm": arm, "scenario": "auth",
                         "seed": pair, "order": (idx + pair) % 2}
                        for pair in range(2) for idx, arm in enumerate(("block", "candidate"))],
    }


def observations(m):
    return {"manifest_sha256": manifest_digest(m), "runs": [
        {"assignment_id": a["id"], "run_id": a["id"], "status": "complete", "horizon_verified": True,
         "protected_goal_seconds": 10 if a["arm"] == "block" else None,
         "legitimate_latency_p95_ms": 20, "legitimate_transactions": 100, "legitimate_errors": 0,
         "safety_violations": dict.fromkeys(SAFETY_FIELDS, 0), "evidence_sha256": "e" * 64}
        for a in m["assignments"]]}


def test_admin_censoring_is_finite_and_pilot_can_never_prove_superiority():
    m = manifest()
    report = analyze(m, observations(m))
    assert report["time_gain_seconds"]["mean"] == 50
    assert report["time_gain_seconds"]["interval_95"] == [50, 50]
    assert report["protected_goals_completed"] == {"block": 2, "candidate": 0}
    assert report["measurement_gate"] == "recorded_thresholds_met_requires_independent_review"
    assert report["claim_status"] == "mechanical_only"


def test_immediate_block_can_win_and_both_censored_is_zero_time_gain():
    m = manifest()
    o = observations(m)
    for r in o["runs"]:
        if r["assignment_id"].endswith("block"):
            r["protected_goal_seconds"] = None
    report = analyze(m, o)
    assert report["time_gain_seconds"]["mean"] == 0
    assert report["measurement_gate"] == "practical_time_gain_not_demonstrated"


def test_missing_failed_and_early_lost_runs_never_become_successes():
    m = manifest()
    for fault in ("missing", "failed", "early_loss"):
        o = observations(m)
        if fault == "missing":
            o["runs"].pop()
        elif fault == "failed":
            o["runs"][-1]["status"] = "failed"
        else:
            o["runs"][-1]["horizon_verified"] = False
        report = analyze(m, o)
        assert report["complete_pairs"] == 1
        assert report["measurement_gate"] == "inconclusive_missing_or_insufficient_pairs"
        assert report["assigned_runs"] == 4


@pytest.mark.parametrize("fault,expected", [("latency", "legitimate_service_gate_failed"), ("errors", "legitimate_service_gate_failed"), ("escape", "safety_failed")])
def test_harm_overrides_extra_dwell_time(fault, expected):
    m = manifest()
    o = observations(m)
    for r in o["runs"]:
        if r["assignment_id"].endswith("candidate"):
            if fault == "latency":
                r["legitimate_latency_p95_ms"] = 100
            elif fault == "errors":
                r["legitimate_errors"] = 10
            else:
                r["safety_violations"]["protected_escape"] = 1
    assert analyze(m, o)["measurement_gate"] == expected


def test_frozen_manifest_and_pair_identity_cannot_be_substituted():
    m = manifest()
    o = observations(m)
    altered = copy.deepcopy(m)
    altered["plan"]["minimum_gain_seconds"] = 0
    with pytest.raises(BenefitInputError, match="bound"):
        analyze(altered, o)
    for field, value in (("seed", 99), ("scenario", "other"), ("order", 0)):
        altered = copy.deepcopy(m)
        altered["assignments"][1][field] = value
        with pytest.raises(BenefitInputError):
            validate_manifest(altered)


def test_duplicate_unknown_and_malformed_receipts_are_rejected():
    m = manifest()
    for fault in ("duplicate", "unknown", "nan", "no_denominator", "missing_safety"):
        o = observations(m)
        if fault == "duplicate":
            o["runs"].append(o["runs"][0])
        elif fault == "unknown":
            o["runs"][0]["assignment_id"] = "other"
        elif fault == "nan":
            o["runs"][0]["protected_goal_seconds"] = float("nan")
        elif fault == "no_denominator":
            o["runs"][0]["legitimate_transactions"] = 0
        else:
            o["runs"][0].pop("safety_violations")
        with pytest.raises(BenefitInputError):
            analyze(m, o)


def test_analysis_is_deterministic_immutable_and_has_no_network_or_execution():
    m = manifest()
    o = observations(m)
    before = json.dumps([m, o], sort_keys=True)
    with mock.patch("socket.socket", side_effect=AssertionError("network")), mock.patch("subprocess.run", side_effect=AssertionError("execute")):
        assert analyze(m, o) == analyze(m, o)
    assert json.dumps([m, o], sort_keys=True) == before


def test_capture_ground_truth_uses_verified_horizon_and_does_not_use_alert_counts():
    from azazel_edge.benchmark.benefit_receipt import build_receipt
    m = manifest()
    capture = {"source": "isolated_scenario_controller", "run_id": "capture-1", "boot_id": "boot-a", "clock_id": "clock-a", "clock_kind": "monotonic_elapsed",
               "milestones": [{"id": "s", "kind": "run_start", "elapsed_seconds": 0},
                              {"id": "g", "kind": "protected_goal", "elapsed_seconds": 30},
                              {"id": "e", "kind": "run_end", "elapsed_seconds": 60}],
               "legitimate_transactions": [{"id": "t1", "elapsed_seconds": 1, "duration_ms": 10, "error": False}],
               "safety_violations": dict.fromkeys(SAFETY_FIELDS, 0)}
    receipt = build_receipt(m, "0-block", capture)
    assert receipt["protected_goal_seconds"] == 30
    assert receipt["horizon_verified"]
    gap = copy.deepcopy(capture)
    gap["milestones"][1]["kind"] = "sensor_gap"
    lost = build_receipt(m, "0-block", gap)
    assert not lost["horizon_verified"]
    assert lost["protected_goal_seconds"] is None
    for fault in ("order", "clock", "duplicate", "short", "alert"):
        bad = copy.deepcopy(capture)
        if fault == "order":
            bad["milestones"].reverse()
        elif fault == "clock":
            bad["clock_kind"] = "wall_clock"
        elif fault == "duplicate":
            bad["legitimate_transactions"].append(bad["legitimate_transactions"][0])
        elif fault == "short":
            bad["milestones"][-1]["elapsed_seconds"] = 50
        else:
            bad["milestones"][1]["kind"] = "IDS_alert"
        with pytest.raises(BenefitInputError):
            build_receipt(m, "0-block", bad)


def test_json_loader_rejects_duplicates_and_non_finite_values(tmp_path):
    from azazel_edge.benchmark.benefit import _load
    p = tmp_path / "input.json"
    for raw in ('{"a":1,"a":2}', '{"a":NaN}'):
        p.write_text(raw)
        with pytest.raises(BenefitInputError):
            _load(str(p))
