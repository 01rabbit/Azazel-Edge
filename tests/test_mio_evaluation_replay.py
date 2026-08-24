from __future__ import annotations

from pathlib import Path

from azazel_edge.mio.evaluation import evaluate_scenario, load_scenarios
from azazel_edge.mio.resource_profile import ResourceTimer


ROOT = Path(__file__).parent / "fixtures" / "mio"


def _results():
    return [evaluate_scenario(scenario, fixture_root=ROOT) for scenario in load_scenarios(ROOT / "evaluation_core.json")]


def test_offline_evaluation_corpus_meets_declared_invariants():
    results = _results()
    assert len(results) >= 9
    assert all(result["passed"] for result in results)
    assert all(len(result["validation_digest"]) == 64 for result in results)


def test_accepted_recorded_fixture_passes_and_bad_fixtures_are_rejected():
    results = {result["scenario_id"]: result for result in _results()}
    assert results["recorded-qwen-2b-accepted"]["metrics"]["validation_passed"] is True
    for name in ("contradictory-evidence-role", "empty-recommendation-captured-381", "malformed-model-output",
                 "prompt-injection-directive", "cross-trace-fabricated-ref", "stale-evidence", "model-timeout",
                 "no-llm-model-unavailable"):
        assert results[name]["metrics"]["validation_passed"] is False


def test_recorded_inputs_have_deterministic_validation_result():
    first = _results()
    second = _results()
    assert [item["validation_digest"] for item in first] == [item["validation_digest"] for item in second]


def test_resource_timer_is_a_measurement_helper_not_a_hardware_claim():
    with ResourceTimer() as timer:
        sum(range(100))
    assert timer.sample.elapsed_ms >= 0
    assert timer.sample.peak_rss_kib > 0
