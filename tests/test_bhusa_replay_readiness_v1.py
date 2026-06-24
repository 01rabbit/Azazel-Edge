from __future__ import annotations

import unittest

from azazel_edge.demo import DemoScenarioRunner


class BhusaReplayReadinessV1Tests(unittest.TestCase):
    def test_primary_booth_scenario_is_mixed_correlation_demo(self) -> None:
        result = DemoScenarioRunner().run("mixed_correlation_demo")
        self.assertEqual(result["scenario_id"], "mixed_correlation_demo")
        self.assertEqual(result["execution"]["mode"], "deterministic_replay")
        self.assertFalse(result["execution"]["ai_used"])
        self.assertTrue(result["execution"]["offline_demo"])
        self.assertEqual(result["presentation"]["attack_label"], "SSH Brute Force")

    def test_primary_booth_scenario_is_repeatable_for_five_runs(self) -> None:
        runner = DemoScenarioRunner()
        runs = [runner.run("mixed_correlation_demo") for _ in range(5)]

        def stable_projection(result: dict) -> tuple:
            arbiter = result["arbiter"]
            explanation = result["explanation"]
            execution = result["execution"]
            return (
                result["scenario_id"],
                execution["mode"],
                execution["ai_used"],
                execution["live_telemetry"],
                execution["local_only"],
                execution["offline_demo"],
                arbiter["action"],
                arbiter["reason"],
                arbiter["release_condition"],
                tuple(arbiter["chosen_evidence_ids"]),
                tuple((item["action"], item["reason"]) for item in arbiter["rejected_alternatives"]),
                arbiter["policy"]["version"],
                arbiter["policy"]["hash"],
                explanation["selected_action"],
                tuple(explanation["rejected_actions"]),
                explanation["policy_profile"],
                explanation["config_hash"],
                tuple(explanation["evidence_ids"]),
            )

        baseline = stable_projection(runs[0])
        for result in runs[1:]:
            self.assertEqual(stable_projection(result), baseline)


if __name__ == "__main__":
    unittest.main()
