from __future__ import annotations

import sys
import unittest
from pathlib import Path

from azazel_edge.demo import DemoScenarioPack, DemoScenarioRunner

FORBIDDEN_WORDS = {'disaster', 'shelter', 'evacuation', 'emergency', 'refugee', 'crisis'}
SCENARIO_ID = 'auditable_edge_socnoc'


def _collect_narrative(scenario: dict) -> str:
    """Recursively collect all string leaf values from a scenario dict."""
    parts: list[str] = []

    def _walk(obj: object) -> None:
        if isinstance(obj, str):
            parts.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(item)

    _walk(scenario)
    return ' '.join(parts)


class AuditableEdgeSocnocScenarioV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.pack = DemoScenarioPack()
        self.runner = DemoScenarioRunner()

    # ------------------------------------------------------------------
    # 1. Scenario is present and has the required top-level keys
    # ------------------------------------------------------------------
    def test_scenario_is_registered_in_pack(self) -> None:
        scenarios = self.pack.scenarios()
        self.assertIn(SCENARIO_ID, scenarios,
                      f"'{SCENARIO_ID}' not found in DemoScenarioPack.scenarios()")

    def test_scenario_has_required_keys(self) -> None:
        scenario = self.pack.scenarios()[SCENARIO_ID]
        for key in ('description', 'demo', 'events', 'scoring'):
            self.assertIn(key, scenario,
                          f"Expected key '{key}' missing from scenario '{SCENARIO_ID}'")

    # ------------------------------------------------------------------
    # 2. Runner produces the correct execution metadata
    # ------------------------------------------------------------------
    def test_runner_execution_mode_is_deterministic_replay(self) -> None:
        result = self.runner.run(SCENARIO_ID)
        execution = result.get('execution', {})
        self.assertEqual(execution.get('mode'), 'deterministic_replay',
                         f"Expected execution.mode='deterministic_replay', got {execution.get('mode')!r}")

    def test_runner_ai_used_is_false(self) -> None:
        result = self.runner.run(SCENARIO_ID)
        execution = result.get('execution', {})
        self.assertIs(execution.get('ai_used'), False,
                      f"Expected execution.ai_used=False, got {execution.get('ai_used')!r}")

    # ------------------------------------------------------------------
    # 3. Explanation carries required audit fields
    # ------------------------------------------------------------------
    def test_explanation_rejected_actions_is_non_empty(self) -> None:
        result = self.runner.run(SCENARIO_ID)
        explanation = result.get('explanation', {})
        rejected_actions = explanation.get('rejected_actions')
        self.assertTrue(
            isinstance(rejected_actions, list) and len(rejected_actions) > 0,
            f"Expected non-empty explanation.rejected_actions, got {rejected_actions!r}",
        )

    def test_explanation_why_not_others_is_non_empty(self) -> None:
        result = self.runner.run(SCENARIO_ID)
        explanation = result.get('explanation', {})
        why_not_others = explanation.get('why_not_others')
        self.assertTrue(
            isinstance(why_not_others, list) and len(why_not_others) > 0,
            f"Expected non-empty explanation.why_not_others, got {why_not_others!r}",
        )

    def test_explanation_release_condition_is_non_empty(self) -> None:
        result = self.runner.run(SCENARIO_ID)
        explanation = result.get('explanation', {})
        release_condition = explanation.get('release_condition', '')
        self.assertTrue(
            isinstance(release_condition, str) and release_condition.strip(),
            f"Expected non-empty explanation.release_condition, got {release_condition!r}",
        )

    def test_explanation_config_hash_is_non_empty(self) -> None:
        result = self.runner.run(SCENARIO_ID)
        explanation = result.get('explanation', {})
        config_hash = explanation.get('config_hash', '')
        self.assertTrue(
            isinstance(config_hash, str) and config_hash.strip(),
            f"Expected non-empty explanation.config_hash, got {config_hash!r}",
        )

    def test_explanation_policy_profile_is_non_empty(self) -> None:
        result = self.runner.run(SCENARIO_ID)
        explanation = result.get('explanation', {})
        policy_profile = explanation.get('policy_profile', '')
        self.assertTrue(
            isinstance(policy_profile, str) and policy_profile.strip(),
            f"Expected non-empty explanation.policy_profile, got {policy_profile!r}",
        )

    # ------------------------------------------------------------------
    # 4. Narrative text contains no forbidden words
    # ------------------------------------------------------------------
    def test_narrative_contains_no_forbidden_words(self) -> None:
        scenario = self.pack.scenarios()[SCENARIO_ID]
        narrative = _collect_narrative(scenario).lower()
        found = [w for w in FORBIDDEN_WORDS if w in narrative]
        self.assertEqual(
            found, [],
            f"Forbidden word(s) found in '{SCENARIO_ID}' narrative: {found}",
        )

    # ------------------------------------------------------------------
    # 5. disaster_phishing_demo is still defined (not removed from pack)
    # ------------------------------------------------------------------
    def test_disaster_phishing_demo_still_in_pack(self) -> None:
        scenarios = self.pack.scenarios()
        self.assertIn('disaster_phishing_demo', scenarios,
                      "'disaster_phishing_demo' was removed from DemoScenarioPack — it must remain defined")


if __name__ == '__main__':
    unittest.main()
