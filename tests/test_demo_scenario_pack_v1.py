from __future__ import annotations

import sys
import unittest
from pathlib import Path

from azazel_edge.demo import DemoScenarioPack, DemoScenarioRunner


class DemoScenarioPackV1Tests(unittest.TestCase):
    def test_pack_exposes_expected_scenarios(self) -> None:
        pack = DemoScenarioPack()
        scenarios = pack.scenarios()
        self.assertIn('soc_redirect_demo', scenarios)
        self.assertIn('noc_degraded_demo', scenarios)
        self.assertIn('mixed_correlation_demo', scenarios)
        self.assertIn('disaster_phishing_demo', scenarios)
        self.assertIn('evacuation_network_demo', scenarios)
        self.assertIn('shelter_baseline_demo', scenarios)
        self.assertIn('shelter_scan_detect_demo', scenarios)
        self.assertIn('shelter_ssh_bruteforce_demo', scenarios)
        self.assertIn('shelter_redirect_decoy_demo', scenarios)
        self.assertIn('shelter_audit_review_demo', scenarios)
        self.assertIn('shelter_operator_handoff_demo', scenarios)
        items = pack.list_items()
        self.assertEqual(items[0]['scenario_id'], 'soc_redirect_demo')
        self.assertEqual(items[0]['title'], 'High-confidence SOC path')
        self.assertEqual(items[2]['attack_label'], 'SSH Brute Force')
        for scenario_id in ('disaster_phishing_demo', 'evacuation_network_demo'):
            self.assertIn('description', scenarios[scenario_id])
            self.assertIn('demo', scenarios[scenario_id])
            self.assertIn('events', scenarios[scenario_id])
            self.assertIn('scoring', scenarios[scenario_id])
            scoring = scenarios[scenario_id]['scoring']
            self.assertIn('scenario_id', scoring)
            self.assertIn('response_time_sec', scoring)
            self.assertIn('correct_action', scoring)
            self.assertIn('runbook_proposed', scoring)
            self.assertIn('drills_completed', scoring)

    def test_runner_executes_pipeline(self) -> None:
        result = DemoScenarioRunner().run('mixed_correlation_demo')
        self.assertEqual(result['scenario_id'], 'mixed_correlation_demo')
        self.assertIn('summary', result['soc'])
        self.assertIn('why_chosen', result['explanation'])
        self.assertIn('sigma_hits', result['soc']['summary'])
        self.assertIn('yara_hits', result['soc']['summary'])
        self.assertEqual(result['presentation']['title'], 'Correlation with Sigma and YARA support')
        self.assertEqual(result['demo']['attack_label'], 'SSH Brute Force')
        self.assertIn('second_pass', result['demo']['decision_path'])
        self.assertIn('policy', result['demo']['proofs'])

    def test_runner_executes_shelter_profile_scenario(self) -> None:
        result = DemoScenarioRunner().run('shelter_ssh_bruteforce_demo')
        self.assertEqual(result['scenario_id'], 'shelter_ssh_bruteforce_demo')
        self.assertIn(result['arbiter']['action'], {'notify', 'throttle', 'redirect', 'isolate', 'observe'})
        self.assertIn('release_condition', result['arbiter'])
        self.assertIn('rejected_actions', result['explanation'])


if __name__ == '__main__':
    unittest.main()
