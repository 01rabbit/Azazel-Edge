from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'bin' / 'azazel-edge-demo'


class DemoRunnerV1Tests(unittest.TestCase):
    def test_runner_lists_scenarios(self) -> None:
        result = subprocess.run([str(RUNNER), 'list'], capture_output=True, text=True, cwd=str(ROOT), check=True)
        payload = json.loads(result.stdout)
        self.assertTrue(payload['ok'])
        scenario_ids = {item['scenario_id'] for item in payload['items']}
        self.assertIn('mixed_correlation_demo', scenario_ids)

    def test_runner_executes_known_scenario(self) -> None:
        result = subprocess.run([str(RUNNER), 'run', 'mixed_correlation_demo'], capture_output=True, text=True, cwd=str(ROOT), check=True)
        payload = json.loads(result.stdout)
        self.assertTrue(payload['ok'])
        scenario = payload['result']
        self.assertEqual(scenario['scenario_id'], 'mixed_correlation_demo')
        self.assertIn('arbiter', scenario)
        self.assertEqual(scenario['execution']['mode'], 'deterministic_replay')
        self.assertFalse(scenario['execution']['ai_used'])
        self.assertIn('implemented_now', scenario['capability_boundary'])
        self.assertTrue(scenario['arbiter']['action_profile']['audited'])
        self.assertIn('selected_action', scenario['arbiter']['decision_trace'])


if __name__ == '__main__':
    unittest.main()
