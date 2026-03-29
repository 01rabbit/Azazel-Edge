from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'bin' / 'azazel-edge-demo'


class DemoRunnerV1Tests(unittest.TestCase):
    def test_runner_lists_scenarios(self) -> None:
        result = subprocess.run([str(RUNNER), 'list'], capture_output=True, text=True, cwd=str(ROOT), check=True)
        payload = json.loads(result.stdout)
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['items'][0]['scenario_id'], 'soc_redirect_demo')
        self.assertEqual(payload['items'][0]['title'], 'High-confidence SOC path')
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
        self.assertEqual(scenario['presentation']['title'], 'Correlation with Sigma and YARA support')
        self.assertEqual(scenario['demo']['attack_label'], 'SSH Brute Force')

    def test_runner_can_apply_overlay_and_write_state_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            overlay_path = Path(tmp) / 'demo_overlay.json'
            state_path = Path(tmp) / 'demo_state.json'
            env = os.environ.copy()
            env['AZAZEL_DEMO_OVERLAY'] = str(overlay_path)
            result = subprocess.run(
                [
                    str(RUNNER),
                    'run',
                    'mixed_correlation_demo',
                    '--apply-overlay',
                    '--state-out',
                    str(state_path),
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
                env=env,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload['ok'])
            overlay = json.loads(overlay_path.read_text(encoding='utf-8'))
            self.assertTrue(overlay['active'])
            self.assertEqual(overlay['scenario_id'], 'mixed_correlation_demo')
            self.assertEqual(overlay['demo']['attack_label'], 'SSH Brute Force')
            state = json.loads(state_path.read_text(encoding='utf-8'))
            self.assertEqual(state['scenario_id'], 'mixed_correlation_demo')
            self.assertEqual(state['title'], 'Correlation with Sigma and YARA support')
            self.assertTrue(state['overlay_written'])

    def test_runner_flow_can_keep_final_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            overlay_path = Path(tmp) / 'demo_overlay.json'
            env = os.environ.copy()
            env['AZAZEL_DEMO_OVERLAY'] = str(overlay_path)
            result = subprocess.run(
                [str(RUNNER), 'flow', '--hold-sec', '0', '--keep-final'],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
                env=env,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload['ok'])
            self.assertEqual(len(payload['scenarios']), 3)
            overlay = json.loads(overlay_path.read_text(encoding='utf-8'))
            self.assertEqual(overlay['scenario_id'], 'mixed_correlation_demo')


if __name__ == '__main__':
    unittest.main()
