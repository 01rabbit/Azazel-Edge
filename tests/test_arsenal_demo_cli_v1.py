from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'bin' / 'azazel-edge-arsenal-demo'


class ArsenalDemoCliV1Tests(unittest.TestCase):
    def test_cli_lists_arsenal_stages(self) -> None:
        result = subprocess.run([str(RUNNER), 'list', '--format', 'json'], capture_output=True, text=True, cwd=str(ROOT), check=True)
        payload = json.loads(result.stdout)
        self.assertTrue(payload['ok'])
        stage_ids = [item['stage_id'] for item in payload['items']]
        self.assertEqual(stage_ids, ['arsenal_low_watch', 'arsenal_throttle', 'arsenal_decoy_redirect'])

    def test_cli_run_can_apply_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            overlay_path = Path(tmp) / 'demo_overlay.json'
            state_path = Path(tmp) / 'stage_state.json'
            env = os.environ.copy()
            env['AZAZEL_DEMO_OVERLAY'] = str(overlay_path)
            result = subprocess.run(
                [str(RUNNER), 'run', 'arsenal_throttle', '--format', 'json', '--state-out', str(state_path)],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
                env=env,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload['ok'])
            overlay = json.loads(overlay_path.read_text(encoding='utf-8'))
            self.assertEqual(overlay['scenario_id'], 'arsenal_throttle')
            self.assertEqual(overlay['arsenal_demo']['band'], 'THROTTLE')
            state = json.loads(state_path.read_text(encoding='utf-8'))
            self.assertEqual(state['band'], 'THROTTLE')
            self.assertTrue(state['overlay_written'])
            self.assertEqual(state['attack_label'], 'SSH Brute Force')
            self.assertEqual(state['decision_path']['ollama_review']['status'], 'used')
            self.assertEqual(state['proofs']['tc']['status'], 'active')
            self.assertEqual(state['proofs']['decoy']['status'], 'standby')

    def test_cli_menu_can_select_individual_attack_and_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            overlay_path = Path(tmp) / 'demo_overlay.json'
            state_path = Path(tmp) / 'menu_state.json'
            env = os.environ.copy()
            env['AZAZEL_DEMO_OVERLAY'] = str(overlay_path)
            result = subprocess.run(
                [str(RUNNER), 'menu', '--state-out', str(state_path)],
                input='2\n0\n',
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
                env=env,
            )
            self.assertIn('AZAZEL-PI EXHIBITION MENU', result.stdout)
            self.assertIn('SSH Brute Force', result.stdout)
            state = json.loads(state_path.read_text(encoding='utf-8'))
            self.assertEqual(state['scenario_id'], 'arsenal_throttle')
            self.assertEqual(state['attack_label'], 'SSH Brute Force')
            self.assertEqual(state['decision_path']['ollama_review']['status'], 'used')


if __name__ == '__main__':
    unittest.main()
