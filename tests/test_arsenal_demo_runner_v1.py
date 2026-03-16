from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.demo import ARSENAL_STAGE_ORDER, ArsenalDemoRunner
from azazel_edge.demo_overlay import read_demo_overlay


class ArsenalDemoRunnerV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.overlay_path = Path(self.tmp.name) / 'demo_overlay.json'
        self.runner = ArsenalDemoRunner(root_dir=ROOT, overlay_path=self.overlay_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_list_items_exposes_expected_arsenal_stages(self) -> None:
        items = self.runner.list_items()
        self.assertEqual([item['stage_id'] for item in items], list(ARSENAL_STAGE_ORDER))
        self.assertEqual(items[0]['band'], 'WATCH')
        self.assertEqual(items[1]['band'], 'THROTTLE')
        self.assertEqual(items[2]['band'], 'DECOY REDIRECT')

    def test_run_stage_adapts_result_to_arsenal_band(self) -> None:
        payload = self.runner.run_stage('arsenal_throttle')
        self.assertTrue(payload['ok'])
        result = payload['result']
        self.assertEqual(result['arbiter']['action'], 'throttle')
        self.assertEqual(result['arsenal_demo']['attack_label'], 'SSH Brute Force')
        self.assertEqual(result['arsenal_demo']['band'], 'THROTTLE')
        self.assertGreaterEqual(result['arsenal_demo']['score'], 60)
        self.assertLessEqual(result['arsenal_demo']['score'], 79)
        self.assertEqual(result['arsenal_demo']['proofs']['tc']['status'], 'active')
        self.assertIn('nft', result['arsenal_demo']['proofs']['firewall']['evidence'])
        self.assertEqual(result['arsenal_demo']['decision_path']['ollama_review']['status'], 'used')

    def test_run_stage_can_apply_overlay(self) -> None:
        payload = self.runner.run_stage('arsenal_decoy_redirect', apply_overlay=True)
        self.assertTrue(payload['ok'])
        overlay = read_demo_overlay(self.overlay_path)
        self.assertTrue(overlay.get('active'))
        self.assertEqual(overlay.get('scenario_id'), 'arsenal_decoy_redirect')
        arsenal = overlay.get('arsenal_demo') if isinstance(overlay.get('arsenal_demo'), dict) else {}
        self.assertEqual(arsenal.get('band'), 'DECOY REDIRECT')
        self.assertEqual(arsenal.get('proofs', {}).get('decoy', {}).get('status'), 'redirect')

    def test_run_flow_can_keep_final_overlay(self) -> None:
        payload = self.runner.run_flow(hold_sec=0, keep_final=True)
        self.assertTrue(payload['ok'])
        self.assertEqual(len(payload['stages']), 3)
        overlay = read_demo_overlay(self.overlay_path)
        self.assertEqual(overlay.get('scenario_id'), 'arsenal_decoy_redirect')


if __name__ == '__main__':
    unittest.main()
