from __future__ import annotations

import json
import subprocess
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
        self.assertEqual(items[2]['band'], 'THROTTLE')
        self.assertEqual(items[3]['band'], 'DECOY REDIRECT')

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

    def test_run_stage_can_notify_mattermost(self) -> None:
        calls = []

        def fake_sender(result: dict) -> dict:
            calls.append(result)
            return {'ok': True, 'mode': 'test'}

        runner = ArsenalDemoRunner(root_dir=ROOT, overlay_path=self.overlay_path, mattermost_sender=fake_sender)
        payload = runner.run_stage('arsenal_throttle', notify_mattermost=True)

        self.assertTrue(payload['ok'])
        self.assertEqual(payload['mattermost']['mode'], 'test')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['arsenal_demo']['attack_label'], 'SSH Brute Force')

    def test_run_flow_can_keep_final_overlay(self) -> None:
        payload = self.runner.run_flow(hold_sec=0, keep_final=True)
        self.assertTrue(payload['ok'])
        self.assertEqual(len(payload['stages']), 3)
        overlay = read_demo_overlay(self.overlay_path)
        self.assertEqual(overlay.get('scenario_id'), 'arsenal_decoy_redirect')

    def test_run_stage_ollama_review_scenario_marks_used(self) -> None:
        payload = self.runner.run_stage('arsenal_ollama_review')
        self.assertTrue(payload['ok'])
        result = payload['result']
        self.assertEqual(result['arsenal_demo']['attack_label'], 'Suspicious Admin Login Burst')
        self.assertEqual(result['arsenal_demo']['band'], 'THROTTLE')
        self.assertEqual(result['arsenal_demo']['decision_path']['ollama_review']['status'], 'used')
        self.assertIn('qwen3.5:2b', result['arsenal_demo']['decision_path']['ollama_review']['evidence'])

    def test_run_flow_collects_mattermost_notifications(self) -> None:
        calls = []

        def fake_sender(result: dict) -> dict:
            calls.append(result.get('scenario_id'))
            return {'ok': True, 'mode': 'test'}

        runner = ArsenalDemoRunner(root_dir=ROOT, overlay_path=self.overlay_path, mattermost_sender=fake_sender)
        payload = runner.run_flow(hold_sec=0, keep_final=False, notify_mattermost=True)

        self.assertTrue(payload['ok'])
        self.assertEqual(calls, ['arsenal_low_watch', 'arsenal_ollama_review', 'arsenal_decoy_redirect'])
        self.assertEqual(len(payload['mattermost_notifications']), 3)
        self.assertTrue(all(item.get('ok') for item in payload['mattermost_notifications']))

    def test_refresh_epd_timeout_is_non_fatal(self) -> None:
        import azazel_edge.demo.arsenal as arsenal_mod

        original_run = arsenal_mod.subprocess.run
        arsenal_mod.subprocess.run = lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get('timeout', 15))
        )  # type: ignore[assignment]
        try:
            payload = self.runner.run_stage('arsenal_low_watch', apply_overlay=True, refresh_epd=True)
        finally:
            arsenal_mod.subprocess.run = original_run  # type: ignore[assignment]

        self.assertTrue(payload['ok'])
        self.assertTrue(payload['overlay_written'])
        self.assertFalse(payload['epd_refresh']['ok'])
        self.assertEqual(payload['epd_refresh']['error'], 'epd_refresh_timeout')

    def test_notification_message_uses_booth_url_and_mattermost_link(self) -> None:
        import os
        captured = {}
        runner = ArsenalDemoRunner(root_dir=ROOT, overlay_path=self.overlay_path)
        original = os.environ.get('AZAZEL_ARSENAL_DEMO_URL')
        os.environ['AZAZEL_ARSENAL_DEMO_URL'] = 'https://192.168.40.89/'
        try:
            def fake_api_post(path: str, payload: dict) -> dict:
                captured['path'] = path
                captured['payload'] = payload
                return {'ok': True, 'mode': 'bot_api'}

            runner._mattermost_api_post = fake_api_post  # type: ignore[method-assign]
            runner._mattermost_bot_token = lambda: 'token'  # type: ignore[method-assign]
            runner._mattermost_channel_id = lambda: 'channel'  # type: ignore[method-assign]
            runner._mattermost_open_url = lambda: 'http://172.16.0.254:8065/azazelops/channels/soc-noc'  # type: ignore[method-assign]
            result = runner.run_stage('arsenal_low_watch')['result']
            notify = runner._send_mattermost_notification(result)
        finally:
            if original is None:
                os.environ.pop('AZAZEL_ARSENAL_DEMO_URL', None)
            else:
                os.environ['AZAZEL_ARSENAL_DEMO_URL'] = original

        self.assertTrue(notify['ok'])
        self.assertEqual(captured['path'], '/api/v4/posts')
        self.assertIn('booth=https://192.168.40.89/', captured['payload']['message'])
        self.assertIn('mattermost=http://172.16.0.254:8065/azazelops/channels/soc-noc', captured['payload']['message'])


if __name__ == '__main__':
    unittest.main()
