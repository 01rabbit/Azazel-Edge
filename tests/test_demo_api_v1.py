from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class DemoApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self._orig = {
            "load_token": webapp.load_token,
            "_run_demo_runner": webapp._run_demo_runner,
            "STATE_PATH": webapp.STATE_PATH,
            "read_demo_overlay": webapp.read_demo_overlay,
            "write_demo_overlay": webapp.write_demo_overlay,
            "clear_demo_overlay": webapp.clear_demo_overlay,
            "build_demo_overlay": webapp.build_demo_overlay,
            "_trigger_demo_clear_side_effects": webapp._trigger_demo_clear_side_effects,
        }
        webapp.load_token = lambda: None
        webapp.STATE_PATH = root / "ui_snapshot.json"
        webapp.STATE_PATH.write_text(json.dumps({"ok": True}), encoding="utf-8")
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.load_token = self._orig["load_token"]
        webapp._run_demo_runner = self._orig["_run_demo_runner"]
        webapp.STATE_PATH = self._orig["STATE_PATH"]
        webapp.read_demo_overlay = self._orig["read_demo_overlay"]
        webapp.write_demo_overlay = self._orig["write_demo_overlay"]
        webapp.clear_demo_overlay = self._orig["clear_demo_overlay"]
        webapp.build_demo_overlay = self._orig["build_demo_overlay"]
        webapp._trigger_demo_clear_side_effects = self._orig["_trigger_demo_clear_side_effects"]
        self.tmp.cleanup()

    def test_list_scenarios_endpoint(self) -> None:
        webapp._run_demo_runner = lambda *args: (
            {
                "ok": True,
                "items": [
                    {"scenario_id": "mixed_correlation_demo", "description": "Cross-source demo", "event_count": 3}
                ],
            },
            200,
        )
        response = self.client.get("/api/demo/scenarios")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["items"][0]["scenario_id"], "mixed_correlation_demo")

    def test_run_scenario_endpoint(self) -> None:
        webapp._run_demo_runner = lambda *args: (
            {
                "ok": True,
                "result": {
                    "scenario_id": "noc_degraded_demo",
                    "event_count": 3,
                    "arbiter": {"action": "notify"},
                },
            },
            200,
        )
        response = self.client.post("/api/demo/run/noc_degraded_demo")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["arbiter"]["action"], "notify")

    def test_run_unknown_scenario_bubbles_error(self) -> None:
        webapp._run_demo_runner = lambda *args: (
            {"ok": False, "error": "unknown_scenario:bad-demo"},
            400,
        )
        response = self.client.post("/api/demo/run/bad-demo")
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertIn("unknown_scenario", payload["error"])

    def test_run_scenario_persists_overlay(self) -> None:
        written = {}
        webapp._run_demo_runner = lambda *args: (
            {
                "ok": True,
                "result": {
                    "scenario_id": "mixed_correlation_demo",
                    "description": "Cross-source demo",
                    "event_count": 3,
                    "noc": {"summary": {"status": "degraded"}},
                    "soc": {"summary": {"status": "critical"}, "suspicion": {"score": 97}},
                    "arbiter": {"action": "throttle", "reason": "correlated_signal"},
                    "explanation": {"evidence_ids": ["soc-1"], "operator_wording": "demo wording"},
                },
            },
            200,
        )
        webapp.build_demo_overlay = lambda result: {"active": True, "scenario_id": result["scenario_id"], "action": "throttle"}
        webapp.write_demo_overlay = lambda payload: written.update(payload) or Path("/tmp/demo_overlay.json")
        response = self.client.post("/api/demo/run/mixed_correlation_demo")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["overlay"]["active"])
        self.assertEqual(written["scenario_id"], "mixed_correlation_demo")

    def test_clear_overlay_endpoint(self) -> None:
        cleared = {"done": False}
        side_effect = {"done": False}
        webapp.clear_demo_overlay = lambda: cleared.__setitem__("done", True)
        webapp._trigger_demo_clear_side_effects = lambda: side_effect.__setitem__("done", True)
        response = self.client.post("/api/demo/overlay/clear")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(cleared["done"])
        self.assertTrue(side_effect["done"])


if __name__ == "__main__":
    unittest.main()
