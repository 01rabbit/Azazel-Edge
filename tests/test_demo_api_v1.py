from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp
from azazel_edge.demo_overlay import build_demo_overlay, clear_demo_overlay, read_demo_overlay, write_demo_overlay


class DemoApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self._orig = {
            "load_token": webapp.load_token,
            "_run_demo_runner": webapp._run_demo_runner,
            "STATE_PATH": webapp.STATE_PATH,
            "EPD_LAST_RENDER_PATH": webapp.EPD_LAST_RENDER_PATH,
            "read_demo_overlay": webapp.read_demo_overlay,
            "write_demo_overlay": webapp.write_demo_overlay,
            "clear_demo_overlay": webapp.clear_demo_overlay,
            "build_demo_overlay": webapp.build_demo_overlay,
            "_trigger_demo_clear_side_effects": webapp._trigger_demo_clear_side_effects,
        }
        webapp.load_token = lambda: None
        webapp.STATE_PATH = root / "ui_snapshot.json"
        webapp.STATE_PATH.write_text(json.dumps({"ok": True}), encoding="utf-8")
        webapp.EPD_LAST_RENDER_PATH = root / "epd_last_render.json"
        self.overlay_path = root / "demo_overlay.json"
        webapp.read_demo_overlay = lambda: read_demo_overlay(self.overlay_path)
        webapp.write_demo_overlay = lambda payload: write_demo_overlay(payload, self.overlay_path)
        webapp.clear_demo_overlay = lambda: clear_demo_overlay(self.overlay_path)
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.load_token = self._orig["load_token"]
        webapp._run_demo_runner = self._orig["_run_demo_runner"]
        webapp.STATE_PATH = self._orig["STATE_PATH"]
        webapp.EPD_LAST_RENDER_PATH = self._orig["EPD_LAST_RENDER_PATH"]
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
        calls = {}

        def fake_runner(*args):
            calls["args"] = args
            return (
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

        webapp._run_demo_runner = fake_runner
        response = self.client.post("/api/demo/run/noc_degraded_demo")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["arbiter"]["action"], "notify")
        self.assertEqual(calls["args"], ("run", "noc_degraded_demo", "--format", "json", "--apply-overlay"))

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

    def test_run_scenario_endpoint_requests_overlay_write(self) -> None:
        calls = {}

        def fake_runner(*args):
            calls["args"] = args
            return (
                {
                    "ok": True,
                    "result": {
                        "scenario_id": "mixed_correlation_demo",
                        "event_count": 3,
                        "arbiter": {"action": "throttle"},
                    },
                    "overlay": {"active": True, "scenario_id": "mixed_correlation_demo", "action": "throttle"},
                },
                200,
            )

        webapp._run_demo_runner = fake_runner
        response = self.client.post("/api/demo/run/mixed_correlation_demo")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["overlay"]["active"])
        self.assertEqual(calls["args"], ("run", "mixed_correlation_demo", "--format", "json", "--apply-overlay"))

    def test_demo_state_endpoint_returns_compact_overlay(self) -> None:
        overlay = build_demo_overlay(
            {
                "scenario_id": "mixed_correlation_demo",
                "description": "Cross-source demo",
                "event_count": 3,
                "execution": {"mode": "deterministic_replay", "ai_used": False, "offline_demo": True},
                "arbiter": {"action": "throttle", "reason": "correlated_signal", "control_mode": "route_preference"},
                "explanation": {"operator_wording": "demo wording", "evidence_ids": ["soc-1"], "next_checks": ["review sigma"]},
                "demo": {
                    "title": "Correlation with Sigma and YARA support",
                    "summary": "Cross-source evidence is reinforced by helper hits.",
                    "attack_label": "SSH Brute Force",
                    "talk_track": "demo talk track",
                    "decision_path": {"final_policy": {"headline": "FINAL POLICY: THROTTLE"}},
                    "proofs": {"policy": {"status": "active", "headline": "BOUNDED CONTROL SELECTED"}},
                },
                "presentation": {"title": "Correlation with Sigma and YARA support", "summary": "Cross-source evidence is reinforced by helper hits."},
            }
        )
        write_demo_overlay(overlay, self.overlay_path)
        webapp.EPD_LAST_RENDER_PATH.write_text(
            json.dumps({"ts": "2026-03-29T12:00:00", "render": {"state": "danger", "risk_status": "CHECKING", "suspicion": 97}}),
            encoding="utf-8",
        )
        response = self.client.get("/api/demo/state")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["active"])
        self.assertEqual(payload["title"], "Correlation with Sigma and YARA support")
        self.assertEqual(payload["attack_label"], "SSH Brute Force")
        self.assertEqual(payload["decision_path"]["final_policy"]["headline"], "FINAL POLICY: THROTTLE")
        self.assertEqual(payload["proofs"]["policy"]["status"], "active")
        self.assertEqual(payload["epd"]["state"], "danger")

    def test_demo_flow_endpoint_passes_requested_options(self) -> None:
        calls = {}

        def fake_runner(*args):
            calls["args"] = args
            return ({"ok": True, "mode": "demo_flow", "scenarios": []}, 200)

        webapp._run_demo_runner = fake_runner
        response = self.client.post(
            "/api/demo/flow",
            json={"scenarios": ["soc_redirect_demo", "mixed_correlation_demo"], "hold_sec": 0, "keep_final": True},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(
            calls["args"],
            ("flow", "--format", "json", "--scenarios", "soc_redirect_demo,mixed_correlation_demo", "--hold-sec", "0", "--keep-final"),
        )

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

    def test_stale_overlay_is_ignored_and_removed(self) -> None:
        overlay_path = Path(self.tmp.name) / "demo_overlay.json"
        overlay_path.write_text(json.dumps({
            "active": True,
            "scenario_id": "stale-demo",
            "ts": time.time() - 3600,
            "boot_id": "old-boot",
        }), encoding="utf-8")
        payload = read_demo_overlay(overlay_path)
        self.assertEqual(payload, {})
        self.assertFalse(overlay_path.exists())

    def test_overlay_without_current_boot_id_is_ignored(self) -> None:
        overlay_path = Path(self.tmp.name) / "demo_overlay.json"
        payload = build_demo_overlay({"scenario_id": "boot-check", "arbiter": {"action": "observe"}})
        payload["boot_id"] = "different-boot-id"
        overlay_path.write_text(json.dumps(payload), encoding="utf-8")
        loaded = read_demo_overlay(overlay_path)
        self.assertEqual(loaded, {})
        self.assertFalse(overlay_path.exists())

    def test_demo_capabilities_endpoint(self) -> None:
        response = self.client.get("/api/demo/capabilities")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["execution_mode"], "deterministic_replay")
        self.assertFalse(payload["ai_used_in_core_path"])
        self.assertTrue(payload["local_only_in_core_path"])
        self.assertIn("implemented_now", payload["boundary"])

    def test_latest_explanation_endpoint_reads_active_overlay(self) -> None:
        overlay = build_demo_overlay(
            {
                "scenario_id": "mixed_correlation_demo",
                "event_count": 3,
                "execution": {"mode": "deterministic_replay", "ai_used": False},
                "arbiter": {"action": "throttle", "reason": "correlated_signal"},
                "explanation": {"operator_wording": "demo wording", "evidence_ids": ["soc-1"]},
            }
        )
        write_demo_overlay(overlay, self.overlay_path)
        response = self.client.get("/api/demo/explanation/latest")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scenario_id"], "mixed_correlation_demo")
        self.assertEqual(payload["action"], "throttle")
        self.assertEqual(payload["explanation"]["operator_wording"], "demo wording")


if __name__ == "__main__":
    unittest.main()
