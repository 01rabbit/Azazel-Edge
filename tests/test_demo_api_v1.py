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
            "_run_arsenal_demo_runner": webapp._run_arsenal_demo_runner,
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
        self.overlay_path = root / "demo_overlay.json"
        webapp.read_demo_overlay = lambda: read_demo_overlay(self.overlay_path)
        webapp.write_demo_overlay = lambda payload: write_demo_overlay(payload, self.overlay_path)
        webapp.clear_demo_overlay = lambda: clear_demo_overlay(self.overlay_path)
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.load_token = self._orig["load_token"]
        webapp._run_demo_runner = self._orig["_run_demo_runner"]
        webapp._run_arsenal_demo_runner = self._orig["_run_arsenal_demo_runner"]
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

    def test_arsenal_stages_endpoint(self) -> None:
        webapp._run_arsenal_demo_runner = lambda *args: (
            {
                "ok": True,
                "items": [
                    {"stage_id": "arsenal_throttle", "band": "THROTTLE", "score": 73}
                ],
            },
            200,
        )
        response = self.client.get("/api/arsenal-demo/stages")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["items"][0]["stage_id"], "arsenal_throttle")

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

    def test_arsenal_state_endpoint_returns_compact_overlay(self) -> None:
        overlay = build_demo_overlay(
            {
                "scenario_id": "arsenal_throttle",
                "event_count": 3,
                "execution": {"mode": "deterministic_replay", "ai_used": False, "offline_demo": True},
                "arbiter": {"action": "throttle", "reason": "arsenal_score_band:throttle", "control_mode": "traffic_shaping"},
                "explanation": {"operator_wording": "demo wording", "evidence_ids": ["ars-1"]},
            }
        )
        overlay["arsenal_demo"] = {
            "title": "Risk score triggers throttle",
            "attack_label": "SSH Brute Force",
            "score": 73,
            "band": "THROTTLE",
            "state_message": "Traffic shaping is active with bounded delay / bandwidth control.",
            "talk_track": "demo wording",
            "score_factors": ["severity=3"],
            "decision_path": {
                "first_pass": {"headline": "MOCK-LLM SCORE 67", "detail": "deterministic first pass"},
                "ollama_review": {"status": "used", "headline": "OLLAMA REVIEWED", "detail": "local review", "evidence": "model=qwen3.5:2b"},
                "final_policy": {"headline": "FINAL POLICY: THROTTLE", "detail": "bounded control"},
            },
            "proofs": {
                "tc": {"status": "active", "headline": "TC THROTTLE ACTIVE", "detail": "detail", "evidence": "netem delay 120ms"},
                "firewall": {"status": "active", "headline": "MICRO-POLICY ACTIVE", "detail": "detail", "evidence": "nft counter"},
                "decoy": {"status": "standby", "headline": "DECOY ON HOLD", "detail": "detail", "evidence": "selector idle"},
                "offline": {"status": "active", "headline": "OFFLINE ACTIVE", "detail": "detail", "evidence": "local only"},
                "epd": {"status": "sync", "headline": "EPD SYNC READY", "detail": "detail", "evidence": "expected panel"},
            },
        }
        write_demo_overlay(overlay, self.overlay_path)
        response = self.client.get("/api/arsenal-demo/state")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["presentation"]["brand"], "Azazel-Pi")
        self.assertEqual(payload["band"], "THROTTLE")
        self.assertEqual(payload["action"], "throttle")
        self.assertEqual(payload["attack_label"], "SSH Brute Force")
        self.assertEqual(payload["decision_path"]["ollama_review"]["status"], "used")
        self.assertEqual(payload["proofs"]["tc"]["status"], "active")
        self.assertIn("nft", payload["proofs"]["firewall"]["evidence"])

    def test_arsenal_demo_page_uses_azazel_pi_title(self) -> None:
        response = self.client.get("/arsenal-demo")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("Azazel-Pi", text)
        self.assertIn("arsenalTcCard", text)
        self.assertIn("arsenalOfflineCard", text)
        self.assertIn("arsenalDecisionStrip", text)
        self.assertIn("arsenalOllamaCard", text)
        self.assertIn("langJaBtn", text)
        self.assertIn("langEnBtn", text)


if __name__ == "__main__":
    unittest.main()
