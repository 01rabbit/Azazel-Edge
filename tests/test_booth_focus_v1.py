from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class BoothFocusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.orig = {name: getattr(webapp, name) for name in (
            "STATE_PATH", "FALLBACK_STATE_PATH", "DECISION_EXPLANATIONS_PATH",
            "BOOTH_DEMO_EXPLANATIONS_PATH", "AUTH_FAIL_OPEN", "cp_read_snapshot_payload",
        )}
        webapp.STATE_PATH = root / "state.json"
        webapp.FALLBACK_STATE_PATH = root / "fallback.json"
        webapp.DECISION_EXPLANATIONS_PATH = root / "live-explanations.jsonl"
        webapp.BOOTH_DEMO_EXPLANATIONS_PATH = root / "demo-explanations.jsonl"
        webapp.AUTH_FAIL_OPEN = True
        webapp.cp_read_snapshot_payload = None
        webapp.STATE_PATH.write_text(json.dumps({"snapshot_epoch": 1, "execution": {"mode": "deterministic_replay", "local_only": True}}), encoding="utf-8")
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        for name, value in self.orig.items():
            setattr(webapp, name, value)
        self.tmp.cleanup()

    def _write_record(self, action: str) -> None:
        record = {
            "trace_id": f"demo:{action.lower()}", "format_version": "v2", "selected_action": action,
            "reason": "deterministic test decision", "policy_profile": "demo", "config_hash": "sha256:test",
            "evidence_ids": ["ev-soc-1", "ev-noc-1"], "release_condition": "evidence decays",
            "why_not_others": [{"action": "isolate", "reason": "Containment gate not satisfied"}],
            "why_chosen": {"client_impact": {"affected_client_count": 2}},
            "machine": {"noc_summary": {"status": "degraded"}, "soc_summary": {"status": "critical"}},
        }
        webapp.BOOTH_DEMO_EXPLANATIONS_PATH.write_text(json.dumps(record) + "\n", encoding="utf-8")

    def test_focus_projects_real_explanation_fields_for_replay(self) -> None:
        self._write_record("throttle")
        response = self.client.get("/api/booth-focus")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["available"])
        self.assertEqual(payload["mode"]["kind"], "deterministic_replay")
        self.assertEqual(payload["decision"]["action"], "THROTTLE")
        self.assertEqual(payload["decision"]["soc_status"], "CRITICAL")
        self.assertEqual(payload["decision"]["why_not_others"][0]["reason"], "Containment gate not satisfied")
        self.assertEqual(payload["audit"]["trace_id"], "demo:throttle")
        self.assertIn("M.I.O. ADVISORY", payload["mio"]["advisory_label"])
        self.assertIn("Do%20not%20change%20the%20decision", payload["mio"]["url"])

    def test_focus_preserves_action_variants(self) -> None:
        for action in ("notify", "observe"):
            self._write_record(action)
            payload = self.client.get("/api/booth-focus").get_json()
            self.assertEqual(payload["decision"]["action"], action.upper())

    def test_mio_is_not_promoted_when_snapshot_is_normal(self) -> None:
        self._write_record("observe")
        webapp.STATE_PATH.write_text(json.dumps({
            "snapshot_epoch": 1,
            "execution": {"mode": "deterministic_replay", "local_only": True},
            "network_health": {"status": "healthy"},
            "second_pass": {"soc": {"status": "safe"}},
        }), encoding="utf-8")
        payload = self.client.get("/api/booth-focus").get_json()
        self.assertFalse(payload["mio"]["recommended"])

    def test_focus_reports_missing_decision_without_placeholder_cards(self) -> None:
        payload = self.client.get("/api/booth-focus").get_json()
        self.assertFalse(payload["available"])
        self.assertEqual(payload["status"], "decision_unavailable")

    def test_focus_page_has_full_dashboard_escape_hatch(self) -> None:
        response = self.client.get("/booth-focus")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Open full dashboard", response.get_data(as_text=True))
        self.assertIn("Is NOC healthy? Is SOC quiet?", response.get_data(as_text=True))
        self.assertIn("Get a guided explanation", response.get_data(as_text=True))
