from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class HandoffApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        now = time.time()

        self._orig = {
            "STATE_PATH": webapp.STATE_PATH,
            "AI_LLM_LOG": webapp.AI_LLM_LOG,
            "TRIAGE_AUDIT_LOG": webapp.TRIAGE_AUDIT_LOG,
            "TRIAGE_AUDIT_FALLBACK_LOG": webapp.TRIAGE_AUDIT_FALLBACK_LOG,
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "load_token": webapp.load_token,
            "_sot_candidates": webapp._sot_candidates,
        }

        webapp.STATE_PATH = root / "ui_snapshot.json"
        webapp.AI_LLM_LOG = root / "ai-llm.jsonl"
        webapp.TRIAGE_AUDIT_LOG = root / "triage-audit.jsonl"
        webapp.TRIAGE_AUDIT_FALLBACK_LOG = root / "triage-audit-fallback.jsonl"
        webapp.AUTH_FAIL_OPEN = True
        webapp.load_token = lambda: None

        sot_path = root / "sot.json"
        sot_path.write_text(
            json.dumps(
                {
                    "user_state": "WATCH",
                    "recommendation": "Check suspicious DNS behavior and verify path health.",
                }
            ),
            encoding="utf-8",
        )
        webapp._sot_candidates = lambda: [sot_path]

        webapp.TRIAGE_AUDIT_LOG.write_text(
            "\n".join(
                [
                    json.dumps({"ts": now - 10, "action": "notify", "detail": "initial action"}),
                    json.dumps({"ts": now - 8, "action": "throttle", "detail": "bounded control"}),
                    json.dumps({"ts": now - 6, "action": "observe", "detail": "tracking"}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        webapp.AI_LLM_LOG.write_text(
            json.dumps(
                {
                    "ts": now - 1,
                    "response": {
                        "answer": "Confirm affected segment and preserve current mode.",
                        "operator_note": "Do not restart network services without evidence refresh.",
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.STATE_PATH = self._orig["STATE_PATH"]
        webapp.AI_LLM_LOG = self._orig["AI_LLM_LOG"]
        webapp.TRIAGE_AUDIT_LOG = self._orig["TRIAGE_AUDIT_LOG"]
        webapp.TRIAGE_AUDIT_FALLBACK_LOG = self._orig["TRIAGE_AUDIT_FALLBACK_LOG"]
        webapp.AUTH_FAIL_OPEN = self._orig["AUTH_FAIL_OPEN"]
        webapp.load_token = self._orig["load_token"]
        webapp._sot_candidates = self._orig["_sot_candidates"]
        self.tmp.cleanup()

    def test_handoff_summary_returns_required_keys(self) -> None:
        response = self.client.get("/api/handoff/summary")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        for key in ("generated_at", "posture", "primary_concern", "actions_taken", "do_now", "do_not_do", "next_shift_notes"):
            self.assertIn(key, payload)
        self.assertEqual(payload["posture"], "watch")

    def test_handoff_summary_lang_ja(self) -> None:
        response = self.client.get("/api/handoff/summary?lang=ja")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertIn("primary_concern", payload)

    def test_handoff_summary_format_print_is_text(self) -> None:
        response = self.client.get("/api/handoff/summary?format=print")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("Azazel-Edge Shift Handoff Summary", text)
        self.assertEqual(response.mimetype, "text/plain")


if __name__ == "__main__":
    unittest.main()
