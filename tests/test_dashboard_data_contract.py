from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class DashboardDataContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        now = time.time()

        self._orig = {
            "STATE_PATH": webapp.STATE_PATH,
            "FALLBACK_STATE_PATH": webapp.FALLBACK_STATE_PATH,
            "AI_ADVISORY_PATH": webapp.AI_ADVISORY_PATH,
            "AI_METRICS_PATH": webapp.AI_METRICS_PATH,
            "AI_EVENT_LOG": webapp.AI_EVENT_LOG,
            "AI_LLM_LOG": webapp.AI_LLM_LOG,
            "RUNBOOK_EVENT_LOG": webapp.RUNBOOK_EVENT_LOG,
            "cp_read_snapshot_payload": webapp.cp_read_snapshot_payload,
            "load_token": webapp.load_token,
            "get_monitoring_state": webapp.get_monitoring_state,
            "get_mode_state": webapp.get_mode_state,
            "_mattermost_ping": webapp._mattermost_ping,
            "_service_active": webapp._service_active,
            "_send_ai_manual_query": webapp._send_ai_manual_query,
        }

        webapp.STATE_PATH = root / "ui_snapshot.json"
        webapp.FALLBACK_STATE_PATH = root / "ui_snapshot_fallback.json"
        webapp.AI_ADVISORY_PATH = root / "ai_advisory.json"
        webapp.AI_METRICS_PATH = root / "ai_metrics.json"
        webapp.AI_EVENT_LOG = root / "ai-events.jsonl"
        webapp.AI_LLM_LOG = root / "ai-llm.jsonl"
        webapp.RUNBOOK_EVENT_LOG = root / "runbook-events.jsonl"
        webapp.cp_read_snapshot_payload = None
        webapp.load_token = lambda: None
        webapp.get_monitoring_state = lambda: {
            "suricata": "ON",
            "opencanary": "OFF",
            "ntfy": "ON",
        }
        webapp.get_mode_state = lambda: {
            "ok": True,
            "mode": {
                "current_mode": "shield",
                "last_change": "2026-03-08T18:55:00",
                "requested_by": "webui",
            },
            "source": "TEST",
        }
        webapp._mattermost_ping = lambda: (True, {"status": "OK"})
        webapp._service_active = lambda name: name in {"azazel-edge-ai-agent", "azazel-edge-web"}

        state = {
            "ok": True,
            "snapshot_epoch": now,
            "now_time": "19:00:00",
            "ssid": "ETH:eth1",
            "up_if": "eth1",
            "up_ip": "192.168.40.89",
            "gateway_ip": "192.168.40.1",
            "user_state": "LIMITED",
            "recommendation": "Check DNS mismatch before mode change",
            "suricata_critical": 2,
            "suricata_warning": 1,
            "internal": {"state_name": "PROBE", "suspicion": 66, "decay": 0},
            "connection": {
                "uplink_type": "ethernet",
                "internet_check": "FAIL",
                "captive_portal": "NO",
            },
            "network_health": {
                "status": "SUSPECTED",
                "dns_mismatch": 2,
                "signals": ["dns_mismatch"],
            },
            "evidence": ["net_health=SUSPECTED signals=dns_mismatch"],
            "llm": {"status": "skipped_non_ambiguous"},
        }
        advisory = {
            "ts": now - 3,
            "risk_score": 66,
            "risk_level": "MEDIUM",
            "state_name": "PROBE",
            "user_state": "LIMITED",
            "attack_type": "dns anomaly",
            "src_ip": "192.168.40.12",
            "dst_ip": "8.8.8.8",
            "suricata_sid": 210001,
            "suricata_severity": 2,
            "recommendation": "Verify uplink and DNS policy",
            "ops_coach": {
                "confidence": 0.74,
                "runbook_id": "rb.noc.dns.failure.check",
                "operator_note": "Confirm gateway and resolver mismatch.",
            },
        }
        metrics = {
            "queue_depth": 1,
            "queue_capacity": 8,
            "queue_max_seen": 3,
            "deferred_count": 2,
            "llm_requests": 4,
            "llm_completed": 3,
            "llm_failed": 1,
            "llm_fallback_rate": 0.25,
            "llm_latency_ms_last": 420,
            "llm_latency_ms_ema": 380.5,
            "manual_routed_count": 5,
            "policy_mode": "normal",
            "last_error": "",
            "last_update_ts": now,
        }

        webapp.STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
        webapp.AI_ADVISORY_PATH.write_text(json.dumps(advisory), encoding="utf-8")
        webapp.AI_METRICS_PATH.write_text(json.dumps(metrics), encoding="utf-8")
        webapp.AI_EVENT_LOG.write_text(
            json.dumps({"event": {"normalized": {"sid": 210001, "severity": 2, "attack_type": "dns anomaly", "src_ip": "192.168.40.12", "dst_ip": "8.8.8.8"}}, "advisory": advisory}) + "\n",
            encoding="utf-8",
        )
        webapp.AI_LLM_LOG.write_text(
            json.dumps(
                {
                    "ts": now - 1,
                    "kind": "manual_query_routed",
                    "source": "ops-comm",
                    "sender": "M.I.O. Console",
                    "question": "DNS failure",
                    "model": "manual_router",
                    "response": {
                        "status": "routed",
                        "answer": "M.I.O.判断: DNS 経路と gateway の整合を先に確認します。",
                        "runbook_id": "rb.noc.dns.failure.check",
                        "operator_note": "Check gateway and resolver.",
                        "user_message": "通信経路を確認しています。しばらくお待ちください。",
                        "runbook_review": {"final_status": "approved"},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        webapp.RUNBOOK_EVENT_LOG.write_text(
            json.dumps(
                {
                    "ts": now - 2,
                    "actor": "M.I.O. Console",
                    "action": "preview",
                    "runbook_id": "rb.noc.dns.failure.check",
                    "approved": False,
                    "ok": True,
                    "review_status": "approved",
                    "effect": "read_only",
                    "note": "ops-comm",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.STATE_PATH = self._orig["STATE_PATH"]
        webapp.FALLBACK_STATE_PATH = self._orig["FALLBACK_STATE_PATH"]
        webapp.AI_ADVISORY_PATH = self._orig["AI_ADVISORY_PATH"]
        webapp.AI_METRICS_PATH = self._orig["AI_METRICS_PATH"]
        webapp.AI_EVENT_LOG = self._orig["AI_EVENT_LOG"]
        webapp.AI_LLM_LOG = self._orig["AI_LLM_LOG"]
        webapp.RUNBOOK_EVENT_LOG = self._orig["RUNBOOK_EVENT_LOG"]
        webapp.cp_read_snapshot_payload = self._orig["cp_read_snapshot_payload"]
        webapp.load_token = self._orig["load_token"]
        webapp.get_monitoring_state = self._orig["get_monitoring_state"]
        webapp.get_mode_state = self._orig["get_mode_state"]
        webapp._mattermost_ping = self._orig["_mattermost_ping"]
        webapp._service_active = self._orig["_service_active"]
        webapp._send_ai_manual_query = self._orig["_send_ai_manual_query"]
        self.tmp.cleanup()

    def test_dashboard_summary_contract(self) -> None:
        response = self.client.get("/api/dashboard/summary")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"]["current_mode"], "shield")
        self.assertEqual(payload["uplink"]["up_if"], "eth1")
        self.assertEqual(payload["command_strip"]["direct_critical_count"], 2)
        self.assertEqual(payload["service_health_summary"]["ai_agent"], "ON")

    def test_dashboard_actions_contract(self) -> None:
        response = self.client.get("/api/dashboard/actions")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["suggested_runbook"]["id"], "rb.noc.dns.failure.check")
        self.assertIn("通信経路を確認しています", payload["current_user_guidance"])
        self.assertTrue(payload["current_operator_actions"])
        self.assertTrue(payload["why_now"])
        self.assertTrue(payload["do_next"])
        self.assertTrue(payload["do_not_do"])
        self.assertTrue(payload["escalate_if"])
        self.assertIn("signals", " ".join(payload["why_now"]).lower())
        self.assertEqual(payload["mio"]["question"], "DNS failure")
        self.assertEqual(payload["mio"]["runbook"]["id"], "rb.noc.dns.failure.check")
        self.assertTrue(payload["mio"]["rationale"])
        self.assertEqual(payload["mio"]["handoff"]["ops_comm"], "/ops-comm")

    def test_dashboard_evidence_contract(self) -> None:
        response = self.client.get("/api/dashboard/evidence")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["recent_alerts"][0]["sid"], 210001)
        self.assertEqual(payload["recent_ai_activity"][0]["runbook_id"], "rb.noc.dns.failure.check")
        self.assertEqual(payload["recent_runbook_events"][0]["action"], "preview")
        self.assertEqual(payload["recent_mode_changes"][0]["current_mode"], "shield")
        self.assertTrue(payload["current_triggers"])
        self.assertTrue(payload["decision_changes"])
        self.assertTrue(payload["operator_interactions"])
        self.assertTrue(payload["background_history"])

    def test_dashboard_health_contract(self) -> None:
        response = self.client.get("/api/dashboard/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["queue"]["depth"], 1)
        self.assertAlmostEqual(payload["llm"]["fallback_rate"], 0.25)
        self.assertTrue(payload["mattermost"]["reachable"])
        self.assertFalse(payload["stale_flags"]["snapshot"])

    def test_dashboard_index_renders_new_sections(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("Command Dashboard", text)
        self.assertIn("Audience Mode", text)
        self.assertIn("Snapshot", text)
        self.assertIn("AI Metrics", text)
        self.assertIn("AI Activity", text)
        self.assertIn("Runbook Event", text)
        self.assertIn("M.I.O. Assist", text)
        self.assertIn("Last Manual Ask", text)
        self.assertIn("Recommended Runbook", text)
        self.assertIn("Rationale", text)
        self.assertIn("Open Ops Comm", text)
        self.assertIn("Current Triggers", text)
        self.assertIn("Decision Changes", text)
        self.assertIn("Operator Interactions", text)
        self.assertIn("Background History", text)
        self.assertIn("Ask M.I.O.", text)
        self.assertIn("Why now", text)
        self.assertIn("Do not do", text)
        self.assertIn("Escalate if", text)
        self.assertIn("Reconnect", text)
        self.assertIn("Onboarding", text)
        self.assertIn("Portal", text)

    def test_manual_ai_ask_enriches_rationale_and_handoff(self) -> None:
        webapp._send_ai_manual_query = lambda **_: {
            "ok": True,
            "status": "routed",
            "model": "manual_router",
            "answer": "M.I.O.: DNS と gateway を確認します。",
            "runbook_id": "rb.noc.dns.failure.check",
            "user_message": "通信経路を確認しています。",
            "runbook_review": {"final_status": "approved", "findings": ["Resolver mismatch detected."]},
        }
        response = self.client.post(
            "/api/ai/ask",
            json={"question": "DNS が引けない", "sender": "tester", "source": "ops-comm"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["handoff"]["ops_comm"], "/ops-comm")
        self.assertIn("rationale", payload)
        self.assertTrue(payload["rationale"])

    def test_mattermost_response_includes_rationale_and_continue_hint(self) -> None:
        text = webapp._format_mattermost_ai_response(
            {
                "ok": True,
                "status": "routed",
                "answer": "M.I.O.: DNS と gateway を確認します。",
                "user_message": "通信経路を確認しています。",
                "runbook_id": "rb.noc.dns.failure.check",
                "runbook_review": {"final_status": "approved"},
                "rationale": ["Symptom router handled this request without waiting for LLM."],
                "handoff": {"ops_comm": "/ops-comm", "mattermost": "http://example.invalid/mm"},
            },
            None,
        )
        self.assertIn("Rationale:", text)
        self.assertIn("Continue:", text)


if __name__ == "__main__":
    unittest.main()
