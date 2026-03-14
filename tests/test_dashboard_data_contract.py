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
            "TRIAGE_AUDIT_LOG": webapp.TRIAGE_AUDIT_LOG,
            "TRIAGE_AUDIT_FALLBACK_LOG": webapp.TRIAGE_AUDIT_FALLBACK_LOG,
            "cp_read_snapshot_payload": webapp.cp_read_snapshot_payload,
            "load_token": webapp.load_token,
            "get_monitoring_state": webapp.get_monitoring_state,
            "get_mode_state": webapp.get_mode_state,
            "_mattermost_ping": webapp._mattermost_ping,
            "_service_active": webapp._service_active,
            "_send_ai_manual_query": webapp._send_ai_manual_query,
            "read_demo_overlay": webapp.read_demo_overlay,
        }

        webapp.STATE_PATH = root / "ui_snapshot.json"
        webapp.FALLBACK_STATE_PATH = root / "ui_snapshot_fallback.json"
        webapp.AI_ADVISORY_PATH = root / "ai_advisory.json"
        webapp.AI_METRICS_PATH = root / "ai_metrics.json"
        webapp.AI_EVENT_LOG = root / "ai-events.jsonl"
        webapp.AI_LLM_LOG = root / "ai-llm.jsonl"
        webapp.RUNBOOK_EVENT_LOG = root / "runbook-events.jsonl"
        webapp.TRIAGE_AUDIT_LOG = root / "triage-audit.jsonl"
        webapp.TRIAGE_AUDIT_FALLBACK_LOG = root / "triage-audit-fallback.jsonl"
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
            "noc_capacity": {
                "state": "elevated",
                "mode": "utilization_known",
                "utilization_pct": 78.4,
                "top_sources": [{"src_ip": "192.168.40.12", "bytes": 4096}],
                "signals": ["capacity_elevated"],
            },
            "noc_client_inventory": {
                "current_client_count": 6,
                "new_client_count": 1,
                "unknown_client_count": 1,
                "unauthorized_client_count": 0,
                "inventory_mismatch_count": 1,
                "stale_session_count": 0,
            },
            "noc_service_assurance": {
                "status": "degraded",
                "degraded_targets": ["resolver-tcp"],
            },
            "noc_resolution_assurance": {
                "status": "failed",
                "failed_targets": ["example.com"],
            },
            "noc_blast_radius": {
                "affected_uplinks": ["eth1"],
                "affected_segments": ["lan-main", "wan"],
                "related_service_targets": ["dns", "resolver-tcp"],
                "affected_client_count": 4,
                "critical_client_count": 1,
            },
            "noc_config_drift": {
                "status": "drift",
                "baseline_state": "present",
                "changed_fields": ["uplink_preference.preferred_uplink", "policy_markers.policy_version"],
                "rollback_hint": "review_changed_fields_and_restore_last_known_good",
            },
            "noc_incident_summary": {
                "incident_id": "incident:abc123",
                "probable_cause": "resolution_failure",
                "confidence": 0.88,
                "supporting_symptoms": [
                    "resolution_health:resolution_window_failed:example.com",
                    "service_health:service_window_down:resolver-tcp",
                ],
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
            "decision_pipeline": {
                "first_pass": {"engine": "tactical_scorer_v1", "role": "first_minute_triage"},
                "second_pass": {"engine": "soc_evaluator_v1", "role": "second_pass_evaluation", "status": "completed", "evidence_count": 2, "flow_support_count": 1},
            },
            "second_pass": {
                "status": "completed",
                "evidence_count": 2,
                "flow_support_count": 1,
                "soc": {
                    "status": "high",
                    "attack_candidates": ["T1071 Application Layer Protocol"],
                    "ti_matches": [{"indicator_type": "ip", "value": "8.8.8.8"}],
                    "sigma_hits": [{"rule_id": "sig-1"}],
                    "yara_hits": [{"rule_id": "yara-1"}],
                    "correlation": {"status": "present", "reasons": ["cluster_detected"]},
                    "security_visibility_state": {"status": "partial", "missing_sources": ["syslog_min"], "stale_sources": []},
                    "suppression_exception_state": {"status": "partial", "suppressed_count": 2, "exception_count": 1},
                    "asset_target_criticality": {"status": "critical_targets_observed", "critical_target_count": 1},
                    "exposure_change_state": {"status": "expanding", "new_external_destinations": ["8.8.8.8"], "new_service_targets": ["8.8.8.8:443"]},
                    "confidence_provenance": {"status": "medium", "adjusted_score": 74, "supports": ["ti_match"], "weakens": ["limited_visibility"]},
                    "behavior_sequence_state": {"status": "multi_stage", "stage_sequence": ["recon", "access", "command"], "chain_hits": ["recon->access->command"]},
                    "triage_priority_state": {
                        "status": "now",
                        "score": 84,
                        "now": [{"id": "inc-1", "kind": "incident", "score": 92}],
                        "watch": [{"id": "ent-1", "kind": "entity", "score": 64}],
                        "backlog": [{"id": "ent-2", "kind": "entity", "score": 35}],
                        "top_priority_ids": ["inc-1", "ent-1"],
                    },
                    "incident_campaign_state": {"status": "active", "incident_count": 2, "active_count": 1},
                    "entity_risk_state": {"entity_count": 3},
                },
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
        webapp.TRIAGE_AUDIT_LOG.write_text(
            json.dumps(
                {
                    "ts": "2026-03-11T10:00:00+09:00",
                    "kind": "triage_runbook_proposed",
                    "trace_id": "triage-1",
                    "source": "triage_engine",
                    "session_id": "triage-1",
                    "intent_id": "dns_resolution",
                    "diagnostic_state": "dns_global_failure",
                    "proposed_runbooks": ["rb.noc.dns.failure.check"],
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
        webapp.TRIAGE_AUDIT_LOG = self._orig["TRIAGE_AUDIT_LOG"]
        webapp.TRIAGE_AUDIT_FALLBACK_LOG = self._orig["TRIAGE_AUDIT_FALLBACK_LOG"]
        webapp.cp_read_snapshot_payload = self._orig["cp_read_snapshot_payload"]
        webapp.load_token = self._orig["load_token"]
        webapp.get_monitoring_state = self._orig["get_monitoring_state"]
        webapp.get_mode_state = self._orig["get_mode_state"]
        webapp._mattermost_ping = self._orig["_mattermost_ping"]
        webapp._service_active = self._orig["_service_active"]
        webapp._send_ai_manual_query = self._orig["_send_ai_manual_query"]
        webapp.read_demo_overlay = self._orig["read_demo_overlay"]
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
        self.assertIn("soc_focus", payload)
        self.assertIn("noc_focus", payload)
        self.assertIn("decision_path", payload)
        self.assertEqual(payload["soc_focus"]["attack_type"], "dns anomaly")
        self.assertEqual(payload["noc_focus"]["path_health"]["uplink"], "eth1")
        self.assertEqual(payload["noc_focus"]["capacity"]["state"], "elevated")
        self.assertEqual(payload["noc_focus"]["capacity"]["top_talker"], "192.168.40.12")
        self.assertEqual(payload["noc_focus"]["client_inventory"]["current_client_count"], 6)
        self.assertEqual(payload["noc_focus"]["client_inventory"]["inventory_mismatch_count"], 1)
        self.assertEqual(payload["noc_focus"]["service_assurance"]["status"], "degraded")
        self.assertEqual(payload["noc_focus"]["resolution_health"]["status"], "failed")
        self.assertEqual(payload["noc_focus"]["blast_radius"]["affected_client_count"], 4)
        self.assertEqual(payload["noc_focus"]["blast_radius"]["related_service_targets"], ["dns", "resolver-tcp"])
        self.assertEqual(payload["noc_focus"]["config_drift"]["status"], "drift")
        self.assertEqual(payload["noc_focus"]["config_drift"]["rollback_hint"], "review_changed_fields_and_restore_last_known_good")
        self.assertEqual(payload["noc_focus"]["incident_summary"]["incident_id"], "incident:abc123")
        self.assertEqual(payload["noc_focus"]["incident_summary"]["probable_cause"], "resolution_failure")
        self.assertEqual(payload["decision_path"]["first_pass_engine"], "tactical_scorer_v1")
        self.assertEqual(payload["decision_path"]["second_pass_status"], "completed")
        self.assertEqual(payload["soc_focus"]["visibility"]["status"], "partial")
        self.assertEqual(payload["soc_focus"]["suppression"]["suppressed_count"], 2)
        self.assertEqual(payload["soc_focus"]["triage_priority"]["status"], "now")
        self.assertEqual(payload["soc_focus"]["triage_priority"]["top_priority_ids"], ["inc-1", "ent-1"])
        self.assertEqual(payload["soc_focus"]["incident_campaign"]["incident_count"], 2)
        self.assertEqual(payload["soc_focus"]["entity_risk"]["entity_count"], 3)

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
        self.assertTrue(payload["rejected_stronger_actions"])
        self.assertEqual(payload["noc_runbook_support"]["runbook_candidate_id"], "rb.noc.dns.failure.check")
        self.assertTrue(payload["noc_runbook_support"]["operator_checks"])
        self.assertEqual(payload["decision_path"]["first_pass_role"], "first_minute_triage")
        self.assertEqual(payload["decision_path"]["second_pass_flow_support_count"], 1)
        self.assertEqual(payload["soc_priority"]["status"], "now")
        self.assertEqual(len(payload["soc_priority"]["now"]), 1)
        self.assertEqual(payload["soc_priority"]["top_priority_ids"], ["inc-1", "ent-1"])

    def test_dashboard_actions_falls_back_to_deterministic_noc_runbook_without_ai_context(self) -> None:
        webapp.AI_LLM_LOG.write_text("", encoding="utf-8")
        advisory = json.loads(webapp.AI_ADVISORY_PATH.read_text(encoding="utf-8"))
        advisory["ops_coach"]["runbook_id"] = ""
        webapp.AI_ADVISORY_PATH.write_text(json.dumps(advisory), encoding="utf-8")
        response = self.client.get("/api/dashboard/actions")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["suggested_runbook"]["id"], "rb.noc.dns.failure.check")
        self.assertIn("resolver", payload["noc_runbook_support"]["why_this_runbook"].lower())
        self.assertTrue(payload["current_operator_actions"])

    def test_dashboard_actions_hides_dashboard_demo_context_when_overlay_is_inactive(self) -> None:
        now = time.time()
        webapp.read_demo_overlay = lambda: {}
        webapp.AI_LLM_LOG.write_text(
            json.dumps(
                {
                    "ts": now - 1,
                    "kind": "manual_query_completed",
                    "source": "dashboard_demo",
                    "sender": "Dashboard",
                    "question": "Demo scenario noc_degraded_demo",
                    "model": "manual_router",
                    "response": {
                        "status": "completed",
                        "answer": "Demo explanation",
                        "runbook_id": "rb.noc.dns.failure.check",
                        "operator_note": "demo only",
                        "user_message": "demo only",
                        "runbook_review": {"final_status": "approved"},
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        response = self.client.get("/api/dashboard/actions")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mio"]["status"], "idle")
        self.assertEqual(payload["mio"]["answer"], "")

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
        self.assertTrue(payload["triage_audit"])
        self.assertEqual(payload["recent_triage_audit"][0]["kind"], "triage_runbook_proposed")

    def test_dashboard_health_contract(self) -> None:
        response = self.client.get("/api/dashboard/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["queue"]["depth"], 1)
        self.assertAlmostEqual(payload["llm"]["fallback_rate"], 0.25)
        self.assertTrue(payload["mattermost"]["reachable"])
        self.assertFalse(payload["stale_flags"]["snapshot"])
        self.assertIn("idle_flags", payload)
        self.assertIn("ai_activity", payload["idle_flags"])

    def test_dashboard_index_renders_new_sections(self) -> None:
        response = self.client.get("/?lang=en")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Content-Language"), "en")
        text = response.get_data(as_text=True)
        self.assertIn("Command Dashboard", text)
        self.assertIn("Audience Mode", text)
        self.assertIn("Current Mission", text)
        self.assertIn("What the operator should do now", text)
        self.assertIn("Primary Objective", text)
        self.assertIn("SOC / NOC Split Board", text)
        self.assertIn("Threat Evidence Summary", text)
        self.assertIn("Rejected Stronger Actions", text)
        self.assertIn("Temporary Mission", text)
        self.assertIn("Safe first response for the person in front of you", text)
        self.assertIn("Immediate Action", text)
        self.assertIn("Decision Path", text)
        self.assertIn("Snapshot", text)
        self.assertIn("AI Metrics", text)
        self.assertIn("AI Activity", text)
        self.assertIn("Runbook Event", text)
        self.assertIn("Resource Guard", text)
        self.assertIn('id="resourceGuardHeadline"', text)
        self.assertIn('id="resourceGuardReasonList"', text)
        self.assertIn('id="resourceGuardQueueBar"', text)
        self.assertIn('id="resourceGuardFallbackBar"', text)
        self.assertIn('id="resourceGuardLatencyBar"', text)
        self.assertIn("M.I.O. Assist", text)
        self.assertIn("Last Manual Ask", text)
        self.assertIn("Recommended Runbook", text)
        self.assertIn("Rationale", text)
        self.assertIn("Open Ops Comm", text)
        self.assertIn("Current Triggers", text)
        self.assertIn("Decision Changes", text)
        self.assertIn("Operator Interactions", text)
        self.assertIn("Background History", text)
        self.assertIn("Triage Audit", text)
        self.assertIn("Supporting history and audit trail", text)
        self.assertIn("Open Demo Page", text)
        self.assertIn("temporaryOpsCommLink", text)
        self.assertIn("Ask M.I.O.", text)
        self.assertIn("Why now", text)
        self.assertIn("Do not do", text)
        self.assertIn("Escalate if", text)
        self.assertIn("Reconnect", text)
        self.assertIn("Onboarding", text)
        self.assertIn("Portal", text)
        self.assertNotIn('id="demoRunForm"', text)
        self.assertNotIn('id="reviewPanel"', text)

    def test_dashboard_index_renders_japanese_labels_when_requested(self) -> None:
        response = self.client.get("/?lang=ja")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Content-Language"), "ja")
        text = response.get_data(as_text=True)
        self.assertIn("表示言語", text)
        self.assertIn("プロ向け", text)
        self.assertIn("デモ表示", text)
        self.assertIn("実務ダッシュボードは live のままです", text)
        self.assertIn("Service Health", text)
        self.assertIn("NOC Focus", text)
        self.assertIn("Action Board", text)
        self.assertNotIn("サービス健全性", text)
        self.assertNotIn("NOC 注視点", text)
        self.assertNotIn("アクションボード", text)

    def test_dashboard_index_renders_english_labels_without_japanese_heading_leakage(self) -> None:
        response = self.client.get("/?lang=en")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Content-Language"), "en")
        text = response.get_data(as_text=True)
        self.assertIn("Service Health", text)
        self.assertIn("Core daemons", text)
        self.assertIn("NOC Focus", text)
        self.assertIn("Action Board", text)
        self.assertIn("Uplink and route", text)
        self.assertIn("How should I guide a user who cannot connect to Wi-Fi?", text)
        self.assertNotIn("アップリンクと経路", text)
        self.assertNotIn("NOC 注視点", text)
        self.assertNotIn("アクションボード", text)
        self.assertNotIn("主要デーモン", text)
        self.assertNotIn("Wi-Fi に繋がらない利用者へどう案内するか", text)

    def test_demo_page_renders_replay_and_review_sections(self) -> None:
        response = self.client.get("/demo?lang=en")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("Demo Runner", text)
        self.assertIn("Scenario Replay", text)
        self.assertIn("Run Demo", text)
        self.assertIn("Review Readiness", text)
        self.assertIn("Capability Boundary and Resource Guard", text)
        self.assertIn("Open Latest Explanation", text)
        self.assertNotIn('id="resourceGuardQueue"', text)

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
        with webapp.app.test_request_context("/?lang=en"):
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
                lang="en",
            )
        self.assertIn("Rationale:", text)
        self.assertIn("Continue:", text)


if __name__ == "__main__":
    unittest.main()
