from __future__ import annotations

import json
import os
import queue
import tempfile
import unittest
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = REPO_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge_ai import agent
import azazel_edge_epd_mode_refresh as epd_refresh


class Phase5OperationalHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = {
            "ADVISORY_PATH": agent.ADVISORY_PATH,
            "EVENT_LOG_PATH": agent.EVENT_LOG_PATH,
            "SNAPSHOT_PATH": agent.SNAPSHOT_PATH,
            "LLM_DEFERRED_LOG_PATH": agent.LLM_DEFERRED_LOG_PATH,
            "LLM_RESULT_LOG_PATH": agent.LLM_RESULT_LOG_PATH,
            "METRICS_PATH": agent.METRICS_PATH,
            "POLICY_PATH": agent.POLICY_PATH,
            "LLM_ENABLED": agent.LLM_ENABLED,
            "LLM_RETRY_MAX": agent.LLM_RETRY_MAX,
            "LLM_QUEUE_MAX": agent.LLM_QUEUE_MAX,
            "LLM_QUEUE": agent.LLM_QUEUE,
            "METRICS": dict(agent.METRICS),
            "RUNTIME_POLICY": dict(agent.RUNTIME_POLICY),
            "DECISION_LOG": agent.DECISION_LOGGER.log_decision,
            "_LAST_RISK_SCORE": agent._LAST_RISK_SCORE,
            "_LAST_STATE_NAME": agent._LAST_STATE_NAME,
            "CORR_ENABLED": agent.CORR_ENABLED,
            "CORR_WINDOW_SEC": agent.CORR_WINDOW_SEC,
            "CORR_REPEAT_THRESHOLD": agent.CORR_REPEAT_THRESHOLD,
            "CORR_SID_DIVERSITY_THRESHOLD": agent.CORR_SID_DIVERSITY_THRESHOLD,
            "CORR_MIN_RISK_SCORE": agent.CORR_MIN_RISK_SCORE,
            "CORR_MAX_HISTORY_PER_SRC": agent.CORR_MAX_HISTORY_PER_SRC,
            "CORR_STATE": dict(agent.CORR_STATE),
            "EPD_CANDIDATES": epd_refresh.RUNTIME_SNAPSHOT_CANDIDATES,
            "EPD_STATE_PATH": epd_refresh.EPD_STATE,
            "EPD_LAST_RENDER": epd_refresh.EPD_LAST_RENDER,
        }
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        agent.ADVISORY_PATH = root / "ai_advisory.json"
        agent.EVENT_LOG_PATH = root / "ai-events.jsonl"
        agent.SNAPSHOT_PATH = root / "ui_snapshot.json"
        agent.LLM_DEFERRED_LOG_PATH = root / "ai-deferred.jsonl"
        agent.LLM_RESULT_LOG_PATH = root / "ai-llm.jsonl"
        agent.METRICS_PATH = root / "ai_metrics.json"
        agent.POLICY_PATH = root / "ai_policy.json"
        agent.LLM_QUEUE_MAX = 4
        agent.LLM_QUEUE = queue.Queue(maxsize=agent.LLM_QUEUE_MAX)
        metrics_reset = {}
        for key, value in self._orig["METRICS"].items():
            if isinstance(value, bool):
                metrics_reset[key] = False
            elif isinstance(value, int):
                metrics_reset[key] = 0
            elif isinstance(value, float):
                metrics_reset[key] = 0.0
            elif isinstance(value, str):
                metrics_reset[key] = ""
            else:
                metrics_reset[key] = value
        metrics_reset["policy_mode"] = "normal"
        metrics_reset["last_error"] = ""
        metrics_reset["last_update_ts"] = 0.0
        agent.METRICS = metrics_reset
        agent.RUNTIME_POLICY = {"mode": "normal", "updated_at": 0.0, "reason": "test"}
        agent.DECISION_LOGGER.log_decision = lambda _: None
        agent._LAST_RISK_SCORE = 0
        agent._LAST_STATE_NAME = "NORMAL"
        agent.CORR_ENABLED = True
        agent.CORR_WINDOW_SEC = 300
        agent.CORR_REPEAT_THRESHOLD = 4
        agent.CORR_SID_DIVERSITY_THRESHOLD = 3
        agent.CORR_MIN_RISK_SCORE = 20
        agent.CORR_MAX_HISTORY_PER_SRC = 32
        agent.CORR_STATE = {}

    def tearDown(self) -> None:
        agent.ADVISORY_PATH = self._orig["ADVISORY_PATH"]
        agent.EVENT_LOG_PATH = self._orig["EVENT_LOG_PATH"]
        agent.SNAPSHOT_PATH = self._orig["SNAPSHOT_PATH"]
        agent.LLM_DEFERRED_LOG_PATH = self._orig["LLM_DEFERRED_LOG_PATH"]
        agent.LLM_RESULT_LOG_PATH = self._orig["LLM_RESULT_LOG_PATH"]
        agent.METRICS_PATH = self._orig["METRICS_PATH"]
        agent.POLICY_PATH = self._orig["POLICY_PATH"]
        agent.LLM_ENABLED = self._orig["LLM_ENABLED"]
        agent.LLM_RETRY_MAX = self._orig["LLM_RETRY_MAX"]
        agent.LLM_QUEUE_MAX = self._orig["LLM_QUEUE_MAX"]
        agent.LLM_QUEUE = self._orig["LLM_QUEUE"]
        agent.METRICS = self._orig["METRICS"]
        agent.RUNTIME_POLICY = self._orig["RUNTIME_POLICY"]
        agent.DECISION_LOGGER.log_decision = self._orig["DECISION_LOG"]
        agent._LAST_RISK_SCORE = self._orig["_LAST_RISK_SCORE"]
        agent._LAST_STATE_NAME = self._orig["_LAST_STATE_NAME"]
        agent.CORR_ENABLED = self._orig["CORR_ENABLED"]
        agent.CORR_WINDOW_SEC = self._orig["CORR_WINDOW_SEC"]
        agent.CORR_REPEAT_THRESHOLD = self._orig["CORR_REPEAT_THRESHOLD"]
        agent.CORR_SID_DIVERSITY_THRESHOLD = self._orig["CORR_SID_DIVERSITY_THRESHOLD"]
        agent.CORR_MIN_RISK_SCORE = self._orig["CORR_MIN_RISK_SCORE"]
        agent.CORR_MAX_HISTORY_PER_SRC = self._orig["CORR_MAX_HISTORY_PER_SRC"]
        agent.CORR_STATE = self._orig["CORR_STATE"]
        epd_refresh.RUNTIME_SNAPSHOT_CANDIDATES = self._orig["EPD_CANDIDATES"]
        epd_refresh.EPD_STATE = self._orig["EPD_STATE_PATH"]
        epd_refresh.EPD_LAST_RENDER = self._orig["EPD_LAST_RENDER"]
        self.tmp.cleanup()

    def test_suricata_to_snapshot_non_ambiguous_skip(self) -> None:
        agent.LLM_ENABLED = True
        event = {
            "normalized": {
                "sid": 200001,
                "severity": 4,
                "attack_type": "tls heartbeat",
                "category": "misc-activity",
                "action": "allowed",
                "target_port": 8443,
                "protocol": "tcp",
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.1",
            }
        }
        agent._handle_line(json.dumps(event))

        advisory = json.loads(agent.ADVISORY_PATH.read_text(encoding="utf-8"))
        snapshot = json.loads(agent.SNAPSHOT_PATH.read_text(encoding="utf-8"))
        metrics = json.loads(agent.METRICS_PATH.read_text(encoding="utf-8"))

        self.assertEqual(advisory["llm"]["status"], "skipped_non_ambiguous")
        self.assertIn("internal", snapshot)
        self.assertIn("attack", snapshot)
        self.assertEqual(snapshot["attack"]["suricata_sid"], 200001)
        self.assertGreaterEqual(int(snapshot["internal"]["suspicion"]), 0)
        self.assertEqual(int(metrics["processed_events"]), 1)

    def test_llm_failure_uses_fallback_policy(self) -> None:
        orig_ollama_chat = agent._ollama_chat
        agent.LLM_ENABLED = True
        agent.LLM_RETRY_MAX = 1

        def _always_fail(*_args, **_kwargs) -> dict:
            raise TimeoutError("simulated_timeout")

        agent._ollama_chat = _always_fail
        try:
            event = {
                "normalized": {
                    "sid": 200002,
                    "severity": 3,
                    "attack_type": "port scan",
                    "category": "attempted-recon",
                    "action": "allowed",
                    "target_port": 80,
                    "protocol": "tcp",
                    "src_ip": "10.0.0.3",
                    "dst_ip": "10.0.0.1",
                }
            }
            advisory = agent._build_advisory(event)
            default_reco = advisory["recommendation"]
            agent._route_llm(event, advisory)
            task = agent.LLM_QUEUE.get_nowait()
            processed = agent._process_llm_task(task)
            agent.LLM_QUEUE.task_done()

            metrics = json.loads(agent.METRICS_PATH.read_text(encoding="utf-8"))
            self.assertEqual(processed["llm"]["status"], "fallback")
            self.assertEqual(processed["llm"]["policy"], "tactical_only_keep_recommendation")
            self.assertEqual(processed["recommendation"], default_reco)
            self.assertGreaterEqual(int(metrics["llm_failed"]), 1)
            self.assertGreaterEqual(int(metrics["llm_fallback_count"]), 1)
            self.assertGreaterEqual(int(metrics["llm_retried"]), 1)
        finally:
            agent._ollama_chat = orig_ollama_chat

    def test_epd_uses_runtime_snapshot_suspicion(self) -> None:
        runtime_snapshot = Path(self.tmp.name) / "runtime_snapshot.json"
        runtime_snapshot.write_text(
            json.dumps(
                {
                    "ssid": "AzazelNet",
                    "signal_dbm": -58,
                    "internal": {"suspicion": 67},
                    "connection": {"wifi_state": "CONNECTED", "internet_check": "OK"},
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        epd_refresh.RUNTIME_SNAPSHOT_CANDIDATES = (runtime_snapshot,)

        desired = epd_refresh._desired_render_spec({"mode": "shield", "ssid": "-", "upstream_if": "wlan0"})
        self.assertEqual(desired["state"], "normal")
        self.assertEqual(int(desired["suspicion"]), 67)
        self.assertEqual(desired["risk_status"], "SAFE")

    def test_epd_normal_render_spec_keeps_ethernet_uplink(self) -> None:
        runtime_snapshot = Path(self.tmp.name) / "runtime_snapshot_eth.json"
        runtime_snapshot.write_text(
            json.dumps(
                {
                    "ssid": "ETH:eth1",
                    "signal_dbm": -42,
                    "internal": {"suspicion": 12},
                    "connection": {
                        "wifi_state": "N/A(ETH)",
                        "uplink_type": "ethernet",
                        "internet_check": "OK",
                    },
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        epd_refresh.RUNTIME_SNAPSHOT_CANDIDATES = (runtime_snapshot,)

        desired = epd_refresh._desired_render_spec({"mode": "shield", "ssid": "ETH:eth1", "upstream_if": "eth1"})
        self.assertEqual(desired["state"], "normal")
        self.assertEqual(desired["uplink_type"], "ethernet")
        self.assertIsNone(desired["signal"])

    def test_epd_resolve_prefers_edge_script(self) -> None:
        root = Path(self.tmp.name) / "repo"
        py_dir = root / "py"
        py_dir.mkdir(parents=True, exist_ok=True)
        edge_script = py_dir / "azazel_edge_epd.py"
        legacy_script = py_dir / "azazel_epd.py"
        edge_script.write_text("# edge\n", encoding="utf-8")
        legacy_script.write_text("# legacy\n", encoding="utf-8")
        resolved = epd_refresh._resolve_epd_script(root)
        self.assertEqual(resolved, edge_script)

    def test_epd_main_uses_legacy_script_when_edge_missing(self) -> None:
        root = Path(self.tmp.name) / "repo_legacy"
        py_dir = root / "py"
        py_dir.mkdir(parents=True, exist_ok=True)
        legacy_script = py_dir / "azazel_epd.py"
        legacy_script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

        epd_state = Path(self.tmp.name) / "epd_state.json"
        epd_state.write_text(json.dumps({"mode": "failed"}), encoding="utf-8")
        epd_last = Path(self.tmp.name) / "epd_last_render.json"

        epd_refresh.EPD_STATE = epd_state
        epd_refresh.EPD_LAST_RENDER = epd_last

        calls = []
        orig_run = epd_refresh.subprocess.run
        epd_refresh.subprocess.run = lambda cmd, timeout=0, check=False: calls.append(cmd)  # type: ignore[assignment]
        old_root = os.environ.get("AZAZEL_ROOT")
        os.environ["AZAZEL_ROOT"] = str(root)
        try:
            rc = epd_refresh.main()
        finally:
            epd_refresh.subprocess.run = orig_run  # type: ignore[assignment]
            if old_root is None:
                os.environ.pop("AZAZEL_ROOT", None)
            else:
                os.environ["AZAZEL_ROOT"] = old_root
        self.assertEqual(rc, 0)
        self.assertTrue(calls)
        self.assertIn(str(legacy_script), calls[0])

    def test_epd_main_passes_ethernet_uplink_type_for_normal_render(self) -> None:
        root = Path(self.tmp.name) / "repo_normal"
        py_dir = root / "py"
        py_dir.mkdir(parents=True, exist_ok=True)
        edge_script = py_dir / "azazel_edge_epd.py"
        edge_script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

        epd_state = Path(self.tmp.name) / "epd_state_normal.json"
        epd_state.write_text(json.dumps({"mode": "shield", "ssid": "ETH:eth1", "upstream_if": "eth1"}), encoding="utf-8")
        epd_last = Path(self.tmp.name) / "epd_last_render_normal.json"
        runtime_snapshot = Path(self.tmp.name) / "runtime_snapshot_main_eth.json"
        runtime_snapshot.write_text(
            json.dumps(
                {
                    "ssid": "ETH:eth1",
                    "connection": {
                        "wifi_state": "N/A(ETH)",
                        "uplink_type": "ethernet",
                        "internet_check": "OK",
                    },
                    "internal": {"suspicion": 9},
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        epd_refresh.EPD_STATE = epd_state
        epd_refresh.EPD_LAST_RENDER = epd_last
        epd_refresh.RUNTIME_SNAPSHOT_CANDIDATES = (runtime_snapshot,)

        calls = []
        orig_run = epd_refresh.subprocess.run
        epd_refresh.subprocess.run = lambda cmd, timeout=0, check=False: calls.append(cmd)  # type: ignore[assignment]
        old_root = os.environ.get("AZAZEL_ROOT")
        os.environ["AZAZEL_ROOT"] = str(root)
        try:
            rc = epd_refresh.main()
        finally:
            epd_refresh.subprocess.run = orig_run  # type: ignore[assignment]
            if old_root is None:
                os.environ.pop("AZAZEL_ROOT", None)
            else:
                os.environ["AZAZEL_ROOT"] = old_root
        self.assertEqual(rc, 0)
        self.assertTrue(calls)
        self.assertIn("--uplink-type", calls[0])
        self.assertIn("ethernet", calls[0])


    def test_correlation_escalation_routes_low_risk_event_to_llm(self) -> None:
        agent.LLM_ENABLED = True
        agent.CORR_REPEAT_THRESHOLD = 2
        base = {
            "severity": 4,
            "attack_type": "tls heartbeat",
            "category": "misc-activity",
            "action": "allowed",
            "target_port": 8443,
            "protocol": "tcp",
            "src_ip": "10.20.0.8",
            "dst_ip": "10.0.0.1",
        }
        first = {"normalized": dict(base, sid=210001)}
        second = {"normalized": dict(base, sid=210002)}
        agent._handle_line(json.dumps(first))
        agent._handle_line(json.dumps(second))

        advisory = json.loads(agent.ADVISORY_PATH.read_text(encoding="utf-8"))
        metrics = json.loads(agent.METRICS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(advisory["llm"]["status"], "queued")
        self.assertEqual(advisory["llm"]["reason"], "correlation_escalation")
        self.assertTrue(advisory.get("correlation", {}).get("force_llm"))
        self.assertGreaterEqual(int(metrics.get("correlation_escalations", 0)), 1)
        self.assertGreaterEqual(int(metrics.get("llm_requests", 0)), 1)

    def test_invalid_analyst_schema_falls_back(self) -> None:
        orig_ollama_chat = agent._ollama_chat
        agent.LLM_ENABLED = True
        agent.LLM_RETRY_MAX = 0

        def _bad_schema(*_args, **_kwargs) -> dict:
            return {
                "verdict": "permit",
                "confidence": "high",
                "reason": "",
                "suggested_action": "",
                "escalation": "maybe",
            }

        agent._ollama_chat = _bad_schema
        try:
            event = {
                "normalized": {
                    "sid": 220001,
                    "severity": 3,
                    "attack_type": "port scan",
                    "category": "attempted-recon",
                    "action": "allowed",
                    "target_port": 80,
                    "protocol": "tcp",
                    "src_ip": "10.30.0.3",
                    "dst_ip": "10.0.0.1",
                }
            }
            advisory = agent._build_advisory(event)
            agent._route_llm(event, advisory)
            task = agent.LLM_QUEUE.get_nowait()
            processed = agent._process_llm_task(task)
            agent.LLM_QUEUE.task_done()
            metrics = json.loads(agent.METRICS_PATH.read_text(encoding="utf-8"))
            self.assertEqual(processed["llm"]["status"], "fallback")
            self.assertIn("analyst_", processed["llm"]["reason"])
            self.assertGreaterEqual(int(metrics.get("llm_schema_invalid_count", 0)), 1)
        finally:
            agent._ollama_chat = orig_ollama_chat


if __name__ == "__main__":
    unittest.main()
