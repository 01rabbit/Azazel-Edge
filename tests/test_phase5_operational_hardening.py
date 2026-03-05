from __future__ import annotations

import json
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
            "RUNTIME_POLICY": dict(agent.RUNTIME_POLICY),
            "DECISION_LOG": agent.DECISION_LOGGER.log_decision,
            "_LAST_RISK_SCORE": agent._LAST_RISK_SCORE,
            "_LAST_STATE_NAME": agent._LAST_STATE_NAME,
            "EPD_CANDIDATES": epd_refresh.RUNTIME_SNAPSHOT_CANDIDATES,
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
        agent.RUNTIME_POLICY = {"mode": "normal", "updated_at": 0.0, "reason": "test"}
        agent.DECISION_LOGGER.log_decision = lambda _: None
        agent._LAST_RISK_SCORE = 0
        agent._LAST_STATE_NAME = "NORMAL"

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
        agent.RUNTIME_POLICY = self._orig["RUNTIME_POLICY"]
        agent.DECISION_LOGGER.log_decision = self._orig["DECISION_LOG"]
        agent._LAST_RISK_SCORE = self._orig["_LAST_RISK_SCORE"]
        agent._LAST_STATE_NAME = self._orig["_LAST_STATE_NAME"]
        epd_refresh.RUNTIME_SNAPSHOT_CANDIDATES = self._orig["EPD_CANDIDATES"]
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


if __name__ == "__main__":
    unittest.main()
