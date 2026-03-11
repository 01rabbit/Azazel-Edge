from __future__ import annotations

import tempfile
import unittest

import azazel_edge_web.app as webapp
from azazel_edge.triage import TriageFlowEngine, TriageSessionStore


class TriageApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._orig = {
            "load_token": webapp.load_token,
            "_TRIAGE_STORE": webapp._TRIAGE_STORE,
            "_TRIAGE_ENGINE": webapp._TRIAGE_ENGINE,
        }
        webapp.load_token = lambda: None
        store = TriageSessionStore(base_dir=self.tmp.name)
        webapp._TRIAGE_STORE = store
        webapp._TRIAGE_ENGINE = TriageFlowEngine(store=store)
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.load_token = self._orig["load_token"]
        webapp._TRIAGE_STORE = self._orig["_TRIAGE_STORE"]
        webapp._TRIAGE_ENGINE = self._orig["_TRIAGE_ENGINE"]
        self.tmp.cleanup()

    def test_triage_intents_endpoint(self) -> None:
        response = self.client.get("/api/triage/intents?lang=en")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        intent_ids = {item["intent_id"] for item in payload["items"]}
        self.assertIn("wifi_connectivity", intent_ids)
        self.assertIn("dns_resolution", intent_ids)

    def test_triage_classify_endpoint(self) -> None:
        response = self.client.post("/api/triage/classify?lang=en", json={"text": "Users cannot reconnect to Wi-Fi"})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertGreaterEqual(len(payload["items"]), 1)
        intent_ids = [item["intent_id"] for item in payload["items"]]
        self.assertIn("wifi_reconnect", intent_ids)

    def test_triage_flow_reaches_diagnostic_with_runbooks(self) -> None:
        start = self.client.post("/api/triage/start?lang=en", json={"intent_id": "dns_resolution", "audience": "temporary"})
        self.assertEqual(start.status_code, 200)
        start_payload = start.get_json()
        self.assertTrue(start_payload["ok"])
        session_id = start_payload["session"]["session_id"]
        self.assertEqual(start_payload["next_step"]["step_id"], "internet_vs_name")
        self.assertIn("mio", start_payload)
        self.assertTrue(start_payload["mio"]["preface"])

        answer1 = self.client.post("/api/triage/answer?lang=en", json={"session_id": session_id, "answer": "yes"})
        self.assertEqual(answer1.status_code, 200)
        payload1 = answer1.get_json()
        self.assertEqual(payload1["next_step"]["step_id"], "resolver_scope")

        answer2 = self.client.post("/api/triage/answer?lang=en", json={"session_id": session_id, "answer": "many"})
        self.assertEqual(answer2.status_code, 200)
        payload2 = answer2.get_json()
        self.assertTrue(payload2["completed"])
        self.assertEqual(payload2["diagnostic_state"]["state_id"], "dns_global_failure")
        self.assertIn("runbooks", payload2)
        self.assertTrue(payload2["mio"]["summary"])
        runbook_ids = [item["runbook_id"] for item in payload2["runbooks"]]
        self.assertIn("rb.noc.dns.failure.check", runbook_ids)


if __name__ == "__main__":
    unittest.main()
