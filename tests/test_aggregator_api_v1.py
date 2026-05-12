from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp
from azazel_edge.aggregator import AggregatorRegistry, FreshnessPolicy


class AggregatorApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.auth_tokens_path = root / "auth_tokens.json"
        self.auth_tokens_path.write_text(
            json.dumps(
                {
                    "tokens": [
                        {"token": "viewer-token", "principal": "viewer-1", "role": "viewer"},
                        {"token": "operator-token", "principal": "operator-1", "role": "operator"},
                        {"token": "admin-token", "principal": "admin-1", "role": "admin"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        self._orig = {
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "AUTH_TOKENS_FILE": webapp.AUTH_TOKENS_FILE,
            "AUTHZ_AUDIT_LOG": webapp.AUTHZ_AUDIT_LOG,
            "_AGGREGATOR_REGISTRY": webapp._AGGREGATOR_REGISTRY,
        }
        self.authz_log_path = root / "authz-events.jsonl"
        webapp.AUTH_FAIL_OPEN = False
        webapp.AUTH_TOKENS_FILE = self.auth_tokens_path
        webapp.AUTHZ_AUDIT_LOG = self.authz_log_path
        webapp._AGGREGATOR_REGISTRY = AggregatorRegistry(
            policy=FreshnessPolicy(poll_interval_sec=30, stale_multiplier=2, offline_multiplier=6)
        )
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.AUTH_FAIL_OPEN = self._orig["AUTH_FAIL_OPEN"]
        webapp.AUTH_TOKENS_FILE = self._orig["AUTH_TOKENS_FILE"]
        webapp.AUTHZ_AUDIT_LOG = self._orig["AUTHZ_AUDIT_LOG"]
        webapp._AGGREGATOR_REGISTRY = self._orig["_AGGREGATOR_REGISTRY"]
        self.tmp.cleanup()

    def test_register_requires_admin_role(self) -> None:
        denied = self.client.post(
            "/api/aggregator/nodes/register",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json={"node_id": "az-node-1", "site_id": "hq"},
        )
        self.assertEqual(denied.status_code, 403)
        allowed = self.client.post(
            "/api/aggregator/nodes/register",
            headers={"X-AZAZEL-TOKEN": "admin-token"},
            json={"node_id": "az-node-1", "site_id": "hq"},
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertTrue(allowed.get_json().get("ok"))

    def test_ingest_and_list_nodes(self) -> None:
        ingest = self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json={
                "trace_id": "agg-api-1",
                "node": {"node_id": "az-node-2", "site_id": "branch-a"},
                "timestamps": {"generated_at": time.time()},
                "risk": {"current_level": "watch", "score": 67},
            },
        )
        self.assertEqual(ingest.status_code, 200)
        listed = self.client.get("/api/aggregator/nodes", headers={"X-AZAZEL-TOKEN": "viewer-token"})
        self.assertEqual(listed.status_code, 200)
        payload = listed.get_json()
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("counts", {}).get("fresh"), 1)
        self.assertEqual(len(payload.get("items", [])), 1)

    def test_ingest_rejects_missing_trace_id(self) -> None:
        response = self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json={"node": {"node_id": "az-node-3", "site_id": "branch-b"}, "timestamps": {"generated_at": 100.0}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json().get("error"), "trace_id_required")


if __name__ == "__main__":
    unittest.main()
