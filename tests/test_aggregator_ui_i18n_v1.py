from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp
from azazel_edge.aggregator import AggregatorRegistry, FreshnessPolicy
from azazel_edge.i18n import UI_STRINGS


class AggregatorUiI18nV1Tests(unittest.TestCase):
    REQUIRED_KEYS = [
        "dashboard.aggregator_kicker",
        "dashboard.aggregator_title",
        "dashboard.aggregator_note",
        "dashboard.aggregator_fresh",
        "dashboard.aggregator_stale",
        "dashboard.aggregator_offline",
        "dashboard.aggregator_no_nodes",
        "dashboard.aggregator_node_list_label",
        "dashboard.aggregator_last_polled",
        "dashboard.aggregator_quarantined",
    ]

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
        webapp.AUTH_FAIL_OPEN = False
        webapp.AUTH_TOKENS_FILE = self.auth_tokens_path
        webapp.AUTHZ_AUDIT_LOG = root / "authz-events.jsonl"
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

    def test_aggregator_i18n_keys_present_in_ja(self) -> None:
        catalog = UI_STRINGS["ja"]
        for key in self.REQUIRED_KEYS:
            self.assertIn(key, catalog)

    def test_aggregator_i18n_keys_present_in_en(self) -> None:
        catalog = UI_STRINGS["en"]
        for key in self.REQUIRED_KEYS:
            self.assertIn(key, catalog)

    def test_aggregator_nodes_api_returns_counts(self) -> None:
        now = time.time()
        self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json={
                "trace_id": "agg-ui-fresh",
                "node": {"node_id": "az-node-fresh", "site_id": "site-a"},
                "timestamps": {"generated_at": now},
            },
        )
        self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json={
                "trace_id": "agg-ui-stale",
                "node": {"node_id": "az-node-stale", "site_id": "site-b"},
                "timestamps": {"generated_at": now - 70},
            },
        )
        self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json={
                "trace_id": "agg-ui-offline",
                "node": {"node_id": "az-node-offline", "site_id": "site-c"},
                "timestamps": {"generated_at": now - 220},
            },
        )
        listed = self.client.get("/api/aggregator/nodes", headers={"X-AZAZEL-TOKEN": "viewer-token"})
        self.assertEqual(listed.status_code, 200)
        payload = listed.get_json()
        self.assertTrue(payload.get("ok"))
        counts = payload.get("counts", {})
        self.assertIn("fresh", counts)
        self.assertIn("stale", counts)
        self.assertIn("offline", counts)
        self.assertEqual(counts.get("fresh"), 1)
        self.assertEqual(counts.get("stale"), 1)
        self.assertEqual(counts.get("offline"), 1)


if __name__ == "__main__":
    unittest.main()
