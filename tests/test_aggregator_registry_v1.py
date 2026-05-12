from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = PROJECT_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.aggregator import AggregatorRegistry, FreshnessPolicy


class AggregatorRegistryTests(unittest.TestCase):
    def test_register_and_ingest_marks_node_fresh(self) -> None:
        registry = AggregatorRegistry(FreshnessPolicy(poll_interval_sec=30, stale_multiplier=2, offline_multiplier=6))
        registry.register_node("az-node-1", "hq", node_label="HQ Node")
        registry.ingest_summary(
            {
                "trace_id": "agg-1",
                "node": {"node_id": "az-node-1", "site_id": "hq", "node_label": "HQ Node"},
                "timestamps": {"generated_at": 100.0},
                "risk": {"current_level": "watch", "score": 67},
            }
        )
        items = registry.list_nodes(now_epoch=120.0)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["freshness"], "fresh")

    def test_summary_becomes_stale_then_offline(self) -> None:
        registry = AggregatorRegistry(FreshnessPolicy(poll_interval_sec=30, stale_multiplier=2, offline_multiplier=6))
        registry.ingest_summary(
            {
                "trace_id": "agg-2",
                "node": {"node_id": "az-node-2", "site_id": "branch-a"},
                "timestamps": {"generated_at": 100.0},
            }
        )
        self.assertEqual(registry.list_nodes(now_epoch=170.0)[0]["freshness"], "stale")
        self.assertEqual(registry.list_nodes(now_epoch=400.0)[0]["freshness"], "offline")

    def test_older_summary_is_rejected(self) -> None:
        registry = AggregatorRegistry()
        registry.ingest_summary(
            {
                "trace_id": "agg-3a",
                "node": {"node_id": "az-node-3", "site_id": "branch-b"},
                "timestamps": {"generated_at": 200.0},
            }
        )
        with self.assertRaises(ValueError):
            registry.ingest_summary(
                {
                    "trace_id": "agg-3b",
                    "node": {"node_id": "az-node-3", "site_id": "branch-b"},
                    "timestamps": {"generated_at": 150.0},
                }
            )


if __name__ == "__main__":
    unittest.main()
