"""Edge#343: the runtime ``disk_percent`` reading and the optional fleet ``role``.

Both are read/display additions. ``disk_percent`` is ``None`` whenever it was
not read -- never 0 and never an estimate. ``role`` is optional on node
registration and, until its vocabulary is decided, refused when given.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import azazel_edge.aggregator as aggregator
import azazel_edge_web.app as webapp
from azazel_edge.aggregator import AggregatorRegistry, FreshnessPolicy, normalize_node_role
from azazel_edge.snapshot_model import build_snapshot
from azazel_edge_control import daemon as control_daemon


def _statvfs(blocks: int, bfree: int, bavail: int, frsize: int = 4096) -> os.statvfs_result:
    # f_bsize, f_frsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree, f_favail, f_flag, f_namemax
    return os.statvfs_result((frsize, frsize, blocks, bfree, bavail, 0, 0, 0, 0, 255))


class DiskPercentReaderTests(unittest.TestCase):
    def test_reads_root_filesystem_by_default(self) -> None:
        self.assertEqual(control_daemon.DISK_USAGE_PATH, "/")
        seen = []

        def fake(path):
            seen.append(path)
            return _statvfs(blocks=1000, bfree=400, bavail=350)

        with patch.object(control_daemon.os, "statvfs", side_effect=fake):
            value = control_daemon._read_disk_percent()
        self.assertEqual(seen, ["/"])
        # df's Use%: used / (used + available) = 600 / 950, root reserve excluded.
        self.assertEqual(value, round(600 * 100.0 / 950, 1))

    def test_value_present_on_a_real_filesystem(self) -> None:
        value = control_daemon._read_disk_percent()
        self.assertIsInstance(value, float)
        self.assertGreaterEqual(value, 0.0)
        self.assertLessEqual(value, 100.0)

    def test_read_failure_is_none_not_zero(self) -> None:
        with patch.object(control_daemon.os, "statvfs", side_effect=OSError(5, "EIO")):
            self.assertIsNone(control_daemon._read_disk_percent())

    def test_missing_path_is_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(control_daemon._read_disk_percent(str(Path(tmp) / "absent")))

    def test_filesystem_without_blocks_is_none(self) -> None:
        with patch.object(control_daemon.os, "statvfs", return_value=_statvfs(blocks=0, bfree=0, bavail=0)):
            self.assertIsNone(control_daemon._read_disk_percent())

    def _enrich(self, disk_value):
        with patch.object(control_daemon, "_default_route_info", return_value={"up_if": "eth1", "up_ip": "-", "gateway_ip": "-", "uplink_type": "ethernet"}), \
             patch.object(control_daemon, "_read_cpu_usage_percent", return_value=12.3), \
             patch.object(control_daemon, "_read_mem_usage", return_value=(30, 100, 512)), \
             patch.object(control_daemon, "_read_temp_c", return_value=45.2), \
             patch.object(control_daemon, "_read_disk_percent", return_value=disk_value), \
             patch.object(control_daemon, "_read_signal_dbm", return_value=None), \
             patch.object(control_daemon.NETWORK_HEALTH, "assess", return_value={"status": "SAFE", "signals": [], "internet_check": "PASS", "captive_portal": "NO", "captive_portal_reason": "NOT_CAPTIVE"}), \
             patch.object(control_daemon, "_compute_live_noc_projection", return_value={}):
            return control_daemon._enrich_snapshot({"user_state": "SAFE", "internal": {"state_name": "NORMAL", "suspicion": 0}})

    def test_enriched_snapshot_carries_the_reading(self) -> None:
        self.assertEqual(self._enrich(63.2)["disk_percent"], 63.2)

    def test_enriched_snapshot_carries_none_on_failure(self) -> None:
        enriched = self._enrich(None)
        self.assertIn("disk_percent", enriched)
        self.assertIsNone(enriched["disk_percent"])


class SnapshotModelDiskTests(unittest.TestCase):
    def test_value_present(self) -> None:
        self.assertEqual(build_snapshot({"disk_percent": 42.5}).disk_percent, 42.5)

    def test_value_absent_is_none(self) -> None:
        self.assertIsNone(build_snapshot({}).disk_percent)

    def test_unusable_values_are_none(self) -> None:
        for bad in (None, "", "n/a", True, float("nan"), -1, 100.1, [], {}):
            with self.subTest(value=bad):
                self.assertIsNone(build_snapshot({"disk_percent": bad}).disk_percent)

    def test_existing_fields_unchanged(self) -> None:
        snap = build_snapshot({"cpu_percent": 5.0, "temp_c": 40.0})
        self.assertEqual(snap.cpu_percent, 5.0)
        self.assertEqual(snap.temp_c, 40.0)


class TrendPointDiskTests(unittest.TestCase):
    def test_value_present(self) -> None:
        point = webapp._dashboard_trend_point_payload({"disk_percent": 37.0}, {}, {}, now_epoch=1.0)
        self.assertEqual(point["disk_percent"], 37.0)

    def test_value_absent_is_none(self) -> None:
        point = webapp._dashboard_trend_point_payload({}, {}, {}, now_epoch=1.0)
        self.assertIsNone(point["disk_percent"])

    def test_failed_read_is_none(self) -> None:
        for bad in (None, "garbage", False, 250):
            with self.subTest(value=bad):
                point = webapp._dashboard_trend_point_payload({"disk_percent": bad}, {}, {}, now_epoch=1.0)
                self.assertIsNone(point["disk_percent"])


class NodeRoleRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = AggregatorRegistry()

    def test_vocabulary_is_not_decided_yet(self) -> None:
        self.assertEqual(aggregator.NODE_ROLES, frozenset())

    def test_register_without_role_still_works(self) -> None:
        node = self.registry.register_node("az-node-1", "hq", node_label="peer")
        self.assertIsNone(node["role"])
        self.assertEqual(node["status"], "active")
        self.assertEqual(node["node_label"], "peer")

    def test_blank_role_is_absent(self) -> None:
        self.assertIsNone(self.registry.register_node("az-node-1", "hq", role="  ")["role"])

    def test_role_outside_the_vocabulary_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "role_unknown"):
            self.registry.register_node("az-node-1", "hq", role="sensor")
        self.assertEqual(self.registry.list_nodes(), [])

    def test_non_string_role_is_refused(self) -> None:
        for bad in (1, True, ["sensor"], {"r": 1}):
            with self.subTest(value=bad):
                with self.assertRaisesRegex(ValueError, "role_must_be_string"):
                    normalize_node_role(bad)

    def test_role_in_the_vocabulary_is_recorded_and_listed(self) -> None:
        with patch.object(aggregator, "NODE_ROLES", frozenset({"sensor"})):
            node = self.registry.register_node("az-node-1", "hq", role=" sensor ")
        self.assertEqual(node["role"], "sensor")
        listed = self.registry.list_nodes()
        self.assertEqual([row["role"] for row in listed], ["sensor"])

    def test_ingest_only_node_has_no_role(self) -> None:
        self.registry.ingest_summary(
            {
                "trace_id": "t-1",
                "node": {"node_id": "az-node-2", "site_id": "branch"},
                "timestamps": {"generated_at": time.time()},
            }
        )
        self.assertIsNone(self.registry.list_nodes()[0]["role"])


class NodeRoleApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        tokens = root / "auth_tokens.json"
        tokens.write_text(
            json.dumps({"tokens": [{"token": "admin-token", "principal": "admin-1", "role": "admin"}]}),
            encoding="utf-8",
        )
        self._orig = {
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "AUTH_TOKENS_FILE": webapp.AUTH_TOKENS_FILE,
            "AUTHZ_AUDIT_LOG": webapp.AUTHZ_AUDIT_LOG,
            "AGGREGATOR_AUDIT_LOG": getattr(webapp, "AGGREGATOR_AUDIT_LOG", None),
            "_AGGREGATOR_REGISTRY": webapp._AGGREGATOR_REGISTRY,
        }
        webapp.AUTH_FAIL_OPEN = False
        webapp.AUTH_TOKENS_FILE = tokens
        webapp.AUTHZ_AUDIT_LOG = root / "authz-events.jsonl"
        if self._orig["AGGREGATOR_AUDIT_LOG"] is not None:
            webapp.AGGREGATOR_AUDIT_LOG = root / "aggregator-events.jsonl"
        webapp._AGGREGATOR_REGISTRY = AggregatorRegistry(policy=FreshnessPolicy())
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        for key, value in self._orig.items():
            if key == "AGGREGATOR_AUDIT_LOG" and value is None:
                continue
            setattr(webapp, key, value)
        self.tmp.cleanup()

    def _register(self, body):
        return self.client.post(
            "/api/aggregator/nodes/register",
            headers={"X-AZAZEL-TOKEN": "admin-token"},
            json=body,
        )

    def test_register_without_role(self) -> None:
        resp = self._register({"node_id": "az-node-1", "site_id": "hq"})
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.get_json()["node"]["role"])

    def test_register_with_undecided_role_is_refused(self) -> None:
        resp = self._register({"node_id": "az-node-1", "site_id": "hq", "role": "sensor"})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "role_unknown")

    def test_register_with_role_in_vocabulary(self) -> None:
        with patch.object(aggregator, "NODE_ROLES", frozenset({"sensor"})):
            resp = self._register({"node_id": "az-node-1", "site_id": "hq", "role": "sensor"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["node"]["role"], "sensor")


if __name__ == "__main__":
    unittest.main()
