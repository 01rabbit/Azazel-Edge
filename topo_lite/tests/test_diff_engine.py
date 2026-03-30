from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from db.repository import TopoLiteRepository
from diff_engine import generate_inventory_diff


class DiffEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "diff.sqlite3"
        self.repository = TopoLiteRepository(self.database_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_first_snapshot_creates_baseline_without_events(self) -> None:
        host = self.repository.upsert_host(ip="192.168.40.10", hostname="printer")
        self._write_discovery_snapshot(
            [{"host_id": host["id"], "ip": host["ip"], "mac": "aa:bb:cc:dd:ee:10", "vendor": "Acme", "subnet": "192.168.40.0/24"}]
        )
        self._write_probe_snapshot(
            [{"host_id": host["id"], "ip": host["ip"], "proto": "tcp", "port": 9100, "state": "open", "source": "tcp-connect-probe"}]
        )

        result = generate_inventory_diff(self.repository)

        self.assertTrue(result["baseline_created"])
        self.assertEqual(result["event_count"], 0)
        snapshot_run = self.repository.get_latest_scan_run("inventory_snapshot", statuses=("completed",))
        snapshot = json.loads(snapshot_run["details_json"])
        self.assertEqual(len(snapshot["hosts"]), 1)

    def test_second_snapshot_emits_new_host_and_service_events(self) -> None:
        host_one = self.repository.upsert_host(ip="192.168.40.10", hostname="printer")
        self._write_discovery_snapshot(
            [{"host_id": host_one["id"], "ip": host_one["ip"], "mac": "aa:bb:cc:dd:ee:10", "vendor": "Acme", "subnet": "192.168.40.0/24"}]
        )
        self._write_probe_snapshot(
            [{"host_id": host_one["id"], "ip": host_one["ip"], "proto": "tcp", "port": 9100, "state": "open", "source": "tcp-connect-probe"}]
        )
        generate_inventory_diff(self.repository)

        host_two = self.repository.upsert_host(ip="192.168.40.20", hostname="laptop")
        self._write_discovery_snapshot(
            [
                {"host_id": host_one["id"], "ip": host_one["ip"], "mac": "aa:bb:cc:dd:ee:10", "vendor": "Acme", "subnet": "192.168.40.0/24"},
                {"host_id": host_two["id"], "ip": host_two["ip"], "mac": "aa:bb:cc:dd:ee:20", "vendor": "Example", "subnet": "192.168.40.0/24"},
            ]
        )
        self._write_probe_snapshot(
            [
                {"host_id": host_one["id"], "ip": host_one["ip"], "proto": "tcp", "port": 9100, "state": "open", "source": "tcp-connect-probe"},
                {"host_id": host_two["id"], "ip": host_two["ip"], "proto": "tcp", "port": 22, "state": "open", "source": "tcp-connect-probe"},
            ]
        )

        result = generate_inventory_diff(self.repository)

        event_types = [event["event_type"] for event in result["events"]]
        self.assertEqual(result["event_count"], 2)
        self.assertIn("new_host", event_types)
        self.assertIn("service_added", event_types)

    def test_hostname_service_and_missing_events_respect_threshold(self) -> None:
        host = self.repository.upsert_host(ip="192.168.40.30", hostname="old-name")
        self._write_discovery_snapshot(
            [{"host_id": host["id"], "ip": host["ip"], "mac": "aa:bb:cc:dd:ee:30", "vendor": "Acme", "subnet": "192.168.40.0/24"}]
        )
        self._write_probe_snapshot(
            [{"host_id": host["id"], "ip": host["ip"], "proto": "tcp", "port": 80, "state": "open", "source": "tcp-connect-probe"}]
        )
        generate_inventory_diff(self.repository, missing_threshold_runs=2)

        self.repository.upsert_host(ip="192.168.40.30", hostname="new-name")
        self._write_discovery_snapshot(
            [{"host_id": host["id"], "ip": host["ip"], "mac": "aa:bb:cc:dd:ee:30", "vendor": "Acme", "subnet": "192.168.40.0/24"}]
        )
        self._write_probe_snapshot([])
        result = generate_inventory_diff(self.repository, missing_threshold_runs=2)
        event_types = [event["event_type"] for event in result["events"]]
        self.assertIn("hostname_changed", event_types)
        self.assertIn("service_removed", event_types)
        self.assertNotIn("host_missing", event_types)

        self._write_discovery_snapshot([])
        self._write_probe_snapshot([])
        first_missing = generate_inventory_diff(self.repository, missing_threshold_runs=2)
        self.assertNotIn("host_missing", [event["event_type"] for event in first_missing["events"]])

        self._write_discovery_snapshot([])
        self._write_probe_snapshot([])
        second_missing = generate_inventory_diff(self.repository, missing_threshold_runs=2)
        self.assertIn("host_missing", [event["event_type"] for event in second_missing["events"]])

    def _write_discovery_snapshot(self, discovered_hosts: list[dict[str, object]]) -> None:
        run = self.repository.create_scan_run(scan_kind="arp_discovery")
        self.repository.finish_scan_run(
            run["id"],
            status="completed",
            details={
                "interface": "eth0",
                "subnets": ["192.168.40.0/24"],
                "source": "arp-scan",
                "host_count": len(discovered_hosts),
                "observation_count": len(discovered_hosts),
                "discovered_hosts": discovered_hosts,
                "errors": [],
            },
        )

    def _write_probe_snapshot(self, services: list[dict[str, object]]) -> None:
        run = self.repository.create_scan_run(scan_kind="service_probe")
        self.repository.finish_scan_run(
            run["id"],
            status="completed",
            details={
                "target_ports": [22, 80, 443],
                "timeout_seconds": 2,
                "concurrency": 8,
                "service_count": len(services),
                "services": services,
                "errors": [],
            },
        )


if __name__ == "__main__":
    unittest.main()
