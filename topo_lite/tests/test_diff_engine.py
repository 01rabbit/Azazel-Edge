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
        severities = {event["event_type"]: event["severity"] for event in result["events"]}
        self.assertEqual(severities["new_host"], "medium")
        self.assertEqual(severities["service_added"], "medium")

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

    def test_gateway_like_changes_raise_high_severity(self) -> None:
        gateway = self.repository.upsert_host(ip="192.168.40.1", hostname="gateway-main")
        self.repository.set_classification(
            host_id=gateway["id"],
            label="network_device",
            confidence=0.95,
            reason={"hostname": "gateway-main"},
        )
        self._write_discovery_snapshot(
            [{"host_id": gateway["id"], "ip": gateway["ip"], "mac": "aa:bb:cc:dd:ee:01", "vendor": "Gateway", "subnet": "192.168.40.0/24"}]
        )
        self._write_probe_snapshot(
            [{"host_id": gateway["id"], "ip": gateway["ip"], "proto": "tcp", "port": 443, "state": "open", "source": "tcp-connect-probe"}]
        )
        generate_inventory_diff(self.repository, missing_threshold_runs=1)

        self._write_discovery_snapshot([])
        self._write_probe_snapshot([])
        result = generate_inventory_diff(self.repository, missing_threshold_runs=1)

        host_missing = next(event for event in result["events"] if event["event_type"] == "host_missing")
        self.assertEqual(host_missing["severity"], "high")

    def test_same_mac_different_ip_new_host_is_high_severity(self) -> None:
        first = self.repository.upsert_host(ip="192.168.40.50", mac="aa:bb:cc:dd:ee:50", hostname="device-a")
        self._write_discovery_snapshot(
            [{"host_id": first["id"], "ip": first["ip"], "mac": first["mac"], "vendor": "Vendor", "subnet": "192.168.40.0/24"}]
        )
        self._write_probe_snapshot([])
        generate_inventory_diff(self.repository)

        second = self.repository.upsert_host(ip="192.168.40.51", mac="aa:bb:cc:dd:ee:50", hostname="device-a")
        self._write_discovery_snapshot(
            [{"host_id": second["id"], "ip": second["ip"], "mac": second["mac"], "vendor": "Vendor", "subnet": "192.168.40.0/24"}]
        )
        self._write_probe_snapshot([])
        result = generate_inventory_diff(self.repository)

        new_host = next(event for event in result["events"] if event["event_type"] == "new_host")
        self.assertEqual(new_host["severity"], "high")

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
