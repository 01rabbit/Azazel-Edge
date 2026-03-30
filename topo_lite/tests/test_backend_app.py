from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from backend.app import create_app
from db.repository import TopoLiteRepository


class BackendAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.logs_dir = Path(self.temp_dir.name) / "logs"
        self.config_path.write_text(
            "\n".join(
                [
                    "interface: eth0",
                    "subnets:",
                    "  - 192.168.40.0/24",
                    f"database_path: {self.database_path}",
                    "logging:",
                    "  level: INFO",
                    f"  app_log_path: {self.logs_dir / 'app.jsonl'}",
                    f"  access_log_path: {self.logs_dir / 'access.jsonl'}",
                    f"  audit_log_path: {self.logs_dir / 'audit.jsonl'}",
                    f"  scanner_log_path: {self.logs_dir / 'scanner.jsonl'}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.app = create_app(config_path=self.config_path)
        self.client = self.app.test_client()
        self.repository = TopoLiteRepository(self.database_path)

        self.host_one = self.repository.upsert_host(
            ip="192.168.40.10",
            mac="aa:bb:cc:dd:ee:10",
            vendor="Printer Vendor",
            hostname="printer-1",
            status="up",
        )
        self.host_two = self.repository.upsert_host(
            ip="192.168.40.20",
            mac="aa:bb:cc:dd:ee:20",
            vendor="Laptop Vendor",
            hostname="laptop-1",
            status="up",
        )
        self.repository.upsert_service(host_id=self.host_one["id"], proto="tcp", port=9100, state="open")
        self.repository.upsert_service(host_id=self.host_two["id"], proto="tcp", port=22, state="open")
        self.repository.record_observation(
            host_id=self.host_one["id"],
            source="arp-scan",
            payload={"ip": "192.168.40.10"},
        )
        self.repository.create_event(
            event_type="new_host",
            host_id=self.host_one["id"],
            summary="new printer found",
        )
        self.repository.create_scan_run(scan_kind="arp_discovery", status="completed", details={"host_count": 2})
        self.repository.set_classification(
            host_id=self.host_one["id"],
            label="printer",
            confidence=0.95,
            reason={"ports": [9100]},
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_health_endpoint(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["ok"], True)
        self.assertIn("log_paths", response.get_json())

    def test_meta_endpoint_lists_workspace_directories(self) -> None:
        response = self.client.get("/api/meta")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["project"], "Azazel-Topo-Lite")
        self.assertIn("backend", payload["directories"])
        self.assertIn("scanner", payload["directories"])
        self.assertEqual(payload["database"]["host_count"], 2)

    def test_hosts_endpoint_supports_filter_sort_and_pagination(self) -> None:
        response = self.client.get("/api/hosts?page=1&page_size=1&role=printer&sort=last_seen&order=desc")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["total"], 1)
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["hostname"], "printer-1")
        self.assertEqual(payload["items"][0]["role"], "printer")

    def test_host_detail_endpoint_returns_joined_data(self) -> None:
        response = self.client.get(f"/api/hosts/{self.host_one['id']}")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["hostname"], "printer-1")
        self.assertEqual(payload["classification"]["label"], "printer")
        self.assertEqual(len(payload["services"]), 1)
        self.assertEqual(len(payload["events"]), 1)
        self.assertEqual(len(payload["observations"]), 1)

    def test_services_events_scan_runs_and_topology_endpoints(self) -> None:
        services = self.client.get("/api/services?host_id=1").get_json()
        events = self.client.get("/api/events?event_type=new_host").get_json()
        scan_runs = self.client.get("/api/scan-runs?scan_kind=arp_discovery").get_json()
        topology = self.client.get("/api/topology").get_json()

        self.assertEqual(services["total"], 1)
        self.assertEqual(events["total"], 1)
        self.assertEqual(scan_runs["total"], 1)
        self.assertTrue(any(node["type"] == "subnet" for node in topology["nodes"]))
        self.assertTrue(any(edge["type"] == "belongs_to" for edge in topology["edges"]))

    def test_create_override_endpoint_persists_record(self) -> None:
        response = self.client.post(
            "/api/overrides",
            json={
                "host_id": self.host_one["id"],
                "fixed_label": "trusted-printer",
                "ignored": False,
                "note": "known device",
            },
        )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertEqual(payload["host_id"], self.host_one["id"])
        self.assertEqual(payload["fixed_label"], "trusted-printer")

    def test_api_errors_return_json(self) -> None:
        not_found = self.client.get("/api/hosts/999999")
        invalid = self.client.get("/api/hosts?sort=unknown")

        self.assertEqual(not_found.status_code, 404)
        self.assertEqual(not_found.get_json()["error"], "not_found")
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.get_json()["error"], "bad_request")

    def test_access_and_audit_logs_are_written_as_jsonl(self) -> None:
        self.client.get("/api/meta")

        access_lines = (self.logs_dir / "access.jsonl").read_text(encoding="utf-8").strip().splitlines()
        audit_lines = (self.logs_dir / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()

        access_entry = json.loads(access_lines[-1])
        audit_entry = json.loads(audit_lines[-1])

        self.assertEqual(access_entry["event"], "http_request")
        self.assertEqual(access_entry["path"], "/api/meta")
        self.assertEqual(audit_entry["event"], "backend_startup")
        self.assertEqual(audit_entry["actor"], "system")


if __name__ == "__main__":
    unittest.main()
