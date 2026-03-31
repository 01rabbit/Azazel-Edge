from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.app import create_app
from db.repository import TopoLiteRepository


class QualityScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.database_path = self.temp_path / "quality.sqlite3"
        self.logs_dir = self.temp_path / "logs"
        self.config_path = self.temp_path / "config.yaml"
        self.config_path.write_text(
            "\n".join(
                [
                    "interface: br0",
                    "subnets:",
                    "  - 172.16.0.0/24",
                    f"database_path: {self.database_path}",
                    "logging:",
                    "  level: INFO",
                    f"  app_log_path: {self.logs_dir / 'app.jsonl'}",
                    f"  access_log_path: {self.logs_dir / 'access.jsonl'}",
                    f"  audit_log_path: {self.logs_dir / 'audit.jsonl'}",
                    f"  scanner_log_path: {self.logs_dir / 'scanner.jsonl'}",
                    "auth:",
                    "  enabled: true",
                    "  mode: local",
                    "  token_required: true",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.app = create_app(config_path=self.config_path)
        self.client = self.app.test_client()
        self.repository = TopoLiteRepository(self.database_path)
        for index in range(1, 101):
            host = self.repository.upsert_host(
                ip=f"192.168.40.{index}",
                mac=f"aa:bb:cc:dd:ee:{index:02x}",
                hostname=f"host-{index}",
                vendor="Lab Vendor",
                status="up",
            )
            role = "printer" if index % 10 == 0 else "laptop"
            self.repository.set_classification(
                host_id=int(host["id"]),
                label=role,
                confidence=0.9,
                reason={"seed": index},
            )
            self.repository.upsert_service(host_id=int(host["id"]), proto="tcp", port=22, state="open")
            self.repository.create_event(
                event_type="new_host",
                host_id=int(host["id"]),
                severity="high" if index % 15 == 0 else "low",
                summary=f"host-{index} event",
            )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _login(self) -> None:
        response = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "change-me-admin-password"},
        )
        self.assertEqual(response.status_code, 200)

    def test_large_dataset_inventory_topology_and_events_endpoints(self) -> None:
        self._login()

        inventory_page_one = self.client.get("/api/hosts?page=1&page_size=50&sort=last_seen&order=desc").get_json()
        inventory_page_two = self.client.get("/api/hosts?page=2&page_size=50&sort=last_seen&order=desc").get_json()
        topology = self.client.get("/api/topology").get_json()
        events = self.client.get("/api/events?page=1&page_size=100").get_json()

        self.assertEqual(inventory_page_one["total"], 100)
        self.assertEqual(len(inventory_page_one["items"]), 50)
        self.assertEqual(len(inventory_page_two["items"]), 50)
        self.assertGreaterEqual(len(topology["nodes"]), 201)
        self.assertEqual(events["total"], 100)
        self.assertTrue(any(item["severity"] == "high" for item in events["items"]))


if __name__ == "__main__":
    unittest.main()
