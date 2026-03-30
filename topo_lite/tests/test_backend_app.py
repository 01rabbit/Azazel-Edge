from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from backend.app import create_app


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
        self.assertEqual(payload["database"]["host_count"], 0)

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
