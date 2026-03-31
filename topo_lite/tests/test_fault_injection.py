from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app import create_app
from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging
from notify_engine import dispatch_event_notifications
from scanner.discovery import discover_hosts, parse_arp_scan_output
from scanner.probe_scheduler import ProbeScheduler


class _FailingNotifier:
    def send(self, payload):  # noqa: ANN001
        raise RuntimeError("simulated notification outage")


class FaultInjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "faults.sqlite3")
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.config.notification.enabled = True
        self.config.notification.endpoint = "https://ntfy.local/topic"
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)
        host = self.repository.upsert_host(ip="192.168.40.77", hostname="fault-host", status="up")
        self.event = self.repository.create_event(
            event_type="new_host",
            host_id=int(host["id"]),
            severity="low",
            summary="fault host discovered",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_malformed_scan_output_is_ignored_without_exception(self) -> None:
        results = parse_arp_scan_output(
            "garbage\n192.168.40.bad nope nope\n192.168.40.10 aa:bb:cc:dd:ee:10 Valid Vendor\n",
            subnet="192.168.40.0/24",
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].ip, "192.168.40.10")

    def test_notification_failure_does_not_raise(self) -> None:
        result = dispatch_event_notifications(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            events=[self.event],
            notifier=_FailingNotifier(),
            now_fn=lambda: "2026-03-31T00:30:00Z",
        )
        self.assertEqual(result["failed"], 1)
        self.assertIn("simulated notification outage", self.repository.get_event(int(self.event["id"]))["notification_error"])

    def test_probe_scheduler_tolerates_post_processing_database_lock_error(self) -> None:
        scheduler = ProbeScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.temp_path / "probe_scheduler.lock",
            sleep_fn=lambda _seconds: None,
        )

        with patch("scanner.probe_scheduler.probe_hosts", return_value={"scan_run_id": 99, "status": "completed"}), \
             patch("scanner.probe_scheduler.generate_inventory_diff", side_effect=sqlite3.OperationalError("database is locked")):
            result = scheduler.run_forever(max_runs=1)

        self.assertEqual(result.status, "stopped")
        self.assertEqual(result.failures, 1)
        scanner_lines = (self.temp_path / "scanner.jsonl").read_text(encoding="utf-8").strip().splitlines()
        events = [json.loads(line)["event"] for line in scanner_lines]
        self.assertIn("probe_scheduler_post_processing_failed", events)

    def test_backend_can_restart_and_reuse_existing_database_state(self) -> None:
        config_path = self.temp_path / "config.yaml"
        config_path.write_text(
            "\n".join(
                [
                    "interface: eth0",
                    "subnets:",
                    "  - 192.168.40.0/24",
                    f"database_path: {self.config.database_path}",
                    "logging:",
                    "  level: INFO",
                    f"  app_log_path: {self.temp_path / 'restart-app.jsonl'}",
                    f"  access_log_path: {self.temp_path / 'restart-access.jsonl'}",
                    f"  audit_log_path: {self.temp_path / 'restart-audit.jsonl'}",
                    f"  scanner_log_path: {self.temp_path / 'restart-scanner.jsonl'}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        first = create_app(config_path=config_path)
        second = create_app(config_path=config_path)
        client = second.test_client()
        login = client.post("/api/auth/login", json={"username": "admin", "password": "change-me-admin-password"})
        self.assertEqual(login.status_code, 200)
        detail = client.get(f"/api/hosts/{int(self.event['host_id'])}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.get_json()["hostname"], "fault-host")

    def test_discovery_timeout_returns_failed_result(self) -> None:
        result = discover_hosts(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            runner=lambda command, timeout: (_ for _ in ()).throw(subprocess.TimeoutExpired(command, timeout)),
            arp_cache_reader=lambda: "",
            dhcp_lease_reader=lambda: "",
        )
        self.assertEqual(result["status"], "failed")


if __name__ == "__main__":
    unittest.main()
