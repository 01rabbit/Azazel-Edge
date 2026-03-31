from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging
from scanner.probe_scheduler import ProbeScheduler, ProbeSchedulerLockError


class ProbeSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "probe-scheduler.sqlite3")
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.config.scan_intervals.probe_seconds = 1
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)
        self.lock_path = self.temp_path / "probe_scheduler.lock"
        self.sleep_calls: list[float] = []

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_probe_scheduler_runs_once_and_stops(self) -> None:
        scheduler = ProbeScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )

        with patch("scanner.probe_scheduler.probe_hosts", return_value={"scan_run_id": 51, "status": "completed"}):
            result = scheduler.run_forever(max_runs=1)

        self.assertEqual(result.status, "stopped")
        self.assertEqual(result.runs_completed, 1)
        self.assertEqual(result.last_scan_run_id, 51)
        self.assertEqual(self.sleep_calls, [])

    def test_probe_scheduler_lock_prevents_second_instance(self) -> None:
        scheduler_one = ProbeScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )
        scheduler_two = ProbeScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )

        scheduler_one._acquire_lock()
        try:
            with self.assertRaises(ProbeSchedulerLockError):
                scheduler_two._acquire_lock()
        finally:
            scheduler_one._release_lock()

    def test_probe_scheduler_writes_audit_log(self) -> None:
        scheduler = ProbeScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )

        with patch("scanner.probe_scheduler.probe_hosts", return_value={"scan_run_id": 61, "status": "completed"}):
            scheduler.run_forever(max_runs=1)

        audit_lines = Path(self.config.logging.audit_log_path).read_text(encoding="utf-8").strip().splitlines()
        events = [json.loads(line)["event"] for line in audit_lines]
        self.assertIn("probe_scheduler_started", events)
        self.assertIn("probe_scheduler_stopped", events)

    def test_probe_scheduler_runs_post_processing_chain(self) -> None:
        scheduler = ProbeScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )

        with patch("scanner.probe_scheduler.probe_hosts", return_value={"scan_run_id": 71, "status": "completed"}), \
             patch("scanner.probe_scheduler.generate_inventory_diff", return_value={"event_count": 1, "events": [{"id": 1}]}), \
             patch("scanner.probe_scheduler.dispatch_event_notifications", return_value={"sent": 1}), \
             patch("scanner.probe_scheduler.export_azazel_events", return_value={"exported": 1}), \
             patch("scanner.probe_scheduler.cleanup_retention_data", return_value={"deleted": {"events": 1, "observations": 2, "scan_runs": 3}}):
            result = scheduler.run_forever(max_runs=1)

        self.assertEqual(result.status, "stopped")
        scanner_lines = Path(self.config.logging.scanner_log_path).read_text(encoding="utf-8").strip().splitlines()
        events = [json.loads(line)["event"] for line in scanner_lines]
        self.assertIn("probe_scheduler_post_processing_completed", events)


if __name__ == "__main__":
    unittest.main()
