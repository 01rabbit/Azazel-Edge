from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging
from scanner.scheduler import DiscoveryScheduler, SchedulerLockError


class SchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "scheduler.sqlite3")
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.config.scan_intervals.discovery_seconds = 1
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)
        self.lock_path = self.temp_path / "scheduler.lock"
        self.sleep_calls: list[float] = []

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_scheduler_runs_once_and_stops(self) -> None:
        scheduler = DiscoveryScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )

        with patch("scanner.scheduler.discover_hosts", return_value={"scan_run_id": 11, "status": "completed"}):
            result = scheduler.run_forever(max_runs=1)

        self.assertEqual(result.status, "stopped")
        self.assertEqual(result.runs_completed, 1)
        self.assertEqual(result.last_scan_run_id, 11)
        self.assertEqual(self.sleep_calls, [])

    def test_scheduler_retries_and_fails_after_limit(self) -> None:
        scheduler = DiscoveryScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            retry_limit=1,
            retry_delay_seconds=2,
            sleep_fn=self.sleep_calls.append,
        )

        with patch(
            "scanner.scheduler.discover_hosts",
            side_effect=[
                {"scan_run_id": 21, "status": "failed"},
                {"scan_run_id": 22, "status": "failed"},
            ],
        ):
            result = scheduler.run_forever(max_runs=5)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.failures, 2)
        self.assertEqual(self.sleep_calls, [2])

    def test_scheduler_lock_prevents_second_instance(self) -> None:
        scheduler_one = DiscoveryScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )
        scheduler_two = DiscoveryScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )

        scheduler_one._acquire_lock()
        try:
            with self.assertRaises(SchedulerLockError):
                scheduler_two._acquire_lock()
        finally:
            scheduler_one._release_lock()

    def test_scheduler_writes_audit_log(self) -> None:
        scheduler = DiscoveryScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )

        with patch("scanner.scheduler.discover_hosts", return_value={"scan_run_id": 31, "status": "completed"}):
            scheduler.run_forever(max_runs=1)

        audit_lines = Path(self.config.logging.audit_log_path).read_text(encoding="utf-8").strip().splitlines()
        events = [json.loads(line)["event"] for line in audit_lines]
        self.assertIn("discovery_scheduler_started", events)
        self.assertIn("discovery_scheduler_stopped", events)


if __name__ == "__main__":
    unittest.main()
