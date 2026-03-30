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
            retry_backoff_multiplier=3.0,
            retry_max_delay_seconds=9,
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

    def test_scheduler_uses_exponential_backoff_until_max_delay(self) -> None:
        scheduler = DiscoveryScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            retry_limit=2,
            retry_delay_seconds=2,
            retry_backoff_multiplier=3.0,
            retry_max_delay_seconds=5,
            sleep_fn=self.sleep_calls.append,
        )

        with patch(
            "scanner.scheduler.discover_hosts",
            side_effect=[
                {"scan_run_id": 41, "status": "failed"},
                {"scan_run_id": 42, "status": "failed"},
                {"scan_run_id": 43, "status": "failed"},
            ],
        ):
            result = scheduler.run_forever(max_runs=5)

        self.assertEqual(result.status, "failed")
        self.assertEqual(self.sleep_calls, [2.0, 5])

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

    def test_scheduler_triggers_deep_probe_after_successful_discovery(self) -> None:
        scheduler = DiscoveryScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            sleep_fn=self.sleep_calls.append,
        )

        with patch("scanner.scheduler.discover_hosts", return_value={"scan_run_id": 71, "status": "completed"}), patch(
            "scanner.scheduler.deep_probe_new_hosts",
            return_value={"scan_run_id": 81, "status": "completed", "host_count": 1},
        ) as deep_probe:
            scheduler.run_forever(max_runs=1)

        deep_probe.assert_called_once()
        self.assertEqual(deep_probe.call_args.kwargs["discovery_scan_run_id"], 71)

    def test_scheduler_skips_deep_probe_after_failed_discovery(self) -> None:
        scheduler = DiscoveryScheduler(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            lock_path=self.lock_path,
            retry_limit=0,
            sleep_fn=self.sleep_calls.append,
        )

        with patch("scanner.scheduler.discover_hosts", return_value={"scan_run_id": 72, "status": "failed"}), patch(
            "scanner.scheduler.deep_probe_new_hosts"
        ) as deep_probe:
            scheduler.run_forever(max_runs=1)

        deep_probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
