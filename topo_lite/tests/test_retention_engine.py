from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging
from retention_engine import cleanup_retention_data


class RetentionEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "retention.sqlite3")
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.config.retention_period.observations_days = 7
        self.config.retention_period.events_days = 7
        self.config.retention_period.scan_runs_days = 7
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)
        host = self.repository.upsert_host(ip="192.168.40.30", status="up", seen_at="2026-03-01T00:00:00Z")
        self.host_id = int(host["id"])
        self.repository.record_observation(
            host_id=self.host_id,
            source="arp-scan",
            payload={"ip": "192.168.40.30"},
            observed_at="2026-03-01T00:00:00Z",
        )
        self.repository.record_observation(
            host_id=self.host_id,
            source="arp-scan",
            payload={"ip": "192.168.40.30"},
            observed_at="2026-03-30T00:00:00Z",
        )
        self.repository.create_event(
            event_type="new_host",
            host_id=self.host_id,
            summary="old event",
            created_at="2026-03-01T00:00:00Z",
        )
        self.repository.create_event(
            event_type="new_host",
            host_id=self.host_id,
            summary="new event",
            created_at="2026-03-30T00:00:00Z",
        )
        old_run = self.repository.create_scan_run(
            scan_kind="arp_discovery",
            started_at="2026-03-01T00:00:00Z",
            details={},
        )
        self.repository.finish_scan_run(old_run["id"], status="completed", finished_at="2026-03-01T00:01:00Z", details={})
        new_run = self.repository.create_scan_run(
            scan_kind="arp_discovery",
            started_at="2026-03-30T00:00:00Z",
            details={},
        )
        self.repository.finish_scan_run(new_run["id"], status="completed", finished_at="2026-03-30T00:01:00Z", details={})

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_cleanup_retention_data_deletes_only_expired_history(self) -> None:
        result = cleanup_retention_data(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            now_fn=lambda: "2026-03-31T00:00:00Z",
        )

        self.assertEqual(result["deleted"]["observations"], 1)
        self.assertEqual(result["deleted"]["events"], 1)
        self.assertEqual(result["deleted"]["scan_runs"], 1)
        self.assertEqual(len(self.repository.list_observations()), 1)
        self.assertEqual(len(self.repository.list_events()), 1)
        self.assertEqual(len(self.repository.list_scan_runs()), 1)


if __name__ == "__main__":
    unittest.main()
