from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging
from notify_engine import dispatch_event_notifications


class _FakeNotifier:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.payloads: list[dict[str, object]] = []

    def send(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(payload)
        if self.fail:
            raise RuntimeError("simulated notification failure")
        return {"ok": True, "adapter": "fake", "status": 202}


class NotificationEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "notify.sqlite3")
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.config.notification.enabled = True
        self.config.notification.endpoint = "https://ntfy.local/topic"
        self.config.notification.rate_limit_seconds = 300
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)
        host = self.repository.upsert_host(ip="192.168.40.20", hostname="host-20", status="up")
        self.host_id = int(host["id"])
        self.new_host_event = self.repository.create_event(
            event_type="new_host",
            host_id=self.host_id,
            severity="low",
            summary="new host discovered",
            created_at="2026-03-31T00:00:00Z",
        )
        self.high_event = self.repository.create_event(
            event_type="service_added",
            host_id=self.host_id,
            severity="high",
            summary="service added on 192.168.40.20: tcp/22",
            created_at="2026-03-31T00:01:00Z",
        )
        self.low_event = self.repository.create_event(
            event_type="service_added",
            host_id=self.host_id,
            severity="low",
            summary="service added on 192.168.40.20: tcp/80",
            created_at="2026-03-31T00:02:00Z",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_dispatch_sends_new_host_and_high_events(self) -> None:
        notifier = _FakeNotifier()

        result = dispatch_event_notifications(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            notifier=notifier,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["sent"], 2)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(len(notifier.payloads), 2)
        self.assertIsNotNone(self.repository.get_event(int(self.new_host_event["id"]))["notified_at"])
        self.assertIsNotNone(self.repository.get_event(int(self.high_event["id"]))["notified_at"])
        self.assertIsNone(self.repository.get_event(int(self.low_event["id"]))["notified_at"])

    def test_dispatch_rate_limits_recent_attempt(self) -> None:
        notifier = _FakeNotifier()
        self.repository.mark_event_notification(
            int(self.new_host_event["id"]),
            attempted_at="2026-03-31T00:04:30Z",
            notified_at=None,
            error="temporary failure",
        )

        result = dispatch_event_notifications(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            notifier=notifier,
            now_fn=lambda: "2026-03-31T00:05:00Z",
        )

        self.assertEqual(result["sent"], 1)
        self.assertEqual(result["skipped_count"], 2)
        self.assertEqual(len(notifier.payloads), 1)

    def test_dispatch_records_failure_without_raising(self) -> None:
        notifier = _FakeNotifier(fail=True)

        result = dispatch_event_notifications(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            events=[self.high_event],
            notifier=notifier,
            now_fn=lambda: "2026-03-31T00:10:00Z",
        )

        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["failed"], 1)
        event = self.repository.get_event(int(self.high_event["id"]))
        self.assertEqual(event["notification_attempted_at"], "2026-03-31T00:10:00Z")
        self.assertIn("simulated notification failure", str(event["notification_error"]))


if __name__ == "__main__":
    unittest.main()
