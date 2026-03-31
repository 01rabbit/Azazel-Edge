from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from configuration import default_config
from db.repository import TopoLiteRepository
from integration_engine import export_azazel_events
from logging_utils import configure_logging


class IntegrationEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "integration.sqlite3")
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.config.integration.enabled = True
        self.config.integration.queue_path = str(self.temp_path / "queue")
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)
        host = self.repository.upsert_host(
            ip="192.168.40.40",
            mac="aa:bb:cc:dd:ee:40",
            hostname="gateway-40",
            vendor="Gateway Vendor",
            status="up",
        )
        self.host_id = int(host["id"])
        self.repository.upsert_service(host_id=self.host_id, proto="tcp", port=22, state="open")
        self.high_event = self.repository.create_event(
            event_type="service_added",
            host_id=self.host_id,
            severity="high",
            summary="service added on 192.168.40.40: tcp/22",
            created_at="2026-03-31T00:15:00Z",
        )
        self.low_event = self.repository.create_event(
            event_type="service_added",
            host_id=self.host_id,
            severity="low",
            summary="service added on 192.168.40.40: tcp/80",
            created_at="2026-03-31T00:16:00Z",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_export_azazel_events_writes_local_queue_payload(self) -> None:
        result = export_azazel_events(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            events=[self.high_event, self.low_event],
            now_fn=lambda: "2026-03-31T00:20:00Z",
        )

        queue_dir = Path(self.config.integration.queue_path)
        exported_file = queue_dir / f"topo-lite-event-{int(self.high_event['id'])}.json"
        self.assertEqual(result["exported"], 1)
        self.assertEqual(result["skipped_count"], 1)
        self.assertTrue(exported_file.is_file())
        payload = json.loads(exported_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["event_name"], "suspicious_exposure")
        self.assertEqual(payload["host"]["ip"], "192.168.40.40")
        self.assertEqual(payload["open_services"][0]["port"], 22)

        second = export_azazel_events(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            events=[self.high_event],
            now_fn=lambda: "2026-03-31T00:21:00Z",
        )
        self.assertEqual(second["exported"], 0)
        self.assertEqual(second["skipped_count"], 1)


if __name__ == "__main__":
    unittest.main()
