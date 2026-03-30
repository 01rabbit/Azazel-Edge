from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from classification import classify_host, classify_hosts
from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging


class ClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "classification.sqlite3")
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_classify_host_identifies_printer_from_ports_and_banner(self) -> None:
        result = classify_host(
            host={"vendor": "Printer Vendor", "hostname": "printer-1"},
            services=[
                {"port": 9100, "state": "open"},
                {"port": 80, "state": "open"},
            ],
            observations=[
                {"source": "http-banner", "payload_json": '{"title": "Office Printer", "server": "jetdirect"}'},
            ],
        )

        self.assertEqual(result.label, "printer")
        self.assertGreaterEqual(result.confidence, 0.88)

    def test_classify_host_falls_back_to_unknown(self) -> None:
        result = classify_host(
            host={"vendor": "", "hostname": ""},
            services=[],
            observations=[],
        )

        self.assertEqual(result.label, "unknown")

    def test_classify_hosts_persists_results(self) -> None:
        server = self.repository.upsert_host(ip="192.168.40.10", vendor="Dell", hostname="server-01")
        self.repository.upsert_service(host_id=server["id"], proto="tcp", port=22, state="open")
        self.repository.upsert_service(host_id=server["id"], proto="tcp", port=443, state="open")
        self.repository.record_observation(
            host_id=server["id"],
            source="tls-banner",
            payload={"subject": {"commonName": "vpn-server"}, "issuer": {"organizationName": "Acme CA"}},
        )

        summary = classify_hosts(self.repository, loggers=self.loggers)
        classification = self.repository.get_classification(server["id"])

        self.assertEqual(summary["host_count"], 1)
        self.assertEqual(classification["label"], "server")
        self.assertGreaterEqual(classification["confidence"], 0.8)


if __name__ == "__main__":
    unittest.main()
