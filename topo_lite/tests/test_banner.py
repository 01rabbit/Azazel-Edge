from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging
from scanner.banner import collect_banner_observations


class BannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "banner.sqlite3")
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)
        self.host = self.repository.upsert_host(ip="192.168.40.10", hostname="printer.local")
        self.repository.upsert_service(host_id=self.host["id"], proto="tcp", port=80, state="open")
        self.repository.upsert_service(host_id=self.host["id"], proto="tcp", port=443, state="open")
        self.repository.upsert_service(host_id=self.host["id"], proto="tcp", port=5353, state="open")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_collect_banner_observations_persists_http_tls_and_mdns(self) -> None:
        result = collect_banner_observations(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            http_fetcher=lambda ip, scheme, port, timeout: {"ip": ip, "port": port, "scheme": scheme, "title": "Printer Home", "server": "jetdirect"},
            tls_fetcher=lambda ip, port, timeout: {"ip": ip, "port": port, "subject": {"commonName": "printer-nas"}, "issuer": {"organizationName": "Acme CA"}},
            mdns_fetcher=lambda ip: "printer-mdns.local",
        )

        observations = self.repository.list_observations(self.host["id"])
        services = self.repository.list_services(self.host["id"])

        self.assertEqual(result["observation_count"], 4)
        self.assertEqual(len(observations), 4)
        sources = {item["source"] for item in observations}
        self.assertEqual(sources, {"http-banner", "tls-banner", "mdns-name"})
        service_80 = next(item for item in services if int(item["port"]) == 80)
        self.assertEqual(service_80["service_name"], "http")
        self.assertIn("Printer Home", service_80["banner"])

    def test_collect_banner_observations_keeps_running_on_fetch_error(self) -> None:
        result = collect_banner_observations(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            http_fetcher=lambda ip, scheme, port, timeout: (_ for _ in ()).throw(RuntimeError("boom")),
            tls_fetcher=lambda ip, port, timeout: None,
            mdns_fetcher=lambda ip: None,
        )

        self.assertEqual(result["observation_count"], 0)
        self.assertEqual(len(result["errors"]), 2)
        self.assertIn("boom", result["errors"][0]["error"])


if __name__ == "__main__":
    unittest.main()
