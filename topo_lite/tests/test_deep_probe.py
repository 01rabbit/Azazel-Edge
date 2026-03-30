from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging
from scanner.deep_probe import deep_probe_new_hosts


class DeepProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "deep-probe.sqlite3")
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.config.probe.batch_size = 2
        self.config.deep_probe.target_ports = [22, 443]
        self.config.deep_probe.timeout_seconds = 1
        self.config.deep_probe.dedupe_window_seconds = 900
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_deep_probe_targets_only_new_hosts(self) -> None:
        old_host = self.repository.upsert_host(ip="192.168.40.10", hostname="old-host")
        new_host = self.repository.upsert_host(ip="192.168.40.20", hostname="new-host")
        previous_run = self.repository.create_scan_run(scan_kind="arp_discovery", details={})
        self.repository.finish_scan_run(
            int(previous_run["id"]),
            status="completed",
            details={
                "discovered_hosts": [
                    {"host_id": old_host["id"], "ip": "192.168.40.10", "mac": None, "vendor": None, "subnet": "192.168.40.0/24"}
                ]
            },
        )
        current_run = self.repository.create_scan_run(scan_kind="arp_discovery", details={})
        self.repository.finish_scan_run(
            int(current_run["id"]),
            status="completed",
            details={
                "discovered_hosts": [
                    {"host_id": old_host["id"], "ip": "192.168.40.10", "mac": None, "vendor": None, "subnet": "192.168.40.0/24"},
                    {"host_id": new_host["id"], "ip": "192.168.40.20", "mac": None, "vendor": None, "subnet": "192.168.40.0/24"},
                ]
            },
        )

        result = deep_probe_new_hosts(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            discovery_scan_run_id=int(current_run["id"]),
            connector=lambda ip, port, timeout: "open" if ip == "192.168.40.20" and port == 22 else "closed",
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["host_count"], 1)
        self.assertEqual(result["service_count"], 2)
        self.assertEqual([item["ip"] for item in result["target_hosts"]], ["192.168.40.20"])
        services = self.repository.list_services(new_host["id"])
        self.assertEqual(len(services), 2)
        observations = self.repository.list_observations(new_host["id"])
        payloads = [json.loads(item["payload_json"]) for item in observations]
        self.assertTrue(any(payload["source"] == "tcp-connect-deep-probe" for payload in payloads))

    def test_deep_probe_skips_when_same_discovery_run_was_already_processed(self) -> None:
        host = self.repository.upsert_host(ip="192.168.40.30", hostname="new-host")
        discovery_run = self.repository.create_scan_run(scan_kind="arp_discovery", details={})
        self.repository.finish_scan_run(
            int(discovery_run["id"]),
            status="completed",
            details={"discovered_hosts": [{"host_id": host["id"], "ip": "192.168.40.30"}]},
        )
        existing_run = self.repository.create_scan_run(
            scan_kind="deep_probe",
            details={
                "trigger_discovery_scan_run_id": int(discovery_run["id"]),
                "target_hosts": [{"host_id": host["id"], "ip": "192.168.40.30"}],
            },
        )
        self.repository.finish_scan_run(int(existing_run["id"]), status="completed")

        result = deep_probe_new_hosts(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            discovery_scan_run_id=int(discovery_run["id"]),
            connector=lambda ip, port, timeout: "open",
        )

        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "already_processed")

    def test_deep_probe_respects_recent_dedupe_window(self) -> None:
        first_host = self.repository.upsert_host(ip="192.168.40.41", hostname="first")
        second_host = self.repository.upsert_host(ip="192.168.40.42", hostname="second")
        previous_run = self.repository.create_scan_run(scan_kind="arp_discovery", details={})
        self.repository.finish_scan_run(int(previous_run["id"]), status="completed", details={"discovered_hosts": []})
        discovery_run = self.repository.create_scan_run(scan_kind="arp_discovery", details={})
        self.repository.finish_scan_run(
            int(discovery_run["id"]),
            status="completed",
            details={
                "discovered_hosts": [
                    {"host_id": first_host["id"], "ip": "192.168.40.41"},
                    {"host_id": second_host["id"], "ip": "192.168.40.42"},
                ]
            },
        )
        prior_deep_probe = self.repository.create_scan_run(
            scan_kind="deep_probe",
            details={"target_hosts": [{"host_id": first_host["id"], "ip": "192.168.40.41"}]},
        )
        self.repository.finish_scan_run(int(prior_deep_probe["id"]), status="completed")

        result = deep_probe_new_hosts(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            discovery_scan_run_id=int(discovery_run["id"]),
            connector=lambda ip, port, timeout: "closed",
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual([item["ip"] for item in result["target_hosts"]], ["192.168.40.42"])

    def test_deep_probe_returns_skipped_when_disabled(self) -> None:
        self.config.deep_probe.enabled = False
        discovery_run = self.repository.create_scan_run(scan_kind="arp_discovery", details={})
        self.repository.finish_scan_run(int(discovery_run["id"]), status="completed", details={"discovered_hosts": []})

        result = deep_probe_new_hosts(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            discovery_scan_run_id=int(discovery_run["id"]),
            connector=lambda ip, port, timeout: "open",
        )

        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "disabled")
