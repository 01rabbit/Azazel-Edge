from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from configuration import default_config
from db.repository import TopoLiteRepository
from logging_utils import configure_logging
from scanner.probe import probe_hosts, tcp_connect_probe


class ProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.config = default_config()
        self.config.database_path = str(self.temp_path / "probe.sqlite3")
        self.config.target_ports = [22, 443]
        self.config.probe.timeout_seconds = 1
        self.config.probe.concurrency = 4
        self.config.probe.retry_count = 2
        self.config.probe.retry_backoff_seconds = 0.1
        self.config.probe.batch_size = 1
        self.config.logging.app_log_path = str(self.temp_path / "app.jsonl")
        self.config.logging.access_log_path = str(self.temp_path / "access.jsonl")
        self.config.logging.audit_log_path = str(self.temp_path / "audit.jsonl")
        self.config.logging.scanner_log_path = str(self.temp_path / "scanner.jsonl")
        self.repository = TopoLiteRepository(self.config.database_path)
        self.loggers = configure_logging(self.config.logging)
        self.host = self.repository.upsert_host(ip="127.0.0.1", hostname="loopback")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_probe_hosts_persists_services_and_observations(self) -> None:
        result = probe_hosts(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            connector=lambda ip, port, timeout: "open" if port == 22 else "closed",
        )

        services = self.repository.list_services(self.host["id"])
        observations = self.repository.list_observations(self.host["id"])

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["service_count"], 2)
        self.assertIn("duration_ms", result)
        self.assertEqual(result["state_counts"]["open"], 1)
        self.assertEqual(result["state_counts"]["closed"], 1)
        self.assertEqual(len(services), 2)
        self.assertEqual(len(observations), 2)
        first_payload = json.loads(observations[0]["payload_json"])
        self.assertEqual(first_payload["source"], "tcp-connect-probe")
        self.assertEqual(first_payload["attempts"], 1)

    def test_probe_hosts_keeps_running_when_single_probe_raises(self) -> None:
        def connector(ip: str, port: int, timeout: float) -> str:
            if port == 443:
                raise RuntimeError("boom")
            return "open"

        result = probe_hosts(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            connector=connector,
        )

        self.assertEqual(result["status"], "partial_failed")
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(len(self.repository.list_services(self.host["id"])), 1)

    def test_probe_hosts_retries_timeouts_with_backoff(self) -> None:
        attempt_counter: dict[tuple[str, int], int] = {}
        sleep_calls: list[float] = []

        def connector(ip: str, port: int, timeout: float) -> str:
            key = (ip, port)
            attempt_counter[key] = attempt_counter.get(key, 0) + 1
            if port == 22 and attempt_counter[key] == 1:
                return "timeout"
            return "open" if port == 22 else "closed"

        result = probe_hosts(
            config=self.config,
            repository=self.repository,
            loggers=self.loggers,
            connector=connector,
            sleep_fn=sleep_calls.append,
        )

        observations = self.repository.list_observations(self.host["id"])
        payloads = [json.loads(item["payload_json"]) for item in observations]
        ssh_payload = next(item for item in payloads if item["port"] == 22)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(sleep_calls, [0.1])
        self.assertEqual(ssh_payload["attempts"], 2)
        self.assertEqual(ssh_payload["state"], "open")

    def test_tcp_connect_probe_reports_open_and_closed(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        stop = threading.Event()

        def accept_once() -> None:
            conn, _ = server.accept()
            conn.close()
            stop.set()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        try:
            self.assertEqual(tcp_connect_probe("127.0.0.1", port, 1), "open")
            self.assertEqual(tcp_connect_probe("127.0.0.1", port + 1, 1), "closed")
        finally:
            stop.wait(timeout=1)
            server.close()
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
