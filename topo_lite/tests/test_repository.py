from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from db.repository import TopoLiteRepository


class RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "repo.sqlite3"
        self.repository = TopoLiteRepository(self.database_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_host_service_and_event_crud(self) -> None:
        host = self.repository.upsert_host(ip="192.168.40.10", mac="aa:bb:cc:dd:ee:ff", hostname="printer")
        host_again = self.repository.upsert_host(ip="192.168.40.10", vendor="Acme")
        service = self.repository.upsert_service(
            host_id=host["id"],
            proto="tcp",
            port=9100,
            state="open",
            service_name="jetdirect",
        )
        event = self.repository.create_event(
            event_type="new_host",
            host_id=host["id"],
            summary="new printer found",
        )

        self.assertEqual(host["id"], host_again["id"])
        self.assertEqual(self.repository.get_host(host["id"])["vendor"], "Acme")
        self.assertEqual(service["service_name"], "jetdirect")
        self.assertEqual(event["event_type"], "new_host")
        self.assertEqual(len(self.repository.list_hosts()), 1)
        self.assertEqual(len(self.repository.list_services(host["id"])), 1)
        self.assertEqual(len(self.repository.list_events()), 1)

    def test_scan_run_and_cleanup_flow(self) -> None:
        run = self.repository.create_scan_run(scan_kind="discovery", details={"source": "test"})
        finished = self.repository.finish_scan_run(run["id"], status="completed")
        host = self.repository.upsert_host(ip="192.168.40.20")
        self.repository.record_observation(
            host_id=host["id"],
            source="arp-scan",
            payload={"ip": "192.168.40.20"},
            observed_at="2025-01-01T00:00:00Z",
        )
        self.repository.create_event(
            event_type="service_added",
            host_id=host["id"],
            summary="ssh open",
            created_at="2025-01-01T00:00:00Z",
        )
        deleted = self.repository.cleanup_history(
            observations_before="2025-06-01T00:00:00Z",
            events_before="2025-06-01T00:00:00Z",
        )

        self.assertEqual(finished["status"], "completed")
        self.assertEqual(deleted["observations"], 1)
        self.assertEqual(deleted["events"], 1)
        self.assertEqual(deleted["scan_runs"], 0)

    def test_transaction_rolls_back_on_error(self) -> None:
        with self.assertRaises(RuntimeError):
            with self.repository.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO hosts(ip, status, first_seen, last_seen)
                    VALUES(?, ?, ?, ?)
                    """,
                    ("192.168.40.99", "up", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
                )
                raise RuntimeError("boom")

        self.assertEqual(len(self.repository.list_hosts()), 0)


if __name__ == "__main__":
    unittest.main()
