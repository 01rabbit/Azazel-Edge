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
        self.assertEqual(self.repository.get_host_by_ip("192.168.40.10")["id"], host["id"])
        self.assertEqual(service["service_name"], "jetdirect")
        self.assertEqual(event["event_type"], "new_host")
        self.assertEqual(len(self.repository.list_hosts()), 1)
        self.assertEqual(len(self.repository.list_services(host["id"])), 1)
        self.assertEqual(len(self.repository.list_events()), 1)

    def test_latest_scan_run_classification_and_override_helpers(self) -> None:
        host = self.repository.upsert_host(ip="192.168.40.21", hostname="desk-01")
        self.repository.set_classification(
            host_id=host["id"],
            label="desktop",
            confidence=0.91,
            reason={"ports": [22, 443]},
        )
        override = self.repository.create_override(
            host_id=host["id"],
            fixed_label="managed-desktop",
            ignored=False,
            note="known asset",
        )
        run = self.repository.create_scan_run(scan_kind="inventory_snapshot")
        self.repository.finish_scan_run(run["id"], status="completed", details={"baseline": True})

        self.assertEqual(self.repository.get_classification(host["id"])["label"], "desktop")
        self.assertEqual(self.repository.list_overrides(host["id"])[0]["id"], override["id"])
        self.assertEqual(self.repository.get_latest_override(host["id"])["fixed_label"], "managed-desktop")
        self.assertEqual(self.repository.get_latest_scan_run("inventory_snapshot", statuses=("completed",))["id"], run["id"])

    def test_user_and_api_token_helpers(self) -> None:
        user = self.repository.upsert_user(
            username="admin",
            password_hash="pbkdf2_sha256$1$salt$deadbeef",
            role="admin",
        )
        token = self.repository.upsert_api_token(
            user_id=user["id"],
            token_hash="abc123",
            label="bootstrap-admin",
        )

        self.assertEqual(self.repository.get_user(user["id"])["username"], "admin")
        self.assertEqual(self.repository.get_user_by_username("admin")["id"], user["id"])
        self.assertEqual(self.repository.get_user_by_token_hash("abc123")["id"], user["id"])
        self.assertEqual(token["label"], "bootstrap-admin")

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
