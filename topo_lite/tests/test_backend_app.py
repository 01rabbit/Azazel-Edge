from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from backend.app import create_app
from classification import classify_hosts
from db.repository import TopoLiteRepository


class BackendAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test.sqlite3"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.logs_dir = Path(self.temp_dir.name) / "logs"
        self.config_path.write_text(
            "\n".join(
                [
                    "interface: eth0",
                    "subnets:",
                    "  - 192.168.40.0/24",
                    f"database_path: {self.database_path}",
                    "logging:",
                    "  level: INFO",
                    f"  app_log_path: {self.logs_dir / 'app.jsonl'}",
                    f"  access_log_path: {self.logs_dir / 'access.jsonl'}",
                    f"  audit_log_path: {self.logs_dir / 'audit.jsonl'}",
                    f"  scanner_log_path: {self.logs_dir / 'scanner.jsonl'}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        self.app = create_app(config_path=self.config_path)
        self.client = self.app.test_client()
        self.repository = TopoLiteRepository(self.database_path)

        self.host_one = self.repository.upsert_host(
            ip="192.168.40.10",
            mac="aa:bb:cc:dd:ee:10",
            vendor="Printer Vendor",
            hostname="printer-1",
            status="up",
        )
        self.host_two = self.repository.upsert_host(
            ip="192.168.40.20",
            mac="aa:bb:cc:dd:ee:20",
            vendor="Laptop Vendor",
            hostname="laptop-1",
            status="up",
        )
        self.repository.upsert_service(host_id=self.host_one["id"], proto="tcp", port=9100, state="open")
        self.repository.upsert_service(host_id=self.host_two["id"], proto="tcp", port=22, state="open")
        self.repository.record_observation(
            host_id=self.host_one["id"],
            source="arp-scan",
            payload={"ip": "192.168.40.10"},
        )
        self.repository.create_event(
            event_type="new_host",
            host_id=self.host_one["id"],
            summary="new printer found",
        )
        self.repository.create_scan_run(scan_kind="arp_discovery", status="completed", details={"host_count": 2})
        self.repository.set_classification(
            host_id=self.host_one["id"],
            label="printer",
            confidence=0.95,
            reason={"ports": [9100]},
        )

    def _login(self, username: str, password: str):
        return self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_health_endpoint(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["ok"], True)
        self.assertIn("log_paths", response.get_json())

    def test_meta_endpoint_lists_workspace_directories(self) -> None:
        self._login("admin", "change-me-admin-password")
        response = self.client.get("/api/meta")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["project"], "Azazel-Topo-Lite")
        self.assertIn("backend", payload["directories"])
        self.assertIn("scanner", payload["directories"])
        self.assertEqual(payload["database"]["host_count"], 2)

    def test_hosts_endpoint_supports_filter_sort_and_pagination(self) -> None:
        self._login("admin", "change-me-admin-password")
        response = self.client.get("/api/hosts?page=1&page_size=1&role=printer&sort=last_seen&order=desc")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["total"], 1)
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["hostname"], "printer-1")
        self.assertEqual(payload["items"][0]["role"], "printer")

    def test_host_detail_endpoint_returns_joined_data(self) -> None:
        self._login("admin", "change-me-admin-password")
        response = self.client.get(f"/api/hosts/{self.host_one['id']}")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["hostname"], "printer-1")
        self.assertEqual(payload["classification"]["label"], "printer")
        self.assertEqual(len(payload["services"]), 1)
        self.assertEqual(len(payload["events"]), 1)
        self.assertEqual(len(payload["observations"]), 1)

    def test_services_events_scan_runs_and_topology_endpoints(self) -> None:
        self._login("admin", "change-me-admin-password")
        services = self.client.get("/api/services?host_id=1").get_json()
        events = self.client.get("/api/events?event_type=new_host").get_json()
        scan_runs = self.client.get("/api/scan-runs?scan_kind=arp_discovery").get_json()
        topology = self.client.get("/api/topology").get_json()

        self.assertEqual(services["total"], 1)
        self.assertEqual(events["total"], 1)
        self.assertEqual(scan_runs["total"], 1)
        self.assertTrue(any(node["type"] == "subnet" for node in topology["nodes"]))
        self.assertTrue(any(edge["type"] == "belongs_to" for edge in topology["edges"]))

    def test_create_override_endpoint_persists_record(self) -> None:
        self._login("admin", "change-me-admin-password")
        response = self.client.post(
            "/api/overrides",
            json={
                "host_id": self.host_one["id"],
                "fixed_label": "trusted-printer",
                "ignored": False,
                "note": "known device",
            },
        )
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertEqual(payload["host_id"], self.host_one["id"])
        self.assertEqual(payload["fixed_label"], "trusted-printer")

    def test_update_and_delete_override_endpoints(self) -> None:
        self._login("admin", "change-me-admin-password")
        created = self.client.post(
            "/api/overrides",
            json={
                "host_id": self.host_one["id"],
                "fixed_label": "known-printer",
                "fixed_role": "printer",
                "ignored": False,
            },
        ).get_json()

        updated = self.client.put(
            f"/api/overrides/{created['id']}",
            json={
                "fixed_label": "ignore-me",
                "fixed_role": "iot",
                "fixed_icon": "printer",
                "ignored": True,
                "note": "temporary suppression",
            },
        )
        deleted = self.client.delete(f"/api/overrides/{created['id']}")

        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()["fixed_role"], "iot")
        self.assertEqual(updated.get_json()["ignored"], 1)
        self.assertEqual(deleted.status_code, 200)
        self.assertIsNone(self.repository.get_override(created["id"]))

    def test_ignored_override_hides_host_from_inventory_and_topology(self) -> None:
        self._login("admin", "change-me-admin-password")
        self.client.post(
            "/api/overrides",
            json={
                "host_id": self.host_one["id"],
                "fixed_role": "printer",
                "ignored": True,
            },
        )

        hosts = self.client.get("/api/hosts").get_json()
        topology = self.client.get("/api/topology").get_json()

        returned_ids = {item["id"] for item in hosts["items"]}
        topology_ids = {node["id"] for node in topology["nodes"]}
        self.assertNotIn(self.host_one["id"], returned_ids)
        self.assertNotIn(f"host:{self.host_one['id']}", topology_ids)

    def test_effective_role_uses_override_after_reclassification(self) -> None:
        self._login("admin", "change-me-admin-password")
        self.client.post(
            "/api/overrides",
            json={
                "host_id": self.host_two["id"],
                "fixed_label": "trusted-workstation",
                "fixed_role": "desktop",
                "fixed_icon": "desktop",
                "ignored": False,
            },
        )
        classify_hosts(self.repository)

        hosts = self.client.get("/api/hosts").get_json()
        detail = self.client.get(f"/api/hosts/{self.host_two['id']}").get_json()
        host_two = next(item for item in hosts["items"] if item["id"] == self.host_two["id"])

        self.assertEqual(host_two["role"], "desktop")
        self.assertEqual(host_two["label"], "trusted-workstation")
        self.assertEqual(detail["classification"]["source"], "override")
        self.assertEqual(detail["icon"], "desktop")

    def test_api_errors_return_json(self) -> None:
        self._login("admin", "change-me-admin-password")
        not_found = self.client.get("/api/hosts/999999")
        invalid = self.client.get("/api/hosts?sort=unknown")

        self.assertEqual(not_found.status_code, 404)
        self.assertEqual(not_found.get_json()["error"], "not_found")
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.get_json()["error"], "bad_request")

    def test_unauthenticated_requests_are_rejected(self) -> None:
        response = self.client.get("/api/hosts/1")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"], "unauthorized")

    def test_read_only_user_cannot_call_admin_endpoint(self) -> None:
        login = self._login("viewer", "change-me-viewer-password")
        self.assertEqual(login.status_code, 200)
        response = self.client.post(
            "/api/overrides",
            json={"host_id": self.host_one["id"], "fixed_label": "blocked"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "forbidden")

    def test_api_token_auth_and_session_auth_both_work(self) -> None:
        session_login = self._login("admin", "change-me-admin-password")
        self.assertEqual(session_login.status_code, 200)
        session_me = self.client.get("/api/auth/me")
        token_me = self.client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer change-me-admin-token"},
        )

        self.assertEqual(session_me.status_code, 200)
        self.assertEqual(session_me.get_json()["auth_method"], "session")
        self.assertEqual(token_me.status_code, 200)
        self.assertEqual(token_me.get_json()["auth_method"], "token")

    def test_logout_clears_session(self) -> None:
        self._login("admin", "change-me-admin-password")
        logout = self.client.post("/api/auth/logout")
        after_logout = self.client.get("/api/auth/me")

        self.assertEqual(logout.status_code, 200)
        self.assertEqual(after_logout.status_code, 401)

    def test_api_responses_include_cors_headers_for_frontend_origin(self) -> None:
        response = self.client.open(
            "/api/auth/login",
            method="OPTIONS",
            headers={
                "Origin": "http://127.0.0.1:18081",
                "Access-Control-Request-Method": "POST",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Access-Control-Allow-Origin"], "http://127.0.0.1:18081")
        self.assertEqual(response.headers["Access-Control-Allow-Credentials"], "true")

    def test_local_only_mode_rejects_non_loopback_client(self) -> None:
        response = self.client.get(
            "/api/ping",
            environ_overrides={"REMOTE_ADDR": "192.168.40.10"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "forbidden")

        audit_lines = (self.logs_dir / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
        audit_entry = json.loads(audit_lines[-1])
        self.assertEqual(audit_entry["event"], "network_access_denied")
        self.assertEqual(audit_entry["remote_addr"], "192.168.40.10")
        self.assertEqual(audit_entry["reason"], "local_only")

    def test_allowlisted_cidr_permits_remote_access(self) -> None:
        config_path = Path(self.temp_dir.name) / "allowlist-config.yaml"
        config_path.write_text(
            "\n".join(
                [
                    "interface: eth0",
                    "subnets:",
                    "  - 192.168.40.0/24",
                    f"database_path: {self.database_path}",
                    "logging:",
                    "  level: INFO",
                    f"  app_log_path: {self.logs_dir / 'allow-app.jsonl'}",
                    f"  access_log_path: {self.logs_dir / 'allow-access.jsonl'}",
                    f"  audit_log_path: {self.logs_dir / 'allow-audit.jsonl'}",
                    f"  scanner_log_path: {self.logs_dir / 'allow-scanner.jsonl'}",
                    "exposure:",
                    "  backend_bind_host: 0.0.0.0",
                    "  frontend_bind_host: 0.0.0.0",
                    "  local_only: false",
                    "  allowed_cidrs:",
                    "    - 192.168.40.0/24",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        allow_app = create_app(config_path=config_path)
        allow_client = allow_app.test_client()

        response = allow_client.get(
            "/api/ping",
            environ_overrides={"REMOTE_ADDR": "192.168.40.55"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], "pong")

    def test_access_and_audit_logs_are_written_as_jsonl(self) -> None:
        self._login("admin", "change-me-admin-password")
        self.client.get("/api/meta")

        access_lines = (self.logs_dir / "access.jsonl").read_text(encoding="utf-8").strip().splitlines()
        audit_lines = (self.logs_dir / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()

        access_entry = json.loads(access_lines[-1])
        audit_entry = json.loads(audit_lines[-1])

        self.assertEqual(access_entry["event"], "http_request")
        self.assertEqual(access_entry["path"], "/api/meta")
        self.assertIn(audit_entry["event"], {"backend_startup", "login_succeeded"})


if __name__ == "__main__":
    unittest.main()
