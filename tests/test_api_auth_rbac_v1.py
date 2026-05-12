from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class ApiAuthRBACTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.auth_tokens_path = root / "auth_tokens.json"
        self.authz_log_path = root / "authz-events.jsonl"
        self.auth_tokens_path.write_text(
            json.dumps(
                {
                    "tokens": [
                        {"token": "viewer-token", "principal": "viewer-1", "role": "viewer"},
                        {"token": "operator-token", "principal": "operator-1", "role": "operator"},
                        {"token": "responder-token", "principal": "responder-1", "role": "responder"},
                        {"token": "admin-token", "principal": "admin-1", "role": "admin"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        self._orig = {
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "AUTH_TOKENS_FILE": webapp.AUTH_TOKENS_FILE,
            "AUTHZ_AUDIT_LOG": webapp.AUTHZ_AUDIT_LOG,
            "AUTH_MTLS_REQUIRED": webapp.AUTH_MTLS_REQUIRED,
            "AUTH_MTLS_FINGERPRINTS": set(webapp.AUTH_MTLS_FINGERPRINTS),
            "send_control_command": webapp.send_control_command,
            "send_control_command_with_params": webapp.send_control_command_with_params,
        }
        webapp.AUTH_FAIL_OPEN = False
        webapp.AUTH_TOKENS_FILE = self.auth_tokens_path
        webapp.AUTHZ_AUDIT_LOG = self.authz_log_path
        webapp.AUTH_MTLS_REQUIRED = False
        webapp.AUTH_MTLS_FINGERPRINTS = set()
        webapp.send_control_command = lambda action: {"ok": True, "action": action}  # type: ignore[assignment]
        webapp.send_control_command_with_params = lambda action, params: {"ok": True, "action": action, "params": params}  # type: ignore[assignment]
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.AUTH_FAIL_OPEN = self._orig["AUTH_FAIL_OPEN"]
        webapp.AUTH_TOKENS_FILE = self._orig["AUTH_TOKENS_FILE"]
        webapp.AUTHZ_AUDIT_LOG = self._orig["AUTHZ_AUDIT_LOG"]
        webapp.AUTH_MTLS_REQUIRED = self._orig["AUTH_MTLS_REQUIRED"]
        webapp.AUTH_MTLS_FINGERPRINTS = self._orig["AUTH_MTLS_FINGERPRINTS"]
        webapp.send_control_command = self._orig["send_control_command"]
        webapp.send_control_command_with_params = self._orig["send_control_command_with_params"]
        self.tmp.cleanup()

    def test_viewer_can_read_state(self) -> None:
        response = self.client.get("/api/state", headers={"X-AZAZEL-TOKEN": "viewer-token"})
        self.assertEqual(response.status_code, 200)

    def test_viewer_cannot_execute_action(self) -> None:
        response = self.client.post("/api/action", headers={"X-AZAZEL-TOKEN": "viewer-token"}, json={"action": "refresh"})
        self.assertEqual(response.status_code, 403)

    def test_responder_can_execute_action(self) -> None:
        response = self.client.post("/api/action", headers={"X-AZAZEL-TOKEN": "responder-token"}, json={"action": "refresh"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json().get("status"), "ok")

    def test_operator_cannot_patch_sot(self) -> None:
        response = self.client.patch("/api/sot/devices", headers={"X-AZAZEL-TOKEN": "operator-token"}, json={"devices": []})
        self.assertEqual(response.status_code, 403)

    def test_admin_can_set_mode(self) -> None:
        response = self.client.post("/api/mode", headers={"X-AZAZEL-TOKEN": "admin-token"}, json={"mode": "shield"})
        self.assertEqual(response.status_code, 200)

    def test_mtls_required_for_action_role_endpoints(self) -> None:
        webapp.AUTH_MTLS_REQUIRED = True
        webapp.AUTH_MTLS_FINGERPRINTS = {"sha256:test"}
        denied = self.client.post("/api/action", headers={"X-AZAZEL-TOKEN": "responder-token"}, json={"action": "refresh"})
        self.assertEqual(denied.status_code, 403)
        allowed = self.client.post(
            "/api/action",
            headers={"X-AZAZEL-TOKEN": "responder-token", webapp.AUTH_MTLS_HEADER: "sha256:test"},
            json={"action": "refresh"},
        )
        self.assertEqual(allowed.status_code, 200)

    def test_authz_audit_log_contains_principal_role_and_result(self) -> None:
        self.client.post("/api/action", headers={"X-AZAZEL-TOKEN": "viewer-token"}, json={"action": "refresh", "trace_id": "trace-a"})
        rows = [json.loads(line) for line in self.authz_log_path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(rows)
        row = rows[-1]
        self.assertEqual(row.get("trace_id"), "trace-a")
        self.assertEqual(row.get("principal"), "viewer-1")
        self.assertEqual(row.get("role"), "viewer")
        self.assertEqual(row.get("requested_action"), "refresh")
        self.assertFalse(bool(row.get("allowed")))


if __name__ == "__main__":
    unittest.main()

