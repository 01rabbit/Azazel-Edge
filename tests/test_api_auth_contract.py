from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class ApiAuthContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.token_path = Path(self.tmp.name) / "web_token.txt"
        self.token_path.write_text("secret-token", encoding="utf-8")
        self._orig = {
            "TOKEN_FILE": webapp.TOKEN_FILE,
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "runbook_list": webapp.runbook_list,
            "send_control_command_with_params": webapp.send_control_command_with_params,
        }
        webapp.TOKEN_FILE = self.token_path
        webapp.AUTH_FAIL_OPEN = False
        webapp.runbook_list = lambda lang=None: []  # type: ignore[assignment]
        webapp.send_control_command_with_params = lambda action, params: {"ok": True}  # type: ignore[assignment]
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.TOKEN_FILE = self._orig["TOKEN_FILE"]
        webapp.AUTH_FAIL_OPEN = self._orig["AUTH_FAIL_OPEN"]
        webapp.runbook_list = self._orig["runbook_list"]
        webapp.send_control_command_with_params = self._orig["send_control_command_with_params"]
        self.tmp.cleanup()

    def test_error_only_unauthorized_shape_for_state_endpoint(self) -> None:
        response = self.client.get("/api/state")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"error": "Unauthorized"})

    def test_ok_false_unauthorized_shape_for_runbooks_endpoint(self) -> None:
        response = self.client.get("/api/runbooks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"ok": False, "error": "Unauthorized"})

    def test_wifi_connect_preserves_401_unauthorized(self) -> None:
        response = self.client.post("/api/wifi/connect", json={"ssid": "TestAP", "security": "OPEN"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json(), {"ok": False, "error": "Unauthorized"})

    def test_missing_token_file_is_fail_closed_by_default(self) -> None:
        self.token_path.unlink()
        response = self.client.get("/api/state")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"error": "Unauthorized"})

    def test_missing_token_file_can_be_fail_open_when_explicitly_enabled(self) -> None:
        self.token_path.unlink()
        webapp.AUTH_FAIL_OPEN = True
        response = self.client.get("/api/state")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
