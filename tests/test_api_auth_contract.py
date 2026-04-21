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
            "runbook_list": webapp.runbook_list,
            "send_control_command_with_params": webapp.send_control_command_with_params,
        }
        webapp.TOKEN_FILE = self.token_path
        webapp.runbook_list = lambda lang=None: []  # type: ignore[assignment]
        webapp.send_control_command_with_params = lambda action, params: {"ok": True}  # type: ignore[assignment]
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.TOKEN_FILE = self._orig["TOKEN_FILE"]
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

    def test_arsenal_demo_state_is_public_for_booth_surface(self) -> None:
        response = self.client.get("/api/arsenal-demo/state")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])

    def test_root_redirects_to_arsenal_demo_surface(self) -> None:
        response = self.client.get("/?lang=en", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/arsenal-demo?lang=en")


if __name__ == "__main__":
    unittest.main()
