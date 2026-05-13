from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class CaptivePortalApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self._orig = {
            "CAPTIVE_REGISTRY_PATH": webapp.CAPTIVE_REGISTRY_PATH,
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "load_token": webapp.load_token,
        }
        webapp.CAPTIVE_REGISTRY_PATH = root / "captive-allowlist.json"
        webapp.AUTH_FAIL_OPEN = True
        webapp.load_token = lambda: None
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.CAPTIVE_REGISTRY_PATH = self._orig["CAPTIVE_REGISTRY_PATH"]
        webapp.AUTH_FAIL_OPEN = self._orig["AUTH_FAIL_OPEN"]
        webapp.load_token = self._orig["load_token"]
        self.tmp.cleanup()

    def test_captive_page_renders(self) -> None:
        res = self.client.get("/captive")
        self.assertEqual(res.status_code, 200)
        text = res.get_data(as_text=True)
        self.assertIn("consentForm", text)
        self.assertIn("/api/captive/register", text)

    def test_captive_register_requires_consent(self) -> None:
        res = self.client.post("/api/captive/register", json={"agree": False, "ip": "172.16.0.20"})
        self.assertEqual(res.status_code, 400)
        payload = res.get_json()
        self.assertFalse(payload["ok"])

    def test_captive_register_persists_allowlist(self) -> None:
        res = self.client.post(
            "/api/captive/register",
            json={"agree": True, "operator_name": "ops1", "mac": "aa:bb:cc:dd:ee:ff", "ip": "172.16.0.20"},
        )
        self.assertEqual(res.status_code, 200)
        payload = res.get_json()
        self.assertTrue(payload["ok"])
        saved = json.loads(webapp.CAPTIVE_REGISTRY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(saved["clients"]), 1)
        self.assertEqual(saved["clients"][0]["mac"], "aa:bb:cc:dd:ee:ff")


if __name__ == "__main__":
    unittest.main()
