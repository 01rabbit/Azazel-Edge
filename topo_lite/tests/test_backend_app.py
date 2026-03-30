from __future__ import annotations

import unittest

from backend.app import create_app


class BackendAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app()
        self.client = self.app.test_client()

    def test_health_endpoint(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["ok"], True)

    def test_meta_endpoint_lists_workspace_directories(self) -> None:
        response = self.client.get("/api/meta")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["project"], "Azazel-Topo-Lite")
        self.assertIn("backend", payload["directories"])
        self.assertIn("scanner", payload["directories"])


if __name__ == "__main__":
    unittest.main()

