from __future__ import annotations

import unittest

import azazel_edge_web.app as webapp


class OpsCommDemoUiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_load_token = webapp.load_token
        webapp.load_token = lambda: None
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.load_token = self._orig_load_token

    def test_ops_comm_renders_demo_runner(self) -> None:
        response = self.client.get("/ops-comm")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("Demo Runner", text)
        self.assertIn("Run Demo", text)
        self.assertIn("Clear Overlay", text)
        self.assertIn("demoScenarioSelect", text)


if __name__ == "__main__":
    unittest.main()
