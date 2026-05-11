from __future__ import annotations

import unittest

import azazel_edge_web.app as webapp


class OpsCommDemoUiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_load_token = webapp.load_token
        self._orig_auth_fail_open = webapp.AUTH_FAIL_OPEN
        webapp.load_token = lambda: None
        webapp.AUTH_FAIL_OPEN = True
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.load_token = self._orig_load_token
        webapp.AUTH_FAIL_OPEN = self._orig_auth_fail_open

    def test_ops_comm_renders_demo_runner(self) -> None:
        response = self.client.get("/ops-comm?lang=en")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("Demo Runner", text)
        self.assertIn("Run Demo", text)
        self.assertIn("Clear Overlay", text)
        self.assertIn("demoScenarioSelect", text)
        self.assertIn("Triage Navigator", text)
        self.assertIn("triageClassifyBtn", text)
        self.assertIn("triageSessionCard", text)
        self.assertIn("triageHandoffBtn", text)
        self.assertIn("Triage Audit", text)
        self.assertIn("triageAuditList", text)


if __name__ == "__main__":
    unittest.main()
