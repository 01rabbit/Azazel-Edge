from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class TopoLiteBoardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        token_path = Path(self.tmp.name) / "web_token.txt"
        token_path.write_text("secret-token", encoding="utf-8")
        self._orig = {
            "TOKEN_FILE": webapp.TOKEN_FILE,
            "_topo_lite_board_payload": webapp._topo_lite_board_payload,
        }
        webapp.TOKEN_FILE = token_path
        webapp._topo_lite_board_payload = lambda: {
            "ok": True,
            "status": "synthetic",
            "summary": "Synthetic internal-LAN story is active.",
            "topo_lite": {
                "config": {"interface": "br0", "subnets": ["172.16.0.0/24"], "auth_enabled": False},
                "data_mode": {"synthetic": True, "label": "Synthetic internal LAN sample", "scenario": "internal_lan_story_v1"},
                "counts": {"host_total": 6, "service_total": 11, "event_total": 6, "high_events": 2, "medium_events": 2, "low_events": 2, "subnet_total": 1, "network_device_count": 2, "server_count": 1, "unknown_count": 0},
                "severity_counts": {"high": 2, "medium": 2, "low": 2, "info": 0},
                "subnets": [{"subnet": "172.16.0.0/24", "service_count": 11, "hosts": []}],
                "high_events": [{"event_type": "service_added", "severity": "high", "summary": "service added", "created_at": "2026-04-01T00:18:00Z", "host": {"hostname": "fileserver-01", "ip": "172.16.0.80"}}],
                "recent_events": [],
                "scan_runs": [{"scan_kind": "service_probe", "status": "completed", "started_at": "2026-04-01T00:12:00Z"}],
                "freshness": {"started_at": "2026-04-01T00:12:00Z"},
                "ai_support": {"prompts": ["Review high-severity changes first."], "caveats": ["Synthetic mode is validation-only."]},
            },
        }
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.TOKEN_FILE = self._orig["TOKEN_FILE"]
        webapp._topo_lite_board_payload = self._orig["_topo_lite_board_payload"]
        self.tmp.cleanup()

    def test_board_page_renders(self) -> None:
        response = self.client.get("/topo-lite")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Internal LAN Situation Board", html)
        self.assertIn("topo_lite_board.js", html)

    def test_board_api_requires_token(self) -> None:
        response = self.client.get("/api/topo-lite/board")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"ok": False, "error": "Unauthorized"})

    def test_board_api_returns_payload_with_valid_token(self) -> None:
        response = self.client.get("/api/topo-lite/board", headers={"X-Auth-Token": "secret-token"})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["topo_lite"]["config"]["interface"], "br0")
        self.assertTrue(payload["topo_lite"]["data_mode"]["synthetic"])


if __name__ == "__main__":
    unittest.main()
