from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import azazel_edge_web.app as webapp


class SotApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.sot_path = root / "sot.json"
        self.audit_path = root / "sot-events.jsonl"
        self.sot_path.write_text(
            json.dumps(
                {
                    "devices": [
                        {
                            "id": "dev-1",
                            "hostname": "client-1",
                            "ip": "172.16.0.10",
                            "mac": "aa:bb:cc:dd:ee:10",
                            "criticality": "normal",
                            "allowed_networks": ["lan-main"],
                        }
                    ],
                    "networks": [
                        {
                            "id": "lan-main",
                            "cidr": "172.16.0.0/24",
                            "zone": "lan",
                            "gateway": "172.16.0.1",
                        }
                    ],
                    "services": [
                        {
                            "id": "svc-dns",
                            "proto": "udp",
                            "port": 53,
                            "owner": "noc",
                            "exposure": "internal",
                        }
                    ],
                    "expected_paths": [
                        {
                            "src": "lan-main",
                            "dst": "wan",
                            "service_id": "svc-dns",
                            "via": "edge",
                            "policy": "allow",
                        }
                    ],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        self._orig = {
            "load_token": webapp.load_token,
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "SOT_AUDIT_LOG": webapp.SOT_AUDIT_LOG,
            "send_control_command": webapp.send_control_command,
            "AZAZEL_SOT_PATH": webapp.os.environ.get("AZAZEL_SOT_PATH"),
        }
        webapp.load_token = lambda: None
        webapp.AUTH_FAIL_OPEN = True
        webapp.SOT_AUDIT_LOG = self.audit_path
        self._captured_actions: list[str] = []

        def _fake_send(action: str) -> dict:
            self._captured_actions.append(action)
            return {"ok": True, "action": action}

        webapp.send_control_command = _fake_send
        webapp.os.environ["AZAZEL_SOT_PATH"] = str(self.sot_path)
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.load_token = self._orig["load_token"]
        webapp.AUTH_FAIL_OPEN = self._orig["AUTH_FAIL_OPEN"]
        webapp.SOT_AUDIT_LOG = self._orig["SOT_AUDIT_LOG"]
        webapp.send_control_command = self._orig["send_control_command"]
        if self._orig["AZAZEL_SOT_PATH"] is None:
            webapp.os.environ.pop("AZAZEL_SOT_PATH", None)
        else:
            webapp.os.environ["AZAZEL_SOT_PATH"] = self._orig["AZAZEL_SOT_PATH"]
        self.tmp.cleanup()

    def test_put_replaces_devices_and_triggers_refresh(self) -> None:
        response = self.client.put(
            "/api/sot/devices",
            json={
                "devices": [
                    {
                        "id": "dev-2",
                        "hostname": "client-2",
                        "ip": "172.16.0.20",
                        "mac": "aa:bb:cc:dd:ee:20",
                        "criticality": "high",
                        "allowed_networks": ["lan-main"],
                    }
                ]
            },
            headers={"X-AZAZEL-ACTOR": "operator:alice"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["diff"]["added"], 1)
        self.assertEqual(payload["diff"]["removed"], 1)
        self.assertIn("refresh", self._captured_actions)

        saved = json.loads(self.sot_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["devices"][0]["id"], "dev-2")

        rows = [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[-1]["kind"], "sot_devices_replaced")
        self.assertEqual(rows[-1]["actor"], "operator:alice")
        self.assertIn("remote_addr", rows[-1])

    def test_patch_merges_existing_device(self) -> None:
        response = self.client.patch(
            "/api/sot/devices",
            json={
                "devices": [
                    {
                        "id": "dev-1",
                        "hostname": "client-1-new",
                        "criticality": "high",
                    }
                ]
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["diff"]["updated"], 1)

        saved = json.loads(self.sot_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["devices"][0]["hostname"], "client-1-new")
        self.assertEqual(saved["devices"][0]["criticality"], "high")
        self.assertEqual(saved["devices"][0]["ip"], "172.16.0.10")

    def test_put_rejects_invalid_schema(self) -> None:
        response = self.client.put(
            "/api/sot/devices",
            json={"devices": [{"id": "broken"}]},
        )
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertFalse(payload["ok"])
        self.assertIn("invalid_sot", payload["error"])


if __name__ == "__main__":
    unittest.main()
