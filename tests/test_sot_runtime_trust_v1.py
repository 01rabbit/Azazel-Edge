from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.sot import load_sot_file
from azazel_edge_control import daemon as control_daemon


class SoTRuntimeTrustV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._sot_cache = json.loads(json.dumps(control_daemon._SOT_CACHE, ensure_ascii=False))
        self._noc_cache = json.loads(json.dumps(control_daemon._NOC_CACHE, ensure_ascii=False))
        self._snapshot_cache = {
            "ts": float(control_daemon._SNAPSHOT_CACHE.get("ts") or 0.0),
            "payload": control_daemon._SNAPSHOT_CACHE.get("payload"),
        }

    def tearDown(self) -> None:
        with control_daemon.SOT_CACHE_LOCK:
            control_daemon._SOT_CACHE.clear()
            control_daemon._SOT_CACHE.update(self._sot_cache)
        with control_daemon.NOC_CACHE_LOCK:
            control_daemon._NOC_CACHE.clear()
            control_daemon._NOC_CACHE.update(self._noc_cache)
        with control_daemon.SNAPSHOT_CACHE_LOCK:
            control_daemon._SNAPSHOT_CACHE.clear()
            control_daemon._SNAPSHOT_CACHE.update(self._snapshot_cache)

    def test_execute_action_trust_creates_sot_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sot.json"
            with patch.dict(
                os.environ,
                {"AZAZEL_SOT_PATH": str(path)},
                clear=False,
            ), patch.object(control_daemon, "_sot_target_path", return_value=path), patch.object(
                control_daemon,
                "read_ui_snapshot",
                return_value={"ok": True},
            ):
                result = control_daemon.execute_action(
                    "sot_trust_client",
                    {
                        "trusted": True,
                        "session_key": "aa:bb:cc:dd:ee:02",
                        "ip": "192.168.40.21",
                        "mac": "aa:bb:cc:dd:ee:02",
                        "hostname": "unknown-client",
                        "interface_or_segment": "lan-main",
                        "expected_interface_or_segment": "eth0",
                        "note": "known kiosk",
                        "allowed_networks": "lan-main,guest-lan",
                    },
                )
                sot = load_sot_file(path).to_dict()

        self.assertTrue(result["ok"])
        self.assertTrue(result["trusted"])
        self.assertEqual(result["device"]["hostname"], "unknown-client")
        self.assertEqual(len(sot["devices"]), 1)
        self.assertEqual(sot["devices"][0]["mac"], "aa:bb:cc:dd:ee:02")
        self.assertTrue(sot["devices"][0]["authorized"])
        self.assertEqual(sot["devices"][0]["expected_interface_or_segment"], "eth0")
        self.assertEqual(sot["devices"][0]["notes"], "known kiosk")
        self.assertEqual(sot["devices"][0]["allowed_networks"], ["guest-lan", "lan-main"])

    def test_execute_action_trust_updates_existing_device_authorization(self) -> None:
        seed = {
            "devices": [
                {
                    "id": "unknown-client",
                    "hostname": "unknown-client",
                    "ip": "192.168.40.21",
                    "mac": "aa:bb:cc:dd:ee:02",
                    "criticality": "standard",
                    "allowed_networks": [],
                    "authorized": True,
                }
            ],
            "networks": [],
            "services": [],
            "expected_paths": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sot.json"
            path.write_text(json.dumps(seed), encoding="utf-8")
            with patch.dict(os.environ, {"AZAZEL_SOT_PATH": str(path)}, clear=False), patch.object(
                control_daemon,
                "_sot_target_path",
                return_value=path,
            ), patch.object(
                control_daemon,
                "read_ui_snapshot",
                return_value={"ok": True},
            ):
                result = control_daemon.execute_action(
                    "sot_trust_client",
                    {
                        "trusted": False,
                        "session_key": "aa:bb:cc:dd:ee:02",
                        "ip": "192.168.40.21",
                        "mac": "aa:bb:cc:dd:ee:02",
                        "hostname": "unknown-client",
                    },
                )
                sot = load_sot_file(path).to_dict()

        self.assertTrue(result["ok"])
        self.assertFalse(result["trusted"])
        self.assertEqual(len(sot["devices"]), 1)
        self.assertFalse(sot["devices"][0]["authorized"])

    def test_execute_action_trust_rejects_public_ip_without_mac(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sot.json"
            with patch.dict(
                os.environ,
                {"AZAZEL_SOT_PATH": str(path)},
                clear=False,
            ), patch.object(control_daemon, "_sot_target_path", return_value=path), patch.object(
                control_daemon,
                "read_ui_snapshot",
                return_value={"ok": True},
            ):
                result = control_daemon.execute_action(
                    "sot_trust_client",
                    {
                        "trusted": True,
                        "session_key": "8.8.8.8",
                        "ip": "8.8.8.8",
                        "hostname": "public-only",
                    },
                )

        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "trust_requires_mac_or_private_ip")

    def test_execute_action_trust_can_ignore_client_view_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sot.json"
            with patch.dict(
                os.environ,
                {"AZAZEL_SOT_PATH": str(path)},
                clear=False,
            ), patch.object(control_daemon, "_sot_target_path", return_value=path), patch.object(
                control_daemon,
                "read_ui_snapshot",
                return_value={"ok": True},
            ):
                result = control_daemon.execute_action(
                    "sot_trust_client",
                    {
                        "trusted": False,
                        "ignored": True,
                        "session_key": "aa:bb:cc:dd:ee:77",
                        "ip": "172.16.0.77",
                        "mac": "aa:bb:cc:dd:ee:77",
                        "hostname": "transit-switch",
                    },
                )
                sot = load_sot_file(path).to_dict()

        self.assertTrue(result["ok"])
        self.assertEqual(result["device"]["monitoring_scope"], "ignore")
        self.assertFalse(result["device"]["authorized"])
        self.assertEqual(sot["devices"][0]["monitoring_scope"], "ignore")

    def test_execute_action_trust_bootstraps_managed_networks_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sot.json"
            with patch.dict(
                os.environ,
                {
                    "AZAZEL_SOT_PATH": str(path),
                    "AZAZEL_MANAGED_CLIENT_CIDRS": "172.16.0.0/24",
                },
                clear=False,
            ), patch.object(control_daemon, "_sot_target_path", return_value=path), patch.object(
                control_daemon,
                "read_ui_snapshot",
                return_value={"ok": True},
            ):
                result = control_daemon.execute_action(
                    "sot_trust_client",
                    {
                        "trusted": True,
                        "session_key": "aa:bb:cc:dd:ee:21",
                        "ip": "172.16.0.21",
                        "mac": "aa:bb:cc:dd:ee:21",
                        "hostname": "internal-client",
                    },
                )
                sot = load_sot_file(path).to_dict()

        self.assertTrue(result["ok"])
        self.assertEqual(sot["networks"][0]["cidr"], "172.16.0.0/24")
        self.assertEqual(sot["devices"][0]["allowed_networks"], ["managed-lan"])


if __name__ == "__main__":
    unittest.main()
