from __future__ import annotations

import importlib
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from azazel_edge.path_schema import first_minute_config_candidates
from azazel_edge.tactics_engine.config_hash import ConfigHash


class PathConfigContractV1Tests(unittest.TestCase):
    def test_control_socket_env_override_keeps_default_when_unset(self) -> None:
        import azazel_edge.control_plane as control_plane

        with patch.dict(os.environ, {}, clear=True):
            reloaded = importlib.reload(control_plane)
            self.assertEqual(reloaded.CONTROL_SOCKET, Path("/run/azazel-edge/control.sock"))

        with patch.dict(os.environ, {"AZAZEL_CONTROL_SOCKET": "/tmp/azazel-control.sock"}, clear=False):
            reloaded = importlib.reload(control_plane)
            self.assertEqual(reloaded.CONTROL_SOCKET, Path("/tmp/azazel-control.sock"))

        importlib.reload(control_plane)

    def test_config_hash_uses_path_schema_first_minute_candidates(self) -> None:
        candidates = first_minute_config_candidates(schema="v2")
        with patch("azazel_edge.tactics_engine.config_hash.Path.exists", return_value=False), patch(
            "azazel_edge.tactics_engine.config_hash.first_minute_config_candidates",
            return_value=candidates,
        ) as mocked:
            digest = ConfigHash.compute()

        self.assertTrue(digest.startswith("sha256:"))
        mocked.assert_called_once_with(schema="v2")


if __name__ == "__main__":
    unittest.main()
