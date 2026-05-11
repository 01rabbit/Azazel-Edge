from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


class EpdCliHelpV1Tests(unittest.TestCase):
    def test_epd_cli_help_returns_zero(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "py" / "azazel_edge_epd.py"
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True,
            text=True,
            cwd=str(repo_root),
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Azazel EPD Controller", result.stdout)
        self.assertIn("--signal", result.stdout)


if __name__ == "__main__":
    unittest.main()
