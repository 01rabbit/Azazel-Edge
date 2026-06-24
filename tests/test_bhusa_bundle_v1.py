from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "bin" / "azazel-edge-bhusa-bundle"


class BhusaBundleV1Tests(unittest.TestCase):
    def test_bundle_builds_manifest_and_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "bundle"
            result = subprocess.run(
                [str(BUNDLE), "--output-dir", str(output_dir), "--json"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["document_count"], 10)
            self.assertTrue((output_dir / "INDEX.md").exists())
            self.assertTrue((output_dir / "manifest.json").exists())
            manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["documents"]), 10)
            self.assertTrue((output_dir / "docs" / "final-command-sheet.md").exists())
            self.assertTrue((output_dir / "docs" / "booth-runbook.md").exists())

    def test_bundle_requires_force_when_output_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "bundle"
            output_dir.mkdir()
            result = subprocess.run(
                [str(BUNDLE), "--output-dir", str(output_dir), "--json"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            payload = json.loads(result.stdout)
            self.assertFalse(payload["ok"])
            self.assertTrue(any("already exists" in item for item in payload["errors"]))


if __name__ == "__main__":
    unittest.main()
