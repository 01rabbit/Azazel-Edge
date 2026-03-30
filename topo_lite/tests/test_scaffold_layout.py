from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from configuration import default_config
from db.schema import INITIAL_TABLES, SCHEMA_VERSION
from scanner.discovery import build_default_job


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


class ScaffoldLayoutTests(unittest.TestCase):
    def test_required_directories_exist(self) -> None:
        required = ["backend", "frontend", "scanner", "db", "docs", "scripts"]
        for name in required:
            self.assertTrue((WORKSPACE_ROOT / name).is_dir(), name)

    def test_schema_placeholder_matches_initial_issue_scope(self) -> None:
        self.assertEqual(SCHEMA_VERSION, "0.1.2")
        self.assertIn("hosts", INITIAL_TABLES)
        self.assertIn("scan_runs", INITIAL_TABLES)

    def test_discovery_job_defaults_are_lightweight(self) -> None:
        job = build_default_job()
        self.assertEqual(job.interval_seconds, 300)
        self.assertEqual(job.target_ports, [22, 80, 443])

    def test_default_config_uses_sqlite_database_path(self) -> None:
        config = default_config()
        self.assertEqual(config.database_path, "topo_lite.sqlite3")
        self.assertIn("192.168.40.0/24", config.subnets)


if __name__ == "__main__":
    unittest.main()
