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

    def test_inventory_and_host_detail_pages_exist(self) -> None:
        self.assertTrue((WORKSPACE_ROOT / "frontend" / "index.html").is_file())
        self.assertTrue((WORKSPACE_ROOT / "frontend" / "host.html").is_file())
        self.assertTrue((WORKSPACE_ROOT / "frontend" / "events.html").is_file())
        self.assertTrue((WORKSPACE_ROOT / "frontend" / "topology.html").is_file())

    def test_systemd_assets_exist(self) -> None:
        systemd_dir = WORKSPACE_ROOT / "systemd"
        self.assertTrue((systemd_dir / "azazel-topo-lite-api.service").is_file())
        self.assertTrue((systemd_dir / "azazel-topo-lite-scanner.service").is_file())
        self.assertTrue((systemd_dir / "azazel-topo-lite-scheduler.service").is_file())
        self.assertTrue((systemd_dir / "azazel-topo-lite.env.example").is_file())
        self.assertTrue((WORKSPACE_ROOT / "scripts" / "run_web_stack.py").is_file())
        self.assertTrue((WORKSPACE_ROOT / "scripts" / "run_probe_scheduler.py").is_file())

    def test_systemd_units_include_environment_file_and_install_section(self) -> None:
        for name in [
            "azazel-topo-lite-api.service",
            "azazel-topo-lite-scanner.service",
            "azazel-topo-lite-scheduler.service",
        ]:
            text = (WORKSPACE_ROOT / "systemd" / name).read_text(encoding="utf-8")
            self.assertIn("EnvironmentFile=-/etc/default/azazel-topo-lite", text)
            self.assertIn("ExecStart=", text)
            self.assertIn("WantedBy=multi-user.target", text)

    def test_schema_placeholder_matches_initial_issue_scope(self) -> None:
        self.assertEqual(SCHEMA_VERSION, "0.1.3")
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
