from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backup_utils import create_backup_bundle, restore_backup_bundle
from db.repository import TopoLiteRepository
from db.schema import initialize_database


class BackupUtilsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.database_path = self.temp_path / "topo_lite.sqlite3"
        self.config_path = self.temp_path / "config.yaml"
        self.config_path.write_text("interface: eth0\nsubnets:\n  - 192.168.40.0/24\n", encoding="utf-8")
        initialize_database(self.database_path)
        self.repository = TopoLiteRepository(self.database_path)
        self.host = self.repository.upsert_host(ip="192.168.40.10", hostname="printer-1")
        self.repository.create_override(host_id=self.host["id"], fixed_label="managed-printer", note="known device")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_backup_bundle_contains_database_and_config(self) -> None:
        manifest = create_backup_bundle(
            database_path=self.database_path,
            config_path=self.config_path,
            output_dir=self.temp_path / "backups",
        )

        self.assertTrue(Path(manifest["bundle_dir"]).is_dir())
        self.assertTrue(Path(manifest["database_backup_path"]).is_file())
        self.assertTrue(Path(manifest["config_backup_path"]).is_file())
        self.assertTrue(Path(manifest["manifest_path"]).is_file())

    def test_restore_bundle_recovers_database_and_config(self) -> None:
        manifest = create_backup_bundle(
            database_path=self.database_path,
            config_path=self.config_path,
            output_dir=self.temp_path / "backups",
        )
        restored_db = self.temp_path / "restored.sqlite3"
        restored_config = self.temp_path / "restored-config.yaml"

        result = restore_backup_bundle(
            bundle_dir=manifest["bundle_dir"],
            restore_database_to=restored_db,
            restore_config_to=restored_config,
        )

        restored_repository = TopoLiteRepository(restored_db)
        self.assertTrue(result["database_restored"])
        self.assertTrue(result["config_restored"])
        self.assertEqual(restored_repository.list_hosts()[0]["hostname"], "printer-1")
        self.assertEqual(restored_repository.get_latest_override(self.host["id"])["fixed_label"], "managed-printer")
        self.assertEqual(restored_config.read_text(encoding="utf-8"), self.config_path.read_text(encoding="utf-8"))
