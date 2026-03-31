from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def create_backup_bundle(
    *,
    database_path: str | Path,
    config_path: str | Path | None,
    output_dir: str | Path,
) -> dict[str, Any]:
    database = Path(database_path)
    config = Path(config_path) if config_path else None
    bundle_dir = Path(output_dir) / f"topo-lite-backup-{utc_stamp()}"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    restored_paths: dict[str, str | None] = {"database": None, "config": None}
    if database.exists():
        backup_db = bundle_dir / database.name
        _sqlite_backup(database, backup_db)
        restored_paths["database"] = str(backup_db)

    if config and config.exists():
        backup_config = bundle_dir / config.name
        shutil.copy2(config, backup_config)
        restored_paths["config"] = str(backup_config)

    manifest = {
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "bundle_dir": str(bundle_dir),
        "database_backup_path": restored_paths["database"],
        "config_backup_path": restored_paths["config"],
    }
    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest


def restore_backup_bundle(
    *,
    bundle_dir: str | Path,
    restore_database_to: str | Path | None = None,
    restore_config_to: str | Path | None = None,
) -> dict[str, Any]:
    bundle = Path(bundle_dir)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    restored = {"database_restored": False, "config_restored": False}

    if restore_database_to and manifest.get("database_backup_path"):
        destination = Path(restore_database_to)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(Path(manifest["database_backup_path"]), destination)
        restored["database_restored"] = True
        restored["database_path"] = str(destination)

    if restore_config_to and manifest.get("config_backup_path"):
        destination = Path(restore_config_to)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(Path(manifest["config_backup_path"]), destination)
        restored["config_restored"] = True
        restored["config_path"] = str(destination)

    restored["bundle_dir"] = str(bundle)
    return restored


def _sqlite_backup(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(source)) as source_connection, sqlite3.connect(str(destination)) as destination_connection:
        source_connection.backup(destination_connection)
