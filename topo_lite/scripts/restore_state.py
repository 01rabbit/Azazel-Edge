from __future__ import annotations

import argparse
import json
from pathlib import Path

from backup_utils import restore_backup_bundle
from configuration import load_config
from db.schema import initialize_database
from logging_utils import append_audit_record, configure_logging, log_event


def main() -> int:
    parser = argparse.ArgumentParser(description="Restore an Azazel-Topo-Lite backup bundle.")
    parser.add_argument("--config", default="config.yaml", help="Path to config YAML file")
    parser.add_argument("--bundle-dir", required=True, help="Backup bundle directory created by backup_state.py")
    parser.add_argument("--restore-db", action="store_true", help="Restore the SQLite database from the bundle")
    parser.add_argument("--restore-config", action="store_true", help="Restore the config file from the bundle")
    parser.add_argument("--init-db", action="store_true", help="Initialize an empty database after restore or when no DB backup is used")
    args = parser.parse_args()

    config = load_config(args.config)
    loggers = configure_logging(config.logging)
    restored = restore_backup_bundle(
        bundle_dir=args.bundle_dir,
        restore_database_to=config.database_path if args.restore_db else None,
        restore_config_to=args.config if args.restore_config else None,
    )
    if args.init_db:
        initialize_database(config.database_path)
        restored["initialized_database"] = str(Path(config.database_path))

    append_audit_record(
        loggers.audit,
        "backup_restored",
        actor="operator",
        bundle_dir=restored["bundle_dir"],
        database_restored=restored["database_restored"],
        config_restored=restored["config_restored"],
        initialized_database=restored.get("initialized_database"),
    )
    log_event(
        loggers.app,
        "restore_completed",
        "backup bundle restored",
        bundle_dir=restored["bundle_dir"],
        database_restored=restored["database_restored"],
        config_restored=restored["config_restored"],
        initialized_database=restored.get("initialized_database"),
    )
    print(json.dumps(restored, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
