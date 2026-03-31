from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from configuration import config_to_dict, load_config
from db.schema import fetch_schema_version, initialize_database, list_tables
from db import connect_db
from logging_utils import append_audit_record, configure_logging, log_event


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize the Azazel-Topo-Lite SQLite database.")
    parser.add_argument(
        "--config",
        default=os.environ.get("AZAZEL_TOPO_LITE_CONFIG", "config.yaml"),
        help="Path to config YAML file",
    )
    parser.add_argument("--db-path", default=None, help="Override the configured database path")
    args = parser.parse_args()

    config = load_config(args.config)
    database_path = Path(args.db_path or config.database_path)
    loggers = configure_logging(config.logging)

    log_event(
        loggers.app,
        "init_db_started",
        "database initialization started",
        database_path=str(database_path),
        config_path=args.config,
    )
    initialize_database(database_path)

    with connect_db(database_path) as connection:
        payload = {
            "database_path": str(database_path.resolve()),
            "schema_version": fetch_schema_version(connection),
            "tables": list_tables(connection),
            "config": config_to_dict(config),
        }
    append_audit_record(
        loggers.audit,
        "initialize_database",
        actor="operator",
        database_path=str(database_path.resolve()),
        table_count=len(payload["tables"]),
        schema_version=payload["schema_version"],
    )
    log_event(
        loggers.app,
        "init_db_completed",
        "database initialization completed",
        database_path=str(database_path.resolve()),
        table_count=len(payload["tables"]),
    )
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
