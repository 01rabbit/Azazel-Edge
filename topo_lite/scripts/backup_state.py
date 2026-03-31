from __future__ import annotations

import argparse
import json
from pathlib import Path

from backup_utils import create_backup_bundle
from configuration import load_config
from logging_utils import append_audit_record, configure_logging, log_event


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an Azazel-Topo-Lite backup bundle.")
    parser.add_argument("--config", default="config.yaml", help="Path to config YAML file")
    parser.add_argument("--output-dir", default="backups", help="Directory where backup bundles are created")
    args = parser.parse_args()

    config = load_config(args.config)
    loggers = configure_logging(config.logging)
    manifest = create_backup_bundle(
        database_path=config.database_path,
        config_path=args.config,
        output_dir=args.output_dir,
    )
    append_audit_record(
        loggers.audit,
        "backup_created",
        actor="operator",
        bundle_dir=manifest["bundle_dir"],
        database_backup_path=manifest["database_backup_path"],
        config_backup_path=manifest["config_backup_path"],
    )
    log_event(
        loggers.app,
        "backup_completed",
        "backup bundle created",
        bundle_dir=manifest["bundle_dir"],
    )
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
