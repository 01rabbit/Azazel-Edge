from __future__ import annotations

import json
import os
from pathlib import Path

from configuration import load_config
from db.repository import TopoLiteRepository
from db.schema import initialize_database
from logging_utils import configure_logging
from scanner.deep_probe import deep_probe_new_hosts


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    env_map = dict(os.environ)
    config_path = Path(env_map.get("AZAZEL_TOPO_LITE_CONFIG", WORKSPACE_ROOT / "config.yaml"))
    config = load_config(config_path if config_path.exists() else None, env=env_map)
    initialize_database(config.database_path)
    repository = TopoLiteRepository(config.database_path)
    loggers = configure_logging(config.logging)
    discovery_scan_run_id = int(env_map["AZAZEL_TOPO_LITE_DEEP_PROBE_DISCOVERY_SCAN_RUN_ID"])
    result = deep_probe_new_hosts(
        config=config,
        repository=repository,
        loggers=loggers,
        discovery_scan_run_id=discovery_scan_run_id,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["status"] in {"completed", "partial_failed", "skipped"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
