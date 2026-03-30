from __future__ import annotations

import json
import os
from pathlib import Path

from configuration import load_config
from db.repository import TopoLiteRepository
from db.schema import initialize_database
from diff_engine import generate_inventory_diff


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    env_map = dict(os.environ)
    config_path = Path(env_map.get("AZAZEL_TOPO_LITE_CONFIG", WORKSPACE_ROOT / "config.yaml"))
    config = load_config(config_path if config_path.exists() else None, env=env_map)
    initialize_database(config.database_path)
    repository = TopoLiteRepository(config.database_path)
    missing_threshold_runs = int(env_map.get("AZAZEL_TOPO_LITE_MISSING_THRESHOLD_RUNS", "2"))
    result = generate_inventory_diff(repository, missing_threshold_runs=missing_threshold_runs)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
