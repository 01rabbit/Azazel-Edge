from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from configuration import load_config
from db.repository import TopoLiteRepository
from db.schema import initialize_database
from sample_seed import seed_internal_lan_story


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed deterministic internal-LAN sample data for Azazel-Topo-Lite.")
    parser.add_argument(
        "--config",
        default=os.environ.get("AZAZEL_TOPO_LITE_CONFIG", str(WORKSPACE_ROOT / "config.yaml")),
        help="Path to config YAML file",
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    env_map = dict(os.environ)
    config = load_config(config_path if config_path.exists() else None, env=env_map)
    initialize_database(config.database_path)
    repository = TopoLiteRepository(config.database_path)
    payload = seed_internal_lan_story(repository)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
