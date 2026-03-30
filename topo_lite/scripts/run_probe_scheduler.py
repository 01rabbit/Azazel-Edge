from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path

from configuration import load_config
from db.repository import TopoLiteRepository
from db.schema import initialize_database
from logging_utils import configure_logging
from scanner.probe_scheduler import ProbeScheduler, ProbeSchedulerLockError


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    env_map = dict(os.environ)
    config_path = Path(env_map.get("AZAZEL_TOPO_LITE_CONFIG", WORKSPACE_ROOT / "config.yaml"))
    config = load_config(config_path if config_path.exists() else None, env=env_map)
    initialize_database(config.database_path)
    repository = TopoLiteRepository(config.database_path)
    loggers = configure_logging(config.logging)
    max_runs = int(env_map["AZAZEL_TOPO_LITE_PROBE_SCHEDULER_MAX_RUNS"]) if "AZAZEL_TOPO_LITE_PROBE_SCHEDULER_MAX_RUNS" in env_map else None
    lock_path = env_map.get("AZAZEL_TOPO_LITE_PROBE_SCHEDULER_LOCK_PATH", "run/probe_scheduler.lock")
    scheduler = ProbeScheduler(
        config=config,
        repository=repository,
        loggers=loggers,
        lock_path=lock_path,
    )
    scheduler.install_signal_handlers()
    try:
        result = scheduler.run_forever(max_runs=max_runs)
    except ProbeSchedulerLockError as error:
        print(json.dumps({"status": "locked", "error": str(error)}, indent=2, ensure_ascii=False))
        return 1
    print(json.dumps(asdict(result), indent=2, ensure_ascii=False))
    return 0 if result.status == "stopped" else 1


if __name__ == "__main__":
    raise SystemExit(main())
