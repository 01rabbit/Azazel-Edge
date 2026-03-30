from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from configuration import load_config


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def main() -> int:
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(WORKSPACE_ROOT))
    config_path = Path(env.get("AZAZEL_TOPO_LITE_CONFIG", WORKSPACE_ROOT / "config.yaml"))
    config = load_config(config_path if config_path.exists() else None, env=env)

    backend_host = env.get("AZAZEL_TOPO_LITE_BACKEND_HOST", config.exposure.backend_bind_host)
    backend_port = int(env.get("AZAZEL_TOPO_LITE_BACKEND_PORT", "18080"))
    frontend_host = env.get("AZAZEL_TOPO_LITE_FRONTEND_HOST", config.exposure.frontend_bind_host)
    frontend_port = int(env.get("AZAZEL_TOPO_LITE_FRONTEND_PORT", "18081"))

    runtime_config_path = WORKSPACE_ROOT / "frontend" / "runtime-config.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "backendPort": backend_port,
                "frontendPort": frontend_port,
                "frontendHost": frontend_host,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    env["AZAZEL_TOPO_LITE_BACKEND_HOST"] = backend_host
    env["AZAZEL_TOPO_LITE_BACKEND_PORT"] = str(backend_port)
    env["AZAZEL_TOPO_LITE_FRONTEND_HOST"] = frontend_host
    env["AZAZEL_TOPO_LITE_FRONTEND_PORT"] = str(frontend_port)

    backend = subprocess.Popen(
        [sys.executable, "-m", "backend.app"],
        cwd=WORKSPACE_ROOT,
        env=env,
    )
    frontend = subprocess.Popen(
        [sys.executable, "scripts/serve_frontend.py"],
        cwd=WORKSPACE_ROOT,
        env=env,
    )

    def handle_signal(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        while True:
            if backend.poll() is not None:
                return backend.returncode or 1
            if frontend.poll() is not None:
                return frontend.returncode or 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 0
    finally:
        _terminate(frontend)
        _terminate(backend)


if __name__ == "__main__":
    raise SystemExit(main())
