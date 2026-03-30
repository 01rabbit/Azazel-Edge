from __future__ import annotations

import os
import json
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
BACKEND_PORT = os.environ.get("AZAZEL_TOPO_LITE_BACKEND_PORT", "18080")
FRONTEND_PORT = os.environ.get("AZAZEL_TOPO_LITE_FRONTEND_PORT", "18081")
BACKEND_HOST = os.environ.get("AZAZEL_TOPO_LITE_BACKEND_HOST", "127.0.0.1")
FRONTEND_HOST = os.environ.get("AZAZEL_TOPO_LITE_FRONTEND_HOST", "127.0.0.1")


def _pick_port(preferred: str, reserved: set[int] | None = None) -> int:
    start = int(preferred)
    reserved = reserved or set()
    for port in range(start, start + 50):
        if port in reserved:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise RuntimeError(f"no free port found near {start}")


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    backend_port = _pick_port(BACKEND_PORT)
    frontend_port = _pick_port(FRONTEND_PORT, reserved={backend_port})

    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(WORKSPACE_ROOT))
    env["AZAZEL_TOPO_LITE_BACKEND_PORT"] = str(backend_port)
    env["AZAZEL_TOPO_LITE_BACKEND_HOST"] = BACKEND_HOST

    runtime_config_path = WORKSPACE_ROOT / "frontend" / "runtime-config.json"
    runtime_config_path.write_text(
        json.dumps(
            {
                "backendPort": backend_port,
                "frontendPort": frontend_port,
                "frontendHost": FRONTEND_HOST,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    backend = subprocess.Popen(
        [sys.executable, "-m", "backend.app"],
        cwd=WORKSPACE_ROOT,
        env=env,
    )
    frontend = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "http.server",
            str(frontend_port),
            "--bind",
            FRONTEND_HOST,
            "--directory",
            str(WORKSPACE_ROOT / "frontend"),
        ],
        cwd=WORKSPACE_ROOT,
        env=env,
    )

    print(f"Azazel-Topo-Lite API: http://{BACKEND_HOST}:{backend_port}")
    print(f"Azazel-Topo-Lite UI:  http://{FRONTEND_HOST}:{frontend_port}")
    print("Press Ctrl-C to stop both processes.")

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
            time.sleep(0.2)
    except KeyboardInterrupt:
        return 0
    finally:
        _terminate(frontend)
        _terminate(backend)


if __name__ == "__main__":
    raise SystemExit(main())
