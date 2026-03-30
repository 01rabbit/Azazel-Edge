from __future__ import annotations

import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from configuration import load_config
from exposure import evaluate_remote_access
from logging_utils import append_audit_record, configure_logging, log_event


class FrontendRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, directory: str | None = None, **kwargs):
        self._loggers = kwargs.pop("loggers")
        self._exposure = kwargs.pop("exposure")
        super().__init__(*args, directory=directory, **kwargs)

    def do_GET(self) -> None:
        if not self._allow_request():
            return
        super().do_GET()

    def do_HEAD(self) -> None:
        if not self._allow_request():
            return
        super().do_HEAD()

    def log_message(self, format: str, *args) -> None:
        log_event(
            self._loggers.access,
            "frontend_http_request",
            "frontend request completed",
            remote_addr=self.client_address[0],
            path=self.path,
            access_log=format % args,
        )

    def _allow_request(self) -> bool:
        remote_addr = self.client_address[0]
        access = evaluate_remote_access(remote_addr, self._exposure)
        if access.allowed:
            return True

        append_audit_record(
            self._loggers.audit,
            "frontend_access_denied",
            actor="anonymous",
            path=self.path,
            method=self.command,
            remote_addr=remote_addr,
            reason=access.reason,
        )
        self.send_error(403, "client address is not allowed")
        return False


def main() -> int:
    env = os.environ.copy()
    config_path = Path(env.get("AZAZEL_TOPO_LITE_CONFIG", WORKSPACE_ROOT / "config.yaml"))
    config = load_config(config_path if config_path.exists() else None, env=env)
    loggers = configure_logging(config.logging)

    host = env.get("AZAZEL_TOPO_LITE_FRONTEND_HOST", config.exposure.frontend_bind_host)
    port = int(env.get("AZAZEL_TOPO_LITE_FRONTEND_PORT", "18081"))
    frontend_dir = str(WORKSPACE_ROOT / "frontend")

    def factory(*args, **kwargs):
        return FrontendRequestHandler(
            *args,
            directory=frontend_dir,
            loggers=loggers,
            exposure=config.exposure,
            **kwargs,
        )

    server = ThreadingHTTPServer((host, port), factory)
    log_event(
        loggers.app,
        "frontend_started",
        "frontend server initialized",
        bind_host=host,
        bind_port=port,
        frontend_dir=frontend_dir,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
