from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Mapping

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from configuration import config_to_dict, load_config
from db.repository import TopoLiteRepository
from db.schema import initialize_database
from logging_utils import append_audit_record, configure_logging, log_event, log_exception


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def create_app(
    config_path: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Flask:
    app = Flask(__name__)
    env_map = dict(env or os.environ)
    resolved_config_path = Path(config_path or env_map.get("AZAZEL_TOPO_LITE_CONFIG", WORKSPACE_ROOT / "config.yaml"))
    config = load_config(resolved_config_path if resolved_config_path.exists() else None, env=env_map)
    initialize_database(config.database_path)
    repository = TopoLiteRepository(config.database_path)
    loggers = configure_logging(config.logging)

    log_event(
        loggers.app,
        "backend_started",
        "backend initialized",
        database_path=config.database_path,
        config_path=str(resolved_config_path),
    )
    append_audit_record(
        loggers.audit,
        "backend_startup",
        actor="system",
        database_path=config.database_path,
        config_path=str(resolved_config_path),
    )

    @app.before_request
    def before_request() -> None:
        g.request_started_at = time.perf_counter()

    @app.after_request
    def after_request(response):
        duration_ms = round((time.perf_counter() - g.request_started_at) * 1000, 2)
        log_event(
            loggers.access,
            "http_request",
            "request completed",
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            remote_addr=request.remote_addr,
            duration_ms=duration_ms,
        )
        return response

    @app.errorhandler(Exception)
    def handle_exception(error: Exception):
        if isinstance(error, HTTPException):
            return error
        log_exception(
            loggers.app,
            "unhandled_exception",
            "unhandled exception",
            path=request.path,
            method=request.method,
        )
        return jsonify({"error": "internal_server_error"}), 500

    @app.get("/health")
    def health():
        return jsonify(
            {
                "ok": True,
                "service": "azazel-topo-lite-backend",
                "database_path": config.database_path,
                "log_paths": config_to_dict(config)["logging"],
            }
        )

    @app.get("/api/ping")
    def ping():
        return jsonify({"message": "pong"})

    @app.get("/api/logs/meta")
    def logs_meta():
        return jsonify(config_to_dict(config)["logging"])

    @app.get("/api/meta")
    def meta():
        return jsonify(
            {
                "project": "Azazel-Topo-Lite",
                "workspace_root": str(WORKSPACE_ROOT),
                "config_path": str(resolved_config_path),
                "config": config_to_dict(config),
                "database": {
                    "path": config.database_path,
                    "host_count": len(repository.list_hosts()),
                    "event_count": len(repository.list_events()),
                },
                "directories": {
                    "backend": str(WORKSPACE_ROOT / "backend"),
                    "frontend": str(WORKSPACE_ROOT / "frontend"),
                    "scanner": str(WORKSPACE_ROOT / "scanner"),
                    "db": str(WORKSPACE_ROOT / "db"),
                    "docs": str(WORKSPACE_ROOT / "docs"),
                    "scripts": str(WORKSPACE_ROOT / "scripts"),
                },
            }
        )

    return app


app = create_app()


if __name__ == "__main__":
    host = os.environ.get("AZAZEL_TOPO_LITE_BACKEND_HOST", "127.0.0.1")
    port = int(os.environ.get("AZAZEL_TOPO_LITE_BACKEND_PORT", "18080"))
    app.run(host=host, port=port, debug=False, use_reloader=False)
