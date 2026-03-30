from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/health")
    def health():
        return jsonify({"ok": True, "service": "azazel-topo-lite-backend"})

    @app.get("/api/ping")
    def ping():
        return jsonify({"message": "pong"})

    @app.get("/api/meta")
    def meta():
        return jsonify(
            {
                "project": "Azazel-Topo-Lite",
                "workspace_root": str(WORKSPACE_ROOT),
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

