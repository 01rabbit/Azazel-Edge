from __future__ import annotations

import ipaddress
import os
import time
from pathlib import Path
from typing import Any
from typing import Mapping

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import BadRequest, HTTPException, NotFound

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
            if request.path.startswith("/api/"):
                return jsonify({"error": error.name.lower().replace(" ", "_"), "message": error.description}), error.code
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

    @app.get("/api/hosts")
    def hosts():
        host_rows = repository.list_hosts()
        classifications = {
            int(item["host_id"]): item
            for item in repository.list_classifications()
        }
        overrides = {
            int(item["host_id"]): item
            for item in repository.list_overrides()
        }

        items = []
        for row in host_rows:
            host_id = int(row["id"])
            classification = classifications.get(host_id)
            override = overrides.get(host_id)
            item = {
                **row,
                "role": classification["label"] if classification else None,
                "confidence": classification["confidence"] if classification else None,
                "override": override,
            }
            items.append(item)

        query = request.args.get("q", "").strip().lower()
        if query:
            items = [
                item
                for item in items
                if query in str(item["ip"]).lower()
                or query in str(item.get("hostname") or "").lower()
                or query in str(item.get("role") or "").lower()
            ]

        role = request.args.get("role")
        if role:
            items = [item for item in items if item.get("role") == role]

        status = request.args.get("status")
        if status:
            items = [item for item in items if item.get("status") == status]

        sort_field = request.args.get("sort", "id")
        sort_reverse = request.args.get("order", "asc").lower() == "desc"
        sort_key_map = {
            "id": lambda item: int(item["id"]),
            "ip": lambda item: str(item["ip"]),
            "hostname": lambda item: str(item.get("hostname") or ""),
            "last_seen": lambda item: str(item.get("last_seen") or ""),
            "status": lambda item: str(item.get("status") or ""),
            "role": lambda item: str(item.get("role") or ""),
        }
        if sort_field not in sort_key_map:
            raise BadRequest("invalid sort field")
        items = sorted(items, key=sort_key_map[sort_field], reverse=sort_reverse)

        return jsonify(_paginate(items))

    @app.get("/api/hosts/<int:host_id>")
    def host_detail(host_id: int):
        host = repository.get_host(host_id)
        if host is None:
            raise NotFound(f"host {host_id} not found")
        classification = repository.get_classification(host_id)
        override = repository.get_latest_override(host_id)
        payload = {
            **host,
            "classification": classification,
            "override": override,
            "services": repository.list_services(host_id),
            "events": [item for item in repository.list_events() if item.get("host_id") == host_id],
            "observations": repository.list_observations(host_id),
        }
        return jsonify(payload)

    @app.get("/api/services")
    def services():
        host_id = request.args.get("host_id", type=int)
        state = request.args.get("state")
        items = repository.list_services(host_id)
        if state:
            items = [item for item in items if item["state"] == state]
        return jsonify(_paginate(items))

    @app.get("/api/events")
    def events():
        items = repository.list_events()
        severity = request.args.get("severity")
        if severity:
            items = [item for item in items if item["severity"] == severity]
        event_type = request.args.get("event_type")
        if event_type:
            items = [item for item in items if item["event_type"] == event_type]
        host_id = request.args.get("host_id", type=int)
        if host_id is not None:
            items = [item for item in items if item.get("host_id") == host_id]
        items = sorted(items, key=lambda item: int(item["id"]), reverse=True)
        return jsonify(_paginate(items))

    @app.get("/api/topology")
    def topology():
        hosts = repository.list_hosts()
        classifications = {
            int(item["host_id"]): item
            for item in repository.list_classifications()
        }
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        subnet_ids: set[str] = set()

        for host in hosts:
            host_id = int(host["id"])
            ip = str(host["ip"])
            subnet = _match_subnet(ip, config.subnets)
            subnet_id = f"subnet:{subnet}" if subnet else "subnet:unknown"
            if subnet_id not in subnet_ids:
                subnet_ids.add(subnet_id)
                nodes.append({"id": subnet_id, "type": "subnet", "label": subnet or "unknown"})

            host_type = "gateway" if ip.endswith(".1") else "host"
            nodes.append(
                {
                    "id": f"host:{host_id}",
                    "type": host_type,
                    "label": host.get("hostname") or ip,
                    "ip": ip,
                    "role": classifications.get(host_id, {}).get("label"),
                    "status": host.get("status"),
                }
            )
            edges.append(
                {
                    "id": f"belongs_to:{subnet_id}:host:{host_id}",
                    "source": f"host:{host_id}",
                    "target": subnet_id,
                    "type": "belongs_to",
                }
            )
            for service in repository.list_services(host_id):
                if service["state"] != "open":
                    continue
                service_id = f"service:{host_id}:{service['proto']}:{service['port']}"
                nodes.append(
                    {
                        "id": service_id,
                        "type": "service",
                        "label": f"{service['proto']}/{service['port']}",
                        "state": service["state"],
                    }
                )
                edges.append(
                    {
                        "id": f"exposes:{host_id}:{service['proto']}:{service['port']}",
                        "source": f"host:{host_id}",
                        "target": service_id,
                        "type": "exposes",
                    }
                )

        return jsonify({"nodes": nodes, "edges": edges})

    @app.get("/api/scan-runs")
    def scan_runs():
        items = repository.list_scan_runs()
        scan_kind = request.args.get("scan_kind")
        if scan_kind:
            items = [item for item in items if item["scan_kind"] == scan_kind]
        items = sorted(items, key=lambda item: int(item["id"]), reverse=True)
        return jsonify(_paginate(items))

    @app.post("/api/overrides")
    def create_override():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise BadRequest("request body must be a JSON object")
        host_id = payload.get("host_id")
        if not isinstance(host_id, int):
            raise BadRequest("host_id must be an integer")
        host = repository.get_host(host_id)
        if host is None:
            raise NotFound(f"host {host_id} not found")

        override = repository.create_override(
            host_id=host_id,
            fixed_label=_optional_string(payload.get("fixed_label")),
            fixed_role=_optional_string(payload.get("fixed_role")),
            fixed_icon=_optional_string(payload.get("fixed_icon")),
            ignored=bool(payload.get("ignored", False)),
            note=_optional_string(payload.get("note")),
        )
        append_audit_record(
            loggers.audit,
            "override_created",
            actor="system",
            host_id=host_id,
            override_id=override["id"],
        )
        return jsonify(override), 201

    return app


def _paginate(items: list[dict[str, Any]]) -> dict[str, Any]:
    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=50, type=int)
    if page < 1 or page_size < 1 or page_size > 200:
        raise BadRequest("page must be >= 1 and page_size must be between 1 and 200")
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    return {
        "items": items[start:end],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise BadRequest("override fields must be strings when provided")
    stripped = value.strip()
    return stripped or None


def _match_subnet(ip: str, subnets: list[str]) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for subnet in subnets:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            continue
        if address in network:
            return subnet
    return None


app = create_app()


if __name__ == "__main__":
    host = os.environ.get("AZAZEL_TOPO_LITE_BACKEND_HOST", "127.0.0.1")
    port = int(os.environ.get("AZAZEL_TOPO_LITE_BACKEND_PORT", "18080"))
    app.run(host=host, port=port, debug=False, use_reloader=False)
