from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from db.repository import TopoLiteRepository
from logging_utils import TopoLiteLoggers, append_audit_record, log_event, utc_now


def export_azazel_events(
    *,
    config,
    repository: TopoLiteRepository,
    loggers: TopoLiteLoggers,
    events: list[dict[str, Any]] | None = None,
    now_fn: Callable[[], str] = utc_now,
) -> dict[str, object]:
    if not config.integration.enabled:
        return {"status": "skipped", "reason": "disabled", "exported": 0, "failed": 0, "skipped_count": 0}

    queue_dir = Path(config.integration.queue_path)
    queue_dir.mkdir(parents=True, exist_ok=True)
    candidate_events = repository.list_events() if events is None else events
    exported = 0
    failed = 0
    skipped_count = 0

    for item in candidate_events:
        event = repository.get_event(int(item["id"])) or item
        if not _should_export_event(event):
            skipped_count += 1
            continue
        if event.get("exported_at"):
            skipped_count += 1
            continue

        attempted_at = now_fn()
        payload = _build_payload(event=event, repository=repository)
        destination = queue_dir / f"topo-lite-event-{int(event['id'])}.json"
        try:
            destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError as error:
            failed += 1
            repository.mark_event_export(
                int(event["id"]),
                attempted_at=attempted_at,
                exported_at=None,
                error=str(error),
            )
            append_audit_record(
                loggers.audit,
                "azazel_event_export_failed",
                actor="system",
                event_id=event["id"],
                destination=str(destination),
                error=str(error),
            )
            log_event(
                loggers.app,
                "azazel_event_export_failed",
                "Azazel-Edge event export failed",
                event_id=event["id"],
                destination=str(destination),
                error=str(error),
            )
            continue

        exported += 1
        repository.mark_event_export(
            int(event["id"]),
            attempted_at=attempted_at,
            exported_at=attempted_at,
            error=None,
        )
        append_audit_record(
            loggers.audit,
            "azazel_event_exported",
            actor="system",
            event_id=event["id"],
            destination=str(destination),
        )

    return {
        "status": "completed",
        "queue_path": str(queue_dir),
        "exported": exported,
        "failed": failed,
        "skipped_count": skipped_count,
    }


def _should_export_event(event: dict[str, Any]) -> bool:
    return str(event.get("severity") or "") == "high"


def _build_payload(*, event: dict[str, Any], repository: TopoLiteRepository) -> dict[str, Any]:
    host = repository.get_host(int(event["host_id"])) if event.get("host_id") else None
    services = repository.list_services(int(event["host_id"])) if event.get("host_id") else []
    open_services = [
        {"proto": str(service["proto"]), "port": int(service["port"])}
        for service in services
        if str(service.get("state")) == "open"
    ]
    return {
        "schema_version": "1.0",
        "source": "azazel-topo-lite",
        "event_name": "suspicious_exposure",
        "created_at": str(event["created_at"]),
        "severity": str(event["severity"]),
        "topo_event": {
            "id": int(event["id"]),
            "event_type": str(event["event_type"]),
            "summary": str(event["summary"]),
        },
        "host": {
            "id": int(host["id"]),
            "ip": str(host["ip"]),
            "mac": str(host.get("mac") or ""),
            "hostname": str(host.get("hostname") or ""),
            "vendor": str(host.get("vendor") or ""),
        } if host else {},
        "open_services": open_services,
    }
