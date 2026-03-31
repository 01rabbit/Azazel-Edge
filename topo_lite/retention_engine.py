from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Callable

from db.repository import TopoLiteRepository
from logging_utils import TopoLiteLoggers, append_audit_record, log_event, utc_now


def cleanup_retention_data(
    *,
    config,
    repository: TopoLiteRepository,
    loggers: TopoLiteLoggers,
    now_fn: Callable[[], str] = utc_now,
) -> dict[str, object]:
    current = _parse_timestamp(now_fn())
    observations_before = _format_timestamp(current - timedelta(days=config.retention_period.observations_days))
    events_before = _format_timestamp(current - timedelta(days=config.retention_period.events_days))
    scan_runs_before = _format_timestamp(current - timedelta(days=config.retention_period.scan_runs_days))

    deleted = repository.cleanup_history(
        observations_before=observations_before,
        events_before=events_before,
        scan_runs_before=scan_runs_before,
    )
    payload = {
        "status": "completed",
        "observations_before": observations_before,
        "events_before": events_before,
        "scan_runs_before": scan_runs_before,
        "deleted": deleted,
    }
    append_audit_record(
        loggers.audit,
        "retention_cleanup_completed",
        actor="system",
        **payload,
    )
    log_event(
        loggers.scanner,
        "retention_cleanup_completed",
        "retention cleanup completed",
        **payload,
    )
    return payload


def _parse_timestamp(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")
