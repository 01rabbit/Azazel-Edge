from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from db.repository import TopoLiteRepository
from logging_utils import TopoLiteLoggers, append_audit_record, log_event, utc_now


class NotificationError(RuntimeError):
    pass


class NtfyNotifier:
    def __init__(self, endpoint: str, token: str = "") -> None:
        self.endpoint = endpoint
        self.token = token

    def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=5) as response:
                status = getattr(response, "status", 200)
        except (HTTPError, URLError) as error:
            raise NotificationError(f"ntfy_send_failed:{error}") from error
        if status >= 400:
            raise NotificationError(f"ntfy_send_failed_status:{status}")
        return {"ok": True, "adapter": "ntfy", "status": status}


class MattermostNotifier:
    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint

    def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = {
            "text": (
                f"[{payload['severity']}] {payload['event_type']} "
                f"{payload['host'].get('hostname') or payload['host'].get('ip') or 'unknown-host'}: {payload['summary']}"
            )
        }
        request = Request(
            self.endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=5) as response:
                status = getattr(response, "status", 200)
        except (HTTPError, URLError) as error:
            raise NotificationError(f"mattermost_send_failed:{error}") from error
        if status >= 400:
            raise NotificationError(f"mattermost_send_failed_status:{status}")
        return {"ok": True, "adapter": "mattermost", "status": status}


def dispatch_event_notifications(
    *,
    config,
    repository: TopoLiteRepository,
    loggers: TopoLiteLoggers,
    events: list[dict[str, Any]] | None = None,
    now_fn: Callable[[], str] = utc_now,
    notifier: Any | None = None,
) -> dict[str, Any]:
    if not config.notification.enabled:
        return {"status": "skipped", "reason": "disabled", "sent": 0, "failed": 0, "skipped_count": 0}
    if not config.notification.endpoint.strip():
        return {"status": "skipped", "reason": "missing_endpoint", "sent": 0, "failed": 0, "skipped_count": 0}

    run_notifier = notifier or _build_notifier(
        provider=config.notification.provider,
        endpoint=config.notification.endpoint,
        token=config.notification.token,
    )
    candidate_events = repository.list_events() if events is None else events
    sent = 0
    failed = 0
    skipped_count = 0

    for item in candidate_events:
        event = repository.get_event(int(item["id"])) or item
        if not _should_notify_event(event):
            skipped_count += 1
            continue
        if event.get("notified_at"):
            skipped_count += 1
            continue
        if _is_rate_limited(event, config.notification.rate_limit_seconds, now_fn=now_fn):
            skipped_count += 1
            continue

        payload = _build_payload(event, repository)
        attempted_at = now_fn()
        try:
            result = run_notifier.send(payload)
        except Exception as error:
            failed += 1
            repository.mark_event_notification(
                int(event["id"]),
                attempted_at=attempted_at,
                notified_at=None,
                error=str(error),
            )
            append_audit_record(
                loggers.audit,
                "notification_failed",
                actor="system",
                event_id=event["id"],
                provider=config.notification.provider,
                error=str(error),
            )
            log_event(
                loggers.app,
                "notification_failed",
                "event notification failed",
                event_id=event["id"],
                provider=config.notification.provider,
                error=str(error),
            )
            continue

        sent += 1
        repository.mark_event_notification(
            int(event["id"]),
            attempted_at=attempted_at,
            notified_at=attempted_at,
            error=None,
        )
        append_audit_record(
            loggers.audit,
            "notification_sent",
            actor="system",
            event_id=event["id"],
            provider=result["adapter"],
            status=result["status"],
        )

    return {
        "status": "completed",
        "provider": config.notification.provider,
        "sent": sent,
        "failed": failed,
        "skipped_count": skipped_count,
    }


def _build_notifier(*, provider: str, endpoint: str, token: str):
    normalized = provider.strip().lower()
    if normalized == "ntfy":
        return NtfyNotifier(endpoint=endpoint, token=token)
    if normalized == "mattermost":
        return MattermostNotifier(endpoint=endpoint)
    raise NotificationError(f"unsupported_provider:{provider}")


def _should_notify_event(event: dict[str, Any]) -> bool:
    return str(event.get("event_type")) == "new_host" or str(event.get("severity")) == "high"


def _is_rate_limited(
    event: dict[str, Any],
    rate_limit_seconds: int,
    *,
    now_fn: Callable[[], str],
) -> bool:
    attempted_at = _parse_timestamp(str(event.get("notification_attempted_at") or ""))
    if attempted_at is None:
        return False
    current = _parse_timestamp(now_fn())
    if current is None:
        return False
    return attempted_at >= current - timedelta(seconds=rate_limit_seconds)


def _build_payload(event: dict[str, Any], repository: TopoLiteRepository) -> dict[str, Any]:
    host = repository.get_host(int(event["host_id"])) if event.get("host_id") else None
    return {
        "event_id": int(event["id"]),
        "event_type": str(event["event_type"]),
        "severity": str(event["severity"]),
        "summary": str(event["summary"]),
        "created_at": str(event["created_at"]),
        "host": {
            "id": host["id"],
            "ip": host["ip"],
            "hostname": host["hostname"],
        } if host else {},
    }


def _parse_timestamp(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
