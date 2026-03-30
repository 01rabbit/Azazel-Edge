from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from configuration import LoggingConfig


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": utc_now(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "event"):
            payload["event"] = record.event
        if hasattr(record, "payload") and isinstance(record.payload, dict):
            payload.update(record.payload)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


@dataclass(slots=True)
class TopoLiteLoggers:
    app: logging.Logger
    access: logging.Logger
    audit: logging.Logger
    scanner: logging.Logger


def configure_logging(config: LoggingConfig) -> TopoLiteLoggers:
    level = getattr(logging, config.level.upper(), logging.INFO)
    return TopoLiteLoggers(
        app=_build_logger("topo_lite.app", config.app_log_path, level),
        access=_build_logger("topo_lite.access", config.access_log_path, level),
        audit=_build_logger("topo_lite.audit", config.audit_log_path, level),
        scanner=_build_logger("topo_lite.scanner", config.scanner_log_path, level),
    )


def log_event(logger: logging.Logger, event: str, message: str, **payload: Any) -> None:
    logger.info(message, extra={"event": event, "payload": payload})


def log_exception(logger: logging.Logger, event: str, message: str, **payload: Any) -> None:
    logger.error(message, extra={"event": event, "payload": payload}, exc_info=True)


def append_audit_record(logger: logging.Logger, event: str, actor: str, **payload: Any) -> None:
    data = {"actor": actor}
    data.update(payload)
    logger.info("audit", extra={"event": event, "payload": data})


def _build_logger(name: str, path: str, level: int) -> logging.Logger:
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(JsonLineFormatter())
    logger.addHandler(handler)
    return logger
