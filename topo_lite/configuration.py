from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml


DEFAULT_TARGET_PORTS = [22, 53, 80, 123, 139, 443, 445, 631, 3389, 5353, 8000, 8080, 8443, 9100]


class ValidationError(ValueError):
    """Raised when the Topo-Lite configuration is invalid."""


@dataclass(slots=True)
class ScanIntervals:
    discovery_seconds: int = 300
    probe_seconds: int = 900
    deep_probe_seconds: int = 60


@dataclass(slots=True)
class ProbeConfig:
    timeout_seconds: int = 2
    concurrency: int = 32


@dataclass(slots=True)
class NotificationConfig:
    enabled: bool = False
    provider: str = "ntfy"
    endpoint: str = ""


@dataclass(slots=True)
class AuthConfig:
    enabled: bool = True
    mode: str = "local"
    token_required: bool = True
    session_secret: str = "change-me-topo-lite-session-secret"
    admin_username: str = "admin"
    admin_password: str = "change-me-admin-password"
    admin_api_token: str = "change-me-admin-token"
    readonly_username: str = "viewer"
    readonly_password: str = "change-me-viewer-password"
    readonly_api_token: str = "change-me-viewer-token"


@dataclass(slots=True)
class RetentionConfig:
    observations_days: int = 30
    events_days: int = 90
    scan_runs_days: int = 14


@dataclass(slots=True)
class LoggingConfig:
    level: str = "INFO"
    app_log_path: str = "logs/app.jsonl"
    access_log_path: str = "logs/access.jsonl"
    audit_log_path: str = "logs/audit.jsonl"
    scanner_log_path: str = "logs/scanner.jsonl"


@dataclass(slots=True)
class TopoLiteConfig:
    interface: str = "eth0"
    subnets: list[str] = field(default_factory=lambda: ["192.168.40.0/24"])
    target_ports: list[int] = field(default_factory=lambda: list(DEFAULT_TARGET_PORTS))
    database_path: str = "topo_lite.sqlite3"
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    scan_intervals: ScanIntervals = field(default_factory=ScanIntervals)
    probe: ProbeConfig = field(default_factory=ProbeConfig)
    notification: NotificationConfig = field(default_factory=NotificationConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    retention_period: RetentionConfig = field(default_factory=RetentionConfig)


def default_config() -> TopoLiteConfig:
    return TopoLiteConfig()


def config_to_dict(config: TopoLiteConfig) -> dict[str, Any]:
    return asdict(config)


def load_config(
    path: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> TopoLiteConfig:
    env_map = dict(env or os.environ)
    base = config_to_dict(default_config())
    config_path = Path(path) if path is not None else Path("config.yaml")

    if config_path.exists():
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValidationError("config file must contain a mapping at the top level")
        _deep_merge(base, loaded)

    _apply_env_overrides(base, env_map)
    config = _dict_to_config(base)
    validate_config(config)
    return config


def validate_config(config: TopoLiteConfig) -> None:
    if not config.interface.strip():
        raise ValidationError("interface must be a non-empty string")
    if not config.subnets or not all(subnet.strip() for subnet in config.subnets):
        raise ValidationError("subnets must contain at least one non-empty entry")
    if not config.target_ports:
        raise ValidationError("target_ports must contain at least one port")
    if len(set(config.target_ports)) != len(config.target_ports):
        raise ValidationError("target_ports must not contain duplicates")
    if any(port < 1 or port > 65535 for port in config.target_ports):
        raise ValidationError("target_ports must be within 1..65535")
    if not config.database_path.strip():
        raise ValidationError("database_path must be a non-empty string")
    if config.logging.level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValidationError("logging.level must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL")
    for name, value in asdict(config.logging).items():
        if name == "level":
            continue
        if not value.strip():
            raise ValidationError(f"logging.{name} must be a non-empty string")
    for name, value in asdict(config.scan_intervals).items():
        if value <= 0:
            raise ValidationError(f"scan_intervals.{name} must be greater than zero")
    for name, value in asdict(config.probe).items():
        if value <= 0:
            raise ValidationError(f"probe.{name} must be greater than zero")
    for name, value in asdict(config.retention_period).items():
        if value <= 0:
            raise ValidationError(f"retention_period.{name} must be greater than zero")
    if config.notification.enabled and not config.notification.provider.strip():
        raise ValidationError("notification.provider must be set when notification is enabled")
    if config.auth.mode not in {"local"}:
        raise ValidationError("auth.mode must be 'local' in the initial implementation")
    if config.auth.enabled:
        for name, value in asdict(config.auth).items():
            if name == "enabled" or name == "token_required":
                continue
            if not str(value).strip():
                raise ValidationError(f"auth.{name} must be a non-empty string when auth is enabled")


def _dict_to_config(data: dict[str, Any]) -> TopoLiteConfig:
    return TopoLiteConfig(
        interface=str(data["interface"]),
        subnets=[str(item) for item in data["subnets"]],
        target_ports=[int(item) for item in data["target_ports"]],
        database_path=str(data["database_path"]),
        logging=LoggingConfig(**data["logging"]),
        scan_intervals=ScanIntervals(**data["scan_intervals"]),
        probe=ProbeConfig(**data["probe"]),
        notification=NotificationConfig(**data["notification"]),
        auth=AuthConfig(**data["auth"]),
        retention_period=RetentionConfig(**data["retention_period"]),
    )


def _deep_merge(base: dict[str, Any], extra: dict[str, Any]) -> None:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _parse_bool(raw: str) -> bool:
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValidationError(f"invalid boolean value: {raw}")


def _parse_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_int_csv(raw: str) -> list[int]:
    return [int(item) for item in _parse_csv(raw)]


def _apply_env_overrides(base: dict[str, Any], env: Mapping[str, str]) -> None:
    simple_overrides: dict[str, tuple[tuple[str, ...], Any]] = {
        "AZAZEL_TOPO_LITE_INTERFACE": (("interface",), str),
        "AZAZEL_TOPO_LITE_DATABASE_PATH": (("database_path",), str),
        "AZAZEL_TOPO_LITE_SUBNETS": (("subnets",), _parse_csv),
        "AZAZEL_TOPO_LITE_TARGET_PORTS": (("target_ports",), _parse_int_csv),
        "AZAZEL_TOPO_LITE_LOG_LEVEL": (("logging", "level"), str),
        "AZAZEL_TOPO_LITE_APP_LOG_PATH": (("logging", "app_log_path"), str),
        "AZAZEL_TOPO_LITE_ACCESS_LOG_PATH": (("logging", "access_log_path"), str),
        "AZAZEL_TOPO_LITE_AUDIT_LOG_PATH": (("logging", "audit_log_path"), str),
        "AZAZEL_TOPO_LITE_SCANNER_LOG_PATH": (("logging", "scanner_log_path"), str),
        "AZAZEL_TOPO_LITE_DISCOVERY_INTERVAL_SECONDS": (("scan_intervals", "discovery_seconds"), int),
        "AZAZEL_TOPO_LITE_PROBE_INTERVAL_SECONDS": (("scan_intervals", "probe_seconds"), int),
        "AZAZEL_TOPO_LITE_DEEP_PROBE_INTERVAL_SECONDS": (("scan_intervals", "deep_probe_seconds"), int),
        "AZAZEL_TOPO_LITE_PROBE_TIMEOUT_SECONDS": (("probe", "timeout_seconds"), int),
        "AZAZEL_TOPO_LITE_PROBE_CONCURRENCY": (("probe", "concurrency"), int),
        "AZAZEL_TOPO_LITE_NOTIFICATION_ENABLED": (("notification", "enabled"), _parse_bool),
        "AZAZEL_TOPO_LITE_NOTIFICATION_PROVIDER": (("notification", "provider"), str),
        "AZAZEL_TOPO_LITE_NOTIFICATION_ENDPOINT": (("notification", "endpoint"), str),
        "AZAZEL_TOPO_LITE_AUTH_ENABLED": (("auth", "enabled"), _parse_bool),
        "AZAZEL_TOPO_LITE_AUTH_MODE": (("auth", "mode"), str),
        "AZAZEL_TOPO_LITE_AUTH_TOKEN_REQUIRED": (("auth", "token_required"), _parse_bool),
        "AZAZEL_TOPO_LITE_AUTH_SESSION_SECRET": (("auth", "session_secret"), str),
        "AZAZEL_TOPO_LITE_AUTH_ADMIN_USERNAME": (("auth", "admin_username"), str),
        "AZAZEL_TOPO_LITE_AUTH_ADMIN_PASSWORD": (("auth", "admin_password"), str),
        "AZAZEL_TOPO_LITE_AUTH_ADMIN_API_TOKEN": (("auth", "admin_api_token"), str),
        "AZAZEL_TOPO_LITE_AUTH_READONLY_USERNAME": (("auth", "readonly_username"), str),
        "AZAZEL_TOPO_LITE_AUTH_READONLY_PASSWORD": (("auth", "readonly_password"), str),
        "AZAZEL_TOPO_LITE_AUTH_READONLY_API_TOKEN": (("auth", "readonly_api_token"), str),
        "AZAZEL_TOPO_LITE_RETENTION_OBSERVATIONS_DAYS": (("retention_period", "observations_days"), int),
        "AZAZEL_TOPO_LITE_RETENTION_EVENTS_DAYS": (("retention_period", "events_days"), int),
        "AZAZEL_TOPO_LITE_RETENTION_SCAN_RUNS_DAYS": (("retention_period", "scan_runs_days"), int),
    }

    for env_name, (path, parser) in simple_overrides.items():
        if env_name not in env:
            continue
        target = base
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = parser(env[env_name])
