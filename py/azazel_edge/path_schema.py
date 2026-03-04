from __future__ import annotations

import os
import shutil
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA_V1 = "v1"
SCHEMA_V2 = "v2"
SUPPORTED_SCHEMAS = (SCHEMA_V1, SCHEMA_V2)
LEGACY_DEPRECATION_DATE = date(2026, 12, 31)

_warned_legacy_paths: set[str] = set()


def _env_schema() -> str:
    raw = str(os.environ.get("AZAZEL_PATH_SCHEMA", "")).strip().lower()
    if raw in SUPPORTED_SCHEMAS:
        return raw
    return ""


def active_schema() -> str:
    env = _env_schema()
    if env:
        return env
    if Path("/etc/default/azazel-edge").exists() or Path("/etc/azazel-edge").exists():
        return SCHEMA_V2
    return SCHEMA_V1


def _order_for(schema: Optional[str] = None) -> tuple[str, str]:
    selected = (schema or active_schema()).lower()
    if selected == SCHEMA_V2:
        return "azazel-edge", "azazel-gadget"
    return "azazel-gadget", "azazel-zero"


def warn_if_legacy_path(path: Path, logger: Any = None) -> None:
    text = str(path)
    if "azazel-gadget" not in text:
        return
    if text in _warned_legacy_paths:
        return
    _warned_legacy_paths.add(text)
    msg = (
        f"Legacy path compatibility in use: {text}. "
        f"This path is scheduled for removal after {LEGACY_DEPRECATION_DATE.isoformat()}."
    )
    if logger is not None:
        try:
            logger.warning(msg)
        except Exception:
            pass


def _home_candidates(schema: Optional[str] = None, home: Optional[Path] = None) -> tuple[Path, Path]:
    primary_name, legacy_name = _order_for(schema)
    h = home or Path.home()
    return (h / f".{primary_name}", h / f".{legacy_name}")


def _schema_names(schema: Optional[str] = None) -> tuple[str, str]:
    return _order_for(schema)


def _dedupe_paths(paths: Iterable[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def runtime_dir_candidates(schema: Optional[str] = None) -> list[Path]:
    primary_name, legacy_name = _order_for(schema)
    return [Path(f"/run/{primary_name}"), Path(f"/run/{legacy_name}")]


def log_dir_candidates(schema: Optional[str] = None) -> list[Path]:
    primary_name, legacy_name = _order_for(schema)
    return [Path(f"/var/log/{primary_name}"), Path(f"/var/log/{legacy_name}")]


def config_dir_candidates(schema: Optional[str] = None) -> list[Path]:
    primary_name, legacy_name = _order_for(schema)
    return [Path(f"/etc/{primary_name}"), Path(f"/etc/{legacy_name}")]


def defaults_file_candidates(schema: Optional[str] = None) -> list[Path]:
    primary_name, legacy_name = _order_for(schema)
    return [Path(f"/etc/default/{primary_name}"), Path(f"/etc/default/{legacy_name}")]


def snapshot_path_candidates(schema: Optional[str] = None, home: Optional[Path] = None) -> list[Path]:
    run_primary, run_legacy = runtime_dir_candidates(schema)
    home_primary, home_legacy = _home_candidates(schema, home=home)
    return [
        run_primary / "ui_snapshot.json",
        run_legacy / "ui_snapshot.json",
        home_primary / "run" / "ui_snapshot.json",
        home_legacy / "run" / "ui_snapshot.json",
    ]


def command_path_candidates(schema: Optional[str] = None, home: Optional[Path] = None) -> list[Path]:
    run_primary, run_legacy = runtime_dir_candidates(schema)
    home_primary, home_legacy = _home_candidates(schema, home=home)
    return [
        run_primary / "ui_command.json",
        run_legacy / "ui_command.json",
        home_primary / "run" / "ui_command.json",
        home_legacy / "run" / "ui_command.json",
    ]


def first_minute_config_candidates(schema: Optional[str] = None) -> list[Path]:
    cfg_primary, cfg_legacy = config_dir_candidates(schema)
    return [cfg_primary / "first_minute.yaml", cfg_legacy / "first_minute.yaml"]


def mode_state_candidates(schema: Optional[str] = None) -> list[Path]:
    cfg_primary, cfg_legacy = config_dir_candidates(schema)
    return _dedupe_paths(
        [
            Path("/etc/azazel/mode.json"),
            cfg_primary / "mode.json",
            cfg_legacy / "mode.json",
        ]
    )


def opencanary_config_candidates(schema: Optional[str] = None, repo_root: Optional[Path] = None) -> list[Path]:
    cfg_primary, cfg_legacy = config_dir_candidates(schema)
    candidates: list[Path] = [
        Path("/etc/opencanaryd/opencanary.conf"),
        cfg_primary / "opencanary.conf",
        cfg_legacy / "opencanary.conf",
    ]
    if repo_root is not None:
        candidates.append(Path(repo_root) / "configs" / "opencanary.conf")
    return _dedupe_paths(candidates)


def runtime_snapshot_path_candidates(schema: Optional[str] = None, home: Optional[Path] = None) -> list[Path]:
    paths = [p for p in snapshot_path_candidates(schema=schema, home=home) if str(p).startswith("/run/")]
    if paths:
        return paths
    return snapshot_path_candidates(schema=schema, home=home)[:2]


def portal_env_candidates(schema: Optional[str] = None) -> list[Path]:
    cfg_primary, cfg_legacy = config_dir_candidates(schema)
    return [cfg_primary / "portal-viewer.env", cfg_legacy / "portal-viewer.env"]


def web_token_candidates(schema: Optional[str] = None, home: Optional[Path] = None) -> list[Path]:
    home_primary, home_legacy = _home_candidates(schema, home=home)
    return [home_primary / "web_token.txt", home_legacy / "web_token.txt"]


def wifi_health_path_candidates(
    schema: Optional[str] = None,
    home: Optional[Path] = None,
    repo_root: Optional[Path] = None,
) -> list[Path]:
    primary_name, legacy_name = _schema_names(schema)
    run_primary, run_legacy = runtime_dir_candidates(schema)
    home_primary, home_legacy = _home_candidates(schema, home=home)

    candidates: list[Path] = [
        run_primary / "wifi_health.json",
        run_legacy / "wifi_health.json",
        home_primary / "run" / "wifi_health.json",
        home_legacy / "run" / "wifi_health.json",
    ]
    if repo_root is not None:
        root = Path(repo_root)
        candidates.extend(
            [
                root / f".{primary_name}" / "run" / "wifi_health.json",
                root / f".{legacy_name}" / "run" / "wifi_health.json",
            ]
        )
    return _dedupe_paths(candidates)


def choose_read_path(paths: Iterable[Path]) -> Path:
    options = list(paths)
    for p in options:
        if p.exists():
            return p
    return options[0]


def status() -> dict[str, Any]:
    return {
        "active_schema": active_schema(),
        "supported": list(SUPPORTED_SCHEMAS),
        "legacy_deprecation_date": LEGACY_DEPRECATION_DATE.isoformat(),
        "defaults_files": [str(p) for p in defaults_file_candidates()],
        "runtime_dirs": [str(p) for p in runtime_dir_candidates()],
        "config_dirs": [str(p) for p in config_dir_candidates()],
    }


def migrate_schema(target_schema: str, dry_run: bool = False, home: Optional[Path] = None) -> dict[str, Any]:
    target = str(target_schema).strip().lower()
    if target not in SUPPORTED_SCHEMAS:
        return {
            "ok": False,
            "target_schema": target_schema,
            "errors": [f"Unsupported schema: {target_schema}"],
            "actions": [],
            "rollback_hints": [],
        }

    actions: list[str] = []
    errors: list[str] = []
    rollback_hints = [f"Re-run migrate with --to {'v1' if target == 'v2' else 'v2'}"]

    def _record(action: str) -> None:
        actions.append(action)

    def _mkdir(path: Path) -> None:
        _record(f"mkdir -p {path}")
        if not dry_run:
            path.mkdir(parents=True, exist_ok=True)

    def _copytree(src: Path, dst: Path) -> None:
        _record(f"copytree {src} -> {dst}")
        if dry_run:
            return
        if not src.exists():
            return
        dst.mkdir(parents=True, exist_ok=True)
        for item in src.iterdir():
            to = dst / item.name
            if item.is_dir():
                shutil.copytree(item, to, dirs_exist_ok=True)
            else:
                shutil.copy2(item, to)

    def _symlink(link: Path, target_path: Path) -> None:
        _record(f"ln -sfn {target_path} {link}")
        if dry_run:
            return
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.exists() or link.is_symlink():
            if link.is_symlink():
                link.unlink()
            elif link.is_dir():
                # Preserve real directories for safety.
                return
            else:
                link.unlink()
        link.symlink_to(target_path)

    try:
        runtime_primary, runtime_legacy = runtime_dir_candidates(target)
        _mkdir(runtime_primary)
        if not runtime_legacy.exists():
            _symlink(runtime_legacy, runtime_primary)
    except Exception as exc:
        errors.append(f"runtime migration failed: {exc}")

    try:
        cfg_primary, cfg_legacy = config_dir_candidates(target)
        if cfg_legacy.exists() and not cfg_primary.exists():
            _copytree(cfg_legacy, cfg_primary)
        _mkdir(cfg_primary)
        if not cfg_legacy.exists():
            _symlink(cfg_legacy, cfg_primary)
    except Exception as exc:
        errors.append(f"config migration failed: {exc}")

    try:
        def_primary, def_legacy = defaults_file_candidates(target)
        if def_legacy.exists() and not def_primary.exists():
            _record(f"copy2 {def_legacy} -> {def_primary}")
            if not dry_run:
                def_primary.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(def_legacy, def_primary)
        if def_primary.exists() and not def_legacy.exists():
            _symlink(def_legacy, def_primary)
    except Exception as exc:
        errors.append(f"defaults migration failed: {exc}")

    try:
        home_primary, home_legacy = _home_candidates(target, home=home)
        if home_legacy.exists() and not home_primary.exists():
            _symlink(home_primary, home_legacy)
        elif home_primary.exists() and not home_legacy.exists():
            _symlink(home_legacy, home_primary)
    except Exception as exc:
        errors.append(f"user-home migration failed: {exc}")

    return {
        "ok": len(errors) == 0,
        "target_schema": target,
        "dry_run": dry_run,
        "actions": actions,
        "errors": errors,
        "rollback_hints": rollback_hints,
    }
