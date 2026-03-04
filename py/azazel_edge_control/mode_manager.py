#!/usr/bin/env python3
"""Lightweight Azazel-Edge mode manager for portal/shield/scapegoat."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from azazel_edge.path_schema import mode_state_candidates

LOGGER = logging.getLogger("azazel-edge.mode")
MODE_CHOICES = ("portal", "shield", "scapegoat")
DEFAULT_MODE = "shield"

EPD_STATE_PATH = Path("/run/azazel-edge/epd_state.json")


class ModeManager:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or LOGGER

    def _iso_now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _state_path(self) -> Path:
        candidates = mode_state_candidates()
        for p in candidates:
            if p.exists():
                return p
        return Path("/etc/azazel-edge/mode.json")

    def _read_state(self) -> Dict[str, Any]:
        p = self._state_path()
        try:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {
            "current_mode": DEFAULT_MODE,
            "last_change": "",
            "requested_by": "init",
            "config_hash": "",
        }

    def _write_state(self, state: Dict[str, Any]) -> None:
        p = self._state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _write_epd_state(self, mode: str, requested_by: str, error: str = "") -> None:
        payload = {
            "mode": mode,
            "requested_by": requested_by,
            "mode_last_change": self._iso_now(),
            "internet": "unknown",
            "ssid": "",
            "upstream_if": "",
            "last_error": error,
        }
        try:
            EPD_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            EPD_STATE_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except Exception as exc:
            self.logger.debug("failed to write epd state: %s", exc)

    def status(self) -> Dict[str, Any]:
        state = self._read_state()
        return {
            "ok": True,
            "mode": {
                "current_mode": state.get("current_mode", DEFAULT_MODE),
                "last_change": state.get("last_change", ""),
                "requested_by": state.get("requested_by", ""),
                "config_hash": state.get("config_hash", ""),
            },
            "ts": self._iso_now(),
        }

    def set_mode(self, mode: str, requested_by: str = "daemon", dry_run: bool = False) -> Dict[str, Any]:
        target = str(mode or "").strip().lower()
        if target not in MODE_CHOICES:
            return {"ok": False, "error": f"Unknown mode: {target}", "ts": self._iso_now()}

        prev = self._read_state()
        if dry_run:
            return {
                "ok": True,
                "dry_run": True,
                "from": prev.get("current_mode", DEFAULT_MODE),
                "to": target,
                "requested_by": requested_by,
                "ts": self._iso_now(),
            }

        config_hash = "sha256:" + hashlib.sha256(target.encode("utf-8")).hexdigest()
        state = {
            "current_mode": target,
            "last_change": self._iso_now(),
            "requested_by": requested_by,
            "config_hash": config_hash,
        }
        self._write_state(state)
        self._write_epd_state(target, requested_by)
        return {
            "ok": True,
            "from": prev.get("current_mode", DEFAULT_MODE),
            "to": target,
            "requested_by": requested_by,
            "config_hash": config_hash,
            "ts": self._iso_now(),
        }

    def apply_default(self, requested_by: str = "boot") -> Dict[str, Any]:
        return self.set_mode(DEFAULT_MODE, requested_by=requested_by)
