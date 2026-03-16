#!/usr/bin/env python3
"""Render mode-centric EPD state from /run/azazel-edge/epd_state.json."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

from azazel_edge.control_plane import read_snapshot_payload
from azazel_edge.demo_overlay import is_demo_overlay_active, read_demo_overlay
from azazel_edge.path_schema import runtime_snapshot_path_candidates

EPD_STATE = Path("/run/azazel-edge/epd_state.json")
EPD_LAST_RENDER = Path("/run/azazel-edge/epd_last_render.json")
RUNTIME_SNAPSHOT_CANDIDATES = tuple(runtime_snapshot_path_candidates())


def _safe_load(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        return {}


def _read_runtime_snapshot() -> Dict[str, Any]:
    for path in RUNTIME_SNAPSHOT_CANDIDATES:
        data = _safe_load(path)
        if isinstance(data, dict) and data:
            return data
    try:
        payload, _source = read_snapshot_payload(prefer_control_plane=True)
        if isinstance(payload, dict) and payload:
            return payload
    except Exception:
        pass
    return {}


def _fallback_epd_state() -> Dict[str, Any]:
    """Build minimal mode payload when epd_state.json is unavailable."""
    data = _read_runtime_snapshot()
    if isinstance(data, dict) and data:
        mode_payload = data.get("mode")
        mode = "shield"
        if isinstance(mode_payload, dict):
            mode = str(mode_payload.get("current_mode", "shield") or "shield").strip().lower()
        return {
            "mode": mode if mode in ("portal", "shield", "scapegoat") else "shield",
            "internet": "unknown",
            "ssid": str(data.get("ssid", "") or ""),
            "upstream_if": str(data.get("up_if", "") or ""),
        }
    return {"mode": "shield", "internet": "unknown", "ssid": "", "upstream_if": ""}


def _read_live_ssid(upstream_if: str) -> str:
    iface = str(upstream_if or "").strip()
    candidates = []
    if iface:
        # iwgetid syntax varies by distro; try both forms.
        candidates.append(["iwgetid", iface, "-r"])
        candidates.append(["iwgetid", "-r", iface])
    candidates.append(["iwgetid", "-r"])

    for cmd in candidates:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=3, check=False).stdout.strip()
            if out:
                return out
        except Exception:
            continue
    return "No SSID"


def _normal_render_spec(payload: Dict[str, Any], mode_label: str, risk_status: str) -> Dict[str, Any]:
    live_ssid = ""
    live_signal: int | None = None
    live_wifi_state = ""
    live_suspicion = 0
    data = _read_runtime_snapshot()
    if isinstance(data, dict) and data:
        conn = data.get("connection")
        if isinstance(conn, dict):
            live_wifi_state = str(conn.get("wifi_state", "")).strip().upper()
        raw_ssid = str(data.get("ssid", "")).strip()
        if raw_ssid and raw_ssid != "-":
            live_ssid = raw_ssid
        raw_signal = data.get("signal_dbm")
        try:
            live_signal = int(float(str(raw_signal).strip()))
        except Exception:
            pass
        internal = data.get("internal")
        if isinstance(internal, dict):
            try:
                live_suspicion = int(float(str(internal.get("suspicion", 0)).strip()))
            except Exception:
                live_suspicion = 0

    ssid = live_ssid or str(payload.get("ssid", "")).strip() or _read_live_ssid(str(payload.get("upstream_if", "")).strip())
    signal = live_signal if live_wifi_state == "CONNECTED" else None
    return {
        "state": "normal",
        "mode_label": str(mode_label or "SHIELD").strip().upper()[:12],
        "ssid": ssid,
        "risk_status": str(risk_status or "UNKNOWN").strip().upper(),
        "suspicion": max(0, min(100, live_suspicion)),
        "signal": signal,
    }


def _risk_status_from_snapshot() -> str:
    data = _read_runtime_snapshot()
    if isinstance(data, dict) and data:
        # Align with TUI/WebUI status source first.
        user_state = str(data.get("user_state", "")).strip().upper()
        if user_state in ("SAFE", "CHECKING", "LIMITED", "CONTAINED", "DECEPTION"):
            return user_state
        conn = data.get("connection")
        if not isinstance(conn, dict):
            return "UNKNOWN"
        internet = str(conn.get("internet_check", "")).strip().upper()
        if internet == "OK":
            return "SAFE"
        if internet == "FAIL":
            return "FAIL"
        if internet in ("N/A", "UNKNOWN"):
            return "CHECKING"
    return "UNKNOWN"


def _desired_render_spec(payload: Dict[str, Any]) -> Dict[str, Any]:
    overlay = read_demo_overlay()
    if is_demo_overlay_active(overlay):
        band = str((((overlay.get("arsenal_demo") or {}) if isinstance(overlay.get("arsenal_demo"), dict) else {}).get("band") or "")).strip().upper()
        if band == "WATCH":
            return {"state": "warning", "msg": "CHECK WEB"}
        return {"state": "danger", "msg": "CHECK WEB"}

    mode = str(payload.get("mode", "")).strip().lower()

    # Keep base screen during mode switch (no WARNING banner).
    if mode == "switching":
        target = str(payload.get("target_mode", "shield")).strip().lower()
        if target not in ("portal", "shield", "scapegoat"):
            target = "shield"
        return _normal_render_spec(payload, target, "CHECKING")

    if mode == "failed":
        return {"state": "danger", "msg": "MODE FAIL"}

    if mode in ("portal", "shield", "scapegoat"):
        # Prefer first-minute runtime snapshot for live internet verdict.
        risk = _risk_status_from_snapshot()
        if risk == "UNKNOWN":
            net = str(payload.get("internet", "unknown")).strip().upper()
            if net == "OK":
                risk = "SAFE"
            elif net == "FAIL":
                risk = "FAIL"
            else:
                risk = "CHECKING"
        return _normal_render_spec(payload, mode, risk)

    return {"state": "warning", "msg": "MODE N/A"}


def _same_render(desired: Dict[str, Any], last_payload: Dict[str, Any]) -> bool:
    last_render = {}
    if isinstance(last_payload, dict):
        if isinstance(last_payload.get("render"), dict):
            last_render = last_payload.get("render") or {}
        elif isinstance(last_payload, dict):
            # backward compatibility: raw render dict
            last_render = last_payload

    return _visual_fingerprint(desired) == _visual_fingerprint(last_render)


def _to_int_or_none(value: Any) -> int | None:
    try:
        return int(float(str(value).strip()))
    except Exception:
        return None


def _signal_bucket(signal_value: Any) -> str:
    # Keep in sync with py/azazel_edge_epd.py:render_normal icon thresholds.
    signal_dbm = _to_int_or_none(signal_value)
    if signal_dbm is None:
        return "none"
    if signal_dbm >= -60:
        return "strong"
    if signal_dbm >= -70:
        return "medium"
    return "weak"


def _visual_fingerprint(render: Dict[str, Any]) -> Dict[str, Any]:
    """Return a fingerprint that matches what the panel actually displays."""
    state = str(render.get("state", "")).strip().lower()
    if state == "normal":
        return {
            "state": "normal",
            "mode_label": str(render.get("mode_label", "")).strip().upper(),
            "ssid": str(render.get("ssid", "")).strip(),
            "risk_status": str(render.get("risk_status", "")).strip().upper(),
            "suspicion": int(_to_int_or_none(render.get("suspicion")) or 0),
            "signal_bucket": _signal_bucket(render.get("signal")),
        }
    return {
        "state": state,
        "msg": str(render.get("msg", "")).strip(),
    }


def _resolve_epd_script(root: Path) -> Path | None:
    """Resolve EPD renderer path with backward compatibility."""
    candidates = (
        root / "py" / "azazel_edge_epd.py",
        root / "py" / "azazel_epd.py",
    )
    for path in candidates:
        if path.exists():
            return path
    return None


def main() -> int:
    payload = _safe_load(EPD_STATE)
    if not payload:
        payload = _fallback_epd_state()

    root = Path(os.environ.get("AZAZEL_ROOT", str(Path(__file__).resolve().parents[1])))
    epd_script = _resolve_epd_script(root)
    if epd_script is None:
        return 0

    desired = _desired_render_spec(payload)
    last = _safe_load(EPD_LAST_RENDER)
    if _same_render(desired, last):
        return 0

    cmd = [sys.executable, str(epd_script), "--state", desired.get("state", "warning")]
    if desired.get("state") == "normal":
        cmd.extend(
            [
                "--ssid", str(desired.get("ssid", "")),
                "--mode-label", str(desired.get("mode_label", "SHIELD")),
                "--risk-status", str(desired.get("risk_status", "UNKNOWN")),
                "--suspicion", str(desired.get("suspicion", 0)),
            ]
        )
        if desired.get("signal") is not None:
            cmd.extend(["--signal", str(desired.get("signal"))])
    else:
        cmd.extend(["--msg", str(desired.get("msg", "MODE"))])

    try:
        subprocess.run(cmd, timeout=45, check=False)
    except Exception:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
