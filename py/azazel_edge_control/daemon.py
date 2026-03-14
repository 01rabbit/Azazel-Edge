#!/usr/bin/env python3
"""
Azazel-Edge Control Daemon
Listens on Unix socket /run/azazel-edge/control.sock and executes actions
"""

import json
import time
import sys
import os
import logging
import socket
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse
try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None

# Import project modules
PROJECT_ROOT = Path(__file__).resolve().parents[2]
PY_ROOT = PROJECT_ROOT / "py"
sys.path.insert(0, str(Path(__file__).parent))
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))
from wifi_scan import scan_wifi, get_wireless_interface, check_networkmanager
from mode_manager import ModeManager
from wifi_connect import connect_wifi, update_state_json
from azazel_edge.evaluators import NocEvaluator
from azazel_edge.evidence_plane import NocProbeAdapter, build_client_inventory
from azazel_edge.sensors.network_health import NetworkHealthMonitor
from azazel_edge.path_schema import (
    first_minute_config_candidates,
    migrate_schema,
    portal_env_candidates,
    snapshot_path_candidates,
    status as path_schema_status,
    warn_if_legacy_path,
)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('azazel-edge-daemon')
MODE_MANAGER = ModeManager(logger=logger)

SOCKET_PATH = Path('/run/azazel-edge/control.sock')
AI_ADVISORY_PATH = Path("/run/azazel-edge/ai_advisory.json")
PORTAL_VIEWER_SERVICE = "azazel-edge-portal-viewer.service"
PORTAL_VIEWER_ENV_CANDIDATES = portal_env_candidates()
PORTAL_START_URL_RUNTIME_PATH = Path("/run/azazel-edge/portal-viewer-start-url")
SCRIPT_ROOT = PROJECT_ROOT / "py" / "azazel_edge_control" / "scripts"
ACTION_SCRIPTS = {
    'refresh': str(SCRIPT_ROOT / 'refresh.sh'),
    'reprobe': str(SCRIPT_ROOT / 'reprobe.sh'),
    'contain': str(SCRIPT_ROOT / 'contain.sh'),
    'stage_open': str(SCRIPT_ROOT / 'stage_open.sh'),
    'disconnect': str(SCRIPT_ROOT / 'disconnect.sh'),
    'details': str(SCRIPT_ROOT / 'details.sh'),
    'shutdown': str(SCRIPT_ROOT / 'shutdown.sh'),
    'reboot': str(SCRIPT_ROOT / 'reboot.sh'),
}

# Rate limiting
last_action_time = {}
RATE_LIMITS = {
    'wifi_scan': 1.0,      # 1 second
    'wifi_connect': 3.0,   # 3 seconds
    'mode_set': 2.0,       # 2 seconds
    'shutdown': 10.0,      # Prevent accidental repeated shutdown requests
    'reboot': 10.0,        # Prevent accidental repeated reboot requests
}
PORTAL_DEFAULT_START_URL = "http://neverssl.com"
_LAST_CPU_TOTAL: float | None = None
_LAST_CPU_IDLE: float | None = None
NETWORK_HEALTH = NetworkHealthMonitor(
    cache_ttl_sec=float(os.environ.get("AZAZEL_HEALTH_CACHE_TTL", "25")),
    captive_url=os.environ.get("AZAZEL_CAPTIVE_CHECK_URL", "http://connectivitycheck.gstatic.com/generate_204"),
)
SURICATA_ADVISORY_TTL_SEC = int(os.environ.get("AZAZEL_SURICATA_ADVISORY_TTL_SEC", "300"))
NOC_REFRESH_SEC = max(5.0, float(os.environ.get("AZAZEL_NOC_REFRESH_SEC", "20")))
NOC_EVALUATOR = NocEvaluator()
NOC_CACHE_LOCK = threading.Lock()
_NOC_CACHE: dict[str, Any] = {
    "key": "",
    "ts": 0.0,
    "payload": {},
}
_NOC_ADAPTER: Optional[NocProbeAdapter] = None
_NOC_ADAPTER_KEY = ""


def _read_portal_viewer_env() -> dict[str, str]:
    """Read portal-viewer.env (schema-aware) into a dict."""
    parsed: dict[str, str] = {}
    try:
        for env_path in PORTAL_VIEWER_ENV_CANDIDATES:
            if not env_path.exists():
                continue
            warn_if_legacy_path(env_path, logger=logger)
            for raw in env_path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[7:].strip()
                key, value = line.split("=", 1)
                parsed[key.strip()] = value.strip().strip('"').strip("'")
            if parsed:
                break
    except Exception as e:
        logger.debug(f"Failed to read portal env: {e}")
    return parsed


def _normalize_http_url(candidate: object) -> str:
    """Return normalized http(s) URL or empty string."""
    text = str(candidate or "").strip()
    if not text or any(ch in text for ch in ("\r", "\n")):
        return ""
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return text


def _write_runtime_start_url(url: str) -> tuple[bool, str]:
    """Write transient portal start URL for next portal-viewer launch."""
    try:
        PORTAL_START_URL_RUNTIME_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = PORTAL_START_URL_RUNTIME_PATH.with_suffix(".tmp")
        tmp.write_text(url + "\n", encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, PORTAL_START_URL_RUNTIME_PATH)
        return True, ""
    except Exception as e:
        return False, str(e)


def _service_is_active(service: str) -> bool:
    try:
        active = subprocess.run(
            ["/bin/systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return active.returncode == 0 and (active.stdout or "").strip() == "active"
    except Exception:
        return False


def _load_portal_viewer_endpoint(default_port: int = 6080) -> tuple[str, int]:
    """Read PORTAL_NOVNC_BIND/PORT from env file if present."""
    env = _read_portal_viewer_env()
    bind = str(env.get("PORTAL_NOVNC_BIND") or os.environ.get("PORTAL_NOVNC_BIND") or os.environ.get("MGMT_IP") or "10.55.0.10")
    try:
        port = int(env.get("PORTAL_NOVNC_PORT") or os.environ.get("PORTAL_NOVNC_PORT") or default_port)
    except Exception:
        port = default_port
    return bind, port


def _load_portal_start_url(default: str = PORTAL_DEFAULT_START_URL) -> str:
    env = _read_portal_viewer_env()
    url = _normalize_http_url(env.get("PORTAL_START_URL", ""))
    if url:
        return url
    fallback = _normalize_http_url(os.environ.get("PORTAL_START_URL", ""))
    return fallback or default


def _probe_hosts_for_bind(bind_host: str) -> list[str]:
    """Build probe host candidates from bind address."""
    host = str(bind_host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host in {"", "0.0.0.0", "::", "*"}:
        return ["127.0.0.1", "::1"]
    if host in {"localhost", "127.0.0.1", "::1"}:
        return [host]
    return [host, "127.0.0.1"]


def _tcp_open(port: int, hosts: list[str], timeout_sec: float = 0.2) -> bool:
    """Check TCP availability on any candidate host."""
    seen = set()
    for host in hosts:
        if host in seen:
            continue
        seen.add(host)
        try:
            with socket.create_connection((host, port), timeout=timeout_sec):
                return True
        except Exception:
            continue
    return False


def ensure_portal_viewer_ready(timeout_sec: float = 15.0, start_url: str | None = None) -> dict:
    """Start portal viewer service and wait until noVNC TCP port is reachable."""
    bind, port = _load_portal_viewer_endpoint()
    probe_hosts = _probe_hosts_for_bind(bind)
    requested_start_url = _normalize_http_url(start_url or "")
    if start_url and not requested_start_url:
        return {
            "ok": False,
            "error": "Invalid start_url (must be absolute http/https URL)",
            "service": PORTAL_VIEWER_SERVICE,
            "bind": bind,
            "probe_hosts": probe_hosts,
            "port": port,
            "ts": time.time(),
        }
    try:
        service_action = "start"
        if requested_start_url:
            ok, err = _write_runtime_start_url(requested_start_url)
            if not ok:
                return {
                    "ok": False,
                    "error": f"Failed to stage runtime portal URL: {err}",
                    "service": PORTAL_VIEWER_SERVICE,
                    "bind": bind,
                    "probe_hosts": probe_hosts,
                    "port": port,
                    "start_url": requested_start_url,
                    "ts": time.time(),
                }
            # Restart when URL is requested so Chromium always lands on the target page.
            service_action = "restart" if _service_is_active(PORTAL_VIEWER_SERVICE) else "start"

        start = subprocess.run(
            ["/bin/systemctl", service_action, PORTAL_VIEWER_SERVICE],
            capture_output=True,
            text=True,
            timeout=6,
        )
        if start.returncode != 0:
            err = (start.stderr or start.stdout or "").strip() or "systemctl start failed"
            return {
                "ok": False,
                "error": err,
                "service": PORTAL_VIEWER_SERVICE,
                "bind": bind,
                "probe_hosts": probe_hosts,
                "port": port,
                "service_action": service_action,
                "start_url": requested_start_url or _load_portal_start_url(),
                "ts": time.time(),
            }

        deadline = time.time() + max(1.0, timeout_sec)
        last_active = ""
        while time.time() < deadline:
            active = subprocess.run(
                ["/bin/systemctl", "is-active", PORTAL_VIEWER_SERVICE],
                capture_output=True,
                text=True,
                timeout=2,
            )
            last_active = (active.stdout or "").strip()
            if active.returncode == 0 and last_active == "active" and _tcp_open(port, probe_hosts):
                return {
                    "ok": True,
                    "service": PORTAL_VIEWER_SERVICE,
                    "active": True,
                    "ready": True,
                    "bind": bind,
                    "probe_hosts": probe_hosts,
                    "port": port,
                    "service_action": service_action,
                    "start_url": requested_start_url or _load_portal_start_url(),
                    "ts": time.time(),
                }
            time.sleep(0.25)

        return {
            "ok": False,
            "error": (
                f"Portal viewer not ready within {timeout_sec:.0f}s "
                f"(is-active={last_active or 'unknown'}, bind={bind}, probe={probe_hosts})"
            ),
            "service": PORTAL_VIEWER_SERVICE,
            "active": last_active == "active",
            "ready": False,
            "bind": bind,
            "probe_hosts": probe_hosts,
            "port": port,
            "service_action": service_action,
            "start_url": requested_start_url or _load_portal_start_url(),
            "ts": time.time(),
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "service": PORTAL_VIEWER_SERVICE,
            "bind": bind,
            "probe_hosts": probe_hosts,
            "port": port,
            "start_url": requested_start_url or _load_portal_start_url(),
            "ts": time.time(),
        }


def load_control_flags() -> dict:
    flags = {"suppress_auto_wifi": True}
    if yaml is None:
        return flags

    repo_cfg = Path(__file__).resolve().parents[2] / "configs" / "first_minute.yaml"
    candidates = []
    for env_key in ("AZAZEL_FIRST_MINUTE_CONFIG", "AZAZEL_CONFIG"):
        env_path = os.environ.get(env_key)
        if env_path:
            candidates.append(Path(env_path))
    candidates.extend(first_minute_config_candidates())
    candidates.append(repo_cfg)

    for path in candidates:
        try:
            if not path.exists():
                continue
            warn_if_legacy_path(path, logger=logger)
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict) and "suppress_auto_wifi" in data:
                flags["suppress_auto_wifi"] = bool(data.get("suppress_auto_wifi"))
                logger.info(f"Loaded control flag from {path}: suppress_auto_wifi={flags['suppress_auto_wifi']}")
                return flags
        except Exception as e:
            logger.debug(f"Failed to read control config {path}: {e}")
    return flags


def _snapshot_candidates() -> list[Path]:
    candidates = snapshot_path_candidates(home=Path.home())
    runtime_only = [p for p in candidates if str(p).startswith("/run/")]
    if runtime_only:
        return runtime_only
    return candidates[:2]


def _parse_json_dict_lenient(text: str) -> dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    try:
        parsed, _idx = json.JSONDecoder().raw_decode(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _read_cpu_usage_percent() -> float:
    global _LAST_CPU_TOTAL, _LAST_CPU_IDLE
    try:
        fields = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()
        if not fields or fields[0] != "cpu":
            return 0.0
        nums = [float(x) for x in fields[1:8]]
        user, nice, system, idle, iowait, irq, softirq = nums
        total = user + nice + system + idle + iowait + irq + softirq
        idle_all = idle + iowait
        if _LAST_CPU_TOTAL is None or _LAST_CPU_IDLE is None:
            _LAST_CPU_TOTAL = total
            _LAST_CPU_IDLE = idle_all
            return 0.0
        total_delta = total - _LAST_CPU_TOTAL
        idle_delta = idle_all - _LAST_CPU_IDLE
        _LAST_CPU_TOTAL = total
        _LAST_CPU_IDLE = idle_all
        if total_delta <= 0:
            return 0.0
        usage = (1.0 - (idle_delta / total_delta)) * 100.0
        return round(max(0.0, min(100.0, usage)), 1)
    except Exception:
        return 0.0


def _read_mem_usage() -> tuple[int, int, int]:
    try:
        mem_total_kb = 0
        mem_available_kb = 0
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                mem_total_kb = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                mem_available_kb = int(line.split()[1])
        if mem_total_kb <= 0:
            return 0, 0, 0
        used_kb = max(0, mem_total_kb - mem_available_kb)
        percent = int(round((used_kb / mem_total_kb) * 100.0))
        return percent, int(used_kb / 1024), int(mem_total_kb / 1024)
    except Exception:
        return 0, 0, 0


def _read_temp_c() -> float:
    candidates = [
        Path("/sys/class/thermal/thermal_zone0/temp"),
        Path("/sys/class/hwmon/hwmon0/temp1_input"),
    ]
    for p in candidates:
        try:
            if not p.exists():
                continue
            raw = p.read_text(encoding="utf-8").strip()
            val = float(raw)
            if val > 1000:
                val = val / 1000.0
            return round(val, 1)
        except Exception:
            continue
    return 0.0


def _read_signal_dbm(iface: str = "wlan0") -> int | None:
    try:
        result = subprocess.run(
            ["iw", "dev", iface, "link"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            s = line.strip().lower()
            if s.startswith("signal:") and "dbm" in s:
                return int(float(s.split()[1]))
    except Exception:
        return None
    return None


def _default_route_info() -> dict[str, str]:
    """Best-effort default route info for current uplink."""
    result = {"up_if": "-", "up_ip": "-", "gateway_ip": "-", "uplink_type": "unknown"}
    out: list[str] = []
    for ip_cmd in ("/usr/sbin/ip", "/sbin/ip", "ip"):
        try:
            out = (
                subprocess.run(
                    [ip_cmd, "-4", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                ).stdout.strip().splitlines()
            )
            if out:
                break
        except Exception:
            continue

    if not out:
        return result

    line = out[0].strip().split()
    if "dev" in line:
        try:
            result["up_if"] = line[line.index("dev") + 1]
        except Exception:
            pass
    if "via" in line:
        try:
            result["gateway_ip"] = line[line.index("via") + 1]
        except Exception:
            pass
    if "src" in line:
        try:
            result["up_ip"] = line[line.index("src") + 1]
        except Exception:
            pass

    iface = result["up_if"]
    if iface.startswith("wl"):
        result["uplink_type"] = "wifi"
    elif iface.startswith("eth") or iface.startswith("en"):
        result["uplink_type"] = "ethernet"
    elif iface != "-":
        result["uplink_type"] = "other"
    return result


def _event_payloads(events: list[Any]) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for event in events:
        if hasattr(event, "to_dict"):
            payload = event.to_dict()
        elif isinstance(event, dict):
            payload = dict(event)
        else:
            continue
        if isinstance(payload.get("attrs"), dict):
            payloads.append(payload)
    return payloads


def _parse_reason_targets(reasons: Any, prefixes: tuple[str, ...]) -> list[str]:
    if not isinstance(reasons, list):
        return []
    targets: list[str] = []
    for item in reasons:
        text = str(item or "")
        for prefix in prefixes:
            if text.startswith(prefix):
                value = text[len(prefix):].strip()
                if value:
                    targets.append(value)
                break
    return sorted(dict.fromkeys(targets))


def _capacity_state_from_label(label: str) -> str:
    mapping = {
        "good": "normal",
        "degraded": "elevated",
        "poor": "congested",
        "critical": "congested",
    }
    return mapping.get(str(label or "").strip().lower(), "unknown")


def _select_capacity_row(event_payloads: list[dict[str, Any]], preferred_uplink: str) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for payload in event_payloads:
        if str(payload.get("kind") or "") != "capacity_pressure":
            continue
        attrs = payload.get("attrs")
        if isinstance(attrs, dict):
            rows.append(attrs)
    if not rows:
        return {}
    uplink = str(preferred_uplink or "").strip()
    if uplink:
        for row in rows:
            if str(row.get("interface") or "").strip() == uplink:
                return row
    return rows[0]


def _traffic_top_sources(event_payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for payload in event_payloads:
        if str(payload.get("kind") or "") != "traffic_concentration":
            continue
        attrs = payload.get("attrs")
        if not isinstance(attrs, dict):
            continue
        top_sources = attrs.get("top_sources")
        if not isinstance(top_sources, list):
            continue
        normalized: list[dict[str, Any]] = []
        for item in top_sources[:5]:
            if not isinstance(item, dict):
                continue
            normalized.append(
                {
                    "src_ip": str(item.get("src_ip") or ""),
                    "bytes": int(item.get("bytes") or 0),
                    "packets": int(item.get("packets") or 0),
                    "flows": int(item.get("flows") or 0),
                }
            )
        return normalized
    return []


def _build_noc_runtime_projection(
    *,
    evaluation: dict[str, Any],
    event_payloads: list[dict[str, Any]],
    inventory_summary: dict[str, Any],
    inventory_sessions: list[dict[str, Any]] | None = None,
    preferred_uplink: str = "",
) -> dict[str, Any]:
    capacity = evaluation.get("capacity_health") if isinstance(evaluation.get("capacity_health"), dict) else {}
    service = evaluation.get("service_health") if isinstance(evaluation.get("service_health"), dict) else {}
    resolution = evaluation.get("resolution_health") if isinstance(evaluation.get("resolution_health"), dict) else {}
    config_drift = evaluation.get("config_drift_health") if isinstance(evaluation.get("config_drift_health"), dict) else {}
    blast_radius = evaluation.get("affected_scope") if isinstance(evaluation.get("affected_scope"), dict) else {}
    incident = evaluation.get("incident_summary") if isinstance(evaluation.get("incident_summary"), dict) else {}
    summary = evaluation.get("summary") if isinstance(evaluation.get("summary"), dict) else {}

    capacity_reasons = capacity.get("reasons") if isinstance(capacity.get("reasons"), list) else []
    service_reasons = service.get("reasons") if isinstance(service.get("reasons"), list) else []
    resolution_reasons = resolution.get("reasons") if isinstance(resolution.get("reasons"), list) else []
    drift_reasons = config_drift.get("reasons") if isinstance(config_drift.get("reasons"), list) else []

    capacity_row = _select_capacity_row(event_payloads, preferred_uplink=preferred_uplink)
    capacity_state = str(capacity_row.get("state") or _capacity_state_from_label(str(capacity.get("label") or "")))
    utilization_pct = capacity_row.get("avg_utilization_pct")
    if utilization_pct is None:
        utilization_pct = capacity_row.get("peak_utilization_pct")
    capacity_mode = str(capacity_row.get("mode") or "deterministic_noc_evaluator_v1")

    changed_fields = _parse_reason_targets(drift_reasons, ("config_drift:",))
    baseline_state = "present"
    if "config_baseline_missing" in drift_reasons:
        baseline_state = "missing"
    elif "config_baseline_invalid" in drift_reasons:
        baseline_state = "invalid"
    if changed_fields:
        config_state = "drift"
    elif baseline_state == "missing":
        config_state = "baseline_missing"
    elif baseline_state == "invalid":
        config_state = "baseline_invalid"
    else:
        config_state = "normal"
    rollback_hint = ""
    if config_state == "drift":
        rollback_hint = "review_changed_fields_and_restore_last_known_good"
    elif config_state == "baseline_missing":
        rollback_hint = "create_last_known_good_baseline"
    elif config_state == "baseline_invalid":
        rollback_hint = "validate_baseline_and_restore_valid_state"

    inventory = inventory_summary if isinstance(inventory_summary, dict) else {}
    sessions_raw = inventory_sessions if isinstance(inventory_sessions, list) else []
    sessions: list[dict[str, Any]] = []
    for row in sessions_raw[:120]:
        if not isinstance(row, dict):
            continue
        sessions.append(
            {
                "session_key": str(row.get("session_key") or ""),
                "mac": str(row.get("mac") or "").lower(),
                "ip": str(row.get("ip") or ""),
                "hostname": str(row.get("hostname") or ""),
                "interface_or_segment": str(row.get("interface_or_segment") or "unknown"),
                "last_seen": str(row.get("last_seen") or ""),
                "session_state": str(row.get("session_state") or "unknown_present"),
                "sot_status": str(row.get("sot_status") or "unknown"),
                "evidence_ids": [str(item) for item in (row.get("evidence_ids") or []) if str(item)],
            }
        )
    return {
        "noc_summary": {
            "status": str(summary.get("status") or "unknown"),
            "degraded_mode": bool(summary.get("degraded_mode")),
            "reasons": [str(item) for item in (summary.get("reasons") or []) if str(item)],
        },
        "noc_capacity": {
            "state": capacity_state,
            "mode": capacity_mode,
            "utilization_pct": float(utilization_pct) if isinstance(utilization_pct, (int, float)) else None,
            "top_sources": _traffic_top_sources(event_payloads),
            "signals": [str(item) for item in capacity_reasons],
        },
        "noc_client_inventory": {
            "current_client_count": int(inventory.get("current_client_count") or 0),
            "new_client_count": int(inventory.get("new_client_count") or 0),
            "unknown_client_count": int(inventory.get("unknown_client_count") or 0),
            "unauthorized_client_count": int(inventory.get("unauthorized_client_count") or 0),
            "inventory_mismatch_count": int(inventory.get("inventory_mismatch_count") or 0),
            "stale_session_count": int(inventory.get("stale_session_count") or 0),
        },
        "noc_client_sessions": sessions,
        "noc_service_assurance": {
            "status": str(service.get("label") or "unknown"),
            "degraded_targets": _parse_reason_targets(
                service_reasons,
                (
                    "service_probe_failed:",
                    "service_window_down:",
                    "service_window_degraded:",
                    "service_off:",
                    "service_degraded:",
                    "service_result:",
                ),
            ),
        },
        "noc_resolution_assurance": {
            "status": str(resolution.get("label") or "unknown"),
            "failed_targets": _parse_reason_targets(
                resolution_reasons,
                (
                    "resolution_failed:",
                    "resolution_window_failed:",
                    "resolution_window_degraded:",
                ),
            ),
        },
        "noc_blast_radius": {
            "affected_uplinks": [str(item) for item in (blast_radius.get("affected_uplinks") or []) if str(item)],
            "affected_segments": [str(item) for item in (blast_radius.get("affected_segments") or []) if str(item)],
            "related_service_targets": [str(item) for item in (blast_radius.get("related_service_targets") or []) if str(item)],
            "affected_client_count": int(blast_radius.get("affected_client_count") or 0),
            "critical_client_count": int(blast_radius.get("critical_client_count") or 0),
        },
        "noc_config_drift": {
            "status": config_state,
            "baseline_state": baseline_state,
            "changed_fields": changed_fields,
            "rollback_hint": rollback_hint,
        },
        "noc_incident_summary": {
            "incident_id": str(incident.get("incident_id") or ""),
            "probable_cause": str(incident.get("probable_cause") or "stable"),
            "confidence": float(incident.get("confidence") or 0.0),
            "supporting_symptoms": [str(item) for item in (incident.get("supporting_symptoms") or []) if str(item)],
        },
        "noc_runtime": {
            "status": str(summary.get("status") or "unknown"),
            "evidence_count": int(len(evaluation.get("evidence_ids") or [])),
            "updated_epoch": time.time(),
        },
    }


def _compute_live_noc_projection(up_if: str, down_if: str, gateway_ip: str) -> dict[str, Any]:
    global _NOC_ADAPTER, _NOC_ADAPTER_KEY
    now = time.time()
    key = f"{up_if}|{down_if}|{gateway_ip}"
    refresh_sec = max(5.0, float(NOC_REFRESH_SEC))
    with NOC_CACHE_LOCK:
        cache_ts = float(_NOC_CACHE.get("ts") or 0.0)
        cache_key = str(_NOC_CACHE.get("key") or "")
        cache_payload = _NOC_CACHE.get("payload")
        if cache_key == key and isinstance(cache_payload, dict) and now - cache_ts < refresh_sec:
            return dict(cache_payload)

        if _NOC_ADAPTER is None or _NOC_ADAPTER_KEY != key:
            _NOC_ADAPTER = NocProbeAdapter(
                up_interface=str(up_if or "eth1"),
                down_interface=str(down_if or "usb0"),
                gateway_ip=str(gateway_ip or ""),
            )
            _NOC_ADAPTER_KEY = key

        events = _NOC_ADAPTER.collect()
        payloads = _event_payloads(events)
        inventory = build_client_inventory(events)
        inventory_summary = inventory.get("summary") if isinstance(inventory.get("summary"), dict) else {}
        inventory_sessions = inventory.get("sessions") if isinstance(inventory.get("sessions"), list) else []
        evaluation = NOC_EVALUATOR.evaluate(events)
        projection = _build_noc_runtime_projection(
            evaluation=evaluation,
            event_payloads=payloads,
            inventory_summary=inventory_summary,
            inventory_sessions=inventory_sessions,
            preferred_uplink=up_if,
        )
        _NOC_CACHE["key"] = key
        _NOC_CACHE["ts"] = now
        _NOC_CACHE["payload"] = projection
        return dict(projection)


def _enrich_snapshot(data: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(data)
    now = time.time()
    enriched["now_time"] = datetime.now().strftime("%H:%M:%S")
    enriched["snapshot_epoch"] = now

    route = _default_route_info()
    up_if = str(route.get("up_if") or "-")
    up_ip = str(route.get("up_ip") or "-")
    gateway_ip = str(route.get("gateway_ip") or "-")
    uplink_type = str(route.get("uplink_type") or "unknown")
    enriched["up_if"] = up_if
    enriched["up_ip"] = up_ip
    enriched["gateway_ip"] = gateway_ip
    enriched.setdefault("down_if", "usb0")
    enriched.setdefault("down_ip", "10.12.194.1")
    if uplink_type == "ethernet":
        enriched["ssid"] = f"ETH:{up_if}" if up_if != "-" else "ETH"

    cpu_percent = _read_cpu_usage_percent()
    mem_percent, mem_used_mb, mem_total_mb = _read_mem_usage()
    temp_c = _read_temp_c()
    signal_dbm = _read_signal_dbm(up_if if up_if.startswith("wl") else "wlan0")

    enriched["cpu_percent"] = cpu_percent
    enriched["mem_percent"] = mem_percent
    enriched["mem_used_mb"] = mem_used_mb
    enriched["mem_total_mb"] = mem_total_mb
    enriched["temp_c"] = temp_c
    if signal_dbm is not None:
        enriched["signal_dbm"] = signal_dbm

    monitoring = enriched.get("monitoring")
    if not isinstance(monitoring, dict):
        monitoring = {}
    monitoring.setdefault("suricata", "UNKNOWN")
    monitoring.setdefault("opencanary", "UNKNOWN")
    monitoring.setdefault("ntfy", "UNKNOWN")
    enriched["monitoring"] = monitoring

    connection = enriched.get("connection")
    if not isinstance(connection, dict):
        connection = {}
    if uplink_type == "wifi":
        connection["wifi_state"] = "CONNECTED"
    elif uplink_type == "ethernet":
        connection["wifi_state"] = "N/A(ETH)"
    else:
        connection.setdefault("wifi_state", "DISCONNECTED")
    connection["uplink_if"] = up_if
    connection["uplink_type"] = uplink_type
    connection.setdefault("internet_check", "N/A")
    connection.setdefault("usb_nat", "OFF")

    iface = up_if if up_if != "-" else str(enriched.get("up_if", "wlan0") or "wlan0").strip()
    gateway = gateway_ip if gateway_ip != "-" else str(enriched.get("gateway_ip", "") or "").strip()
    health = NETWORK_HEALTH.assess(iface=iface, gateway_ip=gateway)
    enriched["network_health"] = health
    if health.get("internet_check"):
        connection["internet_check"] = str(health.get("internet_check"))
    connection["captive_portal"] = str(health.get("captive_portal", connection.get("captive_portal", "NA")))
    connection["captive_portal_reason"] = str(
        health.get("captive_portal_reason", connection.get("captive_portal_reason", "NOT_CHECKED"))
    )
    try:
        noc_projection = _compute_live_noc_projection(
            up_if=up_if,
            down_if=str(enriched.get("down_if") or "usb0"),
            gateway_ip=gateway_ip,
        )
        if isinstance(noc_projection, dict):
            enriched.update(noc_projection)
    except Exception as exc:
        logger.debug(f"Failed to evaluate live NOC projection: {exc}")

    user_state = str(enriched.get("user_state", "") or "").upper()
    signals = health.get("signals", []) if isinstance(health.get("signals"), list) else []
    if user_state in ("", "CHECKING", "SAFE") and signals:
        if "captive_portal" in signals or "evil_ap" in signals:
            enriched["user_state"] = "CONTAINED"
        else:
            enriched["user_state"] = "LIMITED"

    evidence = enriched.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
    if signals:
        evidence.append(f"net_health={health.get('status','NA')} signals={','.join(signals)}")
    else:
        evidence.append(f"net_health={health.get('status','NA')}")
    enriched["evidence"] = [str(x) for x in evidence][-8:]

    reasons = enriched.get("reasons")
    if not isinstance(reasons, list):
        reasons = []
    reasons = [str(x) for x in reasons if not str(x).startswith("health:")]
    if signals:
        reasons.append(f"health:{signals[0]}")
    enriched["reasons"] = reasons[-5:]

    enriched["connection"] = connection

    # Keep WebUI/TUI status source consistent.
    internal = enriched.get("internal")
    if not isinstance(internal, dict):
        internal = {}
    state_name = str(internal.get("state_name", "") or "").upper()
    try:
        suspicion = int(float(str(internal.get("suspicion", enriched.get("risk_score", 0))).strip()))
    except Exception:
        suspicion = 0
    try:
        advisory_epoch = float(enriched.get("advisory_epoch") or 0)
    except Exception:
        advisory_epoch = 0.0
    if advisory_epoch <= 0 and AI_ADVISORY_PATH.exists():
        try:
            advisory_payload = json.loads(AI_ADVISORY_PATH.read_text(encoding="utf-8"))
            if isinstance(advisory_payload, dict):
                advisory_epoch = float(advisory_payload.get("ts") or 0)
                if advisory_epoch > 0:
                    enriched["advisory_epoch"] = advisory_epoch
        except Exception:
            advisory_epoch = 0.0
    advisory_age_sec = max(0.0, now - advisory_epoch) if advisory_epoch > 0 else 0.0
    advisory_stale = bool(advisory_epoch and advisory_age_sec > float(SURICATA_ADVISORY_TTL_SEC))
    health_status = str(health.get("status") or "").upper()
    current_user_state = str(enriched.get("user_state", "") or "").upper()
    if advisory_stale:
        reasons = [str(x) for x in enriched.get("reasons", []) if not str(x).startswith("suricata_sid=")]
        enriched["reasons"] = reasons[-5:]
        attack = enriched.get("attack")
        if not isinstance(attack, dict):
            attack = {}
        attack["suricata_alert"] = False
        attack["stale_advisory_expired"] = True
        attack["suricata_sid"] = 0
        attack["suricata_severity"] = 0
        enriched["attack"] = attack
        enriched["suricata_critical"] = 0
        enriched["suricata_warning"] = 0
        enriched["suricata_info"] = 0
        if not signals and health_status == "SAFE":
            suspicion = 0
            enriched["user_state"] = "SAFE"
            state_name = "NORMAL"
            enriched["recommendation"] = "No active issues detected"
            enriched["llm"] = {"status": "idle", "reason": "stale_advisory_expired"}
            enriched["ops_coach"] = {}
            idle_second_pass = {
                "stage": "second_pass",
                "engine": "evidence_plane_soc_v1",
                "status": "idle",
                "reason": "stale_advisory_expired",
                "evidence_count": 0,
                "flow_support_count": 0,
                "soc": {
                    "status": "low",
                    "reasons": [],
                    "attack_candidates": [],
                    "ti_matches": [],
                    "sigma_hits": [],
                    "yara_hits": [],
                    "correlation": {"status": "none", "cluster_count": 0, "top_score": 0, "clusters": [], "reasons": [], "evidence_ids": []},
                    "event_count": 0,
                    "evidence_ids": [],
                },
            }
            enriched["second_pass"] = idle_second_pass
            decision_pipeline = enriched.get("decision_pipeline")
            if not isinstance(decision_pipeline, dict):
                decision_pipeline = {}
            first_pass = decision_pipeline.get("first_pass")
            if not isinstance(first_pass, dict):
                first_pass = {"engine": "tactical_scorer_v1", "role": "first_minute_triage"}
            decision_pipeline["first_pass"] = first_pass
            decision_pipeline["second_pass"] = dict(idle_second_pass)
            enriched["decision_pipeline"] = decision_pipeline
    if not signals and health_status == "SAFE" and suspicion <= 0:
        if current_user_state in ("", "CHECKING", "LIMITED", "SAFE"):
            enriched["user_state"] = "SAFE"
        if state_name in ("", "PROBE", "DEGRADED", "NORMAL"):
            state_name = "NORMAL"
        recommendation = str(enriched.get("recommendation") or "").strip().lower()
        if recommendation in ("", "initializing", "checking", "observe"):
            enriched["recommendation"] = "No active issues detected"
    if not state_name:
        state_name = {
            "SAFE": "NORMAL",
            "CHECKING": "PROBE",
            "LIMITED": "DEGRADED",
            "CONTAINED": "CONTAIN",
            "DECEPTION": "DECEPTION",
        }.get(str(enriched.get("user_state", "CHECKING")).upper(), "PROBE")
    internal["state_name"] = state_name
    internal["suspicion"] = suspicion
    internal.setdefault("decay", 0)
    enriched["internal"] = internal

    return enriched


def _default_snapshot_seed() -> dict[str, Any]:
    """Bootstrap snapshot when /run is empty after reboot."""
    route = _default_route_info()
    up_if = str(route.get("up_if") or "-")
    uplink_type = str(route.get("uplink_type") or "unknown")
    ssid = f"ETH:{up_if}" if uplink_type == "ethernet" and up_if != "-" else "-"
    return {
        "now_time": "",
        "ssid": ssid,
        "up_if": up_if,
        "up_ip": str(route.get("up_ip") or "-"),
        "gateway_ip": str(route.get("gateway_ip") or "-"),
        "down_if": "usb0",
        "down_ip": "10.12.194.1",
        "connection": {
            "wifi_state": "N/A(ETH)" if uplink_type == "ethernet" else "DISCONNECTED",
            "uplink_if": up_if,
            "uplink_type": uplink_type,
            "internet_check": "UNKNOWN",
            "usb_nat": "OFF",
            "captive_portal": "NA",
            "captive_portal_reason": "NOT_CHECKED",
        },
        "user_state": "CHECKING",
        "internal": {"state_name": "PROBE", "suspicion": 0, "decay": 0},
        "recommendation": "Initializing",
        "evidence": [],
        "snapshot_epoch": 0,
    }


def _seed_snapshot_if_missing() -> tuple[dict[str, Any] | None, Path | None]:
    """Create and return a minimal snapshot when no runtime snapshot exists."""
    seed = _default_snapshot_seed()
    for path in _snapshot_candidates():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text(json.dumps(seed, ensure_ascii=False), encoding="utf-8")
            warn_if_legacy_path(path, logger=logger)
            data = _parse_json_dict_lenient(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data, path
        except Exception as exc:
            logger.debug(f"Failed to seed snapshot {path}: {exc}")
    return None, None


def _persist_snapshot(path: Path, payload: dict[str, Any]) -> None:
    """Persist enriched snapshot so file readers (EPD/legacy tools) stay in sync."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
    except Exception as exc:
        logger.debug(f"Failed to persist snapshot {path}: {exc}")


def read_ui_snapshot() -> dict[str, Any]:
    """Read latest UI snapshot from schema-aware paths."""
    mode_payload: dict[str, Any] = {}
    try:
        mode_payload = MODE_MANAGER.status()
    except Exception as exc:
        logger.debug(f"Failed to read mode status: {exc}")
    for path in _snapshot_candidates():
        try:
            if not path.exists():
                continue
            warn_if_legacy_path(path, logger=logger)
            data = _parse_json_dict_lenient(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data = _enrich_snapshot(data)
                _persist_snapshot(path, data)
                if mode_payload.get("ok"):
                    data["mode"] = mode_payload.get("mode", {})
                return {
                    "ok": True,
                    "snapshot": data,
                    "path": str(path),
                    "ts": time.time(),
                }
        except Exception as exc:
            logger.debug(f"Failed to read snapshot {path}: {exc}")

    seeded, seeded_path = _seed_snapshot_if_missing()
    if isinstance(seeded, dict) and seeded_path is not None:
        data = _enrich_snapshot(seeded)
        _persist_snapshot(seeded_path, data)
        if mode_payload.get("ok"):
            data["mode"] = mode_payload.get("mode", {})
        return {
            "ok": True,
            "snapshot": data,
            "path": str(seeded_path),
            "ts": time.time(),
        }

    return {
        "ok": False,
        "error": "snapshot_not_found",
        "paths": [str(p) for p in _snapshot_candidates()],
        "ts": time.time(),
    }


def stream_ui_snapshots(conn: socket.socket, interval_sec: float = 1.0) -> None:
    """Stream newline-delimited snapshots whenever content changes."""
    interval = max(0.2, min(float(interval_sec), 5.0))
    last_fp = ""
    while True:
        payload = read_ui_snapshot()
        fp = json.dumps(payload.get("snapshot", {}), sort_keys=True, ensure_ascii=False) if payload.get("ok") else ""
        if fp != last_fp:
            conn.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
            last_fp = fp
        time.sleep(interval)

def ensure_socket_dir():
    """Create /run/azazel if needed"""
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Remove old socket if exists
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()
    
    # Set directory permissions so any user can access
    os.chmod(str(SOCKET_PATH.parent), 0o777)

def suppress_auto_wifi(enabled: bool = True):
    """Disable Wi-Fi auto-connect and disconnect existing session on startup."""
    if not enabled:
        logger.info("suppress_auto_wifi disabled by config; keeping existing Wi-Fi session")
        return
    try:
        iface = get_wireless_interface()
        if not iface:
            return

        # NetworkManager: disable autoconnect for all Wi-Fi connections and disconnect
        if check_networkmanager(iface):
            try:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "NAME,TYPE", "con", "show"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.splitlines():
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[1] == "802-11-wireless":
                        subprocess.run(
                            ["nmcli", "con", "mod", parts[0], "connection.autoconnect", "no"],
                            capture_output=True,
                            timeout=5
                        )
                subprocess.run(
                    ["nmcli", "dev", "disconnect", iface],
                    capture_output=True,
                    timeout=5
                )
                logger.info("suppress_auto_wifi enabled: disconnected Wi-Fi and disabled autoconnect profiles")
            except Exception as e:
                logger.debug(f"Failed to disable NetworkManager auto-connect: {e}")
        else:
            logger.warning("NetworkManager not found or not managing interface")

        # Update UI snapshot to reflect disconnected state
        update_state_json(
            "DISCONNECTED",
            wifi_error=None,
            ssid="",
            ip_wlan="",
            gateway_ip="",
            bssid="",
            usb_nat="OFF",
            internet_check="N/A",
            captive_probe_iface="",
            captive_portal="NA",
            captive_portal_reason="SUPPRESSED_AT_BOOT",
            captive_checked_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
    except Exception as e:
        logger.debug(f"suppress_auto_wifi failed: {e}")

def check_rate_limit(action: str) -> bool:
    """Check if action is rate-limited"""
    if action not in RATE_LIMITS:
        return True
    
    limit = RATE_LIMITS[action]
    now = time.time()
    last_time = last_action_time.get(action, 0)
    
    if now - last_time < limit:
        return False
    
    last_action_time[action] = now
    return True

def rate_limit_error(action: str, error_message: str) -> dict | None:
    """Return a standard rate-limit error payload when throttled."""
    if check_rate_limit(action):
        return None
    return {"ok": False, "error": error_message, "ts": time.time()}

def execute_wifi_action(action_name: str, params: dict) -> dict:
    """Execute Wi-Fi-specific actions (Python modules)"""
    if action_name == "wifi_scan":
        limited = rate_limit_error("wifi_scan", "Rate limit exceeded (1 req/sec)")
        if limited:
            return limited
        return scan_wifi()
    
    elif action_name == "wifi_connect":
        limited = rate_limit_error("wifi_connect", "Rate limit exceeded (1 req/3sec)")
        if limited:
            return limited
        
        # Extract parameters
        ssid = params.get("ssid")
        security = params.get("security", "UNKNOWN")
        passphrase = params.get("passphrase")
        persist = params.get("persist", False)
        
        if not ssid:
            return {"ok": False, "error": "Missing SSID parameter", "ts": time.time()}
        
        # NEVER log passphrase
        logger.info(f"Wi-Fi connect request: SSID={ssid}, Security={security}, Persist={persist}")
        
        return connect_wifi(ssid, security, passphrase, persist)
    
    return {"ok": False, "error": f"Unknown Wi-Fi action: {action_name}"}

def execute_action(action_name, params=None):
    """Execute action script and return result"""
    params = params or {}

    if action_name == "get_snapshot":
        return read_ui_snapshot()
    if action_name in ("mode_status", "mode_get"):
        status = MODE_MANAGER.status()
        status["ts"] = time.time()
        return status
    if action_name in ("mode_set", "mode_portal", "mode_shield", "mode_scapegoat"):
        limited = rate_limit_error("mode_set", "Rate limit exceeded (1 req/2sec)")
        if limited:
            return limited
        target_mode = str(params.get("mode", "")).strip().lower()
        if action_name.startswith("mode_") and action_name != "mode_set":
            target_mode = action_name.split("_", 1)[1]
        if target_mode not in ("portal", "shield", "scapegoat"):
            return {"ok": False, "error": f"Unknown mode: {target_mode}", "ts": time.time()}
        requested_by = str(params.get("requested_by", "daemon")).strip() or "daemon"
        dry_run = bool(params.get("dry_run", False))
        result = MODE_MANAGER.set_mode(target_mode, requested_by=requested_by, dry_run=dry_run)
        result["ts"] = time.time()
        return result
    if action_name == "mode_apply_default":
        limited = rate_limit_error("mode_set", "Rate limit exceeded (1 req/2sec)")
        if limited:
            return limited
        requested_by = str(params.get("requested_by", "boot")).strip() or "boot"
        result = MODE_MANAGER.apply_default(requested_by=requested_by)
        result["ts"] = time.time()
        return result
    if action_name == "path_schema_status":
        return {"ok": True, "schema": path_schema_status(), "ts": time.time()}
    if action_name == "migrate_path_schema":
        target = str(params.get("target_schema", "v2")).strip().lower()
        dry_run = bool(params.get("dry_run", False))
        result = migrate_schema(target, dry_run=dry_run, home=Path.home())
        result["ts"] = time.time()
        return result

    # Handle Wi-Fi actions via Python modules
    if action_name in ["wifi_scan", "wifi_connect"]:
        return execute_wifi_action(action_name, params)

    if action_name in ("shutdown", "reboot"):
        limited = rate_limit_error(action_name, "Rate limit exceeded (1 req/10sec)")
        if limited:
            return limited

    if action_name == "portal_viewer_open":
        timeout_raw = params.get("timeout_sec", 15)
        try:
            timeout_sec = float(timeout_raw)
        except Exception:
            timeout_sec = 15.0
        timeout_sec = max(1.0, min(timeout_sec, 30.0))
        start_url_raw = params.get("start_url", "")
        start_url = str(start_url_raw).strip() if isinstance(start_url_raw, str) else ""
        return ensure_portal_viewer_ready(timeout_sec=timeout_sec, start_url=start_url or None)
    
    # Handle shell script actions
    script_path = ACTION_SCRIPTS.get(action_name)
    
    if not script_path:
        return {'ok': False, 'error': f'Unknown action: {action_name}'}
    
    if not Path(script_path).exists():
        return {'ok': False, 'error': f'Script not found: {script_path}'}
    
    try:
        script_timeout = 90 if action_name in ("shutdown", "reboot") else 10
        result = subprocess.run(
            ['/bin/bash', script_path],
            timeout=script_timeout,
            capture_output=True,
            text=True
        )
        
        return {
            'ok': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr if result.returncode != 0 else None,
            'ts': time.time()
        }
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'Action timeout', 'ts': time.time()}
    except Exception as e:
        return {'ok': False, 'error': str(e), 'ts': time.time()}

def handle_client(conn, addr):
    """Handle incoming client connection"""
    try:
        raw = conn.recv(4096).decode("utf-8", errors="ignore")
        data = raw.strip()
        if not data:
            conn.sendall(b'{"ok": false, "error": "Empty request"}\n')
            return
        request = json.loads(data)
        action = request.get('action')
        params = request.get('params', {})

        if action == "watch_snapshot":
            interval = float((params or {}).get("interval_sec", 1.0))
            logger.info(f"Received action: watch_snapshot interval={interval}")
            stream_ui_snapshots(conn, interval_sec=interval)
            return
        
        # Special handling: NEVER log wifi_connect params (contains passphrase)
        if action == 'wifi_connect':
            logger.info(f"Received action: wifi_connect (params sanitized)")
        else:
            logger.info(f"Received action: {action}")
        
        result = execute_action(action, params)
        
        response = json.dumps(result, ensure_ascii=False) + "\n"
        conn.sendall(response.encode("utf-8"))
    except json.JSONDecodeError:
        conn.sendall(b'{"ok": false, "error": "Invalid JSON"}\n')
    except (BrokenPipeError, ConnectionResetError):
        logger.debug("Client disconnected")
    except Exception as e:
        logger.error(f"Error handling client: {e}")
        try:
            conn.sendall((json.dumps({'ok': False, 'error': str(e)}) + "\n").encode("utf-8"))
        except Exception:
            pass
    finally:
        conn.close()

def main():
    flags = load_control_flags()
    ensure_socket_dir()
    suppress_auto_wifi(enabled=bool(flags.get("suppress_auto_wifi", True)))
    logger.info("Azazel-Edge Control Daemon started")
    
    # Create Unix socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(SOCKET_PATH))
    # Make socket world-readable/writable for other processes
    os.chmod(str(SOCKET_PATH), 0o666)
    sock.listen(16)
    logger.info(f"Listening on {SOCKET_PATH}")
    
    try:
        while True:
            conn, _ = sock.accept()
            # Handle in thread to allow concurrent connections
            thread = threading.Thread(target=handle_client, args=(conn, _))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        sock.close()
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()

if __name__ == '__main__':
    main()
