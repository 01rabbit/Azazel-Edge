#!/usr/bin/env python3
"""
Azazel-Edge Control Daemon
Listens on Unix socket /run/azazel-edge/control.sock and executes actions
"""

import json
import time
import sys
import os
import grp
import logging
import ipaddress
import re
import select
import socket
import stat
import subprocess
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
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
from wifi_scan import (
    scan_wifi,
    get_wireless_interface,
    check_networkmanager,
    _nmcli_env,
    internal_lan_interfaces,
    nm_ap_profiles,
    InternalLanUnknown,
    select_uplink_wireless_interface,
)
from mode_manager import ModeManager
from wifi_connect import connect_wifi, update_state_json
from azazel_edge.evaluators import NocEvaluator
from azazel_edge.evidence_plane import EvidenceBus, EvidencePlaneService, NocProbeAdapter, build_client_inventory
from azazel_edge.sensors.link_watch import LinkStateWatcher
from azazel_edge.sensors.network_health import NetworkHealthMonitor
from azazel_edge.sensors.wifi_channel_scanner import scan_wifi_channels
from azazel_edge.sensors.wifi_scanner import scan_and_parse
from azazel_edge.path_schema import (
    config_dir_candidates,
    first_minute_config_candidates,
    migrate_schema,
    runtime_snapshot_path_candidates,
    status as path_schema_status,
    warn_if_legacy_path,
)
from azazel_edge.sot import SoTConfig, SoTValidationError, load_sot_file
from azazel_edge.peercred import account_uid, peer_credentials

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('azazel-edge-daemon')
MODE_MANAGER = ModeManager(logger=logger)

SOCKET_PATH = Path(os.environ.get("AZAZEL_CONTROL_SOCKET", "/run/azazel-edge/control.sock"))
RUNTIME_DIR_MODE = int(str(os.environ.get("AZAZEL_RUNTIME_DIR_MODE", "0770")), 8)
SOCKET_MODE = int(str(os.environ.get("AZAZEL_CONTROL_SOCKET_MODE", "0660")), 8)
RUNTIME_SOCKET_GROUP = str(os.environ.get("AZAZEL_RUNTIME_SOCKET_GROUP", ""))
# The AI agent's advisory and its snapshot fields (Edge#471 stage 2: the agent
# runs as azazel-agent and writes only in its own /run/azazel-edge-agent). The
# same variable and default as the agent's, read from the same environment
# file. This daemon is the only writer of the shared ui_snapshot.json: it
# merges AGENT_SNAPSHOT_KEYS from the agent's ai_snapshot.json.
AI_ADVISORY_PATH = Path(os.environ.get("AZAZEL_AI_ADVISORY", "/run/azazel-edge-agent/ai_advisory.json"))
AGENT_SNAPSHOT_PATH = AI_ADVISORY_PATH.parent / "ai_snapshot.json"
AGENT_SNAPSHOT_KEYS = (
    "advisory_epoch", "user_state", "recommendation", "reasons", "evidence",
    "suricata_critical", "suricata_warning", "suricata_info",
    "deferred_recent", "deferred_lifetime_at_snapshot",
    "llm", "ops_coach", "decision_pipeline", "second_pass", "llm_metrics", "internal", "attack",
)
AGENT_SNAPSHOT_MAX_BYTES = 1024 * 1024
SCRIPT_ROOT = PROJECT_ROOT / "py" / "azazel_edge_control" / "scripts"
ACTION_SCRIPTS = {
    'refresh': str(SCRIPT_ROOT / 'refresh.sh'),
    'reprobe': str(SCRIPT_ROOT / 'reprobe.sh'),
    'details': str(SCRIPT_ROOT / 'details.sh'),
    'shutdown': str(SCRIPT_ROOT / 'shutdown.sh'),
    'reboot': str(SCRIPT_ROOT / 'reboot.sh'),
}

# Actions this socket accepts by name but does not carry out (Edge#477). Their
# scripts only appended a line to /run/azazel-edge/action_requests.log, which
# nothing reads, and answered success. They now answer an explicit
# "not_implemented" so no caller shows them as done. Adding enforcement here
# is out of scope. The Web UI does not offer contain or stage_open (the port
# 8082 status API they used to go to has no server for this device) and sends
# disconnect as the fixed uplink_disconnect; only other local tools (the TUI)
# still send these names here.
NOT_IMPLEMENTED_ACTIONS = frozenset({"contain", "disconnect", "stage_open"})

# Rate limiting
last_action_time = {}
RATE_LIMITS = {
    'wifi_scan': 1.0,      # 1 second
    'wifi_connect': 3.0,   # 3 seconds
    'mode_set': 2.0,       # 2 seconds
    'shutdown': 10.0,      # Prevent accidental repeated shutdown requests
    'reboot': 10.0,        # Prevent accidental repeated reboot requests
    'uplink_disconnect': 3.0,
}

# --- control.sock peer table (Edge#471 stage 1) ---------------------------
# The daemon reads the peer's uid from the kernel (SO_PEERCRED) on every
# connection and allows an action only if this fixed table allows it:
#   * uid 0 (and the daemon's own account, which is root under the unit):
#     every action;
#   * the Web UI account (WEB_UI_ACCOUNT): exactly WEB_UI_ACTIONS;
#   * anyone else, an account that cannot be resolved, or a peer whose uid
#     the kernel does not report: nothing (refused and counted).
# ROOT_ONLY_ACTIONS need uid 0 whatever else applies. Nothing here is read
# from the environment or from the request.
WEB_UI_ACCOUNT = "azazel-web"
# What azazel_edge_web sends on this socket today (app.py ALLOWED_ACTIONS
# except disconnect, which it sends as uplink_disconnect, plus control_plane's
# snapshot reads),
# and the fixed operations moved here from the Web UI in Edge#471 stage 1
# (uplink_disconnect, sot_devices_replace, sot_devices_patch).
WEB_UI_ACTIONS = frozenset({
    "get_snapshot", "watch_snapshot",
    "refresh", "reprobe", "details",
    "wifi_scan", "wifi_connect",
    "shutdown", "reboot",
    "mode_set", "mode_status", "mode_get", "mode_portal", "mode_shield", "mode_scapegoat",
    "sot_trust_client",
    "uplink_disconnect", "sot_devices_replace", "sot_devices_patch",
})
ROOT_ONLY_ACTIONS = frozenset({"migrate_path_schema"})
_PEER_REFUSALS_LOCK = threading.Lock()
_PEER_REFUSALS: dict[str, Any] = {"total": 0, "by_uid": {}}
# One request per connection; SoT edits can exceed a single 4 KiB read. The
# whole request must arrive within REQUEST_READ_TIMEOUT_SEC (a total
# deadline, not per read). Connections are handled concurrently up to
# MAX_CONCURRENT_CLIENTS; non-root peers together may hold at most
# MAX_NONROOT_CLIENTS of them (so root tools always have headroom), and at
# most MAX_NONROOT_WATCHERS long-lived watch_snapshot streams. Beyond that a
# client is answered "busy" and closed. A watch stream whose client has gone
# is noticed while idle (end of stream on the socket) and frees its slot.
MAX_REQUEST_BYTES = 1024 * 1024
REQUEST_READ_TIMEOUT_SEC = 10.0
MAX_CONCURRENT_CLIENTS = 32
MAX_NONROOT_CLIENTS = 24
MAX_NONROOT_WATCHERS = 16


class _ClientSlots:
    """Concurrent connection accounting for control.sock (see above)."""

    def __init__(self, total: int, nonroot: int, nonroot_watchers: int):
        self._lock = threading.Lock()
        self.limits = (total, nonroot, nonroot_watchers)
        self.total = 0
        self.nonroot = 0
        self.watchers = 0

    def acquire(self, uid: Optional[int]) -> bool:
        total_max, nonroot_max, _ = self.limits
        with self._lock:
            if self.total >= total_max:
                return False
            if uid != 0:
                if self.nonroot >= nonroot_max:
                    return False
                self.nonroot += 1
            self.total += 1
            return True

    def release(self, uid: Optional[int]) -> None:
        with self._lock:
            self.total = max(0, self.total - 1)
            if uid != 0:
                self.nonroot = max(0, self.nonroot - 1)

    def acquire_watch(self, uid: Optional[int]) -> bool:
        if uid == 0:
            return True
        with self._lock:
            if self.watchers >= self.limits[2]:
                return False
            self.watchers += 1
            return True

    def release_watch(self, uid: Optional[int]) -> None:
        if uid == 0:
            return
        with self._lock:
            self.watchers = max(0, self.watchers - 1)


_CLIENT_SLOTS = _ClientSlots(MAX_CONCURRENT_CLIENTS, MAX_NONROOT_CLIENTS, MAX_NONROOT_WATCHERS)
_LAST_CPU_TOTAL: float | None = None
_LAST_CPU_IDLE: float | None = None


def _demo_fast() -> bool:
    """True when the booth/demo fast-reaction profile is enabled.

    Set ``AZAZEL_DEMO_FAST=1`` (dev/booth only, e.g. ``devstack up --demo-fast``)
    to collapse the dashboard reaction time: an injected alert reflects on the
    board within a few seconds instead of up to ~30s. It only lowers refresh /
    cache cadences — never any decision logic — so the deterministic outcome is
    unchanged. NEVER set it on an appliance/production deployment, where the
    slower cadences deliberately damp probe/telemetry cost.
    """
    return str(os.environ.get("AZAZEL_DEMO_FAST", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


_DEMO_FAST = _demo_fast()


def _timing_default(env_key: str, prod_default: str, demo_default: str) -> str:
    """Resolve a timing knob: an explicit env override always wins; otherwise
    demo-fast picks the snappy default and production picks the damped one."""
    override = os.environ.get(env_key)
    if override is not None and str(override).strip() != "":
        return override
    return demo_default if _DEMO_FAST else prod_default


NETWORK_HEALTH = NetworkHealthMonitor(
    cache_ttl_sec=float(_timing_default("AZAZEL_HEALTH_CACHE_TTL", "25", "3")),
    captive_url=os.environ.get("AZAZEL_CAPTIVE_CHECK_URL", "http://connectivitycheck.gstatic.com/generate_204"),
)
SURICATA_ADVISORY_TTL_SEC = int(os.environ.get("AZAZEL_SURICATA_ADVISORY_TTL_SEC", "300"))


def _dev_healthy_baseline() -> bool:
    """True when the dev-only healthy-baseline override is enabled.

    Set ``AZAZEL_DEV_HEALTHY_BASELINE=1`` only in the macOS dev profile
    (``tools/macdev/env.sh``); never on an appliance/production deployment.
    """
    return str(os.environ.get("AZAZEL_DEV_HEALTHY_BASELINE", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
NOC_REFRESH_SEC = max(2.0 if _DEMO_FAST else 5.0, float(_timing_default("AZAZEL_NOC_REFRESH_SEC", "20", "3")))
NOC_EVALUATOR = NocEvaluator()
NOC_CACHE_LOCK = threading.Lock()
NOC_COLLECT_LOCK = threading.Lock()
_NOC_CACHE: dict[str, Any] = {
    "key": "",
    "ts": 0.0,
    "payload": {},
}
SNAPSHOT_CACHE_TTL_SEC = float(_timing_default("AZAZEL_SNAPSHOT_CACHE_TTL_SEC", "30", "3"))
SNAPSHOT_REFRESH_INTERVAL_SEC = max(2.0 if _DEMO_FAST else 10.0, float(_timing_default("AZAZEL_SNAPSHOT_REFRESH_SEC", "12", "3")))
SNAPSHOT_CACHE_LOCK = threading.Lock()
SNAPSHOT_WRITE_LOCK = threading.Lock()
_SNAPSHOT_CACHE: dict[str, Any] = {
    "ts": 0.0,
    "payload": None,
}
_NOC_ADAPTER: Optional[NocProbeAdapter] = None
_NOC_ADAPTER_KEY = ""
_NOC_LINK_WATCHER: Optional[LinkStateWatcher] = None
_WIFI_EVIDENCE_SERVICE = EvidencePlaneService(EvidenceBus())
_WIFI_SENSOR_STOP = threading.Event()
POLL_INTERVALS = {
    "wifi_channel_scan": 60.0,
}
_LAST_POLL_TS: dict[str, float] = {key: 0.0 for key in POLL_INTERVALS.keys()}
SOT_CACHE_LOCK = threading.Lock()
# Serializes every SoT read-modify-write in this process (the single writer).
SOT_WRITE_LOCK = threading.Lock()
SOT_AUDIT_LOG = Path(os.environ.get("AZAZEL_SOT_AUDIT_LOG", "/var/log/azazel-edge/sot-events.jsonl"))
_SOT_CACHE: dict[str, Any] = {
    "path": "",
    "mtime": 0.0,
    "payload": {},
}


def _default_sot_payload() -> dict[str, Any]:
    return {
        "devices": [],
        "networks": [],
        "services": [],
        "expected_paths": [],
    }


def _should_poll(name: str, now: float | None = None) -> bool:
    interval = float(POLL_INTERVALS.get(name, 0.0))
    if interval <= 0:
        return False
    current = float(now if now is not None else time.time())
    prev = float(_LAST_POLL_TS.get(name, 0.0))
    if current - prev < interval:
        return False
    _LAST_POLL_TS[name] = current
    return True


def _wifi_sensor_interface() -> tuple[str, str]:
    """``(interface, "")`` the Wi-Fi sensor scans on, or ``("", reason)``.

    ``AZAZEL_WIFI_SCAN_IFACE`` when set, else the uplink wireless interface.
    An interface that serves the internal LAN (the internal AP, a bridge or
    a bridge port) is never scanned on: a scan on the AP's radio disturbs the
    AP's clients. When that cannot be determined, nothing is scanned."""
    configured = str(os.environ.get("AZAZEL_WIFI_SCAN_IFACE", "")).strip()
    if not configured:
        interface, error = select_uplink_wireless_interface()
        return (interface, "") if interface else ("", error)
    try:
        internal = internal_lan_interfaces()
    except InternalLanUnknown as exc:
        return "", f"cannot tell whether {configured} serves the internal LAN ({exc})"
    if configured in internal:
        return "", f"AZAZEL_WIFI_SCAN_IFACE={configured} serves the internal LAN (internal AP or bridge)"
    return configured, ""


def _wifi_sensor_loop() -> None:
    shelter_ssid = str(os.environ.get("AZAZEL_SHELTER_SSID", "")).strip()
    skipped_reason = ""
    while not _WIFI_SENSOR_STOP.wait(1.0):
        try:
            if not _should_poll("wifi_channel_scan"):
                continue
            interface, reason = _wifi_sensor_interface()
            if not interface:
                if reason != skipped_reason:
                    logger.warning(f"wifi sensor: not scanning: {reason}")
                    skipped_reason = reason
                continue
            skipped_reason = ""
            scan_result = scan_wifi_channels(interface)
            _WIFI_EVIDENCE_SERVICE.dispatch_wifi_scan(scan_result if isinstance(scan_result, dict) else {})
            if shelter_ssid:
                nearby = scan_result.get("nearby_aps") if isinstance(scan_result, dict) else []
                if not isinstance(nearby, list) or not nearby:
                    nearby = scan_and_parse(interface, deduplicate=False, keep_hidden=True)
                _WIFI_EVIDENCE_SERVICE.dispatch_rogue_ap(shelter_ssid, nearby if isinstance(nearby, list) else [])
        except Exception as exc:
            logger.debug(f"wifi sensor poll skipped: {exc}")


def _env_list(name: str) -> list[str]:
    raw = str(os.environ.get(name, "")).strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _resolve_monitor_scope(route: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, str]:
    scope_mode = str(os.environ.get("AZAZEL_NOC_MONITOR_SCOPE", "internal")).strip().lower()
    if scope_mode not in {"internal", "external"}:
        scope_mode = "internal"
    internal_if = str(os.environ.get("AZAZEL_INTERNAL_BRIDGE_IF", "br0")).strip() or "br0"
    internal_cidr = str(os.environ.get("AZAZEL_MANAGED_CLIENT_CIDRS", "172.16.0.0/24")).strip() or "172.16.0.0/24"
    internal_target = str(os.environ.get("AZAZEL_INTERNAL_MONITOR_TARGET", "172.16.0.254")).strip() or "172.16.0.254"
    external_if = str(route.get("up_if") or "eth1").strip() or "eth1"
    down_if = str(snapshot.get("down_if") or os.environ.get("AZAZEL_NOC_DOWN_INTERFACE", "usb0")).strip() or "usb0"

    if scope_mode == "internal":
        return {
            "mode": "internal",
            "label": f"internal:{internal_if} ({internal_cidr})",
            "up_if": internal_if,
            "down_if": down_if,
            "gateway_ip": internal_target,
            "cidr": internal_cidr,
        }

    return {
        "mode": "external",
        "label": f"external:{external_if}",
        "up_if": external_if,
        "down_if": down_if,
        "gateway_ip": str(route.get("gateway_ip") or "").strip(),
        "cidr": "",
    }


def _sot_candidates() -> list[Path]:
    candidates: list[Path] = []
    env_path = str(os.environ.get("AZAZEL_SOT_PATH", "")).strip()
    if env_path:
        candidates.append(Path(env_path))
    for cfg_dir in config_dir_candidates():
        candidates.append(cfg_dir / "sot.yaml")
        candidates.append(cfg_dir / "sot.json")
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped or [Path("/etc/azazel-edge/sot.yaml")]


def _sot_target_path() -> Path:
    for path in _sot_candidates():
        if path.exists():
            return path
    return _sot_candidates()[0]


def _load_sot_payload(force: bool = False) -> tuple[dict[str, Any], Path]:
    target = _sot_target_path()
    if target.exists():
        try:
            mtime = target.stat().st_mtime
        except Exception:
            mtime = 0.0
        with SOT_CACHE_LOCK:
            cached_path = str(_SOT_CACHE.get("path") or "")
            cached_mtime = float(_SOT_CACHE.get("mtime") or 0.0)
            cached_payload = _SOT_CACHE.get("payload")
            if (
                not force
                and cached_path == str(target)
                and cached_mtime == mtime
                and isinstance(cached_payload, dict)
                and cached_payload
            ):
                return json.loads(json.dumps(cached_payload, ensure_ascii=False)), target
        try:
            payload = load_sot_file(target).to_dict()
        except (SoTValidationError, OSError, ValueError) as exc:
            logger.warning(f"Failed to load SoT {target}: {exc}")
            payload = _default_sot_payload()
        with SOT_CACHE_LOCK:
            _SOT_CACHE["path"] = str(target)
            _SOT_CACHE["mtime"] = mtime
            _SOT_CACHE["payload"] = json.loads(json.dumps(payload, ensure_ascii=False))
        return payload, target

    payload = _default_sot_payload()
    with SOT_CACHE_LOCK:
        _SOT_CACHE["path"] = str(target)
        _SOT_CACHE["mtime"] = 0.0
        _SOT_CACHE["payload"] = json.loads(json.dumps(payload, ensure_ascii=False))
    return payload, target


def _sot_file_mode_and_group(target: Path) -> tuple[int, Optional[int]]:
    """Mode and group for a rewritten SoT file: those of the file it replaces
    (the installer makes it 0640 root:azazel-web, Edge#471), so a write never
    widens it. A new file is 0640 with the Web UI's group when this process
    is root and that group exists, otherwise 0644 as before."""
    try:
        st = os.stat(target)
        return stat.S_IMODE(st.st_mode) & 0o7777, st.st_gid
    except OSError:
        pass
    if os.geteuid() == 0:
        try:
            return 0o640, grp.getgrnam(WEB_UI_ACCOUNT).gr_gid
        except KeyError:
            pass
    return 0o644, None


def _persist_sot_payload(payload: dict[str, Any], target: Path) -> None:
    """Write the SoT atomically: a new temporary file in the same directory,
    flushed to disk, then renamed over the target (readers see either the
    old or the new file, never a partial one). The daemon is the only writer
    (Edge#471 stage 1); callers hold SOT_WRITE_LOCK."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.suffix.lower() == ".json" or yaml is None:
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    else:
        text = yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        mode, gid = _sot_file_mode_and_group(target)
        if gid is not None:
            try:
                os.chown(tmp_name, -1, gid)
            except OSError:
                pass
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    try:
        dir_fd = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass
    try:
        mtime = target.stat().st_mtime
    except Exception:
        mtime = time.time()
    with SOT_CACHE_LOCK:
        _SOT_CACHE["path"] = str(target)
        _SOT_CACHE["mtime"] = mtime
        _SOT_CACHE["payload"] = json.loads(json.dumps(payload, ensure_ascii=False))


def _normalize_mac(mac: object) -> str:
    text = str(mac or "").strip().lower()
    if not text:
        return ""
    text = text.replace("-", ":")
    return text


def _is_private_ip(ip: object) -> bool:
    text = str(ip or "").strip()
    if not text:
        return False
    try:
        return ipaddress.ip_address(text).is_private
    except ValueError:
        return False


def _guess_allowed_networks(sot: dict[str, Any], ip: str) -> list[str]:
    text = str(ip or "").strip()
    if not text:
        return []
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return []
    allowed: list[str] = []
    for item in sot.get("networks", []) if isinstance(sot.get("networks"), list) else []:
        if not isinstance(item, dict):
            continue
        try:
            cidr = ipaddress.ip_network(str(item.get("cidr") or ""), strict=False)
        except ValueError:
            continue
        if addr in cidr:
            net_id = str(item.get("id") or "").strip()
            if net_id:
                allowed.append(net_id)
    return sorted(dict.fromkeys(allowed))


def _normalize_allowed_networks(value: Any) -> list[str]:
    if isinstance(value, list):
        return sorted(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
    text = str(value or "").strip()
    if not text:
        return []
    return sorted(dict.fromkeys(part.strip() for part in text.split(",") if part.strip()))


def _managed_network_defaults() -> list[dict[str, Any]]:
    raw = str(os.environ.get("AZAZEL_MANAGED_CLIENT_CIDRS", "172.16.0.0/24")).strip()
    cidrs = [part.strip() for part in raw.split(",") if part.strip()]
    defaults: list[dict[str, Any]] = []
    for idx, cidr_text in enumerate(cidrs, start=1):
        try:
            network = ipaddress.ip_network(cidr_text, strict=False)
        except ValueError:
            continue
        gateway = ""
        try:
            gateway = str(next(network.hosts()))
        except StopIteration:
            gateway = str(network.network_address)
        defaults.append(
            {
                "id": "managed-lan" if idx == 1 else f"managed-lan-{idx}",
                "cidr": str(network),
                "zone": "managed",
                "gateway": gateway,
            }
        )
    return defaults


def _ensure_managed_network_entries(sot: dict[str, Any]) -> None:
    networks = sot.get("networks")
    if not isinstance(networks, list):
        networks = []
        sot["networks"] = networks
    existing_cidrs = {str(item.get("cidr") or "").strip() for item in networks if isinstance(item, dict)}
    for item in _managed_network_defaults():
        if str(item.get("cidr") or "").strip() in existing_cidrs:
            continue
        networks.append(item)


def _device_identifier(hostname: str, ip: str, mac: str) -> str:
    base = hostname or ip or mac or f"device-{int(time.time())}"
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", base).strip("-").lower()
    return slug or f"device-{int(time.time())}"


def _invalidate_runtime_caches(refresh_snapshot: bool = True) -> None:
    with NOC_CACHE_LOCK:
        _NOC_CACHE["key"] = ""
        _NOC_CACHE["ts"] = 0.0
        _NOC_CACHE["payload"] = {}
    with SNAPSHOT_CACHE_LOCK:
        _SNAPSHOT_CACHE["ts"] = 0.0
        _SNAPSHOT_CACHE["payload"] = None
    if refresh_snapshot:
        try:
            read_ui_snapshot()
        except Exception as exc:
            logger.debug(f"Snapshot refresh after SoT update failed: {exc}")


def _set_client_trust(params: dict[str, Any]) -> dict[str, Any]:
    trusted = bool(params.get("trusted", False))
    ignored = bool(params.get("ignored", False))
    ip = str(params.get("ip") or "").strip()
    mac = _normalize_mac(params.get("mac"))
    hostname = str(params.get("hostname") or params.get("display_name") or "").strip()
    interface_or_segment = str(params.get("interface_or_segment") or "").strip()
    expected_interface_or_segment = str(params.get("expected_interface_or_segment") or "").strip()
    session_key = str(params.get("session_key") or "").strip()
    note = str(params.get("note") or "").strip()[:240]
    allowed_networks = _normalize_allowed_networks(params.get("allowed_networks"))

    if not mac and not _is_private_ip(ip):
        return {
            "ok": False,
            "error": "trust_requires_mac_or_private_ip",
            "ts": time.time(),
        }

    with SOT_WRITE_LOCK:
        return _set_client_trust_locked(params, trusted=trusted, ignored=ignored, ip=ip, mac=mac, hostname=hostname,
                                        interface_or_segment=interface_or_segment,
                                        expected_interface_or_segment=expected_interface_or_segment,
                                        session_key=session_key, note=note, allowed_networks=allowed_networks)


def _set_client_trust_locked(params: dict[str, Any], *, trusted: bool, ignored: bool, ip: str, mac: str,
                             hostname: str, interface_or_segment: str, expected_interface_or_segment: str,
                             session_key: str, note: str, allowed_networks: list[str]) -> dict[str, Any]:
    sot, path = _load_sot_payload(force=True)
    _ensure_managed_network_entries(sot)
    devices = sot.get("devices")
    if not isinstance(devices, list):
        devices = []
        sot["devices"] = devices

    target: dict[str, Any] | None = None
    for item in devices:
        if not isinstance(item, dict):
            continue
        item_mac = _normalize_mac(item.get("mac"))
        item_ip = str(item.get("ip") or "").strip()
        if mac and item_mac and item_mac == mac:
            target = item
            break
        if ip and item_ip and item_ip == ip:
            target = item
            break

    if target is None:
        target = {
            "id": _device_identifier(hostname, ip, mac or session_key),
            "hostname": hostname or ip or mac or session_key or "trusted-device",
            "ip": ip,
            "mac": mac,
            "criticality": "standard",
            "allowed_networks": allowed_networks or _guess_allowed_networks(sot, ip),
            "authorized": trusted and not ignored,
            "monitoring_scope": "ignore" if ignored else "managed",
        }
        if expected_interface_or_segment:
            target["expected_interface_or_segment"] = expected_interface_or_segment
        elif interface_or_segment:
            target["expected_interface_or_segment"] = interface_or_segment
        if note:
            target["notes"] = note
        elif interface_or_segment:
            target["notes"] = f"source_segment:{interface_or_segment}"
        devices.append(target)
    else:
        if hostname:
            target["hostname"] = hostname
        if ip:
            target["ip"] = ip
        if mac:
            target["mac"] = mac
        target["authorized"] = trusted and not ignored
        target["monitoring_scope"] = "ignore" if ignored else "managed"
        target.setdefault("criticality", "standard")
        if allowed_networks:
            target["allowed_networks"] = allowed_networks
        else:
            allowed = target.get("allowed_networks")
            if not isinstance(allowed, list):
                target["allowed_networks"] = []
            if not target.get("allowed_networks") and ip:
                target["allowed_networks"] = _guess_allowed_networks(sot, ip)
        if expected_interface_or_segment:
            target["expected_interface_or_segment"] = expected_interface_or_segment
        elif interface_or_segment and not str(target.get("expected_interface_or_segment") or "").strip():
            target["expected_interface_or_segment"] = interface_or_segment
        if note:
            target["notes"] = note

    _persist_sot_payload(sot, path)
    _invalidate_runtime_caches(refresh_snapshot=True)
    return {
        "ok": True,
        "trusted": trusted,
        "session_key": session_key,
        "device": {
            "id": str(target.get("id") or ""),
            "hostname": str(target.get("hostname") or ""),
            "ip": str(target.get("ip") or ""),
            "mac": _normalize_mac(target.get("mac")),
            "authorized": bool(target.get("authorized", False)),
            "monitoring_scope": str(target.get("monitoring_scope") or "managed"),
            "notes": str(target.get("notes") or ""),
            "allowed_networks": [str(item) for item in (target.get("allowed_networks") or []) if str(item)],
            "expected_interface_or_segment": str(target.get("expected_interface_or_segment") or ""),
        },
        "sot_path": str(path),
        "ts": time.time(),
    }


class SoTEditError(ValueError):
    """A SoT edit request is refused before anything is written."""


SOT_EDIT_PARAMS = frozenset({"devices", "requested_by"})


def _read_sot_for_edit() -> tuple[dict[str, Any], Path]:
    """The current SoT as stored (not the cached, validated view). A file that
    exists but cannot be read or parsed is an error: an edit must never
    replace it with a default document."""
    target = _sot_target_path()
    if not target.exists():
        return _default_sot_payload(), target
    try:
        text = target.read_text(encoding="utf-8")
        if target.suffix.lower() in (".yaml", ".yml"):
            if yaml is None:
                raise SoTEditError("sot_yaml_reader_unavailable")
            payload = yaml.safe_load(text) or {}
        else:
            payload = json.loads(text) if text.strip() else {}
    except SoTEditError:
        raise
    except Exception as exc:
        raise SoTEditError(f"sot_unreadable:{type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise SoTEditError("sot_unreadable:not_a_mapping")
    return payload, target


def _sot_device_diff(before_devices: list[Any], after_devices: list[Any]) -> dict[str, int]:
    before_ids = {str(item.get("id") or "").strip() for item in before_devices if isinstance(item, dict)}
    after_ids = {str(item.get("id") or "").strip() for item in after_devices if isinstance(item, dict)}
    before_ids.discard("")
    after_ids.discard("")
    updated = 0
    before_map = {str(item.get("id")): item for item in before_devices
                  if isinstance(item, dict) and str(item.get("id") or "").strip()}
    for row in after_devices:
        if not isinstance(row, dict):
            continue
        row_id = str(row.get("id") or "").strip()
        if row_id and row_id in before_map and before_map[row_id] != row:
            updated += 1
    return {"added": len(after_ids - before_ids), "removed": len(before_ids - after_ids), "updated": updated}


def _sot_requested_by(params: dict[str, Any]) -> dict[str, str]:
    """Who the Web UI says asked (informational, for the audit line only)."""
    raw = params.get("requested_by")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key, limit in (("actor", 96), ("remote_addr", 64), ("user_agent", 180)):
        value = raw.get(key)
        if value is not None:
            out[key] = str(value)[:limit]
    return out


def _sot_devices_edit(kind: str, params: Any, peer_uid: Optional[int] = None) -> dict[str, Any]:
    """``sot_devices_replace`` / ``sot_devices_patch`` (Edge#471 stage 1).

    Moved from the Web UI so the daemon is the single writer of the SoT. The
    request carries only the device list; the target file is the daemon's
    own SoT path. The candidate document is validated with ``SoTConfig``
    before anything is written, and written atomically."""
    if not isinstance(params, dict):
        return {"ok": False, "error": "params_must_be_object", "ts": time.time()}
    unknown = sorted(set(params) - SOT_EDIT_PARAMS)
    if unknown:
        return {"ok": False, "error": "unexpected_params:" + ",".join(unknown), "ts": time.time()}
    updates = params.get("devices")
    if not isinstance(updates, list):
        return {"ok": False, "error": "devices_must_be_list", "ts": time.time()}
    with SOT_WRITE_LOCK:
        try:
            current, target = _read_sot_for_edit()
        except SoTEditError as exc:
            return {"ok": False, "error": str(exc), "ts": time.time()}
        current_devices = [item for item in list(current.get("devices") or []) if isinstance(item, dict)]
        candidate = dict(current)
        if kind == "sot_devices_replace":
            candidate["devices"] = updates
        else:
            merged: dict[str, dict[str, Any]] = {}
            order: list[str] = []
            for row in current_devices:
                row_id = str(row.get("id") or "").strip()
                if not row_id:
                    continue
                merged[row_id] = dict(row)
                order.append(row_id)
            for row in updates:
                if not isinstance(row, dict):
                    return {"ok": False, "error": "device_item_must_be_object", "ts": time.time()}
                row_id = str(row.get("id") or "").strip()
                if not row_id:
                    return {"ok": False, "error": "device_id_required", "ts": time.time()}
                if row_id not in merged:
                    merged[row_id] = {}
                    order.append(row_id)
                merged[row_id].update(row)
            candidate["devices"] = [merged[row_id] for row_id in order if row_id in merged]
        try:
            validated = SoTConfig.from_dict(candidate).to_dict()
        except (SoTValidationError, ValueError, TypeError, AttributeError, KeyError) as exc:
            return {"ok": False, "error": f"invalid_sot:{exc}", "ts": time.time()}
        try:
            _persist_sot_payload(validated, target)
        except OSError as exc:
            logger.error(f"SoT write failed ({kind}): {exc}")
            return {"ok": False, "error": f"sot_write_failed:{exc.strerror or type(exc).__name__}", "ts": time.time()}
        diff = _sot_device_diff(current_devices, list(validated.get("devices") or []))
        record: dict[str, Any] = {
            "kind": "sot_devices_replaced" if kind == "sot_devices_replace" else "sot_devices_patched",
            "ts": time.time(),
            "source": "control_daemon",
            "peer_uid": peer_uid,
            **_sot_requested_by(params),
            "path": str(target),
            "device_count": len(validated.get("devices") or []),
            "diff": diff,
        }
        if kind == "sot_devices_patch":
            record["patched_count"] = len(updates)
        try:
            SOT_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
            with SOT_AUDIT_LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            audit_ok = True
        except OSError as exc:
            logger.warning(f"SoT audit append failed: {exc}")
            audit_ok = False
    _invalidate_runtime_caches(refresh_snapshot=False)
    return {"ok": True, "path": str(target), "diff": diff, "audit_logged": audit_ok, "ts": time.time()}


# Same source and default the Web UI used for its fallback (AZAZEL_UP_IF).
UPLINK_IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
IP_COMMAND_CANDIDATES = ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip")
SYS_CLASS_NET = Path("/sys/class/net")


def _uplink_disconnect(request: dict[str, Any]) -> dict[str, Any]:
    """``uplink_disconnect`` (Edge#471 stage 1): the Web UI's local disconnect
    fallback (``ip link set <uplink> down``), relocated into the daemon.

    It takes no arguments: any parameter or extra request field is refused.
    The interface is the daemon's own configured uplink (``AZAZEL_UP_IF``,
    default ``wlan0``, the Web UI's old source), checked to be a plausible
    interface name that exists before ``ip`` runs. Failure is returned."""
    extra = sorted(set(request) - {"action", "ts", "params"})
    params = request.get("params")
    if extra or params not in (None, {}):
        return {"ok": False, "action": "uplink_disconnect", "error": "uplink_disconnect_takes_no_parameters",
                "ts": time.time()}
    limited = rate_limit_error("uplink_disconnect", "Rate limit exceeded (1 req/3sec)")
    if limited:
        return limited
    iface = str(os.environ.get("AZAZEL_UP_IF", "wlan0")).strip()
    if not UPLINK_IFACE_RE.match(iface) or iface in (".", ".."):
        return {"ok": False, "action": "uplink_disconnect", "error": "uplink_interface_config_invalid",
                "ts": time.time()}
    if not (SYS_CLASS_NET / iface).exists():
        return {"ok": False, "action": "uplink_disconnect", "error": f"uplink_interface_not_found:{iface}",
                "ts": time.time()}
    # Never the internal LAN (the default wlan0 is the internal AP on a Pi 5):
    # setting it down would cut every client, not the uplink.
    try:
        internal = internal_lan_interfaces(SYS_CLASS_NET)
    except InternalLanUnknown as exc:
        # Fail closed: unknown is not "not internal".
        return {"ok": False, "action": "uplink_disconnect", "interface": iface,
                "error": f"uplink_interface_check_failed:{exc}", "ts": time.time()}
    if iface in internal:
        return {"ok": False, "action": "uplink_disconnect", "interface": iface,
                "error": f"uplink_interface_serves_internal_lan:{iface}", "ts": time.time()}
    ip_bin = next((c for c in IP_COMMAND_CANDIDATES if os.path.isfile(c) and os.access(c, os.X_OK)), "")
    if not ip_bin:
        return {"ok": False, "action": "uplink_disconnect", "error": "ip_command_not_found", "ts": time.time()}
    try:
        proc = subprocess.run([ip_bin, "link", "set", "dev", iface, "down"], capture_output=True, text=True,
                              timeout=5)
    except subprocess.TimeoutExpired:
        return {"ok": False, "action": "uplink_disconnect", "error": "uplink_disconnect_timeout", "ts": time.time()}
    except OSError as exc:
        return {"ok": False, "action": "uplink_disconnect", "error": f"uplink_disconnect_failed:{exc}",
                "ts": time.time()}
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:300] or f"exit {proc.returncode}"
        logger.error(f"uplink_disconnect failed on {iface}: {detail}")
        return {"ok": False, "action": "uplink_disconnect", "interface": iface,
                "error": f"uplink_disconnect_failed:{detail}", "ts": time.time()}
    logger.info(f"uplink_disconnect: {iface} set down")
    return {"ok": True, "action": "uplink_disconnect", "interface": iface,
            "message": f"Uplink disconnected ({iface} down)", "ts": time.time()}


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
    return runtime_snapshot_path_candidates(home=Path.home())


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


NOC_COLLECTION_VIEW_MAX_COLLECTORS = 16
NOC_COLLECTION_VIEW_NAME_MAX = 48


def _noc_collection_view(timing: Any, trigger: str = "periodic") -> dict[str, Any]:
    """Bounded, read-only view of how long one NOC collection took.

    Diagnostic only: per-collector start offset and duration on
    CLOCK_MONOTONIC, copied from the collector's own stamps. Nothing reads it
    for a decision; it lets an operator (and the SO-02 harness) see which
    collector a slow collection spent its time in.
    """

    timing = timing if isinstance(timing, dict) else {}

    def _num(value: Any) -> float | None:
        return round(float(value), 1) if isinstance(value, (int, float)) and not isinstance(value, bool) else None

    started = timing.get("started_monotonic_ns")
    merged = timing.get("link_event_started_monotonic_ns")
    collectors: list[dict[str, Any]] = []
    for row in timing.get("collectors") or []:
        if len(collectors) >= NOC_COLLECTION_VIEW_MAX_COLLECTORS:
            break
        if not isinstance(row, dict):
            continue
        collectors.append({
            "collector": str(row.get("collector") or "")[:NOC_COLLECTION_VIEW_NAME_MAX],
            "started_offset_ms": _num(row.get("started_offset_ms")),
            "duration_ms": _num(row.get("duration_ms")),
            "outcome": str(row.get("outcome") or "")[:16],
        })
    return {
        "trigger": str(trigger or "periodic")[:32],
        "started_monotonic_ns": int(started) if isinstance(started, int) and not isinstance(started, bool) else None,
        # Set when a link-event refresh that started during this collection
        # supplied the rows of its interfaces.
        "link_event_started_monotonic_ns": int(merged) if isinstance(merged, int) and not isinstance(merged, bool) else None,
        "duration_ms": _num(timing.get("duration_ms")),
        "collectors": collectors,
    }


def _build_noc_runtime_projection(
    *,
    evaluation: dict[str, Any],
    event_payloads: list[dict[str, Any]],
    inventory_summary: dict[str, Any],
    inventory_sessions: list[dict[str, Any]] | None = None,
    preferred_uplink: str = "",
    collection: dict[str, Any] | None = None,
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
                "interface_family": str(row.get("interface_family") or "unknown"),
                "last_seen": str(row.get("last_seen") or ""),
                "sources_present": [str(item) for item in (row.get("sources_present") or []) if str(item)],
                "session_origin": str(row.get("session_origin") or "unknown"),
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
            "collection": collection if isinstance(collection, dict) else _noc_collection_view({}),
            "link_watch": _link_watch_view(),
        },
    }


def _project_noc_events(events: list[Any], preferred_uplink: str, collection: dict[str, Any]) -> dict[str, Any]:
    payloads = _event_payloads(events)
    sot_payload, _sot_path = _load_sot_payload()
    inventory = build_client_inventory(events, sot=sot_payload)
    inventory_summary = inventory.get("summary") if isinstance(inventory.get("summary"), dict) else {}
    inventory_sessions = inventory.get("sessions") if isinstance(inventory.get("sessions"), list) else []
    evaluation = NOC_EVALUATOR.evaluate(events, sot=sot_payload)
    return _build_noc_runtime_projection(
        evaluation=evaluation,
        event_payloads=payloads,
        inventory_summary=inventory_summary,
        inventory_sessions=inventory_sessions,
        preferred_uplink=preferred_uplink,
        collection=collection,
    )


def _collection_started_ns(projection: Any) -> int:
    runtime = projection.get("noc_runtime") if isinstance(projection, dict) else None
    collection = runtime.get("collection") if isinstance(runtime, dict) else None
    if not isinstance(collection, dict):
        return -1
    # A periodic result that merged a later link-event refresh is as new as
    # that refresh for the interface rows and newer for everything else.
    stamps = [collection.get("started_monotonic_ns"), collection.get("link_event_started_monotonic_ns")]
    stamps = [int(v) for v in stamps if isinstance(v, int) and not isinstance(v, bool)]
    return max(stamps) if stamps else -1


def _publish_noc_projection(key: str, projection: dict[str, Any], *, periodic: bool = True) -> dict[str, Any]:
    """Cache ``projection`` unless a collection that *started* later has
    already been published for the same scope (a link-event re-evaluation
    overtaking a slow periodic collection); return what is now current.

    A link-event publish (``periodic=False``) keeps the cache's refresh
    stamp, so the periodic full collection stays on its own schedule."""

    started = _collection_started_ns(projection)
    with NOC_CACHE_LOCK:
        cached = _NOC_CACHE.get("payload")
        if (
            str(_NOC_CACHE.get("key") or "") == key
            and isinstance(cached, dict)
            and cached
            and _collection_started_ns(cached) > started
        ):
            if periodic:
                # The full collection did run: keep the periodic schedule
                # instead of re-collecting at once.
                _NOC_CACHE["ts"] = time.time()
            return dict(cached)
        if periodic or str(_NOC_CACHE.get("key") or "") != key:
            _NOC_CACHE["ts"] = time.time()
        _NOC_CACHE["key"] = key
        _NOC_CACHE["payload"] = projection
        return dict(projection)


def _compute_live_noc_projection(up_if: str, down_if: str, gateway_ip: str) -> dict[str, Any]:
    global _NOC_ADAPTER, _NOC_ADAPTER_KEY
    key = f"{up_if}|{down_if}|{gateway_ip}"
    refresh_sec = max(5.0, float(NOC_REFRESH_SEC))

    def _fresh_cache() -> dict[str, Any] | None:
        cache_payload = _NOC_CACHE.get("payload")
        if (
            str(_NOC_CACHE.get("key") or "") == key
            and isinstance(cache_payload, dict)
            and time.time() - float(_NOC_CACHE.get("ts") or 0.0) < refresh_sec
        ):
            return dict(cache_payload)
        return None

    with NOC_CACHE_LOCK:
        cached = _fresh_cache()
    if cached is not None:
        return cached
    # One full collection at a time. The cache lock is not held while
    # collecting, so a link-event re-evaluation can publish meanwhile.
    with NOC_COLLECT_LOCK:
        with NOC_CACHE_LOCK:
            cached = _fresh_cache()
            if cached is not None:
                return cached
            if _NOC_ADAPTER is None or _NOC_ADAPTER_KEY != key:
                _NOC_ADAPTER = NocProbeAdapter(
                    up_interface=str(up_if or "eth1"),
                    down_interface=str(down_if or "usb0"),
                    gateway_ip=str(gateway_ip or ""),
                    extra_interfaces=_env_list("AZAZEL_NOC_EXTRA_INTERFACES"),
                )
                _NOC_ADAPTER_KEY = key
            adapter = _NOC_ADAPTER

        noc_snapshot = adapter.collect_snapshot()
        events = adapter.collect(noc_snapshot)
        projection = _project_noc_events(
            events, up_if, _noc_collection_view(noc_snapshot.get("collection_timing"), "periodic")
        )
        return _publish_noc_projection(key, projection)


def _noc_monitored_interfaces() -> list[str]:
    with NOC_CACHE_LOCK:
        adapter = _NOC_ADAPTER
    monitor = getattr(adapter, "monitor", None)
    return list(monitor.monitored_interfaces()) if monitor is not None else []


def _noc_link_event_reevaluate(interfaces: list[str]) -> None:
    """Re-evaluate the NOC view of ``interfaces`` after a link-state change.

    Observation only: the same probes and the same evaluator as the periodic
    loop, run now for the changed interfaces, so the operator surface shows
    the change sooner. Nothing is decided or enforced here."""

    with NOC_CACHE_LOCK:
        adapter, key = _NOC_ADAPTER, _NOC_ADAPTER_KEY
    monitor = getattr(adapter, "monitor", None)
    if adapter is None or monitor is None:
        return
    snapshot = monitor.refresh_interfaces(interfaces)
    if not isinstance(snapshot, dict):
        return
    events = adapter.collect(snapshot)
    projection = _project_noc_events(
        events, str(adapter.up_interface), _noc_collection_view(snapshot.get("collection_timing"), "link_event")
    )
    _publish_noc_projection(key, projection, periodic=False)
    _overlay_latest_noc_into_snapshot_cache()


def _overlay_latest_noc(payload: Any) -> bool:
    """Put the current NOC projection into a snapshot payload whose NOC view
    comes from an earlier-started collection. True if it changed."""

    snapshot = payload.get("snapshot") if isinstance(payload, dict) else None
    if not isinstance(snapshot, dict) or "noc_runtime" not in snapshot:
        return False
    with NOC_CACHE_LOCK:
        latest = _NOC_CACHE.get("payload")
        latest = json.loads(json.dumps(latest, ensure_ascii=False)) if isinstance(latest, dict) and latest else None
    if latest is None or _collection_started_ns(latest) <= _collection_started_ns(snapshot):
        return False
    snapshot.update(latest)
    return True


def _overlay_latest_noc_into_snapshot_cache() -> None:
    with SNAPSHOT_WRITE_LOCK:
        current = _SNAPSHOT_CACHE.get("payload")
        if not isinstance(current, dict):
            return
        updated = json.loads(json.dumps(current, ensure_ascii=False))
        if _overlay_latest_noc(updated):
            _SNAPSHOT_CACHE["payload"] = updated


def _link_watch_view() -> dict[str, Any]:
    watcher = _NOC_LINK_WATCHER
    if watcher is None:
        return {"mode": "stopped", "reevaluations": 0}
    return {"mode": str(watcher.mode)[:16], "reevaluations": int(watcher.gate.fired)}


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
    monitor_scope = _resolve_monitor_scope(route, enriched)
    enriched["monitor_scope"] = monitor_scope
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
    if _dev_healthy_baseline():
        # Dev host cannot run the live NOC probes, so the projection would report
        # a degraded path/service baseline. Skip it under the dev-only override so
        # the idle dashboard reads healthy; real evidence still flows through the
        # SOC/threat path and drives the visible change on injection.
        logger.debug("dev healthy baseline: skipping live NOC projection")
    else:
        try:
            noc_projection = _compute_live_noc_projection(
                up_if=str(monitor_scope.get("up_if") or up_if),
                down_if=str(monitor_scope.get("down_if") or enriched.get("down_if") or "usb0"),
                gateway_ip=str(monitor_scope.get("gateway_ip") or gateway_ip),
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


def _snapshot_cache_get(max_age_sec: float = SNAPSHOT_CACHE_TTL_SEC) -> dict[str, Any] | None:
    payload = _SNAPSHOT_CACHE.get("payload")
    ts = float(_SNAPSHOT_CACHE.get("ts") or 0.0)
    if not isinstance(payload, dict):
        return None
    if ts <= 0 or (time.time() - ts) > max_age_sec:
        return None
    return json.loads(json.dumps(payload, ensure_ascii=False))


def _snapshot_cache_set(payload: dict[str, Any]) -> None:
    with SNAPSHOT_WRITE_LOCK:
        copied = json.loads(json.dumps(payload, ensure_ascii=False))
        # A snapshot built around a slow periodic collection must not hide a
        # link-event re-evaluation published while it was being built.
        _overlay_latest_noc(copied)
        _SNAPSHOT_CACHE["payload"] = copied
        _SNAPSHOT_CACHE["ts"] = time.time()


def _snapshot_payload_from_file(path: Path, data: dict[str, Any], mode_payload: dict[str, Any]) -> dict[str, Any]:
    if mode_payload.get("ok"):
        data["mode"] = mode_payload.get("mode", {})
    payload = {
        "ok": True,
        "snapshot": data,
        "path": str(path),
        "ts": time.time(),
    }
    return payload


def _valid_str(limit: int):
    return lambda v: isinstance(v, str) and len(v) <= limit


def _valid_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10**9


def _valid_epoch(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v < 10**11


def _valid_str_list(v: Any) -> bool:
    return isinstance(v, list) and len(v) <= 32 and all(isinstance(x, str) and len(x) <= 512 for x in v)


def _valid_object(v: Any) -> bool:
    if not isinstance(v, dict):
        return False
    try:
        return len(json.dumps(v, ensure_ascii=False)) <= 64 * 1024
    except (TypeError, ValueError):
        return False


# The type each merged field must have; anything else is dropped (and counted).
AGENT_SNAPSHOT_VALIDATORS = {
    "advisory_epoch": _valid_epoch,
    "user_state": _valid_str(64),
    "recommendation": _valid_str(1024),
    "reasons": _valid_str_list,
    "evidence": _valid_str_list,
    "suricata_critical": _valid_count,
    "suricata_warning": _valid_count,
    "suricata_info": _valid_count,
    "deferred_recent": _valid_count,
    "deferred_lifetime_at_snapshot": _valid_count,
    "llm": _valid_object,
    "ops_coach": _valid_object,
    "decision_pipeline": _valid_object,
    "second_pass": _valid_object,
    "llm_metrics": _valid_object,
    "internal": _valid_object,
    "attack": _valid_object,
}
_AGENT_SNAPSHOT_DROPPED = {"total": 0, "last": ""}


def _note_dropped_agent_fields(names: list[str], why: str) -> None:
    _AGENT_SNAPSHOT_DROPPED["total"] += len(names) or 1
    message = f"{why}: {','.join(names)}" if names else why
    if _AGENT_SNAPSHOT_DROPPED["last"] != message:
        logger.warning(f"Agent snapshot {AGENT_SNAPSHOT_PATH}: ignored {message} "
                       f"(ignored so far: {_AGENT_SNAPSHOT_DROPPED['total']})")
        _AGENT_SNAPSHOT_DROPPED["last"] = message


def _read_agent_snapshot() -> dict[str, Any]:
    """The agent's ai_snapshot.json, or {}: opened without following a
    symlink and without blocking (a FIFO or device at the path cannot stall
    the snapshot thread), accepted only as a regular file of at most
    AGENT_SNAPSHOT_MAX_BYTES."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(AGENT_SNAPSHOT_PATH), flags)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        _note_dropped_agent_fields([], f"file not readable ({exc.strerror or type(exc).__name__})")
        return {}
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            _note_dropped_agent_fields([], "not a regular file")
            return {}
        if st.st_size > AGENT_SNAPSHOT_MAX_BYTES:
            _note_dropped_agent_fields([], f"file larger than {AGENT_SNAPSHOT_MAX_BYTES} bytes")
            return {}
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > AGENT_SNAPSHOT_MAX_BYTES:
                _note_dropped_agent_fields([], f"file larger than {AGENT_SNAPSHOT_MAX_BYTES} bytes")
                return {}
            chunks.append(chunk)
    except OSError as exc:
        _note_dropped_agent_fields([], f"file not readable ({exc.strerror or type(exc).__name__})")
        return {}
    finally:
        os.close(fd)
    return _parse_json_dict_lenient(b"".join(chunks).decode("utf-8", errors="replace"))


def _overlay_agent_snapshot(data: dict[str, Any]) -> dict[str, Any]:
    """Merge the AI agent's fields (AGENT_SNAPSHOT_KEYS, and monitoring.suricata)
    from its own ai_snapshot.json into the shared snapshot. Only those keys
    are taken, each only with the type it must have (AGENT_SNAPSHOT_VALIDATORS);
    a field of another type is dropped and counted. A missing, non-regular,
    oversized or unreadable file leaves the snapshot as it is."""
    agent = _read_agent_snapshot()
    if not agent:
        return data
    merged = dict(data)
    dropped: list[str] = []
    for key in AGENT_SNAPSHOT_KEYS:
        if key not in agent:
            continue
        if AGENT_SNAPSHOT_VALIDATORS[key](agent[key]):
            merged[key] = agent[key]
        else:
            dropped.append(key)
    agent_monitoring = agent.get("monitoring")
    if isinstance(agent_monitoring, dict) and "suricata" in agent_monitoring:
        if _valid_str(32)(agent_monitoring["suricata"]):
            monitoring = merged.get("monitoring")
            monitoring = dict(monitoring) if isinstance(monitoring, dict) else {}
            monitoring["suricata"] = agent_monitoring["suricata"]
            merged["monitoring"] = monitoring
        else:
            dropped.append("monitoring.suricata")
    if dropped:
        _note_dropped_agent_fields(dropped, "fields of the wrong type")
    return merged


def _build_fresh_snapshot_payload(mode_payload: dict[str, Any]) -> dict[str, Any]:
    for path in _snapshot_candidates():
        try:
            if not path.exists():
                continue
            warn_if_legacy_path(path, logger=logger)
            data = _parse_json_dict_lenient(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data = _enrich_snapshot(_overlay_agent_snapshot(data))
                _persist_snapshot(path, data)
                payload = _snapshot_payload_from_file(path, data, mode_payload)
                _snapshot_cache_set(payload)
                return payload
        except Exception as exc:
            logger.debug(f"Failed to read snapshot {path}: {exc}")

    seeded, seeded_path = _seed_snapshot_if_missing()
    if isinstance(seeded, dict) and seeded_path is not None:
        data = _enrich_snapshot(_overlay_agent_snapshot(seeded))
        _persist_snapshot(seeded_path, data)
        payload = _snapshot_payload_from_file(seeded_path, data, mode_payload)
        _snapshot_cache_set(payload)
        return payload

    return {
        "ok": False,
        "error": "snapshot_not_found",
        "paths": [str(p) for p in _snapshot_candidates()],
        "ts": time.time(),
    }


def read_ui_snapshot() -> dict[str, Any]:
    """Read latest UI snapshot from schema-aware paths."""
    cached = _snapshot_cache_get()
    if cached is not None:
        return cached

    mode_payload: dict[str, Any] = {}
    try:
        mode_payload = MODE_MANAGER.status()
    except Exception as exc:
        logger.debug(f"Failed to read mode status: {exc}")
    acquired_cache_lock = SNAPSHOT_CACHE_LOCK.acquire(blocking=False)
    if not acquired_cache_lock:
        cached = _snapshot_cache_get(max_age_sec=SNAPSHOT_CACHE_TTL_SEC)
        if cached is not None:
            return cached
        for path in _snapshot_candidates():
            try:
                if not path.exists():
                    continue
                data = _parse_json_dict_lenient(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    payload = _snapshot_payload_from_file(path, data, mode_payload)
                    # The persisted snapshot predates any link-event
                    # re-evaluation published while the refresh loop builds.
                    _overlay_latest_noc(payload)
                    return payload
            except Exception:
                continue

    try:
        return _build_fresh_snapshot_payload(mode_payload)
    finally:
        if acquired_cache_lock:
            SNAPSHOT_CACHE_LOCK.release()


def _watch_client_gone(conn: socket.socket) -> bool:
    """True when a watch client has closed its end (or the socket failed).
    Watch clients send nothing after their request, so a readable socket
    means end of stream; stray bytes are discarded."""
    try:
        readable, _, errored = select.select([conn], [], [conn], 0)
    except (OSError, ValueError):
        return True
    if errored:
        return True
    if not readable:
        return False
    try:
        data = conn.recv(4096, socket.MSG_DONTWAIT)
    except (BlockingIOError, InterruptedError):
        return False
    except OSError:
        return True
    return data == b""


def stream_ui_snapshots(conn: socket.socket, interval_sec: float = 1.0) -> None:
    """Stream newline-delimited snapshots whenever content changes. Returns
    when the client goes away, also while nothing changes (so an idle, dead
    watcher frees its connection slot within one interval)."""
    interval = max(0.2, min(float(interval_sec), 5.0))
    last_fp = ""
    while True:
        if _watch_client_gone(conn):
            logger.info("watch_snapshot client went away")
            return
        payload = read_ui_snapshot()
        fp = json.dumps(payload.get("snapshot", {}), sort_keys=True, ensure_ascii=False) if payload.get("ok") else ""
        if fp != last_fp:
            conn.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
            last_fp = fp
        time.sleep(interval)

def ensure_socket_dir():
    """Create runtime socket directory with least-privilege permissions."""
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if RUNTIME_SOCKET_GROUP:
        try:
            gid = grp.getgrnam(RUNTIME_SOCKET_GROUP).gr_gid
            os.chown(str(SOCKET_PATH.parent), -1, gid)
        except KeyError:
            logger.warning(f"Runtime socket group not found: {RUNTIME_SOCKET_GROUP}")
        except PermissionError:
            logger.warning("Insufficient permissions to set runtime socket directory group")
        except Exception as exc:
            logger.warning(f"Failed to set runtime socket directory group: {exc}")
    # Remove old socket if exists
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()
    os.chmod(str(SOCKET_PATH.parent), RUNTIME_DIR_MODE)


def create_listener_socket() -> socket.socket:
    """Create a fresh Unix listener socket at the control path."""
    ensure_socket_dir()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(SOCKET_PATH))
    if RUNTIME_SOCKET_GROUP:
        try:
            gid = grp.getgrnam(RUNTIME_SOCKET_GROUP).gr_gid
            os.chown(str(SOCKET_PATH), -1, gid)
        except Exception:
            pass
    os.chmod(str(SOCKET_PATH), SOCKET_MODE)
    sock.listen(16)
    sock.settimeout(1.0)
    logger.info(f"Listening on {SOCKET_PATH}")
    return sock


def warm_snapshot_cache_once() -> None:
    """Prime snapshot cache in the background after daemon start."""
    try:
        read_ui_snapshot()
    except Exception as exc:
        logger.debug(f"Snapshot warm-up failed: {exc}")


def snapshot_refresh_loop(interval_sec: float = SNAPSHOT_REFRESH_INTERVAL_SEC) -> None:
    """Keep the UI snapshot fresh so socket readers can return immediately."""
    interval = max(5.0, float(interval_sec))
    while True:
        started = time.time()
        acquired_cache_lock = SNAPSHOT_CACHE_LOCK.acquire(timeout=1.0)
        if acquired_cache_lock:
            try:
                mode_payload: dict[str, Any] = {}
                try:
                    mode_payload = MODE_MANAGER.status()
                except Exception as exc:
                    logger.debug(f"Failed to read mode status during refresh: {exc}")
                _build_fresh_snapshot_payload(mode_payload)
            except Exception as exc:
                logger.debug(f"Snapshot refresh failed: {exc}")
            finally:
                SNAPSHOT_CACHE_LOCK.release()
        elapsed = time.time() - started
        time.sleep(max(1.0, interval - elapsed))

def suppress_auto_wifi(enabled: bool = True):
    """Disable Wi-Fi auto-connect and disconnect existing session on startup."""
    if not enabled:
        logger.info("suppress_auto_wifi disabled by config; keeping existing Wi-Fi session")
        return
    try:
        iface, reason = select_uplink_wireless_interface()
        if not iface:
            logger.info(f"suppress_auto_wifi: no uplink wireless interface to disconnect ({reason})")
            return

        # NetworkManager: disable autoconnect for all Wi-Fi client connections
        # and disconnect. The internal AP's profile (AP mode) keeps its
        # autoconnect: without it the AP would not return after a reboot.
        if check_networkmanager(iface):
            try:
                # Raises when nmcli fails: then no profile is changed (the
                # AP's profile could not be told apart).
                ap_profiles = nm_ap_profiles()
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "NAME,TYPE", "con", "show"],
                    env=_nmcli_env(),
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.splitlines():
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[1] == "802-11-wireless" and parts[0] not in ap_profiles:
                        subprocess.run(
                            ["nmcli", "con", "mod", parts[0], "connection.autoconnect", "no"],
                            env=_nmcli_env(),
                            capture_output=True,
                            timeout=5
                        )
                subprocess.run(
                    ["nmcli", "dev", "disconnect", iface],
                    env=_nmcli_env(),
                    capture_output=True,
                    timeout=5
                )
                logger.info("suppress_auto_wifi enabled: disconnected Wi-Fi and disabled autoconnect profiles")
            except Exception as e:
                logger.warning(f"Failed to disable NetworkManager auto-connect: {e}")
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

def execute_action(action_name, params=None, *, request: Optional[dict[str, Any]] = None,
                   peer_uid: Optional[int] = None):
    """Execute action script and return result"""
    if action_name == "uplink_disconnect":
        return _uplink_disconnect(request if isinstance(request, dict)
                                  else {"action": action_name, **({"params": params} if params else {})})
    if action_name in ("sot_devices_replace", "sot_devices_patch"):
        return _sot_devices_edit(action_name, params if params is not None else {}, peer_uid=peer_uid)
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
    if action_name == "sot_trust_client":
        return _set_client_trust(params)
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

    if action_name in NOT_IMPLEMENTED_ACTIONS:
        logger.warning(f"control.sock: {action_name} is not implemented by the control daemon; answered not_implemented")
        return {
            'ok': False,
            'action': action_name,
            'error': 'not_implemented',
            'not_implemented': True,
            'message': f'{action_name} is not implemented by the control daemon; nothing was done',
            'ts': time.time(),
        }

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

def _web_ui_uid() -> Optional[int]:
    """uid of WEB_UI_ACCOUNT, resolved per check; None when it does not exist."""
    return account_uid(WEB_UI_ACCOUNT)


def peer_action_allowed(uid: Optional[int], action: Any) -> tuple[bool, str]:
    """The control.sock peer table (Edge#471 stage 1). Returns (allowed, rule).

    ``uid == os.geteuid()`` (the daemon's own account) is treated like root.
    Under the unit the daemon IS root, so this adds nothing there; it lets a
    development stack run the daemon and the Web UI as one non-root account.
    It must be revisited if the daemon itself stops running as root (stage 3
    or later): its own account would then get every action."""
    if uid is None:
        return False, "peer_uid_unknown"
    action_name = action if isinstance(action, str) else ""
    if action_name in ROOT_ONLY_ACTIONS:
        return (uid == 0), "root_only"
    if uid == 0 or uid == os.geteuid():
        return True, "root"
    web_uid = _web_ui_uid()
    if web_uid is not None and uid == web_uid:
        return (action_name in WEB_UI_ACTIONS), "web_ui"
    return False, "peer_not_allowed"


def peer_may_connect(uid: Optional[int]) -> bool:
    """Whether the table allows this peer any action at all; checked before
    anything is read, so a peer with no action cannot hold a thread."""
    if uid is None:
        return False
    if uid == 0 or uid == os.geteuid():
        return True
    web_uid = _web_ui_uid()
    return web_uid is not None and uid == web_uid


def _count_refusal(uid: Optional[int]) -> int:
    with _PEER_REFUSALS_LOCK:
        _PEER_REFUSALS["total"] = int(_PEER_REFUSALS["total"]) + 1
        key = "unknown" if uid is None else str(uid)
        by_uid = _PEER_REFUSALS["by_uid"]
        by_uid[key] = int(by_uid.get(key, 0)) + 1
        return int(_PEER_REFUSALS["total"])


def peer_refusal_counts() -> dict[str, Any]:
    with _PEER_REFUSALS_LOCK:
        return {"total": int(_PEER_REFUSALS["total"]), "by_uid": dict(_PEER_REFUSALS["by_uid"])}


class _RequestTooLarge(ValueError):
    pass


def _read_request(conn, deadline: float) -> bytes:
    """One request: up to the first newline, the end of the stream, or a
    complete JSON document (older clients send no newline), whichever is
    first; at most MAX_REQUEST_BYTES, all of it before ``deadline``
    (time.monotonic())."""
    buf = b""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout()
        conn.settimeout(remaining)
        chunk = conn.recv(65536)
        if not chunk:
            return buf
        buf += chunk
        if b"\n" in buf:
            return buf.split(b"\n", 1)[0]
        if len(buf) > MAX_REQUEST_BYTES:
            raise _RequestTooLarge()
        try:
            json.loads(buf.decode("utf-8", errors="ignore"))
            return buf
        except ValueError:
            continue


def handle_client(conn, addr):
    """Handle incoming client connection"""
    try:
        peer_uid, peer_pid = peer_credentials(conn)
        if not peer_may_connect(peer_uid):
            allowed, rule = peer_action_allowed(peer_uid, None)
            total = _count_refusal(peer_uid)
            logger.warning(f"control.sock: refused uid={peer_uid} pid={peer_pid} before reading "
                           f"(rule={rule}, refused so far={total})")
            conn.sendall((json.dumps({"ok": False, "error": "forbidden", "reason": rule,
                                      "ts": time.time()}) + "\n").encode("utf-8"))
            return
        try:
            raw_bytes = _read_request(conn, time.monotonic() + REQUEST_READ_TIMEOUT_SEC)
        except _RequestTooLarge:
            conn.sendall(b'{"ok": false, "error": "Request too large"}\n')
            return
        except socket.timeout:
            conn.sendall(b'{"ok": false, "error": "Request timeout"}\n')
            return
        conn.settimeout(None)
        data = raw_bytes.decode("utf-8", errors="ignore").strip()
        if not data:
            conn.sendall(b'{"ok": false, "error": "Empty request"}\n')
            return
        request = json.loads(data)
        if not isinstance(request, dict):
            conn.sendall(b'{"ok": false, "error": "Invalid request"}\n')
            return
        action = request.get('action')
        params = request.get('params', {})

        allowed, rule = peer_action_allowed(peer_uid, action)
        if not allowed:
            total = _count_refusal(peer_uid)
            logger.warning(
                f"control.sock: refused action {str(action)[:64]!r} from uid={peer_uid} pid={peer_pid} "
                f"(rule={rule}, refused so far={total})"
            )
            conn.sendall((json.dumps({"ok": False, "error": "forbidden", "reason": rule,
                                      "action": str(action)[:64], "ts": time.time()}) + "\n").encode("utf-8"))
            return

        if action == "watch_snapshot":
            interval = float((params or {}).get("interval_sec", 1.0))
            if not _CLIENT_SLOTS.acquire_watch(peer_uid):
                logger.warning(f"control.sock: too many watch_snapshot streams; uid={peer_uid} answered busy")
                conn.sendall(b'{"ok": false, "error": "busy"}\n')
                return
            logger.info(f"Received action: watch_snapshot interval={interval}")
            try:
                stream_ui_snapshots(conn, interval_sec=interval)
            finally:
                _CLIENT_SLOTS.release_watch(peer_uid)
            return
        
        # Special handling: NEVER log wifi_connect params (contains passphrase)
        if action == 'wifi_connect':
            logger.info(f"Received action: wifi_connect (params sanitized)")
        else:
            logger.info(f"Received action: {action}")
        
        result = execute_action(action, params, request=request, peer_uid=peer_uid)
        
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

def _dispatch_client(conn, addr) -> bool:
    """Handle a connection in its own thread within the slot limits (root
    keeps headroom); beyond them the client is answered "busy" and closed."""
    uid, _pid = peer_credentials(conn)
    if not _CLIENT_SLOTS.acquire(uid):
        logger.warning(f"control.sock: too many concurrent clients; uid={uid} answered busy")
        try:
            conn.sendall(b'{"ok": false, "error": "busy"}\n')
        except OSError:
            pass
        conn.close()
        return False
    thread = threading.Thread(target=_handle_client_slot, args=(conn, addr, uid))
    thread.daemon = True
    thread.start()
    return True


def _handle_client_slot(conn, addr, uid: Optional[int] = None) -> None:
    try:
        handle_client(conn, addr)
    finally:
        _CLIENT_SLOTS.release(uid)


def start_noc_link_watch() -> None:
    """Start the link-state watch that re-evaluates a monitored interface on
    a carrier/operstate change (netlink multicast; sysfs poll fallback).
    The periodic snapshot loop stays the backstop."""
    global _NOC_LINK_WATCHER
    if _NOC_LINK_WATCHER is None:
        _NOC_LINK_WATCHER = LinkStateWatcher(_noc_monitored_interfaces, _noc_link_event_reevaluate)
        _NOC_LINK_WATCHER.start()


def main():
    flags = load_control_flags()
    ensure_socket_dir()
    suppress_auto_wifi(enabled=bool(flags.get("suppress_auto_wifi", True)))
    logger.info("Azazel-Edge Control Daemon started")

    sock = create_listener_socket()
    threading.Thread(target=warm_snapshot_cache_once, daemon=True).start()
    threading.Thread(target=snapshot_refresh_loop, daemon=True).start()
    threading.Thread(target=_wifi_sensor_loop, daemon=True).start()
    start_noc_link_watch()

    try:
        while True:
            if not SOCKET_PATH.exists():
                logger.warning("Control socket path disappeared; recreating listener")
                try:
                    sock.close()
                except Exception:
                    pass
                sock = create_listener_socket()
                continue
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            _dispatch_client(conn, _)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        _WIFI_SENSOR_STOP.set()
        sock.close()
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()

if __name__ == '__main__':
    main()
