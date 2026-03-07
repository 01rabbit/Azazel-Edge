#!/usr/bin/env python3
"""
Azazel-Edge Web UI - Flask Application

Provides HTTP API for remote monitoring and control via USB gadget network.
- Reads: control-plane snapshot (with file fallback)
- Executes: Actions via Unix socket to control daemon
- Serves: HTML dashboard + JSON API endpoints
"""

from flask import (
    Flask,
    jsonify,
    request,
    render_template,
    send_from_directory,
    send_file,
    Response,
    stream_with_context,
    has_request_context,
)
import json
import os
import socket
import sys
import time
import subprocess
import hashlib
import queue
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, Iterator, Tuple, List
from urllib.request import Request, urlopen
from urllib.parse import urlparse, quote

app = Flask(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = PROJECT_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

try:
    from azazel_edge.control_plane import (
        read_snapshot_payload as cp_read_snapshot_payload,
        watch_snapshots as cp_watch_snapshots,
    )
    from azazel_edge.runbooks import (
        execute_runbook as runbook_execute,
        get_runbook as runbook_get,
        list_runbooks as runbook_list,
    )
    from azazel_edge.runbook_review import (
        propose_runbooks as runbook_propose,
        review_runbook_id as runbook_review_id,
    )
    from azazel_edge.path_schema import (
        config_dir_candidates,
        first_minute_config_candidates,
        mode_state_candidates,
        portal_env_candidates,
        runtime_snapshot_path_candidates,
        web_token_candidates,
        warn_if_legacy_path,
    )
except Exception:
    cp_read_snapshot_payload = None
    cp_watch_snapshots = None
    runbook_execute = None
    runbook_get = None
    runbook_list = None
    runbook_propose = None
    runbook_review_id = None
    config_dir_candidates = lambda: [Path("/etc/azazel-edge"), Path("/etc/azazel-zero")]  # type: ignore
    first_minute_config_candidates = lambda: [Path("/etc/azazel-edge/first_minute.yaml"), Path("/etc/azazel-zero/first_minute.yaml")]  # type: ignore
    mode_state_candidates = lambda: [Path("/etc/azazel/mode.json"), Path("/etc/azazel-edge/mode.json"), Path("/etc/azazel-zero/mode.json")]  # type: ignore
    portal_env_candidates = lambda: [Path("/etc/azazel-edge/portal-viewer.env"), Path("/etc/azazel-zero/portal-viewer.env")]  # type: ignore
    runtime_snapshot_path_candidates = lambda: [Path("/run/azazel-edge/ui_snapshot.json"), Path("/run/azazel-zero/ui_snapshot.json")]  # type: ignore
    web_token_candidates = lambda: [Path.home() / ".azazel-edge" / "web_token.txt", Path.home() / ".azazel-zero" / "web_token.txt"]  # type: ignore
    warn_if_legacy_path = lambda *args, **kwargs: None  # type: ignore

# Configuration
_RUNTIME_STATE_PATHS = runtime_snapshot_path_candidates()
STATE_PATH = _RUNTIME_STATE_PATHS[0]  # Share TUI snapshot
FALLBACK_STATE_PATH = _RUNTIME_STATE_PATHS[-1]  # Legacy runtime fallback
CONTROL_SOCKET = Path("/run/azazel-edge/control.sock")
AI_SOCKET = Path(os.environ.get("AZAZEL_AI_SOCKET", "/run/azazel-edge/ai-bridge.sock"))
AI_MANUAL_TIMEOUT_SEC = float(os.environ.get("AZAZEL_AI_MANUAL_TIMEOUT_SEC", "95"))
RUNBOOK_EVENT_LOG = Path(os.environ.get("AZAZEL_RUNBOOK_EVENT_LOG", "/var/log/azazel-edge/runbook-events.jsonl"))
TOKEN_FILE = web_token_candidates()[0]
BIND_HOST = os.environ.get("AZAZEL_WEB_HOST", "0.0.0.0")
BIND_PORT = int(os.environ.get("AZAZEL_WEB_PORT", "8084"))
STATUS_API_HOSTS = ["10.55.0.10", "127.0.0.1"]
PORTAL_VIEWER_ENV_PATH = portal_env_candidates()[0]
NTFY_CONFIG_PATHS = [
    Path(os.environ.get("AZAZEL_CONFIG_PATH", str(first_minute_config_candidates()[0]))),
    Path("configs/first_minute.yaml"),
]
NTFY_SSE_KEEPALIVE_SEC = int(os.environ.get("AZAZEL_SSE_KEEPALIVE_SEC", "20"))
NTFY_SSE_READ_TIMEOUT_SEC = int(os.environ.get("AZAZEL_NTFY_READ_TIMEOUT_SEC", "35"))
NTFY_SSE_MAX_BACKOFF_SEC = int(os.environ.get("AZAZEL_NTFY_MAX_BACKOFF_SEC", "30"))
MATTERMOST_HOST = str(os.environ.get("AZAZEL_MATTERMOST_HOST", "172.16.0.254")).strip() or "172.16.0.254"
MATTERMOST_PORT = int(os.environ.get("AZAZEL_MATTERMOST_PORT", "8065"))
_mattermost_base_default = f"http://{MATTERMOST_HOST}:{MATTERMOST_PORT}"
MATTERMOST_BASE_URL = os.environ.get("AZAZEL_MATTERMOST_BASE_URL", _mattermost_base_default).rstrip("/")
MATTERMOST_TEAM = str(os.environ.get("AZAZEL_MATTERMOST_TEAM", "azazelops")).strip() or "azazelops"
MATTERMOST_CHANNEL = str(os.environ.get("AZAZEL_MATTERMOST_CHANNEL", "soc-noc")).strip() or "soc-noc"
MATTERMOST_OPEN_URL_DEFAULT = f"{MATTERMOST_BASE_URL}/{MATTERMOST_TEAM}/channels/{MATTERMOST_CHANNEL}"
MATTERMOST_OPEN_URL = str(os.environ.get("AZAZEL_MATTERMOST_OPEN_URL", MATTERMOST_OPEN_URL_DEFAULT)).strip() or MATTERMOST_OPEN_URL_DEFAULT
MATTERMOST_WEBHOOK_URL = str(os.environ.get("AZAZEL_MATTERMOST_WEBHOOK_URL", "")).strip()
MATTERMOST_BOT_TOKEN = str(os.environ.get("AZAZEL_MATTERMOST_BOT_TOKEN", "")).strip()
MATTERMOST_CHANNEL_ID = str(os.environ.get("AZAZEL_MATTERMOST_CHANNEL_ID", "")).strip()
MATTERMOST_COMMAND_TOKEN = str(os.environ.get("AZAZEL_MATTERMOST_COMMAND_TOKEN", "")).strip()
MATTERMOST_TIMEOUT_SEC = float(os.environ.get("AZAZEL_MATTERMOST_TIMEOUT_SEC", "8"))
MATTERMOST_FETCH_LIMIT = int(os.environ.get("AZAZEL_MATTERMOST_FETCH_LIMIT", "40"))
_CA_CERT_FILENAME = "azazel-webui-local-ca.crt"
_WEBUI_CA_CERT_CANDIDATES: List[Path] = []
_env_ca_cert = str(os.environ.get("AZAZEL_WEBUI_CA_PATH", "")).strip()
if _env_ca_cert:
    _WEBUI_CA_CERT_CANDIDATES.append(Path(_env_ca_cert))
for cfg_dir in config_dir_candidates():
    _WEBUI_CA_CERT_CANDIDATES.append(cfg_dir / "certs" / _CA_CERT_FILENAME)
_WEBUI_CA_CERT_CANDIDATES.extend([
    Path("/etc/azazel-edge/tls/ca/azazel-edge-local-ca.crt"),
    Path("/var/lib/azazel-edge/public/azazel-edge-local-ca.crt"),
    Path("/etc/azazel-gadget/tls/ca/azazel-edge-local-ca.crt"),
    Path("/var/lib/azazel-gadget/public/azazel-edge-local-ca.crt"),
])
if not _WEBUI_CA_CERT_CANDIDATES:
    _WEBUI_CA_CERT_CANDIDATES = [
        Path("/etc/azazel-edge/certs/azazel-webui-local-ca.crt"),
        Path("/etc/azazel-zero/certs/azazel-webui-local-ca.crt"),
    ]
_seen_ca_paths: set[str] = set()
WEBUI_CA_CERT_PATHS: List[Path] = []
for _candidate in _WEBUI_CA_CERT_CANDIDATES:
    key = str(_candidate)
    if key in _seen_ca_paths:
        continue
    _seen_ca_paths.add(key)
    WEBUI_CA_CERT_PATHS.append(_candidate)

# Allowed actions
ALLOWED_ACTIONS = {
    "refresh", "reprobe", "contain", "release", "details", "stage_open", "disconnect",
    "wifi_scan", "wifi_connect", "portal_viewer_open", "shutdown", "reboot",
    "mode_set", "mode_status", "mode_get", "mode_portal", "mode_shield", "mode_scapegoat"
}


def _load_first_minute_config() -> Dict[str, Any]:
    """Load first_minute.yaml if available, return empty dict on failure."""
    for cfg_path in NTFY_CONFIG_PATHS:
        try:
            if not cfg_path.exists():
                continue
            try:
                import yaml  # type: ignore
            except Exception:
                app.logger.warning("PyYAML not installed; using default ntfy bridge config")
                return {}
            data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                return data
        except Exception as e:
            app.logger.warning(f"Failed to load config {cfg_path}: {e}")
    return {}


def _load_ntfy_bridge_settings() -> Dict[str, Any]:
    """Resolve ntfy settings from config + env with sane defaults."""
    ntfy_port = os.environ.get("NTFY_PORT", "8081")
    default_base_url = f"http://127.0.0.1:{ntfy_port}"
    default_topic_alert = "azg-alert-critical"
    default_topic_info = "azg-info-status"
    default_token_file = "/etc/azazel/ntfy.token"

    cfg = _load_first_minute_config()
    notify_cfg = cfg.get("notify", {}) if isinstance(cfg, dict) else {}
    ntfy_cfg = notify_cfg.get("ntfy", {}) if isinstance(notify_cfg, dict) else {}

    base_url = (
        os.environ.get("NTFY_BASE_URL")
        or ntfy_cfg.get("base_url")
        or default_base_url
    ).rstrip("/")
    topic_alert = os.environ.get("NTFY_TOPIC_ALERT") or ntfy_cfg.get("topic_alert") or default_topic_alert
    topic_info = os.environ.get("NTFY_TOPIC_INFO") or ntfy_cfg.get("topic_info") or default_topic_info
    token_file = Path(
        os.environ.get("NTFY_TOKEN_FILE")
        or ntfy_cfg.get("token_file")
        or default_token_file
    )

    token = ""
    try:
        if token_file.exists() and os.access(token_file, os.R_OK):
            token = token_file.read_text(encoding="utf-8").strip()
        elif token_file.exists():
            # Subscription can work without token when topics are read-allowed.
            # Avoid noisy warnings for expected permission boundaries.
            app.logger.debug(f"ntfy token file exists but is not readable by webui user: {token_file}")
    except PermissionError:
        app.logger.debug(f"ntfy token file is not readable by webui user: {token_file}")
    except Exception as e:
        app.logger.warning(f"Failed to read ntfy token file {token_file}: {e}")

    topics = [str(topic_alert).strip(), str(topic_info).strip()]
    topics = [t for t in topics if t]
    dedup_topics: List[str] = []
    for topic in topics:
        if topic not in dedup_topics:
            dedup_topics.append(topic)

    return {
        "base_url": base_url,
        "topics": dedup_topics or [default_topic_alert],
        "token": token,
    }


def _build_ntfy_sse_url(base_url: str, topics: List[str]) -> str:
    topic_path = ",".join(topics)
    return f"{base_url}/{topic_path}/sse"


def _to_iso_timestamp(raw_ts: Any) -> str:
    """Convert ntfy timestamp to ISO-8601 if possible."""
    try:
        if isinstance(raw_ts, (int, float)):
            return datetime.fromtimestamp(float(raw_ts)).isoformat()
        if isinstance(raw_ts, str):
            return datetime.fromtimestamp(float(raw_ts)).isoformat()
    except Exception:
        pass
    return datetime.now().isoformat()


def _normalize_ntfy_event(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize ntfy payload for WebUI event consumers."""
    payload_event = str(data.get("event") or "").lower()
    if payload_event in {"open", "keepalive", "poll_request"}:
        return None

    topic = str(data.get("topic") or "unknown")
    title = str(data.get("title") or "Azazel Notification")
    message = str(data.get("message") or data.get("body") or "")
    try:
        priority = int(data.get("priority") or 2)
    except Exception:
        priority = 2
    tags = data.get("tags") if isinstance(data.get("tags"), list) else []
    event_id = str(data.get("id") or "")
    dedup_key = f"ntfy:{event_id}" if event_id else f"ntfy:{topic}:{title}:{message}"

    severity = "info"
    if priority >= 5:
        severity = "error"
    elif priority >= 4:
        severity = "warning"

    return {
        "source": "ntfy",
        "id": event_id,
        "topic": topic,
        "title": title,
        "message": message,
        "priority": priority,
        "tags": tags,
        "timestamp": _to_iso_timestamp(data.get("time")),
        "dedup_key": dedup_key,
        "severity": severity,
        "event": payload_event or "message",
    }


def _iter_ntfy_sse_events(
    ntfy_url: str,
    token: str,
    stop_event: threading.Event,
) -> Iterator[Tuple[str, str]]:
    """Yield ntfy SSE event/data pairs."""
    headers = {"Accept": "text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = Request(ntfy_url, headers=headers, method="GET")
    with urlopen(req, timeout=NTFY_SSE_READ_TIMEOUT_SEC) as resp:
        yield "__bridge_open__", ""
        current_event = "message"
        data_lines: List[str] = []

        while not stop_event.is_set():
            raw_line = resp.readline()
            if not raw_line:
                raise ConnectionError("ntfy SSE stream closed")

            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            if line == "":
                if data_lines:
                    yield current_event, "\n".join(data_lines)
                current_event = "message"
                data_lines = []
                continue

            if line.startswith(":"):
                continue
            if line.startswith("event:"):
                current_event = line.split(":", 1)[1].strip() or "message"
                continue
            if line.startswith("data:"):
                data_lines.append(line.split(":", 1)[1].strip())


def _sse_message(event_name: str, payload: Dict[str, Any]) -> str:
    data = json.dumps(payload, ensure_ascii=False)
    return f"event: {event_name}\ndata: {data}\n\n"


def _sha256_file(path: Path) -> str:
    """Return SHA-256 hex digest for a file."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _resolve_webui_ca_cert_path() -> Tuple[Path, List[Path]]:
    """Return first existing CA cert path plus all checked candidates."""
    for candidate in WEBUI_CA_CERT_PATHS:
        if candidate.exists():
            warn_if_legacy_path(candidate, app.logger)
            return candidate, WEBUI_CA_CERT_PATHS
    return WEBUI_CA_CERT_PATHS[0], WEBUI_CA_CERT_PATHS


def _queue_put_drop_oldest(out_q: queue.Queue, item: Dict[str, Any]) -> None:
    """Try queue put; if full, drop oldest one and retry once."""
    try:
        out_q.put(item, timeout=0.2)
        return
    except queue.Full:
        pass
    try:
        out_q.get_nowait()
    except queue.Empty:
        return
    try:
        out_q.put_nowait(item)
    except queue.Full:
        pass


def _stream_ntfy_to_queue(out_q: queue.Queue, stop_event: threading.Event) -> None:
    """Bridge ntfy SSE events into queue with reconnect/backoff."""
    settings = _load_ntfy_bridge_settings()
    ntfy_url = _build_ntfy_sse_url(settings["base_url"], settings["topics"])
    token = settings["token"]
    backoff = 1.0

    while not stop_event.is_set():
        try:
            _queue_put_drop_oldest(out_q, {
                "kind": "bridge_status",
                "status": "UPSTREAM_CONNECTING",
                "timestamp": datetime.now().isoformat(),
                "source": "bridge",
                "dedup_key": "bridge:upstream_connecting",
                "severity": "info",
            })
            for event_name, raw_data in _iter_ntfy_sse_events(ntfy_url, token, stop_event):
                if stop_event.is_set():
                    break
                if event_name == "__bridge_open__":
                    _queue_put_drop_oldest(out_q, {
                        "kind": "bridge_status",
                        "status": "UPSTREAM_CONNECTED",
                        "timestamp": datetime.now().isoformat(),
                        "source": "bridge",
                        "dedup_key": "bridge:upstream_connected",
                        "severity": "info",
                    })
                    backoff = 1.0
                    continue
                try:
                    parsed = json.loads(raw_data)
                except json.JSONDecodeError:
                    continue
                if not isinstance(parsed, dict):
                    continue
                normalized = _normalize_ntfy_event(parsed)
                if normalized is None:
                    continue
                _queue_put_drop_oldest(out_q, normalized)
        except Exception as e:
            if stop_event.is_set():
                break
            app.logger.warning(f"ntfy bridge disconnected, retrying in {backoff:.1f}s: {e}")
            try:
                _queue_put_drop_oldest(out_q, {
                    "kind": "bridge_status",
                    "status": "UPSTREAM_RECONNECTING",
                    "message": str(e),
                    "retry_sec": round(backoff, 1),
                    "timestamp": datetime.now().isoformat(),
                    "source": "bridge",
                    "dedup_key": f"bridge:{type(e).__name__}",
                    "severity": "warning",
                })
            except Exception:
                pass
            if stop_event.wait(backoff):
                break
            backoff = min(backoff * 2.0, float(NTFY_SSE_MAX_BACKOFF_SEC))

def load_token() -> Optional[str]:
    """Web UI 認証トークンをロード"""
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip()
    return None


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")

def verify_token() -> bool:
    """リクエストのトークン検証（ヘッダーまたはクエリパラメータ）"""
    token = load_token()
    if not token:
        return True  # トークン未設定の場合はスルー
    
    req_token = (
        request.headers.get('X-AZAZEL-TOKEN')
        or request.headers.get('X-Auth-Token')
        or request.args.get('token')
    )
    return req_token == token


def _review_context_from_request(body: Dict[str, Any] | None = None) -> Dict[str, Any]:
    src = body if isinstance(body, dict) else {}
    context = src.get("context") if isinstance(src.get("context"), dict) else {}
    out: Dict[str, Any] = dict(context)
    question = str(src.get("question") or out.get("question") or "").strip()
    audience = str(src.get("audience") or out.get("audience") or "").strip()
    risk_score = src.get("risk_score", out.get("risk_score"))
    if question:
        out["question"] = question
    if audience:
        out["audience"] = audience
    try:
        if risk_score not in (None, ""):
            out["risk_score"] = int(risk_score)
    except Exception:
        pass
    return out


def _mattermost_command_allowed(command_token: str) -> bool:
    token = str(command_token or "").strip()
    if MATTERMOST_COMMAND_TOKEN:
        return token == MATTERMOST_COMMAND_TOKEN
    return True


def _format_mattermost_ai_response(ai_result: Dict[str, Any] | None, proposals: Dict[str, Any] | None) -> str:
    lines: List[str] = []
    if isinstance(ai_result, dict):
        answer = str(ai_result.get("answer") or "").strip()
        if answer:
            lines.append(f"AI: {answer}")
        runbook_id = str(ai_result.get("runbook_id") or "").strip()
        review = ai_result.get("runbook_review") if isinstance(ai_result.get("runbook_review"), dict) else {}
        if runbook_id:
            lines.append(f"Suggested Runbook: `{runbook_id}`")
        if review:
            lines.append(f"Review: `{review.get('final_status', '-')}`")
            changes = review.get("required_changes")
            if isinstance(changes, list) and changes:
                lines.append("Required Changes: " + " | ".join(str(x) for x in changes[:3]))
    if isinstance(proposals, dict):
        items = proposals.get("items")
        if isinstance(items, list) and items:
            lines.append("Candidates:")
            for item in items[:3]:
                review = item.get("review") if isinstance(item.get("review"), dict) else {}
                lines.append(
                    f"- `{item.get('runbook_id', '-')}` [{review.get('final_status', '-')}] {item.get('title', '-')}"
                )
    return "\n".join(lines)[:3000]


def _pid_running(pid_path: Path, expected_cmd: str = "") -> bool:
    """Check whether the pid in pid_path is running."""
    try:
        pid_text = pid_path.read_text().strip()
        if not pid_text:
            return False
        pid = int(pid_text)
    except Exception:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    if expected_cmd:
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", errors="ignore")
            if expected_cmd not in cmdline:
                return False
        except Exception:
            return False
    return True


def _service_active(service: str) -> bool:
    """Check systemd service status without requiring root."""
    try:
        result = subprocess.run(
            ["/bin/systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return result.returncode == 0 and result.stdout.strip() == "active"
    except Exception:
        return False


def _portal_viewer_config() -> Dict[str, Any]:
    """Resolve portal viewer bind/port from env file."""
    default_bind = os.environ.get("PORTAL_NOVNC_BIND", os.environ.get("MGMT_IP", "10.55.0.10"))
    default_port = int(os.environ.get("PORTAL_NOVNC_PORT", "6080"))
    config = {
        "bind": default_bind,
        "port": default_port,
    }
    try:
        if not PORTAL_VIEWER_ENV_PATH.exists():
            return config
        for raw in PORTAL_VIEWER_ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key == "PORTAL_NOVNC_PORT":
                config["port"] = int(value)
            elif key == "PORTAL_NOVNC_BIND":
                config["bind"] = value
    except Exception:
        return config
    return config


def _probe_hosts_for_bind(bind_host: str) -> list:
    """Build probe host candidates from bind address."""
    host = str(bind_host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host in {"", "0.0.0.0", "::", "*"}:
        return ["127.0.0.1", "::1"]
    if host in {"localhost", "127.0.0.1", "::1"}:
        return [host]
    return [host, "127.0.0.1"]


def _tcp_open(port: int, hosts: list, timeout_sec: float = 0.2) -> bool:
    """Check TCP availability on any candidate host."""
    seen = set()
    for host in hosts:
        if host in seen:
            continue
        seen.add(host)
        try:
            with socket.create_connection((host, int(port)), timeout=timeout_sec):
                return True
        except Exception:
            continue
    return False


def _url_host(host: str) -> str:
    """Format host part for URL (wrap IPv6 if needed)."""
    formatted = str(host or "").strip()
    if ":" in formatted and not (formatted.startswith("[") and formatted.endswith("]")):
        return f"[{formatted}]"
    return formatted


def _is_wildcard_bind(host: str) -> bool:
    host = str(host or "").strip()
    return host in {"", "0.0.0.0", "::", "*"}


def _request_host_or_default() -> str:
    if has_request_context():
        return request.host.split(":")[0] if request.host else "10.55.0.10"
    return "10.55.0.10"


def _request_scheme_or_default() -> str:
    if has_request_context():
        return request.scheme
    return "http"


def _normalize_http_url(candidate: Any) -> str:
    """Return normalized http(s) URL or empty string."""
    text = str(candidate or "").strip()
    if not text or any(ch in text for ch in ("\r", "\n")):
        return ""
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return text


def _portal_start_url_from_state(state: Dict[str, Any]) -> str:
    """Infer the best portal start URL from latest captive probe state."""
    if not isinstance(state, dict):
        return ""
    conn = state.get("connection")
    if not isinstance(conn, dict):
        return ""

    status = str(conn.get("captive_portal", "") or "").upper()
    detail = conn.get("captive_portal_detail") if isinstance(conn.get("captive_portal_detail"), dict) else {}
    candidates = [
        detail.get("portal_url"),
        conn.get("captive_portal_url"),
        detail.get("location"),
        detail.get("effective_url"),
        conn.get("captive_location"),
        conn.get("captive_effective_url"),
        detail.get("probe_url"),
        conn.get("captive_probe_url"),
    ]
    for candidate in candidates:
        normalized = _normalize_http_url(candidate)
        if normalized:
            return normalized

    if status in {"YES", "SUSPECTED"}:
        return "http://connectivitycheck.gstatic.com/generate_204"
    return ""


def _portal_viewer_url_host(config_bind: str) -> str:
    """Choose host advertised to clients for noVNC URL."""
    override_host = os.environ.get("PORTAL_VIEWER_HOST", "").strip()
    if override_host:
        return override_host
    if not _is_wildcard_bind(config_bind):
        return config_bind
    return _request_host_or_default()


def _portal_viewer_state_from_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Build portal viewer state from resolved config + runtime checks."""
    bind_host = str(config.get("bind", "")).strip() or os.environ.get("MGMT_IP", "10.55.0.10")
    port = int(config.get("port", 6080))
    probe_hosts = _probe_hosts_for_bind(bind_host)
    active = _service_active("azazel-portal-viewer.service")
    ready = active and _tcp_open(port, probe_hosts)
    scheme = _request_scheme_or_default()
    host = _url_host(_portal_viewer_url_host(bind_host))
    url = f"{scheme}://{host}:{port}/vnc.html?autoconnect=true&resize=scale"
    return {
        "active": active,
        "ready": ready,
        "bind": bind_host,
        "probe_hosts": probe_hosts,
        "port": port,
        "url": url,
    }


def get_portal_viewer_state() -> Dict[str, Any]:
    """Return current noVNC portal viewer availability."""
    return _portal_viewer_state_from_config(_portal_viewer_config())


def _ntfy_health_ok() -> bool:
    """Check ntfy HTTP health endpoint."""
    mgmt_ip = os.environ.get("MGMT_IP", "10.55.0.10")
    ntfy_port = os.environ.get("NTFY_PORT", "8081")
    hosts = [mgmt_ip, "127.0.0.1", "localhost"]
    seen = set()
    for host in hosts:
        if host in seen:
            continue
        seen.add(host)
        url = f"http://{host}:{ntfy_port}/v1/health"
        try:
            with urlopen(url, timeout=2) as resp:
                if resp.status != 200:
                    continue
                body = resp.read(256).decode("utf-8", errors="ignore")
                if '"healthy":true' in body:
                    return True
        except Exception:
            continue
    return False


def _process_running(pattern: str) -> bool:
    """Check process existence by pattern without PID file read access."""
    try:
        result = subprocess.run(
            ["pgrep", "-f", pattern],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


def _container_running(name: str) -> bool:
    """Check Docker container running state by exact name."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode != 0:
            return False
        names = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        return name in names
    except Exception:
        return False


def get_monitoring_state() -> Dict[str, str]:
    """Return ON/OFF status for local monitoring daemons."""
    # Prefer systemd state to avoid pidfile permission issues
    opencanary_ok = (
        _service_active("opencanary@az_canary.service")
        or _service_active("opencanary.service")
        or _service_active("azazel-edge-opencanary.service")
        or _container_running("azazel-edge-opencanary")
    )
    suricata_ok = (
        _service_active("suricata.service")
        or _service_active("azazel-edge-suricata.service")
        or _container_running("azazel-edge-suricata")
    )
    ntfy_ok = _service_active("ntfy.service") and _ntfy_health_ok()
    opencanary_pid = Path("/home/azazel/canary-venv/bin/opencanaryd.pid")
    suricata_pid = Path("/run/suricata.pid")
    return {
        "opencanary": "ON" if (opencanary_ok or _pid_running(opencanary_pid, "opencanary") or _process_running("[o]pencanary.tac")) else "OFF",
        "suricata": "ON" if (suricata_ok or _pid_running(suricata_pid, "suricata")) else "OFF",
        "ntfy": "ON" if ntfy_ok else "OFF",
    }


def get_mode_state() -> Dict[str, Any]:
    """Return gateway mode status from control daemon, with file fallback."""
    daemon_payload = send_control_command_with_params("mode_status", {})
    if daemon_payload.get("ok") and isinstance(daemon_payload.get("mode"), dict):
        return daemon_payload

    fallback_paths = mode_state_candidates()
    for path in fallback_paths:
        try:
            if not path.exists():
                continue
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                return {
                    "ok": True,
                    "mode": {
                        "current_mode": str(payload.get("current_mode", "shield")).lower(),
                        "last_change": str(payload.get("last_change", "")),
                        "requested_by": str(payload.get("requested_by", "")),
                        "config_hash": str(payload.get("config_hash", "")),
                    },
                    "source": f"FILE:{path}",
                }
        except Exception:
            continue

    return {
        "ok": False,
        "mode": {
            "current_mode": "shield",
            "last_change": "",
            "requested_by": "",
            "config_hash": "",
        },
        "error": daemon_payload.get("error", "mode status unavailable"),
    }


def read_state() -> Dict[str, Any]:
    """Read snapshot from control-plane first, then filesystem fallback."""
    try:
        if cp_read_snapshot_payload is not None:
            data, source = cp_read_snapshot_payload(prefer_control_plane=True, logger=app.logger)
            if isinstance(data, dict):
                data["ok"] = True
                data["source"] = source
                return data

        # Try primary path (TUI snapshot)
        path = STATE_PATH
        if not path.exists():
            # Try fallback path (for dev/testing)
            path = FALLBACK_STATE_PATH
        
        if not path.exists():
            return {
                "ok": False,
                "error": "ui_snapshot.json not found",
                "source": "NONE",
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
            }
        
        warn_if_legacy_path(path, logger=app.logger)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["ok"] = True
        data.setdefault("source", f"FILE:{path}")
        return data
    except Exception as e:
        return {
            "ok": False,
            "error": f"Failed to read state: {str(e)}",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
        }


def _normalize_status_payload(payload: Dict[str, Any], action: str = "") -> Dict[str, Any]:
    """Normalize Status API payload shape."""
    if payload.get("status") == "ok" and "ok" not in payload:
        payload["ok"] = True
    if action and "action" not in payload:
        payload["action"] = action
    return payload


def _status_api_json(
    host: str,
    path: str,
    method: str = "GET",
    timeout_sec: float = 2.0,
    action: str = "",
    empty_ok: bool = False,
    empty_message: str = "",
) -> Optional[Dict[str, Any]]:
    """Call first-minute Status API and return normalized JSON payload if available."""
    try:
        cmd: List[str] = ["curl", "-s"]
        if method.upper() == "POST":
            cmd.extend(["-X", "POST"])
        cmd.append(f"http://{host}:8082{path}")

        result = subprocess.run(cmd, capture_output=True, timeout=timeout_sec)
        if result.returncode != 0:
            return None

        response_text = result.stdout.decode("utf-8").strip()
        if not response_text:
            if not empty_ok:
                return None
            payload: Dict[str, Any] = {"ok": True}
            if action:
                payload["action"] = action
            if empty_message:
                payload["message"] = empty_message
            return payload

        payload = json.loads(response_text)
        if not isinstance(payload, dict):
            return None
        return _normalize_status_payload(payload, action=action)
    except Exception:
        return None


def _first_status_api_response(
    path: str,
    method: str = "GET",
    action: str = "",
    empty_ok: bool = False,
    empty_message: str = "",
) -> Optional[Dict[str, Any]]:
    """Try Status API hosts in order and return first successful JSON payload."""
    for host in STATUS_API_HOSTS:
        payload = _status_api_json(
            host=host,
            path=path,
            method=method,
            action=action,
            empty_ok=empty_ok,
            empty_message=empty_message,
        )
        if payload is not None:
            return payload
    return None


def execute_contain_action() -> Dict[str, Any]:
    """Execute contain action: activate CONTAIN stage via Status API"""
    try:
        payload = _first_status_api_response(
            path="/action/contain",
            method="POST",
            action="contain",
            empty_ok=True,
            empty_message="Containment activated",
        )
        if payload is not None:
            return payload
        return {"ok": False, "action": "contain", "error": "Failed to reach Status API on any host"}
    except Exception as e:
        return {"ok": False, "action": "contain", "error": str(e)}

def execute_disconnect_action() -> Dict[str, Any]:
    """Execute disconnect action: disconnect downstream USB clients"""
    try:
        # Try to send to Status API first
        payload = _first_status_api_response(
            path="/action/disconnect",
            method="POST",
            action="disconnect",
            empty_ok=False,
        )
        if payload is not None:
            return payload
        
        # Fallback: attempt to bring down upstream Wi-Fi interface
        iface = os.environ.get("AZAZEL_UP_IF", "wlan0")
        down_result = subprocess.run(
            ["ip", "link", "set", iface, "down"],
            capture_output=True,
            timeout=5
        )
        if down_result.returncode != 0:
            stderr = down_result.stderr.decode("utf-8").strip() if down_result.stderr else "unknown error"
            return {
                "ok": False,
                "action": "disconnect",
                "error": f"Fallback disconnect failed: {iface} down failed: {stderr}"
            }
        
        return {"ok": True, "action": "disconnect", "message": f"Wi-Fi disconnected ({iface} down)"}
    except Exception as e:
        return {"ok": False, "action": "disconnect", "error": str(e)}

def _post_status_action(host: str, action: str) -> Optional[Dict[str, Any]]:
    """POST action to first-minute Status API and normalize response."""
    return _status_api_json(
        host=host,
        path=f"/action/{action}",
        method="POST",
        action=action,
        empty_ok=True,
    )

def _read_status_state(host: str) -> Optional[Dict[str, Any]]:
    """GET current state from first-minute Status API."""
    return _status_api_json(host=host, path="/", method="GET", empty_ok=False)

def execute_release_action() -> Dict[str, Any]:
    """Execute release action and verify that stage actually leaves CONTAIN."""
    try:
        for host in STATUS_API_HOSTS:
            first = _post_status_action(host, "release")
            if not first:
                continue
            if not first.get("ok", False):
                return {
                    "ok": False,
                    "action": "release",
                    "error": first.get("error", "Failed to send release command"),
                }

            second_sent = False
            last_reason = ""
            deadline = time.time() + 12.0

            while time.time() < deadline:
                state_payload = _read_status_state(host)
                if not state_payload:
                    time.sleep(0.25)
                    continue

                state_name = str(state_payload.get("stage") or state_payload.get("state") or "").upper()
                reason = str(state_payload.get("reason") or "").strip()
                if reason:
                    last_reason = reason

                if state_name and state_name != "CONTAIN":
                    return {
                        "ok": True,
                        "action": "release",
                        "message": "Containment released",
                        "state": state_name,
                        "reason": reason,
                    }

                reason_lower = reason.lower()
                if "minimum duration not reached" in reason_lower:
                    return {"ok": False, "action": "release", "error": reason}

                if ("confirmation required" in reason_lower) and not second_sent:
                    second = _post_status_action(host, "release")
                    if not second or not second.get("ok", False):
                        return {
                            "ok": False,
                            "action": "release",
                            "error": (second or {}).get("error", "Failed to send release confirmation"),
                        }
                    second_sent = True

                time.sleep(0.25)

            if last_reason:
                return {"ok": False, "action": "release", "error": f"Release timeout: {last_reason}"}
            return {"ok": False, "action": "release", "error": "Release timeout: stage stayed CONTAIN"}

        return {"ok": False, "action": "release", "error": "Failed to reach Status API on any host"}
    except Exception as e:
        return {"ok": False, "action": "release", "error": str(e)}

def execute_details_action() -> Dict[str, Any]:
    """Execute details action: get detailed threat analysis from Status API"""
    try:
        payload = _first_status_api_response(
            path="/details",
            method="GET",
            action="details",
            empty_ok=True,
            empty_message="No details available",
        )
        if payload is not None:
            return payload
        # Fallback to control-daemon script (details.sh) when Status API is absent.
        return _send_control_command_socket(action="details", params=None, timeout_sec=5.0)
    except Exception as e:
        return {"ok": False, "action": "details", "error": str(e)}

def execute_stage_open_action() -> Dict[str, Any]:
    """Execute stage_open action: return to NORMAL stage via Status API"""
    try:
        payload = _first_status_api_response(
            path="/action/stage_open",
            method="POST",
            action="stage_open",
            empty_ok=True,
            empty_message="Stage opened",
        )
        if payload is not None:
            return payload
        return {"ok": False, "action": "stage_open", "error": "Failed to reach Status API on any host"}
    except Exception as e:
        return {"ok": False, "action": "stage_open", "error": str(e)}


def _send_control_command_socket(
    action: str,
    params: Optional[Dict[str, Any]] = None,
    timeout_sec: float = 5.0,
) -> Dict[str, Any]:
    """Send command to Control Daemon via Unix socket."""
    if not CONTROL_SOCKET.exists():
        return {
            "ok": False,
            "action": action,
            "error": "Control daemon not running",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
        }

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        sock.connect(str(CONTROL_SOCKET))

        command: Dict[str, Any] = {"action": action, "ts": time.time()}
        if params is not None:
            command["params"] = params

        sock.sendall(json.dumps(command).encode("utf-8") + b"\n")

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\n" in chunk:
                break
        sock.close()

        if response:
            return json.loads(response.decode("utf-8"))
        return {
            "ok": False,
            "action": action,
            "error": "Empty response from daemon",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
        }
    except socket.timeout:
        return {
            "ok": False,
            "action": action,
            "error": "Daemon timeout",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
        }
    except Exception as e:
        return {
            "ok": False,
            "action": action,
            "error": str(e),
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
        }

def send_control_command(action: str) -> Dict[str, Any]:
    """Send command to Control Daemon via Unix socket"""
    if action not in ALLOWED_ACTIONS:
        return {
            "ok": False,
            "action": action,
            "error": "Unknown action",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
        }
    
    direct_handlers = {
        "contain": execute_contain_action,
        "release": execute_release_action,
        "disconnect": execute_disconnect_action,
        "details": execute_details_action,
        "stage_open": execute_stage_open_action,
    }
    handler = direct_handlers.get(action)
    if handler is not None:
        return handler()
    if action == "portal_viewer_open":
        return send_control_command_with_params("portal_viewer_open", {"timeout_sec": 15})
    if action in ("shutdown", "reboot"):
        return _send_control_command_socket(action=action, params=None, timeout_sec=45.0)
    return _send_control_command_socket(action=action, params=None, timeout_sec=5.0)


def send_control_command_with_params(action: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Send command with parameters to Control Daemon via Unix socket"""
    if action not in ALLOWED_ACTIONS:
        return {
            "ok": False,
            "action": action,
            "error": "Unknown action",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")
        }
    return _send_control_command_socket(action=action, params=params, timeout_sec=30.0)


def _send_ai_manual_query(
    question: str,
    sender: str = "Azazel-Edge WebUI",
    source: str = "webui",
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if not AI_SOCKET.exists():
        return {"ok": False, "error": f"ai_socket_not_found:{AI_SOCKET}"}
    payload = {
        "action": "manual_query",
        "params": {
            "question": str(question or "").strip(),
            "sender": str(sender or "operator").strip(),
            "source": str(source or "webui").strip(),
            "context": context if isinstance(context, dict) else {},
        },
        "ts": time.time(),
    }
    if not payload["params"]["question"]:
        return {"ok": False, "error": "empty_question"}
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(AI_MANUAL_TIMEOUT_SEC)
        sock.connect(str(AI_SOCKET))
        sock.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n")
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\n" in chunk:
                break
        sock.close()
        if not response:
            return {"ok": False, "error": "empty_ai_response"}
        text = response.decode("utf-8", errors="replace").strip()
        if "\n" in text:
            text = text.splitlines()[0]
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {"ok": False, "error": "invalid_ai_response"}
    except socket.timeout:
        return {"ok": False, "error": "ai_timeout"}
    except Exception as e:
        return {"ok": False, "error": f"ai_query_error:{e}"}


def _mattermost_mode() -> str:
    if MATTERMOST_BOT_TOKEN and MATTERMOST_CHANNEL_ID:
        return "bot_api"
    if MATTERMOST_WEBHOOK_URL:
        return "webhook"
    return "disabled"


def _mattermost_ping() -> tuple[bool, Dict[str, Any]]:
    try:
        req = Request(
            f"{MATTERMOST_BASE_URL}/api/v4/system/ping",
            headers={"Accept": "application/json"},
            method="GET",
        )
        with urlopen(req, timeout=MATTERMOST_TIMEOUT_SEC) as resp:
            payload_raw = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(payload_raw) if payload_raw else {}
        return True, payload if isinstance(payload, dict) else {}
    except Exception as e:
        return False, {"error": str(e)}


def _mattermost_api_request(method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not MATTERMOST_BOT_TOKEN:
        raise RuntimeError("mattermost_token_not_configured")

    body = None
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {MATTERMOST_BOT_TOKEN}",
    }
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = Request(f"{MATTERMOST_BASE_URL}{path}", data=body, headers=headers, method=method.upper())
    try:
        with urlopen(req, timeout=MATTERMOST_TIMEOUT_SEC) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        parsed = json.loads(raw) if raw else {}
        return parsed if isinstance(parsed, dict) else {}
    except Exception as e:
        raise RuntimeError(f"mattermost_api_error:{e}") from e


def _mattermost_send_message(text: str, sender: str = "Azazel-Edge WebUI") -> Dict[str, Any]:
    message = str(text or "").strip()
    if not message:
        raise RuntimeError("empty_message")

    if MATTERMOST_BOT_TOKEN and MATTERMOST_CHANNEL_ID:
        payload = {"channel_id": MATTERMOST_CHANNEL_ID, "message": message}
        result = _mattermost_api_request("POST", "/api/v4/posts", payload)
        return {"ok": True, "mode": "bot_api", "post_id": str(result.get("id") or "")}

    if MATTERMOST_WEBHOOK_URL:
        payload = {"text": message, "username": sender}
        req = Request(
            MATTERMOST_WEBHOOK_URL,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=MATTERMOST_TIMEOUT_SEC):
                pass
            return {"ok": True, "mode": "webhook"}
        except Exception as e:
            raise RuntimeError(f"mattermost_webhook_error:{e}") from e

    raise RuntimeError("mattermost_not_configured")


def _mattermost_fetch_messages(limit: int = MATTERMOST_FETCH_LIMIT) -> Dict[str, Any]:
    per_page = min(200, max(1, int(limit)))
    mode = _mattermost_mode()
    if mode != "bot_api":
        return {"ok": True, "mode": mode, "items": [], "note": "readback_requires_bot_api"}

    channel_id = quote(MATTERMOST_CHANNEL_ID, safe="")
    payload = _mattermost_api_request(
        "GET",
        f"/api/v4/channels/{channel_id}/posts?page=0&per_page={per_page}",
        None,
    )
    posts = payload.get("posts", {}) if isinstance(payload.get("posts"), dict) else {}
    order = payload.get("order", []) if isinstance(payload.get("order"), list) else []
    items: List[Dict[str, Any]] = []
    for post_id in reversed(order):
        post = posts.get(post_id)
        if not isinstance(post, dict):
            continue
        items.append(
            {
                "id": str(post.get("id") or ""),
                "create_at": int(post.get("create_at") or 0),
                "message": str(post.get("message") or ""),
                "user_id": str(post.get("user_id") or ""),
            }
        )
    return {"ok": True, "mode": mode, "items": items}


# Web UI Routes

@app.route("/")
def index():
    """Main dashboard page"""
    return render_template("index.html")


@app.route("/ops-comm")
def ops_comm():
    """Dedicated communication page for Mattermost + WebUI bridge."""
    open_url = MATTERMOST_OPEN_URL
    return render_template("ops_comm.html", mattermost_open_url=open_url)


@app.route("/api/state")
def api_state():
    """GET /api/state - Return current state.json"""
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 403
    
    state = read_state()
    # Add local monitoring status
    state["monitoring"] = get_monitoring_state()
    state["portal_viewer"] = get_portal_viewer_state()
    mode_state = get_mode_state()
    state["mode"] = mode_state.get("mode", {})
    state["mode_runtime"] = mode_state
    return jsonify(state)


@app.route("/api/state/stream")
def api_state_stream():
    """GET /api/state/stream - SSE stream for control-plane snapshot updates."""
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 403

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }

    def generate() -> Iterator[str]:
        yield "event: ready\ndata: " + json.dumps({"ok": True, "source": "state_stream"}) + "\n\n"
        if cp_watch_snapshots is not None:
            for snap in cp_watch_snapshots(interval_sec=1.0):
                payload = dict(snap)
                payload["ok"] = True
                payload["monitoring"] = get_monitoring_state()
                payload["portal_viewer"] = get_portal_viewer_state()
                mode_state = get_mode_state()
                payload["mode"] = mode_state.get("mode", {})
                payload["mode_runtime"] = mode_state
                yield "event: state\ndata: " + json.dumps(payload, ensure_ascii=False) + "\n\n"
            return
        while True:
            payload = read_state()
            payload["monitoring"] = get_monitoring_state()
            payload["portal_viewer"] = get_portal_viewer_state()
            mode_state = get_mode_state()
            payload["mode"] = mode_state.get("mode", {})
            payload["mode_runtime"] = mode_state
            yield "event: state\ndata: " + json.dumps(payload, ensure_ascii=False) + "\n\n"
            time.sleep(1.0)

    return Response(stream_with_context(generate()), headers=headers, mimetype="text/event-stream")


@app.route("/api/portal-viewer")
def api_portal_viewer():
    """GET /api/portal-viewer - Return portal viewer status and URL."""
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(get_portal_viewer_state())


@app.route("/api/portal-viewer/open", methods=["POST"])
def api_portal_viewer_open():
    """POST /api/portal-viewer/open - Ensure noVNC is up then return URL."""
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403

    request_body = request.get_json(silent=True) or {}
    timeout_sec = request_body.get("timeout_sec", 15)
    start_url = _normalize_http_url(request_body.get("start_url", ""))
    if not start_url:
        state = read_state()
        if state.get("ok"):
            start_url = _portal_start_url_from_state(state)

    params = {"timeout_sec": timeout_sec}
    if start_url:
        params["start_url"] = start_url
    daemon_result = send_control_command_with_params(
        "portal_viewer_open",
        params,
    )

    if not daemon_result.get("ok"):
        return jsonify({
            "ok": False,
            "error": daemon_result.get("error", "Failed to start portal viewer"),
            "portal_viewer": get_portal_viewer_state(),
            "daemon": daemon_result,
        }), 500

    portal_state = get_portal_viewer_state()
    if not portal_state.get("ready"):
        return jsonify({
            "ok": False,
            "error": (
                "Portal viewer service started, but noVNC is not reachable "
                f"(bind={portal_state.get('bind')}, probe={portal_state.get('probe_hosts')})"
            ),
            "portal_viewer": portal_state,
            "daemon": daemon_result,
        }), 500

    resolved_start_url = start_url or str(daemon_result.get("start_url", "") or "")
    return jsonify({
        "ok": True,
        "url": portal_state.get("url"),
        "start_url": resolved_start_url,
        "portal_viewer": portal_state,
        "daemon": daemon_result,
    }), 200


@app.route("/api/mode", methods=["GET"])
def api_mode_get():
    """GET /api/mode - Return current mode metadata."""
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    payload = get_mode_state()
    code = 200 if payload.get("ok") else 500
    return jsonify(payload), code


@app.route("/api/mode", methods=["POST"])
def api_mode_set():
    """POST /api/mode - Switch mode via control daemon."""
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403

    body = request.get_json(silent=True) or {}
    target_mode = str(body.get("mode", "")).strip().lower()
    if target_mode not in {"portal", "shield", "scapegoat"}:
        return jsonify({"ok": False, "error": "mode must be one of: portal, shield, scapegoat"}), 400

    requested_by = str(body.get("requested_by", "webui")).strip() or "webui"
    result = send_control_command_with_params(
        "mode_set",
        {"mode": target_mode, "requested_by": requested_by},
    )
    code = 200 if result.get("ok") else 500
    return jsonify(result), code


@app.route("/api/certs/azazel-webui-local-ca/meta")
def api_webui_ca_meta():
    """GET certificate metadata for client-side trust onboarding."""
    cert_path, checked_paths = _resolve_webui_ca_cert_path()
    if not cert_path.exists():
        return jsonify({
            "ok": False,
            "error": "CA certificate not found",
            "path": str(cert_path),
            "checked_paths": [str(p) for p in checked_paths],
        }), 404

    try:
        stat = cert_path.stat()
        return jsonify({
            "ok": True,
            "path": str(cert_path),
            "filename": cert_path.name,
            "sha256": _sha256_file(cert_path),
            "size_bytes": stat.st_size,
            "updated_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "download_url": "/api/certs/azazel-webui-local-ca.crt",
        })
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": f"Failed to inspect CA certificate: {e}",
        }), 500


@app.route("/api/certs/azazel-webui-local-ca.crt")
def api_webui_ca_download():
    """Download local CA certificate used by Caddy internal TLS."""
    cert_path, checked_paths = _resolve_webui_ca_cert_path()
    if not cert_path.exists():
        return jsonify({
            "ok": False,
            "error": "CA certificate not found",
            "path": str(cert_path),
            "checked_paths": [str(p) for p in checked_paths],
        }), 404

    return send_file(
        cert_path,
        mimetype="application/x-x509-ca-cert",
        as_attachment=True,
        download_name="azazel-webui-local-ca.crt",
        conditional=True,
    )


@app.route("/api/events/stream")
def api_events_stream():
    """GET /api/events/stream - SSE bridge for ntfy topic events."""
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 403

    def generate() -> Iterator[str]:
        out_q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=256)
        stop_event = threading.Event()
        worker = threading.Thread(
            target=_stream_ntfy_to_queue,
            args=(out_q, stop_event),
            daemon=True,
        )
        worker.start()
        last_keepalive = time.monotonic()

        # Initial stream event for UI diagnostics
        yield _sse_message("azazel", {
            "kind": "bridge_status",
            "status": "STREAM_CONNECTED",
            "timestamp": datetime.now().isoformat(),
            "source": "bridge",
            "dedup_key": "bridge:stream_connected",
            "severity": "info",
        })

        try:
            while not stop_event.is_set():
                try:
                    item = out_q.get(timeout=1.0)
                    yield _sse_message("azazel", item)
                except queue.Empty:
                    pass

                now = time.monotonic()
                if now - last_keepalive >= NTFY_SSE_KEEPALIVE_SEC:
                    # Safari対策: 定期keepaliveを送る
                    yield ": keepalive\n\n"
                    last_keepalive = now
        except GeneratorExit:
            pass
        finally:
            stop_event.set()
            worker.join(timeout=0.2)

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return Response(stream_with_context(generate()), headers=headers, mimetype="text/event-stream")


@app.route("/api/mattermost/status", methods=["GET"])
def api_mattermost_status():
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    reachable, ping_payload = _mattermost_ping()
    return jsonify(
        {
            "ok": True,
            "reachable": reachable,
            "base_url": MATTERMOST_BASE_URL,
            "open_url": MATTERMOST_OPEN_URL,
            "mode": _mattermost_mode(),
            "channel_id": MATTERMOST_CHANNEL_ID,
            "command_enabled": bool(MATTERMOST_COMMAND_TOKEN),
            "command_endpoint": "/api/mattermost/command",
            "ping": ping_payload,
        }
    )


@app.route("/api/ai/ask", methods=["POST"])
def api_ai_ask():
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    body = request.get_json(silent=True) or {}
    question = str(body.get("question") or "").strip()
    sender = str(body.get("sender") or "Azazel-Edge WebUI").strip() or "Azazel-Edge WebUI"
    source = str(body.get("source") or "webui").strip() or "webui"
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400
    result = _send_ai_manual_query(
        question=question,
        sender=sender,
        source=source,
        context=context,
    )
    code = 200 if result.get("ok") else 500
    return jsonify(result), code


@app.route("/api/runbooks", methods=["GET"])
def api_runbooks_list():
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    if runbook_list is None:
        return jsonify({"ok": False, "error": "runbook_registry_unavailable"}), 500
    return jsonify({"ok": True, "items": runbook_list()}), 200


@app.route("/api/runbooks/<runbook_id>", methods=["GET"])
def api_runbooks_get(runbook_id: str):
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    if runbook_get is None:
        return jsonify({"ok": False, "error": "runbook_registry_unavailable"}), 500
    try:
        return jsonify({"ok": True, "runbook": runbook_get(runbook_id)}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@app.route("/api/runbooks/<runbook_id>/review", methods=["GET"])
def api_runbooks_review(runbook_id: str):
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    if runbook_review_id is None:
        return jsonify({"ok": False, "error": "runbook_review_unavailable"}), 500
    context: Dict[str, Any] = {}
    question = str(request.args.get("question") or "").strip()
    audience = str(request.args.get("audience") or "").strip()
    risk_score = str(request.args.get("risk_score") or "").strip()
    if question:
        context["question"] = question
    if audience:
        context["audience"] = audience
    if risk_score:
        try:
            context["risk_score"] = int(risk_score)
        except ValueError:
            pass
    try:
        return jsonify(runbook_review_id(runbook_id, context=context)), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@app.route("/api/runbooks/execute", methods=["POST"])
def api_runbooks_execute():
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    if runbook_execute is None:
        return jsonify({"ok": False, "error": "runbook_registry_unavailable"}), 500
    body = request.get_json(silent=True) or {}
    runbook_id = str(body.get("runbook_id") or "").strip()
    args = body.get("args") if isinstance(body.get("args"), dict) else {}
    dry_run = bool(body.get("dry_run", True))
    if not runbook_id:
        return jsonify({"ok": False, "error": "runbook_id is required"}), 400
    try:
        result = runbook_execute(runbook_id, args=args, dry_run=dry_run)
        code = 200 if result.get("ok") else 500
        return jsonify(result), code
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/runbooks/propose", methods=["POST"])
def api_runbooks_propose():
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    if runbook_propose is None:
        return jsonify({"ok": False, "error": "runbook_review_unavailable"}), 500
    body = request.get_json(silent=True) or {}
    question = str(body.get("question") or "").strip()
    audience = str(body.get("audience") or "beginner").strip() or "beginner"
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    max_items = body.get("max_items", 3)
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400
    try:
        max_items_int = max(1, min(int(max_items), 10))
    except Exception:
        max_items_int = 3
    try:
        return jsonify(runbook_propose(question, audience=audience, max_items=max_items_int, context=context)), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/runbooks/act", methods=["POST"])
def api_runbooks_act():
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    if runbook_get is None or runbook_execute is None or runbook_review_id is None:
        return jsonify({"ok": False, "error": "runbook_registry_unavailable"}), 500
    body = request.get_json(silent=True) or {}
    runbook_id = str(body.get("runbook_id") or "").strip()
    action = str(body.get("action") or "preview").strip().lower()
    args = body.get("args") if isinstance(body.get("args"), dict) else {}
    actor = str(body.get("actor") or body.get("sender") or "webui-operator").strip() or "webui-operator"
    note = str(body.get("note") or "").strip()[:240]
    approved = bool(body.get("approved", False))
    if not runbook_id:
        return jsonify({"ok": False, "error": "runbook_id is required"}), 400
    if action not in {"preview", "approve", "execute"}:
        return jsonify({"ok": False, "error": "invalid_action"}), 400

    def _log_runbook_decision(ok: bool, error: str = "") -> None:
        _append_jsonl(
            RUNBOOK_EVENT_LOG,
            {
                "ts": time.time(),
                "actor": actor,
                "action": action,
                "runbook_id": runbook_id,
                "args": args,
                "approved": approved,
                "ok": ok,
                "error": error,
                "note": note,
            },
        )

    try:
        runbook = runbook_get(runbook_id)
        review = runbook_review_id(runbook_id, context=_review_context_from_request(body))
    except Exception as e:
        _log_runbook_decision(False, str(e))
        return jsonify({"ok": False, "error": str(e)}), 404

    effect = str(runbook.get("effect") or "")
    requires_approval = bool(runbook.get("requires_approval"))
    review_status = str(review.get("final_status") or "approved")
    if review_status == "rejected":
        _log_runbook_decision(False, "runbook_rejected_by_review")
        return jsonify({"ok": False, "error": "runbook_rejected_by_review", "review": review}), 409
    if action == "execute" and review_status == "amend_required":
        _log_runbook_decision(False, "runbook_requires_changes_before_execute")
        return jsonify({"ok": False, "error": "runbook_requires_changes_before_execute", "review": review}), 409
    if action == "approve" and review_status == "amend_required":
        _log_runbook_decision(False, "runbook_requires_changes_before_approve")
        return jsonify({"ok": False, "error": "runbook_requires_changes_before_approve", "review": review}), 409
    if action in {"approve", "execute"} and requires_approval and not approved:
        _log_runbook_decision(False, "approval_required")
        return jsonify({"ok": False, "error": "approval_required", "review": review}), 409

    result: Dict[str, Any]
    code = 200
    if action == "preview":
        try:
            result = runbook_execute(runbook_id, args=args, dry_run=True)
        except Exception as e:
            _log_runbook_decision(False, str(e))
            return jsonify({"ok": False, "error": str(e), "review": review}), 400
    elif action == "approve":
        result = {
            "ok": True,
            "runbook_id": runbook_id,
            "title": runbook.get("title"),
            "effect": effect,
            "approved": approved or not requires_approval,
            "executed": False,
            "steps": runbook.get("steps", []),
            "user_message_template": runbook.get("user_message_template", ""),
        }
    else:
        if effect not in {"read_only", "controlled_exec"}:
            _log_runbook_decision(False, "execute_supported_only_for_read_only")
            return jsonify({"ok": False, "error": "execute_supported_only_for_read_only_or_controlled_exec", "review": review}), 409
        try:
            result = runbook_execute(
                runbook_id,
                args=args,
                dry_run=False,
                approved=approved,
                allow_controlled_exec=(effect == "controlled_exec"),
            )
            code = 200 if result.get("ok") else 500
        except Exception as e:
            _log_runbook_decision(False, str(e))
            return jsonify({"ok": False, "error": str(e), "review": review}), 400

    result["review"] = review
    result["operator_action"] = action
    result["actor"] = actor
    result["note"] = note
    _append_jsonl(
        RUNBOOK_EVENT_LOG,
        {
            "ts": time.time(),
            "actor": actor,
            "action": action,
            "runbook_id": runbook_id,
            "args": args,
            "approved": approved,
            "review_status": review_status,
            "effect": effect,
            "ok": bool(result.get("ok")),
            "note": note,
        },
    )
    return jsonify(result), code


@app.route("/api/mattermost/message", methods=["POST"])
def api_mattermost_message():
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    body = request.get_json(silent=True) or {}
    message = str(body.get("message") or "").strip()
    sender = str(body.get("sender") or "Azazel-Edge WebUI").strip() or "Azazel-Edge WebUI"
    ask_ai = bool(body.get("ask_ai"))
    post_ai_reply = bool(body.get("post_ai_reply", True))
    send_to_mattermost = bool(body.get("send_to_mattermost", True))
    if not message:
        return jsonify({"ok": False, "error": "message is required"}), 400
    try:
        posted: Dict[str, Any] | None = None
        if send_to_mattermost:
            posted = _mattermost_send_message(message, sender=sender)
        ai_result: Dict[str, Any] | None = None
        ai_post: Dict[str, Any] | None = None
        runbook_proposals: Dict[str, Any] | None = None
        if ask_ai:
            ai_result = _send_ai_manual_query(
                question=message,
                sender=sender,
                source="mattermost_post",
                context={"channel_id": MATTERMOST_CHANNEL_ID},
            )
            if runbook_propose is not None:
                try:
                    runbook_proposals = runbook_propose(
                        message,
                        audience="operator",
                        max_items=3,
                        context={"question": message, "source": "mattermost_post"},
                    )
                except Exception:
                    runbook_proposals = None
            if ai_result.get("ok") and post_ai_reply and send_to_mattermost:
                reply_text = _format_mattermost_ai_response(ai_result, runbook_proposals)
                if reply_text:
                    ai_post = _mattermost_send_message(f"[AI]\n{reply_text}", sender="Azazel-Edge AI")
        return jsonify({"ok": True, "result": posted, "ai_result": ai_result, "runbook_proposals": runbook_proposals, "ai_post_result": ai_post}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/mattermost/command", methods=["POST"])
def api_mattermost_command():
    body = request.get_json(silent=True) or {}
    form = request.form or {}
    text = str(form.get("text") or body.get("text") or "").strip()
    sender = str(form.get("user_name") or body.get("user_name") or body.get("sender") or "mattermost-user").strip() or "mattermost-user"
    command_token = str(form.get("token") or body.get("token") or "").strip()
    channel_id = str(form.get("channel_id") or body.get("channel_id") or MATTERMOST_CHANNEL_ID).strip()
    if not _mattermost_command_allowed(command_token):
        return jsonify({"response_type": "ephemeral", "text": "Mattermost command token mismatch."}), 403
    if not text:
        return jsonify({"response_type": "ephemeral", "text": "Usage: /azops <question>"}), 200

    ai_result = _send_ai_manual_query(
        question=text,
        sender=sender,
        source="mattermost_command",
        context={"channel_id": channel_id, "page": "mattermost"},
    )
    proposals = None
    if runbook_propose is not None:
        try:
            proposals = runbook_propose(
                text,
                audience="operator",
                max_items=3,
                context={"question": text, "source": "mattermost_command"},
            )
        except Exception:
            proposals = None
    reply_text = _format_mattermost_ai_response(ai_result, proposals) or "No response."
    return jsonify({"response_type": "ephemeral", "text": reply_text}), 200


@app.route("/api/mattermost/messages", methods=["GET"])
def api_mattermost_messages():
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    limit = request.args.get("limit", MATTERMOST_FETCH_LIMIT)
    try:
        payload = _mattermost_fetch_messages(int(limit))
        return jsonify(payload), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/action", methods=["POST"])
def api_action_new():
    """POST /api/action - Execute control action (AI Coding Spec v1 format)"""
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    if not data or 'action' not in data:
        return jsonify({
            "status": "error",
            "message": "Missing action"
        }), 400
    
    action = data['action']
    if action not in ALLOWED_ACTIONS:
        return jsonify({
            "status": "error",
            "message": f"Forbidden action: {action}"
        }), 403
    
    result = send_control_command(action)
    
    # Convert to AI Coding Spec format
    if result.get("ok"):
        return jsonify({"status": "ok", "message": result.get("message", "Action executed")}), 200
    else:
        return jsonify({"status": "error", "message": result.get("error", "Unknown error")}), 500


@app.route("/api/action/<action>", methods=["POST"])
def api_action(action: str):
    """POST /api/action/<action> - Execute control action (legacy format)"""
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
    
    # Validate action
    if action not in ALLOWED_ACTIONS:
        return jsonify({
            "ok": False,
            "error": f"Unknown action: {action}"
        }), 404
    
    # Forward to Control Daemon
    result = send_control_command(action)
    
    if result.get("ok"):
        return jsonify(result), 200
    else:
        return jsonify(result), 500


@app.route("/api/wifi/scan", methods=["GET"])
def api_wifi_scan():
    """GET /api/wifi/scan - Scan for Wi-Fi access points"""
    # No token required (read-only operation)
    
    result = send_control_command_with_params("wifi_scan", {})
    
    if result.get("ok"):
        return jsonify(result), 200
    else:
        return jsonify(result), 500


@app.route("/api/wifi/connect", methods=["POST"])
def api_wifi_connect():
    """POST /api/wifi/connect - Connect to Wi-Fi AP"""
    if not verify_token():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    
    data = request.json
    if not data:
        return jsonify({"ok": False, "error": "Missing request body"}), 400
    
    # Extract parameters
    ssid = data.get("ssid")
    security = data.get("security", "UNKNOWN")
    passphrase = data.get("passphrase")
    saved = bool(data.get("saved", False))
    persist = bool(data.get("persist", False))
    
    # Validation
    if not ssid:
        return jsonify({"ok": False, "error": "Missing SSID"}), 400
    
    # For OPEN networks, discard passphrase if present
    if security == "OPEN":
        passphrase = None
        # OPEN AP profiles are always ephemeral to avoid stale remembered entries.
        persist = False
    elif not passphrase and not saved:
        # Non-OPEN network requires passphrase unless already saved
        return jsonify({"ok": False, "error": "Passphrase required for protected network"}), 400
    
    # NEVER log request body for this endpoint
    app.logger.info(f"Wi-Fi connect request: SSID={ssid}, Security={security} (passphrase sanitized)")
    
    # Forward to Control Daemon
    params = {
        "ssid": ssid,
        "security": security,
        "passphrase": passphrase,
        "persist": persist,
        "saved": saved
    }
    
    result = send_control_command_with_params("wifi_connect", params)
    
    if result.get("ok"):
        return jsonify(result), 200
    else:
        return jsonify(result), 500


@app.route("/static/<path:filename>")
def static_files(filename):
    """Serve static files"""
    return send_from_directory("static", filename)


@app.route("/health")
def health():
    """ヘルスチェック（認証不要）"""
    return jsonify({
        "status": "ok",
        "service": "azazel-edge-web",
        "timestamp": datetime.now().isoformat()
    })


# Error handlers

@app.errorhandler(404)
def not_found(e):
    return jsonify({"ok": False, "error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"ok": False, "error": "Server error"}), 500


if __name__ == "__main__":
    print(f"🛡️ Azazel-Edge Web UI starting...")
    print(f"   Bind: {BIND_HOST}:{BIND_PORT}")
    print(f"   State: {STATE_PATH}")
    print(f"   Control: {CONTROL_SOCKET}")
    
    if load_token():
        print(f"   🔒 Token authentication enabled")
    else:
        print(f"   ⚠️  WARNING: No token configured (open access)")
    
    app.run(
        host=BIND_HOST,
        port=BIND_PORT,
        debug=False,
        threaded=True
    )
