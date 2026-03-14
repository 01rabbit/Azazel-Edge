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
from functools import wraps
from collections import deque
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, Iterator, Tuple, List, Callable
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
    from azazel_edge.i18n import (
        normalize_lang,
        translate as i18n_translate,
        ui_catalog as i18n_ui_catalog,
        localize_runbook_user_message,
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
    from azazel_edge.triage import (
        TriageFlowEngine,
        TriageSessionStore,
        classify_intent_candidates,
        list_flows as triage_list_flows,
        select_noc_runbook_support,
        select_runbooks_for_diagnostic_state,
    )
    from azazel_edge.demo_overlay import (
        DEMO_OVERLAY_PATH,
        build_demo_overlay,
        clear_demo_overlay,
        purge_demo_artifacts,
        read_demo_overlay,
        write_demo_overlay,
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
    normalize_lang = lambda value=None: "ja"  # type: ignore
    i18n_translate = lambda key, lang=None, default=None, **kwargs: (default or key).format(**kwargs) if kwargs else (default or key)  # type: ignore
    i18n_ui_catalog = lambda lang=None: {}  # type: ignore
    localize_runbook_user_message = lambda runbook, lang=None, default="": str(runbook.get("user_message_template") or default)  # type: ignore
    runbook_execute = None
    runbook_get = None
    runbook_list = None
    runbook_propose = None
    runbook_review_id = None
    TriageFlowEngine = None  # type: ignore
    TriageSessionStore = None  # type: ignore
    classify_intent_candidates = None  # type: ignore
    triage_list_flows = None  # type: ignore
    select_noc_runbook_support = None  # type: ignore
    select_runbooks_for_diagnostic_state = None  # type: ignore
    DEMO_OVERLAY_PATH = Path("/run/azazel-edge/demo_overlay.json")
    build_demo_overlay = lambda result: {"active": True, "raw_result": result}  # type: ignore
    clear_demo_overlay = lambda: None  # type: ignore
    purge_demo_artifacts = lambda: None  # type: ignore
    read_demo_overlay = lambda: {}  # type: ignore
    write_demo_overlay = lambda payload: DEMO_OVERLAY_PATH  # type: ignore
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
AI_ADVISORY_PATH = Path(os.environ.get("AZAZEL_AI_ADVISORY", "/run/azazel-edge/ai_advisory.json"))
AI_METRICS_PATH = Path(os.environ.get("AZAZEL_AI_METRICS", "/run/azazel-edge/ai_metrics.json"))
AI_EVENT_LOG = Path(os.environ.get("AZAZEL_AI_EVENT_LOG", "/var/log/azazel-edge/ai-events.jsonl"))
AI_LLM_LOG = Path(os.environ.get("AZAZEL_AI_LLM_LOG", "/var/log/azazel-edge/ai-llm.jsonl"))
RUNBOOK_EVENT_LOG = Path(os.environ.get("AZAZEL_RUNBOOK_EVENT_LOG", "/var/log/azazel-edge/runbook-events.jsonl"))
TRIAGE_AUDIT_LOG = Path(os.environ.get("AZAZEL_TRIAGE_AUDIT_PATH", "/var/log/azazel-edge/triage-audit.jsonl"))
TRIAGE_AUDIT_FALLBACK_LOG = Path("/tmp/azazel-edge-triage-audit.jsonl")
TRIAGE_SESSION_DIR = Path(os.environ.get("AZAZEL_TRIAGE_SESSION_DIR", "/run/azazel-edge/triage-sessions"))
TOKEN_FILE = web_token_candidates()[0]
IMAGES_DIR = Path(__file__).resolve().parents[1] / "images"
LOCAL_DEMO_RUNNER = PROJECT_ROOT / "bin" / "azazel-edge-demo"
OPT_DEMO_RUNNER = Path("/opt/azazel-edge/bin/azazel-edge-demo")
USR_LOCAL_DEMO_RUNNER = Path("/usr/local/bin/azazel-edge-demo")
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
MATTERMOST_COMMAND_TOKEN_FILE = Path(
    str(os.environ.get("AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE", "/etc/azazel-edge/mattermost-command-token")).strip()
    or "/etc/azazel-edge/mattermost-command-token"
)
MATTERMOST_COMMAND_ALIASES = [
    item.strip()
    for item in str(os.environ.get("AZAZEL_MATTERMOST_COMMAND_ALIASES", "azops")).split(",")
    if item.strip()
]
MATTERMOST_COMMAND_PRIMARY_TRIGGER = str(os.environ.get("AZAZEL_MATTERMOST_COMMAND_TRIGGER", "mio")).strip() or "mio"


def _request_lang() -> str:
    query_lang = request.args.get("lang") if has_request_context() else ""
    header_lang = request.headers.get("X-AZAZEL-LANG") if has_request_context() else ""
    cookie_lang = request.cookies.get("azazel_lang") if has_request_context() else ""
    return normalize_lang(query_lang or header_lang or cookie_lang or "ja")


def _tr(key: str, default: str | None = None, **kwargs: Any) -> str:
    return i18n_translate(key, lang=_request_lang(), default=default, **kwargs)


@app.context_processor
def _inject_i18n() -> Dict[str, Any]:
    lang = _request_lang()
    return {
        "ui_lang": lang,
        "ui_catalog": i18n_ui_catalog(lang),
        "tr": lambda key, default=None, **kwargs: i18n_translate(key, lang=lang, default=default, **kwargs),
    }


@app.after_request
def _apply_language_headers(response: Response) -> Response:
    lang = _request_lang()
    response.headers["Content-Language"] = lang
    response.set_cookie("azazel_lang", lang, max_age=31536000, samesite="Lax")
    return response


def _read_secret_file(path: Path) -> str:
    try:
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""
    return ""


def _read_mattermost_command_tokens() -> List[str]:
    tokens: List[str] = []
    primary = _read_secret_file(MATTERMOST_COMMAND_TOKEN_FILE)
    if primary:
        tokens.append(primary)
    for extra in sorted(MATTERMOST_COMMAND_TOKEN_FILE.parent.glob(f"{MATTERMOST_COMMAND_TOKEN_FILE.name}.*")):
        value = _read_secret_file(extra)
        if value and value not in tokens:
            tokens.append(value)
    env_token = str(os.environ.get("AZAZEL_MATTERMOST_COMMAND_TOKEN", "")).strip()
    if env_token and env_token not in tokens:
        tokens.append(env_token)
    return tokens


MATTERMOST_COMMAND_TOKENS = _read_mattermost_command_tokens()
MATTERMOST_TIMEOUT_SEC = float(os.environ.get("AZAZEL_MATTERMOST_TIMEOUT_SEC", "8"))
MATTERMOST_FETCH_LIMIT = int(os.environ.get("AZAZEL_MATTERMOST_FETCH_LIMIT", "40"))
DASHBOARD_SNAPSHOT_STALE_SEC = float(os.environ.get("AZAZEL_DASHBOARD_SNAPSHOT_STALE_SEC", "30"))
DASHBOARD_AI_STALE_SEC = float(os.environ.get("AZAZEL_DASHBOARD_AI_STALE_SEC", "120"))
DASHBOARD_EVENT_STALE_SEC = float(os.environ.get("AZAZEL_DASHBOARD_EVENT_STALE_SEC", "300"))
DASHBOARD_ASSIST_STALE_SEC = float(os.environ.get("AZAZEL_DASHBOARD_ASSIST_STALE_SEC", "90"))
_TRIAGE_STORE = TriageSessionStore(base_dir=TRIAGE_SESSION_DIR) if TriageSessionStore is not None else None
_TRIAGE_ENGINE = TriageFlowEngine(store=_TRIAGE_STORE) if TriageFlowEngine is not None and _TRIAGE_STORE is not None else None
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
    try:
        if TOKEN_FILE.exists():
            return TOKEN_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    return None


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _read_json_file(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            data = _parse_json_dict_lenient(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        return {}
    return {}


def _parse_json_dict_lenient(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        pass
    try:
        decoder = json.JSONDecoder()
        parsed, _idx = decoder.raw_decode(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _tail_jsonl(path: Path, limit: int = 20) -> List[Dict[str, Any]]:
    rows: deque[Dict[str, Any]] = deque(maxlen=max(1, int(limit)))
    try:
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception:
                    continue
                if isinstance(payload, dict):
                    rows.append(payload)
    except Exception:
        return []
    return list(rows)


def _tail_first_existing_jsonl(paths: List[Path], limit: int = 20) -> List[Dict[str, Any]]:
    for path in paths:
        rows = _tail_jsonl(path, limit=limit)
        if rows:
            return rows
    return []


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except Exception:
        return default


def _iso_from_epoch(value: Any) -> str:
    try:
        epoch = float(value)
        if epoch > 0:
            return datetime.fromtimestamp(epoch).isoformat()
    except Exception:
        pass
    return ""


def _age_seconds(value: Any, now_epoch: float | None = None) -> Optional[float]:
    try:
        epoch = float(value)
    except Exception:
        return None
    if epoch <= 0:
        return None
    now = time.time() if now_epoch is None else float(now_epoch)
    age = now - epoch
    return age if age >= 0 else 0.0


def _latest_item(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    return items[-1] if items else {}


def _latest_ai_context(advisory: Dict[str, Any], llm_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    result = {
        "answer": "",
        "user_message": "",
        "runbook_id": "",
        "operator_note": "",
        "question": "",
        "status": "",
        "model": "",
        "review": {},
        "ts": 0.0,
        "source": "",
    }
    latest = _latest_item(llm_rows)
    response = latest.get("response") if isinstance(latest.get("response"), dict) else {}
    if response:
        result.update(
            {
                "answer": str(response.get("answer") or response.get("summary") or ""),
                "user_message": str(response.get("user_message") or ""),
                "runbook_id": str(response.get("runbook_id") or ""),
                "operator_note": str(response.get("operator_note") or ""),
                "question": str(latest.get("question") or ""),
                "status": str(response.get("status") or latest.get("kind") or ""),
                "model": str(response.get("model") or latest.get("model") or ""),
                "review": response.get("runbook_review") if isinstance(response.get("runbook_review"), dict) else {},
                "ts": _as_float(latest.get("ts"), 0.0),
                "source": str(latest.get("source") or ""),
            }
        )
    if not advisory:
        return result
    if not result["runbook_id"]:
        ops = advisory.get("ops_coach") if isinstance(advisory.get("ops_coach"), dict) else {}
        result["runbook_id"] = str(ops.get("runbook_id") or "")
    if not result["answer"]:
        result["answer"] = str(
            advisory.get("recommendation")
            or (advisory.get("ops_coach") or {}).get("summary")
            or ""
        )
    if not result["operator_note"]:
        result["operator_note"] = str((advisory.get("ops_coach") or {}).get("operator_note") or "")
    return result


def _blank_ai_context() -> Dict[str, Any]:
    return {
        "answer": "",
        "user_message": "",
        "runbook_id": "",
        "operator_note": "",
        "question": "",
        "status": "idle",
        "model": "",
        "review": {},
        "ts": 0.0,
        "source": "",
    }


def _demo_overlay_is_active() -> bool:
    payload = read_demo_overlay()
    return bool(payload.get("active")) if isinstance(payload, dict) else False


def _trigger_demo_clear_side_effects() -> None:
    # EPD keeps the last rendered frame until refreshed, so clear should force
    # one live redraw instead of waiting for the timer. Call the refresh script
    # directly instead of systemctl to avoid polkit / interactive auth failures.
    # Run it synchronously with a realistic timeout so the hardware actually
    # leaves demo mode before the request returns.
    commands = [
        ["/usr/local/bin/azazel-edge-epd-refresh"],
    ]
    for cmd in commands:
        try:
            subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=45,
            )
        except Exception:
            continue


def _dashboard_visible_ai_context(state: Dict[str, Any], advisory: Dict[str, Any], llm_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    latest_ai = _latest_ai_context(advisory, llm_rows)
    ai_age = _age_seconds(latest_ai.get("ts"))
    if ai_age is not None and ai_age > DASHBOARD_ASSIST_STALE_SEC:
        return _blank_ai_context()
    user_state = str(state.get("user_state") or "").upper()
    internal = state.get("internal") if isinstance(state.get("internal"), dict) else {}
    suspicion = _as_int(internal.get("suspicion"), 0)
    latest_source = str(latest_ai.get("source") or "").lower()
    if latest_source == "dashboard_demo" and not _demo_overlay_is_active():
        return _blank_ai_context()
    if latest_source == "dashboard" and user_state == "SAFE" and suspicion <= 0:
        return _blank_ai_context()
    return latest_ai


def _append_unique(items: List[str], value: str) -> None:
    text = str(value or "").strip()
    if text and text not in items:
        items.append(text)


def _dashboard_action_guidance(
    state: Dict[str, Any],
    advisory: Dict[str, Any],
    latest_ai: Dict[str, Any],
    suggested_runbook: Dict[str, Any],
    noc_runbook_support: Dict[str, Any] | None = None,
) -> Dict[str, List[str]]:
    network_health = state.get("network_health") if isinstance(state.get("network_health"), dict) else {}
    monitoring = state.get("monitoring") if isinstance(state.get("monitoring"), dict) else {}
    internal = state.get("internal") if isinstance(state.get("internal"), dict) else {}
    user_state = str(state.get("user_state") or "").upper()
    state_name = str(internal.get("state_name") or "").upper()
    suspicion = _as_int(internal.get("suspicion"), 0)
    signals = network_health.get("signals") if isinstance(network_health.get("signals"), list) else []
    internet_check = str((state.get("connection") or {}).get("internet_check") or "").upper() if isinstance(state.get("connection"), dict) else ""
    critical = _as_int(state.get("suricata_critical"), 0)
    warning = _as_int(state.get("suricata_warning"), 0)
    support = noc_runbook_support if isinstance(noc_runbook_support, dict) else {}

    why_now: List[str] = []
    do_next: List[str] = []
    do_not_do: List[str] = []
    escalate_if: List[str] = []

    if user_state == "SAFE" and suspicion <= 0 and not signals:
        _append_unique(why_now, _tr("api.no_active_issues", default="No active issues detected."))
    else:
        _append_unique(why_now, f"Current state is {user_state or '-'} / {state_name or '-'} with suspicion {suspicion}.")
    if signals:
        _append_unique(why_now, f"Network health signals require confirmation: {', '.join(str(x) for x in signals)}.")
    if critical > 0:
        _append_unique(why_now, f"{critical} direct critical alert(s) are active.")
    elif warning > 0:
        _append_unique(why_now, f"{warning} warning alert(s) remain under observation.")
    if suggested_runbook.get("title"):
        _append_unique(why_now, f"Recommended runbook is {suggested_runbook['title']}.")
    elif latest_ai.get("answer"):
        _append_unique(why_now, "Latest M.I.O. assist is advisory only and no runbook is currently selected.")
    if support.get("why_this_runbook"):
        _append_unique(why_now, str(support.get("why_this_runbook")))

    recommendation = str(state.get("recommendation") or advisory.get("recommendation") or "").strip()
    _append_unique(do_next, recommendation or _tr("api.keep_monitoring", default="Keep monitoring the current state."))
    if suggested_runbook.get("title"):
        _append_unique(do_next, f"Open {suggested_runbook['title']} and follow the read-only checks first.")
    for step in suggested_runbook.get("steps", []):
        _append_unique(do_next, str(step))
    for check in support.get("operator_checks", []) if isinstance(support.get("operator_checks"), list) else []:
        _append_unique(do_next, str(check))
    if not do_next:
        _append_unique(do_next, _tr("api.keep_monitoring", default="Keep monitoring the current state."))

    if suggested_runbook.get("effect") == "controlled_exec":
        _append_unique(do_not_do, "Do not execute the runbook before approval is granted.")
    if user_state == "SAFE":
        _append_unique(do_not_do, "Do not contain, release, or restart services without fresh evidence.")
    if internet_check == "OK":
        _append_unique(do_not_do, "Do not assume uplink failure while internet reachability is still OK.")
    if not do_not_do:
        _append_unique(do_not_do, "Do not change gateway mode until the current signal is confirmed.")

    if critical > 0:
        _append_unique(escalate_if, "Escalate immediately if direct critical alerts continue or increase.")
    if internet_check not in ("", "OK", "N/A", "UNKNOWN"):
        _append_unique(escalate_if, "Escalate if internet reachability remains degraded after the first check.")
    if any(str(monitoring.get(name) or "").upper() == "OFF" for name in ("suricata", "opencanary", "ntfy")):
        _append_unique(escalate_if, "Escalate if a core monitoring service remains OFF after local verification.")
    if user_state not in ("SAFE", ""):
        _append_unique(escalate_if, "Escalate if the state does not return to SAFE after the recommended checks.")
    if support.get("escalation_hint"):
        _append_unique(escalate_if, str(support.get("escalation_hint")))
    if not escalate_if:
        _append_unique(escalate_if, "Escalate if the state leaves SAFE or new alerts appear.")

    return {
        "why_now": why_now[:4],
        "do_next": do_next[:4],
        "do_not_do": do_not_do[:4],
        "escalate_if": escalate_if[:4],
    }


def _runbook_brief(runbook_id: str, lang: str | None = None) -> Dict[str, Any]:
    if not runbook_id or runbook_get is None:
        return {}
    try:
        runbook = runbook_get(runbook_id, lang=lang)
    except Exception:
        return {}
    steps = runbook.get("steps") if isinstance(runbook.get("steps"), list) else []
    return {
        "id": str(runbook.get("id") or runbook_id),
        "title": str(runbook.get("title") or runbook_id),
        "effect": str(runbook.get("effect") or ""),
        "requires_approval": bool(runbook.get("requires_approval")),
        "steps": [str(item) for item in steps[:3]],
        "user_message_template": localize_runbook_user_message(runbook, lang=lang),
    }


def _dashboard_noc_runbook_support(state: Dict[str, Any], lang: str) -> Dict[str, Any]:
    if select_noc_runbook_support is None:
        return {}
    network_health = state.get("network_health") if isinstance(state.get("network_health"), dict) else {}
    noc_capacity = state.get("noc_capacity") if isinstance(state.get("noc_capacity"), dict) else {}
    noc_client_inventory = state.get("noc_client_inventory") if isinstance(state.get("noc_client_inventory"), dict) else {}
    noc_service_assurance = state.get("noc_service_assurance") if isinstance(state.get("noc_service_assurance"), dict) else {}
    noc_resolution_assurance = state.get("noc_resolution_assurance") if isinstance(state.get("noc_resolution_assurance"), dict) else {}
    noc_blast_radius = state.get("noc_blast_radius") if isinstance(state.get("noc_blast_radius"), dict) else {}
    noc_config_drift = state.get("noc_config_drift") if isinstance(state.get("noc_config_drift"), dict) else {}
    noc_incident_summary = state.get("noc_incident_summary") if isinstance(state.get("noc_incident_summary"), dict) else {}
    return select_noc_runbook_support(
        {
            "summary": {
                "status": str(network_health.get("status") or "unknown"),
                "blast_radius": noc_blast_radius,
                "incident_summary": noc_incident_summary,
            },
            "path_health": {
                "status": str(network_health.get("status") or "unknown"),
                "signals": network_health.get("signals") if isinstance(network_health.get("signals"), list) else [],
            },
            "capacity": noc_capacity,
            "client_inventory": noc_client_inventory,
            "service_health": noc_service_assurance,
            "resolution_health": noc_resolution_assurance,
            "config_drift": noc_config_drift,
            "affected_scope": noc_blast_radius,
            "incident_summary": noc_incident_summary,
        },
        audience="professional",
        lang=lang,
        context={"source": "dashboard"},
        source="dashboard",
    )


def _normalize_alert_event(item: Dict[str, Any]) -> Dict[str, Any]:
    advisory = item.get("advisory") if isinstance(item.get("advisory"), dict) else {}
    event = item.get("event") if isinstance(item.get("event"), dict) else {}
    normalized = event.get("normalized") if isinstance(event.get("normalized"), dict) else {}
    ts = _as_float(advisory.get("ts") or item.get("ts"), 0.0)
    return {
        "ts": ts,
        "ts_iso": _iso_from_epoch(ts),
        "risk_score": _as_int(advisory.get("risk_score"), 0),
        "risk_level": str(advisory.get("risk_level") or ""),
        "state_name": str(advisory.get("state_name") or ""),
        "user_state": str(advisory.get("user_state") or ""),
        "sid": _as_int(advisory.get("suricata_sid") or normalized.get("sid"), 0),
        "severity": _as_int(advisory.get("suricata_severity") or normalized.get("severity"), 0),
        "attack_type": str(advisory.get("attack_type") or normalized.get("attack_type") or ""),
        "src_ip": str(advisory.get("src_ip") or normalized.get("src_ip") or ""),
        "dst_ip": str(advisory.get("dst_ip") or normalized.get("dst_ip") or ""),
        "recommendation": str(advisory.get("recommendation") or ""),
    }


def _normalize_ai_activity(item: Dict[str, Any]) -> Dict[str, Any]:
    response = item.get("response") if isinstance(item.get("response"), dict) else {}
    ts = _as_float(item.get("ts"), 0.0)
    return {
        "ts": ts,
        "ts_iso": _iso_from_epoch(ts),
        "kind": str(item.get("kind") or ""),
        "source": str(item.get("source") or ""),
        "sender": str(item.get("sender") or ""),
        "question": str(item.get("question") or ""),
        "model": str(item.get("model") or response.get("model") or ""),
        "status": str(response.get("status") or ""),
        "answer": str(response.get("answer") or response.get("summary") or ""),
        "runbook_id": str(response.get("runbook_id") or ""),
        "user_message": str(response.get("user_message") or ""),
        "latency_ms": _as_int(item.get("latency_ms") or response.get("latency_ms"), 0),
    }


def _normalize_runbook_event(item: Dict[str, Any]) -> Dict[str, Any]:
    ts = _as_float(item.get("ts"), 0.0)
    return {
        "ts": ts,
        "ts_iso": _iso_from_epoch(ts),
        "actor": str(item.get("actor") or ""),
        "action": str(item.get("action") or ""),
        "runbook_id": str(item.get("runbook_id") or ""),
        "approved": bool(item.get("approved")),
        "ok": bool(item.get("ok")),
        "error": str(item.get("error") or ""),
        "review_status": str(item.get("review_status") or ""),
        "effect": str(item.get("effect") or ""),
        "note": str(item.get("note") or ""),
    }


def _recent_mode_changes(mode_runtime: Dict[str, Any]) -> List[Dict[str, Any]]:
    mode = mode_runtime.get("mode") if isinstance(mode_runtime.get("mode"), dict) else {}
    if not mode:
        return []
    return [
        {
            "current_mode": str(mode.get("current_mode") or ""),
            "last_change": str(mode.get("last_change") or ""),
            "requested_by": str(mode.get("requested_by") or ""),
            "source": str(mode_runtime.get("source") or ""),
        }
    ]


def _dashboard_summary_payload(state: Dict[str, Any], metrics: Dict[str, Any], advisory: Dict[str, Any]) -> Dict[str, Any]:
    lang = _request_lang()
    monitoring = get_monitoring_state()
    mode_runtime = get_mode_state()
    mode = mode_runtime.get("mode") if isinstance(mode_runtime.get("mode"), dict) else {}
    connection = state.get("connection") if isinstance(state.get("connection"), dict) else {}
    network_health = state.get("network_health") if isinstance(state.get("network_health"), dict) else {}
    noc_capacity = state.get("noc_capacity") if isinstance(state.get("noc_capacity"), dict) else {}
    noc_client_inventory = state.get("noc_client_inventory") if isinstance(state.get("noc_client_inventory"), dict) else {}
    internal = state.get("internal") if isinstance(state.get("internal"), dict) else {}
    attack = state.get("attack") if isinstance(state.get("attack"), dict) else {}
    now_epoch = time.time()
    snapshot_age = _age_seconds(state.get("snapshot_epoch"), now_epoch=now_epoch)
    ai_age = _age_seconds(metrics.get("last_update_ts"), now_epoch=now_epoch)
    stale_warning = bool(
        (snapshot_age is not None and snapshot_age > DASHBOARD_SNAPSHOT_STALE_SEC)
        or (ai_age is not None and ai_age > DASHBOARD_AI_STALE_SEC)
    )
    service_summary = {
        "suricata": monitoring.get("suricata", "UNKNOWN"),
        "opencanary": monitoring.get("opencanary", "UNKNOWN"),
        "ntfy": monitoring.get("ntfy", "UNKNOWN"),
        "ai_agent": "ON" if _service_active("azazel-edge-ai-agent") else "OFF",
        "web": "ON" if _service_active("azazel-edge-web") else "OFF",
    }
    attack_type = str(advisory.get("attack_type") or "").strip()
    top_src = str(advisory.get("src_ip") or "").strip()
    top_dst = str(advisory.get("dst_ip") or "").strip()
    top_sid = _as_int(advisory.get("suricata_sid"), 0)
    top_severity = _as_int(advisory.get("suricata_severity"), 0)
    suspicion = _as_int(internal.get("suspicion"), 0)
    if suspicion >= 85 or _as_int(state.get("suricata_critical"), 0) > 0:
        threat_level = "critical"
    elif suspicion >= 60 or _as_int(state.get("suricata_warning"), 0) > 0:
        threat_level = "elevated"
    elif suspicion > 0:
        threat_level = "watch"
    else:
        threat_level = "quiet"
    signals = network_health.get("signals") if isinstance(network_health.get("signals"), list) else []
    decision_pipeline = state.get("decision_pipeline") if isinstance(state.get("decision_pipeline"), dict) else {}
    if not decision_pipeline and isinstance(advisory.get("decision_pipeline"), dict):
        decision_pipeline = advisory.get("decision_pipeline")
    first_pass = decision_pipeline.get("first_pass") if isinstance(decision_pipeline.get("first_pass"), dict) else {}
    second_pass = decision_pipeline.get("second_pass") if isinstance(decision_pipeline.get("second_pass"), dict) else {}
    second_pass_detail = state.get("second_pass") if isinstance(state.get("second_pass"), dict) else {}
    if not second_pass_detail and isinstance(advisory.get("second_pass"), dict):
        second_pass_detail = advisory.get("second_pass")
    second_pass_soc = second_pass_detail.get("soc") if isinstance(second_pass_detail.get("soc"), dict) else {}
    second_pass_status = str(second_pass.get("status") or second_pass_detail.get("status") or "pending")
    if bool(attack.get("stale_advisory_expired")):
        attack_type = ""
        top_src = ""
        top_dst = ""
        top_sid = 0
        top_severity = 0
    path_scope = ("全 uplink 利用者" if lang == "ja" else "all uplink clients") if str(connection.get("internet_check") or "").upper() == "FAIL" else (
        ("DNS 影響利用者" if lang == "ja" else "dns-affected clients") if _as_int(network_health.get("dns_mismatch"), 0) > 0 else ("広域影響なし" if lang == "ja" else "no broad impact indicated")
    )
    top_sources = noc_capacity.get("top_sources") if isinstance(noc_capacity.get("top_sources"), list) else []
    top_talker = "-"
    if top_sources and isinstance(top_sources[0], dict):
        top_talker = str(top_sources[0].get("src_ip") or top_sources[0].get("id") or "-")
    noc_service_assurance = state.get("noc_service_assurance") if isinstance(state.get("noc_service_assurance"), dict) else {}
    noc_resolution_assurance = state.get("noc_resolution_assurance") if isinstance(state.get("noc_resolution_assurance"), dict) else {}
    noc_blast_radius = state.get("noc_blast_radius") if isinstance(state.get("noc_blast_radius"), dict) else {}
    noc_config_drift = state.get("noc_config_drift") if isinstance(state.get("noc_config_drift"), dict) else {}
    noc_incident_summary = state.get("noc_incident_summary") if isinstance(state.get("noc_incident_summary"), dict) else {}
    soc_attack_candidates = (
        second_pass_soc.get("attack_candidates")
        if isinstance(second_pass_soc.get("attack_candidates"), list)
        else ([attack_type] if attack_type else [])
    )
    soc_ti_matches = second_pass_soc.get("ti_matches") if isinstance(second_pass_soc.get("ti_matches"), list) else []
    soc_sigma_hits = second_pass_soc.get("sigma_hits") if isinstance(second_pass_soc.get("sigma_hits"), list) else []
    soc_yara_hits = second_pass_soc.get("yara_hits") if isinstance(second_pass_soc.get("yara_hits"), list) else []
    soc_correlation = second_pass_soc.get("correlation") if isinstance(second_pass_soc.get("correlation"), dict) else {}
    soc_visibility = second_pass_soc.get("security_visibility_state") if isinstance(second_pass_soc.get("security_visibility_state"), dict) else {}
    soc_suppression = second_pass_soc.get("suppression_exception_state") if isinstance(second_pass_soc.get("suppression_exception_state"), dict) else {}
    soc_criticality = second_pass_soc.get("asset_target_criticality") if isinstance(second_pass_soc.get("asset_target_criticality"), dict) else {}
    soc_exposure = second_pass_soc.get("exposure_change_state") if isinstance(second_pass_soc.get("exposure_change_state"), dict) else {}
    soc_confidence_provenance = second_pass_soc.get("confidence_provenance") if isinstance(second_pass_soc.get("confidence_provenance"), dict) else {}
    soc_sequence = second_pass_soc.get("behavior_sequence_state") if isinstance(second_pass_soc.get("behavior_sequence_state"), dict) else {}
    soc_triage = second_pass_soc.get("triage_priority_state") if isinstance(second_pass_soc.get("triage_priority_state"), dict) else {}
    soc_incident = second_pass_soc.get("incident_campaign_state") if isinstance(second_pass_soc.get("incident_campaign_state"), dict) else {}
    soc_entity = second_pass_soc.get("entity_risk_state") if isinstance(second_pass_soc.get("entity_risk_state"), dict) else {}
    soc_status_from_second_pass = str(second_pass_soc.get("status") or "").lower()
    if soc_status_from_second_pass in {"critical", "high"}:
        threat_level = soc_status_from_second_pass if soc_status_from_second_pass != "high" else "elevated"

    return {
        "ok": True,
        "risk": {
            "user_state": str(state.get("user_state") or ""),
            "state_name": str(internal.get("state_name") or ""),
            "suspicion": suspicion,
            "recommendation": str(state.get("recommendation") or advisory.get("recommendation") or ""),
            "suricata_critical": _as_int(state.get("suricata_critical"), 0),
            "suricata_warning": _as_int(state.get("suricata_warning"), 0),
        },
        "mode": {
            "current_mode": str(mode.get("current_mode") or "shield"),
            "last_change": str(mode.get("last_change") or ""),
            "requested_by": str(mode.get("requested_by") or ""),
        },
        "uplink": {
            "ssid": str(state.get("ssid") or ""),
            "up_if": str(state.get("up_if") or ""),
            "up_ip": str(state.get("up_ip") or ""),
            "gateway": str(state.get("gateway_ip") or ""),
            "uplink_type": str(connection.get("uplink_type") or ""),
            "internet_check": str(connection.get("internet_check") or ""),
        },
        "gateway": str(state.get("gateway_ip") or ""),
        "service_health_summary": service_summary,
        "current_recommendation": str(state.get("recommendation") or advisory.get("recommendation") or ""),
        "command_strip": {
            "current_mode": str(mode.get("current_mode") or "shield"),
            "current_risk": str(state.get("user_state") or ""),
            "current_uplink": str(state.get("up_if") or ""),
            "internet_reachability": str(connection.get("internet_check") or ""),
            "direct_critical_count": _as_int(state.get("suricata_critical"), 0),
            "deferred_count": _as_int(metrics.get("deferred_count"), 0),
            "stale_warning": stale_warning,
            "ask_mio_url": "/ops-comm",
            "mattermost_url": MATTERMOST_OPEN_URL,
        },
        "situation_board": {
            "threat_posture": {
                "recommendation": str(state.get("recommendation") or advisory.get("recommendation") or ""),
                "confidence": _as_float((advisory.get("ops_coach") or {}).get("confidence"), 0.0),
                "last_alert": _iso_from_epoch(advisory.get("ts")),
                "llm_status": str((state.get("llm") or {}).get("status") or ""),
            },
            "network_health": {
                "status": str(network_health.get("status") or ""),
                "uplink": str(state.get("up_if") or ""),
                "gateway": str(state.get("gateway_ip") or ""),
                "dns_mismatch": _as_int(network_health.get("dns_mismatch"), 0),
                "captive_portal": str(connection.get("captive_portal") or ""),
                "internet_check": str(connection.get("internet_check") or ""),
                "signals": network_health.get("signals") if isinstance(network_health.get("signals"), list) else [],
            },
            "service_health": service_summary,
        },
        "soc_focus": {
            "threat_level": threat_level,
            "attack_type": attack_type or ("現在の攻撃種別なし" if lang == "ja" else "No current attack type"),
            "top_source": top_src or "-",
            "top_destination": top_dst or "-",
            "top_sid": top_sid or "-",
            "top_severity": top_severity or "-",
            "critical_count": _as_int(state.get("suricata_critical"), 0),
            "warning_count": _as_int(state.get("suricata_warning"), 0),
            "confidence_signal": (
                f"suspicion={suspicion}"
                + (
                    f" | confidence={_as_int(soc_confidence_provenance.get('adjusted_score'), 0)}"
                    if isinstance(soc_confidence_provenance, dict) and soc_confidence_provenance
                    else ""
                )
            ),
            "attack_candidates": soc_attack_candidates,
            "sigma_hits": soc_sigma_hits,
            "yara_hits": soc_yara_hits,
            "ti_matches": soc_ti_matches,
            "correlation": {
                "status": str(soc_correlation.get("status") or ("present" if attack_type or top_src or top_dst else "none")),
                "reasons": (
                    [str(item) for item in soc_correlation.get("reasons", []) if str(item)]
                    if isinstance(soc_correlation, dict) and isinstance(soc_correlation.get("reasons"), list)
                    else [
                        item for item in [
                            f"src={top_src}" if top_src else "",
                            f"dst={top_dst}" if top_dst else "",
                            f"sid={top_sid}" if top_sid else "",
                        ] if item
                    ][:3]
                ),
            },
            "visibility": {
                "status": str(soc_visibility.get("status") or second_pass_soc.get("visibility_status") or "unknown"),
                "missing_sources": soc_visibility.get("missing_sources") if isinstance(soc_visibility.get("missing_sources"), list) else [],
                "stale_sources": soc_visibility.get("stale_sources") if isinstance(soc_visibility.get("stale_sources"), list) else [],
            },
            "suppression": {
                "status": str(soc_suppression.get("status") or "normal"),
                "suppressed_count": _as_int(soc_suppression.get("suppressed_count"), _as_int(second_pass_soc.get("suppressed_count"), 0)),
                "exception_count": _as_int(soc_suppression.get("exception_count"), 0),
            },
            "criticality": {
                "status": str(soc_criticality.get("status") or "unknown"),
                "critical_target_count": _as_int(soc_criticality.get("critical_target_count"), 0),
            },
            "exposure_change": {
                "status": str(soc_exposure.get("status") or "stable"),
                "new_external_destinations": soc_exposure.get("new_external_destinations") if isinstance(soc_exposure.get("new_external_destinations"), list) else [],
                "new_service_targets": soc_exposure.get("new_service_targets") if isinstance(soc_exposure.get("new_service_targets"), list) else [],
            },
            "confidence_provenance": {
                "status": str(soc_confidence_provenance.get("status") or "unknown"),
                "adjusted_score": _as_int(soc_confidence_provenance.get("adjusted_score"), 0),
                "supports": soc_confidence_provenance.get("supports") if isinstance(soc_confidence_provenance.get("supports"), list) else [],
                "weakens": soc_confidence_provenance.get("weakens") if isinstance(soc_confidence_provenance.get("weakens"), list) else [],
            },
            "behavior_sequence": {
                "status": str(soc_sequence.get("status") or "none"),
                "stage_sequence": soc_sequence.get("stage_sequence") if isinstance(soc_sequence.get("stage_sequence"), list) else [],
                "chain_hits": soc_sequence.get("chain_hits") if isinstance(soc_sequence.get("chain_hits"), list) else [],
            },
            "triage_priority": {
                "status": str(soc_triage.get("status") or second_pass_soc.get("triage_status") or "idle"),
                "score": _as_int(soc_triage.get("score"), 0),
                "now": soc_triage.get("now") if isinstance(soc_triage.get("now"), list) else [],
                "watch": soc_triage.get("watch") if isinstance(soc_triage.get("watch"), list) else [],
                "backlog": soc_triage.get("backlog") if isinstance(soc_triage.get("backlog"), list) else [],
                "top_priority_ids": soc_triage.get("top_priority_ids") if isinstance(soc_triage.get("top_priority_ids"), list) else [],
            },
            "incident_campaign": {
                "status": str(soc_incident.get("status") or "none"),
                "incident_count": _as_int(soc_incident.get("incident_count"), _as_int(second_pass_soc.get("incident_count"), 0)),
                "active_count": _as_int(soc_incident.get("active_count"), 0),
                "top_incidents": soc_incident.get("top_incidents") if isinstance(soc_incident.get("top_incidents"), list) else [],
            },
            "entity_risk": {
                "entity_count": _as_int(soc_entity.get("entity_count"), _as_int(second_pass_soc.get("entity_count"), 0)),
                "top_entities": soc_entity.get("top_entities") if isinstance(soc_entity.get("top_entities"), list) else [],
            },
        },
        "noc_focus": {
            "path_health": {
                "status": str(network_health.get("status") or ""),
                "uplink": str(state.get("up_if") or ""),
                "gateway": str(state.get("gateway_ip") or ""),
                "internet_check": str(connection.get("internet_check") or ""),
                "signals": signals[:4],
            },
            "service_health": service_summary,
            "service_assurance": {
                "status": str(noc_service_assurance.get("status") or "unknown"),
                "degraded_targets": noc_service_assurance.get("degraded_targets") if isinstance(noc_service_assurance.get("degraded_targets"), list) else [],
            },
            "resolution_health": {
                "status": str(noc_resolution_assurance.get("status") or "unknown"),
                "failed_targets": noc_resolution_assurance.get("failed_targets") if isinstance(noc_resolution_assurance.get("failed_targets"), list) else [],
            },
            "blast_radius": {
                "affected_uplinks": noc_blast_radius.get("affected_uplinks") if isinstance(noc_blast_radius.get("affected_uplinks"), list) else [],
                "affected_segments": noc_blast_radius.get("affected_segments") if isinstance(noc_blast_radius.get("affected_segments"), list) else [],
                "related_service_targets": noc_blast_radius.get("related_service_targets") if isinstance(noc_blast_radius.get("related_service_targets"), list) else [],
                "affected_client_count": _as_int(noc_blast_radius.get("affected_client_count"), 0),
                "critical_client_count": _as_int(noc_blast_radius.get("critical_client_count"), 0),
            },
            "config_drift": {
                "status": str(noc_config_drift.get("status") or "unknown"),
                "baseline_state": str(noc_config_drift.get("baseline_state") or "unknown"),
                "changed_fields": noc_config_drift.get("changed_fields") if isinstance(noc_config_drift.get("changed_fields"), list) else [],
                "rollback_hint": str(noc_config_drift.get("rollback_hint") or ""),
            },
            "incident_summary": {
                "incident_id": str(noc_incident_summary.get("incident_id") or ""),
                "probable_cause": str(noc_incident_summary.get("probable_cause") or "stable"),
                "confidence": _as_float(noc_incident_summary.get("confidence"), 0.0),
                "supporting_symptoms": noc_incident_summary.get("supporting_symptoms") if isinstance(noc_incident_summary.get("supporting_symptoms"), list) else [],
            },
            "capacity": {
                "state": str(noc_capacity.get("state") or "unknown"),
                "mode": str(noc_capacity.get("mode") or "unknown"),
                "utilization_pct": _as_float(noc_capacity.get("utilization_pct"), 0.0) if "utilization_pct" in noc_capacity else None,
                "top_talker": top_talker,
                "signals": noc_capacity.get("signals") if isinstance(noc_capacity.get("signals"), list) else [],
            },
            "client_inventory": {
                "current_client_count": _as_int(noc_client_inventory.get("current_client_count"), 0),
                "new_client_count": _as_int(noc_client_inventory.get("new_client_count"), 0),
                "unknown_client_count": _as_int(noc_client_inventory.get("unknown_client_count"), 0),
                "unauthorized_client_count": _as_int(noc_client_inventory.get("unauthorized_client_count"), 0),
                "inventory_mismatch_count": _as_int(noc_client_inventory.get("inventory_mismatch_count"), 0),
                "stale_session_count": _as_int(noc_client_inventory.get("stale_session_count"), 0),
            },
            "client_impact": {
                "scope": path_scope,
                "segment_scope": str(state.get("up_if") or "unknown"),
                "captive_portal": str(connection.get("captive_portal") or ""),
                "dns_mismatch": _as_int(network_health.get("dns_mismatch"), 0),
            },
        },
        "timestamps": {
            "snapshot_at": _iso_from_epoch(state.get("snapshot_epoch")),
            "ai_metrics_at": _iso_from_epoch(metrics.get("last_update_ts")),
            "mode_last_change": str(mode.get("last_change") or ""),
        },
        "decision_path": {
            "first_pass_engine": str(first_pass.get("engine") or "tactical_scorer_v1"),
            "first_pass_role": str(first_pass.get("role") or "first_minute_triage"),
            "second_pass_engine": str(second_pass.get("engine") or "soc_evaluator_v1"),
            "second_pass_role": str(second_pass.get("role") or "second_pass_evaluation"),
            "second_pass_status": second_pass_status,
            "second_pass_evidence_count": _as_int(second_pass.get("evidence_count") or second_pass_detail.get("evidence_count"), 0),
            "second_pass_flow_support_count": _as_int(second_pass.get("flow_support_count") or second_pass_detail.get("flow_support_count"), 0),
            "soc_status": str(((second_pass_detail.get("soc") or {}) if isinstance(second_pass_detail.get("soc"), dict) else {}).get("status") or ""),
            "ai_role": "supplemental_operator_assist",
        },
    }


def _dashboard_actions_payload(state: Dict[str, Any], advisory: Dict[str, Any], llm_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    lang = _request_lang()
    latest_ai = _dashboard_visible_ai_context(state, advisory, llm_rows)
    noc_runbook_support = _dashboard_noc_runbook_support(state, lang=lang)
    selected_runbook_id = str(latest_ai.get("runbook_id") or noc_runbook_support.get("runbook_candidate_id") or "")
    suggested_runbook = _runbook_brief(selected_runbook_id, lang=lang)
    guidance = _dashboard_action_guidance(state, advisory, latest_ai, suggested_runbook, noc_runbook_support=noc_runbook_support)
    second_pass_detail = state.get("second_pass") if isinstance(state.get("second_pass"), dict) else {}
    if not second_pass_detail and isinstance(advisory.get("second_pass"), dict):
        second_pass_detail = advisory.get("second_pass")
    second_pass_soc = second_pass_detail.get("soc") if isinstance(second_pass_detail.get("soc"), dict) else {}
    triage_state = second_pass_soc.get("triage_priority_state") if isinstance(second_pass_soc.get("triage_priority_state"), dict) else {}
    triage_now = triage_state.get("now") if isinstance(triage_state.get("now"), list) else []
    triage_watch = triage_state.get("watch") if isinstance(triage_state.get("watch"), list) else []
    triage_backlog = triage_state.get("backlog") if isinstance(triage_state.get("backlog"), list) else []
    triage_status = str(triage_state.get("status") or second_pass_soc.get("triage_status") or "").strip()
    if triage_status:
        _append_unique(guidance["why_now"], f"SOC triage priority is {triage_status}.")
    if triage_now:
        _append_unique(guidance["do_next"], f"Review {len(triage_now)} SOC triage-now item(s) before stronger controls.")
    if triage_watch:
        _append_unique(guidance["do_next"], f"Keep {len(triage_watch)} SOC watch item(s) under active monitoring.")
    user_guidance = str(
        latest_ai.get("user_message")
        or suggested_runbook.get("user_message_template")
        or noc_runbook_support.get("why_this_runbook")
        or state.get("recommendation")
        or ""
    )
    recommendation = str(state.get("recommendation") or advisory.get("recommendation") or "").strip()
    review = latest_ai.get("review") if isinstance(latest_ai.get("review"), dict) else {}
    if not review:
        reviewed_runbook = (noc_runbook_support.get("reviewed_runbook") or {}) if isinstance(noc_runbook_support.get("reviewed_runbook"), dict) else {}
        review = reviewed_runbook.get("review") if isinstance(reviewed_runbook.get("review"), dict) else {}
    rationale: List[str] = []
    for item in guidance["why_now"][:2]:
        _append_unique(rationale, item)
    if noc_runbook_support.get("why_this_runbook"):
        _append_unique(rationale, str(noc_runbook_support.get("why_this_runbook")))
    if review.get("final_status"):
        _append_unique(rationale, f"{_tr('api.review_prefix', default='Review')}: {review.get('final_status')}.")
    findings = review.get("findings") if isinstance(review.get("findings"), list) else []
    if findings:
        _append_unique(rationale, f"Review findings: {' | '.join(str(x) for x in findings[:2])}.")
    suspicion = _as_int((state.get("internal") or {}).get("suspicion"), 0) if isinstance(state.get("internal"), dict) else 0
    critical = _as_int(state.get("suricata_critical"), 0)
    stronger_actions: List[Dict[str, str]] = []
    if critical <= 0 and suspicion < 80:
        stronger_actions.append({"action": "throttle", "reason": "Threat signal is not strong enough yet."})
        stronger_actions.append({"action": "redirect", "reason": "High-confidence deception criteria are not met."})
        stronger_actions.append({"action": "isolate", "reason": "Client impact is not justified by current evidence."})
    elif suspicion < 95:
        stronger_actions.append({"action": "redirect", "reason": "Reversible control remains safer than redirect."})
        stronger_actions.append({"action": "isolate", "reason": "Isolation requires stronger blast-radius evidence."})
    else:
        stronger_actions.append({"action": "isolate", "reason": "Isolation stays reserved for confirmed, high-impact compromise."})
    decision_pipeline = state.get("decision_pipeline") if isinstance(state.get("decision_pipeline"), dict) else {}
    if not decision_pipeline and isinstance(advisory.get("decision_pipeline"), dict):
        decision_pipeline = advisory.get("decision_pipeline")
    first_pass = decision_pipeline.get("first_pass") if isinstance(decision_pipeline.get("first_pass"), dict) else {}
    second_pass = decision_pipeline.get("second_pass") if isinstance(decision_pipeline.get("second_pass"), dict) else {}
    return {
        "ok": True,
        "current_operator_actions": guidance["do_next"],
        "why_now": guidance["why_now"],
        "do_next": guidance["do_next"],
        "do_not_do": guidance["do_not_do"],
        "escalate_if": guidance["escalate_if"],
        "current_user_guidance": user_guidance[:160],
        "suggested_runbook": suggested_runbook,
        "approval_required": bool(suggested_runbook.get("requires_approval")),
        "current_recommendation": recommendation,
        "operator_note": str(latest_ai.get("operator_note") or noc_runbook_support.get("operator_note") or ""),
        "noc_runbook_support": {
            "runbook_candidate_id": str(noc_runbook_support.get("runbook_candidate_id") or ""),
            "why_this_runbook": str(noc_runbook_support.get("why_this_runbook") or ""),
            "operator_checks": noc_runbook_support.get("operator_checks") if isinstance(noc_runbook_support.get("operator_checks"), list) else [],
            "escalation_hint": str(noc_runbook_support.get("escalation_hint") or ""),
            "ai_used": bool(noc_runbook_support.get("ai_used")),
        },
        "rejected_stronger_actions": stronger_actions[:4],
        "mio": {
            "answer": str(latest_ai.get("answer") or ""),
            "status": str(latest_ai.get("status") or ""),
            "model": str(latest_ai.get("model") or ""),
            "question": str(latest_ai.get("question") or ""),
            "source": str(latest_ai.get("source") or ""),
            "asked_at": _iso_from_epoch(latest_ai.get("ts")),
            "runbook": suggested_runbook,
            "review": review,
            "rationale": rationale[:4],
            "handoff": {
                "ops_comm": "/ops-comm",
                "mattermost": MATTERMOST_OPEN_URL,
            },
        },
        "links": {
            "ask_mio": "/ops-comm",
            "mattermost": MATTERMOST_OPEN_URL,
        },
        "decision_path": {
            "first_pass_engine": str(first_pass.get("engine") or "tactical_scorer_v1"),
            "first_pass_role": str(first_pass.get("role") or "first_minute_triage"),
            "second_pass_engine": str(second_pass.get("engine") or "soc_evaluator_v1"),
            "second_pass_role": str(second_pass.get("role") or "second_pass_evaluation"),
            "second_pass_status": str(second_pass.get("status") or second_pass_detail.get("status") or "pending"),
            "second_pass_evidence_count": _as_int(second_pass.get("evidence_count") or second_pass_detail.get("evidence_count"), 0),
            "second_pass_flow_support_count": _as_int(second_pass.get("flow_support_count") or second_pass_detail.get("flow_support_count"), 0),
            "soc_status": str(((second_pass_detail.get("soc") or {}) if isinstance(second_pass_detail.get("soc"), dict) else {}).get("status") or ""),
            "ai_role": "supplemental_operator_assist",
        },
        "soc_priority": {
            "status": triage_status or "idle",
            "now": triage_now[:8],
            "watch": triage_watch[:8],
            "backlog": triage_backlog[:8],
            "top_priority_ids": triage_state.get("top_priority_ids") if isinstance(triage_state.get("top_priority_ids"), list) else [],
        },
    }


def _dashboard_evidence_sections(
    state: Dict[str, Any],
    advisory: Dict[str, Any],
    ai_activity: List[Dict[str, Any]],
    runbook_events: List[Dict[str, Any]],
    triage_audit: List[Dict[str, Any]],
    mode_runtime: Dict[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    now_iso = datetime.now().isoformat()
    internal = state.get("internal") if isinstance(state.get("internal"), dict) else {}
    network_health = state.get("network_health") if isinstance(state.get("network_health"), dict) else {}
    monitoring = state.get("monitoring") if isinstance(state.get("monitoring"), dict) else {}
    current_triggers: List[Dict[str, Any]] = []
    decision_changes: List[Dict[str, Any]] = []
    operator_interactions: List[Dict[str, Any]] = []
    background_history: List[Dict[str, Any]] = []
    triage_timeline: List[Dict[str, Any]] = []

    suspicion = _as_int(internal.get("suspicion"), 0)
    user_state = str(state.get("user_state") or "")
    if user_state and user_state.upper() != "SAFE":
        current_triggers.append(
            {
                "ts_iso": now_iso,
                "title": f"State {user_state}",
                "detail": f"state_name={internal.get('state_name', '-')} suspicion={suspicion}",
                "kind": "state",
            }
        )
    signals = network_health.get("signals") if isinstance(network_health.get("signals"), list) else []
    for signal in signals[:3]:
        current_triggers.append(
            {
                "ts_iso": now_iso,
                "title": f"Signal {signal}",
                "detail": f"network_health={network_health.get('status', '-')}",
                "kind": "signal",
            }
        )
    if _as_int(state.get("suricata_critical"), 0) > 0:
        current_triggers.append(
            {
                "ts_iso": now_iso,
                "title": "Direct critical alerts",
                "detail": f"count={_as_int(state.get('suricata_critical'), 0)}",
                "kind": "suricata",
            }
        )
    for name in ("suricata", "opencanary", "ntfy"):
        if str(monitoring.get(name) or "").upper() == "OFF":
            current_triggers.append(
                {
                    "ts_iso": now_iso,
                    "title": f"Service {name} OFF",
                    "detail": "Operator verification required",
                    "kind": "service",
                }
            )
    if not current_triggers:
        current_triggers.append(
            {
                "ts_iso": now_iso,
                "title": "No active trigger",
                "detail": "Current state is SAFE and no trigger is active.",
                "kind": "quiet",
            }
        )

    recent_mode = _recent_mode_changes(mode_runtime)
    for item in recent_mode[:3]:
        decision_changes.append(
            {
                "ts_iso": str(item.get("last_change") or ""),
                "title": f"Mode -> {item.get('current_mode') or '-'}",
                "detail": f"requested_by={item.get('requested_by') or '-'}",
                "kind": "mode",
            }
        )
    for item in runbook_events[-5:]:
        decision_changes.append(
            {
                "ts_iso": str(item.get("ts_iso") or ""),
                "title": f"{item.get('action') or '-'} {item.get('runbook_id') or '-'}",
                "detail": f"actor={item.get('actor') or '-'} ok={item.get('ok')}",
                "kind": "runbook",
            }
        )

    for item in ai_activity[-8:]:
        source = str(item.get("source") or "")
        if source in {"dashboard", "ops-comm", "mattermost_command", "mattermost_post"}:
            operator_interactions.append(
                {
                    "ts_iso": str(item.get("ts_iso") or ""),
                    "title": str(item.get("question") or item.get("answer") or "-"),
                    "detail": f"{item.get('source') or '-'} | runbook={item.get('runbook_id') or '-'}",
                    "kind": "operator",
                }
            )
        else:
            background_history.append(
                {
                    "ts_iso": str(item.get("ts_iso") or ""),
                    "title": str(item.get("question") or item.get("answer") or "-"),
                    "detail": f"{item.get('model') or '-'} | {item.get('status') or item.get('kind') or '-'}",
                    "kind": "background",
                }
            )
    if advisory:
        background_history.insert(
            0,
            {
                "ts_iso": _iso_from_epoch(advisory.get("ts")),
                "title": str(advisory.get("attack_type") or advisory.get("recommendation") or "Current advisory"),
                "detail": f"risk={_as_int(advisory.get('risk_score'), 0)} state={advisory.get('user_state') or '-'}",
                "kind": "advisory",
            },
        )

    for item in triage_audit[-8:]:
        triage_timeline.append(
            {
                "ts_iso": str(item.get("ts_iso") or ""),
                "title": str(item.get("title") or item.get("kind") or "-"),
                "detail": str(item.get("detail") or "-"),
                "kind": "triage",
            }
        )

    return {
        "current_triggers": current_triggers[:6],
        "decision_changes": decision_changes[:8],
        "operator_interactions": operator_interactions[:8],
        "background_history": background_history[:8],
        "triage_audit": triage_timeline[:8],
    }


def _normalize_triage_audit_event(item: Dict[str, Any]) -> Dict[str, Any]:
    kind = str(item.get("kind") or "triage")
    session_id = str(item.get("session_id") or item.get("trace_id") or "")
    state_bits: List[str] = []
    if item.get("intent_id"):
        state_bits.append(f"intent={item.get('intent_id')}")
    if item.get("step_id"):
        state_bits.append(f"step={item.get('step_id')}")
    if item.get("diagnostic_state"):
        state_bits.append(f"diagnostic={item.get('diagnostic_state')}")
    if item.get("target"):
        state_bits.append(f"target={item.get('target')}")
    if item.get("reason"):
        state_bits.append(f"reason={item.get('reason')}")
    if item.get("proposed_runbooks"):
        state_bits.append(
            "runbooks=" + ",".join(str(x) for x in list(item.get("proposed_runbooks") or [])[:3])
        )
    return {
        "ts_iso": str(item.get("ts") or ""),
        "kind": kind,
        "trace_id": str(item.get("trace_id") or ""),
        "session_id": session_id,
        "title": kind.replace("_", " "),
        "detail": " | ".join(state_bits) if state_bits else str(item.get("source") or "triage_engine"),
        "source": str(item.get("source") or ""),
    }


def _dashboard_evidence_payload(
    state: Dict[str, Any],
    advisory: Dict[str, Any],
    alert_rows: List[Dict[str, Any]],
    llm_rows: List[Dict[str, Any]],
    runbook_rows: List[Dict[str, Any]],
    triage_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    recent_alerts = [_normalize_alert_event(item) for item in alert_rows[-10:]]
    if not recent_alerts and advisory:
        recent_alerts = [_normalize_alert_event({"advisory": advisory, "event": {}})]
    ai_activity = [_normalize_ai_activity(item) for item in llm_rows[-10:]]
    runbook_events = [_normalize_runbook_event(item) for item in runbook_rows[-10:]]
    triage_audit = [_normalize_triage_audit_event(item) for item in triage_rows[-10:]]
    mode_runtime = get_mode_state()
    sections = _dashboard_evidence_sections(state, advisory, ai_activity, runbook_events, triage_audit, mode_runtime)
    return {
        "ok": True,
        "recent_alerts": recent_alerts,
        "recent_ai_activity": ai_activity,
        "recent_runbook_events": runbook_events,
        "recent_triage_audit": triage_audit,
        "recent_mode_changes": _recent_mode_changes(mode_runtime),
        "current_triggers": sections["current_triggers"],
        "decision_changes": sections["decision_changes"],
        "operator_interactions": sections["operator_interactions"],
        "background_history": sections["background_history"],
        "triage_audit": sections["triage_audit"],
        "snapshot_evidence": [str(item) for item in (state.get("evidence") or [])[:8]] if isinstance(state.get("evidence"), list) else [],
    }


def _dashboard_health_payload(state: Dict[str, Any], metrics: Dict[str, Any], llm_rows: List[Dict[str, Any]], runbook_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    now_epoch = time.time()
    snapshot_age = _age_seconds(state.get("snapshot_epoch"), now_epoch=now_epoch)
    ai_metrics_age = _age_seconds(metrics.get("last_update_ts"), now_epoch=now_epoch)
    last_ai_ts = _as_float((_latest_item(llm_rows)).get("ts"), 0.0)
    last_runbook_ts = _as_float((_latest_item(runbook_rows)).get("ts"), 0.0)
    network_health = state.get("network_health") if isinstance(state.get("network_health"), dict) else {}
    signals = network_health.get("signals") if isinstance(network_health.get("signals"), list) else []
    safe_idle = (
        str(state.get("user_state") or "").upper() == "SAFE"
        and _as_int((state.get("internal") or {}).get("suspicion"), 0) <= 0
        and not signals
        and _as_int(metrics.get("queue_depth"), 0) <= 0
    )
    ai_activity_stale = bool(last_ai_ts and (_age_seconds(last_ai_ts, now_epoch=now_epoch) or 0.0) > DASHBOARD_EVENT_STALE_SEC)
    runbook_stale = bool(last_runbook_ts and (_age_seconds(last_runbook_ts, now_epoch=now_epoch) or 0.0) > DASHBOARD_EVENT_STALE_SEC)
    idle_flags = {
        "ai_activity": bool(safe_idle and ai_activity_stale),
        "runbook_events": bool(safe_idle and runbook_stale),
    }
    reachable, ping = _mattermost_ping()
    return {
        "ok": True,
        "stale_flags": {
            "snapshot": bool(snapshot_age is not None and snapshot_age > DASHBOARD_SNAPSHOT_STALE_SEC),
            "ai_metrics": bool(ai_metrics_age is not None and ai_metrics_age > DASHBOARD_AI_STALE_SEC),
            "ai_activity": bool(ai_activity_stale and not idle_flags["ai_activity"]),
            "runbook_events": bool(runbook_stale and not idle_flags["runbook_events"]),
        },
        "idle_flags": idle_flags,
        "queue": {
            "depth": _as_int(metrics.get("queue_depth"), 0),
            "capacity": _as_int(metrics.get("queue_capacity"), 0),
            "max_seen": _as_int(metrics.get("queue_max_seen"), 0),
            "deferred_count": _as_int(metrics.get("deferred_count"), 0),
        },
        "llm": {
            "requests": _as_int(metrics.get("llm_requests"), 0),
            "completed": _as_int(metrics.get("llm_completed"), 0),
            "failed": _as_int(metrics.get("llm_failed"), 0),
            "fallback_rate": _as_float(metrics.get("llm_fallback_rate"), 0.0),
            "latency_ms_last": _as_int(metrics.get("llm_latency_ms_last"), 0),
            "latency_ms_ema": _as_float(metrics.get("llm_latency_ms_ema"), 0.0),
            "manual_routed_count": _as_int(metrics.get("manual_routed_count"), 0),
        },
        "timestamps": {
            "snapshot_at": _iso_from_epoch(state.get("snapshot_epoch")),
            "ai_metrics_at": _iso_from_epoch(metrics.get("last_update_ts")),
            "last_ai_activity_at": _iso_from_epoch(last_ai_ts),
            "last_runbook_event_at": _iso_from_epoch(last_runbook_ts),
        },
        "ages_sec": {
            "snapshot": snapshot_age,
            "ai_metrics": ai_metrics_age,
            "ai_activity": _age_seconds(last_ai_ts, now_epoch=now_epoch),
            "runbook_events": _age_seconds(last_runbook_ts, now_epoch=now_epoch),
        },
        "policy_mode": str(metrics.get("policy_mode") or ""),
        "last_error": str(metrics.get("last_error") or ""),
        "mattermost": {
            "reachable": reachable,
            "ping": ping,
        },
    }

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


def _unauthorized_response(*, ok_payload: Optional[bool] = False, status_code: int = 403) -> tuple[Response, int]:
    if ok_payload is None:
        payload: Dict[str, Any] = {"error": "Unauthorized"}
    else:
        payload = {"ok": bool(ok_payload), "error": "Unauthorized"}
    return jsonify(payload), int(status_code)


def require_token(*, ok_payload: Optional[bool] = False, status_code: int = 403) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Endpoint decorator that centralizes token verification responses."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not verify_token():
                return _unauthorized_response(ok_payload=ok_payload, status_code=status_code)
            return func(*args, **kwargs)

        return wrapped

    return decorator


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
    out["lang"] = str(src.get("lang") or out.get("lang") or _request_lang())
    try:
        if risk_score not in (None, ""):
            out["risk_score"] = int(risk_score)
    except Exception:
        pass
    return out


def _mattermost_command_allowed(command_token: str) -> bool:
    token = str(command_token or "").strip()
    if not token:
        return False
    return token in MATTERMOST_COMMAND_TOKENS


def _extract_mattermost_context_and_text(text: str) -> tuple[str, str, str]:
    raw = str(text or "").strip()
    audience = "operator"
    lang = "ja"
    prefixes = {
        "temporary:": ("audience", "beginner"),
        "temp:": ("audience", "beginner"),
        "beginner:": ("audience", "beginner"),
        "casual:": ("audience", "beginner"),
        "pro:": ("audience", "operator"),
        "operator:": ("audience", "operator"),
        "professional:": ("audience", "operator"),
        "ja:": ("lang", "ja"),
        "jp:": ("lang", "ja"),
        "japanese:": ("lang", "ja"),
        "en:": ("lang", "en"),
        "english:": ("lang", "en"),
    }
    changed = True
    current = raw
    while changed and current:
        changed = False
        lowered = current.lower()
        for prefix, (kind, value) in prefixes.items():
            if lowered.startswith(prefix):
                if kind == "audience":
                    audience = value
                else:
                    lang = normalize_lang(value)
                current = current[len(prefix):].strip()
                changed = True
                break
    return audience, lang, current


def _format_mattermost_ai_response(
    ai_result: Dict[str, Any] | None,
    proposals: Dict[str, Any] | None,
    lang: str | None = None,
) -> str:
    lang_norm = normalize_lang(lang)
    tr = lambda key, default=None, **kwargs: i18n_translate(key, lang=lang_norm, default=default, **kwargs)
    lines: List[str] = []
    if isinstance(ai_result, dict):
        routed = str(ai_result.get("status") or "") == "routed"
        answer = str(ai_result.get("answer") or "").strip()
        if answer:
            prefix = "" if answer.startswith("M.I.O.") else "M.I.O.: "
            lines.append(f"{prefix}{answer}")
        rationale = ai_result.get("rationale")
        if isinstance(rationale, list) and rationale:
            lines.append("Rationale: " + " | ".join(str(x) for x in rationale[:2]))
        user_message = str(ai_result.get("user_message") or "").strip()
        if user_message:
            lines.append(f"{tr('api.user_guidance', default='User Guidance')}: {user_message}")
        runbook_id = str(ai_result.get("runbook_id") or "").strip()
        review = ai_result.get("runbook_review") if isinstance(ai_result.get("runbook_review"), dict) else {}
        if runbook_id:
            lines.append(f"{tr('api.suggested_runbook', default='Suggested Runbook')}: `{runbook_id}`")
        if review:
            lines.append(f"{tr('api.review_prefix', default='Review')}: `{review.get('final_status', '-')}`")
            changes = review.get("required_changes")
            if isinstance(changes, list) and changes:
                lines.append(tr("api.required_changes", default="Required Changes") + ": " + " | ".join(str(x) for x in changes[:3]))
        handoff = ai_result.get("handoff") if isinstance(ai_result.get("handoff"), dict) else {}
        ops_comm = str(handoff.get("ops_comm") or "").strip()
        if ops_comm:
            lines.append(f"{tr('api.continue', default='Continue')}: `{ops_comm}`")
        if routed:
            return "\n".join(lines)[:1200]
    if isinstance(proposals, dict):
        items = proposals.get("items")
        if isinstance(items, list) and items:
            lines.append(tr("api.candidates", default="Candidates") + ":")
            for item in items[:3]:
                review = item.get("review") if isinstance(item.get("review"), dict) else {}
                lines.append(
                    f"- `{item.get('runbook_id', '-')}` [{review.get('final_status', '-')}] {item.get('title', '-')}"
                )
    return "\n".join(lines)[:3000]


def _assist_handoff_payload() -> Dict[str, str]:
    return {
        "ops_comm": "/ops-comm",
        "mattermost": MATTERMOST_OPEN_URL,
    }


def _resolve_demo_runner() -> Path:
    candidates = [USR_LOCAL_DEMO_RUNNER, OPT_DEMO_RUNNER, LOCAL_DEMO_RUNNER]
    for path in candidates:
        try:
            if path.exists() and os.access(path, os.X_OK):
                return path
        except Exception:
            continue
    return LOCAL_DEMO_RUNNER


def _run_demo_runner(*args: str) -> tuple[Dict[str, Any], int]:
    runner = _resolve_demo_runner()
    cmd = [str(runner), *[str(x) for x in args]]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PY_ROOT) + (f":{env['PYTHONPATH']}" if env.get("PYTHONPATH") else "")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
            env=env,
            cwd=str(PROJECT_ROOT),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "demo_runner_timeout", "command": cmd}, 504
    except Exception as e:
        return {"ok": False, "error": str(e), "command": cmd}, 500

    stdout = str(result.stdout or "").strip()
    stderr = str(result.stderr or "").strip()
    payload: Dict[str, Any] = {}
    if stdout:
        try:
            payload = json.loads(stdout)
        except Exception:
            payload = {"ok": False, "error": "invalid_demo_runner_output", "stdout": stdout}
    if result.returncode != 0:
        if not payload:
            payload = {"ok": False}
        payload.setdefault("error", stderr or f"demo_runner_exit_{result.returncode}")
        payload["stderr"] = stderr
        payload["returncode"] = result.returncode
        payload["command"] = cmd
        return payload, 400 if "unknown_scenario" in str(payload.get("error", "")) else 500

    if not payload:
        payload = {"ok": True}
    payload["runner"] = str(runner)
    return payload, 200


def _assist_rationale(ai_result: Dict[str, Any]) -> List[str]:
    rationale: List[str] = []
    status = str(ai_result.get("status") or "").strip()
    model = str(ai_result.get("model") or "").strip()
    runbook_id = str(ai_result.get("runbook_id") or "").strip()
    review = ai_result.get("runbook_review") if isinstance(ai_result.get("runbook_review"), dict) else {}

    if status == "routed":
        _append_unique(rationale, "Symptom router handled this request without waiting for LLM.")
    elif status == "fallback":
        _append_unique(rationale, "Fallback response was used because the primary model path did not complete in time.")
    elif status:
        _append_unique(rationale, f"Response status: {status}.")

    if model:
        _append_unique(rationale, f"Response source: {model}.")
    if runbook_id:
        _append_unique(rationale, f"Recommended runbook: {runbook_id}.")
    if review.get("final_status"):
        _append_unique(rationale, f"Runbook review status: {review.get('final_status')}.")
    findings = review.get("findings") if isinstance(review.get("findings"), list) else []
    changes = review.get("required_changes") if isinstance(review.get("required_changes"), list) else []
    for item in findings[:2]:
        _append_unique(rationale, str(item))
    for item in changes[:2]:
        _append_unique(rationale, f"Change required: {item}")
    return rationale[:4]


def _enrich_ai_result(ai_result: Dict[str, Any] | None) -> Dict[str, Any]:
    result = dict(ai_result) if isinstance(ai_result, dict) else {}
    if not result:
        return {"ok": False, "error": "empty_ai_result", "rationale": [], "handoff": _assist_handoff_payload()}
    runbook_id = str(result.get("runbook_id") or "").strip()
    if runbook_id and not str(result.get("user_message") or "").strip() and runbook_get is not None:
        try:
            runbook = runbook_get(runbook_id, lang=_request_lang())
            result["user_message"] = localize_runbook_user_message(runbook, lang=_request_lang())[:160]
        except Exception:
            pass
    result["rationale"] = _assist_rationale(result)
    result["handoff"] = _assist_handoff_payload()
    return result


def _run_runbook_action(body: Dict[str, Any]) -> tuple[Dict[str, Any], int]:
    if runbook_get is None or runbook_execute is None or runbook_review_id is None:
        return {"ok": False, "error": "runbook_registry_unavailable"}, 500

    runbook_id = str(body.get("runbook_id") or "").strip()
    action = str(body.get("action") or "preview").strip().lower()
    args = body.get("args") if isinstance(body.get("args"), dict) else {}
    actor = str(body.get("actor") or body.get("sender") or "webui-operator").strip() or "webui-operator"
    note = str(body.get("note") or "").strip()[:240]
    approved = bool(body.get("approved", False))
    context = _review_context_from_request(body)
    lang = str(context.get("lang") or _request_lang())

    def _log_runbook_decision(ok: bool, error: str = "", review_status: str = "", effect: str = "") -> None:
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
                "review_status": review_status,
                "effect": effect,
                "note": note,
            },
        )

    if not runbook_id:
        return {"ok": False, "error": "runbook_id is required"}, 400
    if action not in {"preview", "approve", "execute"}:
        return {"ok": False, "error": "invalid_action"}, 400

    try:
        runbook = runbook_get(runbook_id, lang=lang)
        review = runbook_review_id(runbook_id, context=context)
    except Exception as e:
        _log_runbook_decision(False, str(e))
        return {"ok": False, "error": str(e)}, 404

    effect = str(runbook.get("effect") or "")
    requires_approval = bool(runbook.get("requires_approval"))
    user_message = localize_runbook_user_message(runbook, lang=lang).strip()[:160]
    review_status = str(review.get("final_status") or "approved")
    if review_status == "rejected":
        _log_runbook_decision(False, "runbook_rejected_by_review", review_status=review_status, effect=effect)
        return {"ok": False, "error": "runbook_rejected_by_review", "review": review}, 409
    if action == "execute" and review_status == "amend_required":
        _log_runbook_decision(False, "runbook_requires_changes_before_execute", review_status=review_status, effect=effect)
        return {"ok": False, "error": "runbook_requires_changes_before_execute", "review": review}, 409
    if action == "approve" and review_status == "amend_required":
        _log_runbook_decision(False, "runbook_requires_changes_before_approve", review_status=review_status, effect=effect)
        return {"ok": False, "error": "runbook_requires_changes_before_approve", "review": review}, 409
    if action in {"approve", "execute"} and requires_approval and not approved:
        _log_runbook_decision(False, "approval_required", review_status=review_status, effect=effect)
        return {"ok": False, "error": "approval_required", "review": review}, 409

    result: Dict[str, Any]
    code = 200
    if action == "preview":
        try:
            result = runbook_execute(runbook_id, args=args, dry_run=True, lang=lang)
        except Exception as e:
            _log_runbook_decision(False, str(e), review_status=review_status, effect=effect)
            return {"ok": False, "error": str(e), "review": review}, 400
    elif action == "approve":
        result = {
            "ok": True,
            "runbook_id": runbook_id,
            "title": runbook.get("title"),
            "effect": effect,
            "approved": approved or not requires_approval,
            "executed": False,
            "steps": runbook.get("steps", []),
            "user_message_template": localize_runbook_user_message(runbook, lang=lang),
        }
    else:
        if effect not in {"read_only", "controlled_exec"}:
            _log_runbook_decision(False, "execute_supported_only_for_read_only_or_controlled_exec", review_status=review_status, effect=effect)
            return {"ok": False, "error": "execute_supported_only_for_read_only_or_controlled_exec", "review": review}, 409
        try:
            result = runbook_execute(
                runbook_id,
                args=args,
                dry_run=False,
                approved=approved,
                allow_controlled_exec=(effect == "controlled_exec"),
                lang=lang,
            )
            code = 200 if result.get("ok") else 500
        except Exception as e:
            _log_runbook_decision(False, str(e), review_status=review_status, effect=effect)
            return {"ok": False, "error": str(e), "review": review}, 400

    result["review"] = review
    result["operator_action"] = action
    result["actor"] = actor
    result["note"] = note
    result["user_message"] = user_message
    _log_runbook_decision(bool(result.get("ok")), review_status=review_status, effect=effect)
    return result, code


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
        data = _parse_json_dict_lenient(path.read_text(encoding="utf-8"))
        if not data:
            raise ValueError("ui_snapshot.json could not be parsed as object")
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


def _triage_unavailable_payload() -> tuple[Dict[str, Any], int]:
    return {"ok": False, "error": "triage_unavailable"}, 503


def _triage_step_payload(step: Any, lang: str) -> Dict[str, Any]:
    question_i18n = step.question_i18n if isinstance(getattr(step, "question_i18n", None), dict) else {}
    question = question_i18n.get(lang) or question_i18n.get("en") or next(iter(question_i18n.values()), "")
    return {
        "step_id": step.step_id,
        "question": question,
        "answer_type": step.answer_type,
        "choices": list(step.choices or []),
    }


def _triage_mio_payload(progress: Any, lang: str) -> Dict[str, Any]:
    session = progress.session
    flow_label = progress.flow.label_i18n.get(lang) or progress.flow.label_i18n.get("en") or progress.flow.flow_id
    if progress.next_step is not None:
        return {
            "preface": i18n_translate("triage.mio.preface.question", lang=lang, default="M.I.O.: narrow the symptom with one deterministic question before changing settings."),
            "summary": i18n_translate("triage.mio.summary.in_progress", lang=lang, default="Current flow: {flow}. Answer one question at a time and avoid changing mode or restarting services yet.", flow=flow_label),
            "handoff": i18n_translate("triage.mio.handoff.none", lang=lang, default="No handoff is required yet."),
        }
    diagnostic = progress.diagnostic_state
    if diagnostic is None:
        return {
            "preface": i18n_translate("triage.mio.preface.idle", lang=lang, default="M.I.O. will add a short preface before the next deterministic question."),
            "summary": i18n_translate("triage.mio.summary.idle", lang=lang, default="No triage summary yet."),
            "handoff": i18n_translate("triage.mio.handoff.none", lang=lang, default="No handoff is required."),
        }
    state_id = diagnostic.state_id
    summary_text = i18n_translate("triage.mio.summary.ready", lang=lang, default="Diagnostic state: {state}. Review the candidate runbooks before taking stronger action.", state=state_id)
    if session.handoff_reason:
        return {
            "preface": i18n_translate("triage.mio.preface.done", lang=lang, default="M.I.O.: the deterministic triage has finished."),
            "summary": summary_text,
            "handoff": i18n_translate("triage.mio.handoff.operator", lang=lang, default="Handoff to an operator: the user could not provide enough input. Continue with the reviewed runbooks and current context."),
        }
    return {
        "preface": i18n_translate("triage.mio.preface.done", lang=lang, default="M.I.O.: the deterministic triage has finished."),
        "summary": summary_text,
        "handoff": i18n_translate("triage.mio.handoff.review", lang=lang, default="No forced handoff. Continue with the reviewed runbooks and the current diagnostic state."),
    }


def _triage_progress_payload(progress: Any, lang: str) -> Dict[str, Any]:
    session = progress.session
    payload: Dict[str, Any] = {
        "ok": True,
        "session": session.to_dict(),
        "completed": bool(progress.completed),
        "flow_id": progress.flow.flow_id,
        "flow_label": progress.flow.label_i18n.get(lang) or progress.flow.label_i18n.get("en") or progress.flow.flow_id,
        "mio": _triage_mio_payload(progress, lang=lang),
    }
    if progress.next_step is not None:
        payload["next_step"] = _triage_step_payload(progress.next_step, lang=lang)
    if progress.diagnostic_state is not None:
        diagnostic_payload = progress.diagnostic_state.to_dict()
        diagnostic_payload["summary_i18n"] = {
            "ja": i18n_translate(progress.diagnostic_state.summary_key, lang="ja", default=progress.diagnostic_state.state_id),
            "en": i18n_translate(progress.diagnostic_state.summary_key, lang="en", default=progress.diagnostic_state.state_id),
        }
        payload["diagnostic_state"] = diagnostic_payload
        if select_runbooks_for_diagnostic_state is not None:
            payload["runbooks"] = select_runbooks_for_diagnostic_state(
                progress.diagnostic_state.state_id,
                audience=session.audience,
                lang=lang,
                context={"lang": lang, "audience": session.audience, "diagnostic_state": progress.diagnostic_state.state_id},
            ).get("items", [])
    return payload


# Web UI Routes

@app.route("/")
def index():
    """Main dashboard page"""
    return render_template("index.html")


@app.route("/demo")
def demo_page():
    """Dedicated demo and review workspace."""
    return render_template("demo.html")


@app.route("/ops-comm")
def ops_comm():
    """Dedicated communication page for Mattermost + WebUI bridge."""
    open_url = MATTERMOST_OPEN_URL
    return render_template("ops_comm.html", mattermost_open_url=open_url)


@app.route("/api/state")
@require_token(ok_payload=None)
def api_state():
    """GET /api/state - Return current state.json"""
    state = read_state()
    # Add local monitoring status
    state["monitoring"] = get_monitoring_state()
    state["portal_viewer"] = get_portal_viewer_state()
    mode_state = get_mode_state()
    state["mode"] = mode_state.get("mode", {})
    state["mode_runtime"] = mode_state
    return jsonify(state)


@app.route("/api/state/stream")
@require_token(ok_payload=None)
def api_state_stream():
    """GET /api/state/stream - SSE stream for control-plane snapshot updates."""

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
@require_token(ok_payload=None)
def api_portal_viewer():
    """GET /api/portal-viewer - Return portal viewer status and URL."""
    return jsonify(get_portal_viewer_state())


@app.route("/api/portal-viewer/open", methods=["POST"])
@require_token()
def api_portal_viewer_open():
    """POST /api/portal-viewer/open - Ensure noVNC is up then return URL."""
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
@require_token()
def api_mode_get():
    """GET /api/mode - Return current mode metadata."""
    payload = get_mode_state()
    code = 200 if payload.get("ok") else 500
    return jsonify(payload), code


@app.route("/api/mode", methods=["POST"])
@require_token()
def api_mode_set():
    """POST /api/mode - Switch mode via control daemon."""
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
@require_token(ok_payload=None)
def api_events_stream():
    """GET /api/events/stream - SSE bridge for ntfy topic events."""
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
@require_token()
def api_mattermost_status():
    reachable, ping_payload = _mattermost_ping()
    return jsonify(
        {
            "ok": True,
            "reachable": reachable,
            "base_url": MATTERMOST_BASE_URL,
            "open_url": MATTERMOST_OPEN_URL,
            "mode": _mattermost_mode(),
            "channel_id": MATTERMOST_CHANNEL_ID,
            "command_enabled": bool(MATTERMOST_COMMAND_TOKENS),
            "command_endpoint": "/api/mattermost/command",
            "command_triggers": [MATTERMOST_COMMAND_PRIMARY_TRIGGER, *MATTERMOST_COMMAND_ALIASES],
            "ping": ping_payload,
        }
    )


@app.route("/api/ai/ask", methods=["POST"])
@require_token()
def api_ai_ask():
    body = request.get_json(silent=True) or {}
    question = str(body.get("question") or "").strip()
    sender = str(body.get("sender") or "M.I.O. Console").strip() or "M.I.O. Console"
    source = str(body.get("source") or "webui").strip() or "webui"
    context = body.get("context") if isinstance(body.get("context"), dict) else {}
    context = dict(context)
    context.setdefault("lang", str(body.get("lang") or _request_lang()))
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400
    result = _send_ai_manual_query(
        question=question,
        sender=sender,
        source=source,
        context=context,
    )
    result = _enrich_ai_result(result)
    code = 200 if result.get("ok") else 500
    return jsonify(result), code


@app.route("/api/ai/capabilities", methods=["GET"])
@require_token()
def api_ai_capabilities():
    return jsonify(
        {
            "ok": True,
            "mattermost_triggers": [MATTERMOST_COMMAND_PRIMARY_TRIGGER, *MATTERMOST_COMMAND_ALIASES],
            "manual_router_categories": [
                "wifi_onboarding",
                "wifi_reconnect",
                "wifi_issue",
                "dns",
                "route",
                "service",
                "epd",
                "ai_logs",
                "snapshot",
            ],
            "capabilities": [
                {
                    "title": "Symptom Router",
                    "detail": _tr("api.detail.symptom_router", default="Wi-Fi, DNS, route, service, EPD, and AI logs are answered immediately without waiting for the LLM."),
                },
                {
                    "title": "Audience Adaptation",
                    "detail": _tr("api.detail.audience", default="Professional and Temporary modes adjust wording, runbook priority, and user guidance."),
                },
                {
                    "title": "Runbook Guidance",
                    "detail": _tr("api.detail.runbook", default="M.I.O. proposes reviewed runbooks and returns user-facing guidance together with operator notes."),
                },
                {
                    "title": "Mattermost Integration",
                    "detail": _tr("api.detail.mattermost", default="Slash commands /mio and /azops are available. Prefixes temp: and pro: switch the audience mode."),
                },
            ],
        }
    ), 200


@app.route("/api/triage/intents", methods=["GET"])
@require_token()
def api_triage_intents():
    if triage_list_flows is None:
        payload, code = _triage_unavailable_payload()
        return jsonify(payload), code
    lang = _request_lang()
    items = []
    for flow in triage_list_flows():
        items.append(
            {
                "intent_id": flow.flow_id,
                "label": flow.label_i18n.get(lang) or flow.label_i18n.get("en") or flow.flow_id,
                "entry_state": flow.entry_state,
            }
        )
    return jsonify({"ok": True, "items": items}), 200


@app.route("/api/triage/classify", methods=["POST"])
@require_token()
def api_triage_classify():
    if classify_intent_candidates is None:
        payload, code = _triage_unavailable_payload()
        return jsonify(payload), code
    body = request.get_json(silent=True) or {}
    text = str(body.get("text") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "text is required"}), 400
    lang = _request_lang()
    items = [item.to_dict() for item in classify_intent_candidates(text, lang=lang, limit=2)]
    return jsonify({"ok": True, "items": items}), 200


@app.route("/api/triage/start", methods=["POST"])
@require_token()
def api_triage_start():
    if _TRIAGE_ENGINE is None:
        payload, code = _triage_unavailable_payload()
        return jsonify(payload), code
    body = request.get_json(silent=True) or {}
    intent_id = str(body.get("intent_id") or "").strip()
    if not intent_id:
        return jsonify({"ok": False, "error": "intent_id is required"}), 400
    audience = str(body.get("audience") or "temporary").strip() or "temporary"
    lang = _request_lang()
    progress = _TRIAGE_ENGINE.start(intent_id, audience=audience, lang=lang)
    return jsonify(_triage_progress_payload(progress, lang=lang)), 200


@app.route("/api/triage/answer", methods=["POST"])
@require_token()
def api_triage_answer():
    if _TRIAGE_ENGINE is None:
        payload, code = _triage_unavailable_payload()
        return jsonify(payload), code
    body = request.get_json(silent=True) or {}
    session_id = str(body.get("session_id") or "").strip()
    if not session_id:
        return jsonify({"ok": False, "error": "session_id is required"}), 400
    if "answer" not in body:
        return jsonify({"ok": False, "error": "answer is required"}), 400
    lang = _request_lang()
    try:
        progress = _TRIAGE_ENGINE.answer(session_id, body.get("answer"))
    except KeyError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify(_triage_progress_payload(progress, lang=lang)), 200


@app.route("/api/triage/session/<session_id>", methods=["GET"])
@require_token()
def api_triage_session(session_id: str):
    if _TRIAGE_ENGINE is None:
        payload, code = _triage_unavailable_payload()
        return jsonify(payload), code
    lang = _request_lang()
    try:
        progress = _TRIAGE_ENGINE.resume(str(session_id or "").strip())
    except KeyError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify(_triage_progress_payload(progress, lang=lang)), 200


@app.route("/api/triage/audit", methods=["GET"])
@require_token()
def api_triage_audit():
    limit = min(max(_as_int(request.args.get("limit"), 20), 1), 100)
    rows = _tail_first_existing_jsonl([TRIAGE_AUDIT_LOG, TRIAGE_AUDIT_FALLBACK_LOG], limit=limit)
    items = [_normalize_triage_audit_event(item) for item in rows[-limit:]]
    return jsonify({"ok": True, "items": items, "count": len(items)}), 200


@app.route("/api/demo/scenarios", methods=["GET"])
@require_token()
def api_demo_scenarios():
    payload, code = _run_demo_runner("list")
    return jsonify(payload), code


@app.route("/api/demo/overlay", methods=["GET"])
@require_token()
def api_demo_overlay():
    payload = read_demo_overlay()
    return jsonify({"ok": True, "overlay": payload, "active": bool(payload.get("active"))}), 200


@app.route("/api/demo/capabilities", methods=["GET"])
@require_token()
def api_demo_capabilities():
    try:
        from azazel_edge.demo import DemoScenarioRunner
    except Exception as exc:
        return jsonify({"ok": False, "error": f"demo_capabilities_unavailable:{exc}"}), 500
    return jsonify(
        {
            "ok": True,
            "execution_mode": "deterministic_replay",
            "ai_used_in_core_path": False,
            "live_telemetry_required": False,
            "local_only_in_core_path": True,
            "boundary": DemoScenarioRunner.capability_boundary(),
        }
    ), 200


@app.route("/api/demo/explanation/latest", methods=["GET"])
@require_token()
def api_demo_explanation_latest():
    payload = read_demo_overlay()
    if not payload.get("active"):
        return jsonify({"ok": False, "error": "no_active_demo_overlay"}), 404
    raw = payload.get("raw_result") if isinstance(payload.get("raw_result"), dict) else {}
    explanation = raw.get("explanation") if isinstance(raw.get("explanation"), dict) else {}
    if not explanation:
        return jsonify({"ok": False, "error": "no_explanation_available"}), 404
    return jsonify(
        {
            "ok": True,
            "scenario_id": payload.get("scenario_id"),
            "action": payload.get("action"),
            "explanation": explanation,
        }
    ), 200


@app.route("/api/demo/overlay/clear", methods=["POST"])
@require_token()
def api_demo_overlay_clear():
    clear_demo_overlay()
    purge_demo_artifacts()
    _trigger_demo_clear_side_effects()
    return jsonify({"ok": True, "cleared": True}), 200


@app.route("/api/demo/run/<scenario_id>", methods=["POST"])
@require_token()
def api_demo_run(scenario_id: str):
    scenario = str(scenario_id or "").strip()
    if not scenario:
        return jsonify({"ok": False, "error": "scenario_id is required"}), 400
    payload, code = _run_demo_runner("run", scenario)
    if code == 200 and isinstance(payload, dict) and payload.get("ok") and isinstance(payload.get("result"), dict):
        overlay = build_demo_overlay(payload["result"])
        write_demo_overlay(overlay)
        payload["overlay"] = overlay
    return jsonify(payload), code


@app.route("/api/dashboard/summary", methods=["GET"])
@require_token()
def api_dashboard_summary():
    state = read_state()
    metrics = _read_json_file(AI_METRICS_PATH)
    advisory = _read_json_file(AI_ADVISORY_PATH)
    return jsonify(_dashboard_summary_payload(state, metrics, advisory)), 200


@app.route("/api/dashboard/actions", methods=["GET"])
@require_token()
def api_dashboard_actions():
    state = read_state()
    advisory = _read_json_file(AI_ADVISORY_PATH)
    llm_rows = _tail_jsonl(AI_LLM_LOG, limit=20)
    return jsonify(_dashboard_actions_payload(state, advisory, llm_rows)), 200


@app.route("/api/dashboard/evidence", methods=["GET"])
@require_token()
def api_dashboard_evidence():
    state = read_state()
    advisory = _read_json_file(AI_ADVISORY_PATH)
    alert_rows = _tail_jsonl(AI_EVENT_LOG, limit=20)
    llm_rows = _tail_jsonl(AI_LLM_LOG, limit=20)
    runbook_rows = _tail_jsonl(RUNBOOK_EVENT_LOG, limit=20)
    triage_rows = _tail_first_existing_jsonl([TRIAGE_AUDIT_LOG, TRIAGE_AUDIT_FALLBACK_LOG], limit=20)
    return jsonify(_dashboard_evidence_payload(state, advisory, alert_rows, llm_rows, runbook_rows, triage_rows)), 200


@app.route("/api/dashboard/health", methods=["GET"])
@require_token()
def api_dashboard_health():
    state = read_state()
    metrics = _read_json_file(AI_METRICS_PATH)
    llm_rows = _tail_jsonl(AI_LLM_LOG, limit=20)
    runbook_rows = _tail_jsonl(RUNBOOK_EVENT_LOG, limit=20)
    return jsonify(_dashboard_health_payload(state, metrics, llm_rows, runbook_rows)), 200


@app.route("/api/runbooks", methods=["GET"])
@require_token()
def api_runbooks_list():
    if runbook_list is None:
        return jsonify({"ok": False, "error": "runbook_registry_unavailable"}), 500
    return jsonify({"ok": True, "items": runbook_list(lang=_request_lang())}), 200


@app.route("/api/runbooks/<runbook_id>", methods=["GET"])
@require_token()
def api_runbooks_get(runbook_id: str):
    if runbook_get is None:
        return jsonify({"ok": False, "error": "runbook_registry_unavailable"}), 500
    try:
        return jsonify({"ok": True, "runbook": runbook_get(runbook_id, lang=_request_lang())}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 404


@app.route("/api/runbooks/<runbook_id>/review", methods=["GET"])
@require_token()
def api_runbooks_review(runbook_id: str):
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
@require_token()
def api_runbooks_execute():
    body = request.get_json(silent=True) or {}
    dry_run = bool(body.get("dry_run", True))
    body["action"] = "preview" if dry_run else "execute"
    result, code = _run_runbook_action(body)
    result["legacy_execute_endpoint"] = True
    return jsonify(result), code


@app.route("/api/runbooks/propose", methods=["POST"])
@require_token()
def api_runbooks_propose():
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
@require_token()
def api_runbooks_act():
    body = request.get_json(silent=True) or {}
    result, code = _run_runbook_action(body)
    return jsonify(result), code


@app.route("/api/mattermost/message", methods=["POST"])
@require_token()
def api_mattermost_message():
    body = request.get_json(silent=True) or {}
    message = str(body.get("message") or "").strip()
    sender = str(body.get("sender") or "M.I.O. Console").strip() or "M.I.O. Console"
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
            lang = str(body.get("lang") or _request_lang())
            ai_result = _enrich_ai_result(_send_ai_manual_query(
                question=message,
                sender=sender,
                source="mattermost_post",
                context={"channel_id": MATTERMOST_CHANNEL_ID, "lang": lang},
            ))
            if runbook_propose is not None:
                try:
                    runbook_proposals = runbook_propose(
                        message,
                        audience="operator",
                        max_items=3,
                        context={"question": message, "source": "mattermost_post", "lang": lang},
                    )
                except Exception:
                    runbook_proposals = None
            if ai_result.get("ok") and post_ai_reply and send_to_mattermost:
                reply_text = _format_mattermost_ai_response(ai_result, runbook_proposals, lang=lang)
                if reply_text:
                    ai_post = _mattermost_send_message(f"[M.I.O.]\n{reply_text}", sender="M.I.O.")
        return jsonify({"ok": True, "result": posted, "ai_result": ai_result, "runbook_proposals": runbook_proposals, "ai_post_result": ai_post}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/mattermost/command", methods=["POST"])
def api_mattermost_command():
    body = request.get_json(silent=True) or {}
    form = request.form or {}
    raw_text = str(form.get("text") or body.get("text") or "").strip()
    sender = str(form.get("user_name") or body.get("user_name") or body.get("sender") or "mattermost-user").strip() or "mattermost-user"
    command_token = str(form.get("token") or body.get("token") or "").strip()
    channel_id = str(form.get("channel_id") or body.get("channel_id") or MATTERMOST_CHANNEL_ID).strip()
    if not _mattermost_command_allowed(command_token):
        return jsonify({"response_type": "ephemeral", "text": "Mattermost command token mismatch."}), 403
    audience, lang, text = _extract_mattermost_context_and_text(raw_text)
    if not text:
        aliases = ", ".join(f"/{x}" for x in [MATTERMOST_COMMAND_PRIMARY_TRIGGER, *MATTERMOST_COMMAND_ALIASES])
        return jsonify({"response_type": "ephemeral", "text": f"Usage: {aliases} <question>\nOptional prefix: `temp:` or `pro:` / `ja:` or `en:`"}), 200

    ai_result = _send_ai_manual_query(
        question=text,
        sender=sender,
        source="mattermost_command",
        context={"channel_id": channel_id, "page": "mattermost", "audience": audience, "lang": lang},
    )
    ai_result = _enrich_ai_result(ai_result)
    proposals = None
    if runbook_propose is not None:
        try:
            proposals = runbook_propose(
                text,
                audience=audience,
                max_items=3,
                context={"question": text, "source": "mattermost_command", "audience": audience, "lang": lang},
            )
        except Exception:
            proposals = None
    reply_text = _format_mattermost_ai_response(ai_result, proposals, lang=lang) or "No response."
    return jsonify({"response_type": "ephemeral", "text": reply_text}), 200


@app.route("/api/mattermost/messages", methods=["GET"])
@require_token()
def api_mattermost_messages():
    limit = request.args.get("limit", MATTERMOST_FETCH_LIMIT)
    try:
        payload = _mattermost_fetch_messages(int(limit))
        return jsonify(payload), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/action", methods=["POST"])
@require_token(ok_payload=None)
def api_action_new():
    """POST /api/action - Execute control action (AI Coding Spec v1 format)"""

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
@require_token()
def api_action(action: str):
    """POST /api/action/<action> - Execute control action (legacy format)"""

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
@require_token(status_code=401)
def api_wifi_connect():
    """POST /api/wifi/connect - Connect to Wi-Fi AP"""

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


@app.route("/images/<path:filename>")
def image_files(filename):
    """Serve project image assets"""
    return send_from_directory(IMAGES_DIR, filename)


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
