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
    g,
)
import json
import os
import socket
import sys
import time
import subprocess
import ipaddress
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
STATIC_ASSET_VERSION = str(int(time.time()))

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
    from azazel_edge.sot import SoTConfig, SoTValidationError
    from azazel_edge.aggregator import (
        AggregatorRegistry,
        FreshnessPolicy,
        AEVT_NODE_REGISTER,
        AEVT_INGEST_ACCEPT,
        AEVT_INGEST_REJECT,
        AEVT_NODE_QUARANTINE,
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
    SoTConfig = None  # type: ignore
    SoTValidationError = ValueError  # type: ignore
    AggregatorRegistry = None  # type: ignore
    FreshnessPolicy = None  # type: ignore

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
TOPOLITE_SEED_MODE_PATH = Path(os.environ.get("AZAZEL_TOPOLITE_SEED_MODE_PATH", "/run/azazel-edge/topolite_seed_mode.json"))
SOT_AUDIT_LOG = Path(os.environ.get("AZAZEL_SOT_AUDIT_LOG", "/var/log/azazel-edge/sot-events.jsonl"))
TRIAGE_SESSION_DIR = Path(os.environ.get("AZAZEL_TRIAGE_SESSION_DIR", "/run/azazel-edge/triage-sessions"))
OPERATOR_PROGRESS_PATH = Path(os.environ.get("AZAZEL_OPERATOR_PROGRESS_PATH", "/run/azazel-edge/operator-progress.json"))
_TOKEN_FILE_OVERRIDE = str(os.environ.get("AZAZEL_WEB_TOKEN_FILE", "")).strip()
TOKEN_FILE = Path(_TOKEN_FILE_OVERRIDE) if _TOKEN_FILE_OVERRIDE else web_token_candidates()[0]
AUTH_FAIL_OPEN = os.environ.get("AZAZEL_AUTH_FAIL_OPEN", "0") == "1"
AUTH_TOKENS_FILE = Path(str(os.environ.get("AZAZEL_AUTH_TOKENS_FILE", "/etc/azazel-edge/auth_tokens.json")).strip() or "/etc/azazel-edge/auth_tokens.json")
AUTHZ_AUDIT_LOG = Path(str(os.environ.get("AZAZEL_AUTHZ_AUDIT_LOG", "/var/log/azazel-edge/authz-events.jsonl")).strip() or "/var/log/azazel-edge/authz-events.jsonl")
AUTH_MTLS_REQUIRED = str(os.environ.get("AZAZEL_AUTH_MTLS_REQUIRED", "0")).strip().lower() in {"1", "true", "yes", "on"}
AUTH_MTLS_HEADER = str(os.environ.get("AZAZEL_AUTH_MTLS_HEADER", "X-Client-Cert-Fingerprint")).strip() or "X-Client-Cert-Fingerprint"
AUTH_MTLS_FINGERPRINTS = {
    item.strip().lower()
    for item in str(os.environ.get("AZAZEL_AUTH_MTLS_FINGERPRINTS", "")).split(",")
    if item.strip()
}
AUTH_MTLS_FINGERPRINTS_FILE = Path(str(os.environ.get("AZAZEL_AUTH_MTLS_FINGERPRINTS_FILE", "/etc/azazel-edge/client-cert-fingerprints.txt")).strip() or "/etc/azazel-edge/client-cert-fingerprints.txt")
_ROLE_RANK: Dict[str, int] = {"viewer": 10, "operator": 20, "responder": 30, "admin": 40}
IMAGES_DIR = Path(__file__).resolve().parents[1] / "images"
LOCAL_DEMO_RUNNER = PROJECT_ROOT / "bin" / "azazel-edge-demo"
OPT_DEMO_RUNNER = Path("/opt/azazel-edge/bin/azazel-edge-demo")
USR_LOCAL_DEMO_RUNNER = Path("/usr/local/bin/azazel-edge-demo")
EPD_LAST_RENDER_PATH = Path("/run/azazel-edge/epd_last_render.json")
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
AGGREGATOR_POLL_INTERVAL_SEC = max(5, int(os.environ.get("AZAZEL_AGGREGATOR_POLL_INTERVAL_SEC", "30")))
AGGREGATOR_STALE_MULTIPLIER = max(2, int(os.environ.get("AZAZEL_AGGREGATOR_STALE_MULTIPLIER", "2")))
AGGREGATOR_OFFLINE_MULTIPLIER = max(3, int(os.environ.get("AZAZEL_AGGREGATOR_OFFLINE_MULTIPLIER", "6")))
_agg_hmac_key_raw = os.environ.get("AZAZEL_AGGREGATOR_INGEST_HMAC_KEY", "")
AGGREGATOR_INGEST_HMAC_SECRET: bytes | None = _agg_hmac_key_raw.encode("utf-8") if _agg_hmac_key_raw else None
AGGREGATOR_SIG_REQUIRED = os.environ.get("AZAZEL_AGGREGATOR_SIG_REQUIRED", "false").lower() in ("1", "true", "yes")
AGGREGATOR_REPLAY_WINDOW_SEC = max(30, int(os.environ.get("AZAZEL_AGGREGATOR_REPLAY_WINDOW_SEC", "300")))
AGGREGATOR_AUDIT_LOG = Path(
    str(os.environ.get("AZAZEL_AGGREGATOR_AUDIT_LOG", "/var/log/azazel-edge/aggregator-events.jsonl")).strip()
    or "/var/log/azazel-edge/aggregator-events.jsonl"
)

if AggregatorRegistry is not None and FreshnessPolicy is not None:
    _AGGREGATOR_REGISTRY = AggregatorRegistry(
        policy=FreshnessPolicy(
            poll_interval_sec=AGGREGATOR_POLL_INTERVAL_SEC,
            stale_multiplier=AGGREGATOR_STALE_MULTIPLIER,
            offline_multiplier=AGGREGATOR_OFFLINE_MULTIPLIER,
        ),
        hmac_secret=AGGREGATOR_INGEST_HMAC_SECRET,
        sig_required=AGGREGATOR_SIG_REQUIRED,
        replay_window_sec=AGGREGATOR_REPLAY_WINDOW_SEC,
    )
else:
    _AGGREGATOR_REGISTRY = None


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
        "asset_version": STATIC_ASSET_VERSION,
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
DASHBOARD_TRENDS_PATH = Path(os.environ.get("AZAZEL_DASHBOARD_TRENDS_PATH", "/run/azazel-edge/dashboard-trends.jsonl"))
DASHBOARD_TRENDS_WRITE_INTERVAL_SEC = float(os.environ.get("AZAZEL_DASHBOARD_TRENDS_WRITE_INTERVAL_SEC", "15"))
DASHBOARD_TRENDS_RETENTION_SEC = float(os.environ.get("AZAZEL_DASHBOARD_TRENDS_RETENTION_SEC", "3600"))
DASHBOARD_TRENDS_LIMIT = int(os.environ.get("AZAZEL_DASHBOARD_TRENDS_LIMIT", "240"))
ALERT_QUEUE_NOW_THRESHOLD = int(os.environ.get("AZAZEL_ALERT_QUEUE_NOW_THRESHOLD", "80"))
ALERT_QUEUE_WATCH_THRESHOLD = int(os.environ.get("AZAZEL_ALERT_QUEUE_WATCH_THRESHOLD", "50"))
ALERT_QUEUE_ESCALATE_THRESHOLD = int(os.environ.get("AZAZEL_ALERT_QUEUE_ESCALATE_THRESHOLD", "90"))
ALERT_SUPPRESSION_WINDOW_SEC = int(os.environ.get("AZAZEL_ALERT_SUPPRESSION_WINDOW_SEC", "120"))
ALERT_AGGREGATION_WINDOW_SEC = int(os.environ.get("AZAZEL_ALERT_AGGREGATION_WINDOW_SEC", "300"))
ALERT_ESCALATION_COUNT_THRESHOLD = int(os.environ.get("AZAZEL_ALERT_ESCALATION_COUNT_THRESHOLD", "5"))
_dashboard_trends_lock = threading.Lock()
_dashboard_trends_last_write_ts = 0.0
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
    "mode_set", "mode_status", "mode_get", "mode_portal", "mode_shield", "mode_scapegoat",
    "sot_trust_client",
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


def _write_json_file(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


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


def _default_sot_payload() -> Dict[str, Any]:
    return {
        "devices": [],
        "networks": [],
        "services": [],
        "expected_paths": [],
    }


def _sot_candidates() -> List[Path]:
    candidates: List[Path] = []
    env_path = str(os.environ.get("AZAZEL_SOT_PATH", "")).strip()
    if env_path:
        candidates.append(Path(env_path))
    for cfg_dir in config_dir_candidates():
        candidates.append(cfg_dir / "sot.yaml")
        candidates.append(cfg_dir / "sot.json")
    deduped: List[Path] = []
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


def _read_sot_payload() -> Tuple[Dict[str, Any], Path]:
    target = _sot_target_path()
    if not target.exists():
        return _default_sot_payload(), target
    try:
        if target.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
            except Exception:
                app.logger.warning("PyYAML is required to read SoT YAML")
                return _default_sot_payload(), target
            payload = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        else:
            payload = _parse_json_dict_lenient(target.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    return payload if isinstance(payload, dict) else _default_sot_payload(), target


def _validate_sot_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if SoTConfig is None:
        raise ValueError("sot_validation_unavailable")
    return SoTConfig.from_dict(payload).to_dict()


def _write_sot_payload(payload: Dict[str, Any], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    if target.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise RuntimeError("yaml_writer_unavailable") from exc
        tmp.write_text(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False), encoding="utf-8")
    else:
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(target)


def _sot_device_diff(before_devices: List[Dict[str, Any]], after_devices: List[Dict[str, Any]]) -> Dict[str, int]:
    before_ids = {str(item.get("id") or "").strip() for item in before_devices if isinstance(item, dict)}
    after_ids = {str(item.get("id") or "").strip() for item in after_devices if isinstance(item, dict)}
    before_ids.discard("")
    after_ids.discard("")
    added = len(after_ids - before_ids)
    removed = len(before_ids - after_ids)
    updated = 0
    before_map = {str(item.get("id")): item for item in before_devices if isinstance(item, dict) and str(item.get("id") or "").strip()}
    for row in after_devices:
        if not isinstance(row, dict):
            continue
        row_id = str(row.get("id") or "").strip()
        if not row_id or row_id not in before_map:
            continue
        if before_map[row_id] != row:
            updated += 1
    return {"added": added, "removed": removed, "updated": updated}


def _request_actor() -> Dict[str, str]:
    actor = (
        str(request.headers.get("X-AZAZEL-ACTOR") or "").strip()
        or str(request.headers.get("X-Forwarded-User") or "").strip()
        or str(request.headers.get("X-Auth-User") or "").strip()
        or str(request.remote_addr or "").strip()
        or "unknown"
    )
    return {
        "actor": actor[:96],
        "remote_addr": str(request.remote_addr or "").strip(),
        "user_agent": str(request.headers.get("User-Agent") or "").strip()[:180],
    }


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


_MIO_SURFACE_RULES: Dict[str, Dict[str, Any]] = {
    "dashboard": {"max_chars": 260, "format": "summary_first"},
    "ops-comm": {"max_chars": 900, "format": "conversation"},
    "mattermost": {"max_chars": 1200, "format": "handoff_share"},
}


def _normalize_mio_audience(value: Any, default: str = "professional") -> str:
    text = str(value or "").strip().lower()
    if text in {"temporary", "beginner", "casual", "temp"}:
        return "beginner"
    if text in {"professional", "operator", "pro", "expert"}:
        return "professional"
    return "beginner" if default == "beginner" else "professional"


def _normalize_mio_surface(value: Any, default: str = "dashboard") -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    mapping = {
        "dashboard": "dashboard",
        "webui": "dashboard",
        "ops-comm": "ops-comm",
        "opscomm": "ops-comm",
        "ops-comm-ui": "ops-comm",
        "mattermost": "mattermost",
        "mattermost-post": "mattermost",
        "mattermost-command": "mattermost",
    }
    return mapping.get(text, mapping.get(str(default or "dashboard").strip().lower().replace("_", "-"), "dashboard"))


def _truncate_text(value: str, limit: int) -> str:
    text = str(value or "").strip()
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= 1:
        return text[:limit]
    return text[: limit - 1].rstrip() + "…"


def _mio_sentence_slices(text: str, limit: int = 3) -> List[str]:
    chunks: List[str] = []
    source = str(text or "").replace("\n", " ").strip()
    if not source:
        return []
    parts = source.replace("。", ". ").replace("！", "! ").replace("？", "? ").split(".")
    for part in parts:
        item = part.strip(" \t\r\n。!?")
        if not item:
            continue
        _append_unique(chunks, item)
        if len(chunks) >= limit:
            break
    if not chunks:
        chunks = [source]
    return chunks[:limit]


def _mio_review_payload(ai_result: Dict[str, Any]) -> Dict[str, Any]:
    review = ai_result.get("runbook_review") if isinstance(ai_result.get("runbook_review"), dict) else {}
    if review:
        return review
    alt = ai_result.get("review")
    return alt if isinstance(alt, dict) else {}


def _string_list(value: Any, limit: int = 3) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for item in value:
        text = str(item or "").strip()
        if not text:
            continue
        _append_unique(out, text)
        if len(out) >= limit:
            break
    return out[:limit]


def _mio_next_actions(ai_result: Dict[str, Any], lang: str, limit: int = 3) -> List[str]:
    next_actions = _string_list(ai_result.get("do_next"), limit=limit)
    if not next_actions:
        next_actions = _string_list(ai_result.get("current_operator_actions"), limit=limit)
    runbook_id = str(ai_result.get("runbook_id") or "").strip()
    if runbook_id and len(next_actions) < limit:
        _append_unique(
            next_actions,
            (f"Runbook `{runbook_id}` で確認を進める" if lang == "ja" else f"Proceed with runbook `{runbook_id}` checks."),
        )
    handoff = ai_result.get("handoff") if isinstance(ai_result.get("handoff"), dict) else {}
    ops_comm = str(handoff.get("ops_comm") or "").strip()
    if ops_comm and len(next_actions) < limit:
        _append_unique(
            next_actions,
            (f"不確実な点は `{ops_comm}` に引き継ぐ" if lang == "ja" else f"Handoff unresolved points to `{ops_comm}`."),
        )
    return next_actions[:limit]


def _mio_beginner_steps(ai_result: Dict[str, Any], lang: str, limit: int = 3) -> List[str]:
    steps: List[str] = []
    user_message = str(ai_result.get("user_message") or "").strip()
    answer = str(ai_result.get("answer") or "").strip()
    if user_message:
        for piece in _mio_sentence_slices(user_message, limit=limit):
            _append_unique(steps, piece)
            if len(steps) >= limit:
                break
    if answer and len(steps) < limit:
        for piece in _mio_sentence_slices(answer, limit=limit):
            _append_unique(steps, piece)
            if len(steps) >= limit:
                break
    for action in _mio_next_actions(ai_result, lang=lang, limit=limit):
        if len(steps) >= limit:
            break
        _append_unique(steps, action)
    if not steps:
        _append_unique(
            steps,
            "最初の安全確認を優先してください。" if lang == "ja" else "Prioritize the first safe check.",
        )
    return steps[:limit]


def _mio_labels(lang: str) -> Dict[str, str]:
    if lang == "ja":
        return {
            "summary": "Summary",
            "do_now": "Do now",
            "rationale": "Rationale",
            "review": "Review",
            "next": "Next",
            "runbook": "Runbook",
            "continue": "Continue",
        }
    return {
        "summary": "Summary",
        "do_now": "Do now",
        "rationale": "Rationale",
        "review": "Review",
        "next": "Next",
        "runbook": "Runbook",
        "continue": "Continue",
    }


def _build_mio_message_profile(
    audience: Any = None,
    lang: Any = None,
    surface: Any = None,
) -> Dict[str, Any]:
    lang_norm = normalize_lang(lang)
    audience_norm = _normalize_mio_audience(audience, default="professional")
    surface_norm = _normalize_mio_surface(surface, default="dashboard")
    rule = _MIO_SURFACE_RULES.get(surface_norm, _MIO_SURFACE_RULES["dashboard"])
    return {
        "audience": audience_norm,
        "lang": lang_norm,
        "surface": surface_norm,
        "style": "action_first" if audience_norm == "beginner" else "summary_rationale_next",
        "max_chars": int(rule["max_chars"]),
        "max_steps": 3 if audience_norm == "beginner" else None,
        "format": str(rule["format"]),
    }


def _build_mio_surface_message(ai_result: Dict[str, Any], profile: Dict[str, Any]) -> str:
    lang = normalize_lang(profile.get("lang"))
    audience = _normalize_mio_audience(profile.get("audience"), default="professional")
    surface = _normalize_mio_surface(profile.get("surface"), default="dashboard")
    labels = _mio_labels(lang)
    max_chars = int(profile.get("max_chars") or _MIO_SURFACE_RULES.get(surface, {}).get("max_chars") or 260)
    runbook_id = str(ai_result.get("runbook_id") or "").strip()
    handoff = ai_result.get("handoff") if isinstance(ai_result.get("handoff"), dict) else {}
    ops_comm = str(handoff.get("ops_comm") or "").strip()
    review = _mio_review_payload(ai_result)
    review_status = str(review.get("final_status") or "").strip()

    if audience == "beginner":
        steps = _mio_beginner_steps(ai_result, lang=lang, limit=3)
        if surface == "dashboard":
            headline = steps[0] if steps else ("最初の確認から開始してください。" if lang == "ja" else "Start with the first safety check.")
            return _truncate_text(headline, max_chars)
        lines = [f"{labels['do_now']}:"]
        for idx, step in enumerate(steps[:3], start=1):
            lines.append(f"{idx}. {step}")
        if runbook_id:
            lines.append(f"{labels['runbook']}: `{runbook_id}`")
        if ops_comm:
            lines.append(f"{labels['continue']}: `{ops_comm}`")
        return _truncate_text("\n".join(lines), max_chars)

    summary = str(ai_result.get("answer") or ai_result.get("user_message") or "").strip() or "-"
    rationale = _string_list(ai_result.get("rationale"), limit=3) or _assist_rationale(ai_result)[:3]
    next_actions = _mio_next_actions(ai_result, lang=lang, limit=3)
    if surface == "dashboard":
        parts = [summary]
        if rationale:
            parts.append(f"{labels['rationale']}: {rationale[0]}")
        if review_status:
            parts.append(f"{labels['review']}: {review_status}")
        if next_actions:
            parts.append(f"{labels['next']}: {next_actions[0]}")
        return _truncate_text(" | ".join(parts), max_chars)

    lines = [f"{labels['summary']}: {summary}"]
    if rationale:
        lines.append(f"{labels['rationale']}: " + " | ".join(rationale[:2]))
    if review_status:
        lines.append(f"{labels['review']}: `{review_status}`")
    if next_actions:
        lines.append(f"{labels['next']}: " + " | ".join(next_actions[:2]))
    if runbook_id:
        lines.append(f"{labels['runbook']}: `{runbook_id}`")
    if ops_comm:
        lines.append(f"{labels['continue']}: `{ops_comm}`")
    return _truncate_text("\n".join(lines), max_chars)


def _build_mio_surface_messages(
    ai_result: Dict[str, Any],
    audience: Any = None,
    lang: Any = None,
) -> Dict[str, str]:
    audience_norm = _normalize_mio_audience(audience, default="professional")
    lang_norm = normalize_lang(lang)
    messages: Dict[str, str] = {}
    for surface in ("dashboard", "ops-comm", "mattermost"):
        profile = _build_mio_message_profile(audience=audience_norm, lang=lang_norm, surface=surface)
        messages[surface] = _build_mio_surface_message(ai_result, profile)
    return messages


def _compose_mio_message_bundle(
    ai_result: Dict[str, Any],
    audience: Any = None,
    lang: Any = None,
    surface: Any = None,
) -> Dict[str, Any]:
    profile = _build_mio_message_profile(audience=audience, lang=lang, surface=surface)
    messages = _build_mio_surface_messages(
        ai_result,
        audience=profile["audience"],
        lang=profile["lang"],
    )
    return {
        "profile": profile,
        "surface_messages": messages,
        "surface_message": str(messages.get(profile["surface"]) or ""),
    }


def _normal_assurance_payload(
    state: Dict[str, Any],
    metrics: Dict[str, Any],
    service_summary: Dict[str, Any],
    snapshot_age: Optional[float],
    ai_age: Optional[float],
    network_health: Dict[str, Any],
) -> Dict[str, Any]:
    gates: List[Dict[str, Any]] = []

    def add_gate(gate_id: str, label: str, ok: bool, detail: str) -> None:
        gates.append(
            {
                "id": gate_id,
                "label": label,
                "ok": bool(ok),
                "detail": detail,
            }
        )

    if snapshot_age is None:
        add_gate("snapshot_fresh", "Snapshot Fresh", False, "snapshot timestamp is missing")
    elif snapshot_age > DASHBOARD_SNAPSHOT_STALE_SEC:
        add_gate(
            "snapshot_fresh",
            "Snapshot Fresh",
            False,
            f"snapshot stale ({round(snapshot_age)}s > {int(DASHBOARD_SNAPSHOT_STALE_SEC)}s)",
        )
    else:
        add_gate("snapshot_fresh", "Snapshot Fresh", True, f"snapshot age {round(snapshot_age)}s")

    if ai_age is None:
        add_gate("ai_metrics_fresh", "AI Metrics Fresh", False, "ai metrics timestamp is missing")
    elif ai_age > DASHBOARD_AI_STALE_SEC:
        add_gate(
            "ai_metrics_fresh",
            "AI Metrics Fresh",
            False,
            f"ai metrics stale ({round(ai_age)}s > {int(DASHBOARD_AI_STALE_SEC)}s)",
        )
    else:
        add_gate("ai_metrics_fresh", "AI Metrics Fresh", True, f"ai metrics age {round(ai_age)}s")

    critical_raw = state.get("suricata_critical")
    if critical_raw in (None, ""):
        add_gate("no_direct_critical", "Direct Critical Alerts", False, "direct critical count is missing")
    else:
        critical = _as_int(critical_raw, 0)
        add_gate(
            "no_direct_critical",
            "Direct Critical Alerts",
            critical <= 0,
            f"direct critical count={critical}",
        )

    has_network_health = isinstance(network_health, dict) and bool(network_health)
    signals_raw = network_health.get("signals") if isinstance(network_health.get("signals"), list) else None
    if not has_network_health or signals_raw is None:
        add_gate("no_network_signals", "Network Signals", False, "network signals are missing")
    else:
        add_gate(
            "no_network_signals",
            "Network Signals",
            len(signals_raw) == 0,
            f"active signals={len(signals_raw)}",
        )

    queue_depth_raw = metrics.get("queue_depth")
    queue_capacity_raw = metrics.get("queue_capacity")
    if queue_depth_raw in (None, "") or queue_capacity_raw in (None, ""):
        add_gate("queue_within_capacity", "Queue Capacity", False, "queue depth/capacity is missing")
    else:
        depth = _as_int(queue_depth_raw, -1)
        capacity = _as_int(queue_capacity_raw, -1)
        queue_ok = capacity > 0 and depth >= 0 and depth <= capacity
        detail = f"depth={depth} capacity={capacity}"
        if capacity <= 0:
            detail += " (invalid capacity)"
        add_gate("queue_within_capacity", "Queue Capacity", queue_ok, detail)

    deferred_raw = metrics.get("deferred_count")
    if deferred_raw in (None, ""):
        add_gate("deferred_clear", "Deferred Queue", False, "deferred count is missing")
    else:
        deferred = _as_int(deferred_raw, 0)
        add_gate("deferred_clear", "Deferred Queue", deferred <= 0, f"deferred count={deferred}")

    service_states = {
        name: str(service_summary.get(name) or "UNKNOWN").upper()
        for name in ("suricata", "opencanary", "ntfy", "ai_agent", "web")
    }
    off_services = [name for name, status in service_states.items() if status != "ON"]
    add_gate(
        "core_services_healthy",
        "Core Services",
        len(off_services) == 0,
        "all core services ON" if not off_services else f"not ON: {', '.join(off_services)}",
    )

    failed = [gate["id"] for gate in gates if not gate["ok"]]
    critical_failure_ids = {
        "snapshot_fresh",
        "ai_metrics_fresh",
        "no_direct_critical",
        "queue_within_capacity",
        "core_services_healthy",
    }
    if not failed:
        status = "normal"
        level = "safe"
    elif any(gate_id in critical_failure_ids for gate_id in failed):
        status = "alert"
        level = "danger"
    else:
        status = "watch"
        level = "caution"

    return {
        "status": status,
        "level": level,
        "all_ok": len(failed) == 0,
        "gate_count": len(gates),
        "passed_count": len(gates) - len(failed),
        "failed_gates": failed,
        "gates": gates,
        "evaluated_at": datetime.now().isoformat(),
    }


def _mask_mac(mac: str) -> str:
    text = str(mac or "").strip().lower()
    if not text:
        return "-"
    parts = text.split(":")
    if len(parts) == 6 and all(len(part) == 2 for part in parts):
        return f"{parts[0]}:{parts[1]}:**:**:**:{parts[5]}"
    return text[:2] + "**"


def _client_trust_eligible(ip: str, mac: str, sot_status: str) -> bool:
    if str(sot_status or "").strip().lower() == "known":
        return True
    if str(mac or "").strip():
        return True
    try:
        return ipaddress.ip_address(str(ip or "").strip()).is_private
    except ValueError:
        return False


def _client_interface_family(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "unknown"
    if text.startswith("wl"):
        return "wlan"
    if text.startswith("eth"):
        return "eth"
    return "other"


def _managed_client_cidrs() -> List[ipaddress._BaseNetwork]:
    raw = str(os.environ.get("AZAZEL_MANAGED_CLIENT_CIDRS", "172.16.0.0/24")).strip()
    networks: List[ipaddress._BaseNetwork] = []
    for item in [part.strip() for part in raw.split(",") if part.strip()]:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return networks


def _ip_in_managed_client_scope(ip: str, networks: List[ipaddress._BaseNetwork]) -> bool:
    text = str(ip or "").strip()
    if not text:
        return False
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return any(addr in network for network in networks)


def _client_identity_excluded_ips(state: Dict[str, Any]) -> set[str]:
    excluded: set[str] = set()
    for key in ("gateway_ip", "up_ip", "down_ip"):
        value = str(state.get(key) or "").strip()
        if value and value != "-":
            excluded.add(value)
    excluded.update({"127.0.0.1", "::1"})
    return excluded


def _client_identity_view_payload(state: Dict[str, Any]) -> Dict[str, Any]:
    sessions_raw = state.get("noc_client_sessions") if isinstance(state.get("noc_client_sessions"), list) else []
    rows: List[Dict[str, Any]] = []
    state_map = {
        "authorized_present": "normal",
        "unknown_present": "unknown",
        "unauthorized_present": "unauthorized",
        "inventory_mismatch": "mismatch",
        "stale_session": "stale",
        "authorized_missing": "missing",
    }
    state_rank = {
        "unauthorized_present": 0,
        "inventory_mismatch": 1,
        "stale_session": 2,
        "unknown_present": 3,
        "authorized_missing": 4,
        "authorized_present": 9,
    }
    segment_counts = {"eth": 0, "wlan": 0, "other": 0, "unknown": 0}
    arp_only_count = 0
    infra_filtered_count = 0
    ignored_filtered_count = 0
    expected_link_mismatch_count = 0
    excluded_ips = _client_identity_excluded_ips(state)
    managed_cidrs = _managed_client_cidrs()

    for row in sessions_raw[:200]:
        if not isinstance(row, dict):
            continue
        session_state = str(row.get("session_state") or "unknown_present")
        state_label = state_map.get(session_state, "unknown")
        requires_attention = session_state != "authorized_present"
        ip = str(row.get("ip") or "")
        if ip in excluded_ips:
            infra_filtered_count += 1
            continue
        if not _ip_in_managed_client_scope(ip, managed_cidrs):
            infra_filtered_count += 1
            continue
        hostname = str(row.get("hostname") or "")
        mac = str(row.get("mac") or "").lower()
        sot_status = str(row.get("sot_status") or "unknown")
        interface_or_segment = str(row.get("interface_or_segment") or "unknown")
        interface_family = _client_interface_family(str(row.get("interface_family") or interface_or_segment))
        session_origin = str(row.get("session_origin") or "unknown")
        monitoring_scope = str(row.get("monitoring_scope") or "managed")
        if monitoring_scope == "ignore":
            ignored_filtered_count += 1
            continue
        if interface_family not in segment_counts:
            interface_family = "other"
        segment_counts[interface_family] += 1
        if session_origin == "arp_only":
            arp_only_count += 1
        if bool(row.get("expected_link_mismatch")):
            expected_link_mismatch_count += 1
        display_name = hostname or ip or mac or str(row.get("session_key") or "unknown-client")
        rows.append(
            {
                "session_key": str(row.get("session_key") or ""),
                "display_name": display_name,
                "hostname": hostname or "",
                "ip": ip or "-",
                "mac": mac or "",
                "masked_mac": _mask_mac(mac),
                "state": state_label,
                "state_raw": session_state,
                "sot_status": sot_status,
                "trusted": bool(sot_status == "known" and session_state != "unauthorized_present"),
                "trust_eligible": _client_trust_eligible(ip, mac, sot_status),
                "last_seen": str(row.get("last_seen") or ""),
                "interface_or_segment": interface_or_segment,
                "interface_family": interface_family,
                "session_origin": session_origin,
                "sources_present": [str(item) for item in (row.get("sources_present") or []) if str(item)],
                "note": str(row.get("notes") or ""),
                "allowed_networks": [str(item) for item in (row.get("allowed_networks") or []) if str(item)],
                "expected_interface_or_segment": str(row.get("expected_interface_or_segment") or ""),
                "expected_link_mismatch": bool(row.get("expected_link_mismatch")),
                "monitoring_scope": monitoring_scope,
                "requires_attention": requires_attention,
            }
        )

    rows.sort(
        key=lambda item: (
            0 if bool(item.get("requires_attention")) else 1,
            state_rank.get(str(item.get("state_raw") or ""), 8),
            str(item.get("display_name") or ""),
        )
    )

    attention_count = sum(1 for item in rows if bool(item.get("requires_attention")))
    normal_count = sum(1 for item in rows if not bool(item.get("requires_attention")))
    return {
        "default_filter": "attention_only",
        "show_normal_toggle": True,
        "attention_count": attention_count,
        "normal_count": normal_count,
        "segment_counts": segment_counts,
        "arp_only_count": arp_only_count,
        "infra_filtered_count": infra_filtered_count,
        "ignored_filtered_count": ignored_filtered_count,
        "expected_link_mismatch_count": expected_link_mismatch_count,
        "items": rows[:120],
    }


def _normalize_progress_session_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) > 120:
        text = text[:120]
    return "".join(ch for ch in text if ch.isalnum() or ch in {"-", "_", "."})


def _operator_progress_store() -> Dict[str, Any]:
    payload = _read_json_file(OPERATOR_PROGRESS_PATH)
    sessions = payload.get("sessions") if isinstance(payload.get("sessions"), dict) else {}
    return {"sessions": sessions}


def _operator_progress_default_items(summary: Dict[str, Any], actions: Dict[str, Any], *, lang: str) -> List[Dict[str, str]]:
    client_view = (((summary.get("noc_focus") or {}) if isinstance(summary.get("noc_focus"), dict) else {}).get("client_identity_view") or {})
    attention_count = _as_int(client_view.get("attention_count"), 0)
    runbook = actions.get("suggested_runbook") if isinstance(actions.get("suggested_runbook"), dict) else {}
    runbook_title = str(runbook.get("title") or "")
    return [
        {
            "id": "baseline",
            "label": i18n_translate(
                "dashboard.progress_item_baseline",
                lang=lang,
                default="Review the first-view baseline",
            ),
            "detail": i18n_translate(
                "dashboard.progress_item_baseline_detail",
                lang=lang,
                default="Confirm Visual Baseline and the strongest heatmap cell before changing anything.",
            ),
        },
        {
            "id": "scope",
            "label": i18n_translate(
                "dashboard.progress_item_scope",
                lang=lang,
                default="Confirm who is affected",
            ),
            "detail": i18n_translate(
                "dashboard.progress_item_scope_detail",
                lang=lang,
                default="Attention endpoints now: {count}. Verify whether impact is one device or wider.",
                count=attention_count,
            ),
        },
        {
            "id": "guidance",
            "label": i18n_translate(
                "dashboard.progress_item_guidance",
                lang=lang,
                default="Give the safe first guidance",
            ),
            "detail": i18n_translate(
                "dashboard.progress_item_guidance_detail",
                lang=lang,
                default="Use the current user guidance before any stronger control change.",
            ),
        },
        {
            "id": "runbook",
            "label": i18n_translate(
                "dashboard.progress_item_runbook",
                lang=lang,
                default="Prepare the reviewed runbook path",
            ),
            "detail": i18n_translate(
                "dashboard.progress_item_runbook_detail",
                lang=lang,
                default="Current reviewed candidate: {title}.",
                title=runbook_title or i18n_translate("dashboard.no_runbook_selected", lang=lang, default="No runbook selected."),
            ),
        },
    ]


def _operator_progress_default_prompt(summary: Dict[str, Any], *, lang: str) -> str:
    noc_focus = summary.get("noc_focus") if isinstance(summary.get("noc_focus"), dict) else {}
    client_view = noc_focus.get("client_identity_view") if isinstance(noc_focus.get("client_identity_view"), dict) else {}
    attention_count = _as_int(client_view.get("attention_count"), 0)
    internet_check = str(((noc_focus.get("path_health") or {}) if isinstance(noc_focus.get("path_health"), dict) else {}).get("internet_check") or "").upper()
    if attention_count > 1:
        return i18n_translate(
            "dashboard.progress_blocked_prompt_many_clients",
            lang=lang,
            default="Ask whether all affected users are seeing the same symptom or only one area is failing.",
        )
    if attention_count == 1:
        return i18n_translate(
            "dashboard.progress_blocked_prompt_one_client",
            lang=lang,
            default="Ask which exact device is affected and what the user sees on screen.",
        )
    if internet_check == "FAIL":
        return i18n_translate(
            "dashboard.progress_blocked_prompt_uplink",
            lang=lang,
            default="Ask whether any external site is reachable from one test device before changing mode.",
        )
    return i18n_translate(
        "dashboard.progress_blocked_prompt_default",
        lang=lang,
        default="Ask what changed first, when it started, and whether this is one device or many.",
    )


def _operator_progress_payload(
    summary: Dict[str, Any],
    actions: Dict[str, Any],
    *,
    session_id: str,
    lang: str,
) -> Dict[str, Any]:
    normalized_session = _normalize_progress_session_id(session_id)
    items = _operator_progress_default_items(summary, actions, lang=lang)
    stored = {}
    if normalized_session:
        stored = (_operator_progress_store().get("sessions") or {}).get(normalized_session) or {}
    done_map = stored.get("items") if isinstance(stored.get("items"), dict) else {}
    payload_items: List[Dict[str, Any]] = []
    for item in items:
        item_id = str(item.get("id") or "")
        stored_item = done_map.get(item_id) if isinstance(done_map.get(item_id), dict) else {}
        payload_items.append(
            {
                "id": item_id,
                "label": str(item.get("label") or ""),
                "detail": str(item.get("detail") or ""),
                "done": bool(stored_item.get("done")),
            }
        )
    next_item = next((item for item in payload_items if not item["done"]), None)
    blocked_reason = str(stored.get("blocked_reason") or "").strip()
    blocked_prompt = str(stored.get("blocked_prompt") or "").strip() or _operator_progress_default_prompt(summary, lang=lang)
    done_count = sum(1 for item in payload_items if item["done"])
    return {
        "session_id": normalized_session,
        "items": payload_items,
        "done_count": done_count,
        "total_count": len(payload_items),
        "next_item": next_item,
        "blocked": bool(blocked_reason),
        "blocked_reason": blocked_reason,
        "blocked_prompt": blocked_prompt,
        "last_updated": str(stored.get("last_updated") or ""),
    }


def _save_operator_progress(
    *,
    session_id: str,
    item_id: str | None = None,
    done: bool | None = None,
    blocked_reason: str | None = None,
    blocked_prompt: str | None = None,
    clear_blocked: bool = False,
) -> Dict[str, Any]:
    normalized_session = _normalize_progress_session_id(session_id)
    if not normalized_session:
        raise ValueError("session_id_required")
    store = _operator_progress_store()
    sessions = store.setdefault("sessions", {})
    session_payload = sessions.get(normalized_session) if isinstance(sessions.get(normalized_session), dict) else {}
    if not session_payload:
        session_payload = {"created_at": datetime.now().isoformat(), "items": {}}
        sessions[normalized_session] = session_payload
    items = session_payload.get("items") if isinstance(session_payload.get("items"), dict) else {}
    session_payload["items"] = items
    if item_id:
        entry = items.get(item_id) if isinstance(items.get(item_id), dict) else {}
        if done is not None:
            entry["done"] = bool(done)
        items[item_id] = entry
    if clear_blocked:
        session_payload["blocked_reason"] = ""
        session_payload["blocked_prompt"] = ""
    else:
        if blocked_reason is not None:
            session_payload["blocked_reason"] = str(blocked_reason).strip()
        if blocked_prompt is not None:
            session_payload["blocked_prompt"] = str(blocked_prompt).strip()
    session_payload["last_updated"] = datetime.now().isoformat()
    _write_json_file(OPERATOR_PROGRESS_PATH, store)
    return session_payload


def _remote_peer_view_payload(state: Dict[str, Any]) -> Dict[str, Any]:
    noc_capacity = state.get("noc_capacity") if isinstance(state.get("noc_capacity"), dict) else {}
    top_sources = noc_capacity.get("top_sources") if isinstance(noc_capacity.get("top_sources"), list) else []
    managed_cidrs = _managed_client_cidrs()
    excluded_ips = _client_identity_excluded_ips(state)
    items: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for row in top_sources[:12]:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("src_ip") or row.get("id") or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        if ip in excluded_ips:
            continue
        if _ip_in_managed_client_scope(ip, managed_cidrs):
            continue
        items.append(
            {
                "id": ip,
                "label": ip,
                "bytes": _as_int(row.get("bytes"), 0),
                "packets": _as_int(row.get("packets"), 0),
                "flows": _as_int(row.get("flows"), 0),
            }
        )
    items.sort(key=lambda item: (-_as_int(item.get("bytes"), 0), str(item.get("id") or "")))
    return {
        "count": len(items),
        "items": items[:8],
    }


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


def _primary_anomaly_card_payload(
    state: Dict[str, Any],
    advisory: Dict[str, Any],
    guidance: Dict[str, List[str]],
) -> Dict[str, Any]:
    lang = _request_lang()
    internal = state.get("internal") if isinstance(state.get("internal"), dict) else {}
    connection = state.get("connection") if isinstance(state.get("connection"), dict) else {}
    network_health = state.get("network_health") if isinstance(state.get("network_health"), dict) else {}
    blast_radius = state.get("noc_blast_radius") if isinstance(state.get("noc_blast_radius"), dict) else {}
    monitoring = state.get("monitoring") if isinstance(state.get("monitoring"), dict) else {}
    second_pass_detail = state.get("second_pass") if isinstance(state.get("second_pass"), dict) else {}
    if not second_pass_detail and isinstance(advisory.get("second_pass"), dict):
        second_pass_detail = advisory.get("second_pass")
    second_pass_soc = second_pass_detail.get("soc") if isinstance(second_pass_detail.get("soc"), dict) else {}

    critical = _as_int(state.get("suricata_critical"), 0)
    warning = _as_int(state.get("suricata_warning"), 0)
    suspicion = _as_int(internal.get("suspicion"), 0)
    attack_type = str(advisory.get("attack_type") or "").strip()
    soc_status = str(second_pass_soc.get("status") or "").lower()
    signals = network_health.get("signals") if isinstance(network_health.get("signals"), list) else []
    internet_check = str(connection.get("internet_check") or "").upper()
    affected_clients = _as_int(blast_radius.get("affected_client_count"), 0)
    critical_clients = _as_int(blast_radius.get("critical_client_count"), 0)
    off_services = [
        name for name in ("suricata", "opencanary", "ntfy")
        if str(monitoring.get(name) or "").upper() == "OFF"
    ]

    candidates: List[Dict[str, Any]] = []

    if critical > 0 or soc_status in {"critical", "high"}:
        candidates.append(
            {
                "severity": "critical",
                "source": "soc",
                "title": "SOC critical evidence detected" if lang == "en" else "SOC 重大根拠を検知",
                "what_happened": (
                    f"direct critical={critical}, attack={attack_type or '-'}"
                    if lang == "en"
                    else f"direct critical={critical}、attack={attack_type or '-'}"
                ),
                "impact": (
                    "A stronger security response may be required if this trend persists."
                    if lang == "en"
                    else "この傾向が続く場合、より強いセキュリティ対応が必要になる可能性があります。"
                ),
            }
        )
    elif warning > 0 or suspicion >= 60 or soc_status in {"elevated", "watch", "medium"}:
        candidates.append(
            {
                "severity": "warning",
                "source": "soc",
                "title": "SOC warning signals detected" if lang == "en" else "SOC 警戒シグナルを検知",
                "what_happened": (
                    f"warning={warning}, suspicion={suspicion}, attack={attack_type or '-'}"
                    if lang == "en"
                    else f"warning={warning}、suspicion={suspicion}、attack={attack_type or '-'}"
                ),
                "impact": (
                    "Escalation readiness should be maintained while evidence is confirmed."
                    if lang == "en"
                    else "根拠確定までエスカレーション準備を維持してください。"
                ),
            }
        )

    if internet_check == "FAIL" or signals:
        noc_severity = "critical" if (internet_check == "FAIL" and critical_clients > 0) else "warning"
        candidates.append(
            {
                "severity": noc_severity,
                "source": "noc",
                "title": "NOC path/service anomaly detected" if lang == "en" else "NOC 経路/サービス異常を検知",
                "what_happened": (
                    f"internet={internet_check or '-'}, signals={len(signals)}, affected_clients={affected_clients}"
                    if lang == "en"
                    else f"internet={internet_check or '-'}、signals={len(signals)}、affected_clients={affected_clients}"
                ),
                "impact": (
                    "User connectivity can degrade quickly across impacted segments."
                    if lang == "en"
                    else "影響セグメントで利用者の接続性が急速に低下する可能性があります。"
                ),
            }
        )

    if off_services:
        candidates.append(
            {
                "severity": "warning",
                "source": "noc",
                "title": "Core monitoring service is OFF" if lang == "en" else "コア監視サービスが OFF",
                "what_happened": f"off_services={','.join(off_services)}",
                "impact": (
                    "Operator visibility is reduced until monitoring coverage is restored."
                    if lang == "en"
                    else "監視カバレッジが復旧するまで、運用可視性が低下します。"
                ),
            }
        )

    severity_rank = {"none": 0, "info": 1, "warning": 2, "critical": 3}
    source_rank = {"soc": 0, "noc": 1, "runtime": 2}
    selected = None
    if candidates:
        selected = sorted(
            candidates,
            key=lambda item: (
                -severity_rank.get(str(item.get("severity") or "").lower(), 0),
                source_rank.get(str(item.get("source") or ""), 9),
            ),
        )[0]

    do_now = [str(item) for item in guidance.get("do_next", []) if str(item).strip()][:3]
    dont_do = [str(item) for item in guidance.get("do_not_do", []) if str(item).strip()][:3]

    if selected is None:
        return {
            "status": "none",
            "severity": "none",
            "source": "none",
            "title": "No primary anomaly right now" if lang == "en" else "現在の主要異常はありません",
            "what_happened": (
                "No SOC/NOC anomaly has been selected as the current primary trigger."
                if lang == "en"
                else "SOC/NOC で主要トリガーとして選ぶべき異常は現在ありません。"
            ),
            "impact": (
                "Keep the normal baseline visible and continue routine monitoring."
                if lang == "en"
                else "正常ベースラインを維持し、通常監視を継続してください。"
            ),
            "do_now": do_now,
            "dont_do": dont_do,
        }

    return {
        "status": "anomaly",
        "severity": str(selected.get("severity") or "warning"),
        "source": str(selected.get("source") or "noc"),
        "title": str(selected.get("title") or ""),
        "what_happened": str(selected.get("what_happened") or ""),
        "impact": str(selected.get("impact") or ""),
        "do_now": do_now,
        "dont_do": dont_do,
    }


def _decision_trust_capsule_payload(
    state: Dict[str, Any],
    metrics: Dict[str, Any],
    guidance: Dict[str, List[str]],
    review: Dict[str, Any],
    decision_path: Dict[str, Any],
    *,
    lang: str,
) -> Dict[str, Any]:
    tr = lambda key, default=None, **kwargs: i18n_translate(key, lang=lang, default=default, **kwargs)
    now_epoch = time.time()
    snapshot_age = _age_seconds(state.get("snapshot_epoch"), now_epoch=now_epoch)
    ai_age = _age_seconds(metrics.get("last_update_ts"), now_epoch=now_epoch)
    second_pass_status = str(decision_path.get("second_pass_status") or "pending").strip().lower()
    evidence_count = _as_int(decision_path.get("second_pass_evidence_count"), 0)
    why_this = [str(item) for item in (guidance.get("why_now") or []) if str(item).strip()][:3]
    unknowns: List[str] = []
    freshness_unknown = False
    execution_unknown = False

    if snapshot_age is None:
        freshness_unknown = True
        _append_unique(unknowns, tr("dashboard.trust_unknown_snapshot_missing", default="Snapshot time is unavailable."))
    elif snapshot_age > DASHBOARD_SNAPSHOT_STALE_SEC:
        freshness_unknown = True
        _append_unique(
            unknowns,
            tr("dashboard.trust_unknown_snapshot_stale", default="Snapshot is stale ({age}s old).", age=int(round(snapshot_age))),
        )

    if ai_age is None:
        freshness_unknown = True
        _append_unique(unknowns, tr("dashboard.trust_unknown_ai_metrics_missing", default="AI metrics time is unavailable."))
    elif ai_age > DASHBOARD_AI_STALE_SEC:
        freshness_unknown = True
        _append_unique(
            unknowns,
            tr("dashboard.trust_unknown_ai_metrics_stale", default="AI metrics are stale ({age}s old).", age=int(round(ai_age))),
        )

    if second_pass_status in {"pending", "running"}:
        execution_unknown = True
        _append_unique(unknowns, tr("dashboard.trust_unknown_second_pass_pending", default="Deterministic second-pass is not finished yet."))
    elif second_pass_status in {"failed", "error"}:
        execution_unknown = True
        _append_unique(unknowns, tr("dashboard.trust_unknown_second_pass_failed", default="Deterministic second-pass did not complete successfully."))

    if not review.get("final_status"):
        _append_unique(unknowns, tr("dashboard.trust_unknown_review_missing", default="Runbook review status is not available."))

    if not why_this:
        _append_unique(unknowns, tr("dashboard.trust_unknown_reasoning_thin", default="Reasoning detail is still thin."))

    if second_pass_status in {"done", "complete", "completed", "ready"} and evidence_count > 0:
        confidence_source = tr("dashboard.trust_confidence_source_second_pass", default="Deterministic second-pass with live evidence support")
        confidence_label = tr("dashboard.trust_confidence_high", default="HIGH")
        tone = "safe" if not unknowns else "neutral"
    elif evidence_count > 0:
        confidence_source = tr("dashboard.trust_confidence_source_live_evidence", default="Live evidence and first-pass recommendation")
        confidence_label = tr("dashboard.trust_confidence_medium", default="MEDIUM")
        tone = "neutral" if not unknowns else "caution"
    else:
        confidence_source = tr("dashboard.trust_confidence_source_first_pass", default="First-pass recommendation with limited supporting evidence")
        confidence_label = tr("dashboard.trust_confidence_limited", default="LIMITED")
        tone = "caution"

    if second_pass_status in {"failed", "error"}:
        tone = "danger"
        confidence_label = tr("dashboard.trust_confidence_limited", default="LIMITED")
    elif freshness_unknown or execution_unknown:
        tone = "caution"

    first_reason = why_this[0] if why_this else tr("dashboard.waiting_causal_summary_ui", default="Waiting for causal summary.")
    beginner_summary = tr(
        "dashboard.trust_beginner_summary",
        default="Why: {reason} | Confidence: {confidence}",
        reason=first_reason,
        confidence=confidence_label,
    )
    professional_summary = tr(
        "dashboard.trust_professional_summary",
        default="{source} | evidence={evidence} | unknowns={unknowns}",
        source=confidence_source,
        evidence=evidence_count,
        unknowns=len(unknowns),
    )

    return {
        "tone": tone,
        "beginner_summary": beginner_summary[:220],
        "professional_summary": professional_summary[:260],
        "why_this": why_this,
        "confidence_source": confidence_source,
        "confidence_label": confidence_label,
        "unknowns": unknowns[:3],
        "evidence_count": evidence_count,
        "review_status": str(review.get("final_status") or ""),
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
    topolite_mode = _read_topolite_seed_mode()
    synthetic_story = (
        _build_topolite_synthetic_story(str(topolite_mode.get("seed_id") or "topolite-default"))
        if str(topolite_mode.get("mode") or "live") == "synthetic"
        else {}
    )
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


def _dashboard_alert_queues_payload(state: Dict[str, Any], recent_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    now_threshold = max(0, min(100, _as_int(ALERT_QUEUE_NOW_THRESHOLD, 80)))
    watch_threshold = max(0, min(now_threshold, _as_int(ALERT_QUEUE_WATCH_THRESHOLD, 50)))
    escalate_threshold = max(now_threshold, min(100, _as_int(ALERT_QUEUE_ESCALATE_THRESHOLD, 90)))
    now_items: List[Dict[str, Any]] = []
    watch_items: List[Dict[str, Any]] = []
    backlog_items: List[Dict[str, Any]] = []
    escalation_candidates: List[Dict[str, Any]] = []
    for alert in recent_alerts:
        risk = _as_int(alert.get("risk_score"), 0)
        severity = _as_int(alert.get("severity"), 0)
        recommendation = str(alert.get("recommendation") or "").lower()
        compact = {
            "ts_iso": str(alert.get("ts_iso") or ""),
            "src_ip": str(alert.get("src_ip") or ""),
            "dst_ip": str(alert.get("dst_ip") or ""),
            "sid": _as_int(alert.get("sid"), 0),
            "risk_score": risk,
            "risk_level": str(alert.get("risk_level") or ""),
            "attack_type": str(alert.get("attack_type") or ""),
            "recommendation": str(alert.get("recommendation") or ""),
        }
        if risk >= now_threshold:
            now_items.append(compact)
        elif risk >= watch_threshold:
            watch_items.append(compact)
        else:
            backlog_items.append(compact)

        if risk >= escalate_threshold or "isolate" in recommendation or "redirect" in recommendation or "throttle" in recommendation or (severity > 0 and severity <= 1):
            escalation_candidates.append(compact)

    second_pass_soc = state.get("second_pass_soc") if isinstance(state.get("second_pass_soc"), dict) else {}
    suppression = second_pass_soc.get("suppression_exception_state") if isinstance(second_pass_soc.get("suppression_exception_state"), dict) else {}
    return {
        "now": {"count": len(now_items), "items": now_items[:5]},
        "watch": {"count": len(watch_items), "items": watch_items[:5]},
        "backlog": {"count": len(backlog_items), "items": backlog_items[:5]},
        "escalation_candidates": escalation_candidates[:5],
        "suppression": {
            "status": str(suppression.get("status") or "normal"),
            "suppressed_count": _as_int(suppression.get("suppressed_count"), _as_int(second_pass_soc.get("suppressed_count"), 0)),
            "exception_count": _as_int(suppression.get("exception_count"), 0),
        },
        "thresholds": {
            "now": now_threshold,
            "watch": watch_threshold,
            "escalate": escalate_threshold,
        },
    }


def _dashboard_alert_aggregation_payload(recent_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    now_epoch = time.time()
    suppression_window = max(30, int(ALERT_SUPPRESSION_WINDOW_SEC))
    aggregation_window = max(suppression_window, int(ALERT_AGGREGATION_WINDOW_SEC))
    escalation_count = max(2, int(ALERT_ESCALATION_COUNT_THRESHOLD))
    groups: Dict[str, Dict[str, Any]] = {}
    for alert in recent_alerts:
        ts = _as_float(alert.get("ts"), 0.0)
        if ts <= 0 or now_epoch - ts > aggregation_window:
            continue
        src = str(alert.get("src_ip") or "-")
        dst = str(alert.get("dst_ip") or "-")
        sid = _as_int(alert.get("sid"), 0)
        attack_type = str(alert.get("attack_type") or "-")
        risk_level = str(alert.get("risk_level") or "-")
        key = f"{src}|{dst}|{sid}|{attack_type}|{risk_level}"
        row = groups.setdefault(
            key,
            {
                "key": key,
                "src_ip": src,
                "dst_ip": dst,
                "sid": sid,
                "attack_type": attack_type,
                "risk_level": risk_level,
                "first_ts": ts,
                "last_ts": ts,
                "count": 0,
                "suppressed_count": 0,
                "risk_score_max": 0,
                "recommendation": str(alert.get("recommendation") or ""),
            },
        )
        row["count"] = _as_int(row.get("count"), 0) + 1
        row["first_ts"] = min(_as_float(row.get("first_ts"), ts), ts)
        row["last_ts"] = max(_as_float(row.get("last_ts"), ts), ts)
        row["risk_score_max"] = max(_as_int(row.get("risk_score_max"), 0), _as_int(alert.get("risk_score"), 0))

    group_items = sorted(groups.values(), key=lambda x: (_as_int(x.get("count"), 0), _as_int(x.get("risk_score_max"), 0)), reverse=True)
    summaries: List[Dict[str, Any]] = []
    escalations: List[Dict[str, Any]] = []
    suppressed_total = 0
    for row in group_items:
        count = _as_int(row.get("count"), 0)
        suppressed = max(0, count - 1)
        row["suppressed_count"] = suppressed
        suppressed_total += suppressed
        last_ts = _as_float(row.get("last_ts"), 0.0)
        escalated = bool(count >= escalation_count or _as_int(row.get("risk_score_max"), 0) >= ALERT_QUEUE_ESCALATE_THRESHOLD)
        summary = {
            "key": str(row.get("key") or ""),
            "src_ip": str(row.get("src_ip") or ""),
            "dst_ip": str(row.get("dst_ip") or ""),
            "sid": _as_int(row.get("sid"), 0),
            "attack_type": str(row.get("attack_type") or ""),
            "risk_level": str(row.get("risk_level") or ""),
            "risk_score_max": _as_int(row.get("risk_score_max"), 0),
            "count": count,
            "suppressed_count": suppressed,
            "first_ts_iso": _iso_from_epoch(_as_float(row.get("first_ts"), 0.0)),
            "last_ts_iso": _iso_from_epoch(last_ts),
            "recently_suppressed": bool(now_epoch - last_ts <= suppression_window and suppressed > 0),
            "escalated": escalated,
            "reason": (
                f"count>={escalation_count}"
                if count >= escalation_count
                else (f"risk>={ALERT_QUEUE_ESCALATE_THRESHOLD}" if _as_int(row.get("risk_score_max"), 0) >= ALERT_QUEUE_ESCALATE_THRESHOLD else "normal")
            ),
            "notification_summary": f"{count} similar alerts from {row.get('src_ip')} to {row.get('dst_ip')} in {aggregation_window}s",
        }
        summaries.append(summary)
        if escalated:
            escalations.append(summary)
    return {
        "window_sec": aggregation_window,
        "suppression_window_sec": suppression_window,
        "escalation_count_threshold": escalation_count,
        "group_count": len(summaries),
        "suppressed_total": suppressed_total,
        "groups": summaries[:10],
        "escalation_queue": escalations[:10],
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


def _read_topolite_seed_mode() -> Dict[str, Any]:
    fallback = {"mode": "live", "seed_id": "topolite-default", "updated_at": time.time(), "updated_by": "system"}
    try:
        if TOPOLITE_SEED_MODE_PATH.exists():
            data = json.loads(TOPOLITE_SEED_MODE_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                mode = str(data.get("mode") or "live").strip().lower()
                if mode not in {"live", "synthetic"}:
                    mode = "live"
                return {
                    "mode": mode,
                    "seed_id": str(data.get("seed_id") or "topolite-default"),
                    "updated_at": _as_float(data.get("updated_at"), time.time()),
                    "updated_by": str(data.get("updated_by") or "unknown"),
                }
    except Exception:
        pass
    return fallback


def _write_topolite_seed_mode(mode: str, seed_id: str, updated_by: str) -> Dict[str, Any]:
    payload = {
        "mode": "synthetic" if str(mode).lower() == "synthetic" else "live",
        "seed_id": str(seed_id or "topolite-default"),
        "updated_at": time.time(),
        "updated_by": str(updated_by or "unknown"),
    }
    TOPOLITE_SEED_MODE_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOPOLITE_SEED_MODE_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def _build_topolite_synthetic_story(seed_id: str) -> Dict[str, Any]:
    digest = hashlib.sha256(str(seed_id).encode("utf-8")).hexdigest()
    n1 = int(digest[0:2], 16)
    n2 = int(digest[2:4], 16)
    n3 = int(digest[4:6], 16)
    base_latency = 40 + (n1 % 35)
    drop_pct = 2 + (n2 % 8)
    impacted = 1 + (n3 % 5)
    topology = [
        {"id": "gw-br0", "kind": "gateway", "label": "Azazel Gateway (br0)", "state": "watch"},
        {"id": "dns-resolver", "kind": "service", "label": "Resolver", "state": "degraded"},
        {"id": "client-segment-a", "kind": "segment", "label": f"Clients {impacted}", "state": "affected"},
    ]
    timeline = [
        {"ts_iso": "synthetic", "title": "Gateway jitter observed", "detail": f"latency={base_latency}ms", "kind": "topolite_synthetic"},
        {"ts_iso": "synthetic", "title": "Resolver instability", "detail": f"packet_loss={drop_pct}%", "kind": "topolite_synthetic"},
        {"ts_iso": "synthetic", "title": "Segment impact estimated", "detail": f"affected_clients={impacted}", "kind": "topolite_synthetic"},
    ]
    return {
        "seed_id": str(seed_id),
        "topology": topology,
        "timeline": timeline,
        "story_id": f"seed:{seed_id}",
    }


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
    ai_governance = _dashboard_ai_governance_payload(metrics, now_epoch=now_epoch)
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
    monitor_scope = state.get("monitor_scope") if isinstance(state.get("monitor_scope"), dict) else {}
    topolite_mode = _read_topolite_seed_mode()
    synthetic_story = (
        _build_topolite_synthetic_story(str(topolite_mode.get("seed_id") or "topolite-default"))
        if str(topolite_mode.get("mode") or "live") == "synthetic"
        else {}
    )
    client_identity_view = _client_identity_view_payload(state)
    remote_peer_view = _remote_peer_view_payload(state)
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
        "topolite": {
            "mode": str(topolite_mode.get("mode") or "live"),
            "seed_id": str(topolite_mode.get("seed_id") or "topolite-default"),
            "data_source": "synthetic" if str(topolite_mode.get("mode") or "live") == "synthetic" else "live",
            "watermark": "SYNTHETIC DATA - NOT LIVE EVIDENCE" if str(topolite_mode.get("mode") or "live") == "synthetic" else "",
            "story": synthetic_story if isinstance(synthetic_story, dict) else {},
        },
        "service_health_summary": service_summary,
        "current_recommendation": str(state.get("recommendation") or advisory.get("recommendation") or ""),
        "normal_assurance": _normal_assurance_payload(
            state=state,
            metrics=metrics,
            service_summary=service_summary,
            snapshot_age=snapshot_age,
            ai_age=ai_age,
            network_health=network_health,
        ),
        "command_strip": {
            "current_mode": str(mode.get("current_mode") or "shield"),
            "current_risk": str(state.get("user_state") or ""),
            "current_uplink": str(state.get("up_if") or ""),
            "internet_reachability": str(connection.get("internet_check") or ""),
            "direct_critical_count": _as_int(state.get("suricata_critical"), 0),
            "deferred_count": _as_int(metrics.get("deferred_count"), 0),
            "ai_contribution_rate": _as_float((ai_governance.get("rates") or {}).get("ai_contribution"), 0.0),
            "ai_fallback_rate": _as_float((ai_governance.get("rates") or {}).get("fallback"), 0.0),
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
                "monitor_scope": {
                    "mode": str(monitor_scope.get("mode") or "internal"),
                    "label": str(monitor_scope.get("label") or "internal:br0 (172.16.0.0/24)"),
                    "interface": str(monitor_scope.get("up_if") or "br0"),
                    "cidr": str(monitor_scope.get("cidr") or "172.16.0.0/24"),
                },
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
            "client_identity_view": client_identity_view,
            "remote_peers": remote_peer_view,
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


def _dashboard_actions_payload(
    state: Dict[str, Any],
    advisory: Dict[str, Any],
    metrics: Dict[str, Any],
    llm_rows: List[Dict[str, Any]],
    *,
    audience: str | None = None,
    surface: str | None = None,
) -> Dict[str, Any]:
    lang = _request_lang()
    audience_norm = _normalize_mio_audience(audience, default="beginner")
    surface_norm = _normalize_mio_surface(surface or "dashboard", default="dashboard")
    latest_ai = _dashboard_visible_ai_context(state, advisory, llm_rows)
    noc_runbook_support = _dashboard_noc_runbook_support(state, lang=lang)
    selected_runbook_id = str(latest_ai.get("runbook_id") or noc_runbook_support.get("runbook_candidate_id") or "")
    suggested_runbook = _runbook_brief(selected_runbook_id, lang=lang)
    guidance = _dashboard_action_guidance(state, advisory, latest_ai, suggested_runbook, noc_runbook_support=noc_runbook_support)
    primary_anomaly_card = _primary_anomaly_card_payload(state, advisory, guidance)
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
    decision_path = {
        "first_pass_engine": str(first_pass.get("engine") or "tactical_scorer_v1"),
        "first_pass_role": str(first_pass.get("role") or "first_minute_triage"),
        "second_pass_engine": str(second_pass.get("engine") or "soc_evaluator_v1"),
        "second_pass_role": str(second_pass.get("role") or "second_pass_evaluation"),
        "second_pass_status": str(second_pass.get("status") or second_pass_detail.get("status") or "pending"),
        "second_pass_evidence_count": _as_int(second_pass.get("evidence_count") or second_pass_detail.get("evidence_count"), 0),
        "second_pass_flow_support_count": _as_int(second_pass.get("flow_support_count") or second_pass_detail.get("flow_support_count"), 0),
        "soc_status": str(((second_pass_detail.get("soc") or {}) if isinstance(second_pass_detail.get("soc"), dict) else {}).get("status") or ""),
        "ai_role": "supplemental_operator_assist",
    }
    decision_trust_capsule = _decision_trust_capsule_payload(
        state,
        metrics,
        guidance,
        review,
        decision_path,
        lang=lang,
    )
    mio_model_payload = {
        "answer": str(latest_ai.get("answer") or ""),
        "user_message": user_guidance[:160],
        "runbook_id": selected_runbook_id,
        "runbook_review": review,
        "rationale": rationale[:4],
        "do_next": guidance["do_next"][:3],
        "current_operator_actions": guidance["do_next"][:3],
        "handoff": _assist_handoff_payload(),
    }
    mio_bundle = _compose_mio_message_bundle(
        mio_model_payload,
        audience=audience_norm,
        lang=lang,
        surface=surface_norm,
    )
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
        "primary_anomaly_card": primary_anomaly_card,
        "decision_trust_capsule": decision_trust_capsule,
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
            "message_profile": mio_bundle["profile"],
            "surface_message": mio_bundle["surface_message"],
            "surface_messages": mio_bundle["surface_messages"],
        },
        "mio_message_profile": mio_bundle["profile"],
        "mio_surface_messages": mio_bundle["surface_messages"],
        "links": {
            "ask_mio": "/ops-comm",
            "mattermost": MATTERMOST_OPEN_URL,
        },
        "decision_path": decision_path,
        "soc_priority": {
            "status": triage_status or "idle",
            "now": triage_now[:8],
            "watch": triage_watch[:8],
            "backlog": triage_backlog[:8],
            "top_priority_ids": triage_state.get("top_priority_ids") if isinstance(triage_state.get("top_priority_ids"), list) else [],
        },
    }


def _handoff_brief_pack_payload(
    summary: Dict[str, Any],
    actions: Dict[str, Any],
    health: Dict[str, Any],
    progress: Dict[str, Any],
    *,
    lang: str,
) -> Dict[str, Any]:
    noc_focus = summary.get("noc_focus") if isinstance(summary.get("noc_focus"), dict) else {}
    client_view = noc_focus.get("client_identity_view") if isinstance(noc_focus.get("client_identity_view"), dict) else {}
    clients = client_view.get("items") if isinstance(client_view.get("items"), list) else []
    affected_clients = [
        {
            "label": str(item.get("display_name") or item.get("ip") or "-"),
            "state": str(item.get("state") or "unknown"),
            "ip": str(item.get("ip") or "-"),
            "segment": str(item.get("interface_or_segment") or item.get("interface_family") or "-"),
        }
        for item in clients
        if bool(item.get("requires_attention"))
    ][:5]
    primary = actions.get("primary_anomaly_card") if isinstance(actions.get("primary_anomaly_card"), dict) else {}
    trust = actions.get("decision_trust_capsule") if isinstance(actions.get("decision_trust_capsule"), dict) else {}
    stale_flags = health.get("stale_flags") if isinstance(health.get("stale_flags"), dict) else {}
    timestamps = summary.get("timestamps") if isinstance(summary.get("timestamps"), dict) else {}
    done_items = [
        str(item.get("label") or "")
        for item in (progress.get("items") or [])
        if isinstance(item, dict) and bool(item.get("done"))
    ]
    posture = " | ".join(
        [
            f"mode={str(((summary.get('mode') or {}) if isinstance(summary.get('mode'), dict) else {}).get('current_mode') or '-').upper()}",
            f"risk={str(((summary.get('risk') or {}) if isinstance(summary.get('risk'), dict) else {}).get('user_state') or '-').upper()}",
            f"path={str(((noc_focus.get('path_health') or {}) if isinstance(noc_focus.get('path_health'), dict) else {}).get('status') or '-').upper()}",
            f"internet={str(((summary.get('uplink') or {}) if isinstance(summary.get('uplink'), dict) else {}).get('internet_check') or '-').upper()}",
        ]
    )
    anomaly_title = str(primary.get("title") or "")
    anomaly_detail = str(primary.get("what_happened") or "")
    if str(primary.get("status") or "none") == "none" or not anomaly_title:
        anomaly_title = i18n_translate("dashboard.handoff_no_primary_anomaly", lang=lang, default="No primary anomaly selected.")
        anomaly_detail = i18n_translate("dashboard.handoff_no_primary_anomaly_detail", lang=lang, default="The dashboard does not currently have a single dominant anomaly.")
    generated_at = datetime.now().isoformat()
    none_text = i18n_translate("dashboard.handoff_none", lang=lang, default="none")
    brief_text = "\n".join(
        [
            i18n_translate("dashboard.handoff_title", lang=lang, default="Handoff Brief Pack"),
            i18n_translate("dashboard.handoff_generated", lang=lang, default="Generated: {ts}", ts=generated_at),
            i18n_translate(
                "dashboard.handoff_snapshot",
                lang=lang,
                default="Snapshot: {snapshot} | stale snapshot={snapshot_stale} ai={ai_stale}",
                snapshot=str(timestamps.get("snapshot_at") or "-"),
                snapshot_stale="yes" if stale_flags.get("snapshot") else "no",
                ai_stale="yes" if stale_flags.get("ai_metrics") else "no",
            ),
            i18n_translate("dashboard.handoff_posture", lang=lang, default="Current posture: {value}", value=posture),
            i18n_translate(
                "dashboard.handoff_trust",
                lang=lang,
                default="Decision trust: {value}",
                value=str(trust.get("professional_summary") or trust.get("beginner_summary") or "-"),
            ),
            i18n_translate("dashboard.handoff_primary_anomaly", lang=lang, default="Primary anomaly: {title}", title=anomaly_title),
            i18n_translate("dashboard.handoff_primary_detail", lang=lang, default="Anomaly detail: {detail}", detail=anomaly_detail),
            i18n_translate(
                "dashboard.handoff_affected_clients",
                lang=lang,
                default="Affected clients: {value}",
                value=", ".join(f"{item['label']} [{item['state']} / {item['segment']} / {item['ip']}]" for item in affected_clients) or none_text,
            ),
            i18n_translate(
                "dashboard.handoff_actions_done",
                lang=lang,
                default="Actions done: {value}",
                value=", ".join(done_items) or none_text,
            ),
            i18n_translate(
                "dashboard.handoff_do_now",
                lang=lang,
                default="Do now: {value}",
                value=" | ".join([str(item) for item in (actions.get("do_next") or []) if str(item).strip()][:3]) or none_text,
            ),
            i18n_translate(
                "dashboard.handoff_do_not_do",
                lang=lang,
                default="Do not do: {value}",
                value=" | ".join([str(item) for item in (actions.get("do_not_do") or []) if str(item).strip()][:3]) or none_text,
            ),
        ]
    )
    return {
        "current_posture": posture,
        "primary_anomaly": {"title": anomaly_title, "detail": anomaly_detail},
        "affected_clients": affected_clients,
        "actions_done": done_items,
        "do_now": [str(item) for item in (actions.get("do_next") or []) if str(item).strip()][:4],
        "do_not_do": [str(item) for item in (actions.get("do_not_do") or []) if str(item).strip()][:4],
        "timestamps": {
            "generated_at": generated_at,
            "snapshot_at": str(timestamps.get("snapshot_at") or "-"),
            "mode_last_change": str(timestamps.get("mode_last_change") or "-"),
        },
        "stale_flags": {
            "snapshot": bool(stale_flags.get("snapshot")),
            "ai_metrics": bool(stale_flags.get("ai_metrics")),
        },
        "brief_text": brief_text,
        "ops_comm_url": f"/ops-comm?lang={quote(lang)}&audience=operator&message={quote(brief_text)}",
        "mattermost_available": _mattermost_mode() != "disabled",
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
    alert_queues = _dashboard_alert_queues_payload(state, recent_alerts)
    alert_aggregation = _dashboard_alert_aggregation_payload(recent_alerts)
    ai_activity = [_normalize_ai_activity(item) for item in llm_rows[-10:]]
    runbook_events = [_normalize_runbook_event(item) for item in runbook_rows[-10:]]
    triage_audit = [_normalize_triage_audit_event(item) for item in triage_rows[-10:]]
    topolite_mode = _read_topolite_seed_mode()
    is_synthetic = str(topolite_mode.get("mode") or "live") == "synthetic"
    synthetic_story = _build_topolite_synthetic_story(str(topolite_mode.get("seed_id") or "topolite-default")) if is_synthetic else {}
    mode_runtime = get_mode_state()
    sections = _dashboard_evidence_sections(state, advisory, ai_activity, runbook_events, triage_audit, mode_runtime)
    if is_synthetic and isinstance(synthetic_story.get("timeline"), list):
        sections["current_triggers"] = [
            {
                "ts_iso": "synthetic",
                "title": "Synthetic seed mode active",
                "detail": f"seed_id={topolite_mode.get('seed_id')}",
                "kind": "topolite_synthetic",
            },
            *[item for item in synthetic_story.get("timeline", []) if isinstance(item, dict)],
        ][:6]
    return {
        "ok": True,
        "data_source": "synthetic" if is_synthetic else "live",
        "watermark": "SYNTHETIC DATA - NOT LIVE EVIDENCE" if is_synthetic else "",
        "synthetic_story": synthetic_story if isinstance(synthetic_story, dict) else {},
        "recent_alerts": recent_alerts,
        "recent_ai_activity": ai_activity,
        "recent_runbook_events": runbook_events,
        "recent_triage_audit": triage_audit,
        "recent_mode_changes": _recent_mode_changes(mode_runtime),
        "alert_queues": alert_queues,
        "alert_aggregation": alert_aggregation,
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
    ai_governance = _dashboard_ai_governance_payload(metrics, now_epoch=now_epoch)
    payload = {
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
        "ai_governance": ai_governance,
    }
    _record_dashboard_trend_point(state, metrics, payload, now_epoch=now_epoch)
    return payload


def _dashboard_ai_governance_payload(metrics: Dict[str, Any], *, now_epoch: float | None = None) -> Dict[str, Any]:
    now = float(now_epoch if now_epoch is not None else time.time())
    requests = _as_int(metrics.get("llm_requests"), 0)
    completed = _as_int(metrics.get("llm_completed"), 0)
    fallback_count = _as_int(metrics.get("llm_fallback_count"), 0)
    fallback_rate = _as_float(metrics.get("llm_fallback_rate"), 0.0)
    manual_requests = _as_int(metrics.get("manual_requests"), 0)
    manual_routed = _as_int(metrics.get("manual_routed_count"), 0)
    manual_completed = _as_int(metrics.get("manual_completed"), 0)
    updated_age = _age_seconds(metrics.get("last_update_ts"), now_epoch=now)
    stale = bool(updated_age is not None and updated_age > DASHBOARD_AI_STALE_SEC)

    contribution_rate = (completed / requests) if requests > 0 else 0.0
    manual_route_rate = (manual_routed / manual_requests) if manual_requests > 0 else 0.0
    unknown = bool(requests <= 0 or updated_age is None)
    status = "unknown" if unknown else ("stale" if stale else "ok")
    return {
        "ok": True,
        "status": status,
        "stale": stale,
        "unknown": unknown,
        "updated_at": _iso_from_epoch(metrics.get("last_update_ts")),
        "age_sec": updated_age,
        "rates": {
            "ai_contribution": round(contribution_rate, 4),
            "fallback": round(fallback_rate, 4),
            "manual_route": round(manual_route_rate, 4),
        },
        "counts": {
            "llm_requests": requests,
            "llm_completed": completed,
            "llm_fallback_count": fallback_count,
            "manual_requests": manual_requests,
            "manual_routed_count": manual_routed,
            "manual_completed": manual_completed,
        },
    }


def _dashboard_trend_point_payload(
    state: Dict[str, Any],
    metrics: Dict[str, Any],
    health: Dict[str, Any],
    *,
    now_epoch: float | None = None,
) -> Dict[str, Any]:
    now = float(now_epoch if now_epoch is not None else time.time())
    queue = health.get("queue") if isinstance(health.get("queue"), dict) else {}
    llm = health.get("llm") if isinstance(health.get("llm"), dict) else {}
    stale_flags = health.get("stale_flags") if isinstance(health.get("stale_flags"), dict) else {}
    ai_governance = health.get("ai_governance") if isinstance(health.get("ai_governance"), dict) else {}
    rates = ai_governance.get("rates") if isinstance(ai_governance.get("rates"), dict) else {}
    internal = state.get("internal") if isinstance(state.get("internal"), dict) else {}
    noc_capacity = state.get("noc_capacity") if isinstance(state.get("noc_capacity"), dict) else {}
    connection = state.get("connection") if isinstance(state.get("connection"), dict) else {}
    return {
        "ts": now,
        "ts_iso": _iso_from_epoch(now),
        "state": str(state.get("user_state") or ""),
        "queue_depth": _as_int(queue.get("depth"), _as_int(metrics.get("queue_depth"), 0)),
        "queue_capacity": _as_int(queue.get("capacity"), _as_int(metrics.get("queue_capacity"), 0)),
        "queue_max_seen": _as_int(queue.get("max_seen"), _as_int(metrics.get("queue_max_seen"), 0)),
        "llm_fallback_rate": _as_float(llm.get("fallback_rate"), _as_float(metrics.get("llm_fallback_rate"), 0.0)),
        "llm_latency_ms_ema": _as_float(llm.get("latency_ms_ema"), _as_float(metrics.get("llm_latency_ms_ema"), 0.0)),
        "manual_routed_count": _as_int(llm.get("manual_routed_count"), _as_int(metrics.get("manual_routed_count"), 0)),
        "stale_snapshot": bool(stale_flags.get("snapshot")),
        "stale_ai_metrics": bool(stale_flags.get("ai_metrics")),
        "ai_contribution_rate": _as_float(rates.get("ai_contribution"), 0.0),
        "cpu_percent": _as_float(internal.get("cpu_percent"), 0.0),
        "memory_percent": _as_float(internal.get("memory_percent") or internal.get("mem_percent"), 0.0),
        "temperature_c": _as_float(internal.get("temperature_c"), 0.0),
        "iface_utilization_pct": _as_float(noc_capacity.get("utilization_pct"), 0.0),
        "internet_check": str(connection.get("internet_check") or ""),
    }


def _record_dashboard_trend_point(state: Dict[str, Any], metrics: Dict[str, Any], health: Dict[str, Any], *, now_epoch: float | None = None) -> None:
    global _dashboard_trends_last_write_ts
    now = float(now_epoch if now_epoch is not None else time.time())
    with _dashboard_trends_lock:
        if _dashboard_trends_last_write_ts and now - _dashboard_trends_last_write_ts < max(1.0, DASHBOARD_TRENDS_WRITE_INTERVAL_SEC):
            return
        _dashboard_trends_last_write_ts = now
    point = _dashboard_trend_point_payload(state, metrics, health, now_epoch=now)
    _append_jsonl(DASHBOARD_TRENDS_PATH, point)
    try:
        rows = _tail_jsonl(DASHBOARD_TRENDS_PATH, limit=max(DASHBOARD_TRENDS_LIMIT * 2, 120))
        min_ts = now - max(60.0, DASHBOARD_TRENDS_RETENTION_SEC)
        kept = [row for row in rows if _as_float(row.get("ts"), 0.0) >= min_ts]
        if len(kept) > DASHBOARD_TRENDS_LIMIT:
            kept = kept[-DASHBOARD_TRENDS_LIMIT:]
        if len(kept) != len(rows):
            DASHBOARD_TRENDS_PATH.parent.mkdir(parents=True, exist_ok=True)
            DASHBOARD_TRENDS_PATH.write_text(
                "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in kept),
                encoding="utf-8",
            )
    except Exception:
        pass


def _dashboard_trends_payload(limit: int = 120, window_sec: int = 0) -> Dict[str, Any]:
    safe_limit = max(1, min(limit, DASHBOARD_TRENDS_LIMIT))
    rows = _tail_jsonl(DASHBOARD_TRENDS_PATH, limit=max(safe_limit * 2, 40))
    now_epoch = time.time()
    requested_window = max(0, int(window_sec))
    retention = max(60.0, float(requested_window) if requested_window > 0 else DASHBOARD_TRENDS_RETENTION_SEC)
    filtered: List[Dict[str, Any]] = []
    for row in rows:
        ts = _as_float(row.get("ts"), 0.0)
        if ts <= 0:
            continue
        if now_epoch - ts > retention:
            continue
        filtered.append(row)
    points = filtered[-safe_limit:]
    if not points:
        return {
            "ok": True,
            "status": "missing" if not DASHBOARD_TRENDS_PATH.exists() else "empty",
            "storage_warning": "trend_storage_missing_or_empty",
            "points": [],
            "summary": {"samples": 0},
        }

    queue_depth_values = [_as_int(item.get("queue_depth"), 0) for item in points]
    fallback_values = [_as_float(item.get("llm_fallback_rate"), 0.0) for item in points]
    latency_values = [_as_float(item.get("llm_latency_ms_ema"), 0.0) for item in points]
    cpu_values = [_as_float(item.get("cpu_percent"), 0.0) for item in points]
    mem_values = [_as_float(item.get("memory_percent"), 0.0) for item in points]
    temp_values = [_as_float(item.get("temperature_c"), 0.0) for item in points]
    iface_values = [_as_float(item.get("iface_utilization_pct"), 0.0) for item in points]
    snapshot_stale_count = sum(1 for item in points if bool(item.get("stale_snapshot")))
    ai_stale_count = sum(1 for item in points if bool(item.get("stale_ai_metrics")))
    return {
        "ok": True,
        "status": "ok",
        "storage_warning": "",
        "points": points,
        "summary": {
            "samples": len(points),
            "window_sec": int(round(max(0.0, _as_float(points[-1].get("ts"), 0.0) - _as_float(points[0].get("ts"), 0.0)))),
            "queue_depth": {
                "min": min(queue_depth_values),
                "max": max(queue_depth_values),
                "avg": round(sum(queue_depth_values) / len(queue_depth_values), 4),
            },
            "llm_fallback_rate": {
                "min": round(min(fallback_values), 4),
                "max": round(max(fallback_values), 4),
                "avg": round(sum(fallback_values) / len(fallback_values), 4),
            },
            "llm_latency_ms_ema": {
                "min": round(min(latency_values), 2),
                "max": round(max(latency_values), 2),
                "avg": round(sum(latency_values) / len(latency_values), 2),
            },
            "cpu_percent": {
                "min": round(min(cpu_values), 2),
                "max": round(max(cpu_values), 2),
                "avg": round(sum(cpu_values) / len(cpu_values), 2),
            },
            "memory_percent": {
                "min": round(min(mem_values), 2),
                "max": round(max(mem_values), 2),
                "avg": round(sum(mem_values) / len(mem_values), 2),
            },
            "temperature_c": {
                "min": round(min(temp_values), 2),
                "max": round(max(temp_values), 2),
                "avg": round(sum(temp_values) / len(temp_values), 2),
            },
            "iface_utilization_pct": {
                "min": round(min(iface_values), 2),
                "max": round(max(iface_values), 2),
                "avg": round(sum(iface_values) / len(iface_values), 2),
            },
            "stale_flags": {
                "snapshot_count": snapshot_stale_count,
                "ai_metrics_count": ai_stale_count,
            },
        },
    }


def _normalize_role(role: str, default: str = "viewer") -> str:
    role_norm = str(role or "").strip().lower()
    return role_norm if role_norm in _ROLE_RANK else default


def _role_allows(actual_role: str, required_role: str) -> bool:
    return _ROLE_RANK.get(_normalize_role(actual_role), 0) >= _ROLE_RANK.get(_normalize_role(required_role), 0)


def _request_trace_id() -> str:
    header_value = str(request.headers.get("X-Trace-Id") or request.headers.get("X-Azazel-Trace-Id") or "").strip()
    if header_value:
        return header_value[:80]
    body = request.get_json(silent=True) or {}
    if isinstance(body, dict):
        body_trace = str(body.get("trace_id") or "").strip()
        if body_trace:
            return body_trace[:80]
    return ""


def _request_action_hint() -> str:
    endpoint = str(request.endpoint or "")
    path = str(request.path or "")
    if "/api/action/" in path:
        return path.rsplit("/", 1)[-1]
    body = request.get_json(silent=True) or {}
    if isinstance(body, dict):
        explicit = str(body.get("action") or "").strip().lower()
        if explicit:
            return explicit[:64]
    if "runbook" in endpoint:
        action = str((body or {}).get("action") or "").strip().lower()
        runbook_id = str((body or {}).get("runbook_id") or "").strip()
        if runbook_id or action:
            return f"runbook:{action or '-'}:{runbook_id or '-'}"[:120]
    return endpoint[:80]


def _load_mtls_allowlist() -> set[str]:
    allowed = set(AUTH_MTLS_FINGERPRINTS)
    try:
        if AUTH_MTLS_FINGERPRINTS_FILE.exists():
            for line in AUTH_MTLS_FINGERPRINTS_FILE.read_text(encoding="utf-8").splitlines():
                item = line.strip().lower()
                if item and not item.startswith("#"):
                    allowed.add(item)
    except Exception:
        pass
    return allowed


def _load_auth_tokens() -> List[Dict[str, str]]:
    try:
        if AUTH_TOKENS_FILE.exists():
            payload = _parse_json_dict_lenient(AUTH_TOKENS_FILE.read_text(encoding="utf-8"))
            items = payload.get("tokens") if isinstance(payload.get("tokens"), list) else payload.get("items")
            if isinstance(items, list):
                out: List[Dict[str, str]] = []
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    token = str(item.get("token") or "").strip()
                    if not token:
                        continue
                    out.append(
                        {
                            "token": token,
                            "principal": str(item.get("principal") or "unknown").strip() or "unknown",
                            "role": _normalize_role(str(item.get("role") or "viewer"), default="viewer"),
                        }
                    )
                if out:
                    return out
    except Exception:
        pass
    legacy = load_token()
    if legacy:
        return [{"token": legacy, "principal": "legacy-token", "role": "admin"}]
    return []


def _authenticate_request() -> Dict[str, Any]:
    req_token = (
        request.headers.get("X-AZAZEL-TOKEN")
        or request.headers.get("X-Auth-Token")
        or request.args.get("token")
    )
    req_token = str(req_token or "").strip()
    token_items = _load_auth_tokens()
    if not token_items:
        return {"ok": bool(AUTH_FAIL_OPEN), "principal": "anonymous", "role": "admin" if AUTH_FAIL_OPEN else "viewer", "reason": "auth_material_missing"}
    if not req_token:
        return {"ok": False, "principal": "anonymous", "role": "viewer", "reason": "missing_token"}
    for item in token_items:
        if req_token == str(item.get("token") or ""):
            return {"ok": True, "principal": str(item.get("principal") or "unknown"), "role": _normalize_role(str(item.get("role") or "viewer")), "reason": "ok"}
    return {"ok": False, "principal": "anonymous", "role": "viewer", "reason": "token_mismatch"}


def _authorize_mtls(required_role: str) -> Dict[str, Any]:
    if not AUTH_MTLS_REQUIRED:
        return {"ok": True, "reason": "mtls_not_required"}
    if _ROLE_RANK.get(_normalize_role(required_role), 0) < _ROLE_RANK["operator"]:
        return {"ok": True, "reason": "mtls_not_required_for_viewer"}
    observed = str(request.headers.get(AUTH_MTLS_HEADER) or "").strip().lower()
    if not observed:
        return {"ok": False, "reason": "mtls_header_missing"}
    allowlist = _load_mtls_allowlist()
    if not allowlist:
        return {"ok": False, "reason": "mtls_allowlist_empty"}
    if observed not in allowlist:
        return {"ok": False, "reason": "mtls_fingerprint_mismatch"}
    return {"ok": True, "reason": "ok"}


def _audit_authz_event(
    *,
    allowed: bool,
    required_role: str,
    principal: str,
    role: str,
    reason: str,
) -> None:
    try:
        _append_jsonl(
            AUTHZ_AUDIT_LOG,
            {
                "ts": time.time(),
                "trace_id": _request_trace_id(),
                "endpoint": str(request.path or ""),
                "method": str(request.method or ""),
                "requested_action": _request_action_hint(),
                "required_role": _normalize_role(required_role),
                "principal": str(principal or "anonymous"),
                "role": _normalize_role(role),
                "allowed": bool(allowed),
                "reason": str(reason or ""),
                "remote_addr": str(request.remote_addr or ""),
            },
        )
    except Exception as e:
        app.logger.warning(f"authz audit logging failed: {e}")


def _audit_aggregator_event(
    *,
    event: str,
    node_id: str,
    trace_id: str = "",
    reason: str = "",
    **extra: Any,
) -> None:
    try:
        _append_jsonl(
            AGGREGATOR_AUDIT_LOG,
            {
                "ts": time.time(),
                "event": str(event),
                "node_id": str(node_id or ""),
                "trace_id": str(trace_id or _request_trace_id()),
                "principal": str(getattr(g, "auth_principal", "") or ""),
                "reason": str(reason or ""),
                **extra,
            },
        )
    except Exception as e:
        app.logger.warning(f"aggregator audit logging failed: {e}")


def _unauthorized_response(*, ok_payload: Optional[bool] = False, status_code: int = 403) -> tuple[Response, int]:
    if ok_payload is None:
        payload: Dict[str, Any] = {"error": "Unauthorized"}
    else:
        payload = {"ok": bool(ok_payload), "error": "Unauthorized"}
    return jsonify(payload), int(status_code)


def require_token(
    *,
    ok_payload: Optional[bool] = False,
    status_code: int = 403,
    min_role: str = "viewer",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Endpoint decorator that centralizes token verification responses."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            required_role = _normalize_role(min_role, default="viewer")
            auth = _authenticate_request()
            role = _normalize_role(str(auth.get("role") or "viewer"))
            principal = str(auth.get("principal") or "anonymous")
            if not bool(auth.get("ok")):
                _audit_authz_event(
                    allowed=False,
                    required_role=required_role,
                    principal=principal,
                    role=role,
                    reason=str(auth.get("reason") or "auth_failed"),
                )
                if AUTH_FAIL_OPEN:
                    app.logger.warning("AUTH_FAIL_OPEN active: allowing request despite auth failure")
                else:
                    return _unauthorized_response(ok_payload=ok_payload, status_code=status_code)
            mtls = _authorize_mtls(required_role)
            if not bool(mtls.get("ok")):
                _audit_authz_event(
                    allowed=False,
                    required_role=required_role,
                    principal=principal,
                    role=role,
                    reason=str(mtls.get("reason") or "mtls_failed"),
                )
                return _unauthorized_response(ok_payload=ok_payload, status_code=status_code)
            if not _role_allows(role, required_role):
                _audit_authz_event(
                    allowed=False,
                    required_role=required_role,
                    principal=principal,
                    role=role,
                    reason="insufficient_role",
                )
                return _unauthorized_response(ok_payload=ok_payload, status_code=status_code)
            g.auth_principal = principal
            g.auth_role = role
            g.auth_required_role = required_role
            _audit_authz_event(
                allowed=True,
                required_role=required_role,
                principal=principal,
                role=role,
                reason=str(auth.get("reason") or "ok"),
            )
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
        profile = ai_result.get("mio_message_profile") if isinstance(ai_result.get("mio_message_profile"), dict) else {}
        audience = (
            profile.get("audience")
            or ai_result.get("audience")
            or ("beginner" if str(ai_result.get("source") or "").lower() == "temporary" else "operator")
        )
        bundle = _compose_mio_message_bundle(ai_result, audience=audience, lang=lang_norm, surface="mattermost")
        mattermost_summary = str(bundle.get("surface_message") or "").strip()
        if mattermost_summary:
            lines.append(mattermost_summary)
        else:
            answer = str(ai_result.get("answer") or "").strip()
            if answer:
                prefix = "" if answer.startswith("M.I.O.") else "M.I.O.: "
                lines.append(f"{prefix}{answer}")
        user_message = str(ai_result.get("user_message") or "").strip()
        if user_message and user_message not in "\n".join(lines):
            lines.append(f"{tr('api.user_guidance', default='User Guidance')}: {user_message}")
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
        error_text = str(payload.get("error", ""))
        return payload, 400 if "unknown_scenario" in error_text or "unknown_scenarios" in error_text else 500

    if not payload:
        payload = {"ok": True}
    payload["runner"] = str(runner)
    return payload, 200


def _demo_state_payload() -> Dict[str, Any]:
    overlay = read_demo_overlay()
    demo = overlay.get("demo") if isinstance(overlay.get("demo"), dict) else {}
    presentation = overlay.get("presentation") if isinstance(overlay.get("presentation"), dict) else {}
    epd_last = _read_json_file(EPD_LAST_RENDER_PATH)
    epd_render = epd_last.get("render") if isinstance(epd_last, dict) and isinstance(epd_last.get("render"), dict) else {}
    active = bool(overlay.get("active"))
    return {
        "ok": True,
        "active": active,
        "scenario_id": str(overlay.get("scenario_id") or ""),
        "title": str(overlay.get("title") or presentation.get("title") or demo.get("title") or "idle"),
        "summary": str(overlay.get("summary") or presentation.get("summary") or demo.get("summary") or ""),
        "attack_label": str(overlay.get("attack_label") or demo.get("attack_label") or presentation.get("attack_label") or ""),
        "description": str(overlay.get("description") or ""),
        "event_count": int(overlay.get("event_count") or 0),
        "action": str(overlay.get("action") or "observe"),
        "control_mode": str(overlay.get("control_mode") or "none"),
        "reason": str(overlay.get("reason") or ""),
        "operator_wording": str(overlay.get("operator_wording") or ""),
        "talk_track": str(demo.get("talk_track") or ""),
        "next_checks": list(overlay.get("next_checks") or []),
        "chosen_evidence_ids": list(overlay.get("chosen_evidence_ids") or []),
        "rejected_alternatives": list(overlay.get("rejected_alternatives") or []),
        "decision_path": dict(demo.get("decision_path") or {}) if isinstance(demo.get("decision_path"), dict) else {},
        "proofs": dict(demo.get("proofs") or {}) if isinstance(demo.get("proofs"), dict) else {},
        "epd": {
            "ts": str(epd_last.get("ts") or ""),
            "state": str(epd_render.get("state") or ""),
            "mode_label": str(epd_render.get("mode_label") or ""),
            "risk_status": str(epd_render.get("risk_status") or ""),
            "ssid": str(epd_render.get("ssid") or ""),
            "suspicion": _as_int(epd_render.get("suspicion"), 0),
        },
    }


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


def _enrich_ai_result(
    ai_result: Dict[str, Any] | None,
    *,
    audience: str | None = None,
    lang: str | None = None,
    surface: str | None = None,
) -> Dict[str, Any]:
    result = dict(ai_result) if isinstance(ai_result, dict) else {}
    lang_norm = normalize_lang(lang or _request_lang())
    surface_norm = _normalize_mio_surface(surface or "dashboard", default="dashboard")
    audience_norm = _normalize_mio_audience(audience, default="professional")
    if not result:
        bundle = _compose_mio_message_bundle(
            {},
            audience=audience_norm,
            lang=lang_norm,
            surface=surface_norm,
        )
        return {
            "ok": False,
            "error": "empty_ai_result",
            "rationale": [],
            "handoff": _assist_handoff_payload(),
            "mio_message_profile": bundle["profile"],
            "surface_messages": bundle["surface_messages"],
            "surface_message": bundle["surface_message"],
        }
    runbook_id = str(result.get("runbook_id") or "").strip()
    if runbook_id and not str(result.get("user_message") or "").strip() and runbook_get is not None:
        try:
            runbook = runbook_get(runbook_id, lang=lang_norm)
            result["user_message"] = localize_runbook_user_message(runbook, lang=lang_norm)[:160]
        except Exception:
            pass
    existing_rationale = _string_list(result.get("rationale"), limit=4)
    result["rationale"] = existing_rationale if existing_rationale else _assist_rationale(result)
    handoff = result.get("handoff") if isinstance(result.get("handoff"), dict) else {}
    if not handoff:
        result["handoff"] = _assist_handoff_payload()
    else:
        merged_handoff = dict(_assist_handoff_payload())
        merged_handoff.update({k: v for k, v in handoff.items() if v})
        result["handoff"] = merged_handoff
    bundle = _compose_mio_message_bundle(
        result,
        audience=audience_norm,
        lang=lang_norm,
        surface=surface_norm,
    )
    result["mio_message_profile"] = bundle["profile"]
    result["surface_messages"] = bundle["surface_messages"]
    result["surface_message"] = bundle["surface_message"]
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
                data["now_time"] = time.strftime("%H:%M:%S")
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
        data["now_time"] = time.strftime("%H:%M:%S")
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


@app.route("/api/aggregator/nodes/register", methods=["POST"])
@require_token(min_role="admin")
def api_aggregator_register_node():
    if _AGGREGATOR_REGISTRY is None:
        return jsonify({"ok": False, "error": "aggregator_registry_unavailable"}), 500
    body = request.get_json(silent=True) or {}
    node_id = str(body.get("node_id") or "").strip()
    site_id = str(body.get("site_id") or "").strip()
    node_label = str(body.get("node_label") or "").strip()
    trust_fingerprint = str(body.get("trust_fingerprint") or "").strip()
    try:
        node = _AGGREGATOR_REGISTRY.register_node(
            node_id=node_id,
            site_id=site_id,
            node_label=node_label,
            trust_fingerprint=trust_fingerprint,
        )
    except ValueError as e:
        err = str(e)
        _audit_aggregator_event(event=AEVT_NODE_REGISTER, node_id=node_id, reason=err, accepted=False)
        return jsonify({"ok": False, "error": err}), 400
    _audit_aggregator_event(event=AEVT_NODE_REGISTER, node_id=node_id, reason="ok", accepted=True)
    return jsonify({"ok": True, "node": node}), 200


@app.route("/api/aggregator/ingest/summary", methods=["POST"])
@require_token(min_role="operator")
def api_aggregator_ingest_summary():
    if _AGGREGATOR_REGISTRY is None:
        return jsonify({"ok": False, "error": "aggregator_registry_unavailable"}), 500
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "payload_must_be_object"}), 400
    node_id_hint = ""
    try:
        node_hint = body.get("node") if isinstance(body.get("node"), dict) else {}
        node_id_hint = str(node_hint.get("node_id") or "").strip()
    except Exception:
        pass
    try:
        result = _AGGREGATOR_REGISTRY.ingest_summary(body)
    except ValueError as e:
        err = str(e)
        event = AEVT_NODE_QUARANTINE if err == "sig_invalid" else AEVT_INGEST_REJECT
        _audit_aggregator_event(
            event=event,
            node_id=node_id_hint,
            trace_id=str(body.get("trace_id") or ""),
            reason=err,
        )
        return jsonify({"ok": False, "error": err}), 400
    _audit_aggregator_event(
        event=AEVT_INGEST_ACCEPT,
        node_id=result["node_id"],
        trace_id=result["trace_id"],
        reason="ok",
    )
    return jsonify(result), 200


@app.route("/api/aggregator/nodes", methods=["GET"])
@require_token()
def api_aggregator_nodes():
    if _AGGREGATOR_REGISTRY is None:
        return jsonify({"ok": False, "error": "aggregator_registry_unavailable"}), 500
    items = _AGGREGATOR_REGISTRY.list_nodes()
    counters = {
        "fresh": 0,
        "stale": 0,
        "offline": 0,
    }
    for row in items:
        state = str(row.get("freshness") or "offline")
        if state not in counters:
            counters["offline"] += 1
        else:
            counters[state] += 1
    return jsonify(
        {
            "ok": True,
            "items": items,
            "counts": counters,
            "poll_interval_sec": AGGREGATOR_POLL_INTERVAL_SEC,
        }
    ), 200


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
@require_token(min_role="viewer")
def api_mode_get():
    """GET /api/mode - Return current mode metadata."""
    payload = get_mode_state()
    code = 200 if payload.get("ok") else 500
    return jsonify(payload), code


@app.route("/api/mode", methods=["POST"])
@require_token(min_role="admin")
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
    lang = str(context.get("lang") or body.get("lang") or _request_lang())
    context["lang"] = lang
    audience = str(context.get("audience") or body.get("audience") or "").strip()
    surface = str(context.get("surface") or context.get("page") or source).strip()
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400
    result = _send_ai_manual_query(
        question=question,
        sender=sender,
        source=source,
        context=context,
    )
    result = _enrich_ai_result(result, audience=audience, lang=lang, surface=surface)
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
    payload, code = _run_demo_runner("list", "--format", "json")
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


@app.route("/api/demo/state", methods=["GET"])
@require_token()
def api_demo_state():
    return jsonify(_demo_state_payload()), 200


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
    payload, code = _run_demo_runner("run", scenario, "--format", "json", "--apply-overlay")
    return jsonify(payload), code


@app.route("/api/demo/flow", methods=["POST"])
@require_token()
def api_demo_flow():
    body = request.get_json(silent=True) or {}
    cmd = ["flow", "--format", "json"]
    scenarios = body.get("scenarios")
    if isinstance(scenarios, list):
        cleaned = [str(item).strip() for item in scenarios if str(item).strip()]
        if cleaned:
            cmd.extend(["--scenarios", ",".join(cleaned)])
    hold_sec_raw = body.get("hold_sec")
    if hold_sec_raw not in (None, ""):
        cmd.extend(["--hold-sec", str(_as_int(hold_sec_raw, 0))])
    if body.get("keep_final"):
        cmd.append("--keep-final")
    if body.get("refresh_epd"):
        cmd.append("--refresh-epd")
    payload, code = _run_demo_runner(*cmd)
    return jsonify(payload), code


@app.route("/api/topolite/seed-mode", methods=["GET", "POST"])
@require_token()
def api_topolite_seed_mode():
    if request.method == "GET":
        payload = _read_topolite_seed_mode()
        mode = str(payload.get("mode") or "live")
        response = dict(payload)
        if mode == "synthetic":
            response["story"] = _build_topolite_synthetic_story(str(payload.get("seed_id") or "topolite-default"))
            response["watermark"] = "SYNTHETIC DATA - NOT LIVE EVIDENCE"
        else:
            response["story"] = {}
            response["watermark"] = ""
        return jsonify({"ok": True, "topolite_seed_mode": response}), 200

    body = request.get_json(silent=True) or {}
    mode = str(body.get("mode") or "").strip().lower()
    if mode not in {"live", "synthetic"}:
        return jsonify({"ok": False, "error": "mode must be live or synthetic"}), 400
    seed_id = str(body.get("seed_id") or "topolite-default").strip() or "topolite-default"
    updated_by = str(body.get("updated_by") or request.remote_addr or "webui")
    payload = _write_topolite_seed_mode(mode=mode, seed_id=seed_id, updated_by=updated_by)
    response = dict(payload)
    if mode == "synthetic":
        response["story"] = _build_topolite_synthetic_story(seed_id)
        response["watermark"] = "SYNTHETIC DATA - NOT LIVE EVIDENCE"
    else:
        response["story"] = {}
        response["watermark"] = ""
    return jsonify({"ok": True, "topolite_seed_mode": response}), 200


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
    metrics = _read_json_file(AI_METRICS_PATH)
    llm_rows = _tail_jsonl(AI_LLM_LOG, limit=20)
    audience = str(request.args.get("audience") or "temporary").strip() or "temporary"
    surface = str(request.args.get("surface") or "dashboard").strip() or "dashboard"
    return jsonify(_dashboard_actions_payload(state, advisory, metrics, llm_rows, audience=audience, surface=surface)), 200


@app.route("/api/operator-progress", methods=["GET", "POST"])
@require_token(min_role="operator")
def api_operator_progress():
    lang = _request_lang()
    body = request.get_json(silent=True) or {}
    session_id = _normalize_progress_session_id(request.args.get("session_id") or body.get("session_id"))
    if request.method == "POST":
        if not session_id:
            return jsonify({"ok": False, "error": "session_id_required"}), 400
        try:
            _save_operator_progress(
                session_id=session_id,
                item_id=str(body.get("item_id") or "").strip() or None,
                done=body.get("done") if "done" in body else None,
                blocked_reason=body.get("blocked_reason") if "blocked_reason" in body else None,
                blocked_prompt=body.get("blocked_prompt") if "blocked_prompt" in body else None,
                clear_blocked=bool(body.get("clear_blocked")),
            )
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
    state = read_state()
    metrics = _read_json_file(AI_METRICS_PATH)
    advisory = _read_json_file(AI_ADVISORY_PATH)
    llm_rows = _tail_jsonl(AI_LLM_LOG, limit=20)
    summary = _dashboard_summary_payload(state, metrics, advisory)
    actions = _dashboard_actions_payload(state, advisory, metrics, llm_rows, audience="temporary", surface="dashboard")
    payload = _operator_progress_payload(summary, actions, session_id=session_id, lang=lang)
    return jsonify({"ok": True, "operator_progress_state": payload}), 200


@app.route("/api/dashboard/handoff", methods=["GET", "POST"])
@require_token(min_role="operator")
def api_dashboard_handoff():
    lang = _request_lang()
    body = request.get_json(silent=True) or {}
    session_id = _normalize_progress_session_id(request.args.get("session_id") or body.get("session_id"))
    state = read_state()
    metrics = _read_json_file(AI_METRICS_PATH)
    advisory = _read_json_file(AI_ADVISORY_PATH)
    llm_rows = _tail_jsonl(AI_LLM_LOG, limit=20)
    runbook_rows = _tail_jsonl(RUNBOOK_EVENT_LOG, limit=20)
    summary = _dashboard_summary_payload(state, metrics, advisory)
    actions = _dashboard_actions_payload(state, advisory, metrics, llm_rows, audience="professional", surface="dashboard")
    health = _dashboard_health_payload(state, metrics, llm_rows, runbook_rows)
    progress = _operator_progress_payload(summary, actions, session_id=session_id, lang=lang)
    pack = _handoff_brief_pack_payload(summary, actions, health, progress, lang=lang)
    if request.method == "POST":
        target = str(body.get("target") or "").strip().lower()
        if target != "mattermost":
            return jsonify({"ok": False, "error": "unsupported_target", "handoff_brief_pack": pack}), 400
        try:
            result = _mattermost_send_message(f"[Handoff Brief]\n{pack['brief_text']}", sender="Azazel-Edge Handoff")
        except Exception as e:
            return jsonify({"ok": False, "error": str(e), "handoff_brief_pack": pack}), 502
        return jsonify({"ok": True, "result": result, "handoff_brief_pack": pack}), 200
    return jsonify({"ok": True, "handoff_brief_pack": pack}), 200


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


@app.route("/api/dashboard/trends", methods=["GET"])
@require_token()
def api_dashboard_trends():
    limit = _as_int(request.args.get("limit"), 120)
    window_sec = _as_int(request.args.get("window_sec"), 0)
    return jsonify(_dashboard_trends_payload(limit=limit, window_sec=window_sec)), 200


@app.route("/api/dashboard/ai-governance", methods=["GET"])
@require_token()
def api_dashboard_ai_governance():
    metrics = _read_json_file(AI_METRICS_PATH)
    return jsonify(_dashboard_ai_governance_payload(metrics)), 200


@app.route("/api/clients/trust", methods=["POST"])
@require_token()
def api_clients_trust():
    body = request.get_json(silent=True) or {}
    trusted = bool(body.get("trusted", False))
    ignored = bool(body.get("ignored", False))
    ip = str(body.get("ip") or "").strip()
    mac = str(body.get("mac") or "").strip().lower()
    hostname = str(body.get("hostname") or body.get("display_name") or "").strip()
    session_key = str(body.get("session_key") or "").strip()
    interface_or_segment = str(body.get("interface_or_segment") or "").strip()
    note = str(body.get("note") or "").strip()[:240]
    expected_interface_or_segment = str(body.get("expected_interface_or_segment") or "").strip()
    allowed_networks = body.get("allowed_networks")

    if not session_key and not ip and not mac:
        return jsonify({"ok": False, "error": "session_key_or_ip_or_mac_required"}), 400

    result = send_control_command_with_params(
        "sot_trust_client",
        {
            "trusted": trusted,
            "ignored": ignored,
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "display_name": str(body.get("display_name") or "").strip(),
            "session_key": session_key,
            "interface_or_segment": interface_or_segment,
            "note": note,
            "expected_interface_or_segment": expected_interface_or_segment,
            "allowed_networks": allowed_networks,
        },
    )
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/sot/devices", methods=["PUT"])
@require_token(min_role="admin")
def api_sot_devices_put():
    body = request.get_json(silent=True) or {}
    devices = body.get("devices")
    if not isinstance(devices, list):
        return jsonify({"ok": False, "error": "devices_must_be_list"}), 400
    current, target = _read_sot_payload()
    candidate = dict(current)
    candidate["devices"] = devices
    try:
        validated = _validate_sot_payload(candidate)
    except (SoTValidationError, ValueError) as e:
        return jsonify({"ok": False, "error": f"invalid_sot:{e}"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    _write_sot_payload(validated, target)
    diff = _sot_device_diff(list(current.get("devices") or []), list(validated.get("devices") or []))
    actor = _request_actor()
    _append_jsonl(
        SOT_AUDIT_LOG,
        {
            "kind": "sot_devices_replaced",
            "ts": time.time(),
            "source": "web_api",
            **actor,
            "path": str(target),
            "device_count": len(validated.get("devices") or []),
            "diff": diff,
        },
    )
    refresh_result = send_control_command("refresh")
    return jsonify({"ok": True, "path": str(target), "diff": diff, "refresh": refresh_result}), 200


@app.route("/api/sot/devices", methods=["PATCH"])
@require_token(min_role="admin")
def api_sot_devices_patch():
    body = request.get_json(silent=True) or {}
    updates = body.get("devices")
    if not isinstance(updates, list):
        return jsonify({"ok": False, "error": "devices_must_be_list"}), 400
    current, target = _read_sot_payload()
    current_devices = [item for item in list(current.get("devices") or []) if isinstance(item, dict)]
    merged: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for row in current_devices:
        row_id = str(row.get("id") or "").strip()
        if not row_id:
            continue
        merged[row_id] = dict(row)
        order.append(row_id)
    for row in updates:
        if not isinstance(row, dict):
            return jsonify({"ok": False, "error": "device_item_must_be_object"}), 400
        row_id = str(row.get("id") or "").strip()
        if not row_id:
            return jsonify({"ok": False, "error": "device_id_required"}), 400
        if row_id not in merged:
            merged[row_id] = {}
            order.append(row_id)
        merged[row_id].update(row)
    candidate = dict(current)
    candidate["devices"] = [merged[row_id] for row_id in order if row_id in merged]
    try:
        validated = _validate_sot_payload(candidate)
    except (SoTValidationError, ValueError) as e:
        return jsonify({"ok": False, "error": f"invalid_sot:{e}"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    _write_sot_payload(validated, target)
    diff = _sot_device_diff(current_devices, list(validated.get("devices") or []))
    actor = _request_actor()
    _append_jsonl(
        SOT_AUDIT_LOG,
        {
            "kind": "sot_devices_patched",
            "ts": time.time(),
            "source": "web_api",
            **actor,
            "path": str(target),
            "patched_count": len(updates),
            "device_count": len(validated.get("devices") or []),
            "diff": diff,
        },
    )
    refresh_result = send_control_command("refresh")
    return jsonify({"ok": True, "path": str(target), "diff": diff, "refresh": refresh_result}), 200


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
@require_token(min_role="operator")
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
@require_token(min_role="operator")
def api_runbooks_act():
    body = request.get_json(silent=True) or {}
    result, code = _run_runbook_action(body)
    return jsonify(result), code


@app.route("/api/mattermost/message", methods=["POST"])
@require_token(min_role="operator")
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
            audience = str(body.get("audience") or "operator").strip() or "operator"
            ai_result = _enrich_ai_result(_send_ai_manual_query(
                question=message,
                sender=sender,
                source="mattermost_post",
                context={"channel_id": MATTERMOST_CHANNEL_ID, "lang": lang, "audience": audience, "page": "mattermost"},
            ), audience=audience, lang=lang, surface="mattermost")
            if runbook_propose is not None:
                try:
                    runbook_proposals = runbook_propose(
                        message,
                        audience=audience,
                        max_items=3,
                        context={"question": message, "source": "mattermost_post", "lang": lang, "audience": audience},
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
    ai_result = _enrich_ai_result(ai_result, audience=audience, lang=lang, surface="mattermost")
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
@require_token(ok_payload=None, min_role="responder")
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
@require_token(min_role="responder")
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
@require_token(status_code=401, min_role="operator")
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
        if AUTH_FAIL_OPEN:
            print(f"   ⚠️  WARNING: No token configured (fail-open enabled)")
        else:
            print(f"   ⚠️  WARNING: No token configured (API auth will deny protected endpoints)")
    
    app.run(
        host=BIND_HOST,
        port=BIND_PORT,
        debug=False,
        threaded=True
    )
