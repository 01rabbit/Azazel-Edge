#!/usr/bin/env python3
"""Local AI advisory agent for normalized events from Rust core."""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import pwd
import queue
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict

PY_ROOT = Path(__file__).resolve().parents[1]
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.decision_layers import DecisionLayers
from azazel_edge.tactics_engine import ConfigHash, DecisionLogger, TacticalScorer
from azazel_edge.tactics_engine.decision_logger import (
    ChosenAction,
    ScoreDelta,
    StateSnapshot,
)
try:
    from azazel_edge.runbooks import get_runbook as runbook_get
except Exception:  # pragma: no cover
    runbook_get = None
try:
    from azazel_edge.i18n import localize_runbook_user_message, normalize_lang, translate
except Exception:  # pragma: no cover
    localize_runbook_user_message = None
    normalize_lang = lambda value=None: "ja"  # type: ignore
    translate = lambda key, lang=None, default=None, **kwargs: (default or key).format(**kwargs) if kwargs else (default or key)  # type: ignore
try:
    from azazel_edge.runbook_review import review_runbook_id
except Exception:  # pragma: no cover
    review_runbook_id = None
try:
    from azazel_edge.audit import P0AuditLogger
except Exception:  # pragma: no cover
    P0AuditLogger = None  # type: ignore
try:
    from azazel_edge.notify.core_decisions import (
        DEFAULT_CHAIN_SEGMENT_MAX_BYTES,
        DEFAULT_CHAIN_SEGMENTS_KEPT,
        CoreDecisionRecorder,
    )
    from azazel_edge.notify.p0_alert import attach_p0_alert_relay
except Exception:  # pragma: no cover
    CoreDecisionRecorder = None  # type: ignore
    attach_p0_alert_relay = None  # type: ignore
try:
    from azazel_edge.explanations.live import LiveDecisionExplanationWriter
except Exception:  # pragma: no cover
    LiveDecisionExplanationWriter = None  # type: ignore
from azazel_edge._util import ensure_parent as _ensure_parent
from azazel_edge.peercred import account_uid, peer_credentials

SOCKET_PATH = Path(os.environ.get("AZAZEL_AI_SOCKET", "/run/azazel-edge-ai/ai-bridge.sock"))
# The socket's location before Edge#462: inside the shared runtime directory,
# where members of AZAZEL_RUNTIME_SOCKET_GROUP could replace it.
LEGACY_SOCKET_PATH = Path("/run/azazel-edge/ai-bridge.sock")
# ai-bridge.sock is owner only (Edge#462). Its caller, the Rust core (event
# forwarding), runs as root like this agent; the Web UI asks on the separate
# query socket below (Edge#471 stage 1). The optional shared group (AZAZEL_RUNTIME_SOCKET_GROUP) is for the
# control daemon's control.sock only and is never applied here. The socket
# lives in its own directory, owned by the agent's account with mode 0700, so
# no other account can connect to it, replace it or bind its own socket at its
# path. The socket and directory modes are not configurable:
# AZAZEL_AI_SOCKET_MODE is no longer applied.
SOCKET_MODE = 0o600
SOCKET_DIR_MODE = 0o700
# manual_query socket for the Web UI (Edge#471 stage 1). The Web UI runs as
# QUERY_SOCKET_ACCOUNT, which cannot reach the private ai-bridge.sock. This
# second socket accepts exactly one request type, ``manual_query``, from a
# peer whose kernel-reported uid (SO_PEERCRED) is root or that account; it
# never passes anything to _handle_event, forward stats or the P0 path. Its
# directory is owned by the agent's account with group = the Web UI
# account's primary group and mode 0750; the socket is 0660. When the
# account does not exist the socket is not created (fail closed) and the
# agent serves ai-bridge.sock as before.
QUERY_SOCKET_PATH = Path(os.environ.get("AZAZEL_AI_QUERY_SOCKET", "/run/azazel-edge-agent-query/agent-query.sock"))
QUERY_SOCKET_ACCOUNT = "azazel-web"
QUERY_SOCKET_MODE = 0o660
QUERY_SOCKET_DIR_MODE = 0o750
# An existing directory may also be setgid (2750): as azazel-agent (stage 2)
# the agent cannot chgrp to azazel-web itself, so tmpfiles.d creates the
# directory setgid and the socket inherits the group.
QUERY_SOCKET_DIR_MODES_ACCEPTED = (0o750, 0o2750)
QUERY_MAX_REQUEST_BYTES = 256 * 1024
QUERY_READ_TIMEOUT_SEC = 10.0  # total, for the whole request line
# Concurrent query handlers (a manual_query can wait on the LLM); more
# connections are answered "busy" and closed.
QUERY_MAX_CONCURRENT = 4
_QUERY_SLOTS = threading.BoundedSemaphore(QUERY_MAX_CONCURRENT)
_QUERY_REFUSALS_LOCK = threading.Lock()
_QUERY_REFUSALS = {"total": 0}
# Set once the query socket listens. From then on ai-bridge.sock refuses
# manual_query (its only legitimate sender, the Web UI, uses the query
# socket). While the query socket does not exist (no azazel-web account, as
# on a development host), ai-bridge.sock keeps answering manual_query from
# the peers that can reach it (owner only: root / the agent's account).
QUERY_SOCKET_ACTIVE = threading.Event()
# The agent's own directories (Edge#471 stage 2: it runs as azazel-agent).
# /run/azazel-edge-agent and /var/log/azazel-edge/ai are owned by the agent's
# account with group azazel-web, setgid, so the Web UI (and root) can read
# what the agent writes and nobody else can write there. The agent no longer
# writes in the shared /run/azazel-edge (the control daemon's directory).
AGENT_RUNTIME_DIR = Path("/run/azazel-edge-agent")
AGENT_LOG_DIR = Path("/var/log/azazel-edge/ai")
AGENT_STATE_DIR = Path("/var/lib/azazel-edge-agent")
ADVISORY_PATH = Path(os.environ.get("AZAZEL_AI_ADVISORY", str(AGENT_RUNTIME_DIR / "ai_advisory.json")))
EVENT_LOG_PATH = Path(os.environ.get("AZAZEL_AI_EVENT_LOG", str(AGENT_LOG_DIR / "ai-events.jsonl")))
# The agent's own snapshot fields, next to its advisory. The control daemon is
# the only writer of the shared ui_snapshot.json and merges these fields
# (azazel_edge_control.daemon AGENT_SNAPSHOT_KEYS). AZAZEL_UI_SNAPSHOT names
# the shared file and is no longer the agent's.
SNAPSHOT_PATH = ADVISORY_PATH.parent / "ai_snapshot.json"
LLM_DEFERRED_LOG_PATH = Path(os.environ.get("AZAZEL_AI_DEFERRED_LOG", str(AGENT_LOG_DIR / "ai-deferred.jsonl")))
LLM_RESULT_LOG_PATH = Path(os.environ.get("AZAZEL_AI_LLM_LOG", str(AGENT_LOG_DIR / "ai-llm.jsonl")))
METRICS_PATH = Path(os.environ.get("AZAZEL_AI_METRICS", str(AGENT_RUNTIME_DIR / "ai_metrics.json")))
POLICY_PATH = Path(os.environ.get("AZAZEL_AI_POLICY", str(AGENT_RUNTIME_DIR / "ai_runtime_policy.json")))
AI_AUDIT_PATH = Path(os.environ.get("AZAZEL_AI_AUDIT_LOG", str(AGENT_LOG_DIR / "ai-audit.jsonl")))
# P0 alert path for the Rust core's decisions (Edge#412 owner decision: the
# Rust azazel-edge-core is the authoritative decision and enforcement path;
# Edge#414 SO-03). This agent is where the core's decisions arrive (the core
# forwards every decision event to AI_SOCKET). A P0 decision is recorded as an
# action_decision in its own audit chain (azazel_edge.notify.core_decisions),
# and the P0 relay (#453/#458) turns that durable record into the visual/voice
# entries of the one P0 queue. Both files sit beside the AI audit log; no
# setting of their own.
CORE_DECISION_AUDIT_PATH = AI_AUDIT_PATH.parent / "core-decision-audit.jsonl"
P0_ALERT_QUEUE_PATH = AI_AUDIT_PATH.parent / "p0-alert-queue.jsonl"
# v2 decision explanations of the core's decisions (Edge#477), the file the
# Web UI's Booth Focus and audit_review read
# (azazel_edge.explanations.LIVE_DECISION_EXPLANATIONS_PATH). Display and
# audit only; beside the AI audit log, no setting of its own.
DECISION_EXPLANATIONS_PATH = AI_AUDIT_PATH.parent / "decision-explanations.jsonl"
METRICS_HEARTBEAT_SEC = max(5.0, float(os.environ.get("AZAZEL_AI_METRICS_HEARTBEAT_SEC", "15")))
# Rolling suricata severity tallies in the UI snapshot decay linearly to zero over
# this window of no new same-severity events, so a long-running / idle booth does
# not accumulate unbounded counts that keep the dashboard escalated. Aligned with
# daemon.SURICATA_ADVISORY_TTL_SEC (stale-advisory TTL) so the display and the
# tallies age out on the same clock.
SURICATA_COUNT_DECAY_WINDOW_SEC = max(1.0, float(os.environ.get("AZAZEL_SURICATA_COUNT_DECAY_SEC", "300")))
# Hard ceiling so a sustained event storm still cannot grow the tallies without
# bound (decay reclaims them once activity subsides).
SURICATA_COUNT_MAX = max(1, int(os.environ.get("AZAZEL_SURICATA_COUNT_MAX", "99")))
# The lifetime METRICS["deferred_count"] counter never resets (see _metrics_inc
# call sites), so a single LLM-queue-full burst during an attack would pin the
# "Deferred" strip pill to caution for the rest of the process life, including
# all the benign traffic afterward. `deferred_recent` (persisted alongside the
# suricata tallies in the UI snapshot) is a windowed view of the same signal:
# it is bumped by however much the lifetime counter grew since the last
# snapshot write, then ages back to zero after this many seconds of no new
# deferrals - same decay shape as SURICATA_COUNT_DECAY_WINDOW_SEC, just a
# shorter window since queue-full pressure is meant to be a transient signal.
DEFERRED_RECENT_DECAY_WINDOW_SEC = max(1.0, float(os.environ.get("AZAZEL_DEFERRED_RECENT_DECAY_SEC", "60")))


def _decay_suricata_count(prev: int, elapsed_sec: float, window_sec: float = SURICATA_COUNT_DECAY_WINDOW_SEC) -> int:
    """Linearly age a tally toward zero across a decay window.

    Despite the name (kept for backward compatibility with existing callers
    and tests), this is a generic "age a monotonic-ish counter back toward
    zero" helper - `deferred_recent` below reuses it with a shorter window.
    """
    value = max(0, int(prev))
    if value <= 0 or elapsed_sec <= 0:
        return min(SURICATA_COUNT_MAX, value)
    factor = max(0.0, 1.0 - (float(elapsed_sec) / window_sec))
    # Round (not floor) so a small tally survives most of the window instead of
    # truncating to zero on the very next event; a full window of quiet still
    # reclaims it to zero (factor == 0).
    return min(SURICATA_COUNT_MAX, int(round(value * factor)))
LLM_ENABLED = os.environ.get("AZAZEL_LLM_ENABLED", "1") == "1"
LLM_ENDPOINT = os.environ.get("AZAZEL_OLLAMA_ENDPOINT", "http://127.0.0.1:11434")
LLM_MODEL_PRIMARY = os.environ.get("AZAZEL_LLM_MODEL_PRIMARY", os.environ.get("AZAZEL_LLM_MODEL", "qwen3.5:2b"))
LLM_MODEL_DEGRADED = os.environ.get("AZAZEL_LLM_MODEL_DEGRADED", "qwen3.5:0.8b")
OPS_COACH_MODEL = os.environ.get("AZAZEL_OPS_MODEL", "qwen3.5:4b")
OPS_COACH_ENABLED = os.environ.get("AZAZEL_OPS_ENABLED", "1") == "1"
LLM_TIMEOUT_SEC = float(os.environ.get("AZAZEL_LLM_TIMEOUT_SEC", "45"))
LLM_RETRY_MAX = max(0, int(os.environ.get("AZAZEL_LLM_RETRY_MAX", "0")))
LLM_RETRY_BACKOFF_SEC = float(os.environ.get("AZAZEL_LLM_RETRY_BACKOFF_SEC", "0.5"))
LLM_AMBIG_MIN = int(os.environ.get("AZAZEL_LLM_AMBIG_MIN", "40"))
LLM_AMBIG_MAX = int(os.environ.get("AZAZEL_LLM_AMBIG_MAX", "79"))
LLM_AMBIG_MIN_DEGRADED = int(os.environ.get("AZAZEL_LLM_AMBIG_MIN_DEGRADED", str(min(79, LLM_AMBIG_MIN + 10))))
LLM_QUEUE_MAX = int(os.environ.get("AZAZEL_LLM_QUEUE_MAX", "32"))
LLM_NUM_CTX = int(os.environ.get("AZAZEL_LLM_NUM_CTX", "256"))
LLM_NUM_PREDICT = int(os.environ.get("AZAZEL_LLM_NUM_PREDICT", "48"))
LLM_NUM_THREAD = int(os.environ.get("AZAZEL_LLM_NUM_THREAD", "2"))
LLM_KEEP_ALIVE = os.environ.get("AZAZEL_LLM_KEEP_ALIVE", "20m")
LLM_THINK = os.environ.get("AZAZEL_LLM_THINK", "0") == "1"
CORR_ENABLED = os.environ.get("AZAZEL_CORR_ENABLED", "1") == "1"
CORR_WINDOW_SEC = int(os.environ.get("AZAZEL_CORR_WINDOW_SEC", "300"))
CORR_REPEAT_THRESHOLD = int(os.environ.get("AZAZEL_CORR_REPEAT_THRESHOLD", "4"))
CORR_SID_DIVERSITY_THRESHOLD = int(os.environ.get("AZAZEL_CORR_SID_DIVERSITY_THRESHOLD", "3"))
CORR_MIN_RISK_SCORE = int(os.environ.get("AZAZEL_CORR_MIN_RISK_SCORE", "20"))
CORR_MAX_HISTORY_PER_SRC = int(os.environ.get("AZAZEL_CORR_MAX_HISTORY_PER_SRC", "32"))
OPS_KEEP_ALIVE = os.environ.get("AZAZEL_OPS_KEEP_ALIVE", "0s")
OPS_NUM_PREDICT = int(os.environ.get("AZAZEL_OPS_NUM_PREDICT", "80"))
OPS_MIN_MEM_AVAILABLE_MB = int(os.environ.get("AZAZEL_OPS_MIN_MEM_AVAILABLE_MB", "1400"))
OPS_MAX_SWAP_USED_MB = int(os.environ.get("AZAZEL_OPS_MAX_SWAP_USED_MB", "512"))
OPS_ESCALATE_MIN_RISK = int(os.environ.get("AZAZEL_OPS_ESCALATE_MIN_RISK", "70"))
OPS_ESCALATE_LOW_CONF = float(os.environ.get("AZAZEL_OPS_ESCALATE_LOW_CONF", "0.60"))
# Single source of truth for the CRITICAL band. Display (_risk_level/_state_name/
# _recommendation) and the auto-ops escalation at risk>=85 must agree, otherwise a
# threat can land in an [80,84] dead zone where the display says CRITICAL but ops
# does not escalate (or vice-versa). Ships WITH the scorer recalibration.
CRITICAL_MIN = int(os.environ.get("AZAZEL_CRITICAL_MIN", "85"))
OPS_ESCALATE_COOLDOWN_SEC = int(os.environ.get("AZAZEL_OPS_ESCALATE_COOLDOWN_SEC", "180"))
MANUAL_KEEP_ALIVE = os.environ.get("AZAZEL_MANUAL_KEEP_ALIVE", "5m")
MANUAL_NUM_PREDICT = int(os.environ.get("AZAZEL_MANUAL_NUM_PREDICT", "64"))
MANUAL_NUM_CTX = int(os.environ.get("AZAZEL_MANUAL_NUM_CTX", "192"))
MANUAL_NUM_THREAD = int(os.environ.get("AZAZEL_MANUAL_NUM_THREAD", str(LLM_NUM_THREAD)))
OPS_MODEL_CHAIN = [
    m.strip()
    for m in os.environ.get("AZAZEL_OPS_MODEL_CHAIN", f"{OPS_COACH_MODEL},{LLM_MODEL_PRIMARY},{LLM_MODEL_DEGRADED}").split(",")
    if m.strip()
]
LLM_PROMPT_SYSTEM = (
    "You are M.I.O. (Mission Intelligence Operator), a calm tactical analyst. "
    "Return strict minified JSON only. "
    "Keys: verdict, confidence, reason, suggested_action, escalation. "
    "verdict must be exactly one of: allow, monitor, block, deceive, escalate, hold. "
    "reason<=80 chars, suggested_action<=80 chars, confidence=0.0..1.0, escalation=true|false. "
    "Prefer precise, conditional wording over hard certainty."
)
OPS_PROMPT_SYSTEM = (
    "You are M.I.O. (Mission Intelligence Operator), a calm deputy-style ops coach. "
    "Return strict JSON only with keys: runbook_id, summary, operator_note. "
    "Keep summary and operator_note each under 120 chars. "
    "Prioritize situation, likely cause, next check, and safe escalation."
)
MANUAL_PROMPT_SYSTEM = (
    "You are M.I.O. (Mission Intelligence Operator), a calm SOC/NOC support assistant. "
    "Return strict JSON only with keys: "
    "answer,confidence,runbook_id,operator_note,user_message. "
    "answer<=240 chars, operator_note<=120 chars, user_message<=160 chars, confidence=0.0..1.0. "
    "Be concise, structured, and conditional. "
    "For beginner-facing situations, give at most 3 simple steps and do not ask the user to perform operator-only actions."
)
MANUAL_QUERY_MAX_CHARS = int(os.environ.get("AZAZEL_MANUAL_QUERY_MAX_CHARS", "500"))
MANUAL_QUERY_TIMEOUT_SEC = float(os.environ.get("AZAZEL_MANUAL_QUERY_TIMEOUT_SEC", "18"))
MANUAL_TOTAL_TIMEOUT_SEC = float(os.environ.get("AZAZEL_MANUAL_TOTAL_TIMEOUT_SEC", "20"))
MANUAL_MODEL_CHAIN = [
    m.strip()
    for m in os.environ.get("AZAZEL_MANUAL_MODEL_CHAIN", f"{LLM_MODEL_DEGRADED},{LLM_MODEL_PRIMARY}").split(",")
    if m.strip()
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("azazel-edge-ai-agent")
SCORER = TacticalScorer()
DECISION_LOGGER = DecisionLogger(
    Path(str(os.environ.get("AZAZEL_DECISION_LOG_DIR", "")).strip() or str(AGENT_STATE_DIR / "decisions"))
)
CONFIG_HASH = ConfigHash.compute(config_dict={"engine": "tactical_scorer_v1"})
try:
    DECISION_LAYERS = DecisionLayers()
except ValueError as _config_error:
    # The SOC policy or the ATT&CK mapping is there but invalid. Never run on
    # the built-in defaults instead (the operator's policy would be silently
    # replaced): stop with EX_CONFIG, which the unit does not restart
    # (RestartPreventExitStatus=78), instead of a restart loop.
    logger.critical("configuration error, not starting: %s", _config_error)
    raise SystemExit(78)
_LAST_RISK_SCORE = 0
_LAST_STATE_NAME = "NORMAL"
LLM_QUEUE: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=LLM_QUEUE_MAX)
IO_LOCK = threading.Lock()
APPEND_LOCK = threading.Lock()
METRICS_LOCK = threading.Lock()
METRICS: Dict[str, Any] = {
    "processed_events": 0,
    "queue_depth": 0,
    "queue_max_seen": 0,
    "deferred_count": 0,
    "llm_requests": 0,
    "llm_completed": 0,
    "llm_failed": 0,
    "llm_retried": 0,
    "llm_fallback_count": 0,
    "llm_empty_response_count": 0,
    "llm_schema_invalid_count": 0,
    "llm_latency_ms_last": 0,
    "llm_latency_ms_ema": 0.0,
    "llm_completed_rate": 0.0,
    "llm_fallback_rate": 0.0,
    "llm_empty_rate": 0.0,
    "correlation_escalations": 0,
    "ops_requests": 0,
    "ops_completed": 0,
    "ops_skipped": 0,
    "ops_errors": 0,
    "ops_schema_invalid_count": 0,
    "ops_fallback_model_count": 0,
    "manual_requests": 0,
    "manual_routed_count": 0,
    "manual_completed": 0,
    "manual_failed": 0,
    "manual_schema_invalid_count": 0,
    "policy_mode": "normal",
    "last_error": "",
    "last_update_ts": 0.0,
}
RUNTIME_POLICY: Dict[str, Any] = {"mode": "normal", "updated_at": 0.0, "reason": "init"}
_LAST_OPS_ESCALATE_TS = 0.0
CORR_LOCK = threading.Lock()
CORR_STATE: Dict[str, list[Dict[str, Any]]] = {}


AI_AUDIT_ERROR = ""


def _build_ai_audit_logger() -> Any | None:
    """The AI audit chain. No fallback (Edge#471 stage 2): an audit log that
    cannot be opened stops the service in _serve, never moves to /tmp."""
    global AI_AUDIT_ERROR
    if P0AuditLogger is None:
        return None
    try:
        return P0AuditLogger(AI_AUDIT_PATH)
    except Exception as exc:
        AI_AUDIT_ERROR = f"ai audit log {AI_AUDIT_PATH} cannot be opened: {exc}"
        return None


AI_AUDIT = _build_ai_audit_logger()

# The core decision event this agent receives (rust_event_engine_v1 in
# rust/azazel-edge-core/src/main.rs core_event()).
CORE_EVENT_SOURCE = "suricata_eve"
CORE_EVENT_PIPELINE = "rust_event_engine_v1"
# The core's own log of every decision event (same setting and default as the
# core unit); read, bounded, at start to reconcile decisions this agent missed.
CORE_NORMALIZED_EVENT_LOG = Path(os.environ.get("AZAZEL_NORMALIZED_EVENT_LOG", "/var/log/azazel-edge/normalized-events.jsonl"))
# Set by _start_core_p0_path() when the service starts (_serve). None until
# then: importing this module or calling the handlers directly records nothing.
CORE_DECISION_AUDIT: Any | None = None
CORE_P0_RELAY: Any | None = None
CORE_RECORDER: Any | None = None
# On stop: how long queued connections and running handlers get to finish
# before the P0 path is drained (each part of that drain has its own bound).
SHUTDOWN_DRAIN_S = 5.0


def _start_core_p0_path() -> Any | None:
    """Open the core decision chain, attach the P0 relay, start the recorder.

    Observation and notification only: nothing here decides, enforces or
    feeds back into the core. If the chain cannot be opened the agent runs as
    before without the path. If only the relay cannot be attached, P0
    decisions are still recorded in the chain and the relay's startup
    reconcile (#458) enqueues them on the next start.
    """

    global CORE_DECISION_AUDIT, CORE_P0_RELAY, CORE_RECORDER
    if CORE_RECORDER is not None:
        return CORE_P0_RELAY
    if P0AuditLogger is None or attach_p0_alert_relay is None or CoreDecisionRecorder is None:
        logger.error("core decision P0 alert path unavailable: notify/audit modules not importable")
        return None
    if CORE_DECISION_AUDIT is None:
        try:
            # Rotated on a chain boundary (Edge#462 item 1); the relay and
            # the recorder read the retained files as one chain.
            CORE_DECISION_AUDIT = P0AuditLogger(
                CORE_DECISION_AUDIT_PATH,
                max_bytes=DEFAULT_CHAIN_SEGMENT_MAX_BYTES,
                keep=DEFAULT_CHAIN_SEGMENTS_KEPT,
            )
        except Exception as exc:
            logger.error("core decision audit chain not opened (%s): %s", CORE_DECISION_AUDIT_PATH, exc)
            return None
    try:
        CORE_P0_RELAY = attach_p0_alert_relay(CORE_DECISION_AUDIT, P0_ALERT_QUEUE_PATH)
    except Exception as exc:
        logger.error("p0 alert relay not attached to the core decision chain: %s", exc)
    CORE_RECORDER = CoreDecisionRecorder(CORE_DECISION_AUDIT, CORE_P0_RELAY, CORE_NORMALIZED_EVENT_LOG).start()
    return CORE_P0_RELAY


def _stop_core_p0_path() -> None:
    """Drain the recorder (bounded), then let the relay enqueue what it was
    handed (bounded). What is left is counted in the P0 queue and recorded
    from the core's log at the next start. Never raises."""

    recorder, relay, audit = CORE_RECORDER, CORE_P0_RELAY, CORE_DECISION_AUDIT
    try:
        if recorder is not None:
            recorder.stop()
        if relay is not None and audit is not None:
            audit.wait_durable_listeners(5.0)
            relay.wait_idle(5.0)
            relay.stop(5.0)
    except Exception as exc:
        logger.error("core decision P0 alert path did not stop cleanly: %s", exc)


def _record_core_decision(event: Dict[str, Any]) -> None:
    """Hand a core decision event to the recorder. Never blocks, never raises:
    the recorder's bounded queue and single writer do the fsynced writes."""

    recorder = CORE_RECORDER
    if recorder is None:
        return
    try:
        recorder.submit(event)
    except Exception as exc:
        logger.error("core decision not handed to the P0 alert path: %s", exc)


# Set by _start_decision_explanations() when the service starts (_serve), like
# the P0 path: importing this module or calling the handlers writes nothing.
DECISION_EXPLANATIONS: Any | None = None


def _start_decision_explanations() -> Any | None:
    """Open the v2 explanation writer. If it cannot be opened the agent runs
    without it (logged): explanations are display and audit only."""

    global DECISION_EXPLANATIONS
    if DECISION_EXPLANATIONS is not None:
        return DECISION_EXPLANATIONS
    if LiveDecisionExplanationWriter is None:
        logger.error("decision explanations unavailable: azazel_edge.explanations not importable")
        return None
    try:
        DECISION_EXPLANATIONS = LiveDecisionExplanationWriter(DECISION_EXPLANATIONS_PATH)
    except Exception as exc:
        logger.error("decision explanations not written (%s): %s", DECISION_EXPLANATIONS_PATH, exc)
        return None
    return DECISION_EXPLANATIONS


def _record_decision_explanation(event: Dict[str, Any], advisory: Dict[str, Any]) -> None:
    """Write the v2 explanation of a core decision. After the advisory and
    the snapshot are written; never raises (the writer logs its failures)."""

    writer = DECISION_EXPLANATIONS
    if writer is None:
        return
    try:
        writer.record(event, advisory)
    except Exception as exc:
        logger.error("decision explanation not written: %s", exc)


def _note_core_forward_loss(dropped: int, failed: int, since: int) -> None:
    """The core's count of events it could not hand to this agent, to the P0 queue."""

    recorder = CORE_RECORDER
    if recorder is None:
        return
    try:
        recorder.note_forward_stats(dropped, failed, since)
    except Exception as exc:
        logger.error("core forward loss not reported: %s", exc)


def _audit_ai_scope(trace_id: str, source: str, intent: str, in_scope: bool, reason: str) -> None:
    if AI_AUDIT is None:
        return
    try:
        AI_AUDIT.log(
            "ai_assist",
            trace_id=(trace_id or "n/a"),
            source=(source or "ai_agent"),
            stage="scope",
            decision="in_scope" if in_scope else "out_of_scope",
            payload={
                "intent": str(intent or ""),
                "in_scope": bool(in_scope),
                "reason": str(reason or ""),
            },
        )
    except Exception:
        return


class AgentDirError(RuntimeError):
    """One of the agent's own directories is not safe to use; the agent stops."""


def _prepare_runtime_dir(target: Path) -> None:
    """The agent's own runtime directory (Edge#471 stage 2). A missing one is
    created (0750); an existing one is used as it is, never chmod'ed or
    chown'ed: it must be a real directory owned by this process's user that
    nobody else can write (no group/other write bit). Anything else stops
    the agent. The shared /run/azazel-edge belongs to the control daemon and
    is not touched."""
    old_umask = os.umask(0o027)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.mkdir(str(target), 0o750)
        except FileExistsError:
            pass
    except OSError as exc:
        raise AgentDirError(f"agent runtime directory {target}: {exc}") from exc
    finally:
        os.umask(old_umask)
    try:
        st = os.lstat(str(target))
    except OSError as exc:
        raise AgentDirError(f"agent runtime directory {target}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise AgentDirError(f"agent runtime directory {target} is not a real directory; refusing")
    if st.st_uid != os.geteuid():
        raise AgentDirError(
            f"agent runtime directory {target} is owned by uid {st.st_uid}, not this process (uid {os.geteuid()}); "
            "refusing (the shared /run/azazel-edge is the control daemon's)")
    if stat.S_IMODE(st.st_mode) & 0o022:
        raise AgentDirError(
            f"agent runtime directory {target} has mode {stat.S_IMODE(st.st_mode):04o} (group/other writable); refusing")


class AISocketSetupError(RuntimeError):
    """The socket's directory or path is not safe to use; the agent stops."""


def _prepare_ai_socket_dir(path: Path) -> None:
    """Make the socket's directory private: a real directory (not a symlink)
    owned by this process's user with mode 0700 (Edge#462).

    A missing directory is created with mode 0700. An existing one is
    accepted only when it already is private: a symlink, a non-directory,
    a directory owned by another user, or one with any group/other bit is
    refused (the shared runtime directory is 0770 for control.sock, and
    narrowing it would break control.sock). Nothing is changed through a
    path that could be a symlink."""
    target = path.parent
    target.parent.mkdir(parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    try:
        os.mkdir(str(target), SOCKET_DIR_MODE)
    except FileExistsError:
        pass
    finally:
        os.umask(old_umask)
    try:
        st = os.lstat(str(target))
    except OSError as exc:
        raise AISocketSetupError(f"ai socket directory {target}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise AISocketSetupError(f"ai socket directory {target} is a symlink; refusing")
    if not stat.S_ISDIR(st.st_mode):
        raise AISocketSetupError(f"ai socket directory {target} is not a directory; refusing")
    if st.st_uid != os.geteuid():
        raise AISocketSetupError(
            f"ai socket directory {target} is owned by uid {st.st_uid}, not this process (uid {os.geteuid()}); refusing")
    if stat.S_IMODE(st.st_mode) & 0o077:
        hint = ""
        if target == LEGACY_SOCKET_PATH.parent:
            hint = f" (the shared runtime directory; use the default {Path('/run/azazel-edge-ai/ai-bridge.sock')})"
        raise AISocketSetupError(
            f"ai socket directory {target} has mode {stat.S_IMODE(st.st_mode):04o}; it must be 0700{hint}; refusing")


def _bind_ai_socket(path: Path) -> socket.socket:
    """Bind ai-bridge.sock owner only (0600, the agent's own user and group)
    in its private directory (``_prepare_ai_socket_dir``; Edge#462).

    A stale socket is removed; any other entry at the path is refused. The
    umask is 0177 around bind, so the socket never has group/other bits, not
    even before the chmod. The umask is process wide: ``_serve`` binds before
    it starts any thread, so no other file is created while it is set."""
    try:
        st = os.lstat(str(path))
    except FileNotFoundError:
        st = None
    if st is not None:
        if not stat.S_ISSOCK(st.st_mode):
            raise AISocketSetupError(f"ai socket path {path} exists and is not a socket; refusing")
        os.unlink(str(path))
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o177)
    try:
        srv.bind(str(path))
    except Exception:
        srv.close()
        raise
    finally:
        os.umask(old_umask)
    # The agent's own group, also where the directory would pass its group
    # on (BSD semantics, or a setgid directory). The directory is private,
    # so the path cannot have been replaced since bind.
    os.chown(str(path), -1, os.getegid())
    os.chmod(str(path), SOCKET_MODE)
    if os.environ.get("AZAZEL_AI_SOCKET_MODE") not in (None, "", "0600", "600"):
        logger.warning("AZAZEL_AI_SOCKET_MODE is ignored: ai-bridge.sock is owner only (0600)")
    return srv


def _query_account_ids() -> tuple[int, int] | None:
    """(uid, primary gid) of QUERY_SOCKET_ACCOUNT, or None if it cannot be resolved."""
    try:
        entry = pwd.getpwnam(QUERY_SOCKET_ACCOUNT)
    except (KeyError, OSError):
        return None
    return int(entry.pw_uid), int(entry.pw_gid)


def _prepare_query_socket_dir(path: Path, gid: int) -> None:
    """The query socket's directory: a real directory owned by this process's
    user, group ``gid``, mode 0750. A missing one is created with exactly
    that (group and mode set through a descriptor opened without following
    symlinks). An existing one is accepted only as it is: a symlink, a
    non-directory, another owner, another group or another mode is refused,
    never fixed (privilege-inventory §10.4)."""
    target = path.parent
    target.parent.mkdir(parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    created = False
    try:
        os.mkdir(str(target), 0o700)
        created = True
    except FileExistsError:
        pass
    finally:
        os.umask(old_umask)
    try:
        fd = os.open(str(target), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise AISocketSetupError(f"query socket directory {target}: {exc}; refusing") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise AISocketSetupError(f"query socket directory {target} is not a directory; refusing")
        if st.st_uid != os.geteuid():
            raise AISocketSetupError(
                f"query socket directory {target} is owned by uid {st.st_uid}, not this process "
                f"(uid {os.geteuid()}); refusing")
        if created:
            # Only a directory this call created is given its group and mode.
            os.fchown(fd, -1, gid)
            os.fchmod(fd, QUERY_SOCKET_DIR_MODE)
        elif st.st_gid != gid or stat.S_IMODE(st.st_mode) not in QUERY_SOCKET_DIR_MODES_ACCEPTED:
            raise AISocketSetupError(
                f"query socket directory {target} has group {st.st_gid} and mode {stat.S_IMODE(st.st_mode):04o}; "
                f"it must be group {gid} and mode {QUERY_SOCKET_DIR_MODE:04o}; refusing")
    finally:
        os.close(fd)


def _bind_query_socket(path: Path, gid: int) -> socket.socket:
    """Bind the query socket 0660 with group ``gid`` (the Web UI account's
    group) inside its 0750 directory. Bound under umask 0117 so it never has
    other bits; a stale socket is replaced, any other entry is refused."""
    try:
        st = os.lstat(str(path))
    except FileNotFoundError:
        st = None
    if st is not None:
        if not stat.S_ISSOCK(st.st_mode):
            raise AISocketSetupError(f"query socket path {path} exists and is not a socket; refusing")
        os.unlink(str(path))
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o117)
    try:
        srv.bind(str(path))
    except Exception:
        srv.close()
        raise
    finally:
        os.umask(old_umask)
    os.chown(str(path), -1, gid)
    os.chmod(str(path), QUERY_SOCKET_MODE)
    return srv


def _setup_query_socket(path: Path | None = None) -> socket.socket | None:
    """Create the manual_query socket, or return None (logged as an error)
    when it cannot be created safely. ai-bridge.sock is not affected."""
    path = path or QUERY_SOCKET_PATH
    ids = _query_account_ids()
    if ids is None:
        logger.error("manual_query socket disabled: account %s does not exist (Web UI questions will fail)",
                     QUERY_SOCKET_ACCOUNT)
        return None
    _uid, gid = ids
    try:
        _prepare_query_socket_dir(path, gid)
        return _bind_query_socket(path, gid)
    except (AISocketSetupError, OSError) as exc:
        logger.error("manual_query socket disabled: %s (Web UI questions will fail)", exc)
        return None


def query_peer_allowed(uid: int | None) -> bool:
    """Only root or QUERY_SOCKET_ACCOUNT; an unknown peer or account gets nothing."""
    if uid is None:
        return False
    if uid == 0:
        return True
    web_uid = account_uid(QUERY_SOCKET_ACCOUNT)
    return web_uid is not None and uid == web_uid


def _count_query_refusal() -> int:
    with _QUERY_REFUSALS_LOCK:
        _QUERY_REFUSALS["total"] += 1
        return _QUERY_REFUSALS["total"]


def _query_refuse(conn: socket.socket, uid: int | None, pid: int | None, reason: str) -> None:
    total = _count_query_refusal()
    logger.warning("agent-query.sock: refused (%s) uid=%s pid=%s (refused so far=%d)", reason, uid, pid, total)
    try:
        conn.sendall((json.dumps({"ok": False, "error": "forbidden", "reason": reason}) + "\n").encode("utf-8"))
    except OSError:
        pass


def _handle_query_client(conn: socket.socket) -> None:
    """One manual_query per connection on the query socket. Nothing received
    here reaches _handle_event, the forward-stats path or the P0 path."""
    with conn:
        uid, pid = peer_credentials(conn)
        if not query_peer_allowed(uid):
            _query_refuse(conn, uid, pid, "peer_not_allowed")
            return
        deadline = time.monotonic() + QUERY_READ_TIMEOUT_SEC
        buf = b""
        try:
            while b"\n" not in buf:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _query_refuse(conn, uid, pid, "request_timeout")
                    return
                conn.settimeout(remaining)
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > QUERY_MAX_REQUEST_BYTES:
                    _query_refuse(conn, uid, pid, "request_too_large")
                    return
        except socket.timeout:
            _query_refuse(conn, uid, pid, "request_timeout")
            return
        except OSError:
            return
        line = buf.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()
        try:
            payload = json.loads(line) if line else None
        except json.JSONDecodeError:
            payload = None
        if not isinstance(payload, dict):
            _query_refuse(conn, uid, pid, "invalid_request")
            return
        if str(payload.get("action") or "") != "manual_query" or "schema" in payload:
            _query_refuse(conn, uid, pid, "only_manual_query")
            return
        conn.settimeout(None)
        try:
            resp = _handle_manual_query_request(payload)
        except Exception as exc:  # the caller must see a failure, not silence
            logger.exception("manual_query failed")
            resp = {"ok": False, "action": "manual_query", "error": f"manual_query_failed:{type(exc).__name__}"}
        try:
            conn.sendall((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
        except OSError:
            return


def _query_accept_loop(srv: socket.socket, stop: threading.Event) -> None:
    srv.settimeout(1.0)
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            if stop.is_set():
                return
            time.sleep(0.2)
            continue
        if not _QUERY_SLOTS.acquire(blocking=False):
            logger.warning("agent-query.sock: too many concurrent queries; answered busy")
            try:
                conn.sendall(b'{"ok": false, "error": "busy"}\n')
            except OSError:
                pass
            conn.close()
            continue
        threading.Thread(target=_handle_query_slot, args=(conn,), daemon=True).start()


def _handle_query_slot(conn: socket.socket) -> None:
    try:
        _handle_query_client(conn)
    finally:
        _QUERY_SLOTS.release()


def _metrics_snapshot() -> Dict[str, Any]:
    with METRICS_LOCK:
        snap = dict(METRICS)
    snap["queue_depth"] = LLM_QUEUE.qsize()
    snap["queue_capacity"] = LLM_QUEUE_MAX
    snap["policy"] = dict(RUNTIME_POLICY)
    return snap


def _persist_metrics() -> None:
    _write_json(METRICS_PATH, _metrics_snapshot())


def _persist_policy() -> None:
    _write_json(POLICY_PATH, dict(RUNTIME_POLICY))


def _metrics_update(**updates: Any) -> None:
    now = time.time()
    with METRICS_LOCK:
        for k, v in updates.items():
            METRICS[k] = v
        METRICS["queue_depth"] = LLM_QUEUE.qsize()
        METRICS["queue_max_seen"] = max(int(METRICS.get("queue_max_seen", 0)), LLM_QUEUE.qsize())
        METRICS["last_update_ts"] = now


def _metrics_inc(name: str, delta: int = 1) -> None:
    now = time.time()
    with METRICS_LOCK:
        METRICS[name] = int(METRICS.get(name, 0)) + delta
        METRICS["queue_depth"] = LLM_QUEUE.qsize()
        METRICS["queue_max_seen"] = max(int(METRICS.get("queue_max_seen", 0)), LLM_QUEUE.qsize())
        METRICS["last_update_ts"] = now


def _metrics_heartbeat() -> None:
    with METRICS_LOCK:
        METRICS["queue_depth"] = LLM_QUEUE.qsize()
        METRICS["queue_max_seen"] = max(int(METRICS.get("queue_max_seen", 0)), LLM_QUEUE.qsize())
        METRICS["last_update_ts"] = time.time()


def _update_kpi_rates() -> None:
    with METRICS_LOCK:
        requests = max(1, int(METRICS.get("llm_requests", 0)))
        completed = int(METRICS.get("llm_completed", 0))
        fallback = int(METRICS.get("llm_fallback_count", 0))
        empty = int(METRICS.get("llm_empty_response_count", 0))
        METRICS["llm_completed_rate"] = round(completed / requests, 4)
        METRICS["llm_fallback_rate"] = round(fallback / requests, 4)
        METRICS["llm_empty_rate"] = round(empty / requests, 4)


def _set_policy_mode(mode: str, reason: str) -> None:
    mode_norm = "degraded" if str(mode).lower() == "degraded" else "normal"
    if RUNTIME_POLICY.get("mode") == mode_norm and RUNTIME_POLICY.get("reason") == reason:
        return
    RUNTIME_POLICY["mode"] = mode_norm
    RUNTIME_POLICY["reason"] = reason
    RUNTIME_POLICY["updated_at"] = time.time()
    _metrics_update(policy_mode=mode_norm)
    with IO_LOCK:
        _persist_policy()
        _persist_metrics()
    logger.warning("LLM runtime policy switched to %s (%s)", mode_norm, reason)


def _recompute_policy() -> None:
    _update_kpi_rates()
    snap = _metrics_snapshot()
    requests = int(snap.get("llm_requests", 0))
    completed_rate = float(snap.get("llm_completed_rate", 0.0))
    empty_rate = float(snap.get("llm_empty_rate", 0.0))
    fallback_rate = float(snap.get("llm_fallback_rate", 0.0))

    if requests >= 10 and (completed_rate < 0.15 or empty_rate > 0.35 or fallback_rate > 0.70):
        _set_policy_mode("degraded", f"quality_low:c={completed_rate:.2f}:e={empty_rate:.2f}:f={fallback_rate:.2f}")
        return
    if requests >= 20 and completed_rate >= 0.40 and empty_rate < 0.20 and fallback_rate < 0.55:
        _set_policy_mode("normal", f"quality_recovered:c={completed_rate:.2f}:e={empty_rate:.2f}:f={fallback_rate:.2f}")


def _risk_level(score: int) -> str:
    if score >= CRITICAL_MIN:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _system_mem_state() -> tuple[int, int]:
    mem_available_kb = 0
    swap_total_kb = 0
    swap_free_kb = 0
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                mem_available_kb = int(line.split()[1])
            elif line.startswith("SwapTotal:"):
                swap_total_kb = int(line.split()[1])
            elif line.startswith("SwapFree:"):
                swap_free_kb = int(line.split()[1])
    except Exception:
        return 0, 0
    swap_used_kb = max(0, swap_total_kb - swap_free_kb)
    return int(mem_available_kb / 1024), int(swap_used_kb / 1024)


def _ops_coach_allowed() -> tuple[bool, str]:
    if not OPS_COACH_ENABLED:
        return False, "ops_disabled"
    mem_avail_mb, swap_used_mb = _system_mem_state()
    if mem_avail_mb > 0 and mem_avail_mb < OPS_MIN_MEM_AVAILABLE_MB:
        return False, f"low_mem:{mem_avail_mb}MB"
    if swap_used_mb > OPS_MAX_SWAP_USED_MB:
        return False, f"swap_high:{swap_used_mb}MB"
    return True, "ok"


def _should_escalate_to_ops(
    advisory: Dict[str, Any],
    llm_status: str,
    confidence: float,
    llm_escalation: bool = False,
) -> tuple[bool, str]:
    global _LAST_OPS_ESCALATE_TS
    if not OPS_COACH_ENABLED:
        return False, "ops_disabled"

    now = time.time()
    if _LAST_OPS_ESCALATE_TS > 0 and (now - _LAST_OPS_ESCALATE_TS) < OPS_ESCALATE_COOLDOWN_SEC:
        return False, "cooldown"

    risk_score = int(advisory.get("risk_score") or 0)
    if llm_status != "completed":
        return True, "llm_not_completed"
    if risk_score >= CRITICAL_MIN:
        return True, "critical_risk"
    if llm_escalation:
        return True, "llm_escalation_flag"
    if risk_score >= OPS_ESCALATE_MIN_RISK and confidence < OPS_ESCALATE_LOW_CONF:
        return True, "high_risk_low_confidence"
    return False, "not_needed"


def _evaluate_correlation(advisory: Dict[str, Any]) -> Dict[str, Any]:
    if not CORR_ENABLED:
        return {
            "enabled": False,
            "force_llm": False,
            "repeat_trigger": False,
            "sid_diversity_trigger": False,
            "hits_in_window": 0,
            "unique_sid_count": 0,
            "window_sec": CORR_WINDOW_SEC,
        }

    src_ip = str(advisory.get("src_ip") or "").strip()
    sid = int(advisory.get("suricata_sid") or 0)
    attack_type = str(advisory.get("attack_type") or "").strip()
    risk_score = int(advisory.get("risk_score") or 0)
    if not src_ip:
        return {
            "enabled": True,
            "force_llm": False,
            "repeat_trigger": False,
            "sid_diversity_trigger": False,
            "hits_in_window": 0,
            "unique_sid_count": 0,
            "window_sec": CORR_WINDOW_SEC,
        }

    now = time.time()
    cutoff = now - max(1, CORR_WINDOW_SEC)
    with CORR_LOCK:
        bucket = CORR_STATE.get(src_ip, [])
        bucket = [entry for entry in bucket if float(entry.get("ts") or 0.0) >= cutoff]
        bucket.append({"ts": now, "sid": sid, "attack_type": attack_type})
        if len(bucket) > max(1, CORR_MAX_HISTORY_PER_SRC):
            bucket = bucket[-max(1, CORR_MAX_HISTORY_PER_SRC) :]
        CORR_STATE[src_ip] = bucket

    hits = len(bucket)
    unique_sid = len({int(entry.get("sid") or 0) for entry in bucket if int(entry.get("sid") or 0) > 0})
    repeat_trigger = hits >= max(2, CORR_REPEAT_THRESHOLD)
    sid_diversity_trigger = unique_sid >= max(2, CORR_SID_DIVERSITY_THRESHOLD)
    force_llm = (
        (repeat_trigger or sid_diversity_trigger)
        and risk_score >= max(0, CORR_MIN_RISK_SCORE)
        and risk_score < LLM_AMBIG_MIN
    )
    return {
        "enabled": True,
        "force_llm": force_llm,
        "repeat_trigger": repeat_trigger,
        "sid_diversity_trigger": sid_diversity_trigger,
        "hits_in_window": hits,
        "unique_sid_count": unique_sid,
        "window_sec": CORR_WINDOW_SEC,
    }


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on", "escalate", "urgent"}


def _normalize_confidence(value: Any) -> float:
    try:
        conf = float(value)
    except Exception as exc:
        raise ValueError("analyst_invalid_confidence") from exc
    if conf > 1.0 and conf <= 100.0:
        conf = conf / 100.0
    if conf < 0.0 or conf > 1.0:
        raise ValueError("analyst_invalid_confidence")
    return round(conf, 4)


def _normalize_analyst_result(raw: Dict[str, Any]) -> Dict[str, Any]:
    verdict_raw = str(raw.get("verdict") or "").strip().lower()
    verdict_alias = {
        "safe": "allow",
        "benign": "allow",
        "deny": "block",
        "drop": "block",
        "contain": "block",
    }
    verdict = verdict_alias.get(verdict_raw, verdict_raw)
    allowed_verdict = {"allow", "monitor", "block", "deceive", "escalate", "hold"}
    if verdict not in allowed_verdict:
        raise ValueError("analyst_invalid_verdict")

    reason = str(raw.get("reason") or "").strip()
    if not reason:
        raise ValueError("analyst_empty_reason")
    reason = reason[:80]

    suggested_action = str(raw.get("suggested_action") or "").strip()
    if not suggested_action:
        suggested_action = verdict
    suggested_action = suggested_action[:80]

    return {
        "verdict": verdict,
        "confidence": _normalize_confidence(raw.get("confidence")),
        "reason": reason,
        "suggested_action": suggested_action,
        "escalation": _as_bool(raw.get("escalation")),
    }


def _normalize_ops_result(raw: Dict[str, Any]) -> Dict[str, Any]:
    runbook_id = _normalize_runbook_id(raw.get("runbook_id") or raw.get("playbook_id") or raw.get("id") or "")
    summary = str(raw.get("summary") or raw.get("reason") or raw.get("analysis") or "").strip()
    operator_note = str(raw.get("operator_note") or raw.get("suggested_action") or raw.get("action") or "").strip()
    if not summary:
        raise ValueError("ops_empty_summary")
    if not operator_note:
        operator_note = summary
    return {
        "runbook_id": runbook_id,
        "summary": summary[:120],
        "operator_note": operator_note[:120],
    }


def _normalize_manual_result(raw: Dict[str, Any]) -> Dict[str, Any]:
    answer = str(raw.get("answer") or raw.get("summary") or raw.get("operator_note") or "").strip()
    if not answer:
        raise ValueError("manual_empty_answer")
    runbook_id = _normalize_runbook_id(raw.get("runbook_id") or "")
    operator_note = str(raw.get("operator_note") or "").strip()[:120]
    if not operator_note:
        operator_note = answer[:120]
    user_message = str(raw.get("user_message") or raw.get("user_note") or "").strip()[:160]
    return {
        "answer": answer[:240],
        "confidence": _normalize_confidence(raw.get("confidence", 0.6)),
        "runbook_id": runbook_id,
        "operator_note": operator_note,
        "user_message": user_message,
    }


def _latest_advisory_snapshot() -> Dict[str, Any]:
    try:
        if ADVISORY_PATH.exists():
            data = json.loads(ADVISORY_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _normalize_runbook_id(value: Any) -> str:
    runbook_id = str(value or "").strip()[:48]
    if not runbook_id or runbook_get is None:
        return runbook_id
    try:
        runbook_get(runbook_id)
        return runbook_id
    except Exception:
        return ""


def _classify_manual_question(question: str) -> str:
    q = str(question or "").lower()
    if any(token in q for token in ("onboarding", "初回", "初期接続", "登録")):
        return "wifi_onboarding"
    if any(token in q for token in ("reconnect", "再接続", "再接続できない")):
        return "wifi_reconnect"
    if any(token in q for token in ("portal", "ポータル", "captive")):
        return "portal"
    if any(token in q for token in ("dns", "名前解決", "host", "hostname")):
        return "dns"
    if any(token in q for token in ("gateway", "route", "uplink", "回線", "ゲートウェイ")):
        return "route"
    if any(token in q for token in ("service", "systemd", "サービス")):
        return "service"
    if any(token in q for token in ("epd", "display", "e-paper", "電子ペーパー")):
        return "epd"
    if any(token in q for token in ("log", "ログ", "llm", "ai")):
        return "ai_logs"
    if any(token in q for token in ("wifi", "ssid", "connect", "接続", "繋", "ネット")):
        return "wifi_issue"
    return "snapshot"


def _guess_runbook_id(question: str) -> str:
    kind = _classify_manual_question(question)
    mapping = {
        "wifi_onboarding": "rb.user.device-onboarding-guide",
        "wifi_reconnect": "rb.user.reconnect-guide",
        "portal": "rb.user.portal-access-guide",
        "wifi_issue": "rb.user.first-contact.network-issue",
        "dns": "rb.noc.dns.failure.check",
        "route": "rb.noc.default-route.check",
        "service": "rb.noc.service.status.check",
        "epd": "rb.ops.epd.state.check",
        "ai_logs": "rb.ops.logs.ai.recent",
        "snapshot": "rb.noc.ui-snapshot.check",
    }
    return mapping.get(kind, "rb.noc.ui-snapshot.check")


def _runbook_user_message(runbook_id: str, lang: str = "ja", default: str = "") -> str:
    if not runbook_id or runbook_get is None:
        return default[:160]
    try:
        runbook = runbook_get(runbook_id, lang=lang)
        if localize_runbook_user_message is not None:
            return str(localize_runbook_user_message(runbook, lang=lang, default=default)).strip()[:160]
        return str(runbook.get("user_message_template") or default).strip()[:160]
    except Exception:
        return default[:160]


def _manual_router_response(
    question: str,
    sender: str,
    source: str,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any] | None:
    q = str(question or "").strip()
    if not q:
        return None
    q_lower = q.lower()
    ctx = context if isinstance(context, dict) else {}
    audience = str(ctx.get("audience") or ("operator" if str(source or "") in {"webui", "ops-comm", "mattermost_post", "mattermost_command", "cli"} else "beginner")).strip() or "operator"
    lang = normalize_lang(ctx.get("lang"))
    route_info = _default_route_info()
    latest = _latest_advisory_snapshot()
    state_name = str(latest.get("state_name") or "UNKNOWN")
    risk_score = int(latest.get("risk_score") or 0)

    runbook_id = ""
    answer = ""

    kind = _classify_manual_question(q_lower)

    if kind == "wifi_onboarding":
        runbook_id = "rb.user.device-onboarding-guide"
        answer = translate(
            "agent.manual.wifi_onboarding",
            lang=lang,
            default="M.I.O. assessment: Treat this as first-time onboarding. Tell the user to select only the assigned SSID and attempt the connection one step at a time.",
        )
    elif kind == "wifi_reconnect":
        runbook_id = "rb.user.reconnect-guide"
        answer = translate(
            "agent.manual.wifi_reconnect",
            lang=lang,
            default="M.I.O. assessment: Treat this as a reconnect workflow. Instruct the user to toggle Wi-Fi once and confirm the result on the same SSID.",
        )
    elif kind == "portal":
        runbook_id = "rb.user.portal-access-guide"
        answer = translate(
            "agent.manual.portal",
            lang=lang,
            default="M.I.O. assessment: Treat this as portal redirection failure. Keep the user connected and open one normal website once to confirm whether the portal appears.",
        )
    elif kind == "wifi_issue":
        runbook_id = "rb.user.first-contact.network-issue"
        answer = translate(
            "agent.manual.wifi_issue",
            lang=lang,
            default="M.I.O. assessment: First separate single-device failure from multi-device failure. Ask the user for one symptom first and stop repeated restarts.",
        )
    elif kind == "dns":
        runbook_id = "rb.noc.dns.failure.check"
        answer = translate(
            "agent.manual.dns",
            lang=lang,
            default="M.I.O. assessment: Separate DNS failure from uplink failure. Current uplink={uplink} gateway={gateway}",
            uplink=route_info.get("up_if", "-"),
            gateway=route_info.get("gateway_ip", "-"),
        )
    elif kind == "route":
        runbook_id = "rb.noc.default-route.check"
        answer = translate(
            "agent.manual.route",
            lang=lang,
            default="M.I.O. assessment: Verify the actual uplink and route state. Current uplink={uplink} up_ip={up_ip} gateway={gateway}",
            uplink=route_info.get("up_if", "-"),
            up_ip=route_info.get("up_ip", "-"),
            gateway=route_info.get("gateway_ip", "-"),
        )
    elif kind == "service":
        runbook_id = "rb.noc.service.status.check"
        answer = translate(
            "agent.manual.service",
            lang=lang,
            default="M.I.O. assessment: First confirm whether this is a real service failure instead of a UI mismatch. Check status, then journal.",
        )
    elif kind == "epd":
        runbook_id = "rb.ops.epd.state.check"
        answer = translate(
            "agent.manual.epd",
            lang=lang,
            default="M.I.O. assessment: Check the last EPD render state and compare it with the WebUI/TUI snapshot.",
        )
    elif kind == "ai_logs":
        runbook_id = "rb.ops.logs.ai.recent"
        answer = translate(
            "agent.manual.ai_logs",
            lang=lang,
            default="M.I.O. assessment: Check recent AI successes, failures, and fallback activity to isolate the cause of delay.",
        )

    if not runbook_id:
        return None

    user_message = _runbook_user_message(
        runbook_id,
        lang=lang,
        default=translate(
            "agent.user.wait",
            lang=lang,
            default="We are checking the current situation. Do not change settings until we provide the next instruction.",
        ),
    )
    return {
        "status": "routed",
        "model": "manual_router",
        "fallback_model_used": False,
        "latency_ms": 0,
        "answer": answer[:240],
        "confidence": 0.82,
        "runbook_id": runbook_id,
        "operator_note": f"state={state_name} risk={risk_score} audience={audience} route={route_info.get('up_if', '-')} question={q[:48]}",
        "user_message": user_message,
    }


def _manual_fallback_response(question: str, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    latest = _latest_advisory_snapshot()
    state_name = str(latest.get("state_name") or "UNKNOWN")
    risk_score = int(latest.get("risk_score") or 0)
    rec = str(latest.get("recommendation") or "ログ確認を継続してください。")
    ctx = context if isinstance(context, dict) else {}
    lang = normalize_lang(ctx.get("lang"))
    route_info = _default_route_info()
    runbook_id = _guess_runbook_id(question)
    user_message = _runbook_user_message(
        runbook_id,
        lang=lang,
        default=translate(
            "agent.user.wait",
            lang=lang,
            default="We are checking the current situation. Do not change settings until we provide the next instruction.",
        ),
    )
    q = str(question or "").lower()
    answer = translate("agent.fallback.current_recommendation", lang=lang, default="Current recommendation: {recommendation}", recommendation=rec)
    if any(token in q for token in ("dns", "名前解決", "host")):
        answer = translate(
            "agent.fallback.dns",
            lang=lang,
            default="M.I.O. assessment: Separate name-resolution failure from uplink failure. Current uplink={uplink} gateway={gateway}",
            uplink=route_info.get("up_if", "-"),
            gateway=route_info.get("gateway_ip", "-"),
        )[:240]
    elif any(token in q for token in ("wifi", "ssid", "繋", "接続", "ネット")):
        answer = translate(
            "agent.fallback.wifi",
            lang=lang,
            default="M.I.O. assessment: First separate single-device failure from multi-device failure. Ask the user for one symptom and stop repeated restarts.",
        )[:240]
    elif any(token in q for token in ("service", "systemd", "サービス")):
        answer = translate(
            "agent.fallback.service",
            lang=lang,
            default="M.I.O. assessment: Confirm whether this is a real service failure instead of a UI mismatch, then check status and journal if needed.",
        )[:240]
    audience = str(ctx.get("audience") or "").strip() or "operator"
    return {
        "status": "fallback",
        "model": "tactical_snapshot",
        "fallback_model_used": False,
        "latency_ms": 0,
        "answer": answer,
        "confidence": 0.35,
        "runbook_id": runbook_id,
        "operator_note": f"state={state_name} risk={risk_score} audience={audience} question={question[:48]}",
        "user_message": user_message,
    }


def _run_manual_query(
    question: str,
    sender: str,
    source: str,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    q = str(question or "").strip()
    if not q:
        return {"status": "error", "reason": "empty_question", "model": OPS_COACH_MODEL}
    q = q[:MANUAL_QUERY_MAX_CHARS]
    ctx = context if isinstance(context, dict) else {}
    lang = normalize_lang(ctx.get("lang"))
    _metrics_inc("manual_requests", 1)

    routed = _manual_router_response(q, sender=sender, source=source, context=ctx)
    if routed is not None:
        _audit_ai_scope(
            trace_id=str(ctx.get("trace_id") or ""),
            source=str(source or "manual_query"),
            intent="manual_query",
            in_scope=False,
            reason="manual_router_static_path",
        )
        _metrics_inc("manual_routed_count", 1)
        _metrics_inc("manual_completed", 1)
        _append_jsonl(
            LLM_RESULT_LOG_PATH,
            {
                "ts": time.time(),
                "kind": "manual_query_routed",
                "source": source,
                "sender": sender,
                "question": q,
                "model": "manual_router",
                "latency_ms": 0,
                "response": routed,
            },
        )
        return routed

    allowed, why = _ops_coach_allowed()
    if not allowed:
        _audit_ai_scope(
            trace_id=str(ctx.get("trace_id") or ""),
            source=str(source or "manual_query"),
            intent="manual_query",
            in_scope=False,
            reason=why,
        )
        return {"status": "skipped", "reason": why, "model": OPS_COACH_MODEL}

    latest = _latest_advisory_snapshot()
    audience = str(ctx.get("audience") or ("operator" if str(source or "") in {"webui", "ops-comm", "mattermost_post", "mattermost_command", "cli"} else "beginner")).strip() or "operator"
    route_info = _default_route_info()
    payload = {
        "source": str(source or "webui"),
        "sender": str(sender or "operator"),
        "lang": lang,
        "audience": audience,
        "question": q,
        "latest_risk_score": int(latest.get("risk_score") or 0),
        "latest_attack_type": str(latest.get("attack_type") or "unknown"),
        "latest_state_name": str(latest.get("state_name") or "UNKNOWN"),
        "latest_user_state": str(latest.get("user_state") or "CHECKING"),
        "latest_recommendation": str(latest.get("recommendation") or ""),
        "current_uplink": route_info.get("up_if", "-"),
        "current_gateway": route_info.get("gateway_ip", "-"),
        "current_up_ip": route_info.get("up_ip", "-"),
        "context": ctx,
    }

    errors: list[dict[str, str]] = []
    overall_started = time.time()
    _audit_ai_scope(
        trace_id=str(ctx.get("trace_id") or ""),
        source=str(source or "manual_query"),
        intent="manual_query",
        in_scope=False,
        reason="manual_query_schema_outside_ai_governance_contract",
    )
    for idx, model in enumerate(MANUAL_MODEL_CHAIN):
        if (time.time() - overall_started) >= MANUAL_TOTAL_TIMEOUT_SEC:
            errors.append({"model": model, "reason": "manual_total_timeout_exceeded"})
            break
        started = time.time()
        try:
            raw = _ollama_chat(
                payload,
                model=model,
                prompt_system=MANUAL_PROMPT_SYSTEM,
                keep_alive=MANUAL_KEEP_ALIVE,
                num_predict=MANUAL_NUM_PREDICT,
                num_ctx=MANUAL_NUM_CTX,
                num_thread=MANUAL_NUM_THREAD,
                timeout_sec=MANUAL_QUERY_TIMEOUT_SEC,
                return_text_on_parse_error=True,
                required_keys=None,
            )
            out = _normalize_manual_result(raw)
            latency_ms = int((time.time() - started) * 1000)
            _metrics_inc("manual_completed", 1)
            _append_jsonl(
                LLM_RESULT_LOG_PATH,
                {
                    "ts": time.time(),
                    "kind": "manual_query",
                    "source": source,
                    "sender": sender,
                    "question": q,
                    "model": model,
                    "latency_ms": latency_ms,
                    "response": out,
                },
            )
            return {
                "status": "completed",
                "model": model,
                "fallback_model_used": idx > 0,
                "latency_ms": latency_ms,
                **out,
            }
        except Exception as exc:
            reason = str(exc)
            if reason.startswith("manual_"):
                _metrics_inc("manual_schema_invalid_count", 1)
            errors.append({"model": model, "reason": reason})
            if isinstance(exc, LlmEndpointRejected) or "timed out" in reason.lower():
                break
            continue

    _metrics_inc("manual_failed", 1)
    fallback = _manual_fallback_response(q, context=ctx)
    fallback["reason"] = "all_manual_models_failed"
    fallback["errors"] = errors
    return fallback


def _run_ops_coach(advisory: Dict[str, Any], verdict: str, confidence: float, reason: str, trigger_reason: str) -> Dict[str, Any]:
    global _LAST_OPS_ESCALATE_TS
    allowed, why = _ops_coach_allowed()
    if not allowed:
        _audit_ai_scope(
            trace_id=str(advisory.get("trace_id") or ""),
            source="ops_coach",
            intent="ops_coach",
            in_scope=False,
            reason=why,
        )
        return {"status": "skipped", "reason": why, "model": OPS_COACH_MODEL, "trigger": trigger_reason}

    coach_payload = {
        "state_name": advisory.get("state_name", "PROBE"),
        "risk_score": advisory.get("risk_score", 0),
        "attack_type": advisory.get("attack_type", "unknown"),
        "llm_verdict": verdict,
        "llm_confidence": confidence,
        "llm_reason": reason,
        "recommendation": advisory.get("recommendation", ""),
    }
    errors: list[dict[str, str]] = []
    _audit_ai_scope(
        trace_id=str(advisory.get("trace_id") or ""),
        source="ops_coach",
        intent="ops_coach",
        in_scope=False,
        reason="ops_coach_schema_outside_ai_governance_contract",
    )
    for idx, model in enumerate(OPS_MODEL_CHAIN):
        try:
            coach = _ollama_chat(
                coach_payload,
                model=model,
                prompt_system=OPS_PROMPT_SYSTEM,
                keep_alive=OPS_KEEP_ALIVE,
                num_predict=OPS_NUM_PREDICT,
                required_keys=None,
            )
            coach_norm = _normalize_ops_result(coach)
            _LAST_OPS_ESCALATE_TS = time.time()
            if idx > 0:
                _metrics_inc("ops_fallback_model_count", 1)
            return {
                "status": "completed",
                "model": model,
                "trigger": trigger_reason,
                "fallback_model_used": idx > 0,
                "runbook_id": coach_norm["runbook_id"],
                "summary": coach_norm["summary"],
                "operator_note": coach_norm["operator_note"],
            }
        except Exception as exc:
            if str(exc).startswith("ops_"):
                _metrics_inc("ops_schema_invalid_count", 1)
            errors.append({"model": model, "reason": str(exc)})
            if isinstance(exc, LlmEndpointRejected):
                break
            continue
    return {
        "status": "error",
        "model": OPS_COACH_MODEL,
        "trigger": trigger_reason,
        "reason": "all_ops_models_failed",
        "errors": errors,
    }


def _recommendation(ev: Dict[str, Any], score: int) -> str:
    port = int(ev.get("target_port") or 0)
    if score >= CRITICAL_MIN:
        return f"Block source and route to decoy immediately (port={port})"
    if score >= 60:
        return f"Apply delay policy and increase telemetry (port={port})"
    return "Observe and continue baseline monitoring"


def _state_name(score: int) -> str:
    if score >= CRITICAL_MIN:
        return "CONTAIN"
    if score >= 60:
        return "DEGRADED"
    if score >= 40:
        return "PROBE"
    return "NORMAL"


def _user_state(state_name: str) -> str:
    m = {
        "NORMAL": "SAFE",
        "PROBE": "LIMITED",
        "DEGRADED": "LIMITED",
        "CONTAIN": "CONTAINED",
        "DECEPTION": "DECEPTION",
    }
    return m.get(state_name, "CHECKING")


def _event_trace_id(event: Dict[str, Any]) -> str:
    enforcement = event.get("enforcement") if isinstance(event, dict) else {}
    if isinstance(enforcement, dict):
        trace_id = str(enforcement.get("trace_id") or "").strip()
        if trace_id:
            return trace_id
    return f"trace-{secrets.token_hex(8)}"


def _build_advisory(event: Dict[str, Any]) -> Dict[str, Any]:
    global _LAST_RISK_SCORE, _LAST_STATE_NAME

    norm = event.get("normalized") if isinstance(event, dict) else {}
    if not isinstance(norm, dict):
        norm = {}

    features = {
        "suricata_sid": int(norm.get("sid") or 0),
        "suricata_sev": int(norm.get("severity") or 0),
        "suricata_signature": str(norm.get("attack_type") or ""),
        "suricata_category": str(norm.get("category") or ""),
        "suricata_action": str(norm.get("action") or "allowed"),
        "target_port": int(norm.get("target_port") or 0),
        "protocol": str(norm.get("protocol") or ""),
    }
    risk_score, factors = SCORER.score_with_features(features)

    advisory = {
        "ts": time.time(),
        "trace_id": _event_trace_id(event),
        "source": "ai_agent",
        "decision_pipeline": {
            "first_pass": {
                "engine": "tactical_scorer_v1",
                "role": "first_minute_triage",
            },
            "second_pass": {
                "engine": "evidence_plane_soc_v1",
                "role": "context_enrichment",
                "status": "pending",
            },
        },
        "risk_level": _risk_level(risk_score),
        "risk_score": risk_score,
        "attack_type": str(norm.get("attack_type") or "unknown"),
        "src_ip": str(norm.get("src_ip") or ""),
        "dst_ip": str(norm.get("dst_ip") or ""),
        "target_port": int(norm.get("target_port") or 0),
        "recommendation": _recommendation(norm, risk_score),
        "score_factors": factors,
        "score_engine": "tactical_scorer_v1",
        "state_name": _state_name(risk_score),
        "user_state": _user_state(_state_name(risk_score)),
        "suricata_severity": int(features["suricata_sev"]),
        "suricata_sid": int(features["suricata_sid"]),
    }
    try:
        second_pass = DECISION_LAYERS.enrich_with_second_pass(event, advisory)
    except Exception as exc:
        second_pass = {
            "stage": "second_pass",
            "engine": "evidence_plane_soc_v1",
            "status": "failed",
            "reason": str(exc),
        }
    advisory["decision_pipeline"]["second_pass"] = second_pass
    advisory["second_pass"] = second_pass
    correlation = _evaluate_correlation(advisory)
    advisory["correlation"] = correlation
    if bool(correlation.get("force_llm")):
        if bool(correlation.get("repeat_trigger")):
            advisory["score_factors"].append(
                f"corr_repeat_src_ip={int(correlation.get('hits_in_window') or 0)}/{int(correlation.get('window_sec') or 0)}s"
            )
        if bool(correlation.get("sid_diversity_trigger")):
            advisory["score_factors"].append(
                f"corr_sid_diversity={int(correlation.get('unique_sid_count') or 0)}"
            )
        _metrics_inc("correlation_escalations", 1)

    state_before = StateSnapshot(
        state="ANALYZING",
        user_state="NORMAL",
        suspicion=float(_LAST_RISK_SCORE),
        risk_score=int(_LAST_RISK_SCORE),
    )
    state_after = StateSnapshot(
        state="ANALYZING",
        user_state="NORMAL",
        suspicion=float(risk_score),
        risk_score=risk_score,
    )
    score_delta = ScoreDelta(
        suspicion_add=max(0.0, float(risk_score - _LAST_RISK_SCORE)),
        suspicion_decay=max(0.0, float(_LAST_RISK_SCORE - risk_score)),
    )
    record = DecisionLogger.create_record(
        engine_version="0.1.0",
        config_hash=CONFIG_HASH,
        inputs_source="suricata",
        event_digest=f"sid:{features['suricata_sid']}:port:{features['target_port']}",
        event_min={
            "sid": features["suricata_sid"],
            "severity": features["suricata_sev"],
            "signature": features["suricata_signature"],
            "category": features["suricata_category"],
            "action": features["suricata_action"],
        },
        features=features,
        state_before=state_before,
        score_delta=score_delta,
        constraints_triggered=[],
        chosen=[ChosenAction(action_type="action", detail={"recommendation": advisory["recommendation"]})],
        state_after=state_after,
        parse_errors={},
    )
    DECISION_LOGGER.log_decision(record)
    _LAST_RISK_SCORE = risk_score
    _LAST_STATE_NAME = advisory["state_name"]

    return advisory


def _is_ambiguous(advisory: Dict[str, Any]) -> tuple[bool, str]:
    score = int(advisory.get("risk_score") or 0)
    min_score = LLM_AMBIG_MIN_DEGRADED if RUNTIME_POLICY.get("mode") == "degraded" else LLM_AMBIG_MIN
    if min_score <= score <= LLM_AMBIG_MAX:
        return True, "risk_score_ambiguous_range"
    corr = advisory.get("correlation")
    if isinstance(corr, dict) and bool(corr.get("force_llm")):
        return True, "correlation_escalation"
    return False, "risk_score_outside_ambiguous_range"


def _select_analyst_model() -> str:
    if RUNTIME_POLICY.get("mode") == "degraded":
        return LLM_MODEL_DEGRADED
    return LLM_MODEL_PRIMARY


def _route_llm(event: Dict[str, Any], advisory: Dict[str, Any]) -> None:
    if not LLM_ENABLED:
        advisory["llm"] = {"status": "disabled", "reason": "llm_disabled"}
        _metrics_update(last_error="")
        return
    ambiguous, route_reason = _is_ambiguous(advisory)
    if not ambiguous:
        advisory["llm"] = {
            "status": "skipped_non_ambiguous",
            "reason": route_reason,
        }
        if int(advisory.get("risk_score") or 0) >= CRITICAL_MIN:
            try:
                LLM_QUEUE.put_nowait(
                    {
                        "event": event,
                        "advisory": advisory.copy(),
                        "enqueued_at": time.time(),
                        "ops_only": True,
                    }
                )
                advisory["ops_coach"] = {"status": "queued", "reason": "critical_risk_direct", "model": OPS_COACH_MODEL}
                _metrics_inc("ops_requests", 1)
            except queue.Full:
                advisory["ops_coach"] = {"status": "deferred", "reason": "queue_full", "model": OPS_COACH_MODEL}
                _metrics_inc("deferred_count", 1)
        _metrics_update(last_error="")
        return

    queue_depth = LLM_QUEUE.qsize()
    if queue_depth >= LLM_QUEUE_MAX:
        advisory["llm"] = {"status": "deferred", "reason": "queue_full", "queue_depth": queue_depth}
        _metrics_inc("deferred_count", 1)
        _metrics_update(last_error="queue_full")
        _append_jsonl(
            LLM_DEFERRED_LOG_PATH,
            {
                "ts": time.time(),
                "reason": "queue_full",
                "queue_depth": queue_depth,
                "sid": advisory.get("suricata_sid", 0),
                "risk_score": advisory.get("risk_score", 0),
            },
        )
        return

    model = _select_analyst_model()
    task = {"event": event, "advisory": advisory.copy(), "enqueued_at": time.time(), "model": model}
    try:
        LLM_QUEUE.put_nowait(task)
        advisory["llm"] = {"status": "queued", "queue_depth": LLM_QUEUE.qsize(), "model": model, "reason": route_reason}
        _metrics_inc("llm_requests", 1)
        _metrics_update(last_error="")
    except queue.Full:
        advisory["llm"] = {"status": "deferred", "reason": "queue_full", "queue_depth": LLM_QUEUE.qsize()}
        _metrics_inc("deferred_count", 1)
        _metrics_update(last_error="queue_full")
        _append_jsonl(
            LLM_DEFERRED_LOG_PATH,
            {
                "ts": time.time(),
                "reason": "queue_full",
                "queue_depth": LLM_QUEUE.qsize(),
                "sid": advisory.get("suricata_sid", 0),
                "risk_score": advisory.get("risk_score", 0),
            },
        )


# --- Model endpoint policy (Edge#388) -------------------------------------
# The analyst, ops-coach and manual-query payloads carry fields an attacker can
# influence (Suricata EVE). They are sent only to a loopback address, the same
# default as the cognitive core's OllamaStructuredTransport. Unlike that
# adapter, the agent has no private-LAN opt-in: Ollama listens on
# 127.0.0.1:11434 only (#480) and no setting widens this. A host name is
# resolved and every address must be loopback; the connection then goes to the
# checked address, so a later DNS answer cannot move it. Redirects are not
# followed and proxy settings are not used. Anything else leaves the agent in
# its existing no-model fallback without contacting the endpoint.
LLM_MAX_RESPONSE_BYTES = 1024 * 1024
_LLM_ENDPOINT_LOGGED: set[str] = set()
_LLM_ENDPOINT_LOG_LOCK = threading.Lock()


class LlmEndpointRejected(RuntimeError):
    """The configured model endpoint is not allowed; no request was sent."""


def _redact_endpoint(endpoint: str) -> str:
    """The endpoint for a log line, with any user:password@ replaced."""
    text = str(endpoint or "")
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        return "<unparseable>"
    if "@" in parts.netloc:
        parts = parts._replace(netloc="***@" + parts.netloc.rsplit("@", 1)[1])
    if parts.query or parts.fragment:
        parts = parts._replace(query="***" if parts.query else "", fragment="***" if parts.fragment else "")
    return urllib.parse.urlunsplit(parts)[:200]


def _resolve_llm_host(host: str, port: int) -> list[str]:
    return [str(info[4][0]) for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


def _check_llm_endpoint(endpoint: str) -> tuple[str, str, tuple[str, ...], int, str]:
    """(scheme, server name, checked addresses, port, base path), or LlmEndpointRejected.

    Every address is loopback; they are tried in resolver order (localhost may
    answer ::1 first while Ollama listens on 127.0.0.1 only)."""
    try:
        parts = urllib.parse.urlsplit(str(endpoint or "").strip())
        port = parts.port
    except ValueError:
        raise LlmEndpointRejected("llm_endpoint_invalid") from None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise LlmEndpointRejected("llm_endpoint_scheme_not_http")
    if "@" in parts.netloc:
        raise LlmEndpointRejected("llm_endpoint_has_userinfo")
    if parts.query or parts.fragment:
        raise LlmEndpointRejected("llm_endpoint_has_query")
    host = parts.hostname or ""
    if not host:
        raise LlmEndpointRejected("llm_endpoint_no_host")
    if port is None:
        port = 443 if scheme == "https" else 80
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(a.split("%", 1)[0]) for a in _resolve_llm_host(host, port)]
        except (OSError, UnicodeError, ValueError):
            raise LlmEndpointRejected("llm_endpoint_unresolvable") from None
    if not addresses:
        raise LlmEndpointRejected("llm_endpoint_unresolvable")
    if not all(a.is_loopback for a in addresses):
        raise LlmEndpointRejected("llm_endpoint_not_loopback")
    checked = tuple(dict.fromkeys(str(a) for a in addresses))
    return scheme, host, checked, port, parts.path.rstrip("/")


def _log_llm_endpoint_refusal(reason: str) -> None:
    with _LLM_ENDPOINT_LOG_LOCK:
        first = reason not in _LLM_ENDPOINT_LOGGED
        _LLM_ENDPOINT_LOGGED.add(reason)
    if first:
        logger.warning(
            "LLM endpoint refused (%s): %s; no model result is used, advisories stay tactical (fallback)",
            reason,
            _redact_endpoint(LLM_ENDPOINT),
        )


def _llm_endpoint_target() -> tuple[str, str, tuple[str, ...], int, str]:
    try:
        return _check_llm_endpoint(LLM_ENDPOINT)
    except LlmEndpointRejected as exc:
        _log_llm_endpoint_refusal(str(exc))
        raise


def _llm_tls_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _connect_checked(addresses: tuple[str, ...], port: int, timeout: Any) -> socket.socket:
    """A socket to the first checked address that accepts; nothing else is tried."""
    last_error: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout)
        except OSError as exc:
            last_error = exc
    raise last_error or OSError("llm_endpoint_no_address")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, addresses: tuple[str, ...], port: int, timeout: float):
        super().__init__(addresses[0], port, timeout=timeout)
        self._addresses = addresses

    def connect(self) -> None:
        self.sock = _connect_checked(self._addresses, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to the checked addresses, with the configured name for SNI and the certificate."""

    def __init__(self, addresses: tuple[str, ...], port: int, server_name: str, timeout: float):
        super().__init__(addresses[0], port, timeout=timeout, context=_llm_tls_context())
        self._addresses = addresses
        self._server_name = server_name

    def connect(self) -> None:
        sock = _connect_checked(self._addresses, self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self._server_name)
        except BaseException:
            sock.close()
            raise


def _post_to_llm_endpoint(
    target: tuple[str, str, tuple[str, ...], int, str], path: str, body: bytes, timeout_sec: float
) -> bytes:
    scheme, server_name, addresses, port, base = target
    if scheme == "https":
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(addresses, port, server_name, timeout_sec)
    else:
        conn = _PinnedHTTPConnection(addresses, port, timeout_sec)
    # The Host header carries the configured name; the connection stays on the checked address.
    host_header = f"[{server_name}]" if ":" in server_name else server_name
    if port != (443 if scheme == "https" else 80):
        host_header = f"{host_header}:{port}"
    try:
        conn.request("POST", base + path, body=body, headers={"Content-Type": "application/json", "Host": host_header})
        resp = conn.getresponse()
        if 300 <= resp.status < 400:
            _log_llm_endpoint_refusal("llm_endpoint_redirect_refused")
            raise LlmEndpointRejected("llm_endpoint_redirect_refused")
        if resp.status != 200:
            raise RuntimeError(f"llm_http_status_{resp.status}")
        data = resp.read(LLM_MAX_RESPONSE_BYTES + 1)
    finally:
        conn.close()
    if len(data) > LLM_MAX_RESPONSE_BYTES:
        raise RuntimeError("llm_response_too_large")
    return data


def _extract_json_payload(text: str) -> Dict[str, Any]:
    body = text.strip()
    if body.startswith("```"):
        start = body.find("{")
        end = body.rfind("}")
        if start != -1 and end != -1 and end > start:
            body = body[start : end + 1]
    try:
        parsed = json.loads(body)
    except Exception:
        # Small local models sometimes emit doubled braces ({{...}}); strip and retry.
        inner = body
        while inner.startswith("{{") and inner.endswith("}}"):
            inner = inner[1:-1].strip()
        parsed = json.loads(inner)
    return parsed if isinstance(parsed, dict) else {}


def _build_llm_input(event: Dict[str, Any], advisory: Dict[str, Any]) -> Dict[str, Any]:
    norm = event.get("normalized", {})
    if not isinstance(norm, dict):
        norm = {}
    second_pass = advisory.get("second_pass") if isinstance(advisory.get("second_pass"), dict) else {}
    second_soc = second_pass.get("soc") if isinstance(second_pass.get("soc"), dict) else {}
    return {
        "sid": advisory.get("suricata_sid", 0),
        "suricata_severity": advisory.get("suricata_severity", 0),
        "risk_score": advisory.get("risk_score", 0),
        "attack_type": advisory.get("attack_type", "unknown"),
        "src_ip": advisory.get("src_ip", ""),
        "dst_ip": advisory.get("dst_ip", ""),
        "target_port": advisory.get("target_port", 0),
        "signature": norm.get("attack_type", ""),
        "category": norm.get("category", ""),
        "action": norm.get("action", ""),
        "second_pass_soc_status": second_soc.get("status", "unknown"),
        "second_pass_soc_reasons": second_soc.get("reasons", []),
        "second_pass_attack_candidates": second_soc.get("attack_candidates", []),
        "second_pass_correlation": second_soc.get("correlation", {}),
    }


def _ollama_chat(
    payload: Dict[str, Any],
    model: str,
    prompt_system: str = LLM_PROMPT_SYSTEM,
    keep_alive: str = LLM_KEEP_ALIVE,
    num_predict: int = LLM_NUM_PREDICT,
    num_ctx: int = LLM_NUM_CTX,
    num_thread: int = LLM_NUM_THREAD,
    timeout_sec: float = LLM_TIMEOUT_SEC,
    return_text_on_parse_error: bool = False,
    required_keys: tuple[str, ...] | None = ("verdict", "confidence", "reason", "suggested_action", "escalation"),
) -> Dict[str, Any]:
    req_body = {
        "model": model,
        "stream": False,
        "think": LLM_THINK,
        "keep_alive": keep_alive,
        "messages": [
            {"role": "system", "content": prompt_system},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
        "options": {
            "temperature": 0.1,
            "num_predict": num_predict,
            "num_ctx": num_ctx,
            "num_thread": num_thread,
        },
    }
    # The endpoint is checked before anything is sent (Edge#388): the payload
    # carries attacker-influenced EVE fields, so it only goes to loopback.
    target = _llm_endpoint_target()
    raw = json.dumps(req_body, ensure_ascii=False).encode("utf-8")
    data = json.loads(_post_to_llm_endpoint(target, "/api/chat", raw, timeout_sec).decode("utf-8", errors="replace"))
    message = data.get("message", {}) if isinstance(data, dict) else {}
    content = str(message.get("content") or "")
    if not content.strip():
        raise ValueError("empty_content")
    try:
        parsed = _extract_json_payload(content)
    except Exception:
        if return_text_on_parse_error:
            return {
                "answer": content.strip()[:240],
                "confidence": 0.5,
                "runbook_id": "",
                "operator_note": "raw_text_fallback",
            }
        raise
    if required_keys and any(k not in parsed for k in required_keys):
        raise ValueError("invalid_json_schema")
    return parsed


def _call_llm_with_retry(payload: Dict[str, Any], model: str) -> tuple[Dict[str, Any] | None, int, int, str]:
    attempts_total = 1 + LLM_RETRY_MAX
    latency_ms = 0
    last_error = ""
    for attempt in range(1, attempts_total + 1):
        started = time.time()
        try:
            result = _ollama_chat(payload, model=model)
            latency_ms = int((time.time() - started) * 1000)
            return result, latency_ms, attempt, ""
        except Exception as exc:
            latency_ms = int((time.time() - started) * 1000)
            last_error = str(exc)
            if isinstance(exc, LlmEndpointRejected):
                return None, latency_ms, attempt, last_error
            if attempt < attempts_total:
                _metrics_inc("llm_retried", 1)
                time.sleep(max(0.0, LLM_RETRY_BACKOFF_SEC * attempt))
    return None, latency_ms, attempts_total, last_error


def _process_llm_task(task: Dict[str, Any]) -> Dict[str, Any]:
    event = task.get("event", {})
    advisory = task.get("advisory", {})
    _audit_ai_scope(
        trace_id=str(advisory.get("trace_id") or ""),
        source="llm_analyst",
        intent="analyst_inference",
        in_scope=False,
        reason="analyst_schema_outside_ai_governance_contract",
    )
    if bool(task.get("ops_only")):
        ops = _run_ops_coach(
            advisory,
            verdict="not_evaluated",
            confidence=0.0,
            reason="critical_risk_direct",
            trigger_reason="critical_risk_direct",
        )
        advisory["ops_coach"] = ops
        if ops.get("status") == "completed":
            _metrics_inc("ops_completed", 1)
        elif ops.get("status") == "skipped":
            _metrics_inc("ops_skipped", 1)
        else:
            _metrics_inc("ops_errors", 1)
        with IO_LOCK:
            _write_json(ADVISORY_PATH, advisory)
            _update_ui_snapshot(advisory, count_suricata=False)
            _persist_metrics()
        return advisory

    model = str(task.get("model") or _select_analyst_model())
    payload = _build_llm_input(event, advisory)
    result, latency_ms, attempts, error_text = _call_llm_with_retry(payload, model=model)

    if result is not None:
        try:
            analyst = _normalize_analyst_result(result)
        except Exception as exc:
            result = None
            error_text = str(exc)
            _metrics_inc("llm_schema_invalid_count", 1)
            analyst = {}
        confidence = float(analyst.get("confidence") or 0.0)
        verdict = str(analyst.get("verdict") or "").strip()
        reason = str(analyst.get("reason") or "").strip()
        suggested_action = str(analyst.get("suggested_action") or "").strip()
        escalation = bool(analyst.get("escalation") or False)
        has_effective_signal = bool(verdict or reason or suggested_action or escalation or confidence > 0.0)
        if not has_effective_signal:
            result = None
            error_text = error_text or "empty_response"
        else:
            llm_result = {
                "status": "completed",
                "latency_ms": latency_ms,
                "model": model,
                "verdict": verdict,
                "confidence": confidence,
                "reason": reason,
                "suggested_action": suggested_action,
                "escalation": escalation,
                "attempts": attempts,
            }
            if llm_result["suggested_action"] and confidence >= 0.60:
                advisory["recommendation"] = llm_result["suggested_action"]
            need_ops, ops_reason = _should_escalate_to_ops(
                advisory,
                llm_status="completed",
                confidence=confidence,
                llm_escalation=escalation,
            )
            if need_ops:
                _metrics_inc("ops_requests", 1)
                advisory["ops_coach"] = _run_ops_coach(advisory, verdict=verdict, confidence=confidence, reason=reason, trigger_reason=ops_reason)
                if advisory["ops_coach"].get("status") == "completed":
                    _metrics_inc("ops_completed", 1)
                elif advisory["ops_coach"].get("status") == "skipped":
                    _metrics_inc("ops_skipped", 1)
                else:
                    _metrics_inc("ops_errors", 1)
            _metrics_inc("llm_completed", 1)
            with METRICS_LOCK:
                prev_ema = float(METRICS.get("llm_latency_ms_ema", 0.0))
                METRICS["llm_latency_ms_last"] = latency_ms
                METRICS["llm_latency_ms_ema"] = latency_ms if prev_ema <= 0 else (prev_ema * 0.8) + (latency_ms * 0.2)
                METRICS["last_error"] = ""
                METRICS["last_update_ts"] = time.time()
    if result is None:
        llm_result = {
            "status": "fallback",
            "policy": "tactical_only_keep_recommendation",
            "reason": error_text or "llm_failed",
            "attempts": attempts,
            "model": model,
        }
        if llm_result["reason"] == "empty_response":
            _metrics_inc("llm_empty_response_count", 1)
        _metrics_inc("llm_failed", 1)
        _metrics_inc("llm_fallback_count", 1)
        _metrics_update(last_error=llm_result["reason"])
        need_ops, ops_reason = _should_escalate_to_ops(advisory, llm_status="fallback", confidence=0.0)
        if need_ops:
            _metrics_inc("ops_requests", 1)
            advisory["ops_coach"] = _run_ops_coach(
                advisory,
                verdict="fallback",
                confidence=0.0,
                reason=llm_result["reason"],
                trigger_reason=ops_reason,
            )
            if advisory["ops_coach"].get("status") == "completed":
                _metrics_inc("ops_completed", 1)
            elif advisory["ops_coach"].get("status") == "skipped":
                _metrics_inc("ops_skipped", 1)
            else:
                _metrics_inc("ops_errors", 1)

    advisory["llm"] = llm_result
    _recompute_policy()
    _append_jsonl(
        LLM_RESULT_LOG_PATH,
        {
            "ts": time.time(),
            "sid": advisory.get("suricata_sid", 0),
            "risk_score": advisory.get("risk_score", 0),
            "llm": llm_result,
        },
    )
    with IO_LOCK:
        _write_json(ADVISORY_PATH, advisory)
        _update_ui_snapshot(advisory, count_suricata=False)
        _persist_metrics()
    return advisory


def _llm_worker() -> None:
    logger.info(
        "LLM worker started analyst=%s degraded=%s ops=%s endpoint=%s queue_max=%s",
        LLM_MODEL_PRIMARY,
        LLM_MODEL_DEGRADED,
        OPS_COACH_MODEL,
        _redact_endpoint(LLM_ENDPOINT),
        LLM_QUEUE_MAX,
    )
    if LLM_ENABLED:
        try:
            _llm_endpoint_target()
        except LlmEndpointRejected as exc:
            _metrics_update(last_error=str(exc))
    while True:
        task = LLM_QUEUE.get()
        try:
            _process_llm_task(task)
        finally:
            LLM_QUEUE.task_done()


def _update_ui_snapshot(advisory: Dict[str, Any], count_suricata: bool = True) -> None:
    _ensure_parent(SNAPSHOT_PATH)
    now = time.time()
    snapshot: Dict[str, Any] = {}
    if SNAPSHOT_PATH.exists():
        try:
            loaded = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                snapshot = loaded
        except Exception:
            snapshot = {}

    severity = int(advisory.get("suricata_severity") or 0)
    # Age the prior tallies before folding in this event: counts decay toward zero
    # over SURICATA_COUNT_DECAY_WINDOW_SEC of quiet, so idle/benign operation
    # returns the dashboard toward "quiet" instead of ratcheting up forever.
    prev_epoch = float(snapshot.get("snapshot_epoch") or 0.0)
    elapsed = max(0.0, now - prev_epoch) if prev_epoch > 0 else 0.0
    critical = _decay_suricata_count(int(snapshot.get("suricata_critical", 0) or 0), elapsed)
    warning = _decay_suricata_count(int(snapshot.get("suricata_warning", 0) or 0), elapsed)
    info = _decay_suricata_count(int(snapshot.get("suricata_info", 0) or 0), elapsed)
    if count_suricata:
        if severity <= 1:
            critical = min(SURICATA_COUNT_MAX, critical + 1)
        elif severity == 2:
            warning = min(SURICATA_COUNT_MAX, warning + 1)
        else:
            info = min(SURICATA_COUNT_MAX, info + 1)

    # FIX A: windowed/decaying view of the lifetime deferred_count metric (see
    # DEFERRED_RECENT_DECAY_WINDOW_SEC above). Age the prior recent-deferrals
    # tally the same way the suricata tallies are aged above, then fold in
    # however much the lifetime counter grew since the last snapshot write.
    # This is what the "Deferred" strip pill should key its tone on - NOT the
    # raw lifetime count, which only ever goes up.
    with METRICS_LOCK:
        deferred_lifetime = int(METRICS.get("deferred_count", 0) or 0)
    prev_deferred_lifetime = int(snapshot.get("deferred_lifetime_at_snapshot", 0) or 0)
    prev_deferred_recent = int(snapshot.get("deferred_recent", 0) or 0)
    deferred_recent = _decay_suricata_count(prev_deferred_recent, elapsed, DEFERRED_RECENT_DECAY_WINDOW_SEC)
    deferred_recent = min(SURICATA_COUNT_MAX, deferred_recent + max(0, deferred_lifetime - prev_deferred_lifetime))

    reasons = snapshot.get("reasons", [])
    if not isinstance(reasons, list):
        reasons = []
    reasons = [str(r) for r in reasons][-4:]
    reasons.append(f"suricata_sid={advisory.get('suricata_sid', 0)} risk={advisory.get('risk_score', 0)}")

    evidence = snapshot.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    evidence = [str(e) for e in evidence][-7:]
    evidence.append(
        f"{advisory.get('risk_level','LOW')} sid={advisory.get('suricata_sid',0)} "
        f"{advisory.get('attack_type','unknown')}"
    )

    snapshot["now_time"] = time.strftime("%H:%M:%S", time.localtime(now))
    snapshot["snapshot_epoch"] = now
    snapshot["advisory_epoch"] = float(advisory.get("ts") or now)
    snapshot["user_state"] = advisory.get("user_state", "CHECKING")
    snapshot["recommendation"] = advisory.get("recommendation", "Observe")
    snapshot["reasons"] = reasons
    snapshot["evidence"] = evidence
    snapshot["suricata_critical"] = critical
    snapshot["suricata_warning"] = warning
    snapshot["suricata_info"] = info
    # FIX A (continued): persist the decayed "recent deferrals" signal plus the
    # lifetime-count bookmark used to compute its next delta. `deferred_recent`
    # is what UI tone should read; the lifetime `deferred_count` metric (see
    # llm_metrics below) is kept untouched for audit.
    snapshot["deferred_recent"] = deferred_recent
    snapshot["deferred_lifetime_at_snapshot"] = deferred_lifetime
    snapshot["llm"] = advisory.get("llm", {})
    snapshot["ops_coach"] = advisory.get("ops_coach", {})
    snapshot["decision_pipeline"] = advisory.get("decision_pipeline", {})
    snapshot["second_pass"] = advisory.get("second_pass", {})
    snapshot["llm_metrics"] = _metrics_snapshot()
    snapshot["internal"] = {
        "state_name": advisory.get("state_name", _LAST_STATE_NAME),
        "suspicion": int(advisory.get("risk_score", 0)),
        "decay": 0,
    }
    route = _default_route_info()
    up_if = route.get("up_if", "-")
    up_ip = route.get("up_ip", "-")
    gateway_ip = route.get("gateway_ip", "-")
    uplink_type = route.get("uplink_type", "unknown")
    snapshot["up_if"] = up_if
    snapshot["up_ip"] = up_ip
    snapshot["gateway_ip"] = gateway_ip
    snapshot["down_if"] = str(snapshot.get("down_if") or "usb0")
    snapshot["down_ip"] = str(snapshot.get("down_ip") or "10.12.194.1")
    if uplink_type == "ethernet":
        snapshot["ssid"] = f"ETH:{up_if}" if up_if != "-" else "ETH"
    else:
        snapshot["ssid"] = str(snapshot.get("ssid") or "-")
    suricata_sid = int(advisory.get("suricata_sid", 0) or 0)
    # FIX B: only flag an actual suricata alert (severity 1-2, sid present),
    # not benign dummy-eve traffic (severity>=3, sid==0). Previously this was
    # hardcoded True for every advisory including benign, which is a
    # data-quality landmine for audit/STIX export even though no current UI
    # tone reads this field.
    snapshot["attack"] = {
        "suricata_alert": bool(severity and severity <= 2 and suricata_sid),
        "suricata_severity": severity,
        "suricata_sid": suricata_sid,
        "canary_target_alert": False,
        "canary_delay_active": False,
        "canary_delay_target_count": 0,
        "canary_delay_targets": [],
    }
    monitoring = snapshot.get("monitoring")
    if not isinstance(monitoring, dict):
        monitoring = {}
    monitoring["suricata"] = "ON"
    snapshot["monitoring"] = monitoring
    connection = snapshot.get("connection")
    if not isinstance(connection, dict):
        connection = {}
    if uplink_type == "wifi":
        connection["wifi_state"] = "CONNECTED"
    elif uplink_type == "ethernet":
        connection["wifi_state"] = "N/A(ETH)"
    else:
        connection["wifi_state"] = "DISCONNECTED"
    connection["uplink_if"] = up_if
    connection["uplink_type"] = uplink_type
    connection.setdefault("usb_nat", "OFF")
    connection.setdefault("internet_check", "UNKNOWN")
    connection.setdefault("captive_portal", "NA")
    connection.setdefault("captive_portal_reason", "NOT_CHECKED")
    snapshot["connection"] = connection

    _write_json(SNAPSHOT_PATH, snapshot)
    # Emit-alongside: write the shared Azazel-Fabric StatusView next to the
    # snapshot (ui_status_view.json). Best-effort, never raises, no-op without
    # the azazel_fabric package (owner-directed scope extension).
    try:
        from azazel_edge.fabric_view import write_status_view_alongside

        write_status_view_alongside(snapshot, [SNAPSHOT_PATH], logger=logger)
    except Exception:  # pragma: no cover - defensive; StatusView is advisory-only
        pass


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    with APPEND_LOCK:
        _ensure_parent(path)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    _ensure_parent(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _default_route_info() -> Dict[str, str]:
    """Best-effort default route info for current uplink (eth/wlan/etc)."""
    result = {"up_if": "-", "up_ip": "-", "gateway_ip": "-", "uplink_type": "unknown"}
    out = []
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


def _handle_event(event: Dict[str, Any]) -> None:
    _record_core_decision(event)
    advisory = _build_advisory(event)
    _metrics_inc("processed_events", 1)
    _route_llm(event, advisory)
    _append_jsonl(EVENT_LOG_PATH, {"event": event, "advisory": advisory})
    with IO_LOCK:
        _write_json(ADVISORY_PATH, advisory)
        _update_ui_snapshot(advisory)
        _persist_metrics()
    _record_decision_explanation(event, advisory)


def _handle_line(raw: str) -> Dict[str, Any] | None:
    """Backward-compatible single-line handler used by tests and legacy callers."""
    return _handle_request_line(raw)


def _handle_manual_query_request(req: Dict[str, Any]) -> Dict[str, Any]:
    params = req.get("params")
    if not isinstance(params, dict):
        params = {}
    question = str(params.get("question") or req.get("question") or "").strip()
    sender = str(params.get("sender") or req.get("sender") or "operator").strip()
    source = str(params.get("source") or req.get("source") or "webui").strip()
    context = params.get("context")
    lang = normalize_lang((context if isinstance(context, dict) else {}).get("lang"))
    started = time.time()
    result = _run_manual_query(question=question, sender=sender, source=source, context=context if isinstance(context, dict) else {})
    runbook_id = str(result.get("runbook_id") or "").strip()
    if runbook_id and not str(result.get("user_message") or "").strip() and runbook_get is not None:
        try:
            runbook = runbook_get(runbook_id, lang=lang)
            if localize_runbook_user_message is not None:
                result["user_message"] = str(localize_runbook_user_message(runbook, lang=lang)).strip()[:160]
            else:
                result["user_message"] = str(runbook.get("user_message_template") or "").strip()[:160]
        except Exception:
            pass
    if runbook_id and review_runbook_id is not None:
        audience = "operator" if source in {"webui", "ops-comm", "mattermost_post", "mattermost_command", "cli"} else "beginner"
        try:
            result["runbook_review"] = review_runbook_id(
                runbook_id,
                context={
                    "question": question,
                    "audience": audience,
                    "lang": lang,
                    "risk_score": int(_latest_advisory_snapshot().get("risk_score") or 0),
                    "source": source,
                },
            )
        except Exception as exc:
            result["runbook_review_error"] = str(exc)
    with IO_LOCK:
        _persist_metrics()
    result["ok"] = str(result.get("status") or "") in {"completed", "fallback", "routed"}
    result["action"] = "manual_query"
    result["duration_ms"] = int((time.time() - started) * 1000)
    return result


FORWARD_STATS_SCHEMA = "azazel-edge/forward-stats/v1"
_FORWARD_STATS_KEYS = ("dropped", "failed", "sent", "since")


def _record_forward_stats(payload: Dict[str, Any]) -> None:
    """Keep Edge Core's own forward counts as metrics; never treat them as an event.

    The Rust core sends them on this socket (#432) so a receiver can see what
    it could not deliver. Anything that does not fit the closed shape is ignored.
    """
    if set(payload) != {"schema", *_FORWARD_STATS_KEYS}:
        return
    values = [payload[key] for key in _FORWARD_STATS_KEYS]
    if not all(type(v) is int and 0 <= v < 2**63 for v in values):
        return
    _metrics_update(**{f"core_forward_{key}": value for key, value in zip(_FORWARD_STATS_KEYS, values)})
    with IO_LOCK:
        _persist_metrics()
    _note_core_forward_loss(payload["dropped"], payload["failed"], payload["since"])


INGRESS_SHED_SCHEMA = "azazel-edge/ingress-shed/v1"
INGRESS_SHED_METRIC = "core_ingress_shed"
_INGRESS_SHED_COUNTS = (
    "polls", "shed_total", "alerts_shed", "admitted", "alerts_admitted", "examined",
    "max_backlog_bytes", "max_shed_level", "oversized_lines_skipped", "oversized_possible_alerts",
    "truncation_resets", "file_replacements", "unread_bytes_lost",
    "cumulative_shed_total", "cumulative_oversized_lines_skipped", "cumulative_resets",
)
_INGRESS_SHED_CLASSES = ("flow", "dns", "stats", "other", "unparseable")
_INGRESS_SHED_REASONS = ("non_alert_rate", "backlog")
_INGRESS_SHED_INTERVAL_ENDS = ("audit_interval", "shutdown")


def _count(value: Any) -> bool:
    return type(value) is int and 0 <= value < 2**63


def _count_map(value: Any, keys: tuple[str, ...]) -> Dict[str, int] | None:
    if not isinstance(value, dict) or set(value) != set(keys) or not all(_count(value[k]) for k in keys):
        return None
    return {k: value[k] for k in keys}


def _record_ingress_shed(payload: Dict[str, Any]) -> None:
    """Keep the core's last ``ingress_shed`` summary (Edge#414 SO-11) as a metric.

    Read-only: it is counted and shown, never an event, an advisory input or
    a decision. Only the counts, the interval end and the emit time are kept
    (the summary carries no address or id; nothing else is copied). A payload
    that does not fit is ignored, and so is one older than the summary
    already kept (the shutdown summary can reach the socket after a queued
    one).
    """
    counts = {k: payload.get(k) for k in _INGRESS_SHED_COUNTS}
    if not all(_count(v) for v in counts.values()):
        return
    by_type = _count_map(payload.get("shed_by_type"), _INGRESS_SHED_CLASSES)
    by_reason = _count_map(payload.get("shed_by_reason"), _INGRESS_SHED_REASONS)
    emitted = payload.get("emitted_epoch")
    interval_end = payload.get("interval_end")
    if by_type is None or by_reason is None or interval_end not in _INGRESS_SHED_INTERVAL_ENDS:
        return
    if type(emitted) not in (int, float) or not (0 <= emitted < 2**63):
        return
    with METRICS_LOCK:
        kept = METRICS.get(INGRESS_SHED_METRIC)
        if isinstance(kept, dict) and float(kept.get("emitted_epoch") or 0) > float(emitted):
            return
    summary: Dict[str, Any] = {
        "schema": INGRESS_SHED_SCHEMA,
        "emitted_epoch": float(emitted),
        "interval_end": interval_end,
        **counts,
        "shed_by_type": by_type,
        "shed_by_reason": by_reason,
        "received_ts": time.time(),
    }
    _metrics_update(**{INGRESS_SHED_METRIC: summary})
    with IO_LOCK:
        _persist_metrics()


def _handle_request_line(raw: str) -> Dict[str, Any] | None:
    text = raw.strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {"ok": False, "error": "invalid_json"}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "invalid_payload"}

    if "schema" in payload and payload.get("schema") == FORWARD_STATS_SCHEMA:
        _record_forward_stats(payload)
        return None
    if "schema" in payload and payload.get("schema") == INGRESS_SHED_SCHEMA:
        _record_ingress_shed(payload)
        return None

    action = str(payload.get("action") or "").strip().lower()
    if action == "manual_query":
        if QUERY_SOCKET_ACTIVE.is_set():
            logger.warning("ai-bridge.sock: refused manual_query (use the query socket %s)", QUERY_SOCKET_PATH)
            return {"ok": False, "action": "manual_query", "error": "forbidden",
                    "reason": "manual_query_moved_to_query_socket"}
        return _handle_manual_query_request(payload)

    _handle_event(payload)
    return None


def _handle_client(conn: socket.socket) -> None:
    with conn:
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                resp = _handle_request_line(line.decode("utf-8", errors="replace"))
                if isinstance(resp, dict):
                    try:
                        conn.sendall((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
                    except Exception:
                        return


def _serve(stop: threading.Event | None = None) -> None:
    """Run the agent (the unit's ExecStart). ``stop`` ends the accept loop;
    in the main thread SIGTERM (systemd's stop) sets it, so the P0 path is
    drained before the process exits."""
    if stop is None:
        stop = threading.Event()
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
    try:
        for runtime_dir in sorted({ADVISORY_PATH.parent, METRICS_PATH.parent, POLICY_PATH.parent}):
            _prepare_runtime_dir(runtime_dir)
    except AgentDirError as exc:
        logger.error("%s", exc)
        raise SystemExit(f"azazel-edge-ai-agent: {exc}") from None
    if P0AuditLogger is not None and AI_AUDIT is None:
        logger.error("%s", AI_AUDIT_ERROR)
        raise SystemExit(f"azazel-edge-ai-agent: {AI_AUDIT_ERROR}")
    # Bound before any thread starts (bind sets a process-wide umask), but
    # not listening: a connect is refused until the P0 path below runs.
    try:
        _prepare_ai_socket_dir(SOCKET_PATH)
        srv = _bind_ai_socket(SOCKET_PATH)
    except AISocketSetupError as exc:
        logger.error("%s", exc)
        raise SystemExit(f"azazel-edge-ai-agent: {exc}") from None
    # Also bound before any thread starts (umask). Failure disables only
    # the Web UI's manual_query path, never ai-bridge.sock.
    query_srv = _setup_query_socket()
    # Before the socket accepts, so every P0 decision the core sends to this
    # service is recorded and relayed.
    _start_core_p0_path()
    _start_decision_explanations()
    srv.listen(16)
    srv.settimeout(1.0)
    worker = threading.Thread(target=_llm_worker, daemon=True)
    worker.start()
    _persist_policy()
    _persist_metrics()
    logger.info("AI advisory agent listening on %s", SOCKET_PATH)
    if query_srv is not None:
        query_srv.listen(16)
        threading.Thread(target=_query_accept_loop, args=(query_srv, stop), daemon=True).start()
        QUERY_SOCKET_ACTIVE.set()
        logger.info("manual_query socket listening on %s (peers: root, %s)", QUERY_SOCKET_PATH, QUERY_SOCKET_ACCOUNT)
    last_heartbeat = time.time()

    handlers: list[threading.Thread] = []

    def _spawn(conn: socket.socket) -> None:
        handlers[:] = [t for t in handlers if t.is_alive()]
        t = threading.Thread(target=_handle_client, args=(conn,), daemon=True)
        handlers.append(t)
        t.start()

    try:
        while not stop.is_set():
            now = time.time()
            if now - last_heartbeat >= METRICS_HEARTBEAT_SEC:
                _metrics_heartbeat()
                _persist_metrics()
                last_heartbeat = now
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            _spawn(conn)
    finally:
        # Stopping: take the connections already queued (the core counted
        # them as sent), let the handlers finish (bounded), then drain the
        # P0 path. Anything still missed is in the core's log and is
        # reconciled at the next start.
        deadline = time.monotonic() + SHUTDOWN_DRAIN_S
        srv.setblocking(False)
        while time.monotonic() < deadline:
            try:
                conn, _ = srv.accept()
            except (BlockingIOError, socket.timeout, OSError):
                break
            conn.setblocking(True)
            _spawn(conn)
        srv.close()
        if query_srv is not None:
            QUERY_SOCKET_ACTIVE.clear()
            query_srv.close()
        for t in list(handlers):
            t.join(max(0.0, deadline - time.monotonic()))
        _stop_core_p0_path()


if __name__ == "__main__":
    _serve()
