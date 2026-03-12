#!/usr/bin/env python3
"""Local AI advisory agent for normalized events from Rust core."""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
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

SOCKET_PATH = Path(os.environ.get("AZAZEL_AI_SOCKET", "/run/azazel-edge/ai-bridge.sock"))
ADVISORY_PATH = Path(os.environ.get("AZAZEL_AI_ADVISORY", "/run/azazel-edge/ai_advisory.json"))
EVENT_LOG_PATH = Path(os.environ.get("AZAZEL_AI_EVENT_LOG", "/var/log/azazel-edge/ai-events.jsonl"))
SNAPSHOT_PATH = Path(os.environ.get("AZAZEL_UI_SNAPSHOT", "/run/azazel-edge/ui_snapshot.json"))
LLM_DEFERRED_LOG_PATH = Path(os.environ.get("AZAZEL_AI_DEFERRED_LOG", "/var/log/azazel-edge/ai-deferred.jsonl"))
LLM_RESULT_LOG_PATH = Path(os.environ.get("AZAZEL_AI_LLM_LOG", "/var/log/azazel-edge/ai-llm.jsonl"))
METRICS_PATH = Path(os.environ.get("AZAZEL_AI_METRICS", "/run/azazel-edge/ai_metrics.json"))
POLICY_PATH = Path(os.environ.get("AZAZEL_AI_POLICY", "/run/azazel-edge/ai_runtime_policy.json"))
METRICS_HEARTBEAT_SEC = max(5.0, float(os.environ.get("AZAZEL_AI_METRICS_HEARTBEAT_SEC", "15")))
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
    "reason<=80 chars, suggested_action<=80 chars, confidence=0.0..1.0. "
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
DECISION_LOGGER = DecisionLogger()
CONFIG_HASH = ConfigHash.compute(config_dict={"engine": "tactical_scorer_v1"})
DECISION_LAYERS = DecisionLayers()
_LAST_RISK_SCORE = 0
_LAST_STATE_NAME = "NORMAL"
LLM_QUEUE: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=LLM_QUEUE_MAX)
IO_LOCK = threading.Lock()
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


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


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
    if score >= 80:
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
    if risk_score >= 85:
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
    _metrics_inc("manual_requests", 1)

    routed = _manual_router_response(q, sender=sender, source=source, context=ctx)
    if routed is not None:
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
            if "timed out" in reason.lower():
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
    if score >= 80:
        return f"Block source and route to decoy immediately (port={port})"
    if score >= 60:
        return f"Apply delay policy and increase telemetry (port={port})"
    return "Observe and continue baseline monitoring"


def _state_name(score: int) -> str:
    if score >= 80:
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
        if int(advisory.get("risk_score") or 0) >= 85:
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


def _extract_json_payload(text: str) -> Dict[str, Any]:
    body = text.strip()
    if body.startswith("```"):
        start = body.find("{")
        end = body.rfind("}")
        if start != -1 and end != -1 and end > start:
            body = body[start : end + 1]
    parsed = json.loads(body)
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
    raw = json.dumps(req_body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url=f"{LLM_ENDPOINT.rstrip('/')}/api/chat",
        data=raw,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
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
            if attempt < attempts_total:
                _metrics_inc("llm_retried", 1)
                time.sleep(max(0.0, LLM_RETRY_BACKOFF_SEC * attempt))
    return None, latency_ms, attempts_total, last_error


def _process_llm_task(task: Dict[str, Any]) -> Dict[str, Any]:
    event = task.get("event", {})
    advisory = task.get("advisory", {})
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
        LLM_ENDPOINT,
        LLM_QUEUE_MAX,
    )
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
    critical = int(snapshot.get("suricata_critical", 0) or 0)
    warning = int(snapshot.get("suricata_warning", 0) or 0)
    info = int(snapshot.get("suricata_info", 0) or 0)
    if count_suricata:
        if severity <= 1:
            critical += 1
        elif severity == 2:
            warning += 1
        else:
            info += 1

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
    snapshot["user_state"] = advisory.get("user_state", "CHECKING")
    snapshot["recommendation"] = advisory.get("recommendation", "Observe")
    snapshot["reasons"] = reasons
    snapshot["evidence"] = evidence
    snapshot["suricata_critical"] = critical
    snapshot["suricata_warning"] = warning
    snapshot["suricata_info"] = info
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
    snapshot["attack"] = {
        "suricata_alert": True,
        "suricata_severity": severity,
        "suricata_sid": int(advisory.get("suricata_sid", 0)),
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


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
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
    advisory = _build_advisory(event)
    _metrics_inc("processed_events", 1)
    _route_llm(event, advisory)
    _append_jsonl(EVENT_LOG_PATH, {"event": event, "advisory": advisory})
    with IO_LOCK:
        _write_json(ADVISORY_PATH, advisory)
        _update_ui_snapshot(advisory)
        _persist_metrics()


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

    action = str(payload.get("action") or "").strip().lower()
    if action == "manual_query":
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


def _serve() -> None:
    _ensure_parent(SOCKET_PATH)
    _ensure_parent(METRICS_PATH)
    _ensure_parent(POLICY_PATH)
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(SOCKET_PATH))
    os.chmod(SOCKET_PATH, 0o666)
    srv.listen(16)
    srv.settimeout(1.0)
    worker = threading.Thread(target=_llm_worker, daemon=True)
    worker.start()
    _persist_policy()
    _persist_metrics()
    logger.info("AI advisory agent listening on %s", SOCKET_PATH)
    last_heartbeat = time.time()

    while True:
        now = time.time()
        if now - last_heartbeat >= METRICS_HEARTBEAT_SEC:
            _metrics_heartbeat()
            _persist_metrics()
            last_heartbeat = now
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    _serve()
