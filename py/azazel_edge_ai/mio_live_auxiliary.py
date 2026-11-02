"""Bounded, read-only bridge from accepted Edge events to shared M.I.O.

This adapter is optional at runtime: ``azazel_mio`` is a separate package and
may not yet be installed. Work runs on one daemon worker with a latest-only
slot. No result is used by Edge decision, enforcement, lease, or undo code.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import queue
import re
import secrets
import hashlib
import threading
import time
from typing import Any, Callable, Mapping

MAX_JOB_AGE_SECONDS = 10.0
MAX_RESULT_BYTES = 16 * 1024
MAX_SCORE_FACTORS = 32
MIO_FRAME_SUMMARY_MAX_CHARS = 480
_AUTHORITY = "read_only_advisory"
_OBSERVED_OUTCOMES = frozenset({"allowed", "blocked", "drop", "rejected"})


def _unavailable(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "azazel.mio_auxiliary.v1",
        "status": "unavailable" if reason == "package_unavailable" else "degraded",
        "reason": reason,
        "authority": _AUTHORITY,
        "source": "mio_shared_core",
        "generation": "",
        "max_age_seconds": MAX_JOB_AGE_SECONDS,
        "trace_id": "",
        "provenance": {"observations": [], "derived_signals": []},
        "knowledge": {"status": "not_provided", "refs": []},
        "advisory": None,
        "edge_event": {},
    }


_EDGE_ACTIONS = frozenset({"observe", "notify", "throttle", "redirect", "isolate"})
_EDGE_MODES = frozenset({"disabled", "dry_run", "policy_gated", "release_guard_failed", "enforced"})
_EDGE_RESULTS = frozenset({"no_disruptive_action", "planned_not_applied", "extended", "already_held", "applied", "failed", "uncertain"})


def _safe_edge_event(event: Mapping[str, Any]) -> dict[str, Any]:
    defense = event.get("defense") if isinstance(event.get("defense"), Mapping) else {}
    enforcement = event.get("enforcement") if isinstance(event.get("enforcement"), Mapping) else {}
    out: dict[str, Any] = {}
    unknown = any(key not in {"mode", "result", "trace_id"} for key in enforcement)
    unknown = unknown or any(key != "action" for key in defense)
    action = defense.get("action")
    if type(action) is str and action.lower() in _EDGE_ACTIONS:
        out["action"] = action.lower()
    elif action is not None:
        unknown = True
    for key, source, allowed in (("mode", enforcement, _EDGE_MODES), ("result", enforcement, _EDGE_RESULTS)):
        value = source.get(key)
        if type(value) is str and value in allowed:
            out[key] = value
        elif value is not None:
            unknown = True
    trace = enforcement.get("trace_id")
    if type(trace) is str and len(trace) <= 96 and re.fullmatch(r"[A-Za-z0-9._:-]+", trace):
        out["trace_id"] = trace
    elif trace is not None:
        unknown = True
    if unknown:
        out["unknown_fields"] = True
    return out


_EDGE_RISK_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/+()\[\]-]{0,95}$")
_SAFE_TECHNIQUE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_SAFE_TIMESTAMP = re.compile(r"^[0-9TtZz:+.\-]{1,32}$")


def _source_context(event: Mapping[str, Any]) -> dict[str, Any]:
    """Project only small, non-address alert metadata from Rust's normalized event."""
    normalized = event.get("normalized") if isinstance(event.get("normalized"), Mapping) else {}
    values: dict[str, Any] = {}
    for field, limit in (("event_type", 32), ("attack_type", 96), ("category", 64), ("protocol", 16)):
        raw = normalized.get(field)
        if (type(raw) is str and raw.strip().lower() != "unknown"
                and _SAFE_LABEL.fullmatch(raw[:96]) and len(raw) <= limit):
            values[field] = raw
    raw_ts = normalized.get("ts")
    if type(raw_ts) is str and len(raw_ts) <= 32 and _SAFE_TIMESTAMP.fullmatch(raw_ts):
        values["ts"] = raw_ts
    for field in ("sid", "severity", "target_port"):
        raw = normalized.get(field)
        cap = 65535 if field == "target_port" else (2**31 - 1 if field == "sid" else 10)
        if type(raw) is int and (raw > 0 if field in {"sid", "target_port"} else raw >= 0) and raw <= cap:
            values[field] = raw
    technique_ids = normalized.get("technique_ids")
    if isinstance(technique_ids, list):
        values["technique_ids"] = [item for item in technique_ids[:16]
                                   if type(item) is str and _SAFE_TECHNIQUE.fullmatch(item)]
    normalized_outcome = normalized.get("action")
    if type(normalized_outcome) is str and normalized_outcome.strip().lower() in _OBSERVED_OUTCOMES:
        values["normalized_outcome"] = normalized_outcome.strip().lower()
    available = {key: {"value": value, "status": "observed", "provenance": "rust_core_normalized_event"}
                 for key, value in values.items()}
    for field in ("event_type", "attack_type", "category", "protocol", "sid", "severity", "target_port", "technique_ids", "ts", "normalized_outcome"):
        available.setdefault(field, {"value": None, "status": "unavailable", "provenance": "rust_core_normalized_event"})
    identity = {key: values[key] for key in ("event_type", "sid", "ts") if key in values}
    # This digest is only a correlation handle over safe alert metadata; it is
    # not an evidence reference and includes no address, payload, or secret.
    event_key = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()[:24]
    return {"event_key": event_key if "event_type" in values and "sid" in values else "", "fields": available}


def _binding_matches(payload: Mapping[str, Any]) -> bool:
    binding = payload.get("handoff_binding")
    edge = payload.get("edge_event")
    context = payload.get("source_context")
    if not isinstance(binding, Mapping) or not isinstance(edge, Mapping) or not isinstance(context, Mapping):
        return False
    if not context.get("event_key"):
        return False
    edge_trace = edge.get("trace_id")
    edge_action = edge.get("action")
    edge_mode = edge.get("mode")
    edge_result = edge.get("result")
    if (type(edge_trace) is not str or not re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", edge_trace)
            or type(edge_action) is not str or edge_action not in _EDGE_ACTIONS
            or type(edge_mode) is not str or edge_mode not in _EDGE_MODES
            or type(edge_result) is not str or edge_result not in _EDGE_RESULTS):
        return False
    for key in ("generation", "event_key", "edge_trace_id", "edge_action", "edge_mode", "edge_result"):
        actual = edge.get({"edge_trace_id": "trace_id", "edge_action": "action",
                           "edge_mode": "mode", "edge_result": "result"}.get(key, key))
        if binding.get(key) != (payload.get("generation") if key == "generation" else
                                context.get("event_key") if key == "event_key" else actual):
            return False
    if binding.get("edge_trace_id") != payload.get("trace_id"):
        return False
    advisory = payload.get("advisory")
    if payload.get("status") == "complete":
        if not isinstance(advisory, Mapping):
            return False
        if binding.get("mio_trace_id") != advisory.get("trace_id") or binding.get("frame_id") != advisory.get("frame_id"):
            return False
    return binding.get("status") == "matched"


def _safe_event(
    event: Mapping[str, Any], score: int, factors: list[str], risk_level: str,
    *, factors_truncated: bool = False,
) -> dict[str, Any]:
    if type(risk_level) is not str or risk_level not in _EDGE_RISK_LEVELS:
        raise ValueError("invalid_edge_risk_level")
    normalized = event.get("normalized")
    normalized = normalized if isinstance(normalized, Mapping) else {}
    defense = event.get("defense")
    defense = defense if isinstance(defense, Mapping) else {}
    action = str(defense.get("action") or "observe").upper()
    action = action if action in {"OBSERVE", "NOTIFY", "THROTTLE", "REDIRECT", "ISOLATE"} else "OBSERVE"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = secrets.token_hex(8)
    trace_id = f"mio-{nonce}-1"
    frame_id = trace_id + ":frame"
    facts: list[str] = []
    context = _source_context(event)
    event_type = context["fields"]["event_type"]["value"]
    event_type = event_type[:48]
    if event_type:
        facts.append(f"Observed event type: {event_type}")
    observed_outcome = context["fields"]["normalized_outcome"]["value"]
    if type(observed_outcome) is str:
        facts.append(f"Observed normalized event outcome: {observed_outcome}")
    sid = context["fields"]["sid"]["value"]
    if type(sid) is int and 0 < sid <= 2**31 - 1:
        facts.append(f"Observed Suricata SID: {sid}")
    severity = context["fields"]["severity"]["value"]
    if type(severity) is int and 0 <= severity <= 10:
        facts.append(f"Observed Suricata severity: {severity}")
    for field, label in (("attack_type", "Suricata signature"), ("category", "Suricata category"),
                         ("protocol", "normalized protocol")):
        value = context["fields"][field]["value"]
        if value is not None:
            facts.append(f"Observed {label}: {value}")
    port = context["fields"]["target_port"]["value"]
    if port is not None:
        facts.append(f"Observed normalized target port: {port}")
    techniques = context["fields"]["technique_ids"]["value"]
    if techniques:
        facts.append("Observed rule-declared technique IDs: " + ",".join(techniques))
    # The Edge scorer is the owner of the score, level and factors. Retain its
    # complete factor list when it fits the shared frame's 480-character
    # summary cap; otherwise retain whole leading factors and mark truncation.
    score_fact = f"Edge tactical scorer derived risk score: {max(0, min(int(score), 100))}"
    bounded_factors: list[str] = []
    did_truncate = bool(factors_truncated)
    for value in factors:
        if type(value) is not str:
            did_truncate = True
            continue
        bounded = value[:96]
        if bounded != value:
            did_truncate = True
        bounded_factors.append(bounded)
    prefix = score_fact + ("; factors=" if bounded_factors else "")
    complete_summary = prefix + ",".join(bounded_factors)
    if len(complete_summary) <= MIO_FRAME_SUMMARY_MAX_CHARS and not did_truncate:
        score_summary = complete_summary
    else:
        did_truncate = True
        marker = "; FACTORS_TRUNCATED"
        budget = max(0, MIO_FRAME_SUMMARY_MAX_CHARS - len(prefix) - len(marker))
        retained: list[str] = []
        used = 0
        for factor in bounded_factors:
            needed = len(factor) + (1 if retained else 0)
            if used + needed > budget:
                break
            retained.append(factor)
            used += needed
        score_summary = prefix + ",".join(retained) + marker
        score_summary = score_summary[:MIO_FRAME_SUMMARY_MAX_CHARS]
    return {
        "schema_version": "mio.situation_frame.v2",
        "frame_id": frame_id,
        "trace_id": trace_id,
        "created_at": timestamp,
        "mission": "Provide a read-only explanation of this accepted Edge event.",
        "current_defensive_state": action,
        # Edge already classified this score under its configured threshold;
        # carry that exact label as context instead of introducing a M.I.O. scorer.
        "threat_level": risk_level,
        "noc_summary": "No NOC evaluation supplied to this bounded live adapter.",
        "soc_summary": score_summary,
        "known_facts": facts,
        "unknowns": ["LIVE_ADAPTER_CONTEXT_LIMITED"] + [
            "SOURCE_FIELD_UNAVAILABLE:" + name for name, field in context["fields"].items()
            if field["status"] == "unavailable"
        ],
        "contradictions": [],
        # Stable refs are derived only from accepted event identifiers. Score
        # prose and generated frame/trace identifiers are never evidence.
        "evidence_refs": ([f"suricata_sid:{sid}"] if type(sid) is int and 0 < sid <= 2**31 - 1 else []) +
                         ([f"ev:alert:{normalized['event_id']}"] if type(normalized.get("event_id")) is int and normalized["event_id"] >= 0 else []),
        "knowledge_refs": [],
        "knowledge_status": "not_provided",
        "deception_status": "not_provided",
        "provenance": {
            "known_facts": ["caller"],
            "evidence_refs": ["caller"] if (type(sid) is int and 0 < sid <= 2**31 - 1) or
                                                   (type(normalized.get("event_id")) is int and normalized["event_id"] >= 0) else [],
        },
        "freshness_seconds": 0,
        "truncated": did_truncate,
        "actors": [],
        "actions": [],
        "deception_context": None,
    }


def _project_knowledge_advisory(value, *, generation, trace_id):
    if type(value) is not dict:
        return None
    if (value.get('kind') != 'knowledge_context_response_advisory'
            or value.get('source_kind') != 'knowledge_context_response'
            or value.get('claim_status') != 'reported_unverified'
            or value.get('trust') != 'unverified_advisory_only'):
        return None
    groups = value.get('source_groups')
    techniques = value.get('attack_techniques')
    freshness = value.get('source_freshness')
    for items, cap, pattern in ((groups, 16, r'[a-z][a-z0-9_-]{0,31}'),
                                (techniques, 32, r'T[0-9]{4}(?:\.[0-9]{3})?')):
        if type(items) is not list or len(items) > cap or any(
                type(item) is not str or not re.fullmatch(pattern, item) for item in items):
            return None
    if type(freshness) is not dict or set(freshness) - {'oldest_feed_days', 'attack_version'}:
        return None
    days = freshness.get('oldest_feed_days')
    version = freshness.get('attack_version')
    if days is not None and (type(days) not in (int, float) or not 0 <= days <= 36500 or not math.isfinite(days)):
        return None
    if version is not None and (type(version) is not str or not re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}', version)):
        return None
    return {'schema_version': 'azazel.edge_knowledge_advisory.v1',
            'status': 'complete', 'authority': 'read_only_advisory',
            'generation': str(generation), 'trace_id': trace_id,
            'claim_status': 'reported_unverified', 'source_groups': list(groups),
            'attack_techniques': list(techniques), 'source_freshness': dict(freshness)}


def _knowledge_advisory_current(value, envelope):
    """Caller must also validate the existing handoff binding."""
    return (type(value) is dict and envelope.get('is_current') is True
            and envelope.get('status') == 'complete'
            and bool(envelope.get('trace_id'))
            and value.get('generation') == envelope.get('generation')
            and value.get('trace_id') == envelope.get('trace_id'))


class LiveMioAuxiliary:
    """Latest-only asynchronous caller for the product-neutral M.I.O. API."""

    def __init__(self, *, max_age_seconds: float = MAX_JOB_AGE_SECONDS,
                 knowledge_input_builder: Callable[[Mapping[str, Any], Mapping[str, Any]], dict[str, Any] | None] | None = None):
        self.max_age_seconds = max(0.1, min(float(max_age_seconds), MAX_JOB_AGE_SECONDS))
        self._queue: queue.Queue[tuple[float, int, dict[str, Any], int, list[str], str, bool]] = queue.Queue(maxsize=1)
        self._lock = threading.Lock()
        self._generation = 0
        self._result = {**_unavailable("starting"), "status": "pending"}
        self._result_generation = 0
        self._result_completed_monotonic: float | None = None
        self._result_completed_at = ""
        self._frame_snapshot: dict[str, Any] | None = None
        self._knowledge_input: dict[str, Any] | None = None
        self._knowledge_input_builder = knowledge_input_builder
        self._core: Any = None
        self._frame_type: Any = None
        self._knowledge_statuses: frozenset[str] = frozenset()
        self._import_error = ""
        self._thread = threading.Thread(target=self._run, name="mio-live-auxiliary", daemon=True)
        self._thread.start()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            result = json.loads(json.dumps(self._result))
            age = (max(0.0, time.monotonic() - self._result_completed_monotonic)
                   if self._result_completed_monotonic is not None else None)
            if age is not None:
                result["age_seconds"] = age
                result["completed_at"] = self._result_completed_at
            result["is_current"] = (
                result.get("status") == "complete"
                and str(result.get("generation") or "") == str(self._generation)
                and age is not None and age <= self.max_age_seconds
            )
            if not _knowledge_advisory_current(result.get("edge_knowledge_advisory"), result) or not _binding_matches(result):
                result.pop("edge_knowledge_advisory", None)
            return result

    def current_generation(self) -> int:
        with self._lock:
            return self._generation

    def frame_snapshot(self, generation: Any) -> dict[str, Any] | None:
        """Return the bounded accepted frame only while its generation is current."""
        with self._lock:
            if str(generation) != str(self._generation) or self._frame_snapshot is None:
                return None
            return json.loads(json.dumps(self._frame_snapshot))

    def knowledge_input_snapshot(self, generation: Any) -> dict[str, Any] | None:
        """Private loopback-only query input, separate from public snapshots."""
        with self._lock:
            if str(generation) != str(self._generation) or self._knowledge_input is None:
                return None
            return json.loads(json.dumps(self._knowledge_input))

    def submit(self, event: Mapping[str, Any], *, score: int, factors: list[str], risk_level: str) -> dict[str, Any]:
        """Copy bounded inputs and enqueue without waiting for M.I.O."""
        normalized = event.get("normalized") if isinstance(event, Mapping) else {}
        defense = event.get("defense") if isinstance(event, Mapping) else {}
        normalized = normalized if isinstance(normalized, Mapping) else {}
        safe_normalized = {
            key: normalized[key] for key in (
                "event_type", "sid", "severity", "event_id", "attack_type", "category",
                "protocol", "target_port", "technique_ids", "ts",
            ) if key in normalized
        }
        observed_outcome = normalized.get("action")
        if type(observed_outcome) is str:
            observed_outcome = observed_outcome.strip().lower()
            if observed_outcome in _OBSERVED_OUTCOMES:
                safe_normalized["action"] = observed_outcome
        snapshot = {
            "normalized": safe_normalized,
            "defense": {"action": defense.get("action")} if isinstance(defense, Mapping) else {},
            "_source_trace_id": str((event.get("enforcement") or {}).get("trace_id") or "")[:96]
                if isinstance(event.get("enforcement"), Mapping) else "",
            "_edge_event": _safe_edge_event(event),
            "_source_context": _source_context(event),
        }
        if type(risk_level) is not str or risk_level not in _EDGE_RISK_LEVELS:
            raise ValueError("invalid_edge_risk_level")
        safe_factors = list(factors[:MAX_SCORE_FACTORS])
        factors_truncated = len(factors) > len(safe_factors)
        job = (time.monotonic(), 0, snapshot, max(0, min(int(score), 100)), safe_factors, risk_level, factors_truncated)
        accepted = True
        with self._lock:
            self._generation += 1
            generation = self._generation
            self._frame_snapshot = None
            self._knowledge_input = (self._knowledge_input_builder(event, snapshot["_source_context"])
                                     if self._knowledge_input_builder else None)
            self._result_completed_monotonic = None
            self._result_completed_at = ""
            self._result_generation = generation
            job = (job[0], generation, *job[2:])
            try:
                self._queue.put_nowait(job)
            except queue.Full:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except queue.Empty:
                    pass
                try:
                    self._queue.put_nowait(job)
                except queue.Full:
                    accepted = False
                    self._result = _unavailable("queue_full")
                    self._result.update({
                        "generation": str(generation),
                        "max_age_seconds": self.max_age_seconds,
                        "trace_id": snapshot["_source_trace_id"],
                        "edge_event": snapshot["_edge_event"],
                        "source_context": snapshot["_source_context"],
                    })
                self._result_generation = generation
            if accepted:
                # Publish the in-flight generation before the worker starts so
                # downstream latest-only lanes can correlate and wait for it.
                # Supersession also clears any prior frame/result freshness.
                self._result = {
                    **_unavailable("queued"),
                    "status": "queued",
                    "reason": "",
                    "generation": str(generation),
                    "max_age_seconds": self.max_age_seconds,
                    "trace_id": snapshot["_source_trace_id"],
                    "provenance": {"observations": ["rust_core_normalized_event"],
                                   "derived_signals": ["edge_tactical_scorer_v1"]},
                    "edge_event": snapshot["_edge_event"],
                    "source_context": snapshot["_source_context"],
                }
                self._result_generation = generation
                self._result_completed_monotonic = None
                self._result_completed_at = ""
        return {
            "schema_version": "azazel.mio_auxiliary.v1",
            "status": "queued" if accepted else "degraded",
            "reason": "" if accepted else "queue_full",
            "authority": _AUTHORITY,
            "source": "mio_shared_core",
            "generation": str(generation),
            "max_age_seconds": self.max_age_seconds,
            "trace_id": str((event.get("enforcement") or {}).get("trace_id") or "")[:96]
                if isinstance(event.get("enforcement"), Mapping) else "",
            "provenance": {"observations": ["rust_core_normalized_event"], "derived_signals": ["edge_tactical_scorer_v1"]},
            "knowledge": {"status": "not_provided", "refs": []},
            "advisory": None,
            "edge_event": snapshot["_edge_event"],
            "source_context": snapshot["_source_context"],
        }

    def _run(self) -> None:
        try:
            from azazel_mio.assistant import AssistantCore
            from azazel_mio.contracts import ContextDependencyOutcome, MioSituationFrame
            self._core = AssistantCore(model=None)
            self._frame_type = MioSituationFrame
            self._knowledge_statuses = frozenset(item.value for item in ContextDependencyOutcome)
        except Exception:
            self._import_error = "package_unavailable"
        while True:
            job = self._queue.get()
            try:
                queued, generation, event, score, factors, risk_level, factors_truncated = job
                if self._core is None:
                    result = _unavailable(self._import_error or "package_unavailable")
                elif time.monotonic() - queued > self.max_age_seconds:
                    result = _unavailable("stale_job")
                else:
                    try:
                        payload = _safe_event(event, score, factors, risk_level, factors_truncated=factors_truncated)
                        frame = self._frame_type.from_dict(payload)
                        with self._lock:
                            if generation == self._generation:
                                self._frame_snapshot = frame.to_dict() if callable(getattr(frame, "to_dict", None)) else dict(payload)
                        assistance = self._core.explain(
                            frame, now=datetime.now(timezone.utc).isoformat(),
                            knowledge_attempted=False,
                        ).to_dict()
                        if time.monotonic() - queued > self.max_age_seconds:
                            result = _unavailable("stale_job")
                            assistance = None
                        if assistance is None:
                            pass
                        else:
                            canonical = json.dumps(assistance, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                            if len(canonical.encode("ascii")) > MAX_RESULT_BYTES or assistance.get("frame_id") != frame.frame_id or assistance.get("trace_id") != frame.trace_id:
                                raise ValueError("malformed_mio_output")
                            dependency_outcome = assistance.get("dependency_outcome")
                            knowledge_status = dependency_outcome.get("knowledge") if isinstance(dependency_outcome, Mapping) else None
                            if type(knowledge_status) is not str or knowledge_status not in self._knowledge_statuses:
                                result = _unavailable("invalid_knowledge_status")
                                result["knowledge"]["status"] = "rejected"
                            else:
                                result = {
                                "schema_version": "azazel.mio_auxiliary.v1",
                                "status": "complete",
                                "reason": "",
                                "authority": _AUTHORITY,
                                "source": "mio_shared_core",
                                "generation": str(generation),
                                "max_age_seconds": self.max_age_seconds,
                                "trace_id": str(event.get("_source_trace_id") or "")[:96],
                                "provenance": {
                                    "observations": ["rust_core_normalized_event"],
                                    "derived_signals": ["edge_tactical_scorer_v1"],
                                },
                                "knowledge": {"status": knowledge_status, "refs": []},
                                "advisory": assistance,
                                "edge_event": dict(event.get("_edge_event") or {}),
                                "source_context": dict(event.get("_source_context") or {}),
                                "handoff_binding": {
                                    "status": "matched", "generation": str(generation),
                                    "event_key": str((event.get("_source_context") or {}).get("event_key") or ""),
                                    "edge_trace_id": str((event.get("_edge_event") or {}).get("trace_id") or ""),
                                    "edge_action": (event.get("_edge_event") or {}).get("action"),
                                    "edge_mode": (event.get("_edge_event") or {}).get("mode"),
                                    "edge_result": (event.get("_edge_event") or {}).get("result"),
                                    "mio_trace_id": str(assistance.get("trace_id") or ""),
                                    "frame_id": str(assistance.get("frame_id") or ""),
                                },
                                }
                    except Exception as exc:
                        # Only an exception type is retained; exception text
                        # can contain model or event supplied material.
                        result = _unavailable("mio_failure:" + type(exc).__name__[:48])
                assistance_payload = result.get("advisory")
                if isinstance(assistance_payload, dict):
                    receipt = assistance_payload.pop("knowledge_context_response_advisory", None)
                    projected = _project_knowledge_advisory(receipt, generation=generation,
                                        trace_id=str(event.get("_source_trace_id") or "")[:96])
                    if projected is not None:
                        result["edge_knowledge_advisory"] = projected
                result["generation"] = str(generation)
                result["max_age_seconds"] = self.max_age_seconds
                result["trace_id"] = str(event.get("_source_trace_id") or "")[:96]
                result.setdefault("edge_event", dict(event.get("_edge_event") or {}))
                result.setdefault("source_context", dict(event.get("_source_context") or {}))
                if "handoff_binding" not in result:
                    edge = result.get("edge_event") if isinstance(result.get("edge_event"), Mapping) else {}
                    result["handoff_binding"] = {
                        "status": "matched", "generation": str(generation),
                        "event_key": str((event.get("_source_context") or {}).get("event_key") or ""),
                        "edge_trace_id": str(edge.get("trace_id") or ""),
                        "edge_action": edge.get("action"), "edge_mode": edge.get("mode"),
                        "edge_result": edge.get("result"), "mio_trace_id": "", "frame_id": "",
                    }
                if not _binding_matches(result):
                    result["handoff_binding"]["status"] = "mismatch"
                    result["handoff_binding"]["valid"] = False
                else:
                    result["handoff_binding"]["valid"] = True
                if len(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")) > MAX_RESULT_BYTES:
                    result = _unavailable("result_too_large")
                    result["edge_event"] = dict(event.get("_edge_event") or {})
                    result["generation"] = str(generation)
                    result["max_age_seconds"] = self.max_age_seconds
                    result["trace_id"] = str(event.get("_source_trace_id") or "")[:96]
                with self._lock:
                    # Late generations cannot overwrite a newer submitted event.
                    if generation == self._generation:
                        self._result = result
                        self._result_generation = generation
                        if result.get("status") == "complete":
                            self._result_completed_monotonic = time.monotonic()
                            self._result_completed_at = datetime.now(timezone.utc).isoformat()
                        else:
                            self._result_completed_monotonic = None
                            self._result_completed_at = ""
            finally:
                self._queue.task_done()
