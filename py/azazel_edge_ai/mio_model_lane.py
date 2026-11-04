"""Separately paced, opt-in M.I.O. model analysis over an existing fast result.

Its caller supplies the existing Edge Ollama transport. The worker is latest-only, bounded, and advisory-only.
"""
from __future__ import annotations

import json
import inspect
import queue
import threading
import time
from typing import Any, Callable, Mapping

# mio_live_auxiliary imports only the standard library, so this direction cannot cycle.
from azazel_edge_ai.mio_live_auxiliary import binding_matches_same_envelope

KNOWLEDGE_STATUSES = frozenset({'disabled', 'missing_token', 'invalid_configuration', 'unavailable',
                      'timeout', 'oversized', 'redirect_rejected', 'auth_rejected',
                      'scope_rejected', 'malformed', 'received', 'superseded', 'projected', 'rejected'})
MODEL_TASKS = frozenset({"generate_hypotheses", "identify_evidence_gaps",
                         "update_hypotheses", "recommend"})
MODEL_CALL_OUTCOMES = frozenset({"success", "failure"})
MAX_MODEL_CALLS = 4
MAX_MODEL_CALL_ELAPSED_NS = 10_000_000_000


MAX_AGE_SECONDS = 10.0
MAX_DIAGNOSTICS = 64
_ALTERNATIVE_ROLES = {
    "credential_attack": "hostile", "misconfigured_automation": "benign",
    "reconnaissance": "hostile", "inventory_monitoring": "benign",
    "misconfiguration": "benign", "exploit_attempt": "hostile",
    "probe_signature_collision": "benign", "malformed_benign_client": "benign",
    "security_availability_event": "hostile", "independent_noc_failure": "benign",
    "shared_configuration_resource": "unresolved", "behavior_adapted": "unresolved",
    "activity_naturally_ended": "benign", "unrelated_replacement_traffic": "benign",
    "suspicious_behavior_interaction": "hostile", "generic_automated_interaction": "benign",
    "unrelated_confounder": "unresolved", "hostile_activity": "hostile",
    "benign_activity": "benign", "insufficient_evidence": "unresolved",
}
_ROLE_TEXT = {
    "hostile": "A hostile-activity explanation remains possible, but this frame does not establish it.",
    "benign": "A benign-activity explanation remains possible, but this frame does not establish it.",
    "unresolved": "The frame is insufficient to distinguish competing explanations.",
}
_VALIDATION_REJECTIONS = frozenset({"validation_rejected"})


_VALIDATION_STAGES = frozenset({"unknown", "playbook", "generate_hypotheses",
    "identify_evidence_gaps", "update_hypotheses", "recommend"})
_VALIDATION_CLASSES = frozenset({"unknown", "output_shape", "alternative_slots",
    "model_identifier", "evidence_grounding", "raw_payload", "hypothesis_structure",
    "evidence_gap", "hypothesis_lifecycle", "recommendation_structure", "unsupported_claim"})


def bounded_validation_diagnostic(value: Any) -> dict[str, str]:
    """Accept only the complete closed M.I.O. diagnostic; never copy error text."""
    if type(value) is not dict or value.keys() != {"stage", "rejection_class"}:
        return {}
    stage, rejection_class = value["stage"], value["rejection_class"]
    if (type(stage) is not str or stage not in _VALIDATION_STAGES
            or type(rejection_class) is not str or rejection_class not in _VALIDATION_CLASSES):
        return {}
    return {"stage": stage, "rejection_class": rejection_class}


def bounded_truncated_count(value: Any) -> int:
    """Shared fail-closed truncation bound: exact ints 0..4 pass; any other present value is 4."""
    if type(value) is not int or not 0 <= value <= 4:
        return 4
    return value


def bounded_call_timings(values: Any) -> list[dict[str, Any]]:
    """Keep only bounded MIO task timings; never accept prompt or response fields."""
    if type(values) is not list:
        return []
    result = []
    for item in values[:MAX_MODEL_CALLS]:
        if not isinstance(item, Mapping):
            continue
        task, elapsed_ns, outcome = item.get("task"), item.get("elapsed_ns"), item.get("outcome")
        if (type(task) is not str or task not in MODEL_TASKS | {"other"}
                or type(elapsed_ns) is not int or type(outcome) is not str
                or outcome not in MODEL_CALL_OUTCOMES):
            continue
        result.append({"task": task,
                       "elapsed_ns": max(0, min(elapsed_ns, MAX_MODEL_CALL_ELAPSED_NS)),
                       "outcome": outcome})
    return result


def bounded_usage(values: Mapping[str, Any]) -> dict[str, Any]:
    """Allow only bounded accrued measurements across failure boundaries."""
    result = {}
    for key, cap in (("request_count", 4), ("metered_request_count", 4),
                     ("unknown_usage_request_count", 4),
                     ("prompt_tokens", 400_000), ("completion_tokens", 400_000),
                     ("load_duration_ms", 600_000)):
        value = values.get(key)
        result[key] = max(0, min(value, cap)) if type(value) is int else 0
    # A truly missing key carries no truncation evidence (0); a present value is bounded fail-closed.
    result["truncated_count"] = bounded_truncated_count(values["truncated_count"]) if "truncated_count" in values else 0
    result["model"] = values.get("model", "")[:96] if type(values.get("model")) is str else ""
    result["call_timings"] = bounded_call_timings(values.get("call_timings", []))
    requests, metered = result["request_count"], result["metered_request_count"]
    result["unknown_usage_request_count"] = max(0, requests - metered)
    result["usage_status"] = ("unknown" if metered == 0 else
        "complete" if metered == requests and not result["truncated_count"] else "partial")
    if "knowledge_status" in values:
        status = values.get("knowledge_status")
        result["knowledge_status"] = status if type(status) is str and status in KNOWLEDGE_STATUSES else "unavailable"
    return result


class MioModelFailure(RuntimeError):
    def __init__(self, reason: str, metrics: Mapping[str, Any]):
        super().__init__(reason)
        self.reason = reason
        self.metrics = bounded_usage(metrics)


def _bounded_hypotheses(values: Any, frame: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Render only M.I.O.-validated alternative IDs as fixed unverified text.

    Model-authored statements are intentionally not returned. Frame refs are
    context pointers only; they do not establish support for an alternative.
    """
    if not isinstance(values, list):
        return []
    trusted_refs = set(frame.get("evidence_refs", [])) if isinstance(frame.get("evidence_refs"), list) else set()
    result: list[dict[str, Any]] = []
    for item in values[:4]:
        if not isinstance(item, Mapping):
            continue
        alternative_id = item.get("hypothesis_alternative_id")
        role = _ALTERNATIVE_ROLES.get(alternative_id) if type(alternative_id) is str else None
        if role is None:
            continue
        statement = _ROLE_TEXT[role]
        refs = item.get("frame_refs", [])
        refs = [ref[:128] for ref in refs[:8] if type(ref) is str and ref in trusted_refs] if isinstance(refs, list) else []
        result.append({
            "hypothesis_alternative_id": alternative_id,
            "statement": statement,
            "verification": "model_proposed_unverified",
            "source": "mio_validated_alternative",
            "frame_refs": refs,
            **({"context_only": True} if not refs else {}),
        })
    return result


def _empty(status: str, reason: str = "") -> dict[str, Any]:
    return {
        "schema_version": "azazel.mio_model_analysis.v1",
        "status": status,
        "reason": reason,
        "authority": "read_only_advisory",
        "label": "Measured model analysis (advisory)",
        "generation": "",
        "trace_id": "",
        "model": "",
        "duration_ms": 0,
        "load_duration_ms": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "request_count": 0,
        "metered_request_count": 0,
        "unknown_usage_request_count": 0,
        "truncated_count": 0,
        "call_timings": [],
        "usage_status": "unknown",
        "outcome": status,
        "summary": "",
        "uncertainties": [],
        "hypotheses": [],
        "next_checks": [],
        "unknowns": [],
        "mio_state": "",
        "generation_method": "",
        "frame_id": "",
        "frame_generation": "",
        "validation_rejection": "",
    }


def _fast_binding_verified(fast: Mapping[str, Any]) -> bool:
    """Require the producer's explicit valid marker plus the same-envelope field check."""
    binding = fast.get("handoff_binding")
    if not isinstance(binding, Mapping) or binding.get("valid") is not True:
        return False
    try:
        return binding_matches_same_envelope(fast) is True
    except Exception:
        return False


def _fast_payload(result: Mapping[str, Any]) -> dict[str, Any]:
    """Project only small, typed, non-action fields from the static result."""
    advisory = result.get("advisory") if isinstance(result.get("advisory"), Mapping) else {}
    knowledge = result.get("knowledge") if isinstance(result.get("knowledge"), Mapping) else {}
    hypotheses = advisory.get("hypotheses") if isinstance(advisory.get("hypotheses"), list) else []
    checks = advisory.get("next_checks") if isinstance(advisory.get("next_checks"), list) else []

    def statements(values: list[Any], key: str) -> list[str]:
        out = []
        for item in values[:4]:
            value = item.get(key) if isinstance(item, Mapping) else item
            if type(value) is str:
                out.append(value[:160])
        return out

    summary = advisory.get("summary")
    return {
        "trace_id": str(result.get("trace_id") or "")[:96],
        "knowledge_status": str(knowledge.get("status") or "not_provided")[:48],
        "static_summary": summary[:240] if type(summary) is str else "",
        "hypotheses": statements(hypotheses, "statement"),
        "next_checks": statements(checks, "check"),
    }


class LiveMioModelLane:
    """One-slot asynchronous model lane, gated off unless explicitly enabled."""

    def __init__(self, *, enabled: bool, analyze: Callable[[dict[str, Any], float], Mapping[str, Any]],
                 fast_snapshot: Callable[[], Mapping[str, Any]],
                 frame_snapshot: Callable[[Any], Mapping[str, Any] | None] | None = None,
                 authorize: Callable[[Mapping[str, Any]], tuple[bool, str]] | None = None,
                 max_age_seconds: float = MAX_AGE_SECONDS,
                 audit_result: Callable[[str, dict[str, Any]], None] | None = None):
        # audit_result(trace_id, final_result) durably audits the lane-accepted result
        # under self._lock with the freshness re-check and publication. Raising fails the result closed.
        self._audit_result = audit_result
        self.enabled = bool(enabled)
        self.max_age_seconds = max(0.1, min(float(max_age_seconds), MAX_AGE_SECONDS))
        self._analyze = analyze
        self._fast_snapshot = fast_snapshot
        self._frame_snapshot = frame_snapshot
        self._authorize = authorize
        self._queue: queue.Queue[tuple[float, int, str, dict[str, Any], str]] = queue.Queue(maxsize=1)
        self._lock = threading.RLock()
        self._generation = 0
        # The snapshot worker persists only results produced by accepted async
        # submissions. Immediate disabled/skipped/degraded submissions change
        # the visible generation, but are not completion events.
        self._async_generation = 0
        self._result = _empty("disabled" if not self.enabled else "starting")
        self._diagnostics: list[dict[str, Any]] = []
        self._thread = threading.Thread(target=self._run, name="mio-model-analysis", daemon=True)
        self._thread.start()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            result = json.loads(json.dumps(self._result))
            result["diagnostic_count"] = len(self._diagnostics)
            result["is_current"] = (result.get("status") in {"complete", "partial"}
                and str(result.get("generation") or "") == str(self._generation))
            return result

    def diagnostics(self) -> list[dict[str, Any]]:
        with self._lock:
            return json.loads(json.dumps(self._diagnostics))

    def completed_async_generation(self) -> str:
        """Return the current async generation once it reaches a terminal state."""
        with self._lock:
            if self._async_generation == 0 or self._async_generation != self._generation:
                return ""
            if self._result.get("status") in {"starting", "queued"}:
                return ""
            return str(self._async_generation)

    def submit(self, generation: Any, trace_id: str, *, skip_reason: str = "",
               authorization_payload: Mapping[str, Any] | None = None,
               source_trace_id: str = "") -> dict[str, Any]:
        with self._lock:
            self._generation += 1
            current = self._generation
            if not self.enabled:
                self._result = {**_empty("disabled", "opt_in_off"), "generation": str(current), "trace_id": str(trace_id)[:96]}
                return self.snapshot()
            if skip_reason:
                self._result = {**_empty("skipped", skip_reason), "generation": str(current), "trace_id": str(trace_id)[:96]}
                return self.snapshot()
            queued = False
            try:
                self._queue.put_nowait((time.monotonic(), current, str(generation or ""),
                                        dict(authorization_payload or {}), str(source_trace_id)[:96]))
                queued = True
            except queue.Full:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except queue.Empty:
                    pass
                try:
                    self._queue.put_nowait((time.monotonic(), current, str(generation or ""),
                                            dict(authorization_payload or {}), str(source_trace_id)[:96]))
                    queued = True
                except queue.Full:
                    self._result = {**_empty("degraded", "queue_full"), "generation": str(current), "trace_id": str(trace_id)[:96]}
            if queued:
                self._async_generation = current
                self._result = {
                    **_empty("queued"), "generation": str(current), "trace_id": str(trace_id)[:96],
                    "fast_generation": str(generation or ""),
                }
            return json.loads(json.dumps(self._result))

    def _record(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._diagnostics.append(record)
            del self._diagnostics[:-MAX_DIAGNOSTICS]

    def _run(self) -> None:
        while True:
            queued_at, generation, fast_generation, authorization_payload, source_trace_id = self._queue.get()
            try:
                deadline = queued_at + self.max_age_seconds
                fast: Mapping[str, Any] | None = None
                audit_pending = False
                while time.monotonic() < deadline:
                    try:
                        candidate = self._fast_snapshot()
                    except Exception:
                        # Snapshot failure cannot verify the fast result: degrade without killing the worker.
                        fast = None
                        break
                    if str(candidate.get("generation") or "") != fast_generation:
                        break
                    if candidate.get("status") not in {"pending", "starting", "queued"}:
                        fast = candidate
                        break
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
                if fast is None or fast.get("status") != "complete" or fast.get("is_current") is not True:
                    result = _empty("degraded", "fast_result_unavailable")
                elif not _fast_binding_verified(fast):
                    # Checked before authorization, analysis, and audit: an unbound or reduced
                    # fast envelope never reaches the model, governance, or audit boundary.
                    result = _empty("degraded", "fast_binding_unverified")
                elif time.monotonic() >= deadline:
                    result = _empty("degraded", "deadline_exceeded")
                else:
                    if self._authorize is not None:
                        try:
                            allowed, reason = self._authorize(authorization_payload)
                        except Exception:
                            allowed, reason = False, "audit_failed"
                        if not allowed:
                            result = _empty("skipped", "governance_denied:" + str(reason or "denied")[:64])
                            with self._lock:
                                if generation == self._generation:
                                    result.update({"generation": str(generation),
                                                   "trace_id": str(fast.get("trace_id") or "")[:96],
                                                   "fast_generation": fast_generation})
                                    self._result = result
                            self._record({key: result.get(key) for key in (
                                "generation", "trace_id", "model", "duration_ms", "load_duration_ms",
                                "prompt_tokens", "completion_tokens", "request_count", "metered_request_count",
                                "truncated_count", "call_timings", "usage_status", "outcome", "status", "reason")})
                            continue
                        if generation != self._generation:
                            result = _empty("degraded", "superseded")
                            result.update({"generation": str(generation),
                                           "trace_id": str(fast.get("trace_id") or "")[:96],
                                           "fast_generation": fast_generation})
                            self._record({key: result.get(key) for key in (
                                "generation", "trace_id", "model", "duration_ms", "load_duration_ms",
                                "prompt_tokens", "completion_tokens", "request_count", "metered_request_count",
                                "truncated_count", "call_timings", "usage_status", "outcome", "status", "reason")})
                            continue
                    started = time.monotonic()
                    try:
                        remaining = max(0.0, deadline - time.monotonic())
                        if remaining <= 0:
                            raise TimeoutError("deadline_exceeded")
                        # The model lane receives the exact accepted frame used
                        # by the deterministic shared-core lane. Advisory prose
                        # from that lane is never promoted to model evidence.
                        frame_payload = self._frame_snapshot(fast_generation) if self._frame_snapshot else None
                        if not isinstance(frame_payload, Mapping):
                            raise RuntimeError("accepted_frame_unavailable")
                        advisory = fast.get("advisory")
                        if (not isinstance(advisory, Mapping)
                                or frame_payload.get("frame_id") != advisory.get("frame_id")
                                or frame_payload.get("trace_id") != advisory.get("trace_id")):
                            # Bind the fetched frame to the verified fast advisory before any
                            # model call or result-audit adoption can occur.
                            raise MioModelFailure("frame_binding_rejected", {})
                        stale_check = lambda: (generation != self._generation or
                            str(self._fast_snapshot().get("generation") or "") != fast_generation)
                        if stale_check():
                            raise TimeoutError("superseded")
                        try:
                            analyze_parameter_count = len(inspect.signature(self._analyze).parameters)
                        except (TypeError, ValueError):
                            analyze_parameter_count = 0
                        # Only post-authorization analysis attempts are finalized through the output
                        # callback; pre-analysis failures above (frame, stale, deadline) are not audited here.
                        audit_pending = True
                        if analyze_parameter_count >= 4:
                            analyzed = self._analyze(dict(frame_payload), remaining, stale_check, source_trace_id)
                        elif analyze_parameter_count >= 3:
                            analyzed = self._analyze(dict(frame_payload), remaining, stale_check)
                        else:
                            analyzed = self._analyze(dict(frame_payload), remaining)
                        if stale_check():
                            raise TimeoutError("superseded")
                        model_result = dict(analyzed)
                        elapsed = max(0, int((time.monotonic() - started) * 1000))
                        safe_hypotheses = _bounded_hypotheses(model_result.get("hypotheses"), frame_payload)
                        safe_checks = [x[:200] for x in model_result.get("next_checks", [])[:4] if type(x) is str] if isinstance(model_result.get("next_checks"), list) else []
                        safe_unknowns = [x[:160] for x in model_result.get("unknowns", [])[:12] if type(x) is str] if isinstance(model_result.get("unknowns"), list) else []
                        mio_state = str(model_result.get("mio_state") or "")[:48]
                        model_outcome = str(model_result.get("outcome") or "completed")[:48]
                        validation_rejection = model_result.get("validation_rejection")
                        validation_rejection = (validation_rejection if type(validation_rejection) is str
                                                and validation_rejection in _VALIDATION_REJECTIONS else "")
                        # Missing or malformed truncation evidence fails closed as truncated.
                        truncated_count = bounded_truncated_count(model_result.get("truncated_count"))
                        # Never copy analyzer usage_status/unknown count: recompute from normalized values.
                        request_count = max(0, min(int(model_result.get("request_count") or 0), 4))
                        metered_count = max(0, min(int(model_result.get("metered_request_count") or 0), 4))
                        usage = bounded_usage({"request_count": request_count,
                                               "metered_request_count": metered_count,
                                               "truncated_count": truncated_count})
                        has_model_contribution = model_result.get("generation_method") == "model"
                        if model_outcome == "completed" and mio_state == "complete" and truncated_count == 0:
                            result_status, result_reason = "complete", ""
                        elif has_model_contribution:
                            result_status, result_reason = "partial", "mio_partial:" + (mio_state or "incomplete")
                        else:
                            result_status, result_reason = "degraded", "mio_no_model_contribution"
                        result = {
                            **_empty(result_status, result_reason),
                            "summary": str(model_result.get("summary") or "")[:320],
                            "uncertainties": [str(x)[:120] for x in model_result.get("uncertainties", [])[:3]
                                              if type(x) is str] if isinstance(model_result.get("uncertainties"), list) else [],
                            "confidence": round(max(0.0, min(float(model_result.get("confidence", 0.0)), 1.0)), 3),
                            "model": str(model_result.get("model") or "")[:96],
                            "duration_ms": min(elapsed, 600_000),
                            "load_duration_ms": max(0, min(int(model_result.get("load_duration_ms") or 0), 600_000)),
                            "prompt_tokens": max(0, min(int(model_result.get("prompt_tokens") or 0), 100_000)),
                            "completion_tokens": max(0, min(int(model_result.get("completion_tokens") or 0), 100_000)),
                            "request_count": request_count,
                            "metered_request_count": metered_count,
                            "unknown_usage_request_count": usage["unknown_usage_request_count"],
                            "truncated_count": truncated_count,
                            "call_timings": bounded_call_timings(model_result.get("call_timings", [])),
                            "usage_status": usage["usage_status"],
                            "outcome": model_outcome,
                            "frame_id": str(model_result.get("frame_id") or "")[:96],
                            "frame_trace_id": str(model_result.get("trace_id") or "")[:96],
                            "mio_state": mio_state,
                            "generation_method": str(model_result.get("generation_method") or "")[:48],
                            "hypotheses": safe_hypotheses,
                            "next_checks": safe_checks,
                            "unknowns": safe_unknowns,
                            "frame_generation": fast_generation,
                            "validation_rejection": validation_rejection,
                            **({"validation_diagnostic": diagnostic} if (diagnostic :=
                                bounded_validation_diagnostic(model_result.get("validation_diagnostic"))) else {}),
                        }
                        if model_result.get("frame_id") != frame_payload.get("frame_id") or model_result.get("trace_id") != frame_payload.get("trace_id"):
                            result = _empty("degraded", "frame_binding_rejected")
                    except (TimeoutError, MioModelFailure) as exc:
                        elapsed = max(0, int((time.monotonic() - started) * 1000))
                        result = _empty("degraded", exc.reason if isinstance(exc, MioModelFailure) else "deadline_exceeded")
                        if isinstance(exc, MioModelFailure):
                            result.update(exc.metrics)
                        result["duration_ms"] = min(elapsed, 600_000)
                    except Exception:
                        elapsed = max(0, int((time.monotonic() - started) * 1000))
                        result = _empty("degraded", "model_error")
                        result["duration_ms"] = min(elapsed, 600_000)
                with self._lock:
                    # Strict invariant: re-check freshness, audit the final result and publish it
                    # while holding the lane lock, so a newer submit cannot interleave.
                    if audit_pending and self._audit_result is not None:
                        audit_trace = (source_trace_id or str(result.get("frame_trace_id") or "")[:96]
                                       or str(fast.get("trace_id") or "")[:96])
                        # A failing snapshot means freshness cannot be verified: treat as not fresh.
                        try:
                            fresh = (generation == self._generation and
                                     str(self._fast_snapshot().get("generation") or "") == fast_generation)
                        except Exception:
                            fresh = False
                        if not fresh:
                            result = _empty("degraded", "superseded")
                        try:
                            self._audit_result(audit_trace, result)
                        except Exception:
                            if fresh:
                                usage = bounded_usage(result)
                                result = _empty("degraded", "mio_model_result_audit_failed")
                                result.update(usage)
                                result["summary"] = ""
                    if generation == self._generation:
                        result["generation"] = str(generation)
                        result["trace_id"] = (str(result.get("frame_trace_id") or "") if result.get("status") in {"complete", "partial"}
                                               else str(fast.get("trace_id") or "")[:96] if fast else "")
                        result["fast_generation"] = fast_generation
                        result["authority"] = "read_only_advisory"
                        result["label"] = "Measured model analysis (advisory)"
                        self._result = result
                self._record({key: result.get(key) for key in (
                    "generation", "trace_id", "model", "duration_ms", "load_duration_ms",
                    "prompt_tokens", "completion_tokens", "request_count", "metered_request_count",
                    "truncated_count", "call_timings", "usage_status", "outcome", "status", "reason")})
            finally:
                self._queue.task_done()
