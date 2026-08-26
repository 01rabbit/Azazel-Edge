from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .adapter import from_rust_event
from .contracts import CausalSupport, EffectObjective, ExecutionStatus, OutcomeAssessment, OutcomeRecord
from .observer import DEFAULT_INPUT, DEFAULT_MAX_OUTPUT_BYTES, append_jsonl
from .release_evidence import ReleaseEvidenceStatus, from_rust_release_event

POLICY_SCHEMA_VERSION = "outcome-telemetry-policy/v1"
DEFAULT_OUTPUT = "/var/log/azazel-edge/outcome-telemetry.jsonl"
DEFAULT_SAMPLE_INTERVAL_SECONDS = 1.0
DEFAULT_BUFFER_SECONDS = 600.0
DEFAULT_MAX_SAMPLES = 4096
DEFAULT_MAX_ACTIVITY_EVENTS = 8192
DEFAULT_MAX_PENDING = 128
DEFAULT_MAX_SEEN_EXECUTIONS = 4096
_DISRUPTIVE_ACTIONS = {"throttle", "redirect", "isolate"}
_COUNTER_KEYS = (
    "rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
    "tx_bytes", "tx_packets", "tx_errors", "tx_dropped",
)


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _epoch_from_iso(value: Any) -> float | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    epoch = parsed.timestamp()
    return epoch if math.isfinite(epoch) and epoch >= 0.0 else None


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = "|".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:24]}"


@dataclass(frozen=True)
class TelemetrySample:
    epoch: float
    observed_at: str
    interface: str
    network: Mapping[str, int | float]
    system: Mapping[str, int | float]
    coverage: Mapping[str, bool]
    evidence_ref: str


@dataclass(frozen=True)
class ActivityEvent:
    epoch: float
    src_ip: str
    dst_ip: str
    target_port: int
    sid: int
    evidence_ref: str


class TelemetrySource(Protocol):
    def sample(self, *, interface: str, epoch: float) -> TelemetrySample:
        ...


class LinuxProcTelemetrySource:
    """Read-only Linux telemetry source using procfs only."""

    def __init__(self, proc_root: Path | str = "/proc") -> None:
        self.proc_root = Path(proc_root)

    def sample(self, *, interface: str, epoch: float) -> TelemetrySample:
        if not _valid_interface(interface):
            raise ValueError("invalid telemetry interface")
        if not math.isfinite(epoch) or epoch < 0.0:
            raise ValueError("telemetry epoch must be finite and non-negative")

        network: dict[str, int | float] = {}
        system: dict[str, int | float] = {}
        coverage = {"proc_net_dev": False, "proc_loadavg": False, "proc_meminfo": False, "proc_uptime": False}
        material: dict[str, Any] = {"interface": interface, "epoch": epoch}

        try:
            network = _parse_proc_net_dev((self.proc_root / "net" / "dev").read_text(encoding="utf-8"), interface)
            coverage["proc_net_dev"] = bool(network)
            material["net_dev"] = network
        except OSError:
            pass
        try:
            values = _parse_loadavg((self.proc_root / "loadavg").read_text(encoding="utf-8"))
            system.update(values)
            coverage["proc_loadavg"] = bool(values)
            material["loadavg"] = values
        except OSError:
            pass
        try:
            values = _parse_meminfo((self.proc_root / "meminfo").read_text(encoding="utf-8"))
            system.update(values)
            coverage["proc_meminfo"] = bool(values)
            material["meminfo"] = values
        except OSError:
            pass
        try:
            values = _parse_uptime((self.proc_root / "uptime").read_text(encoding="utf-8"))
            system.update(values)
            coverage["proc_uptime"] = bool(values)
            material["uptime"] = values
        except OSError:
            pass

        digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:24]
        return TelemetrySample(
            epoch=epoch,
            observed_at=_iso(epoch),
            interface=interface,
            network=network,
            system=system,
            coverage=coverage,
            evidence_ref=f"procfs-sample:{digest}",
        )


@dataclass(frozen=True)
class ObjectiveTemplate:
    metric: str
    direction: str
    target_or_range: Mapping[str, Any]
    observation_window: Mapping[str, Any]
    guardrails: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    policy_version: str = "unversioned"

    def instantiate(self, decision_id: str) -> EffectObjective:
        objective_id = _stable_id(
            "objective",
            decision_id,
            self.metric,
            self.direction,
            json.dumps(self.target_or_range, sort_keys=True, separators=(",", ":")),
            json.dumps(self.observation_window, sort_keys=True, separators=(",", ":")),
            self.policy_version,
        )
        return EffectObjective(
            decision_id=decision_id,
            metric=self.metric,
            direction=self.direction,
            target_or_range=dict(self.target_or_range),
            observation_window=dict(self.observation_window),
            guardrails=tuple(dict(value) for value in self.guardrails),
            policy_version=self.policy_version,
            objective_id=objective_id,
        )


class OutcomeTelemetryPolicy:
    def __init__(self, templates: Mapping[str, ObjectiveTemplate], *, policy_ref: str) -> None:
        self.templates = {str(key).lower(): value for key, value in templates.items()}
        self.policy_ref = policy_ref

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any], *, source_ref: str = "inline") -> "OutcomeTelemetryPolicy":
        if str(payload.get("schema_version") or "") != POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported outcome telemetry policy schema")
        actions = payload.get("actions")
        if not isinstance(actions, Mapping):
            raise ValueError("outcome telemetry policy requires actions mapping")
        templates: dict[str, ObjectiveTemplate] = {}
        for action, raw in actions.items():
            name = str(action).strip().lower()
            if name not in _DISRUPTIVE_ACTIONS or not isinstance(raw, Mapping):
                raise ValueError(f"unsupported or malformed telemetry policy action: {name}")
            metric = str(raw.get("metric") or "").strip()
            direction = str(raw.get("direction") or "").strip().lower()
            if not metric or direction not in {"increase", "decrease", "within", "observe"}:
                raise ValueError(f"telemetry policy action {name} has invalid metric/direction")
            target = raw.get("target_or_range") or {}
            window = raw.get("observation_window") or {}
            guardrails = raw.get("guardrails") or []
            if not isinstance(target, Mapping) or not isinstance(window, Mapping):
                raise ValueError("target_or_range and observation_window must be mappings")
            if not isinstance(guardrails, Sequence) or isinstance(guardrails, (str, bytes)):
                raise ValueError("guardrails must be a sequence")
            if any(not isinstance(value, Mapping) for value in guardrails):
                raise ValueError("every guardrail must be a mapping")
            _window_seconds(window)
            templates[name] = ObjectiveTemplate(
                metric=metric,
                direction=direction,
                target_or_range=dict(target),
                observation_window=dict(window),
                guardrails=tuple(dict(value) for value in guardrails),
                policy_version=str(raw.get("policy_version") or payload.get("policy_version") or "unversioned"),
            )
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:24]
        return cls(templates, policy_ref=f"telemetry-policy:{source_ref}:{digest}")

    @classmethod
    def from_file(cls, path: Path) -> "OutcomeTelemetryPolicy":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise ValueError("outcome telemetry policy file must contain an object")
        return cls.from_mapping(raw, source_ref=str(path))

    def objective_for(self, action: str, decision_id: str) -> EffectObjective | None:
        template = self.templates.get(str(action).lower())
        return template.instantiate(decision_id) if template is not None else None

    def max_window_seconds(self) -> float:
        maximum = 0.0
        for template in self.templates.values():
            pre, post = _window_seconds(template.observation_window)
            maximum = max(maximum, pre, post)
        return maximum


@dataclass
class _PendingObservation:
    incident_id: str
    decision_id: str
    execution_id: str
    mechanism_id: str
    action_kind: str
    src_ip: str
    objective: EffectObjective
    trigger_epoch: float
    pre_start_epoch: float
    planned_end_epoch: float
    effective_end_epoch: float
    trigger_activity_ref: str = ""
    release_ref: str = ""
    release_owner_token: str = ""
    release_resource_key: str = ""
    termination_reason: str = "observation_window_elapsed"
    execution_evidence_refs: tuple[str, ...] = ()
    mechanism_status: str = ""


class OutcomeTelemetryCollector:
    """Passive bounded pre/post telemetry collector. It never claims tactical success."""

    def __init__(
        self,
        *,
        source: TelemetrySource,
        policy: OutcomeTelemetryPolicy,
        interface: str,
        sample_interval_seconds: float = DEFAULT_SAMPLE_INTERVAL_SECONDS,
        buffer_seconds: float = DEFAULT_BUFFER_SECONDS,
        max_samples: int = DEFAULT_MAX_SAMPLES,
        max_activity_events: int = DEFAULT_MAX_ACTIVITY_EVENTS,
        max_pending: int = DEFAULT_MAX_PENDING,
        max_seen_executions: int = DEFAULT_MAX_SEEN_EXECUTIONS,
    ) -> None:
        if not _valid_interface(interface):
            raise ValueError("invalid telemetry interface")
        if sample_interval_seconds <= 0 or not math.isfinite(sample_interval_seconds):
            raise ValueError("sample interval must be finite and positive")
        if buffer_seconds <= 0 or not math.isfinite(buffer_seconds):
            raise ValueError("buffer_seconds must be finite and positive")
        if policy.max_window_seconds() > buffer_seconds:
            raise ValueError("collector buffer is shorter than policy observation window")
        if min(max_samples, max_activity_events, max_pending, max_seen_executions) <= 0:
            raise ValueError("collector capacity bounds must be positive")
        self.source = source
        self.policy = policy
        self.interface = interface
        self.sample_interval_seconds = float(sample_interval_seconds)
        self.buffer_seconds = float(buffer_seconds)
        self.samples: deque[TelemetrySample] = deque(maxlen=max_samples)
        self.activity: deque[ActivityEvent] = deque(maxlen=max_activity_events)
        self.pending: dict[str, _PendingObservation] = {}
        self.seen_execution_ids: set[str] = set()
        self.max_pending = max_pending
        self.max_seen_executions = max_seen_executions

    def record_sample(self, *, epoch: float | None = None) -> TelemetrySample | None:
        now = time.time() if epoch is None else float(epoch)
        try:
            sample = self.source.sample(interface=self.interface, epoch=now)
        except (OSError, ValueError):
            return None
        self.samples.append(sample)
        self._prune(now)
        return sample

    def observe_event(self, event: Mapping[str, Any], *, observed_epoch: float | None = None) -> bool:
        now = time.time() if observed_epoch is None else float(observed_epoch)
        if not math.isfinite(now) or now < 0.0:
            return False
        if str(event.get("pipeline") or "") == "rust_release_engine_v1":
            return self._observe_release(event)

        normalized = event.get("normalized")
        trigger_activity = self._record_activity(event, normalized, now) if isinstance(normalized, Mapping) else None
        try:
            bundle = from_rust_event(event)
        except (TypeError, ValueError):
            return False
        execution = bundle.execution
        action = execution.action_kind.lower()
        if action not in _DISRUPTIVE_ACTIONS or execution.status is not ExecutionStatus.APPLIED:
            return False
        objective = self.policy.objective_for(action, execution.decision_id)
        if objective is None or objective.decision_id != execution.decision_id:
            return False
        if execution.execution_id in self.seen_execution_ids:
            return False
        if len(self.seen_execution_ids) >= self.max_seen_executions or len(self.pending) >= self.max_pending:
            return False

        pre_seconds, post_seconds = _window_seconds(objective.observation_window)
        src_ip = str(normalized.get("src_ip") or "") if isinstance(normalized, Mapping) else ""
        metadata = execution.applied_parameters.get("metadata")
        provider_metadata = metadata if isinstance(metadata, Mapping) else {}
        self.pending[execution.execution_id] = _PendingObservation(
            incident_id=execution.incident_id,
            decision_id=execution.decision_id,
            execution_id=execution.execution_id,
            mechanism_id=bundle.mechanism.mechanism_id,
            action_kind=action,
            src_ip=src_ip,
            objective=objective,
            trigger_epoch=now,
            pre_start_epoch=max(0.0, now - pre_seconds),
            planned_end_epoch=now + post_seconds,
            effective_end_epoch=now + post_seconds,
            trigger_activity_ref=trigger_activity.evidence_ref if trigger_activity else "",
            release_ref=execution.release_ref,
            release_owner_token=str(provider_metadata.get("release_owner_token") or ""),
            release_resource_key=str(provider_metadata.get("release_resource_key") or ""),
            execution_evidence_refs=tuple(execution.provider_evidence_refs),
            mechanism_status=bundle.mechanism.status.value,
        )
        self.seen_execution_ids.add(execution.execution_id)
        self._prune(now)
        return True

    def finalize_due(self, *, epoch: float | None = None) -> tuple[OutcomeRecord, ...]:
        now = time.time() if epoch is None else float(epoch)
        if not math.isfinite(now) or now < 0.0:
            return ()
        due = [key for key, pending in self.pending.items() if pending.effective_end_epoch <= now]
        records = [self._build_outcome(self.pending.pop(key), now) for key in due]
        self._prune(now)
        return tuple(records)

    def _observe_release(self, event: Mapping[str, Any]) -> bool:
        try:
            release = from_rust_release_event(event)
        except (TypeError, ValueError):
            return False
        if release.status is not ReleaseEvidenceStatus.RELEASED:
            return False
        matched = False
        for pending in self.pending.values():
            if pending.decision_id != release.decision_id or pending.action_kind != release.action_kind:
                continue
            if release.release_task_id != pending.release_ref:
                continue
            if release.owner_token != pending.release_owner_token:
                continue
            if release.resource_key != pending.release_resource_key:
                continue
            if not all((pending.release_ref, pending.release_owner_token, pending.release_resource_key)):
                continue
            pending.effective_end_epoch = min(pending.effective_end_epoch, max(pending.trigger_epoch, release.attempted_at_epoch))
            pending.termination_reason = "owned_mechanism_released"
            matched = True
        return matched

    def _record_activity(self, event: Mapping[str, Any], normalized: Mapping[str, Any], now: float) -> ActivityEvent | None:
        src_ip = str(normalized.get("src_ip") or "")
        if not src_ip:
            return None
        epoch = _epoch_from_iso(normalized.get("ts"))
        if epoch is None:
            epoch = now
        enforcement = event.get("enforcement")
        trace = str(enforcement.get("trace_id") or "") if isinstance(enforcement, Mapping) else ""
        evidence_ref = f"rust-activity:{trace or _stable_id('event', epoch, src_ip)}"
        record = ActivityEvent(
            epoch=epoch,
            src_ip=src_ip,
            dst_ip=str(normalized.get("dst_ip") or ""),
            target_port=_safe_int(normalized.get("target_port")),
            sid=_safe_int(normalized.get("sid")),
            evidence_ref=evidence_ref,
        )
        self.activity.append(record)
        return record

    def _build_outcome(self, pending: _PendingObservation, observed_epoch: float) -> OutcomeRecord:
        pre_samples = self._samples_between(pending.pre_start_epoch, pending.trigger_epoch, end_inclusive=False)
        post_samples = self._samples_between(pending.trigger_epoch, pending.effective_end_epoch, end_inclusive=True)
        pre_activity = tuple(
            item for item in self._activity_between(pending.src_ip, pending.pre_start_epoch, pending.trigger_epoch, end_inclusive=False)
            if item.evidence_ref != pending.trigger_activity_ref
        )
        post_activity = tuple(
            item for item in self._activity_between(pending.src_ip, pending.trigger_epoch, pending.effective_end_epoch, end_inclusive=True)
            if item.evidence_ref != pending.trigger_activity_ref
        )
        baseline_metrics, baseline_flags = _window_metrics(pre_samples, pre_activity, start_epoch=pending.pre_start_epoch, end_epoch=pending.trigger_epoch)
        post_metrics, post_flags = _window_metrics(post_samples, post_activity, start_epoch=pending.trigger_epoch, end_epoch=pending.effective_end_epoch)

        confounders: list[dict[str, Any]] = [
            {"code": "source_ip_is_not_actor_identity", "detail": "activity correlation is source-IP scoped and does not assert attacker identity"},
            {"code": "provider_execution_timestamp_unavailable", "detail": "boundary uses collector receipt time because provider completion timestamp is not grounded"},
        ]
        if pending.mechanism_status != "observed":
            confounders.append({"code": "mechanism_postcondition_not_observed", "detail": f"mechanism_status={pending.mechanism_status}"})
        if len(pre_samples) < 2:
            confounders.append({"code": "insufficient_pre_samples", "count": len(pre_samples)})
        if len(post_samples) < 2:
            confounders.append({"code": "insufficient_post_samples", "count": len(post_samples)})
        for flag in sorted(set((*baseline_flags, *post_flags))):
            confounders.append({"code": flag})
        if pending.objective.metric not in baseline_metrics or pending.objective.metric not in post_metrics:
            confounders.append({"code": "objective_metric_not_collected", "metric": pending.objective.metric})

        expected_pre = max(1, math.floor((pending.trigger_epoch - pending.pre_start_epoch) / self.sample_interval_seconds))
        expected_post = max(1, math.floor((pending.effective_end_epoch - pending.trigger_epoch) / self.sample_interval_seconds))
        all_samples = (*pre_samples, *post_samples)
        coverage = {
            "collector": "outcome_g3_procfs_activity_v1",
            "policy_ref": self.policy.policy_ref,
            "interface": self.interface,
            "sample_interval_seconds": self.sample_interval_seconds,
            "pre_sample_count": len(pre_samples),
            "post_sample_count": len(post_samples),
            "expected_pre_samples": expected_pre,
            "expected_post_samples": expected_post,
            "pre_sample_ratio": min(1.0, len(pre_samples) / expected_pre),
            "post_sample_ratio": min(1.0, len(post_samples) / expected_post),
            "pre_activity_count": len(pre_activity),
            "post_activity_count": len(post_activity),
            "window_truncated_by_release": pending.effective_end_epoch < pending.planned_end_epoch,
            "sources": {
                "proc_net_dev_sample_ratio": _coverage_ratio(all_samples, "proc_net_dev"),
                "proc_loadavg_sample_ratio": _coverage_ratio(all_samples, "proc_loadavg"),
                "proc_meminfo_sample_ratio": _coverage_ratio(all_samples, "proc_meminfo"),
                "rust_event_jsonl": bool(pre_activity or post_activity or pending.trigger_activity_ref),
            },
        }
        first_followup_ms = max(0.0, (post_activity[0].epoch - pending.trigger_epoch) * 1000.0) if post_activity else None
        adversary_response = {
            "correlation_scope": "source_ip",
            "src_ip": pending.src_ip,
            "pre_event_count": len(pre_activity),
            "post_event_count": len(post_activity),
            "first_followup_event_ms": first_followup_ms,
        }
        resource_impact = {
            "pre_load1_mean": baseline_metrics.get("system_load1_mean"),
            "post_load1_mean": post_metrics.get("system_load1_mean"),
            "pre_memory_available_kib_min": baseline_metrics.get("memory_available_kib_min"),
            "post_memory_available_kib_min": post_metrics.get("memory_available_kib_min"),
        }
        evidence_refs = tuple(dict.fromkeys((
            *pending.execution_evidence_refs,
            self.policy.policy_ref,
            *(sample.evidence_ref for sample in pre_samples),
            *(sample.evidence_ref for sample in post_samples),
            *(item.evidence_ref for item in pre_activity),
            *(item.evidence_ref for item in post_activity),
        )))
        return OutcomeRecord(
            incident_id=pending.incident_id,
            decision_id=pending.decision_id,
            execution_id=pending.execution_id,
            mechanism_id=pending.mechanism_id,
            objective_id=pending.objective.objective_id,
            observation_window={
                "baseline_start_epoch": pending.pre_start_epoch,
                "action_observed_epoch": pending.trigger_epoch,
                "planned_end_epoch": pending.planned_end_epoch,
                "effective_end_epoch": pending.effective_end_epoch,
            },
            baseline_metrics=baseline_metrics,
            post_metrics=post_metrics,
            adversary_response=adversary_response,
            asset_impact={},
            noc_impact={},
            resource_impact=resource_impact,
            operator_override={},
            termination_reason=pending.termination_reason,
            assessment=OutcomeAssessment.INCONCLUSIVE,
            causal_support=CausalSupport.INCONCLUSIVE,
            telemetry_coverage=coverage,
            confounders=tuple(confounders),
            evidence_refs=evidence_refs,
            observed_at=_iso(observed_epoch),
            producer="azazel_edge.outcome.telemetry_g3",
            outcome_id=_stable_id("outcome", pending.execution_id, pending.objective.objective_id, f"{pending.effective_end_epoch:.6f}"),
        )

    def _samples_between(self, start: float, end: float, *, end_inclusive: bool) -> tuple[TelemetrySample, ...]:
        return tuple(sample for sample in self.samples if sample.epoch >= start and (sample.epoch <= end if end_inclusive else sample.epoch < end))

    def _activity_between(self, src_ip: str, start: float, end: float, *, end_inclusive: bool) -> tuple[ActivityEvent, ...]:
        seen: set[str] = set()
        result: list[ActivityEvent] = []
        for item in self.activity:
            if item.src_ip != src_ip or item.epoch < start or not (item.epoch <= end if end_inclusive else item.epoch < end):
                continue
            if item.evidence_ref in seen:
                continue
            seen.add(item.evidence_ref)
            result.append(item)
        return tuple(result)

    def _prune(self, now: float) -> None:
        cutoff = max(0.0, now - self.buffer_seconds)
        while self.samples and self.samples[0].epoch < cutoff:
            self.samples.popleft()
        while self.activity and self.activity[0].epoch < cutoff:
            self.activity.popleft()


def _window_seconds(window: Mapping[str, Any]) -> tuple[float, float]:
    try:
        pre, post = float(window.get("pre_seconds")), float(window.get("post_seconds"))
    except (TypeError, ValueError) as exc:
        raise ValueError("observation_window requires numeric pre_seconds/post_seconds") from exc
    if not all(math.isfinite(value) and value > 0.0 for value in (pre, post)):
        raise ValueError("observation_window pre_seconds/post_seconds must be finite and positive")
    if pre > DEFAULT_BUFFER_SECONDS or post > DEFAULT_BUFFER_SECONDS:
        raise ValueError("observation window exceeds G3 v1 safety bound")
    return pre, post


def _window_metrics(samples: Sequence[TelemetrySample], activity: Sequence[ActivityEvent], *, start_epoch: float, end_epoch: float) -> tuple[dict[str, Any], tuple[str, ...]]:
    duration = max(0.001, end_epoch - start_epoch)
    metrics: dict[str, Any] = {
        "window_seconds": duration,
        "telemetry_sample_count": len(samples),
        "source_ip_event_count": len(activity),
        "source_ip_event_rate_hz": len(activity) / duration,
    }
    flags: list[str] = []
    event_epochs = sorted(item.epoch for item in activity)
    if len(event_epochs) >= 2:
        metrics["source_ip_interarrival_ms_median"] = statistics.median(
            max(0.0, (right - left) * 1000.0) for left, right in zip(event_epochs, event_epochs[1:])
        )
    if samples:
        load_values = [float(sample.system["load1"]) for sample in samples if isinstance(sample.system.get("load1"), (int, float))]
        memory_values = [float(sample.system["memory_available_kib"]) for sample in samples if isinstance(sample.system.get("memory_available_kib"), (int, float))]
        if load_values:
            metrics["system_load1_mean"] = statistics.fmean(load_values)
        if memory_values:
            metrics["memory_available_kib_min"] = min(memory_values)
    if len(samples) >= 2:
        first, last = samples[0], samples[-1]
        for key in _COUNTER_KEYS:
            left, right = first.network.get(key), last.network.get(key)
            if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
                continue
            delta = float(right) - float(left)
            if delta < 0:
                flags.append(f"counter_reset:{key}")
            else:
                metrics[f"interface_{key}_delta"] = delta
    return metrics, tuple(flags)


def _coverage_ratio(samples: Sequence[TelemetrySample], key: str) -> float:
    return 0.0 if not samples else sum(1 for sample in samples if sample.coverage.get(key) is True) / len(samples)


def _parse_proc_net_dev(raw: str, interface: str) -> dict[str, int]:
    for line in raw.splitlines():
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        if name.strip() != interface:
            continue
        fields = values.split()
        if len(fields) < 16:
            return {}
        try:
            n = [int(value) for value in fields[:16]]
        except ValueError:
            return {}
        return {"rx_bytes": n[0], "rx_packets": n[1], "rx_errors": n[2], "rx_dropped": n[3], "tx_bytes": n[8], "tx_packets": n[9], "tx_errors": n[10], "tx_dropped": n[11]}
    return {}


def _parse_loadavg(raw: str) -> dict[str, float]:
    fields = raw.split()
    if len(fields) < 3:
        return {}
    try:
        return {"load1": float(fields[0]), "load5": float(fields[1]), "load15": float(fields[2])}
    except ValueError:
        return {}


def _parse_meminfo(raw: str) -> dict[str, int]:
    wanted = {"MemTotal": "memory_total_kib", "MemAvailable": "memory_available_kib", "SwapTotal": "swap_total_kib", "SwapFree": "swap_free_kib"}
    values: dict[str, int] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        target = wanted.get(name)
        if not target:
            continue
        try:
            values[target] = int(value.strip().split()[0])
        except (ValueError, IndexError):
            continue
    return values


def _parse_uptime(raw: str) -> dict[str, float]:
    try:
        value = float(raw.strip().split()[0])
    except (ValueError, IndexError):
        return {}
    return {"uptime_seconds": value} if math.isfinite(value) and value >= 0.0 else {}


def _valid_interface(value: str) -> bool:
    return bool(value) and len(value) <= 15 and all(ch.isalnum() or ch in "_.:-" for ch in value)


def _safe_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _decode_event(line: str) -> Mapping[str, Any] | None:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, Mapping) else None


def run_live(
    *,
    input_path: Path,
    output_path: Path,
    policy_path: Path,
    interface: str,
    poll_seconds: float = 0.25,
    sample_interval_seconds: float = DEFAULT_SAMPLE_INTERVAL_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> None:
    """Foreground live-only collector. Historical procfs reconstruction is forbidden."""
    collector = OutcomeTelemetryCollector(
        source=LinuxProcTelemetrySource(),
        policy=OutcomeTelemetryPolicy.from_file(policy_path),
        interface=interface,
        sample_interval_seconds=sample_interval_seconds,
    )
    next_sample = time.monotonic()
    with input_path.open("r", encoding="utf-8") as stream:
        stream.seek(0, 2)
        while True:
            now_monotonic = time.monotonic()
            if now_monotonic >= next_sample:
                collector.record_sample(epoch=time.time())
                next_sample = now_monotonic + sample_interval_seconds
            saw_record = False
            while True:
                position = stream.tell()
                line = stream.readline()
                if not line:
                    stream.seek(position)
                    break
                saw_record = True
                event = _decode_event(line)
                if event is not None:
                    collector.observe_event(event, observed_epoch=time.time())
            outcomes = collector.finalize_due(epoch=time.time())
            if outcomes:
                append_jsonl(
                    output_path,
                    ({"schema_version": record.schema_version, "outcome": record.to_dict(), "collector_mode": "passive_g3", "effect_assessment": None} for record in outcomes),
                    max_bytes=max_output_bytes,
                )
            if not saw_record:
                time.sleep(max(0.05, poll_seconds))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Passive Azazel Outcome-as-Evidence G3 telemetry collector")
    parser.add_argument("--input", default=os.environ.get("AZAZEL_OUTCOME_INPUT", DEFAULT_INPUT))
    parser.add_argument("--output", default=os.environ.get("AZAZEL_OUTCOME_TELEMETRY_OUTPUT", DEFAULT_OUTPUT))
    parser.add_argument("--policy", required=True, help="Explicit operator-owned G3 objective policy JSON")
    parser.add_argument("--interface", default=os.environ.get("AZAZEL_DEFENSE_IFACE", "br0"))
    parser.add_argument("--poll-seconds", type=float, default=0.25)
    parser.add_argument("--sample-interval-seconds", type=float, default=DEFAULT_SAMPLE_INTERVAL_SECONDS)
    parser.add_argument("--max-output-bytes", type=int, default=int(os.environ.get("AZAZEL_OUTCOME_MAX_BYTES", str(DEFAULT_MAX_OUTPUT_BYTES))))
    args = parser.parse_args(argv)
    run_live(
        input_path=Path(args.input),
        output_path=Path(args.output),
        policy_path=Path(args.policy),
        interface=args.interface,
        poll_seconds=args.poll_seconds,
        sample_interval_seconds=args.sample_interval_seconds,
        max_output_bytes=args.max_output_bytes,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
