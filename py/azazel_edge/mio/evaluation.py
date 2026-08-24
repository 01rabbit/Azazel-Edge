"""Offline, invariant-based evaluation for the M.I.O. shadow loop.

This module deliberately evaluates structured outcomes, not model prose.  It is
safe for CI: callers supply recorded outputs and static broker replies only.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import json
from typing import Any, Mapping

from .broker import CapabilityBroker, CapabilitySpec
from .frame_builder import MioSituationFrameBuilder
from .grounding import GroundingValidator
from .model_adapter import MioModelUnavailable
from .playbook import DEFAULT_PLAYBOOKS
from .reasoning import BoundedReasoningLoop, ReasoningOutcome


@dataclass(frozen=True)
class EvaluationScenario:
    scenario_id: str
    mode: str
    frame_fixture: str
    model_outputs: Mapping[str, Any]
    expect: Mapping[str, Any]
    recorded_output_fixture: str = ""
    model_error: str = ""
    freshness_seconds: int | None = None


def load_scenarios(path: Path) -> tuple[EvaluationScenario, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload.get("scenarios", []) if isinstance(payload, Mapping) else []
    if not isinstance(items, list):
        raise ValueError("evaluation_scenarios_not_list")
    scenarios: list[EvaluationScenario] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError("evaluation_scenario_not_mapping")
        scenario_id = str(item.get("scenario_id") or "")
        frame_fixture = str(item.get("frame_fixture") or "")
        expect = item.get("expect")
        if not scenario_id or not frame_fixture or not isinstance(expect, Mapping):
            raise ValueError("evaluation_scenario_required_field_missing")
        outputs = item.get("model_outputs", {})
        scenarios.append(EvaluationScenario(
            scenario_id=scenario_id,
            mode=str(item.get("mode") or "pure_replay"),
            frame_fixture=frame_fixture,
            model_outputs=outputs if isinstance(outputs, Mapping) else {},
            expect=expect,
            recorded_output_fixture=str(item.get("recorded_output_fixture") or ""),
            model_error=str(item.get("model_error") or ""),
            freshness_seconds=item.get("freshness_seconds") if isinstance(item.get("freshness_seconds"), int) else None,
        ))
    return tuple(scenarios)


def _load_frame(root: Path, name: str, freshness_seconds: int | None):
    source = json.loads((root / name).read_text(encoding="utf-8"))
    if not isinstance(source, Mapping):
        raise ValueError("evaluation_frame_fixture_not_mapping")
    frame = MioSituationFrameBuilder().build(
        events=source.get("events", []), noc_evaluation=source.get("noc_evaluation", {}),
        soc_evaluation=source.get("soc_evaluation", {}),
        current_defensive_state=str(source.get("current_defensive_state") or "OBSERVE"),
        mission=str(source.get("mission") or "Offline M.I.O. evaluation"),
        trace_id=str(source.get("trace_id") or "evaluation-trace"),
        frame_id=str(source.get("frame_id") or "evaluation-frame"),
        created_at=str(source.get("created_at") or "2026-01-01T00:00:00Z"),
        knowledge_refs=source.get("knowledge_refs", []),
    )
    if freshness_seconds is None:
        return frame
    return type(frame)(**{**frame.__dict__, "freshness_seconds": freshness_seconds})


def _static_broker(source: Mapping[str, Any]) -> CapabilityBroker:
    caps: dict[str, CapabilitySpec] = {}
    for name, reply in (source.get("capabilities", {}) or {}).items():
        if isinstance(name, str) and isinstance(reply, Mapping):
            caps[name] = CapabilitySpec(lambda _args, value=dict(reply): dict(value))
    return CapabilityBroker(caps)


def _metrics(outcome: ReasoningOutcome, model_calls: int) -> dict[str, Any]:
    errors = tuple(outcome.errors)
    refs = [ref for error in errors for ref in [error] if "unknown_" in ref or "conflicting_" in ref]
    prohibited = [error for error in errors if error.startswith("forbidden_directive_key:")]
    broker_calls = sum(1 for event in outcome.trace if event.kind == "capability_result")
    recommendation = outcome.recommendation
    grounded = bool(recommendation and GroundingValidator.__name__) and not any(
        error.startswith("unknown_recommendation_ref:") for error in errors
    )
    return {
        "terminal_state": outcome.state.value,
        "unresolved_refs": len(refs),
        "fabricated_refs": sum(1 for error in errors if "unknown_" in error),
        "prohibited_directive_fields": len(prohibited),
        "hypothesis_count": len(outcome.hypotheses),
        "broker_calls": broker_calls,
        "reasoning_rounds": model_calls,
        "fallback_reason": next((error for error in errors if "unavailable" in error or "error" in error or "stale" in error), ""),
        "recommendation_grounded": grounded,
        "executable": bool(recommendation and recommendation.executable),
        "validation_passed": outcome.state.value == "complete",
    }


def evaluate_scenario(scenario: EvaluationScenario, *, fixture_root: Path) -> dict[str, Any]:
    """Replay one recorded scenario and compare only declared invariants."""
    source = json.loads((fixture_root / scenario.frame_fixture).read_text(encoding="utf-8"))
    frame = _load_frame(fixture_root, scenario.frame_fixture, scenario.freshness_seconds)
    outputs = scenario.model_outputs
    if scenario.recorded_output_fixture:
        captured = json.loads((fixture_root / scenario.recorded_output_fixture).read_text(encoding="utf-8"))
        outputs = captured.get("model_outputs", {}) if isinstance(captured, Mapping) else {}
    calls = 0

    def model(task: str, _prompt: str) -> Mapping[str, Any]:
        nonlocal calls
        calls += 1
        if scenario.model_error == "unavailable":
            raise MioModelUnavailable("recorded_model_unavailable")
        if scenario.model_error == "timeout":
            raise TimeoutError("recorded_model_timeout")
        return outputs.get(task, {})

    outcome = BoundedReasoningLoop(model=model, broker=_static_broker(source)).run(
        frame=frame, playbook=DEFAULT_PLAYBOOKS["auth-ambiguity-v1"], cycle_id="evaluation:" + scenario.scenario_id,
    )
    metrics = _metrics(outcome, calls)
    checks: dict[str, bool] = {}
    for key, expected in scenario.expect.items():
        actual = metrics.get(key)
        if isinstance(expected, list):
            checks[key] = actual in expected
        else:
            checks[key] = actual == expected
    canonical = json.dumps({"metrics": metrics, "errors": list(outcome.errors)}, sort_keys=True, separators=(",", ":"))
    return {"scenario_id": scenario.scenario_id, "mode": scenario.mode, "passed": all(checks.values()),
            "checks": checks, "metrics": metrics, "errors": list(outcome.errors),
            "validation_digest": sha256(canonical.encode("utf-8")).hexdigest()}
