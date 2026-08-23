from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .broker import CapabilityBroker, CapabilityBrokerError
from .contracts import (
    MioCapabilityRequest,
    MioEvidenceGap,
    MioHypothesis,
    MioRecommendation,
    MioSituationFrame,
    ReasoningState,
)
from .grounding import GroundingValidator
from .model_adapter import MioModelBlocked, MioModelUnavailable
from .playbook import PromptCompiler, ReasoningPlaybook
from .trace import ReasoningTrace

ModelInvoker = Callable[[str, str], Mapping[str, Any]]
CancelCheck = Callable[[], bool]


@dataclass(frozen=True)
class ReasoningBudget:
    max_model_calls: int = 4
    max_broker_calls: int = 3
    max_hypotheses: int = 4
    max_gaps: int = 3
    max_frame_age_seconds: int = 300


@dataclass(frozen=True)
class ReasoningOutcome:
    state: ReasoningState
    hypotheses: tuple[MioHypothesis, ...]
    evidence_gaps: tuple[MioEvidenceGap, ...]
    recommendation: MioRecommendation | None
    errors: tuple[str, ...]
    trace: tuple[Any, ...]


class BoundedReasoningLoop:
    """Shadow/replay cognitive loop. It never invokes Edge enforcement."""

    def __init__(
        self,
        *,
        model: ModelInvoker,
        broker: CapabilityBroker,
        compiler: PromptCompiler | None = None,
        budget: ReasoningBudget | None = None,
    ):
        self.model = model
        self.broker = broker
        self.compiler = compiler or PromptCompiler()
        self.budget = budget or ReasoningBudget()

    @staticmethod
    def _is_cancelled(cancel_check: CancelCheck | None) -> bool:
        if cancel_check is None:
            return False
        try:
            return bool(cancel_check())
        except Exception:
            return True

    def run(
        self,
        *,
        frame: MioSituationFrame,
        playbook: ReasoningPlaybook,
        cycle_id: str,
        cancel_check: CancelCheck | None = None,
    ) -> ReasoningOutcome:
        trace = ReasoningTrace(trace_id=frame.trace_id, cycle_id=cycle_id)
        errors: list[str] = []
        model_calls = 0
        broker_calls = 0
        trace.record(state=ReasoningState.FRAME_READY.value, kind="frame", payload={"frame_id": frame.frame_id})

        if frame.freshness_seconds > max(0, int(self.budget.max_frame_age_seconds)):
            errors.append('frame_stale')
            return self._finish(trace, ReasoningState.STALE_SUPERSEDED, (), (), None, errors)
        if self._is_cancelled(cancel_check):
            errors.append('operator_cancelled')
            return self._finish(trace, ReasoningState.OPERATOR_CANCELLED, (), (), None, errors)

        try:
            prompt = self.compiler.compile(frame=frame, playbook=playbook, task="generate_hypotheses")
            raw_h = self.model("generate_hypotheses", prompt)
            model_calls += 1
        except (MioModelBlocked, MioModelUnavailable) as exc:
            errors.append(f"model_dependency_unavailable:{str(exc)[:120]}")
            return self._finish(trace, ReasoningState.DEPENDENCY_UNAVAILABLE, (), (), None, errors)
        except Exception as exc:
            errors.append(f"model_hypothesis_error:{str(exc)[:120]}")
            return self._finish(trace, ReasoningState.ERROR_FALLBACK, (), (), None, errors)

        if self._is_cancelled(cancel_check):
            errors.append('operator_cancelled')
            return self._finish(trace, ReasoningState.OPERATOR_CANCELLED, (), (), None, errors)

        items = raw_h.get("hypotheses", []) if isinstance(raw_h, Mapping) else []
        if not isinstance(items, list):
            errors.append("hypotheses_not_list")
            return self._finish(trace, ReasoningState.VALIDATION_REJECTED, (), (), None, errors)
        hypotheses = tuple(
            MioHypothesis.from_mapping(item, ordinal=i + 1)
            for i, item in enumerate(items[: self.budget.max_hypotheses])
            if isinstance(item, Mapping)
        )
        h_check = GroundingValidator(frame).validate_hypotheses(hypotheses)
        if not h_check.ok:
            errors.extend(h_check.errors)
            return self._finish(trace, ReasoningState.VALIDATION_REJECTED, hypotheses, (), None, errors)
        trace.record(state=ReasoningState.HYPOTHESES_READY.value, kind="hypotheses", payload={"ids": [h.hypothesis_id for h in hypotheses]})

        if model_calls >= self.budget.max_model_calls:
            errors.append("model_budget_exhausted_before_gap_planning")
            return self._finish(trace, ReasoningState.BUDGET_EXHAUSTED, hypotheses, (), None, errors)
        prompt = self.compiler.compile(frame=frame, playbook=playbook, hypotheses=hypotheses, task="identify_evidence_gaps")
        try:
            raw_g = self.model("identify_evidence_gaps", prompt)
            model_calls += 1
        except (MioModelBlocked, MioModelUnavailable) as exc:
            errors.append(f"model_dependency_unavailable:{str(exc)[:120]}")
            return self._finish(trace, ReasoningState.DEPENDENCY_UNAVAILABLE, hypotheses, (), None, errors)
        except Exception as exc:
            errors.append(f"model_gap_error:{str(exc)[:120]}")
            return self._finish(trace, ReasoningState.ERROR_FALLBACK, hypotheses, (), None, errors)
        gap_items = raw_g.get("evidence_gaps", []) if isinstance(raw_g, Mapping) else []
        if not isinstance(gap_items, list):
            gap_items = []
        gaps = tuple(
            MioEvidenceGap.from_mapping(item, ordinal=i + 1)
            for i, item in enumerate(gap_items[: self.budget.max_gaps])
            if isinstance(item, Mapping)
        )
        gap_check = GroundingValidator(frame).validate_evidence_gaps(
            gaps,
            hypotheses=hypotheses,
            allowed_capabilities=playbook.allowed_capabilities,
        )
        if not gap_check.ok:
            errors.extend(gap_check.errors)
            return self._finish(trace, ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None, errors)
        trace.record(state=ReasoningState.EVIDENCE_GAPS_IDENTIFIED.value, kind="evidence_gaps", payload={"ids": [g.gap_id for g in gaps]})

        additional_refs: list[str] = []
        broker_summaries: list[dict[str, Any]] = []
        for index, gap in enumerate(sorted(gaps, key=lambda g: g.priority, reverse=True)):
            if self._is_cancelled(cancel_check):
                errors.append('operator_cancelled')
                return self._finish(trace, ReasoningState.OPERATOR_CANCELLED, hypotheses, gaps, None, errors)
            if broker_calls >= self.budget.max_broker_calls:
                errors.append("broker_budget_exhausted")
                break
            if gap.capability not in playbook.allowed_capabilities:
                errors.append(f"capability_not_allowed_by_playbook:{gap.capability}")
                continue
            request = MioCapabilityRequest(
                request_id=f"{cycle_id}:req:{index + 1}",
                trace_id=frame.trace_id,
                capability=gap.capability,
                arguments={"question": gap.question, "frame_id": frame.frame_id},
            )
            trace.record(
                state=ReasoningState.REQUEST_PLANNED.value,
                kind="capability_request",
                payload={"request_id": request.request_id, "capability": request.capability},
            )
            try:
                result = self.broker.execute(request)
                broker_calls += 1
            except CapabilityBrokerError as exc:
                errors.append(str(exc))
                continue
            additional_refs.extend(result.evidence_refs)
            broker_summaries.append(
                {
                    "request_id": result.request_id,
                    "capability": result.capability,
                    "ok": result.ok,
                    "data": dict(result.data),
                    "evidence_refs": list(result.evidence_refs),
                    "error": result.error,
                }
            )
            trace.record(
                state=ReasoningState.EVIDENCE_COLLECTED.value,
                kind="capability_result",
                payload={"request_id": result.request_id, "ok": result.ok, "evidence_refs": list(result.evidence_refs)},
            )

        # New evidence must be allowed to strengthen, weaken, falsify, or leave
        # hypotheses unresolved before a recommendation is produced. This step
        # is skipped when no capability returned a result, avoiding a pointless
        # model call on constrained hardware.
        if broker_summaries:
            if model_calls >= self.budget.max_model_calls:
                errors.append("model_budget_exhausted_before_hypothesis_update")
                return self._finish(trace, ReasoningState.BUDGET_EXHAUSTED, hypotheses, gaps, None, errors)
            if self._is_cancelled(cancel_check):
                errors.append('operator_cancelled')
                return self._finish(trace, ReasoningState.OPERATOR_CANCELLED, hypotheses, gaps, None, errors)
            prompt = self.compiler.compile(
                frame=frame,
                playbook=playbook,
                hypotheses=hypotheses,
                broker_results=broker_summaries,
                task="update_hypotheses",
            )
            try:
                raw_u = self.model("update_hypotheses", prompt)
                model_calls += 1
            except (MioModelBlocked, MioModelUnavailable) as exc:
                errors.append(f"model_dependency_unavailable:{str(exc)[:120]}")
                return self._finish(trace, ReasoningState.DEPENDENCY_UNAVAILABLE, hypotheses, gaps, None, errors)
            except Exception as exc:
                errors.append(f"model_hypothesis_update_error:{str(exc)[:120]}")
                return self._finish(trace, ReasoningState.ERROR_FALLBACK, hypotheses, gaps, None, errors)
            if not isinstance(raw_u, Mapping):
                errors.append("hypothesis_update_not_mapping")
                return self._finish(trace, ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None, errors)
            raw_update_check = GroundingValidator(frame, additional_evidence_refs=additional_refs).validate_raw(raw_u)
            if not raw_update_check.ok:
                errors.extend(raw_update_check.errors)
                return self._finish(trace, ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None, errors)
            update_items = raw_u.get("hypotheses", [])
            if not isinstance(update_items, list):
                errors.append("updated_hypotheses_not_list")
                return self._finish(trace, ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None, errors)
            updated_hypotheses = tuple(
                MioHypothesis.from_mapping(item, ordinal=i + 1)
                for i, item in enumerate(update_items[: self.budget.max_hypotheses])
                if isinstance(item, Mapping)
            )
            updated_check = GroundingValidator(frame, additional_evidence_refs=additional_refs).validate_hypotheses(updated_hypotheses)
            if not updated_check.ok:
                errors.extend(updated_check.errors)
                return self._finish(trace, ReasoningState.VALIDATION_REJECTED, updated_hypotheses, gaps, None, errors)
            hypotheses = updated_hypotheses
            trace.record(
                state=ReasoningState.HYPOTHESES_UPDATED.value,
                kind="hypotheses_updated",
                payload={"ids": [h.hypothesis_id for h in hypotheses], "evidence_refs": list(dict.fromkeys(additional_refs))[:32]},
            )

        if model_calls >= self.budget.max_model_calls:
            errors.append("model_budget_exhausted_before_recommendation")
            return self._finish(trace, ReasoningState.BUDGET_EXHAUSTED, hypotheses, gaps, None, errors)
        if self._is_cancelled(cancel_check):
            errors.append('operator_cancelled')
            return self._finish(trace, ReasoningState.OPERATOR_CANCELLED, hypotheses, gaps, None, errors)

        prompt = self.compiler.compile(
            frame=frame,
            playbook=playbook,
            hypotheses=hypotheses,
            broker_results=broker_summaries,
            task="recommend",
        )
        try:
            raw_r = self.model("recommend", prompt)
            model_calls += 1
        except (MioModelBlocked, MioModelUnavailable) as exc:
            errors.append(f"model_dependency_unavailable:{str(exc)[:120]}")
            return self._finish(trace, ReasoningState.DEPENDENCY_UNAVAILABLE, hypotheses, gaps, None, errors)
        except Exception as exc:
            errors.append(f"model_recommend_error:{str(exc)[:120]}")
            return self._finish(trace, ReasoningState.ERROR_FALLBACK, hypotheses, gaps, None, errors)
        if not isinstance(raw_r, Mapping):
            errors.append("recommendation_not_mapping")
            return self._finish(trace, ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None, errors)
        raw_check = GroundingValidator(frame, additional_evidence_refs=additional_refs).validate_raw(raw_r)
        if not raw_check.ok:
            errors.extend(raw_check.errors)
            return self._finish(trace, ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, None, errors)
        recommendation = MioRecommendation.from_mapping(raw_r, advisory_id=f"{cycle_id}:advisory")
        rec_check = GroundingValidator(frame, additional_evidence_refs=additional_refs).validate_recommendation(recommendation)
        if not rec_check.ok:
            errors.extend(rec_check.errors)
            return self._finish(trace, ReasoningState.VALIDATION_REJECTED, hypotheses, gaps, recommendation, errors)
        trace.record(
            state=ReasoningState.RECOMMENDATION_READY.value,
            kind="recommendation",
            payload={
                "advisory_id": recommendation.advisory_id,
                "recommended_action": recommendation.recommended_action,
                "evidence_refs": list(recommendation.evidence_refs),
                "executable": False,
            },
        )
        trace.record(
            state=ReasoningState.COMPLETE.value,
            kind="complete",
            payload={"model_calls": model_calls, "broker_calls": broker_calls},
        )
        return ReasoningOutcome(ReasoningState.COMPLETE, hypotheses, gaps, recommendation, tuple(errors), trace.events())

    @staticmethod
    def _finish(
        trace: ReasoningTrace,
        state: ReasoningState,
        hypotheses: Sequence[MioHypothesis],
        gaps: Sequence[MioEvidenceGap],
        recommendation: MioRecommendation | None,
        errors: Sequence[str],
    ) -> ReasoningOutcome:
        trace.record(state=state.value, kind="terminal", payload={"errors": list(errors)[:8]})
        return ReasoningOutcome(state, tuple(hypotheses), tuple(gaps), recommendation, tuple(errors), trace.events())
