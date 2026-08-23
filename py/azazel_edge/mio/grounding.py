from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import MioHypothesis, MioRecommendation, MioSituationFrame


FORBIDDEN_DIRECTIVE_KEYS = {"execute", "must_action", "override", "command", "shell", "activate", "enforce"}
ALLOWED_RECOMMENDED_ACTIONS = {"", "OBSERVE", "NOTIFY", "THROTTLE", "REDIRECT", "ISOLATE"}


@dataclass(frozen=True)
class GroundingResult:
    ok: bool
    errors: tuple[str, ...]


class GroundingValidator:
    def __init__(self, frame: MioSituationFrame, *, additional_evidence_refs: Sequence[str] = ()):
        self._allowed_refs = set(frame.evidence_refs) | set(frame.knowledge_refs) | {str(x) for x in additional_evidence_refs}

    def validate_raw(self, payload: Mapping[str, Any]) -> GroundingResult:
        errors: list[str] = []
        for key in payload:
            if str(key).lower() in FORBIDDEN_DIRECTIVE_KEYS:
                errors.append(f"forbidden_directive_key:{key}")
        refs = payload.get("evidence_refs", ())
        if isinstance(refs, (list, tuple)):
            for ref in refs:
                if str(ref) not in self._allowed_refs:
                    errors.append(f"unknown_evidence_ref:{str(ref)[:96]}")
        return GroundingResult(not errors, tuple(errors))

    def validate_hypotheses(self, hypotheses: Sequence[MioHypothesis]) -> GroundingResult:
        errors: list[str] = []
        if not hypotheses:
            errors.append("no_hypotheses")
        if len(hypotheses) > 6:
            errors.append("too_many_hypotheses")
        for hypothesis in hypotheses:
            if not hypothesis.statement:
                errors.append(f"empty_statement:{hypothesis.hypothesis_id}")
            refs = set(hypothesis.supporting_evidence_refs) | set(hypothesis.contradicting_evidence_refs)
            for ref in refs:
                if ref not in self._allowed_refs:
                    errors.append(f"unknown_hypothesis_ref:{hypothesis.hypothesis_id}:{ref}")
        return GroundingResult(not errors, tuple(errors))

    def validate_recommendation(self, recommendation: MioRecommendation) -> GroundingResult:
        errors: list[str] = []
        if recommendation.executable:
            errors.append("recommendation_must_not_be_executable")
        if recommendation.recommended_action not in ALLOWED_RECOMMENDED_ACTIONS:
            errors.append("unknown_recommended_action")
        for ref in recommendation.evidence_refs:
            if ref not in self._allowed_refs:
                errors.append(f"unknown_recommendation_ref:{ref}")
        return GroundingResult(not errors, tuple(errors))
