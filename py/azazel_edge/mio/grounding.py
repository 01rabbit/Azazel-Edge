from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import MioEvidenceGap, MioHypothesis, MioRecommendation, MioSituationFrame


FORBIDDEN_DIRECTIVE_KEYS = {"execute", "must_action", "override", "command", "shell", "activate", "enforce", "executable"}
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

        def walk(value: Any, path: str = "") -> None:
            if isinstance(value, Mapping):
                for key, nested in value.items():
                    key_text = str(key)
                    child_path = f"{path}.{key_text}" if path else key_text
                    if key_text.lower() in FORBIDDEN_DIRECTIVE_KEYS:
                        errors.append(f"forbidden_directive_key:{child_path}")
                    walk(nested, child_path)
            elif isinstance(value, (list, tuple)):
                for index, nested in enumerate(value):
                    walk(nested, f"{path}[{index}]")

        walk(payload)
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
        seen_ids: set[str] = set()
        for hypothesis in hypotheses:
            if not hypothesis.hypothesis_id:
                errors.append("empty_hypothesis_id")
            elif hypothesis.hypothesis_id in seen_ids:
                errors.append(f"duplicate_hypothesis_id:{hypothesis.hypothesis_id}")
            else:
                seen_ids.add(hypothesis.hypothesis_id)
            if not hypothesis.statement:
                errors.append(f"empty_statement:{hypothesis.hypothesis_id}")
            refs = set(hypothesis.supporting_evidence_refs) | set(hypothesis.contradicting_evidence_refs)
            for ref in refs:
                if ref not in self._allowed_refs:
                    errors.append(f"unknown_hypothesis_ref:{hypothesis.hypothesis_id}:{ref}")
        return GroundingResult(not errors, tuple(errors))

    def validate_evidence_gaps(
        self,
        gaps: Sequence[MioEvidenceGap],
        *,
        hypotheses: Sequence[MioHypothesis],
        allowed_capabilities: Sequence[str],
    ) -> GroundingResult:
        errors: list[str] = []
        hypothesis_ids = {item.hypothesis_id for item in hypotheses}
        allowed = {str(item) for item in allowed_capabilities}
        seen_gap_ids: set[str] = set()
        for gap in gaps:
            if not gap.gap_id:
                errors.append("empty_gap_id")
            elif gap.gap_id in seen_gap_ids:
                errors.append(f"duplicate_gap_id:{gap.gap_id}")
            else:
                seen_gap_ids.add(gap.gap_id)
            if not gap.question:
                errors.append(f"empty_gap_question:{gap.gap_id}")
            if not gap.capability:
                errors.append(f"empty_gap_capability:{gap.gap_id}")
            elif gap.capability not in allowed:
                errors.append(f"capability_not_allowed_by_playbook:{gap.capability}")
            for hypothesis_id in gap.discriminates_hypothesis_ids:
                if hypothesis_id not in hypothesis_ids:
                    errors.append(f"unknown_gap_hypothesis:{gap.gap_id}:{hypothesis_id}")
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
