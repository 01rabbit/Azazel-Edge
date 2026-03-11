from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

VALID_ANSWER_TYPES = {"single_choice", "boolean", "text"}
VALID_SEVERITIES = {"low", "medium", "high"}


def _normalize_transition_key(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value).strip()
    lowered = text.lower()
    if lowered in {"true", "yes", "はい"}:
        return "yes"
    if lowered in {"false", "no", "いいえ"}:
        return "no"
    return text


def _normalize_choice_label(value: Any) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


@dataclass(slots=True)
class IntentCandidate:
    intent_id: str
    label: str
    confidence: float
    source: str = "rule_first"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "label": self.label,
            "confidence": float(self.confidence),
            "source": self.source,
        }


@dataclass(slots=True)
class DiagnosticState:
    state_id: str
    severity: str = "low"
    summary_key: str = ""
    user_guidance_key: str = ""
    operator_note_key: str = ""

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "DiagnosticState":
        state_id = str(payload.get("state_id", "")).strip()
        if not state_id:
            raise ValueError("diagnostic_state_id_required")
        severity = str(payload.get("severity", "low")).strip() or "low"
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid_diagnostic_severity:{severity}")
        return cls(
            state_id=state_id,
            severity=severity,
            summary_key=str(payload.get("summary_key", "")).strip(),
            user_guidance_key=str(payload.get("user_guidance_key", "")).strip(),
            operator_note_key=str(payload.get("operator_note_key", "")).strip(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_id": self.state_id,
            "severity": self.severity,
            "summary_key": self.summary_key,
            "user_guidance_key": self.user_guidance_key,
            "operator_note_key": self.operator_note_key,
        }


@dataclass(slots=True)
class TriageStep:
    step_id: str
    question_i18n: Dict[str, str]
    answer_type: str
    choices: List[Dict[str, Any]] = field(default_factory=list)
    transition_map: Dict[str, str] = field(default_factory=dict)
    fallback_transition: str = ""

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "TriageStep":
        step_id = str(payload.get("step_id", "")).strip()
        if not step_id:
            raise ValueError("step_id_required")
        question_i18n = dict(payload.get("question_i18n") or {})
        if not question_i18n or not all(str(v).strip() for v in question_i18n.values()):
            raise ValueError(f"question_i18n_required:{step_id}")
        answer_type = str(payload.get("answer_type", "")).strip()
        if answer_type not in VALID_ANSWER_TYPES:
            raise ValueError(f"invalid_answer_type:{step_id}:{answer_type}")
        raw_choices = list(payload.get("choices") or [])
        choices = []
        for item in raw_choices:
            choice = dict(item or {})
            label_i18n = dict(choice.get("label_i18n") or {})
            if label_i18n:
                choice["label_i18n"] = {str(key): _normalize_choice_label(val) for key, val in label_i18n.items()}
            choices.append(choice)
        if answer_type in {"single_choice", "boolean"} and not choices:
            raise ValueError(f"choices_required:{step_id}")
        transition_map = {
            _normalize_transition_key(key): str(value)
            for key, value in dict(payload.get("transition_map") or {}).items()
            if str(value).strip()
        }
        if not transition_map:
            raise ValueError(f"transition_map_required:{step_id}")
        fallback_transition = str(payload.get("fallback_transition", "")).strip()
        if not fallback_transition:
            raise ValueError(f"fallback_transition_required:{step_id}")
        return cls(
            step_id=step_id,
            question_i18n=question_i18n,
            answer_type=answer_type,
            choices=choices,
            transition_map=transition_map,
            fallback_transition=fallback_transition,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "question_i18n": dict(self.question_i18n),
            "answer_type": self.answer_type,
            "choices": list(self.choices),
            "transition_map": dict(self.transition_map),
            "fallback_transition": self.fallback_transition,
        }


@dataclass(slots=True)
class TriageFlow:
    flow_id: str
    version: int
    intents: List[str]
    label_i18n: Dict[str, str]
    entry_state: str
    steps: List[TriageStep]
    diagnostic_states: List[DiagnosticState] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "TriageFlow":
        flow_id = str(payload.get("flow_id", "")).strip()
        if not flow_id:
            raise ValueError("flow_id_required")
        version = int(payload.get("version", 1))
        intents = [str(item).strip() for item in list(payload.get("intents") or []) if str(item).strip()]
        if not intents:
            raise ValueError(f"intents_required:{flow_id}")
        label_i18n = dict(payload.get("label_i18n") or {})
        if not label_i18n:
            raise ValueError(f"label_i18n_required:{flow_id}")
        entry_state = str(payload.get("entry_state", "")).strip()
        if not entry_state:
            raise ValueError(f"entry_state_required:{flow_id}")
        steps = [TriageStep.from_dict(item) for item in list(payload.get("steps") or [])]
        if not steps:
            raise ValueError(f"steps_required:{flow_id}")
        diagnostic_states = [DiagnosticState.from_dict(item) for item in list(payload.get("diagnostic_states") or [])]
        return cls(
            flow_id=flow_id,
            version=version,
            intents=intents,
            label_i18n=label_i18n,
            entry_state=entry_state,
            steps=steps,
            diagnostic_states=diagnostic_states,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "version": self.version,
            "intents": list(self.intents),
            "label_i18n": dict(self.label_i18n),
            "entry_state": self.entry_state,
            "steps": [item.to_dict() for item in self.steps],
            "diagnostic_states": [item.to_dict() for item in self.diagnostic_states],
        }


@dataclass(slots=True)
class TriageSession:
    session_id: str
    audience: str
    lang: str
    intent_candidates: List[Dict[str, Any]] = field(default_factory=list)
    selected_intent: str = ""
    current_state: str = ""
    answers: Dict[str, Any] = field(default_factory=dict)
    diagnostic_state: str = ""
    proposed_runbooks: List[str] = field(default_factory=list)
    status: str = "active"
    handoff_reason: str = ""
    created_at: int = 0
    updated_at: int = 0

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "TriageSession":
        session_id = str(payload.get("session_id", "")).strip()
        if not session_id:
            raise ValueError("triage_session_id_required")
        return cls(
            session_id=session_id,
            audience=str(payload.get("audience", "temporary") or "temporary"),
            lang=str(payload.get("lang", "ja") or "ja"),
            intent_candidates=list(payload.get("intent_candidates") or []),
            selected_intent=str(payload.get("selected_intent", "")).strip(),
            current_state=str(payload.get("current_state", "")).strip(),
            answers=dict(payload.get("answers") or {}),
            diagnostic_state=str(payload.get("diagnostic_state", "")).strip(),
            proposed_runbooks=[str(item) for item in list(payload.get("proposed_runbooks") or [])],
            status=str(payload.get("status", "active") or "active"),
            handoff_reason=str(payload.get("handoff_reason", "")).strip(),
            created_at=int(payload.get("created_at", 0) or 0),
            updated_at=int(payload.get("updated_at", 0) or 0),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "audience": self.audience,
            "lang": self.lang,
            "intent_candidates": list(self.intent_candidates),
            "selected_intent": self.selected_intent,
            "current_state": self.current_state,
            "answers": dict(self.answers),
            "diagnostic_state": self.diagnostic_state,
            "proposed_runbooks": list(self.proposed_runbooks),
            "status": self.status,
            "handoff_reason": self.handoff_reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
