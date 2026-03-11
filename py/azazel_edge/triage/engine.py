from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Dict, Optional

from azazel_edge.audit import P0AuditLogger

from .loader import load_flow
from .selector import select_runbooks_for_diagnostic_state
from .session import TriageSessionStore
from .types import DiagnosticState, TriageFlow, TriageSession, TriageStep


@dataclass(slots=True)
class TriageProgress:
    session: TriageSession
    flow: TriageFlow
    next_step: Optional[TriageStep] = None
    diagnostic_state: Optional[DiagnosticState] = None
    completed: bool = False


class TriageFlowEngine:
    def __init__(self, store: TriageSessionStore | None = None, audit_logger: P0AuditLogger | None = None):
        self.store = store or TriageSessionStore()
        self.audit = audit_logger or self._build_default_audit_logger()

    def _build_default_audit_logger(self) -> P0AuditLogger:
        primary = Path(os.environ.get("AZAZEL_TRIAGE_AUDIT_PATH", "/var/log/azazel-edge/triage-audit.jsonl"))
        try:
            primary.parent.mkdir(parents=True, exist_ok=True)
            with primary.open("a", encoding="utf-8"):
                pass
            return P0AuditLogger(primary)
        except OSError:
            fallback = Path("/tmp/azazel-edge-triage-audit.jsonl")
            fallback.parent.mkdir(parents=True, exist_ok=True)
            return P0AuditLogger(fallback)

    def start(self, intent_id: str, audience: str = "temporary", lang: str = "ja") -> TriageProgress:
        flow = load_flow(intent_id)
        session = self.store.create(
            audience=audience,
            lang=lang,
            selected_intent=intent_id,
            current_state=flow.entry_state,
        )
        session.intent_candidates = [{"intent_id": intent_id, "label": flow.label_i18n.get(lang) or flow.label_i18n.get("en") or intent_id, "confidence": 1.0, "source": "selected"}]
        self.store.save(session)
        self.audit.log_triage_session_started(
            trace_id=session.session_id,
            source="triage_engine",
            session_id=session.session_id,
            intent_id=intent_id,
            audience=audience,
            lang=lang,
            initial_state=flow.entry_state,
        )
        return TriageProgress(session=session, flow=flow, next_step=self._step(flow, flow.entry_state), completed=False)

    def answer(self, session_id: str, answer: Any) -> TriageProgress:
        session = self.store.get(session_id)
        if session is None:
            raise KeyError(f"triage_session_not_found:{session_id}")
        if session.status != "active":
            raise ValueError(f"triage_session_not_active:{session.session_id}:{session.status}")
        if not session.selected_intent:
            raise ValueError(f"triage_intent_not_selected:{session.session_id}")
        flow = load_flow(session.selected_intent)
        current = self._step(flow, session.current_state)
        normalized = self._normalize_answer(current, answer)
        session.answers[current.step_id] = normalized
        target = current.transition_map.get(str(normalized), current.fallback_transition)
        self.audit.log_triage_step_answered(
            trace_id=session.session_id,
            source="triage_engine",
            session_id=session.session_id,
            intent_id=session.selected_intent,
            step_id=current.step_id,
            answer=normalized,
            previous_state=current.step_id,
            target_state=target,
        )
        diagnostic = self._diagnostic(flow, target)
        if diagnostic is not None:
            session.current_state = ""
            session.diagnostic_state = diagnostic.state_id
            session.status = "diagnostic_ready"
            self.audit.log_triage_state_changed(
                trace_id=session.session_id,
                source="triage_engine",
                session_id=session.session_id,
                intent_id=session.selected_intent,
                previous_state=current.step_id,
                next_state=diagnostic.state_id,
                diagnostic=True,
            )
            selection = select_runbooks_for_diagnostic_state(
                diagnostic.state_id,
                audience=session.audience,
                lang=session.lang,
                context={"lang": session.lang, "audience": session.audience, "diagnostic_state": diagnostic.state_id},
            )
            session.proposed_runbooks = [item["runbook_id"] for item in selection.get("items", [])]
            self.audit.log_triage_runbook_proposed(
                trace_id=session.session_id,
                source="triage_engine",
                session_id=session.session_id,
                intent_id=session.selected_intent,
                diagnostic_state=diagnostic.state_id,
                proposed_runbooks=list(session.proposed_runbooks),
            )
            if diagnostic.state_id == "user_cannot_answer":
                session.handoff_reason = "insufficient_user_input"
                self.audit.log_triage_handoff(
                    trace_id=session.session_id,
                    source="triage_engine",
                    session_id=session.session_id,
                    intent_id=session.selected_intent,
                    diagnostic_state=diagnostic.state_id,
                    target="operator",
                    reason=session.handoff_reason,
                )
            self.store.save(session)
            self.audit.log_triage_completed(
                trace_id=session.session_id,
                source="triage_engine",
                session_id=session.session_id,
                intent_id=session.selected_intent,
                diagnostic_state=diagnostic.state_id,
                proposed_runbooks=list(session.proposed_runbooks),
                handoff_reason=session.handoff_reason,
            )
            return TriageProgress(session=session, flow=flow, diagnostic_state=diagnostic, completed=True)
        next_step = self._step(flow, target)
        session.current_state = next_step.step_id
        self.store.save(session)
        self.audit.log_triage_state_changed(
            trace_id=session.session_id,
            source="triage_engine",
            session_id=session.session_id,
            intent_id=session.selected_intent,
            previous_state=current.step_id,
            next_state=next_step.step_id,
            diagnostic=False,
        )
        return TriageProgress(session=session, flow=flow, next_step=next_step, completed=False)

    def resume(self, session_id: str) -> TriageProgress:
        session = self.store.get(session_id)
        if session is None:
            raise KeyError(f"triage_session_not_found:{session_id}")
        flow = load_flow(session.selected_intent)
        if session.diagnostic_state:
            diagnostic = self._diagnostic(flow, session.diagnostic_state)
            return TriageProgress(session=session, flow=flow, diagnostic_state=diagnostic, completed=True)
        if not session.current_state:
            raise ValueError(f"triage_session_no_current_state:{session.session_id}")
        return TriageProgress(session=session, flow=flow, next_step=self._step(flow, session.current_state), completed=False)

    def _step(self, flow: TriageFlow, step_id: str) -> TriageStep:
        for step in flow.steps:
            if step.step_id == step_id:
                return step
        raise KeyError(f"triage_step_not_found:{flow.flow_id}:{step_id}")

    def _diagnostic(self, flow: TriageFlow, state_id: str) -> Optional[DiagnosticState]:
        for item in flow.diagnostic_states:
            if item.state_id == state_id:
                return item
        return None

    def _normalize_answer(self, step: TriageStep, answer: Any) -> str:
        raw = str(answer).strip().lower()
        if step.answer_type == "boolean":
            if raw in {"yes", "true", "1", "y", "はい"}:
                return "yes"
            if raw in {"no", "false", "0", "n", "いいえ"}:
                return "no"
        if step.answer_type == "single_choice":
            valid = {str(choice.get("value", "")).strip() for choice in step.choices}
            if raw in valid:
                return raw
        if step.answer_type == "text":
            return raw
        return raw
