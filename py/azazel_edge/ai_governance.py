from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Dict, Tuple

from azazel_edge.audit import P0AuditLogger

ALLOWED_INTENTS = {'advice', 'summary', 'candidate'}
SANITIZED_KEYS = {
    'trace_id',
    'source',
    'intent',
    'subject',
    'risk_score',
    'category',
    'ports',
    'ips',
    'evidence_ids',
    'summary',
    'candidate_scope',
}
FORBIDDEN_KEYS = {'raw', 'raw_log', 'full_log', 'message', 'line', 'payload', 'event'}


class AIGovernanceError(ValueError):
    pass


class AIGovernance:
    def __init__(self, audit_logger: P0AuditLogger):
        self.audit = audit_logger

    @staticmethod
    def empty_output() -> Dict[str, Any]:
        return {'advice': '', 'summary': '', 'candidate': '', 'runbook_candidates': [], 'attack_candidates': []}

    def should_invoke(self, context: Dict[str, Any]) -> Tuple[bool, str]:
        intent = str(context.get('intent') or '')
        source = str(context.get('source') or '')
        if intent not in ALLOWED_INTENTS:
            return False, 'intent_not_allowed'
        risk_band = str(context.get('risk_band') or '')
        if intent == 'advice':
            if source == 'suricata_eve' and risk_band in {'ambiguous', 'uncertain'}:
                return True, 'ambiguous_suricata'
            return False, 'advice_requires_ambiguous_suricata'
        if intent == 'candidate' and source == 'suricata_eve' and risk_band in {'ambiguous', 'uncertain'}:
            return True, 'ambiguous_suricata_candidate'
        if intent in {'summary', 'candidate'} and source in {'operator', 'ops_comm', 'mattermost', 'dashboard'}:
            return True, 'operator_requested'
        return False, 'source_not_allowed'

    def sanitize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise AIGovernanceError('payload_not_dict')
        sanitized = {key: deepcopy(value) for key, value in payload.items() if key in SANITIZED_KEYS}
        for key in FORBIDDEN_KEYS:
            sanitized.pop(key, None)
        return sanitized

    def authorize(self, context: Dict[str, Any], raw_payload: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        """Apply the repository AI invocation gate and audit the decision.

        This is the reusable pre-invocation seam for structured advisory clients
        such as the M.I.O. shadow reasoning adapter. It intentionally does not
        validate a domain-specific model response; callers must apply their own
        deterministic schema/grounding validation after invocation.
        """
        trace_id = str(context.get('trace_id') or raw_payload.get('trace_id') or '')
        source = str(context.get('source') or raw_payload.get('source') or 'ai_governance')
        allowed, decision_reason = self.should_invoke(context)
        sanitized = self.sanitize_payload(raw_payload)
        self.audit.log(
            'ai_assist',
            trace_id=trace_id,
            source=source,
            stage='input',
            decision=decision_reason,
            payload=sanitized,
        )
        if not allowed:
            self.audit.log(
                'ai_assist',
                trace_id=trace_id,
                source=source,
                stage='decision',
                decision='blocked',
                payload=self.empty_output(),
            )
        return allowed, decision_reason, sanitized

    def record_structured_result(
        self,
        *,
        trace_id: str,
        source: str,
        candidate_scope: str,
        decision: str,
        metadata: Dict[str, Any] | None = None,
    ) -> None:
        """Audit structured advisory completion without retaining raw prompts/output."""
        payload: Dict[str, Any] = {'candidate_scope': str(candidate_scope or '')[:96]}
        if isinstance(metadata, dict):
            for key in ('task', 'model', 'response_chars', 'error'):
                if key in metadata:
                    value = metadata.get(key)
                    payload[key] = str(value)[:160] if value is not None else ''
        self.audit.log(
            'ai_assist',
            trace_id=str(trace_id or ''),
            source=str(source or 'ai_governance'),
            stage='output',
            decision=str(decision or 'unknown'),
            payload=payload,
        )

    def validate_output(self, output: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(output, dict):
            raise AIGovernanceError('output_not_dict')
        allowed_keys = {'advice', 'summary', 'candidate', 'runbook_candidates', 'attack_candidates'}
        extra = sorted(set(output.keys()).difference(allowed_keys))
        if extra:
            raise AIGovernanceError('output_extra_keys:' + ','.join(extra))
        validated: Dict[str, Any] = {
            'advice': '',
            'summary': '',
            'candidate': '',
            'runbook_candidates': [],
            'attack_candidates': [],
        }
        for key in ('advice', 'summary', 'candidate'):
            value = output.get(key, '')
            if value is None:
                value = ''
            if not isinstance(value, str):
                raise AIGovernanceError(f'output_{key}_must_be_string')
            validated[key] = value[:240]
        for key in ('runbook_candidates', 'attack_candidates'):
            raw = output.get(key, [])
            if raw is None:
                raw = []
            if not isinstance(raw, list):
                raise AIGovernanceError(f'output_{key}_must_be_list')
            values: list[str] = []
            for item in raw[:5]:
                if not isinstance(item, str):
                    raise AIGovernanceError(f'output_{key}_items_must_be_string')
                values.append(item[:96])
            validated[key] = values
        return validated

    def invoke(
        self,
        context: Dict[str, Any],
        raw_payload: Dict[str, Any],
        invoker: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> Dict[str, Any]:
        trace_id = str(context.get('trace_id') or raw_payload.get('trace_id') or '')
        source = str(context.get('source') or raw_payload.get('source') or 'ai_governance')
        allowed, _decision_reason, sanitized = self.authorize(context, raw_payload)
        if not allowed:
            return self.empty_output()
        output = invoker(sanitized)
        try:
            validated = self.validate_output(output)
            self.audit.log(
                'ai_assist',
                trace_id=trace_id,
                source=source,
                stage='output',
                decision='adopted',
                payload=validated,
            )
            return validated
        except AIGovernanceError:
            self.audit.log(
                'ai_assist',
                trace_id=trace_id,
                source=source,
                stage='review',
                decision='rejected',
                payload={'summary': sanitized.get('summary', '')[:240]},
            )
            fallback = {
                'advice': '',
                'summary': sanitized.get('summary', '')[:240],
                'candidate': '',
                'runbook_candidates': [],
                'attack_candidates': [],
            }
            self.audit.log(
                'ai_assist',
                trace_id=trace_id,
                source=source,
                stage='output',
                decision='fallback',
                payload=fallback,
            )
            return fallback
