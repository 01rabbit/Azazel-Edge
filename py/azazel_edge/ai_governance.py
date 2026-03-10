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

    def should_invoke(self, context: Dict[str, Any]) -> Tuple[bool, str]:
        intent = str(context.get('intent') or '')
        source = str(context.get('source') or '')
        if intent not in ALLOWED_INTENTS:
            return False, 'intent_not_allowed'
        if intent == 'advice':
            if source == 'suricata_eve' and str(context.get('risk_band') or '') == 'ambiguous':
                return True, 'ambiguous_suricata'
            return False, 'advice_requires_ambiguous_suricata'
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

    def validate_output(self, output: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(output, dict):
            raise AIGovernanceError('output_not_dict')
        extra = sorted(set(output.keys()).difference({'advice', 'summary', 'candidate'}))
        if extra:
            raise AIGovernanceError('output_extra_keys:' + ','.join(extra))
        validated: Dict[str, Any] = {'advice': '', 'summary': '', 'candidate': ''}
        for key in validated:
            value = output.get(key, '')
            if value is None:
                value = ''
            if not isinstance(value, str):
                raise AIGovernanceError(f'output_{key}_must_be_string')
            validated[key] = value[:240]
        return validated

    def invoke(
        self,
        context: Dict[str, Any],
        raw_payload: Dict[str, Any],
        invoker: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> Dict[str, Any]:
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
            result = {'advice': '', 'summary': '', 'candidate': ''}
            self.audit.log(
                'ai_assist',
                trace_id=trace_id,
                source=source,
                stage='decision',
                decision='blocked',
                payload=result,
            )
            return result
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
            fallback = {
                'advice': '',
                'summary': sanitized.get('summary', '')[:240],
                'candidate': '',
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
