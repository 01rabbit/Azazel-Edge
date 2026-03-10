from __future__ import annotations

from typing import Any, Dict, List


class ActionArbiter:
    REQUIRED_NOC_KEYS = {'availability', 'path_health', 'device_health', 'client_health', 'summary', 'evidence_ids'}
    REQUIRED_SOC_KEYS = {'suspicion', 'confidence', 'technique_likelihood', 'blast_radius', 'summary', 'evidence_ids'}

    def decide(self, noc: Dict[str, Any], soc: Dict[str, Any]) -> Dict[str, Any]:
        self._validate_schema(noc, self.REQUIRED_NOC_KEYS, 'noc')
        self._validate_schema(soc, self.REQUIRED_SOC_KEYS, 'soc')

        availability_label = str(noc.get('availability', {}).get('label') or 'good')
        path_label = str(noc.get('path_health', {}).get('label') or 'good')
        device_label = str(noc.get('device_health', {}).get('label') or 'good')
        suspicion_score = int(soc.get('suspicion', {}).get('score') or 0)
        suspicion_label = str(soc.get('suspicion', {}).get('label') or 'low')
        blast_score = int(soc.get('blast_radius', {}).get('score') or 0)
        confidence_score = int(soc.get('confidence', {}).get('score') or 0)

        action = 'observe'
        reason = 'baseline'

        noc_fragile = availability_label in {'poor', 'critical'} or path_label in {'poor', 'critical'} or device_label in {'poor', 'critical'}
        strong_soc = suspicion_label in {'high', 'critical'} and confidence_score >= 60

        if strong_soc and not noc_fragile and blast_score >= 40:
            action = 'throttle'
            reason = 'soc_high_and_reversible_control_is_safe'
        elif strong_soc:
            action = 'notify'
            reason = 'soc_high_but_noc_fragile'
        elif availability_label in {'poor', 'critical'} or path_label in {'poor', 'critical'} or device_label in {'poor', 'critical'}:
            action = 'notify'
            reason = 'noc_degraded_requires_operator_attention'

        rejected = self._rejected_alternatives(action, noc_fragile=noc_fragile, strong_soc=strong_soc, blast_score=blast_score)
        chosen_evidence_ids = self._chosen_evidence_ids(action, noc, soc)

        return {
            'action': action,
            'reason': reason,
            'chosen_evidence_ids': chosen_evidence_ids,
            'rejected_alternatives': rejected,
        }

    @staticmethod
    def _validate_schema(payload: Dict[str, Any], required: set[str], name: str) -> None:
        if not isinstance(payload, dict):
            raise ValueError(f'{name}_input_not_dict')
        missing = sorted(required.difference(payload.keys()))
        if missing:
            raise ValueError(f'{name}_missing_keys:' + ','.join(missing))

    @staticmethod
    def _chosen_evidence_ids(action: str, noc: Dict[str, Any], soc: Dict[str, Any]) -> List[str]:
        chosen: List[str] = []
        if action == 'observe':
            chosen.extend(noc.get('evidence_ids', []))
            chosen.extend(soc.get('evidence_ids', []))
        elif action == 'notify':
            for key in ('availability', 'path_health', 'device_health'):
                chosen.extend(noc.get(key, {}).get('evidence_ids', []))
            chosen.extend(soc.get('suspicion', {}).get('evidence_ids', []))
        else:
            chosen.extend(soc.get('suspicion', {}).get('evidence_ids', []))
            chosen.extend(soc.get('blast_radius', {}).get('evidence_ids', []))
            chosen.extend(noc.get('availability', {}).get('evidence_ids', []))
            chosen.extend(noc.get('path_health', {}).get('evidence_ids', []))
        return sorted(dict.fromkeys(str(x) for x in chosen if str(x)))

    @staticmethod
    def _rejected_alternatives(action: str, noc_fragile: bool, strong_soc: bool, blast_score: int) -> List[Dict[str, str]]:
        candidates: List[Dict[str, str]] = []
        if action != 'observe':
            if strong_soc:
                candidates.append({'action': 'observe', 'reason': 'insufficient_response_for_detected_threat'})
            else:
                candidates.append({'action': 'observe', 'reason': 'deferred_to_higher_visibility_action'})
        if action != 'notify':
            if noc_fragile and strong_soc:
                candidates.append({'action': 'notify', 'reason': 'throttle_was_preferred_due_to_reversible_control'})
            else:
                candidates.append({'action': 'notify', 'reason': 'operator_notification_not_primary_choice'})
        if action != 'throttle':
            if not strong_soc:
                candidates.append({'action': 'throttle', 'reason': 'threat_signal_not_strong_enough'})
            elif noc_fragile:
                candidates.append({'action': 'throttle', 'reason': 'availability_risk_too_high'})
            elif blast_score < 40:
                candidates.append({'action': 'throttle', 'reason': 'blast_radius_too_small_for_control'})
        return candidates
