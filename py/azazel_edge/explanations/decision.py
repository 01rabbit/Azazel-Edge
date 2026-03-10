from __future__ import annotations

from typing import Any, Dict, List


class DecisionExplainer:
    def explain(
        self,
        noc: Dict[str, Any],
        soc: Dict[str, Any],
        arbiter: Dict[str, Any],
        target: str = 'azazel-edge',
    ) -> Dict[str, Any]:
        action = str(arbiter.get('action') or 'observe')
        reason = str(arbiter.get('reason') or 'unspecified')
        chosen_evidence_ids = [str(x) for x in arbiter.get('chosen_evidence_ids', []) if str(x)]
        rejected = arbiter.get('rejected_alternatives', []) if isinstance(arbiter.get('rejected_alternatives'), list) else []

        noc_summary = noc.get('summary', {}) if isinstance(noc, dict) else {}
        soc_summary = soc.get('summary', {}) if isinstance(soc, dict) else {}
        why_chosen = {
            'action': action,
            'reason': reason,
            'noc_status': noc_summary.get('status', 'unknown'),
            'soc_status': soc_summary.get('status', 'unknown'),
            'target': target,
            'ti_matches': soc_summary.get('ti_matches', []),
        }
        why_not_others = [
            {
                'action': str(item.get('action') or ''),
                'reason': str(item.get('reason') or ''),
            }
            for item in rejected
            if isinstance(item, dict)
        ]
        operator_wording = self._operator_wording(
            action=action,
            reason=reason,
            target=target,
            noc_status=str(noc_summary.get('status') or 'unknown'),
            soc_status=str(soc_summary.get('status') or 'unknown'),
            why_not_others=why_not_others,
            ti_matches=why_chosen['ti_matches'],
        )
        return {
            'why_chosen': why_chosen,
            'why_not_others': why_not_others,
            'evidence_ids': chosen_evidence_ids,
            'operator_wording': operator_wording,
            'machine': {
                'noc_summary': noc_summary,
                'soc_summary': soc_summary,
                'arbiter': arbiter,
            },
        }

    @staticmethod
    def _operator_wording(
        action: str,
        reason: str,
        target: str,
        noc_status: str,
        soc_status: str,
        why_not_others: List[Dict[str, str]],
        ti_matches: List[Dict[str, Any]],
    ) -> str:
        rejected_text = '; '.join(
            f"{item['action']} was rejected because {item['reason']}"
            for item in why_not_others
            if item.get('action') and item.get('reason')
        )
        sentence = (
            f"Selected action {action} for {target} because {reason}. "
            f"NOC status is {noc_status} and SOC status is {soc_status}."
        )
        if ti_matches:
            ti_text = ', '.join(f"{item.get('indicator_type')}:{item.get('value')}" for item in ti_matches[:3])
            sentence += f" TI matches: {ti_text}."
        if rejected_text:
            sentence += f" Alternatives: {rejected_text}."
        return sentence
