from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from azazel_edge.knowledge import AttackDefendKnowledge
from azazel_edge.triage import select_noc_runbook_support


class DecisionExplainer:
    def __init__(self, output_path: str | Path = '/var/log/azazel-edge/decision-explanations.jsonl'):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.knowledge = AttackDefendKnowledge()

    def explain(
        self,
        noc: Dict[str, Any],
        soc: Dict[str, Any],
        arbiter: Dict[str, Any],
        target: str = 'azazel-edge',
        trace_id: str = '',
        persist: bool = False,
    ) -> Dict[str, Any]:
        action = str(arbiter.get('action') or 'observe')
        reason = str(arbiter.get('reason') or 'unspecified')
        control_mode = str(arbiter.get('control_mode') or 'none')
        client_impact = arbiter.get('client_impact', {}) if isinstance(arbiter.get('client_impact'), dict) else {}
        chosen_evidence_ids = [str(x) for x in arbiter.get('chosen_evidence_ids', []) if str(x)]
        rejected = arbiter.get('rejected_alternatives', []) if isinstance(arbiter.get('rejected_alternatives'), list) else []

        noc_summary = noc.get('summary', {}) if isinstance(noc, dict) else {}
        soc_summary = soc.get('summary', {}) if isinstance(soc, dict) else {}
        attack_candidates = []
        if isinstance(soc_summary.get('attack_candidates'), list):
            attack_candidates.extend(str(x) for x in soc_summary.get('attack_candidates', []) if str(x))
        if isinstance(soc_summary.get('ai_attack_candidates'), list):
            attack_candidates.extend(str(x) for x in soc_summary.get('ai_attack_candidates', []) if str(x))
        attack_candidates = list(dict.fromkeys(attack_candidates))
        correlation = soc_summary.get('correlation', {}) if isinstance(soc_summary.get('correlation'), dict) else {}
        sigma_hits = soc_summary.get('sigma_hits', []) if isinstance(soc_summary.get('sigma_hits'), list) else []
        yara_hits = soc_summary.get('yara_hits', []) if isinstance(soc_summary.get('yara_hits'), list) else []
        visualization = self.knowledge.build_visualization(attack_candidates, soc_summary.get('ti_matches', []))
        runbook_support = select_noc_runbook_support(noc if isinstance(noc, dict) else {}, audience='professional', lang='en')
        next_checks = self._next_checks(action, noc_summary, soc_summary, client_impact)
        why_chosen = {
            'format_version': 'v2',
            'action': action,
            'reason': reason,
            'control_mode': control_mode,
            'noc_status': noc_summary.get('status', 'unknown'),
            'soc_status': soc_summary.get('status', 'unknown'),
            'target': target,
            'noc_dimensions': {
                'availability': (noc.get('availability') or {}).get('label', 'unknown') if isinstance(noc, dict) else 'unknown',
                'path_health': (noc.get('path_health') or {}).get('label', 'unknown') if isinstance(noc, dict) else 'unknown',
                'device_health': (noc.get('device_health') or {}).get('label', 'unknown') if isinstance(noc, dict) else 'unknown',
                'client_health': (noc.get('client_health') or {}).get('label', 'unknown') if isinstance(noc, dict) else 'unknown',
                'capacity_health': (noc.get('capacity_health') or {}).get('label', 'unknown') if isinstance(noc, dict) else 'unknown',
                'client_inventory_health': (noc.get('client_inventory_health') or {}).get('label', 'unknown') if isinstance(noc, dict) else 'unknown',
                'service_health': (noc.get('service_health') or {}).get('label', 'unknown') if isinstance(noc, dict) else 'unknown',
                'resolution_health': (noc.get('resolution_health') or {}).get('label', 'unknown') if isinstance(noc, dict) else 'unknown',
                'config_drift_health': (noc.get('config_drift_health') or {}).get('label', 'unknown') if isinstance(noc, dict) else 'unknown',
            },
            'affected_scope': (noc.get('affected_scope') or (noc_summary.get('blast_radius') if isinstance(noc_summary.get('blast_radius'), dict) else {})) if isinstance(noc, dict) else {},
            'config_drift': (noc.get('config_drift_health') or {}) if isinstance(noc, dict) else {},
            'incident_summary': (noc.get('incident_summary') or (noc_summary.get('incident_summary') if isinstance(noc_summary.get('incident_summary'), dict) else {})) if isinstance(noc, dict) else {},
            'runbook_support': runbook_support,
            'ti_matches': soc_summary.get('ti_matches', []),
            'attack_candidates': attack_candidates,
            'sigma_hits': sigma_hits,
            'yara_hits': yara_hits,
            'visualization': visualization,
            'correlation': correlation,
            'client_impact': client_impact,
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
            attack_candidates=attack_candidates,
            sigma_hits=sigma_hits,
            yara_hits=yara_hits,
            correlation=correlation,
            control_mode=control_mode,
            client_impact=client_impact,
            affected_scope=why_chosen['affected_scope'],
            config_drift=why_chosen['config_drift'],
            incident_summary=why_chosen['incident_summary'],
            runbook_support=runbook_support,
        )
        explanation = {
            'ts': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'trace_id': str(trace_id or ''),
            'format_version': 'v2',
            'why_chosen': why_chosen,
            'why_not_others': why_not_others,
            'evidence_ids': chosen_evidence_ids,
            'next_checks': next_checks,
            'operator_wording': operator_wording,
            'machine': {
                'noc_summary': noc_summary,
                'soc_summary': soc_summary,
                'arbiter': arbiter,
            },
        }
        if persist:
            self.write_jsonl(explanation)
        return explanation

    def write_jsonl(self, explanation: Dict[str, Any]) -> None:
        with self.output_path.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(explanation, ensure_ascii=True, separators=(',', ':')) + '\n')

    @staticmethod
    def _operator_wording(
        action: str,
        reason: str,
        target: str,
        noc_status: str,
        soc_status: str,
        why_not_others: List[Dict[str, str]],
        ti_matches: List[Dict[str, Any]],
        attack_candidates: List[str],
        sigma_hits: List[Dict[str, Any]],
        yara_hits: List[Dict[str, Any]],
        correlation: Dict[str, Any],
        control_mode: str,
        client_impact: Dict[str, Any],
        affected_scope: Dict[str, Any],
        config_drift: Dict[str, Any],
        incident_summary: Dict[str, Any],
        runbook_support: Dict[str, Any],
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
        if control_mode and control_mode != 'none':
            sentence += f" Control mode: {control_mode}."
        if ti_matches:
            ti_text = ', '.join(f"{item.get('indicator_type')}:{item.get('value')}" for item in ti_matches[:3])
            sentence += f" TI matches: {ti_text}."
        if attack_candidates:
            sentence += f" ATT&CK candidates: {', '.join(attack_candidates[:3])}."
        if sigma_hits:
            sentence += f" Sigma: {', '.join(str(item.get('rule_id') or '') for item in sigma_hits[:3] if str(item.get('rule_id') or ''))}."
        if yara_hits:
            sentence += f" YARA: {', '.join(str(item.get('rule_id') or '') for item in yara_hits[:3] if str(item.get('rule_id') or ''))}."
        if int(correlation.get('top_score') or 0) > 0:
            sentence += (
                f" Correlation: {int(correlation.get('cluster_count') or 0)} cluster(s), "
                f"top score {int(correlation.get('top_score') or 0)}."
            )
        if client_impact:
            sentence += (
                f" Client impact: score {int(client_impact.get('score') or 0)}, "
                f"affected {int(client_impact.get('affected_client_count') or 0)}, "
                f"critical {int(client_impact.get('critical_client_count') or 0)}."
            )
        if isinstance(affected_scope, dict) and affected_scope:
            sentence += (
                f" Affected scope: uplinks {', '.join(affected_scope.get('affected_uplinks', [])[:3]) or '-'}, "
                f"segments {', '.join(affected_scope.get('affected_segments', [])[:3]) or '-'}, "
                f"estimated clients {int(affected_scope.get('affected_client_count') or 0)}."
            )
        if isinstance(incident_summary, dict) and incident_summary:
            incident_id = str(incident_summary.get('incident_id') or '')
            probable_cause = str(incident_summary.get('probable_cause') or '')
            if incident_id or probable_cause:
                sentence += f" Incident summary: {incident_id or '-'} cause={probable_cause or 'unknown'}."
        if isinstance(config_drift, dict) and config_drift:
            drift_reasons = [str(item) for item in config_drift.get('reasons', []) if str(item)]
            if drift_reasons:
                sentence += f" Config drift indicators: {', '.join(drift_reasons[:3])}."
        if isinstance(runbook_support, dict) and str(runbook_support.get('runbook_candidate_id') or ''):
            runbook_title = str((((runbook_support.get('reviewed_runbook') or {}) if isinstance(runbook_support.get('reviewed_runbook'), dict) else {}).get('title')) or runbook_support.get('runbook_candidate_id') or '')
            sentence += (
                f" Suggested NOC runbook: {runbook_title} "
                f"because {str(runbook_support.get('why_this_runbook') or '').rstrip('.') or 'deterministic NOC review is required'}."
            )
        if rejected_text:
            sentence += f" Alternatives: {rejected_text}."
        return sentence

    @staticmethod
    def _next_checks(
        action: str,
        noc_summary: Dict[str, Any],
        soc_summary: Dict[str, Any],
        client_impact: Dict[str, Any],
    ) -> List[str]:
        checks: List[str] = []
        if action in {'notify', 'observe'}:
            checks.append('confirm_latest_noc_and_soc_status')
        if action in {'throttle', 'redirect', 'isolate'}:
            checks.append('verify_control_applied_and_reversible')
        if str(soc_summary.get('status') or '') in {'high', 'critical'}:
            checks.append('review_soc_evidence_and_attack_candidates')
        if str(noc_summary.get('status') or '') in {'poor', 'critical'}:
            checks.append('confirm_noc_stability_before_escalation')
        if any(str(noc_summary.get('reasons') or '').find(token) >= 0 for token in ('capacity_health', 'client_inventory_health')):
            checks.append('review_capacity_and_client_inventory_summary')
        if any(str(noc_summary.get('reasons') or '').find(token) >= 0 for token in ('service_health', 'resolution_health')):
            checks.append('review_path_and_service_assurance')
        if any(str(noc_summary.get('reasons') or '').find(token) >= 0 for token in ('config_drift_health', 'config_drift')):
            checks.append('review_config_drift_and_last_known_good')
        if isinstance(noc_summary.get('incident_summary'), dict) and str((noc_summary.get('incident_summary') or {}).get('incident_id') or ''):
            checks.append('review_incident_summary_and_drill_down')
        if int(client_impact.get('critical_client_count') or 0) > 0:
            checks.append('confirm_critical_client_owner_before_control')
        return checks
