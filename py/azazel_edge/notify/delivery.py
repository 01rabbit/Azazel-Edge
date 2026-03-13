from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.request import Request, urlopen

from azazel_edge.audit import P0AuditLogger


class NotificationError(RuntimeError):
    pass


class NtfyNotifier:
    def __init__(self, base_url: str, topic: str, token: str = ''):
        self.base_url = base_url.rstrip('/')
        self.topic = topic.strip('/')
        self.token = token

    def send(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps(payload).encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        req = Request(f'{self.base_url}/{self.topic}', data=body, headers=headers, method='POST')
        try:
            with urlopen(req, timeout=5) as resp:
                status = getattr(resp, 'status', 200)
        except Exception as exc:
            raise NotificationError(f'ntfy_send_failed:{exc}') from exc
        if status >= 400:
            raise NotificationError(f'ntfy_send_failed_status:{status}')
        return {'ok': True, 'adapter': 'ntfy', 'status': status}


class MattermostNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        text = (
            f"[{payload.get('level', 'info')}] action={payload.get('action')} "
            f"target={payload.get('target')} reason={payload.get('reason')} "
            f"evidence={','.join(payload.get('evidence_ids', []))}"
        )
        req = Request(
            self.webhook_url,
            data=json.dumps({'text': text}).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urlopen(req, timeout=5) as resp:
                status = getattr(resp, 'status', 200)
        except Exception as exc:
            raise NotificationError(f'mattermost_send_failed:{exc}') from exc
        if status >= 400:
            raise NotificationError(f'mattermost_send_failed_status:{status}')
        return {'ok': True, 'adapter': 'mattermost', 'status': status}


class DecisionNotifier:
    def __init__(self, notifiers: List[Any], audit_logger: P0AuditLogger):
        self.notifiers = list(notifiers)
        self.audit = audit_logger

    def notify(self, arbiter: Dict[str, Any], explanation: Dict[str, Any], target: str) -> Dict[str, Any]:
        action = str(arbiter.get('action') or '')
        if action != 'notify':
            result = {'ok': False, 'skipped': True, 'reason': 'action_not_notify'}
            self.audit.log('notification', trace_id=target, source='decision_notifier', decision='skipped', payload=result)
            return result

        payload = {
            'action': action,
            'reason': str(arbiter.get('reason') or ''),
            'target': target,
            'evidence_ids': [str(x) for x in arbiter.get('chosen_evidence_ids', []) if str(x)],
            'level': 'critical' if 'high' in str(arbiter.get('reason') or '') else 'warning',
            'operator_wording': str(explanation.get('operator_wording') or ''),
            'incident_id': str((((explanation.get('why_chosen') or {}) if isinstance(explanation.get('why_chosen'), dict) else {}).get('incident_summary') or {}).get('incident_id') or ''),
            'runbook_candidate_id': str((((explanation.get('why_chosen') or {}) if isinstance(explanation.get('why_chosen'), dict) else {}).get('runbook_support') or {}).get('runbook_candidate_id') or ''),
        }

        errors: List[str] = []
        for notifier in self.notifiers:
            try:
                result = notifier.send(payload)
                audit_result = {'ok': True, 'adapter': result.get('adapter'), 'payload': payload}
                self.audit.log('notification', trace_id=target, source='decision_notifier', decision='sent', payload=audit_result)
                return audit_result
            except Exception as exc:
                errors.append(str(exc))

        failed = {'ok': False, 'errors': errors, 'payload': payload}
        self.audit.log('notification', trace_id=target, source='decision_notifier', decision='failed', payload=failed)
        return failed
