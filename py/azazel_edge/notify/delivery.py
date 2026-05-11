from __future__ import annotations

import json
import smtplib
from typing import Any, Dict, List
from urllib.request import Request, urlopen
from email.message import EmailMessage

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


class WebhookNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = str(webhook_url or '').strip()

    def send(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.webhook_url:
            raise NotificationError('webhook_send_failed:missing_url')
        req = Request(
            self.webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urlopen(req, timeout=5) as resp:
                status = getattr(resp, 'status', 200)
        except Exception as exc:
            raise NotificationError(f'webhook_send_failed:{exc}') from exc
        if status >= 400:
            raise NotificationError(f'webhook_send_failed_status:{status}')
        return {'ok': True, 'adapter': 'webhook', 'status': status}


class SmtpNotifier:
    def __init__(self, host: str, port: int, sender: str, recipient: str, *, timeout: float = 5.0):
        self.host = str(host or '').strip()
        self.port = int(port)
        self.sender = str(sender or '').strip()
        self.recipient = str(recipient or '').strip()
        self.timeout = float(timeout)

    def send(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.host or not self.sender or not self.recipient:
            raise NotificationError('smtp_send_failed:missing_config')
        msg = EmailMessage()
        msg['From'] = self.sender
        msg['To'] = self.recipient
        msg['Subject'] = f"[Azazel-Edge] {payload.get('level', 'info').upper()} {payload.get('action', '-')}"
        msg.set_content(
            f"target={payload.get('target')}\n"
            f"reason={payload.get('reason')}\n"
            f"evidence={','.join(payload.get('evidence_ids', []))}\n"
            f"incident_id={payload.get('incident_id')}\n"
            f"runbook_candidate_id={payload.get('runbook_candidate_id')}\n"
            f"operator_wording={payload.get('operator_wording')}\n"
        )
        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as client:
                client.send_message(msg)
        except Exception as exc:
            raise NotificationError(f'smtp_send_failed:{exc}') from exc
        return {'ok': True, 'adapter': 'smtp', 'status': 250}


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
        attempts: List[Dict[str, Any]] = []
        for notifier in self.notifiers:
            adapter = self._adapter_name(notifier)
            try:
                result = notifier.send(payload)
                ack = result.get('status')
                attempts.append({'adapter': adapter, 'ok': True, 'ack': ack})
                audit_result = {
                    'ok': True,
                    'adapter': result.get('adapter') or adapter,
                    'ack': ack,
                    'attempts': attempts,
                    'payload': payload,
                }
                self.audit.log('notification', trace_id=target, source='decision_notifier', decision='sent', payload=audit_result)
                return audit_result
            except Exception as exc:
                errors.append(str(exc))
                attempts.append({'adapter': adapter, 'ok': False, 'error': str(exc)})

        failed = {'ok': False, 'errors': errors, 'attempts': attempts, 'payload': payload}
        self.audit.log('notification', trace_id=target, source='decision_notifier', decision='failed', payload=failed)
        return failed

    @staticmethod
    def _adapter_name(notifier: Any) -> str:
        name = notifier.__class__.__name__.lower()
        if 'mattermost' in name:
            return 'mattermost'
        if 'ntfy' in name:
            return 'ntfy'
        if 'webhook' in name:
            return 'webhook'
        if 'smtp' in name:
            return 'smtp'
        return name
