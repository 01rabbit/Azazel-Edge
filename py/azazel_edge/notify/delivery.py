from __future__ import annotations

import json
import logging
import smtplib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.request import Request, urlopen
from email.message import EmailMessage

from azazel_edge.audit import P0AuditLogger


class NotificationError(RuntimeError):
    pass


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


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


class SyslogCEFNotifier:
    CEF_SEVERITY_MAP = {
        'critical': 10,
        'high': 8,
        'warning': 5,
        'info': 3,
    }

    def __init__(self, host: str, port: int = 514, protocol: str = 'udp'):
        import logging.handlers
        self.host = str(host or '').strip()
        self.port = int(port)
        self.protocol = str(protocol or 'udp').lower()
        sock_type = logging.handlers.SOCK_DGRAM if self.protocol == 'udp' else logging.handlers.SOCK_STREAM
        self._handler = logging.handlers.SysLogHandler(
            address=(self.host, self.port),
            socktype=sock_type,
        )

    def _build_cef(self, payload: Dict[str, Any]) -> str:
        action = str(payload.get('action') or 'observe')
        reason = str(payload.get('reason') or '')
        target = str(payload.get('target') or '')
        evidence = ','.join(str(e) for e in payload.get('evidence_ids', []))
        level = str(payload.get('level') or 'info').lower()
        cef_severity = self.CEF_SEVERITY_MAP.get(level, 3)
        incident_id = str(payload.get('incident_id') or '')
        operator_wording = str(payload.get('operator_wording') or '')

        extension = (
            f'act={action} '
            f'reason={reason} '
            f'dst={target} '
            f'cs1={evidence} '
            f'cs1Label=evidence_ids '
            f'cs2={incident_id} '
            f'cs2Label=incident_id '
            f'msg={operator_wording}'
        )
        return (
            f'CEF:0|Azazel-Edge|AzazelEdge|1.0|'
            f'arbiter_{action}|'
            f'Azazel-Edge arbiter: {action}|'
            f'{cef_severity}|'
            f'{extension}'
        )

    def send(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.host:
            raise NotificationError('syslog_cef_send_failed:missing_host')
        cef_line = self._build_cef(payload)
        try:
            self._handler.emit(
                logging.makeLogRecord({'msg': cef_line, 'levelno': logging.WARNING})
            )
        except Exception as exc:
            raise NotificationError(f'syslog_cef_send_failed:{exc}') from exc
        return {'ok': True, 'adapter': 'syslog_cef', 'status': 200, 'cef': cef_line}


class OfflineQueueNotifier:
    def __init__(
        self,
        queue_path: str | Path,
        delegate: Any,
        max_queue_entries: int = 500,
    ):
        self.queue_path = Path(queue_path)
        self.queue_path.parent.mkdir(parents=True, exist_ok=True)
        self.delegate = delegate
        self.max_queue_entries = int(max_queue_entries)

    def _summary_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'action': str(payload.get('action') or ''),
            'reason': str(payload.get('reason') or ''),
            'target': str(payload.get('target') or ''),
            'level': str(payload.get('level') or 'info'),
            'incident_id': str(payload.get('incident_id') or ''),
            'operator_wording': str(payload.get('operator_wording') or ''),
            'queued_at': iso_utc_now(),
        }

    def send(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        summary = self._summary_payload(payload)
        try:
            existing: List[Dict[str, Any]] = []
            if self.queue_path.exists():
                for line in self.queue_path.read_text(encoding='utf-8').splitlines():
                    try:
                        existing.append(json.loads(line))
                    except Exception:
                        pass
            existing.append(summary)
            if len(existing) > self.max_queue_entries:
                existing = existing[-self.max_queue_entries:]
            with self.queue_path.open('w', encoding='utf-8') as fh:
                for entry in existing:
                    fh.write(json.dumps(entry, ensure_ascii=True, separators=(',', ':')) + '\n')
            return {'ok': True, 'adapter': 'offline_queue', 'queued': len(existing)}
        except Exception as exc:
            return {'ok': False, 'adapter': 'offline_queue', 'error': str(exc)}

    def flush(self) -> Dict[str, Any]:
        if not self.queue_path.exists():
            return {'flushed': 0, 'failed': 0, 'remaining': 0}
        entries: List[Dict[str, Any]] = []
        for line in self.queue_path.read_text(encoding='utf-8').splitlines():
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
        flushed, failed, undelivered = 0, 0, []
        for entry in entries:
            try:
                result = self.delegate.send(entry)
                if result.get('ok'):
                    flushed += 1
                else:
                    failed += 1
                    undelivered.append(entry)
            except Exception:
                failed += 1
                undelivered.append(entry)
        if undelivered:
            with self.queue_path.open('w', encoding='utf-8') as fh:
                for entry in undelivered:
                    fh.write(json.dumps(entry, ensure_ascii=True, separators=(',', ':')) + '\n')
        else:
            self.queue_path.unlink(missing_ok=True)
        return {'flushed': flushed, 'failed': failed, 'remaining': len(undelivered)}

    def queue_depth(self) -> int:
        if not self.queue_path.exists():
            return 0
        return sum(1 for line in self.queue_path.read_text(encoding='utf-8').splitlines() if line.strip())


class DecisionNotifier:
    def __init__(self, notifiers: List[Any], audit_logger: P0AuditLogger, summary_only: bool = False):
        self.notifiers = list(notifiers)
        self.audit = audit_logger
        self.summary_only = bool(summary_only)

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

        send_payload = self._payload_for_adapter(payload)
        errors: List[str] = []
        attempts: List[Dict[str, Any]] = []
        for notifier in self.notifiers:
            adapter = self._adapter_name(notifier)
            try:
                result = notifier.send(send_payload)
                ack = result.get('status')
                attempts.append({'adapter': adapter, 'ok': True, 'ack': ack})
                audit_result = {
                    'ok': True,
                    'adapter': result.get('adapter') or adapter,
                    'ack': ack,
                    'attempts': attempts,
                    'payload': send_payload,
                }
                self.audit.log('notification', trace_id=target, source='decision_notifier', decision='sent', payload=audit_result)
                return audit_result
            except Exception as exc:
                errors.append(str(exc))
                attempts.append({'adapter': adapter, 'ok': False, 'error': str(exc)})

        failed = {'ok': False, 'errors': errors, 'attempts': attempts, 'payload': send_payload}
        self.audit.log('notification', trace_id=target, source='decision_notifier', decision='failed', payload=failed)
        return failed

    def _payload_for_adapter(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.summary_only:
            return dict(payload)
        compact = dict(payload)
        compact['evidence_ids'] = []
        compact['operator_wording'] = str(compact.get('operator_wording') or '')[:200]
        return compact

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
