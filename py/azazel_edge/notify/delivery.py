from __future__ import annotations

import json
import logging
import os
import smtplib
import threading
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.request import Request, urlopen
from email.message import EmailMessage

from azazel_edge._util import iso_utc_now
from azazel_edge.audit import P0AuditLogger
from azazel_edge.audit.logger import DURABILITY_FSYNCED, fsync_path

try:  # POSIX: serialise queue writers across processes too.
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX
    _fcntl = None

_O_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
_O_CLOEXEC = getattr(os, 'O_CLOEXEC', 0)

# One lock per queue file in this process, shared by every notifier on it.
_QUEUE_LOCKS: Dict[str, threading.Lock] = {}
_QUEUE_LOCKS_GUARD = threading.Lock()


def _queue_lock(path: Path) -> threading.Lock:
    key = os.path.abspath(str(path))
    with _QUEUE_LOCKS_GUARD:
        return _QUEUE_LOCKS.setdefault(key, threading.Lock())


class NotificationError(RuntimeError):
    pass


# Alert class, recorded for measurement only (Edge#414, SO-03). Nothing reads
# it to route, rank, suppress or escalate an alert: the adapters, their order
# and the level are what they were before the class existed. Which decisions
# are P0 is the owner's to define; this rule names the only alert Edge treats
# as most urgent today (an arbiter 'notify' at level 'critical').
ALERT_CLASS_P0 = 'P0'
ALERT_CLASS_RULE = 'edge-alert-class/v1:notify-at-critical-is-P0'


def classify_alert(action: str, level: str) -> str:
    return ALERT_CLASS_P0 if str(action) == 'notify' and str(level) == 'critical' else ''


def _boot_id() -> str:
    try:
        return Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip()
    except Exception:
        return ''


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
            # The enqueue record names the decision it alerts on, and carries
            # its class (record-only) and the instant it was enqueued on the
            # Edge node's CLOCK_MONOTONIC (comparable only within boot_id).
            'decision_id': str(payload.get('decision_id') or ''),
            'alert_class': str(payload.get('alert_class') or ''),
            'queued_at': iso_utc_now(),
            'enqueued_monotonic_ns': time.monotonic_ns(),
            'boot_id': _boot_id(),
        }

    class _Locked:
        """Holds the in-process lock for the queue file and, on POSIX, an
        exclusive flock on its sidecar lock file, so read-modify-write of the
        queue is never interleaved."""

        def __init__(self, queue_path: Path):
            self.queue_path = queue_path
            self.lock = _queue_lock(queue_path)
            self.fd = None

        def __enter__(self):
            self.lock.acquire()
            try:
                if _fcntl is not None:
                    # O_NOFOLLOW: a symlink planted at the lock path is refused.
                    self.fd = os.open(
                        str(self.queue_path.with_name(self.queue_path.name + '.lock')),
                        os.O_RDWR | os.O_CREAT | _O_NOFOLLOW | _O_CLOEXEC,
                        0o600,
                    )
                    _fcntl.flock(self.fd, _fcntl.LOCK_EX)
            except Exception:
                if self.fd is not None:
                    os.close(self.fd)
                    self.fd = None
                self.lock.release()
                raise
            return self

        def __exit__(self, *exc):
            try:
                if self.fd is not None:
                    _fcntl.flock(self.fd, _fcntl.LOCK_UN)
                    os.close(self.fd)
                    self.fd = None
            finally:
                self.lock.release()
            return False

    def _read_entries(self) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        if self.queue_path.exists():
            for line in self.queue_path.read_text(encoding='utf-8').splitlines():
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        return entries

    def _write_entries(self, entries: List[Dict[str, Any]]) -> None:
        # Durable replace: a crash leaves either the old queue or the new one,
        # never a truncated file, and the new one is on disk before return.
        # The temp name is unique per process and thread; a failed write
        # removes it. Callers hold _Locked.
        tmp = self.queue_path.with_name(f'{self.queue_path.name}.{os.getpid()}.{threading.get_ident()}.tmp')
        try:
            # O_EXCL | O_NOFOLLOW: never write through a file or symlink that
            # is already there; 0600 because the queue holds alert content.
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                for entry in entries:
                    fh.write(json.dumps(entry, ensure_ascii=True, separators=(',', ':')) + '\n')
            fsync_path(tmp)
            os.replace(tmp, self.queue_path)
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        fsync_path(self.queue_path.parent)

    def send(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        summary = self._summary_payload(payload)
        try:
            with self._Locked(self.queue_path):
                existing = self._read_entries()
                existing.append(summary)
                if len(existing) > self.max_queue_entries:
                    existing = existing[-self.max_queue_entries:]
                self._write_entries(existing)
            return {'ok': True, 'adapter': 'offline_queue', 'queued': len(existing)}
        except Exception as exc:
            return {'ok': False, 'adapter': 'offline_queue', 'error': str(exc)}

    def flush(self) -> Dict[str, Any]:
        # Snapshot under the lock, deliver outside it (a slow delegate must not
        # hold up enqueue), then remove exactly the delivered entries under
        # the lock, keeping anything enqueued meanwhile.
        with self._Locked(self.queue_path):
            if not self.queue_path.exists():
                return {'flushed': 0, 'failed': 0, 'remaining': 0}
            entries = self._read_entries()
        flushed, failed = 0, 0
        delivered: List[str] = []
        for entry in entries:
            try:
                result = self.delegate.send(entry)
                if result.get('ok'):
                    flushed += 1
                    delivered.append(json.dumps(entry, sort_keys=True))
                else:
                    failed += 1
            except Exception:
                failed += 1
        with self._Locked(self.queue_path):
            remaining = self._read_entries()
            for key in delivered:
                for idx, entry in enumerate(remaining):
                    if json.dumps(entry, sort_keys=True) == key:
                        del remaining[idx]
                        break
            if remaining:
                self._write_entries(remaining)
            else:
                self.queue_path.unlink(missing_ok=True)
        return {'flushed': flushed, 'failed': failed, 'remaining': len(remaining)}

    def queue_depth(self) -> int:
        if not self.queue_path.exists():
            return 0
        return sum(1 for line in self.queue_path.read_text(encoding='utf-8').splitlines() if line.strip())


class DecisionNotifier:
    def __init__(self, notifiers: List[Any], audit_logger: P0AuditLogger, summary_only: bool = False):
        self.notifiers = list(notifiers)
        self.audit = audit_logger
        self.summary_only = bool(summary_only)

    def notify(self, arbiter: Dict[str, Any], explanation: Dict[str, Any], target: str, *, decision_id: str = '') -> Dict[str, Any]:
        # decision_id is the trace_id of the decision's action_decision audit
        # record. It is carried into the enqueue record and the notification
        # audit record so each names the decision it alerts on (Edge#414,
        # SO-03). It does not change what is sent, to whom, or whether.
        decision_id = str(decision_id or '')
        action = str(arbiter.get('action') or '')
        if action != 'notify':
            result = {'ok': False, 'skipped': True, 'reason': 'action_not_notify'}
            record = self._record(
                target, 'skipped', result, {'decision_id': decision_id, 'alert_class': '', 'alert_class_rule': ALERT_CLASS_RULE}
            )
            return dict(result, **record)

        payload = {
            'action': action,
            'reason': str(arbiter.get('reason') or ''),
            'target': target,
            'evidence_ids': [str(x) for x in arbiter.get('chosen_evidence_ids', []) if str(x)],
            'level': 'critical' if 'high' in str(arbiter.get('reason') or '') else 'warning',
            'operator_wording': str(explanation.get('operator_wording') or ''),
            'incident_id': str((((explanation.get('why_chosen') or {}) if isinstance(explanation.get('why_chosen'), dict) else {}).get('incident_summary') or {}).get('incident_id') or ''),
            'runbook_candidate_id': str((((explanation.get('why_chosen') or {}) if isinstance(explanation.get('why_chosen'), dict) else {}).get('runbook_support') or {}).get('runbook_candidate_id') or ''),
            'decision_id': decision_id,
        }
        # Record-only: computed after the level, read by nothing below.
        payload['alert_class'] = classify_alert(action, payload['level'])
        record_fields = {
            'decision_id': decision_id,
            'alert_class': payload['alert_class'],
            'alert_class_rule': ALERT_CLASS_RULE,
        }

        send_payload = self._payload_for_adapter(payload)
        errors: List[str] = []
        attempts: List[Dict[str, Any]] = []
        for notifier in self.notifiers:
            adapter = self._adapter_name(notifier)
            # Only the send is retried on the next adapter. Recording the
            # outcome is separate: a record that fails must neither re-send an
            # alert that went out nor turn it into a failure.
            try:
                result = notifier.send(send_payload)
            except Exception as exc:
                errors.append(str(exc))
                attempts.append({'adapter': adapter, 'ok': False, 'error': str(exc)})
                continue
            ack = result.get('status')
            attempts.append({'adapter': adapter, 'ok': True, 'ack': ack})
            audit_result = {
                'ok': True,
                'adapter': result.get('adapter') or adapter,
                'ack': ack,
                'attempts': attempts,
                'payload': send_payload,
            }
            return dict(audit_result, **self._record(target, 'sent', audit_result, record_fields))

        failed = {'ok': False, 'errors': errors, 'attempts': attempts, 'payload': send_payload}
        return dict(failed, **self._record(target, 'failed', failed, record_fields))

    def _record(self, target: str, decision: str, payload: Dict[str, Any], fields: Dict[str, Any]) -> Dict[str, Any]:
        """Write the notification audit record; report, never raise, whether it
        is durable. 'audit_record' is 'durable', 'not_durable' (written, but
        fsync failed or the file system cannot sync) or 'not_written'."""

        kwargs = dict(trace_id=target, source='decision_notifier', decision=decision, payload=payload, **fields)
        try:
            reporting = getattr(self.audit, 'log_reporting_durability', None)
            if reporting is None:  # an audit logger that cannot say
                self.audit.log('notification', **kwargs)
                durability = 'durability_unknown'
            else:
                _, durability = reporting('notification', **kwargs)
        except OSError as exc:
            # AuditDurabilityError: appended to the chain, not durable.
            # Any other OSError: the append itself failed.
            from azazel_edge.audit import AuditDurabilityError

            state = 'not_durable' if isinstance(exc, AuditDurabilityError) else 'not_written'
            logging.getLogger(__name__).error('notification audit record %s: %s', state, exc)
            return {'audit_record': state, 'audit_error': str(exc)}
        except Exception as exc:
            logging.getLogger(__name__).error('notification audit record not_written: %s', exc)
            return {'audit_record': 'not_written', 'audit_error': str(exc)}
        if durability == DURABILITY_FSYNCED:
            return {'audit_record': 'durable'}
        return {'audit_record': 'not_durable', 'audit_error': durability}

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
