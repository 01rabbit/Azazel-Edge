from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.audit import P0AuditLogger
from azazel_edge.notify import DecisionNotifier, MattermostNotifier, NtfyNotifier, SmtpNotifier, WebhookNotifier


class _DummyResponse:
    def __init__(self, status: int = 200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class NotificationV1Tests(unittest.TestCase):
    def test_notify_action_sends_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch('azazel_edge.notify.delivery.urlopen', return_value=_DummyResponse(200)):
            logger = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            notifier = DecisionNotifier([NtfyNotifier('http://127.0.0.1:8081', 'azazel-alerts')], logger)
            result = notifier.notify(
                arbiter={'action': 'notify', 'reason': 'soc_high_but_noc_fragile', 'chosen_evidence_ids': ['ev-1']},
                explanation={'operator_wording': 'Notify operator now.', 'why_chosen': {'incident_summary': {'incident_id': 'incident:abc123'}}},
                target='edge-uplink',
            )
            lines = [json.loads(line) for line in (Path(tmp) / 'audit.jsonl').read_text(encoding='utf-8').splitlines()]
        self.assertTrue(result['ok'])
        self.assertEqual(lines[-1]['kind'], 'notification')
        self.assertEqual(lines[-1]['decision'], 'sent')
        self.assertEqual(lines[-1]['payload']['payload']['target'], 'edge-uplink')
        self.assertEqual(lines[-1]['payload']['payload']['incident_id'], 'incident:abc123')
        self.assertEqual(lines[-1]['payload']['payload']['runbook_candidate_id'], '')

    def test_non_notify_action_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logger = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            notifier = DecisionNotifier([], logger)
            result = notifier.notify(
                arbiter={'action': 'observe', 'reason': 'baseline', 'chosen_evidence_ids': []},
                explanation={'operator_wording': 'No action.'},
                target='edge-uplink',
            )
        self.assertTrue(result['skipped'])

    def test_notification_failure_is_handled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch('azazel_edge.notify.delivery.urlopen', side_effect=RuntimeError('network down')):
            logger = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            notifier = DecisionNotifier([NtfyNotifier('http://127.0.0.1:8081', 'azazel-alerts')], logger)
            result = notifier.notify(
                arbiter={'action': 'notify', 'reason': 'noc_degraded_requires_operator_attention', 'chosen_evidence_ids': ['ev-1']},
                explanation={'operator_wording': 'Notify operator now.'},
                target='edge-uplink',
            )
        self.assertFalse(result['ok'])
        self.assertTrue(result['errors'])

    def test_notifier_uses_failover_order_and_records_attempt_ack(self) -> None:
        calls = []

        def _fake_urlopen(req, timeout=5):
            url = str(getattr(req, 'full_url', ''))
            calls.append(url)
            if 'mattermost.invalid' in url:
                raise RuntimeError('mattermost down')
            return _DummyResponse(202)

        with tempfile.TemporaryDirectory() as tmp, patch('azazel_edge.notify.delivery.urlopen', side_effect=_fake_urlopen):
            logger = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            notifier = DecisionNotifier(
                [
                    MattermostNotifier('http://mattermost.invalid/hook'),
                    NtfyNotifier('http://127.0.0.1:8081', 'azazel-alerts'),
                    WebhookNotifier('http://webhook.invalid/endpoint'),
                ],
                logger,
            )
            result = notifier.notify(
                arbiter={'action': 'notify', 'reason': 'soc_high_but_noc_fragile', 'chosen_evidence_ids': ['ev-1']},
                explanation={'operator_wording': 'Notify operator now.'},
                target='edge-uplink',
            )
            rows = [json.loads(line) for line in (Path(tmp) / 'audit.jsonl').read_text(encoding='utf-8').splitlines()]

        self.assertTrue(result['ok'])
        self.assertEqual(result['adapter'], 'ntfy')
        self.assertEqual(result['ack'], 202)
        self.assertEqual(result['attempts'][0]['adapter'], 'mattermost')
        self.assertFalse(result['attempts'][0]['ok'])
        self.assertEqual(result['attempts'][1]['adapter'], 'ntfy')
        self.assertTrue(result['attempts'][1]['ok'])
        self.assertEqual(rows[-1]['payload']['attempts'][1]['ack'], 202)
        self.assertEqual(len(calls), 2)

    def test_smtp_notifier_reports_ack(self) -> None:
        class _FakeSMTP:
            def __init__(self, host, port, timeout=5):
                self.host = host
                self.port = port
                self.timeout = timeout
                self.sent = False

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def send_message(self, msg):
                self.sent = True

        with patch('azazel_edge.notify.delivery.smtplib.SMTP', _FakeSMTP):
            notifier = SmtpNotifier('127.0.0.1', 25, 'azazel@example.local', 'ops@example.local')
            result = notifier.send({'action': 'notify', 'target': 'edge-uplink', 'reason': 'test', 'evidence_ids': [], 'level': 'warning'})
        self.assertTrue(result['ok'])
        self.assertEqual(result['adapter'], 'smtp')
        self.assertEqual(result['status'], 250)

    def test_summary_only_mode_strips_evidence_ids(self) -> None:
        captured = {}

        class _CaptureNotifier:
            def send(self, payload):
                captured.update(payload)
                return {'ok': True, 'adapter': 'capture', 'status': 200}

        with tempfile.TemporaryDirectory() as tmp:
            logger = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            notifier = DecisionNotifier([_CaptureNotifier()], logger, summary_only=True)
            result = notifier.notify(
                arbiter={'action': 'notify', 'reason': 'soc_high_but_noc_fragile', 'chosen_evidence_ids': ['ev-1', 'ev-2']},
                explanation={'operator_wording': 'Notify operator now.'},
                target='edge-uplink',
            )
        self.assertTrue(result['ok'])
        self.assertEqual(captured.get('evidence_ids'), [])

    def test_summary_only_mode_truncates_operator_wording(self) -> None:
        captured = {}

        class _CaptureNotifier:
            def send(self, payload):
                captured.update(payload)
                return {'ok': True, 'adapter': 'capture', 'status': 200}

        long_text = 'x' * 260
        with tempfile.TemporaryDirectory() as tmp:
            logger = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            notifier = DecisionNotifier([_CaptureNotifier()], logger, summary_only=True)
            result = notifier.notify(
                arbiter={'action': 'notify', 'reason': 'soc_high_but_noc_fragile', 'chosen_evidence_ids': ['ev-1']},
                explanation={'operator_wording': long_text},
                target='edge-uplink',
            )
        self.assertTrue(result['ok'])
        self.assertEqual(len(str(captured.get('operator_wording') or '')), 200)


if __name__ == '__main__':
    unittest.main()
