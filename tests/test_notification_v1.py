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
from azazel_edge.notify import DecisionNotifier, NtfyNotifier


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


if __name__ == '__main__':
    unittest.main()
