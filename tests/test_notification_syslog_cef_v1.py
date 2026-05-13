from __future__ import annotations

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
from azazel_edge.notify import DecisionNotifier, NotificationError, SyslogCEFNotifier


class NotificationSyslogCefV1Tests(unittest.TestCase):
    def test_syslog_cef_send_builds_valid_cef_format(self) -> None:
        with patch.object(SyslogCEFNotifier, '__init__', lambda self, host, port=514, protocol='udp': None):
            notifier = SyslogCEFNotifier('127.0.0.1')
            notifier.host = '127.0.0.1'

            class _Handler:
                def emit(self, _record):
                    return None

            notifier._handler = _Handler()
            result = notifier.send({'action': 'notify', 'level': 'warning'})
        self.assertTrue(result['ok'])
        self.assertTrue(str(result['cef']).startswith('CEF:0|Azazel-Edge|'))

    def test_syslog_cef_missing_host_raises(self) -> None:
        with patch.object(SyslogCEFNotifier, '__init__', lambda self, host, port=514, protocol='udp': None):
            notifier = SyslogCEFNotifier('')
            notifier.host = ''
            notifier._handler = object()
            with self.assertRaises(NotificationError):
                notifier.send({'action': 'notify'})

    def test_syslog_cef_severity_map_critical(self) -> None:
        with patch.object(SyslogCEFNotifier, '__init__', lambda self, host, port=514, protocol='udp': None):
            notifier = SyslogCEFNotifier('127.0.0.1')
            line = notifier._build_cef({'action': 'notify', 'level': 'critical'})
        self.assertIn('|10|', line)

    def test_syslog_cef_integrates_with_decision_notifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(SyslogCEFNotifier, '__init__', lambda self, host, port=514, protocol='udp': None):
                notifier = SyslogCEFNotifier('127.0.0.1')
                notifier.host = '127.0.0.1'
                emit_called = {'ok': False}

                class _Handler:
                    def emit(self, _record):
                        emit_called['ok'] = True

                notifier._handler = _Handler()
                logger = P0AuditLogger(Path(tmp) / 'audit.jsonl')
                decision = DecisionNotifier([notifier], logger)
                result = decision.notify(
                    arbiter={'action': 'notify', 'reason': 'soc_high_but_noc_fragile', 'chosen_evidence_ids': ['ev-1']},
                    explanation={'operator_wording': 'Notify operator now.'},
                    target='edge-uplink',
                )
        self.assertTrue(result['ok'])
        self.assertTrue(emit_called['ok'])


if __name__ == '__main__':
    unittest.main()
