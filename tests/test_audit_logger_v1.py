from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.audit import P0AuditLogger


class AuditLoggerV1Tests(unittest.TestCase):
    def test_logs_full_p0_series_with_common_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'audit.jsonl'
            logger = P0AuditLogger(path)
            logger.log_event_receive('trace-1', 'suricata_eve', event_id='ev-1')
            logger.log_evaluation('trace-1', 'noc_evaluator', result='ok')
            logger.log_action_decision('trace-1', 'action_arbiter', action='notify')
            logger.log_notification('trace-1', 'decision_notifier', status='sent')
            logger.log_ai_assist('trace-1', 'ai_governance', decision='adopted')
            records = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]

        self.assertEqual([record['kind'] for record in records], ['event_receive', 'evaluation', 'action_decision', 'notification', 'ai_assist'])
        for record in records:
            for field in ('ts', 'kind', 'trace_id', 'source'):
                self.assertIn(field, record)

    def test_invalid_kind_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logger = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            with self.assertRaises(ValueError):
                logger.log('invalid', trace_id='trace-1', source='x')


if __name__ == '__main__':
    unittest.main()
