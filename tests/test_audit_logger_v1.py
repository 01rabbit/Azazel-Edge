from __future__ import annotations

import json
import hashlib
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
            self.assertIn('chain_prev', record)
            self.assertIn('chain_hash', record)

    def test_chain_hash_links_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'audit.jsonl'
            logger = P0AuditLogger(path)
            logger.log_event_receive('trace-1', 'suricata_eve', event_id='ev-1')
            logger.log_action_decision('trace-1', 'arbiter', action='notify')
            rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]

        self.assertEqual(rows[0]['chain_prev'], '')
        self.assertEqual(rows[1]['chain_prev'], rows[0]['chain_hash'])
        for row in rows:
            without_hash = dict(row)
            expected = row['chain_hash']
            without_hash.pop('chain_hash', None)
            canon = json.dumps(without_hash, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('utf-8')
            self.assertEqual(expected, hashlib.sha256(canon).hexdigest())

    def test_verify_chain_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'audit.jsonl'
            logger = P0AuditLogger(path)
            logger.log_event_receive('trace-1', 'suricata_eve', event_id='ev-1')
            logger.log_action_decision('trace-1', 'arbiter', action='notify')
            self.assertTrue(P0AuditLogger.verify_chain(path)['ok'])

            rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
            rows[1]['action'] = 'isolate'
            path.write_text('\n'.join(json.dumps(row, separators=(',', ':')) for row in rows) + '\n', encoding='utf-8')
            result = P0AuditLogger.verify_chain(path)
            self.assertFalse(result['ok'])
            self.assertIn('chain_hash_mismatch_at:2', result['error'])

    def test_invalid_kind_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logger = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            with self.assertRaises(ValueError):
                logger.log('invalid', trace_id='trace-1', source='x')


if __name__ == '__main__':
    unittest.main()
