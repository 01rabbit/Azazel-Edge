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
from azazel_edge.triage import TriageFlowEngine, TriageSessionStore


class TriageSlice6Tests(unittest.TestCase):
    def test_audit_logs_full_transition_series(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            audit = P0AuditLogger(root / 'triage-audit.jsonl')
            engine = TriageFlowEngine(store=TriageSessionStore(base_dir=root / 'sessions'), audit_logger=audit)

            progress = engine.start('dns_resolution', audience='temporary', lang='en')
            session_id = progress.session.session_id
            engine.answer(session_id, 'yes')
            engine.answer(session_id, 'many')

            records = [json.loads(line) for line in (root / 'triage-audit.jsonl').read_text(encoding='utf-8').splitlines()]

        kinds = [record['kind'] for record in records]
        self.assertEqual(
            kinds,
            [
                'triage_session_started',
                'triage_step_answered',
                'triage_state_changed',
                'triage_step_answered',
                'triage_state_changed',
                'triage_runbook_proposed',
                'triage_completed',
            ],
        )
        self.assertEqual(records[-1]['diagnostic_state'], 'dns_global_failure')

    def test_user_cannot_answer_records_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            audit = P0AuditLogger(root / 'triage-audit.jsonl')
            engine = TriageFlowEngine(store=TriageSessionStore(base_dir=root / 'sessions'), audit_logger=audit)

            progress = engine.start('wifi_reconnect', audience='temporary', lang='ja')
            engine.answer(progress.session.session_id, 'maybe')

            records = [json.loads(line) for line in (root / 'triage-audit.jsonl').read_text(encoding='utf-8').splitlines()]

        self.assertIn('triage_handoff', [record['kind'] for record in records])
        handoff = next(record for record in records if record['kind'] == 'triage_handoff')
        self.assertEqual(handoff['reason'], 'insufficient_user_input')
        self.assertEqual(handoff['target'], 'operator')


if __name__ == '__main__':
    unittest.main()
