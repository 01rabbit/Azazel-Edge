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

from azazel_edge.ai_governance import AIGovernance
from azazel_edge.audit import P0AuditLogger


class AIGovernanceV1Tests(unittest.TestCase):
    def test_only_allowed_conditions_can_invoke_ai(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gov = AIGovernance(P0AuditLogger(Path(tmp) / 'ai.jsonl'))
            result = gov.invoke(
                context={'trace_id': 't1', 'source': 'suricata_eve', 'intent': 'advice', 'risk_band': 'low'},
                raw_payload={'trace_id': 't1', 'source': 'suricata_eve', 'summary': 'x', 'raw_log': 'secret'},
                invoker=lambda payload: {'advice': 'should not run', 'summary': '', 'candidate': ''},
            )
        self.assertEqual(result['advice'], '')

    def test_raw_log_is_not_forwarded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gov = AIGovernance(P0AuditLogger(Path(tmp) / 'ai.jsonl'))
            seen = {}

            def invoker(payload: dict) -> dict:
                seen.update(payload)
                return {'advice': 'ok', 'summary': 'ok', 'candidate': 'rb.test'}

            gov.invoke(
                context={'trace_id': 't2', 'source': 'ops_comm', 'intent': 'summary'},
                raw_payload={'trace_id': 't2', 'source': 'ops_comm', 'summary': 'clean', 'raw_log': 'secret', 'line': 'forbidden'},
                invoker=invoker,
            )
        self.assertNotIn('raw_log', seen)
        self.assertNotIn('line', seen)

    def test_invalid_output_falls_back_and_is_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / 'ai.jsonl'
            gov = AIGovernance(P0AuditLogger(log_path))
            result = gov.invoke(
                context={'trace_id': 't3', 'source': 'mattermost', 'intent': 'candidate'},
                raw_payload={'trace_id': 't3', 'source': 'mattermost', 'summary': 'Need candidate'},
                invoker=lambda payload: {'unexpected': 'bad'},
            )
            lines = [json.loads(line) for line in log_path.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(result['summary'], 'Need candidate')
        self.assertEqual(lines[-1]['decision'], 'fallback')
        self.assertEqual(lines[-1]['kind'], 'ai_assist')


if __name__ == '__main__':
    unittest.main()
