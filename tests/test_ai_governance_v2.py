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


class AIGovernanceV2Tests(unittest.TestCase):
    def test_ai_can_return_runbook_and_attack_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gov = AIGovernance(P0AuditLogger(Path(tmp) / 'ai.jsonl'))
            result = gov.invoke(
                context={'trace_id': 't24a', 'source': 'ops_comm', 'intent': 'candidate'},
                raw_payload={'trace_id': 't24a', 'source': 'ops_comm', 'summary': 'Need triage support'},
                invoker=lambda payload: {
                    'advice': 'Use the DNS runbook first.',
                    'summary': 'Likely DNS path issue.',
                    'candidate': 'rb.noc.dns.failure.check',
                    'runbook_candidates': ['rb.noc.dns.failure.check', 'rb.noc.default-route.check'],
                    'attack_candidates': ['T1071 Application Layer Protocol'],
                },
            )
        self.assertEqual(result['candidate'], 'rb.noc.dns.failure.check')
        self.assertTrue(result['runbook_candidates'])
        self.assertTrue(result['attack_candidates'])

    def test_ambiguous_suricata_candidate_support_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gov = AIGovernance(P0AuditLogger(Path(tmp) / 'ai.jsonl'))
            result = gov.invoke(
                context={'trace_id': 't24b', 'source': 'suricata_eve', 'intent': 'candidate', 'risk_band': 'ambiguous'},
                raw_payload={'trace_id': 't24b', 'source': 'suricata_eve', 'summary': 'Ambiguous beacon event'},
                invoker=lambda payload: {
                    'advice': '',
                    'summary': 'Suspicious but not confirmed.',
                    'candidate': 'rb.soc.alert.triage.basic',
                    'runbook_candidates': ['rb.soc.alert.triage.basic'],
                    'attack_candidates': ['T1071 Application Layer Protocol'],
                },
            )
        self.assertEqual(result['candidate'], 'rb.soc.alert.triage.basic')

    def test_rejected_output_is_logged_before_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / 'ai.jsonl'
            gov = AIGovernance(P0AuditLogger(log_path))
            result = gov.invoke(
                context={'trace_id': 't24c', 'source': 'mattermost', 'intent': 'candidate'},
                raw_payload={'trace_id': 't24c', 'source': 'mattermost', 'summary': 'Need candidate'},
                invoker=lambda payload: {
                    'advice': 'x',
                    'summary': 'y',
                    'candidate': 'z',
                    'runbook_candidates': 'not-a-list',
                },
            )
            rows = [json.loads(line) for line in log_path.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(result['runbook_candidates'], [])
        self.assertEqual(rows[-2]['decision'], 'rejected')
        self.assertEqual(rows[-1]['decision'], 'fallback')


if __name__ == '__main__':
    unittest.main()
