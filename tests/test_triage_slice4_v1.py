from __future__ import annotations

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
from azazel_edge.triage import TriageFlowEngine, TriageSessionStore, select_noc_runbook_support, select_runbooks_for_diagnostic_state


class TriageSlice4Tests(unittest.TestCase):
    def test_selector_prefers_user_guidance_for_temporary_portal(self) -> None:
        payload = select_runbooks_for_diagnostic_state('portal_trigger_likely', audience='temporary', lang='ja')
        self.assertTrue(payload['ok'])
        self.assertGreaterEqual(len(payload['items']), 1)
        self.assertEqual(payload['items'][0]['runbook_id'], 'rb.user.portal-access-guide')

    def test_selector_prefers_operator_checks_for_professional_service(self) -> None:
        payload = select_runbooks_for_diagnostic_state('service_check_ready', audience='professional', lang='en')
        self.assertTrue(payload['ok'])
        ids = [item['runbook_id'] for item in payload['items']]
        self.assertIn('rb.noc.service.status.check', ids)

    def test_engine_persists_proposed_runbooks_when_diagnostic_is_reached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = TriageFlowEngine(store=TriageSessionStore(base_dir=tmp))
            progress = engine.start('portal_access', audience='temporary', lang='ja')
            progress = engine.answer(progress.session.session_id, 'yes')
            self.assertTrue(progress.completed)
            self.assertIn('rb.user.portal-access-guide', progress.session.proposed_runbooks)

    def test_noc_selector_prefers_dns_runbook_for_resolution_failure(self) -> None:
        payload = select_noc_runbook_support(
            {
                'incident_summary': {'incident_id': 'incident:abc123', 'probable_cause': 'resolution_failure'},
                'resolution_health': {'label': 'failed', 'failed_targets': ['example.com'], 'evidence_ids': ['ev-dns-1']},
                'affected_scope': {'affected_segments': ['lan-main']},
            },
            audience='professional',
            lang='en',
            context={'trace_id': 'trace-53a'},
        )
        self.assertTrue(payload['ok'])
        self.assertEqual(payload['runbook_candidate_id'], 'rb.noc.dns.failure.check')
        self.assertIn('resolver failures', payload['why_this_runbook'].lower())
        self.assertIn('ev-dns-1', payload['evidence_ids'])

    def test_noc_selector_keeps_runbook_deterministic_when_ai_helper_is_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = select_noc_runbook_support(
                {
                    'incident_summary': {'probable_cause': 'service_assurance_failure'},
                    'service_health': {'label': 'degraded', 'degraded_targets': ['resolver-tcp'], 'evidence_ids': ['ev-svc-1']},
                },
                audience='professional',
                lang='en',
                context={'trace_id': 'trace-53b'},
                ai_governance=AIGovernance(P0AuditLogger(Path(tmp) / 'ai.jsonl')),
                ai_invoker=lambda payload: {
                    'summary': 'Operator wording helper suggests confirming resolver service first.',
                    'advice': 'Keep the read-only service checks ahead of any action change.',
                    'candidate': 'rb.noc.default-route.check',
                    'runbook_candidates': ['rb.noc.default-route.check'],
                },
                source='dashboard',
            )
        self.assertEqual(payload['runbook_candidate_id'], 'rb.noc.service.status.check')
        self.assertTrue(payload['ai_used'])
        self.assertEqual(payload['operator_note'], 'Operator wording helper suggests confirming resolver service first.')


if __name__ == '__main__':
    unittest.main()
