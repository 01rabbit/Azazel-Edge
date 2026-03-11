from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.triage import TriageFlowEngine, TriageSessionStore, select_runbooks_for_diagnostic_state


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


if __name__ == '__main__':
    unittest.main()
