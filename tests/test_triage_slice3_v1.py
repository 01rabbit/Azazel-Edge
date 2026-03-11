from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.triage import TriageFlowEngine, TriageSessionStore


class TriageSlice3Tests(unittest.TestCase):
    def test_start_returns_entry_step(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = TriageFlowEngine(store=TriageSessionStore(base_dir=tmp))
            progress = engine.start('wifi_connectivity', audience='temporary', lang='ja')
            self.assertFalse(progress.completed)
            self.assertEqual(progress.session.selected_intent, 'wifi_connectivity')
            self.assertEqual(progress.next_step.step_id, 'scope')

    def test_answer_walks_to_next_step(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = TriageFlowEngine(store=TriageSessionStore(base_dir=tmp))
            progress = engine.start('dns_resolution', audience='temporary', lang='ja')
            step = progress.next_step
            self.assertEqual(step.step_id, 'internet_vs_name')
            progress = engine.answer(progress.session.session_id, 'yes')
            self.assertFalse(progress.completed)
            self.assertEqual(progress.next_step.step_id, 'resolver_scope')

    def test_answer_reaches_diagnostic_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = TriageFlowEngine(store=TriageSessionStore(base_dir=tmp))
            progress = engine.start('portal_access', audience='temporary', lang='en')
            progress = engine.answer(progress.session.session_id, 'yes')
            self.assertTrue(progress.completed)
            self.assertEqual(progress.session.status, 'diagnostic_ready')
            self.assertEqual(progress.diagnostic_state.state_id, 'portal_trigger_likely')

    def test_resume_returns_saved_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = TriageFlowEngine(store=TriageSessionStore(base_dir=tmp))
            progress = engine.start('service_status', audience='professional', lang='ja')
            resumed = engine.resume(progress.session.session_id)
            self.assertEqual(resumed.next_step.step_id, 'symptom_scope')

    def test_boolean_localization_normalizes_japanese_answer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            engine = TriageFlowEngine(store=TriageSessionStore(base_dir=tmp))
            progress = engine.start('portal_access', audience='temporary', lang='ja')
            progress = engine.answer(progress.session.session_id, 'はい')
            self.assertTrue(progress.completed)
            self.assertEqual(progress.diagnostic_state.state_id, 'portal_trigger_likely')


if __name__ == '__main__':
    unittest.main()
