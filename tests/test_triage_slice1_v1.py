from __future__ import annotations

import tempfile
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.triage import TriageSessionStore, classify_intent_candidates, list_flows, load_flow
from azazel_edge.triage.loader import validate_flow
from azazel_edge.triage.types import TriageFlow


class TriageSlice1Tests(unittest.TestCase):
    def test_builtin_flows_load(self) -> None:
        flows = list_flows()
        self.assertGreaterEqual(len(flows), 7)
        ids = {flow.flow_id for flow in flows}
        self.assertIn("wifi_connectivity", ids)
        self.assertIn("dns_resolution", ids)
        self.assertIn("service_status", ids)

    def test_flow_validation_rejects_unknown_target(self) -> None:
        payload = {
            "flow_id": "broken_flow",
            "version": 1,
            "intents": ["wifi_connectivity"],
            "label_i18n": {"ja": "壊れた", "en": "Broken"},
            "entry_state": "start",
            "steps": [
                {
                    "step_id": "start",
                    "question_i18n": {"ja": "?", "en": "?"},
                    "answer_type": "boolean",
                    "choices": [{"value": "yes", "label_i18n": {"ja": "はい", "en": "Yes"}}],
                    "transition_map": {"yes": "missing_state"},
                    "fallback_transition": "missing_state",
                }
            ],
            "diagnostic_states": [],
        }
        with self.assertRaisesRegex(ValueError, "invalid_transition_target"):
            validate_flow(TriageFlow.from_dict(payload))

    def test_session_store_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = TriageSessionStore(base_dir=tmp)
            session = store.create(audience="temporary", lang="ja", selected_intent="wifi_connectivity", current_state="scope")
            session.answers["scope"] = "single"
            store.save(session)
            loaded = store.get(session.session_id)
            assert loaded is not None
            self.assertEqual(loaded.selected_intent, "wifi_connectivity")
            self.assertEqual(loaded.current_state, "scope")
            self.assertEqual(loaded.answers.get("scope"), "single")
            self.assertTrue(store.delete(session.session_id))
            self.assertIsNone(store.get(session.session_id))

    def test_classifier_ranks_dns(self) -> None:
        candidates = classify_intent_candidates("DNS が引けず、名前解決だけ失敗しています", lang="ja")
        self.assertGreaterEqual(len(candidates), 1)
        self.assertEqual(candidates[0].intent_id, "dns_resolution")

    def test_classifier_ranks_portal(self) -> None:
        candidates = classify_intent_candidates("portal login page does not appear on the new device", lang="en")
        self.assertGreaterEqual(len(candidates), 1)
        self.assertEqual(candidates[0].intent_id, "portal_access")

    def test_classifier_returns_two_candidates_for_ambiguous_network_issue(self) -> None:
        candidates = classify_intent_candidates("Wi-Fi は見えるが internet に出られない", lang="ja", limit=2)
        ids = [item.intent_id for item in candidates]
        self.assertIn("wifi_connectivity", ids)
        self.assertIn("uplink_reachability", ids)
        self.assertLessEqual(len(candidates), 2)

    def test_load_specific_flow(self) -> None:
        flow = load_flow("wifi_onboarding")
        self.assertEqual(flow.entry_state, "device_type")
        self.assertEqual(flow.intents, ["wifi_onboarding"])
        self.assertGreaterEqual(len(flow.steps), 2)

    def test_boolean_choice_labels_are_normalized_to_strings(self) -> None:
        flow = load_flow("dns_resolution")
        step = flow.steps[0]
        self.assertEqual(step.answer_type, "boolean")
        self.assertEqual(step.choices[0]["label_i18n"]["en"], "Yes")
        self.assertEqual(step.choices[1]["label_i18n"]["en"], "No")


if __name__ == "__main__":
    unittest.main()
