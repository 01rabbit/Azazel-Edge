"""
Black Hat Europe Issue 01 — Auditable Decision Field Inventory (2026-06-10 manual audit).

This test codifies the required auditable fields so their presence cannot silently regress.

Arbiter output fields (ActionArbiter.decide result):
  - rejected_alternatives   list   non-empty for redirect decisions
  - policy.version          str    non-empty
  - policy.hash             str    non-empty
  - chosen_evidence_ids     list
  - release_condition       str    non-empty

Explanation record fields (DecisionExplainer.explain result, format_version='v2'):
  - format_version          str    == 'v2'
  - selected_action         str    matches arbiter action
  - rejected_actions        list   non-empty for redirect decisions
  - why_not_others          list   non-empty for redirect decisions
  - release_condition       str    non-empty
  - policy_profile          str    == arbiter policy.version
  - config_hash             str    non-empty, == arbiter policy.hash
  - trace_id                str    matches caller-supplied trace_id
  - evidence_ids            list
  - operator_wording        str    non-empty
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.explanations import DecisionExplainer


def _dim(score: int, label: str, evidence_ids: list) -> dict:
    return {'score': score, 'label': label, 'reasons': [], 'evidence_ids': evidence_ids}


def _redirect_noc() -> dict:
    """All NOC dimensions healthy — required so redirect is selected over notify."""
    return {
        'availability': _dim(95, 'good', ['noc-a']),
        'path_health': _dim(95, 'good', ['noc-p']),
        'device_health': _dim(95, 'good', ['noc-d']),
        'client_health': _dim(95, 'good', ['noc-c']),
        'summary': {'status': 'good', 'reasons': []},
        'evidence_ids': ['noc-a', 'noc-p', 'noc-d', 'noc-c'],
    }


def _redirect_soc() -> dict:
    """High-suspicion SOC signal that drives a redirect decision."""
    return {
        'suspicion': _dim(92, 'critical', ['soc-s']),
        'confidence': _dim(84, 'critical', ['soc-c']),
        'technique_likelihood': _dim(40, 'medium', ['soc-t']),
        'blast_radius': _dim(72, 'high', ['soc-b']),
        'summary': {'status': 'critical', 'reasons': []},
        'evidence_ids': ['soc-s', 'soc-c', 'soc-t', 'soc-b'],
    }


class AuditableDecisionFieldsV1Tests(unittest.TestCase):
    """Verify all auditable fields required by BHEu issue 01 are present with correct types."""

    def setUp(self) -> None:
        self.noc = _redirect_noc()
        self.soc = _redirect_soc()
        self.arbiter_result = ActionArbiter().decide(
            self.noc,
            self.soc,
            client_impact={'score': 20, 'critical_client_count': 0},
        )
        self.explanation = DecisionExplainer(
            output_path=Path('/tmp/unused-decision-explanations.jsonl')
        ).explain(
            noc=self.noc,
            soc=self.soc,
            arbiter=self.arbiter_result,
            target='edge-uplink',
            trace_id='trace-bheu-01',
            persist=False,
        )

    # ------------------------------------------------------------------
    # Arbiter output field assertions
    # ------------------------------------------------------------------

    def test_arbiter_action_is_redirect(self) -> None:
        self.assertEqual(self.arbiter_result['action'], 'redirect')

    def test_arbiter_rejected_alternatives_is_nonempty_list(self) -> None:
        ra = self.arbiter_result['rejected_alternatives']
        self.assertIsInstance(ra, list)
        self.assertGreater(len(ra), 0, 'redirect decision must have at least one rejected alternative')

    def test_arbiter_policy_version_is_nonempty_string(self) -> None:
        v = self.arbiter_result['policy']['version']
        self.assertIsInstance(v, str)
        self.assertTrue(v, 'policy.version must be non-empty')

    def test_arbiter_policy_hash_is_nonempty_string(self) -> None:
        h = self.arbiter_result['policy']['hash']
        self.assertIsInstance(h, str)
        self.assertTrue(h, 'policy.hash must be non-empty')

    def test_arbiter_chosen_evidence_ids_is_list(self) -> None:
        self.assertIsInstance(self.arbiter_result['chosen_evidence_ids'], list)

    def test_arbiter_release_condition_is_nonempty_string(self) -> None:
        rc = self.arbiter_result['release_condition']
        self.assertIsInstance(rc, str)
        self.assertTrue(rc, 'release_condition must be non-empty')

    # ------------------------------------------------------------------
    # Explanation record field assertions
    # ------------------------------------------------------------------

    def test_explanation_format_version_is_v2(self) -> None:
        self.assertEqual(self.explanation['format_version'], 'v2')

    def test_explanation_selected_action_matches_arbiter(self) -> None:
        self.assertIsInstance(self.explanation['selected_action'], str)
        self.assertEqual(self.explanation['selected_action'], self.arbiter_result['action'])

    def test_explanation_rejected_actions_is_nonempty_list(self) -> None:
        ra = self.explanation['rejected_actions']
        self.assertIsInstance(ra, list)
        self.assertGreater(len(ra), 0, 'redirect explanation must list at least one rejected action')

    def test_explanation_why_not_others_is_list(self) -> None:
        self.assertIsInstance(self.explanation['why_not_others'], list)

    def test_explanation_release_condition_is_nonempty_string(self) -> None:
        rc = self.explanation['release_condition']
        self.assertIsInstance(rc, str)
        self.assertTrue(rc, 'explanation release_condition must be non-empty')

    def test_explanation_policy_profile_matches_arbiter_version(self) -> None:
        self.assertIsInstance(self.explanation['policy_profile'], str)
        self.assertEqual(self.explanation['policy_profile'], self.arbiter_result['policy']['version'])

    def test_explanation_config_hash_matches_arbiter_and_nonempty(self) -> None:
        ch = self.explanation['config_hash']
        self.assertIsInstance(ch, str)
        self.assertTrue(ch, 'config_hash must be non-empty')
        self.assertEqual(ch, self.arbiter_result['policy']['hash'])

    def test_explanation_trace_id_matches_caller_value(self) -> None:
        self.assertIsInstance(self.explanation['trace_id'], str)
        self.assertEqual(self.explanation['trace_id'], 'trace-bheu-01')

    def test_explanation_evidence_ids_is_list(self) -> None:
        self.assertIsInstance(self.explanation['evidence_ids'], list)

    def test_explanation_operator_wording_is_nonempty_string(self) -> None:
        ow = self.explanation['operator_wording']
        self.assertIsInstance(ow, str)
        self.assertTrue(ow, 'operator_wording must be non-empty')


if __name__ == '__main__':
    unittest.main()
