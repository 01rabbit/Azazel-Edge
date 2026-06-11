from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

from azazel_edge.explanations import DecisionExplainer, validate_v2_explanation
from azazel_edge.audit import P0AuditLogger


# ---------------------------------------------------------------------------
# Helpers: build inputs that produce the redirect decision path
# (NOC all 'good', SOC suspicion=92/critical, confidence=84/critical,
#  blast=72/high, client_impact={'score':20,'critical_client_count':0})
# ---------------------------------------------------------------------------

def _dim(score: int, label: str, evidence_ids: list) -> dict:
    return {'score': score, 'label': label, 'reasons': [], 'evidence_ids': evidence_ids}


def _noc_good() -> dict:
    return {
        'availability': _dim(95, 'good', ['noc-a']),
        'path_health': _dim(95, 'good', ['noc-p']),
        'device_health': _dim(95, 'good', ['noc-d']),
        'client_health': _dim(95, 'good', ['noc-c']),
        'summary': {'status': 'good', 'reasons': []},
        'evidence_ids': ['noc-a', 'noc-p', 'noc-d', 'noc-c'],
    }


def _soc_critical() -> dict:
    return {
        'suspicion': _dim(92, 'critical', ['soc-s']),
        'confidence': _dim(84, 'critical', ['soc-c']),
        'technique_likelihood': _dim(60, 'high', ['soc-t']),
        'blast_radius': _dim(72, 'high', ['soc-b']),
        'summary': {'status': 'critical', 'reasons': []},
        'evidence_ids': ['soc-s', 'soc-c', 'soc-t', 'soc-b'],
    }


def _make_redirect_record(trace_id: str = 'trace-schema-v1-test') -> dict:
    """Build a real v2 explanation via the redirect decision path."""
    import tempfile
    from azazel_edge.arbiter import ActionArbiter

    arbiter_result = ActionArbiter().decide(
        _noc_good(),
        _soc_critical(),
        client_impact={'score': 20, 'critical_client_count': 0},
    )
    with tempfile.TemporaryDirectory() as tmp:
        explainer = DecisionExplainer(
            output_path=Path(tmp) / 'test-schema-explanations.jsonl'
        )
        return explainer.explain(
            noc=_noc_good(),
            soc=_soc_critical(),
            arbiter=arbiter_result,
            target='test-edge',
            trace_id=trace_id,
            persist=False,
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class ValidateV2ExplanationTests(unittest.TestCase):

    def setUp(self) -> None:
        # Build the canonical redirect record once; individual tests work
        # on copies so the shared instance stays unmodified.
        self._canonical = _make_redirect_record()

    # -- happy-path ----------------------------------------------------------

    def test_valid_redirect_record_passes(self) -> None:
        """A real v2 redirect record must produce no validation errors."""
        errors = validate_v2_explanation(self._canonical)
        self.assertEqual(
            errors, [],
            msg=f"Expected no errors for a valid record, got: {errors}",
        )

    # -- missing required fields ---------------------------------------------

    def test_missing_config_hash_returns_error(self) -> None:
        bad = copy.deepcopy(self._canonical)
        del bad['config_hash']
        errors = validate_v2_explanation(bad)
        self.assertTrue(
            len(errors) > 0,
            msg="Expected errors when config_hash is missing",
        )
        self.assertTrue(
            any('config_hash' in e for e in errors),
            msg=f"Expected an error mentioning 'config_hash', got: {errors}",
        )

    def test_missing_format_version_returns_error(self) -> None:
        bad = copy.deepcopy(self._canonical)
        del bad['format_version']
        errors = validate_v2_explanation(bad)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('format_version' in e for e in errors))

    def test_missing_trust_capsule_returns_error(self) -> None:
        bad = copy.deepcopy(self._canonical)
        del bad['trust_capsule']
        errors = validate_v2_explanation(bad)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('trust_capsule' in e for e in errors))

    # -- wrong format_version value ------------------------------------------

    def test_wrong_format_version_value_returns_error(self) -> None:
        bad = copy.deepcopy(self._canonical)
        bad['format_version'] = 'v1'
        errors = validate_v2_explanation(bad)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('format_version' in e for e in errors))

    # -- wrong types ---------------------------------------------------------

    def test_evidence_ids_wrong_type_returns_error(self) -> None:
        """evidence_ids must be a list; a string value should be flagged."""
        bad = copy.deepcopy(self._canonical)
        bad['evidence_ids'] = 'x'
        errors = validate_v2_explanation(bad)
        self.assertTrue(
            len(errors) > 0,
            msg="Expected errors when evidence_ids has wrong type",
        )
        self.assertTrue(
            any('evidence_ids' in e for e in errors),
            msg=f"Expected an error mentioning 'evidence_ids', got: {errors}",
        )

    def test_why_chosen_wrong_type_returns_error(self) -> None:
        bad = copy.deepcopy(self._canonical)
        bad['why_chosen'] = 'not-a-dict'
        errors = validate_v2_explanation(bad)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('why_chosen' in e for e in errors))

    def test_rejected_actions_wrong_type_returns_error(self) -> None:
        bad = copy.deepcopy(self._canonical)
        bad['rejected_actions'] = {'action': 'observe'}  # dict instead of list
        errors = validate_v2_explanation(bad)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any('rejected_actions' in e for e in errors))

    # -- extra keys are allowed ----------------------------------------------

    def test_extra_keys_are_allowed(self) -> None:
        extra = copy.deepcopy(self._canonical)
        extra['experimental_field'] = 'some-value'
        extra['another_new_key'] = [1, 2, 3]
        errors = validate_v2_explanation(extra)
        self.assertEqual(
            errors, [],
            msg=f"Extra keys should not cause errors, got: {errors}",
        )


class TraceIdContinuityTests(unittest.TestCase):
    """
    Verify that within the Python pipeline the same trace_id appears on
    both the P0AuditLogger record and the v2 explanation record.
    """

    TRACE_ID = 'trace-bheu-02'

    def test_trace_id_continuity_and_chain_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / 'audit.jsonl'
            audit_logger = P0AuditLogger(audit_path)

            # 1. Write an audit record for the action decision.
            audit_record = audit_logger.log_action_decision(
                trace_id=self.TRACE_ID,
                source='arbiter',
                action='redirect',
            )

            # 2. Generate the v2 explanation for the same trace.
            explanation = _make_redirect_record(trace_id=self.TRACE_ID)

            # 3. Both records must carry the same trace_id.
            self.assertEqual(
                audit_record['trace_id'],
                self.TRACE_ID,
                msg="Audit record must carry the shared trace_id",
            )
            self.assertEqual(
                explanation['trace_id'],
                self.TRACE_ID,
                msg="Explanation record must carry the shared trace_id",
            )

            # 4. The audit chain must be intact.
            chain_result = P0AuditLogger.verify_chain(audit_path)
            self.assertTrue(
                chain_result['ok'],
                msg=f"verify_chain must report ok=True, got: {chain_result}",
            )
            self.assertEqual(
                chain_result['error'],
                '',
                msg=f"verify_chain must report empty error string, got: {chain_result}",
            )
            self.assertGreater(
                chain_result['entries'],
                0,
                msg="verify_chain must report at least one entry",
            )


if __name__ == '__main__':
    unittest.main()
