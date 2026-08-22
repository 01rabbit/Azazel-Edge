from __future__ import annotations

import sys
import unittest
from pathlib import Path

from azazel_edge.arbiter import ActionArbiter
from tests.helpers import noc as _noc
from tests.helpers import soc as _soc


class ActionArbiterV2Tests(unittest.TestCase):
    def test_redirect_requires_high_confidence_soc_and_safe_noc(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(),
            _soc(suspicion=92, suspicion_label='critical', confidence=84, confidence_label='critical', blast=72, blast_label='high'),
            client_impact={'score': 20, 'critical_client_count': 0},
        )
        self.assertEqual(result['action'], 'redirect')
        self.assertEqual(result['control_mode'], 'opencanary_redirect')
        self.assertEqual(result['release_condition'], 'no_repeated_failures_for_300_seconds')

    def test_isolate_for_extreme_signal_with_low_impact(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(),
            _soc(suspicion=96, suspicion_label='critical', confidence=92, confidence_label='critical', blast=82, blast_label='critical'),
            client_impact={'score': 15, 'critical_client_count': 0},
        )
        self.assertEqual(result['action'], 'isolate')
        self.assertEqual(result['control_mode'], 'segment_isolation')
        self.assertEqual(result['release_condition'], 'manual_review_and_no_high_risk_signals_for_600_seconds')

    def test_high_client_impact_blocks_control_actions(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(),
            _soc(suspicion=96, suspicion_label='critical', confidence=92, confidence_label='critical', blast=82, blast_label='critical'),
            client_impact={'score': 90, 'critical_client_count': 1},
        )
        self.assertEqual(result['action'], 'notify')
        self.assertEqual(result['reason'], 'client_impact_too_high_for_control')
        self.assertEqual(result['release_condition'], 'operator_acknowledged_or_signal_stabilized')


class ActionArbiterFailSafeTests(unittest.TestCase):
    """Ambiguous / malformed NOC health must degrade conservatively, never
    escalate to an aggressive control and never crash (fail-safe doctrine)."""

    @staticmethod
    def _extreme_soc() -> dict:
        return {
            'suspicion': {'label': 'critical', 'score': 99, 'evidence_ids': ['s1']},
            'confidence': {'score': 95},
            'technique_likelihood': {},
            'blast_radius': {'score': 90, 'evidence_ids': ['b1']},
            'summary': 'x', 'evidence_ids': [],
        }

    def test_empty_noc_health_does_not_escalate_to_isolate(self) -> None:
        # Health sub-objects present but empty (e.g. a collector outage) must be
        # treated as unknown/fragile, NOT 'good' — so extreme SOC cannot drive
        # isolation on genuinely-unknown NOC state.
        noc = {'availability': {}, 'path_health': {}, 'device_health': {},
               'client_health': {}, 'summary': 'x', 'evidence_ids': []}
        result = ActionArbiter().decide(noc, self._extreme_soc())
        self.assertNotIn(result['action'], {'isolate', 'redirect', 'throttle'})
        self.assertEqual(result['action'], 'notify')
        self.assertTrue(result['decision_trace']['noc_fragile'])
        # The audit trace reflects the SAME state the decision used.
        self.assertEqual(result['decision_trace']['availability_label'], 'unknown')

    def test_none_valued_noc_health_does_not_crash(self) -> None:
        # A required key present with value None passed key-presence validation
        # and used to crash `.get('label')`; it must now degrade safely instead.
        noc = {'availability': None, 'path_health': {'label': 'good'},
               'device_health': {'label': 'good'}, 'client_health': {'label': 'good'},
               'summary': 'x', 'evidence_ids': []}
        soc = {'suspicion': {'label': 'low', 'score': 5, 'evidence_ids': []},
               'confidence': {'score': 5}, 'technique_likelihood': {},
               'blast_radius': {'score': 5, 'evidence_ids': []},
               'summary': 'x', 'evidence_ids': []}
        result = ActionArbiter().decide(noc, soc)  # must not raise
        self.assertIn(result['action'], {'observe', 'notify'})
        self.assertEqual(result['decision_trace']['availability_label'], 'unknown')

    def test_none_valued_soc_section_does_not_crash(self) -> None:
        # Same fail-safe for a malformed SOC section: None must not crash, and
        # must default to the conservative floor (no escalation).
        noc = {'availability': {'label': 'good'}, 'path_health': {'label': 'good'},
               'device_health': {'label': 'good'}, 'client_health': {'label': 'good'},
               'summary': 'x', 'evidence_ids': []}
        soc = {'suspicion': None, 'confidence': None, 'technique_likelihood': {},
               'blast_radius': None, 'summary': 'x', 'evidence_ids': []}
        result = ActionArbiter().decide(noc, soc)  # must not raise
        self.assertEqual(result['action'], 'observe')


if __name__ == '__main__':
    unittest.main()
