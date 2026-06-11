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


if __name__ == '__main__':
    unittest.main()
