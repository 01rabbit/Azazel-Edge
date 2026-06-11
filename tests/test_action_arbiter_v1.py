from __future__ import annotations

import sys
import unittest
from pathlib import Path

from azazel_edge.arbiter import ActionArbiter
from tests.helpers import noc as _noc
from tests.helpers import soc as _soc


class ActionArbiterV1Tests(unittest.TestCase):
    def test_observe_for_low_signal(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(_noc(), _soc())
        self.assertEqual(result['action'], 'observe')
        self.assertTrue(result['chosen_evidence_ids'])
        self.assertTrue(result['rejected_alternatives'])

    def test_throttle_for_high_soc_when_noc_is_stable(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(_noc(), _soc(suspicion=85, suspicion_label='critical', confidence=85, confidence_label='critical', blast=60, blast_label='high'))
        self.assertEqual(result['action'], 'throttle')
        self.assertEqual(result['reason'], 'soc_high_and_reversible_control_is_safe')

    def test_notify_when_soc_is_high_but_noc_is_fragile(self) -> None:
        arbiter = ActionArbiter()
        result = arbiter.decide(
            _noc(availability='poor', path='poor'),
            _soc(suspicion=85, suspicion_label='critical', confidence=85, confidence_label='critical', blast=70, blast_label='high'),
        )
        self.assertEqual(result['action'], 'notify')
        self.assertEqual(result['reason'], 'soc_high_but_noc_fragile')

    def test_schema_validation_rejects_invalid_inputs(self) -> None:
        arbiter = ActionArbiter()
        with self.assertRaises(ValueError):
            arbiter.decide({}, _soc())


if __name__ == '__main__':
    unittest.main()
