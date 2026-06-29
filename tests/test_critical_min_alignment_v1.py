"""
CRITICAL_MIN must be a single source of truth: the user-facing risk level, the state
name, the recommendation, and the auto-ops escalation all agree on the same boundary,
so a threat never lands in an [80,84] dead zone where one says CRITICAL and another
does not. Ships WITH the scorer recalibration.
"""

from __future__ import annotations

import unittest

from azazel_edge_ai import agent


class CriticalMinAlignmentTests(unittest.TestCase):
    def test_all_display_sites_agree_at_critical_min(self) -> None:
        c = agent.CRITICAL_MIN
        self.assertEqual(agent._risk_level(c), "CRITICAL")
        self.assertEqual(agent._state_name(c), "CONTAIN")
        self.assertTrue(agent._recommendation({"target_port": 22}, c).startswith("Block"))

    def test_just_below_critical_is_high_everywhere(self) -> None:
        c = agent.CRITICAL_MIN
        self.assertEqual(agent._risk_level(c - 1), "HIGH")
        self.assertEqual(agent._state_name(c - 1), "DEGRADED")
        self.assertFalse(agent._recommendation({"target_port": 22}, c - 1).startswith("Block"))

    def test_no_dead_zone_between_display_and_ops(self) -> None:
        """The auto-ops escalation at risk>=85 and the CRITICAL display must coincide."""
        self.assertEqual(agent.CRITICAL_MIN, 85)


if __name__ == "__main__":
    unittest.main()
