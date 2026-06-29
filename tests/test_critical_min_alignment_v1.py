"""
CRITICAL_MIN must be a single source of truth: the user-facing risk level, the state
name, the recommendation, AND the auto-ops escalation all agree on the same boundary,
so a threat never lands in an [80,84] dead zone where one says CRITICAL and another
does not. The ops linkage is the one the constant was created for, so it is exercised
directly (parametrized over CRITICAL_MIN values), not pinned to a memorized literal.
"""

from __future__ import annotations

import contextlib
import unittest

from azazel_edge_ai import agent


@contextlib.contextmanager
def _critical_min(value: int):
    """Temporarily override CRITICAL_MIN and a clean, ops-enabled, no-cooldown state."""
    saved = (agent.CRITICAL_MIN, agent.OPS_COACH_ENABLED, agent._LAST_OPS_ESCALATE_TS)
    agent.CRITICAL_MIN = value
    agent.OPS_COACH_ENABLED = True
    agent._LAST_OPS_ESCALATE_TS = 0.0
    try:
        yield
    finally:
        agent.CRITICAL_MIN, agent.OPS_COACH_ENABLED, agent._LAST_OPS_ESCALATE_TS = saved


class CriticalMinAlignmentTests(unittest.TestCase):
    def test_display_sites_track_critical_min(self) -> None:
        for c in (80, 85, 90):
            with _critical_min(c):
                self.assertEqual(agent._risk_level(c), "CRITICAL")
                self.assertEqual(agent._state_name(c), "CONTAIN")
                self.assertTrue(agent._recommendation({"target_port": 22}, c).startswith("Block"))
                self.assertEqual(agent._risk_level(c - 1), "HIGH")
                self.assertEqual(agent._state_name(c - 1), "DEGRADED")
                self.assertFalse(agent._recommendation({"target_port": 22}, c - 1).startswith("Block"))

    def test_ops_escalation_tracks_critical_min(self) -> None:
        """The auto-ops critical_risk branch must fire at CRITICAL_MIN, not a literal 85."""
        for c in (80, 85, 90):
            with _critical_min(c):
                # High confidence + completed LLM isolates the critical_risk branch from
                # the high_risk_low_confidence and llm_not_completed branches.
                at = agent._should_escalate_to_ops(
                    {"risk_score": c}, llm_status="completed", confidence=0.95
                )
                self.assertEqual(at, (True, "critical_risk"), f"CRITICAL_MIN={c}")
                agent._LAST_OPS_ESCALATE_TS = 0.0
                below = agent._should_escalate_to_ops(
                    {"risk_score": c - 1}, llm_status="completed", confidence=0.95
                )
                self.assertEqual(below[0], False, f"CRITICAL_MIN={c}: {c-1} should not be critical")
                self.assertNotEqual(below[1], "critical_risk")


if __name__ == "__main__":
    unittest.main()
