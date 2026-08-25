from __future__ import annotations

import unittest

from azazel_edge.outcome import MechanismKind, from_rust_event


def rust_event(*, result: str = "applied", executed_count: int = 1, failed_count: int = 0) -> dict:
    return {
        "normalized": {
            "ts": "2026-08-26T00:00:00Z",
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "target_port": 22,
            "sid": 1001,
        },
        "defense": {
            "action": "throttle",
            "target": "10.0.0.8",
            "policy_reason": "test",
        },
        "enforcement": {
            "mode": "enforced",
            "trace_id": "trace-test-truth",
            "selected_action": "throttle",
            "target": "10.0.0.8",
            "policy_reason": "test",
            "command_plan": [
                "tc qdisc replace dev br0 root tbf rate 256kbit burst 32kbit latency 1000ms",
                "nft add rule inet test input counter",
            ],
            "rollback_plan": ["tc qdisc del dev br0 root"],
            "executed_count": executed_count,
            "failed_count": failed_count,
            "errors": ["second command failed"] if failed_count else [],
            "result": result,
            "metadata": {},
        },
        "pipeline": "rust_event_engine_v1",
    }


class AdapterTruthfulnessTests(unittest.TestCase):
    def test_requested_plan_stays_requested_when_provider_only_reports_aggregate_success(self) -> None:
        bundle = from_rust_event(rust_event())
        self.assertIn("command_plan", bundle.execution.requested_parameters)
        self.assertNotIn("command_plan", bundle.execution.applied_parameters)
        self.assertEqual(bundle.execution.applied_parameters["executed_count"], 1)
        self.assertFalse(bundle.execution.applied_parameters["individual_command_mapping_verified"])
        self.assertEqual(bundle.execution.lifecycle.value, "active")
        self.assertEqual(bundle.mechanism.status.value, "unverified")

    def test_partial_failure_does_not_claim_which_requested_command_applied(self) -> None:
        bundle = from_rust_event(
            rust_event(result="partial_failure", executed_count=1, failed_count=1)
        )
        self.assertEqual(bundle.execution.status.value, "partial")
        self.assertEqual(bundle.execution.lifecycle.value, "unverified")
        self.assertEqual(bundle.mechanism.status.value, "disputed")
        self.assertNotIn("command_plan", bundle.execution.applied_parameters)
        self.assertEqual(bundle.execution.applied_parameters["executed_count"], 1)
        self.assertEqual(bundle.execution.applied_parameters["failed_count"], 1)
        self.assertFalse(bundle.execution.applied_parameters["individual_command_mapping_verified"])

    def test_disruptive_applied_with_zero_executed_commands_is_unverified(self) -> None:
        bundle = from_rust_event(rust_event(result="applied", executed_count=0, failed_count=0))
        self.assertEqual(bundle.execution.status.value, "unverified")
        self.assertEqual(bundle.execution.lifecycle.value, "unverified")
        self.assertEqual(bundle.execution.applied_parameters, {})
        self.assertEqual(bundle.mechanism.status.value, "unverified")

    def test_provider_trace_and_effective_fallback_action_remain_distinct(self) -> None:
        event = rust_event(result="no_disruptive_action", executed_count=0, failed_count=0)
        # Rust calculates trace_id before redirect policy fallback. The enforcement
        # record may therefore keep the original redirect trace while selecting a
        # different effective action. Preserve the trace as decision provenance and
        # represent the effective action separately rather than rewriting history.
        event["defense"]["action"] = "redirect"
        event["enforcement"].update(
            {
                "mode": "disabled",
                "selected_action": "notify",
                "policy_reason": "redirect_policy:unsupported_port_default",
                "command_plan": [],
                "rollback_plan": [],
            }
        )
        bundle = from_rust_event(event)
        self.assertEqual(bundle.execution.decision_id, "trace-test-truth")
        self.assertEqual(bundle.correlation.reasoning_trace_id, "trace-test-truth")
        self.assertEqual(bundle.execution.action_kind, "notify")
        self.assertEqual(bundle.mechanism.mechanism_kind, MechanismKind.NOTIFICATION)
        self.assertEqual(bundle.execution.status.value, "unverified")
        self.assertIn("unsupported_port_default", bundle.execution.requested_parameters["policy_reason"])


if __name__ == "__main__":
    unittest.main()
