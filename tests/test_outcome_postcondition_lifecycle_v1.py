from __future__ import annotations

import unittest
from dataclasses import replace
from typing import Sequence

from azazel_edge.outcome import (
    ActionLifecycle,
    MechanismStatus,
    ReadOnlyCommandResult,
    from_rust_event,
    verify_mechanism_postcondition,
)


class NoCallRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout_seconds: float) -> ReadOnlyCommandResult:
        args = tuple(str(value) for value in argv)
        self.calls.append(args)
        raise AssertionError(f"G1a must not probe an ineligible lifecycle state: {args!r}")


def throttle_event() -> dict:
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
            "trace_id": "trace-lifecycle-test",
            "selected_action": "throttle",
            "target": "10.0.0.8",
            "policy_reason": "test",
            "command_plan": [
                "tc qdisc replace dev br0 root tbf rate 256kbit burst 32kbit latency 1000ms"
            ],
            "rollback_plan": ["tc qdisc del dev br0 root"],
            "executed_count": 1,
            "failed_count": 0,
            "errors": [],
            "result": "applied",
            "metadata": {},
        },
        "pipeline": "rust_event_engine_v1",
    }


class LifecycleEligibilityTests(unittest.TestCase):
    def test_released_execution_cannot_reopen_mechanism(self) -> None:
        bundle = from_rust_event(throttle_event())
        execution = replace(bundle.execution, lifecycle=ActionLifecycle.RELEASED)
        runner = NoCallRunner()

        result = verify_mechanism_postcondition(
            execution=execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )

        self.assertIs(result, bundle.mechanism)
        self.assertEqual(result.status, MechanismStatus.UNVERIFIED)
        self.assertEqual(runner.calls, [])

    def test_already_observed_mechanism_is_not_revalidated_by_g1a(self) -> None:
        bundle = from_rust_event(throttle_event())
        mechanism = replace(bundle.mechanism, status=MechanismStatus.OBSERVED)
        runner = NoCallRunner()

        result = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=mechanism,
            runner=runner,
        )

        self.assertIs(result, mechanism)
        self.assertEqual(result.status, MechanismStatus.OBSERVED)
        self.assertEqual(runner.calls, [])

    def test_not_observed_mechanism_is_not_later_resurrected_by_same_receipt(self) -> None:
        bundle = from_rust_event(throttle_event())
        mechanism = replace(bundle.mechanism, status=MechanismStatus.NOT_OBSERVED)
        runner = NoCallRunner()

        result = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=mechanism,
            runner=runner,
        )

        self.assertIs(result, mechanism)
        self.assertEqual(result.status, MechanismStatus.NOT_OBSERVED)
        self.assertEqual(runner.calls, [])

    def test_stale_mechanism_is_not_reopened(self) -> None:
        bundle = from_rust_event(throttle_event())
        mechanism = replace(bundle.mechanism, status=MechanismStatus.STALE)
        runner = NoCallRunner()

        result = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=mechanism,
            runner=runner,
        )

        self.assertIs(result, mechanism)
        self.assertEqual(result.status, MechanismStatus.STALE)
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
