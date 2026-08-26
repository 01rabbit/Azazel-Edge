from __future__ import annotations

import json
import unittest
from dataclasses import replace
from typing import Sequence

from azazel_edge.outcome import (
    ActionLifecycle,
    ExecutionStatus,
    MechanismStatus,
    ReadOnlyCommandResult,
    ReleaseEvidenceStatus,
    ShadowOutcomeObserver,
    from_rust_event,
    from_rust_release_event,
    reconcile_release_evidence,
    verify_mechanism_postcondition,
)


class FakeRunner:
    def __init__(self, results: dict[tuple[str, ...], ReadOnlyCommandResult]) -> None:
        self.results = results
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout_seconds: float) -> ReadOnlyCommandResult:
        args = tuple(str(value) for value in argv)
        self.calls.append(args)
        if args not in self.results:
            raise AssertionError(f"unexpected probe command: {args!r}")
        return self.results[args]


def command_result(argv: tuple[str, ...], payload: object) -> ReadOnlyCommandResult:
    return ReadOnlyCommandResult(argv=argv, returncode=0, stdout=json.dumps(payload), stderr="")


def owned_event(action: str) -> dict:
    trace = f"trace-g1b-{action}"
    task_id = f"release-{action}-001"
    owner = f"azazel-edge:{task_id}"
    commands = {
        "throttle": [
            "tc qdisc replace dev br0 root handle 1a: tbf rate 256kbit burst 32kbit latency 1000ms"
        ],
        "isolate": [
            f"nft insert rule inet azazel_edge input ip saddr 10.0.0.8 drop comment {owner}"
        ],
        "redirect": [
            f"nft insert rule inet azazel_edge prerouting ip saddr 10.0.0.8 tcp dport 22 redirect to 12222 comment {owner}"
        ],
    }
    rollback = {
        "throttle": ["tc qdisc del dev br0 root handle 1a:"],
        "isolate": [f"nft delete rule inet azazel_edge input handle <owned:{owner}>"] ,
        "redirect": [f"nft delete rule inet azazel_edge prerouting handle <owned:{owner}>"] ,
    }
    target = "10.0.0.8:22" if action == "redirect" else "10.0.0.8"
    return {
        "normalized": {
            "ts": "2026-08-26T00:00:00+00:00",
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "target_port": 22,
            "sid": 1001,
        },
        "defense": {"action": action, "target": target, "policy_reason": "test"},
        "enforcement": {
            "mode": "enforced",
            "trace_id": trace,
            "selected_action": action,
            "target": target,
            "policy_reason": "test",
            "command_plan": commands[action],
            "rollback_plan": rollback[action],
            "executed_count": 1,
            "failed_count": 0,
            "errors": [],
            "result": "applied",
            "metadata": {
                "release_task_id": task_id,
                "release_due_epoch": 1_777_000_300.0,
                "release_resource_key": "test-resource",
                "release_owner_token": owner,
                "release_tc_handle": "1a:" if action == "throttle" else "",
                "release_ledger_state": "active",
            },
        },
        "pipeline": "rust_event_engine_v1",
    }


def release_event(action: str, *, status: str = "released", verified: bool = True, owner_override: str = "") -> dict:
    base = owned_event(action)
    metadata = base["enforcement"]["metadata"]
    owner = owner_override or metadata["release_owner_token"]
    return {
        "release": {
            "release_task_id": metadata["release_task_id"],
            "trace_id": base["enforcement"]["trace_id"],
            "action": action,
            "resource_key": metadata["release_resource_key"],
            "owner_token": owner,
            "tc_handle": "1a:" if action == "throttle" else "",
            "due_epoch": 1_777_000_300.0,
            "attempted_at_epoch": 1_777_000_301.0,
            "status": status,
            "result": "rollback_applied_and_absence_verified" if status == "released" else "release_attempt_failed",
            "command_count": 1,
            "failed_count": 0 if status == "released" else 1,
            "errors": [] if status == "released" else ["temporary failure"],
            "postcondition": {"verified": verified, "owned_state_present": False},
        },
        "pipeline": "rust_release_engine_v1",
        "source": "release_ledger",
    }


def nft_match(protocol: str, field: str, right: object) -> dict:
    return {
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": protocol, "field": field}},
            "right": right,
        }
    }


class OwnershipAwarePostconditionTests(unittest.TestCase):
    def test_tc_identical_tbf_with_wrong_handle_is_not_observed(self) -> None:
        bundle = from_rust_event(owned_event("throttle"))
        argv = ("tc", "-j", "qdisc", "show", "dev", "br0")
        runner = FakeRunner(
            {
                argv: command_result(
                    argv,
                    [{"kind": "tbf", "root": True, "handle": "ffff:", "rate": 32000, "burst": 4096, "lat": 1_000_000}],
                )
            }
        )
        verified = verify_mechanism_postcondition(
            execution=bundle.execution, mechanism=bundle.mechanism, runner=runner
        )
        self.assertEqual(verified.status, MechanismStatus.NOT_OBSERVED)

    def test_tc_owned_handle_and_parameters_are_observed(self) -> None:
        bundle = from_rust_event(owned_event("throttle"))
        argv = ("tc", "-j", "qdisc", "show", "dev", "br0")
        runner = FakeRunner(
            {
                argv: command_result(
                    argv,
                    [{"kind": "tbf", "root": True, "handle": "1a:", "rate": 32000, "burst": 4096, "lat": 1_000_000}],
                )
            }
        )
        verified = verify_mechanism_postcondition(
            execution=bundle.execution, mechanism=bundle.mechanism, runner=runner
        )
        self.assertEqual(verified.status, MechanismStatus.OBSERVED)
        self.assertEqual(
            verified.observed_parameters["postcondition_probe"]["ownership"],
            {"kind": "tc_handle", "value": "1a:"},
        )

    def test_nft_same_rule_with_wrong_comment_is_not_observed(self) -> None:
        bundle = from_rust_event(owned_event("isolate"))
        argv = ("nft", "-j", "list", "chain", "inet", "azazel_edge", "input")
        payload = {
            "nftables": [
                {
                    "rule": {
                        "chain": "input",
                        "comment": "azazel-edge:release-other",
                        "expr": [nft_match("ip", "saddr", "10.0.0.8"), {"drop": None}],
                    }
                }
            ]
        }
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=FakeRunner({argv: command_result(argv, payload)}),
        )
        self.assertEqual(verified.status, MechanismStatus.NOT_OBSERVED)

    def test_nft_owned_comment_and_semantics_are_observed(self) -> None:
        event = owned_event("isolate")
        bundle = from_rust_event(event)
        owner = event["enforcement"]["metadata"]["release_owner_token"]
        argv = ("nft", "-j", "list", "chain", "inet", "azazel_edge", "input")
        payload = {
            "nftables": [
                {
                    "rule": {
                        "chain": "input",
                        "comment": owner,
                        "expr": [nft_match("ip", "saddr", "10.0.0.8"), {"drop": None}],
                    }
                }
            ]
        }
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=FakeRunner({argv: command_result(argv, payload)}),
        )
        self.assertEqual(verified.status, MechanismStatus.OBSERVED)
        self.assertEqual(
            verified.observed_parameters["postcondition_probe"]["ownership"],
            {"kind": "nft_comment", "value": owner},
        )


class ReleaseEvidenceTests(unittest.TestCase):
    def _observed_throttle(self):
        bundle = from_rust_event(owned_event("throttle"))
        argv = ("tc", "-j", "qdisc", "show", "dev", "br0")
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=FakeRunner(
                {
                    argv: command_result(
                        argv,
                        [{"kind": "tbf", "root": True, "handle": "1a:", "rate": 32000, "burst": 4096, "lat": 1_000_000}],
                    )
                }
            ),
        )
        return bundle, verified

    def test_adapter_binds_durable_release_reference_and_expiry(self) -> None:
        bundle = from_rust_event(owned_event("throttle"))
        self.assertEqual(bundle.execution.release_ref, "release-throttle-001")
        self.assertTrue(bundle.execution.expires_at)
        self.assertEqual(bundle.mechanism.expires_at, bundle.execution.expires_at)

    def test_verified_release_reconciles_only_observed_owned_mechanism(self) -> None:
        bundle, verified = self._observed_throttle()
        release = from_rust_release_event(release_event("throttle"))
        execution, mechanism = reconcile_release_evidence(
            execution=bundle.execution, mechanism=verified, release=release
        )
        self.assertEqual(execution.status, ExecutionStatus.RELEASED)
        self.assertEqual(execution.lifecycle, ActionLifecycle.RELEASED)
        self.assertEqual(mechanism.status, MechanismStatus.RELEASED)
        self.assertEqual(execution.release_ref, release.release_task_id)
        self.assertEqual(
            mechanism.observed_parameters["release_evidence"]["ownership"],
            {"kind": "tc_handle", "value": "1a:"},
        )

    def test_released_without_verified_absence_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            from_rust_release_event(release_event("throttle", verified=False))

    def test_retry_pending_never_changes_active_evidence(self) -> None:
        bundle, verified = self._observed_throttle()
        release = from_rust_release_event(
            release_event("throttle", status="retry_pending", verified=False)
        )
        execution, mechanism = reconcile_release_evidence(
            execution=bundle.execution, mechanism=verified, release=release
        )
        self.assertEqual(execution.status, ExecutionStatus.APPLIED)
        self.assertEqual(mechanism.status, MechanismStatus.OBSERVED)

    def test_release_with_different_owner_is_rejected(self) -> None:
        bundle, verified = self._observed_throttle()
        release = from_rust_release_event(
            release_event("throttle", owner_override="azazel-edge:release-other")
        )
        with self.assertRaises(ValueError):
            reconcile_release_evidence(
                execution=bundle.execution, mechanism=verified, release=release
            )

    def test_unobserved_mechanism_is_not_retroactively_marked_released(self) -> None:
        bundle = from_rust_event(owned_event("throttle"))
        release = from_rust_release_event(release_event("throttle"))
        execution, mechanism = reconcile_release_evidence(
            execution=bundle.execution, mechanism=bundle.mechanism, release=release
        )
        self.assertEqual(execution.status, ExecutionStatus.APPLIED)
        self.assertEqual(mechanism.status, MechanismStatus.UNVERIFIED)

    def test_release_observer_emits_evidence_only(self) -> None:
        observed = ShadowOutcomeObserver().observe(release_event("isolate"))
        self.assertIsNotNone(observed)
        assert observed is not None
        self.assertEqual(
            observed["release_evidence"]["status"], ReleaseEvidenceStatus.RELEASED.value
        )
        self.assertNotIn("execution", observed)

    def test_release_guard_failure_is_not_normalized_as_applied(self) -> None:
        event = owned_event("throttle")
        event["enforcement"]["mode"] = "release_guard_failed"
        event["enforcement"]["result"] = "planned_not_applied"
        event["enforcement"]["executed_count"] = 0
        event["enforcement"]["metadata"]["release_ledger_state"] = "prepare_failed"
        bundle = from_rust_event(event)
        self.assertEqual(bundle.execution.status, ExecutionStatus.UNVERIFIED)
        self.assertNotEqual(bundle.execution.lifecycle, ActionLifecycle.ACTIVE)
        self.assertEqual(bundle.execution.release_ref, "")


if __name__ == "__main__":
    unittest.main()
