from __future__ import annotations

import json
import unittest
from dataclasses import replace
from typing import Sequence

from azazel_edge.outcome import (
    MechanismStatus,
    ReadOnlyCommandRejected,
    ReadOnlyCommandResult,
    SubprocessReadOnlyRunner,
    from_rust_event,
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


def command_result(argv: tuple[str, ...], payload: object, *, returncode: int = 0, stderr: str = "") -> ReadOnlyCommandResult:
    return ReadOnlyCommandResult(
        argv=argv,
        returncode=returncode,
        stdout=json.dumps(payload),
        stderr=stderr,
    )


def rust_event(
    action: str,
    *,
    mode: str = "enforced",
    result: str = "applied",
    executed_count: int = 1,
    failed_count: int = 0,
) -> dict:
    commands = {
        "throttle": ["tc qdisc replace dev br0 root tbf rate 256kbit burst 32kbit latency 1000ms"],
        "redirect": ["nft insert rule inet azazel_edge prerouting ip saddr 10.0.0.8 tcp dport 22 redirect to 12222"],
        "isolate": ["nft insert rule inet azazel_edge input ip saddr 10.0.0.8 drop"],
        "notify": [],
    }
    rollback = {
        "throttle": ["tc qdisc del dev br0 root"],
        "redirect": ["nft delete rule inet azazel_edge prerouting ip saddr 10.0.0.8 tcp dport 22 redirect to 12222"],
        "isolate": ["nft delete rule inet azazel_edge input ip saddr 10.0.0.8 drop"],
        "notify": [],
    }
    return {
        "normalized": {
            "ts": "2026-08-26T00:00:00Z",
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "target_port": 22,
            "sid": 1001,
        },
        "defense": {
            "action": action,
            "target": "10.0.0.8",
            "policy_reason": "test",
        },
        "enforcement": {
            "mode": mode,
            "trace_id": f"trace-postcondition-{action}",
            "selected_action": action,
            "target": "10.0.0.8",
            "policy_reason": "test",
            "command_plan": commands[action],
            "rollback_plan": rollback[action],
            "executed_count": executed_count,
            "failed_count": failed_count,
            "errors": ["provider failure"] if failed_count else [],
            "result": result,
            "metadata": {},
        },
        "pipeline": "rust_event_engine_v1",
    }


def nft_match(protocol: str, field: str, right: object) -> dict:
    return {
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": protocol, "field": field}},
            "right": right,
        }
    }


class TrafficShapingPostconditionTests(unittest.TestCase):
    def test_exact_root_tbf_readback_promotes_mechanism_to_observed(self) -> None:
        bundle = from_rust_event(rust_event("throttle"))
        argv = ("tc", "-j", "qdisc", "show", "dev", "br0")
        runner = FakeRunner(
            {
                argv: command_result(
                    argv,
                    [
                        {
                            "kind": "tbf",
                            "root": True,
                            # iproute2 internal rate representation may be raw bytes/s.
                            "rate": 32000,
                            "burst": 4000,
                            "lat": 1_000_000,
                        }
                    ],
                )
            }
        )

        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )

        self.assertEqual(verified.status, MechanismStatus.OBSERVED)
        probe = verified.observed_parameters["postcondition_probe"]
        self.assertEqual(probe["verification_strength"], "exact")
        self.assertEqual(probe["basis"], "tc_root_tbf_parameter_readback_match")
        self.assertEqual(runner.calls, [argv])
        self.assertTrue(any(ref.startswith("postcondition:") for ref in verified.evidence_refs))

    def test_tbf_with_different_rate_is_not_observed(self) -> None:
        bundle = from_rust_event(rust_event("throttle"))
        argv = ("tc", "-j", "qdisc", "show", "dev", "br0")
        runner = FakeRunner(
            {
                argv: command_result(
                    argv,
                    [{"kind": "tbf", "root": True, "rate": 64000, "burst": 4000, "lat": 1_000_000}],
                )
            }
        )
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertEqual(verified.status, MechanismStatus.NOT_OBSERVED)
        self.assertEqual(
            verified.observed_parameters["postcondition_probe"]["basis"],
            "tc_root_tbf_parameter_match_not_found",
        )

    def test_root_tbf_without_complete_parameters_stays_unverified(self) -> None:
        bundle = from_rust_event(rust_event("throttle"))
        argv = ("tc", "-j", "qdisc", "show", "dev", "br0")
        runner = FakeRunner({argv: command_result(argv, [{"kind": "tbf", "root": True}])})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertEqual(verified.status, MechanismStatus.UNVERIFIED)
        self.assertEqual(
            verified.observed_parameters["postcondition_probe"]["verification_strength"],
            "partial",
        )

    def test_tc_query_failure_stays_unverified(self) -> None:
        bundle = from_rust_event(rust_event("throttle"))
        argv = ("tc", "-j", "qdisc", "show", "dev", "br0")
        runner = FakeRunner({argv: command_result(argv, {}, returncode=2, stderr="device unavailable")})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertEqual(verified.status, MechanismStatus.UNVERIFIED)
        self.assertEqual(verified.observed_parameters["postcondition_probe"]["basis"], "tc_query_failed")

    def test_invalid_interface_scope_never_reaches_runner(self) -> None:
        bundle = from_rust_event(rust_event("throttle"))
        poisoned = replace(
            bundle.mechanism,
            scope={"scope_kind": "interface_root_qdisc", "interface": "br0;touch-/tmp/pwn"},
        )
        runner = FakeRunner({})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=poisoned,
            runner=runner,
        )
        self.assertEqual(verified.status, MechanismStatus.UNVERIFIED)
        self.assertEqual(runner.calls, [])


class NftPostconditionTests(unittest.TestCase):
    def test_exact_redirect_rule_is_observed(self) -> None:
        bundle = from_rust_event(rust_event("redirect"))
        argv = ("nft", "-j", "list", "chain", "inet", "azazel_edge", "prerouting")
        payload = {
            "nftables": [
                {
                    "rule": {
                        "chain": "prerouting",
                        "expr": [
                            nft_match("ip", "saddr", "10.0.0.8"),
                            nft_match("tcp", "dport", 22),
                            {"redirect": {"port": 12222}},
                        ],
                    }
                }
            ]
        }
        runner = FakeRunner({argv: command_result(argv, payload)})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertEqual(verified.status, MechanismStatus.OBSERVED)
        self.assertEqual(
            verified.observed_parameters["postcondition_probe"]["verification_strength"],
            "exact",
        )

    def test_redirect_to_different_port_is_not_observed(self) -> None:
        bundle = from_rust_event(rust_event("redirect"))
        argv = ("nft", "-j", "list", "chain", "inet", "azazel_edge", "prerouting")
        payload = {
            "nftables": [
                {
                    "rule": {
                        "chain": "prerouting",
                        "expr": [
                            nft_match("ip", "saddr", "10.0.0.8"),
                            nft_match("tcp", "dport", 22),
                            {"redirect": {"port": 13333}},
                        ],
                    }
                }
            ]
        }
        runner = FakeRunner({argv: command_result(argv, payload)})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertEqual(verified.status, MechanismStatus.NOT_OBSERVED)

    def test_nft_drop_null_verdict_is_observed(self) -> None:
        bundle = from_rust_event(rust_event("isolate"))
        argv = ("nft", "-j", "list", "chain", "inet", "azazel_edge", "input")
        payload = {
            "nftables": [
                {
                    "rule": {
                        "chain": "input",
                        "expr": [
                            nft_match("ip", "saddr", "10.0.0.8"),
                            {"drop": None},
                        ],
                    }
                }
            ]
        }
        runner = FakeRunner({argv: command_result(argv, payload)})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertEqual(verified.status, MechanismStatus.OBSERVED)

    def test_drop_for_different_source_is_not_observed(self) -> None:
        bundle = from_rust_event(rust_event("isolate"))
        argv = ("nft", "-j", "list", "chain", "inet", "azazel_edge", "input")
        payload = {
            "nftables": [
                {
                    "rule": {
                        "chain": "input",
                        "expr": [nft_match("ip", "saddr", "10.0.0.9"), {"drop": None}],
                    }
                }
            ]
        }
        runner = FakeRunner({argv: command_result(argv, payload)})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertEqual(verified.status, MechanismStatus.NOT_OBSERVED)


class AuthorityAndFailureTests(unittest.TestCase):
    def test_dry_run_receipt_is_never_upgraded_even_if_matching_state_exists(self) -> None:
        bundle = from_rust_event(
            rust_event("throttle", mode="dry_run", result="planned_not_applied", executed_count=0)
        )
        runner = FakeRunner({})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertNotEqual(verified.status, MechanismStatus.OBSERVED)
        self.assertEqual(runner.calls, [])

    def test_partial_execution_is_never_upgraded(self) -> None:
        bundle = from_rust_event(
            rust_event("throttle", result="partial_failure", executed_count=1, failed_count=1)
        )
        runner = FakeRunner({})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertNotEqual(verified.status, MechanismStatus.OBSERVED)
        self.assertEqual(runner.calls, [])

    def test_execution_mechanism_correlation_mismatch_is_rejected(self) -> None:
        bundle = from_rust_event(rust_event("throttle"))
        mismatched = replace(bundle.mechanism, execution_id="execution-other")
        with self.assertRaises(ValueError):
            verify_mechanism_postcondition(
                execution=bundle.execution,
                mechanism=mismatched,
                runner=FakeRunner({}),
            )

    def test_notification_has_no_tc_or_nft_probe(self) -> None:
        bundle = from_rust_event(rust_event("notify", mode="disabled", result="no_disruptive_action", executed_count=0))
        runner = FakeRunner({})
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
        )
        self.assertNotEqual(verified.status, MechanismStatus.OBSERVED)
        self.assertEqual(runner.calls, [])

    def test_arbitrary_provider_stdout_is_not_persisted(self) -> None:
        bundle = from_rust_event(rust_event("throttle"))
        argv = ("tc", "-j", "qdisc", "show", "dev", "br0")
        payload = [{"kind": "tbf", "root": True, "rate": 32000, "burst": 4000, "lat": 1_000_000}]
        result = ReadOnlyCommandResult(
            argv=argv,
            returncode=0,
            stdout=json.dumps(payload),
            stderr="S" * 800,
        )
        verified = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=FakeRunner({argv: result}),
        )
        probe = verified.observed_parameters["postcondition_probe"]
        self.assertNotIn("stdout", probe)
        self.assertLessEqual(len(probe["stderr"]), 512)

    def test_subprocess_runner_rejects_mutating_command_before_execution(self) -> None:
        runner = SubprocessReadOnlyRunner()
        with self.assertRaises(ReadOnlyCommandRejected):
            runner.run(
                ("nft", "delete", "rule", "inet", "azazel_edge", "input"),
                timeout_seconds=1.0,
            )

    def test_subprocess_runner_rejects_shell_shaped_tc_argument(self) -> None:
        runner = SubprocessReadOnlyRunner()
        with self.assertRaises(ReadOnlyCommandRejected):
            runner.run(
                ("tc", "-j", "qdisc", "show", "dev", "br0;id"),
                timeout_seconds=1.0,
            )


if __name__ == "__main__":
    unittest.main()
