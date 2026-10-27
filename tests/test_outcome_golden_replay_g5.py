"""Outcome-as-Evidence G5: end-to-end golden replay (#400).

Decision -> Execution -> Mechanism -> Release -> Outcome -> Effect is replayed
from a recorded fixture and every stage must equal the golden transcript. The
replay must never reach a live path: every live executor, enforcement, control
daemon, Action Arbiter, procfs, subprocess, socket, wall-clock and file-write
entry point is replaced by a stub that fails the test when called.
"""

from __future__ import annotations

import ast
import builtins
import copy
import io
import json
import os
import socket
import subprocess
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator
from unittest import mock

from azazel_edge.outcome import from_rust_event, verify_mechanism_postcondition
from azazel_edge.outcome.contracts import (
    CausalSupport,
    EffectAssessmentStatus,
    OutcomeAssessment,
    OutcomeRecord,
)
from azazel_edge.outcome.golden_replay import (
    GoldenReplayError,
    RecordedProbeRunner,
    run_golden_replay,
)
from azazel_edge.outcome.outcome_identity import (
    AdmissionStatus,
    OutcomeIdentityLedger,
    outcome_identity_key,
)
from azazel_edge.outcome.postcondition import SubprocessReadOnlyRunner

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "outcome"
INPUT = FIXTURES / "g5_golden_replay_input_v1.json"
EXPECTED = FIXTURES / "g5_golden_replay_expected_v1.json"
REPLAY_MODULES = (
    ROOT / "py" / "azazel_edge" / "outcome" / "golden_replay.py",
    ROOT / "py" / "azazel_edge" / "outcome" / "outcome_identity.py",
)

STAGES = (
    "decision",
    "correlation",
    "execution",
    "mechanism",
    "mechanism_postcondition",
    "release",
    "execution_final",
    "mechanism_final",
    "objective",
    "outcome",
    "outcome_identity_key",
    "effect",
)


def load_fixture() -> dict:
    return json.loads(INPUT.read_text(encoding="utf-8"))


def load_expected() -> dict:
    return json.loads(EXPECTED.read_text(encoding="utf-8"))


def normalize(value: object) -> object:
    return json.loads(json.dumps(value, sort_keys=True))


class _LiveCallRecorder:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def stub(self, name: str):
        def _forbidden(*_args: object, **_kwargs: object):
            self.calls.append(name)
            raise AssertionError(f"golden replay reached a live path: {name}")

        return _forbidden

    def write_guard(self, name: str, original):
        def _guarded(file, mode="r", *args, **kwargs):
            if any(flag in str(mode) for flag in "wax+"):
                self.calls.append(f"{name}:{mode}")
                raise AssertionError(f"golden replay attempted a file write: {file!r}")
            return original(file, mode, *args, **kwargs)

        return _guarded


@contextmanager
def live_paths_forbidden() -> Iterator[_LiveCallRecorder]:
    """Replace every live execution/authority/IO entry point with a failing stub."""

    recorder = _LiveCallRecorder()
    targets = [
        # live process execution (tc / nft / any helper)
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.replace",
        "os.rename",
        "os.remove",
        "os.unlink",
        "os.mkdir",
        "os.makedirs",
        "socket.create_connection",
        # live read-only probe runner and live procfs telemetry
        "azazel_edge.outcome.postcondition.SubprocessReadOnlyRunner.run",
        "azazel_edge.outcome.telemetry.LinuxProcTelemetrySource.sample",
        # live outcome writers / CLIs
        "azazel_edge.outcome.telemetry.run_live",
        "azazel_edge.outcome.telemetry.append_jsonl",
        "azazel_edge.outcome.observer.append_jsonl",
        "azazel_edge.outcome.observer.run",
        # execution providers
        "azazel_edge.outcome.replay.LiveExecutionProvider.execute",
        "azazel_edge.outcome.replay.ReplayExecutionProvider.execute",
        # decision / enforcement authorities that replay must never consult
        "azazel_edge.arbiter.action.ActionArbiter.decide",
        "azazel_edge.opencanary_redirect.OpenCanaryRedirectController.apply",
        "azazel_edge.runbooks.execute_runbook",
        # control daemon client paths
        "azazel_edge.control_plane._socket_request",
        "azazel_edge.control_plane.send_action",
        "azazel_edge.control_plane.send_action_with_fallback",
        "azazel_edge.control_plane.write_command_file_fallback",
        # wall clock: replay time comes from the recording only
        "azazel_edge.outcome.contracts.utc_now",
        "azazel_edge.outcome.postcondition.utc_now",
    ]
    if hasattr(os, "posix_spawn"):
        targets.append("os.posix_spawn")
    with ExitStack() as stack:
        for target in targets:
            stack.enter_context(mock.patch(target, recorder.stub(target)))
        stack.enter_context(mock.patch.object(socket.socket, "connect", recorder.stub("socket.socket.connect")))
        stack.enter_context(
            mock.patch(
                "azazel_edge.outcome.telemetry.time",
                SimpleNamespace(
                    time=recorder.stub("telemetry.time.time"),
                    monotonic=recorder.stub("telemetry.time.monotonic"),
                    sleep=recorder.stub("telemetry.time.sleep"),
                ),
            )
        )
        stack.enter_context(mock.patch("builtins.open", recorder.write_guard("builtins.open", builtins.open)))
        stack.enter_context(mock.patch("io.open", recorder.write_guard("io.open", io.open)))
        yield recorder


class GoldenReplayStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = normalize(run_golden_replay(load_fixture()))
        self.expected = load_expected()

    def test_every_stage_of_every_decision_matches_golden(self) -> None:
        got = {item["decision_id"]: item for item in self.result["decisions"]}
        want = {item["decision_id"]: item for item in self.expected["decisions"]}
        self.assertEqual(list(got), list(want))
        for decision_id, expected in want.items():
            actual = got[decision_id]
            for key in ("first_boot", "action", "deliveries", "notes"):
                with self.subTest(decision=decision_id, field=key):
                    self.assertEqual(actual[key], expected[key])
            for stage in STAGES:
                with self.subTest(decision=decision_id, stage=stage):
                    self.assertEqual(actual["stages"].get(stage), expected["stages"].get(stage))
            self.assertEqual(set(actual["stages"]), set(expected["stages"]))

    def test_replay_level_records_match_golden(self) -> None:
        for key in ("outcome_admissions", "outcome_ledger", "restart_gaps", "rejected_inputs", "summary", "boots"):
            with self.subTest(key=key):
                self.assertEqual(self.result[key], self.expected[key])
        self.assertEqual(self.result, self.expected)

    def test_replay_is_deterministic(self) -> None:
        fixture = load_fixture()
        first = normalize(run_golden_replay(fixture))
        second = normalize(run_golden_replay(copy.deepcopy(fixture)))
        self.assertEqual(first, second)
        self.assertEqual(fixture, load_fixture(), "replay must not mutate its input")


class GoldenReplaySemanticsTests(unittest.TestCase):
    """Golden content is pinned to the locked #400 semantics, not only to a snapshot."""

    @classmethod
    def setUpClass(cls) -> None:
        result = normalize(run_golden_replay(load_fixture()))
        cls.result = result
        cls.by_action = {item["action"]: item for item in result["decisions"]}

    def test_throttle_full_chain(self) -> None:
        stages = self.by_action["throttle"]["stages"]
        self.assertEqual(stages["decision"]["authority"], "recorded_rust_decide_defense")
        self.assertEqual(stages["execution"]["status"], "applied")
        # provider command success alone is not a mechanism fact
        self.assertEqual(stages["mechanism"]["status"], "unverified")
        self.assertEqual(stages["mechanism"]["mechanism_kind"], "TRAFFIC_SHAPING")
        self.assertEqual(stages["mechanism_postcondition"]["status"], "observed")
        self.assertEqual([item["reconciliation"] for item in stages["release"]], ["released"])
        self.assertEqual(stages["execution_final"]["status"], "released")
        self.assertEqual(stages["mechanism_final"]["status"], "released")
        outcome = stages["outcome"]
        self.assertEqual(outcome["termination_reason"], "owned_mechanism_released")
        self.assertTrue(outcome["telemetry_coverage"]["window_truncated_by_release"])
        self.assertEqual(outcome["assessment"], OutcomeAssessment.INCONCLUSIVE.value)
        self.assertEqual(outcome["causal_support"], CausalSupport.INCONCLUSIVE.value)
        effect = stages["effect"]
        self.assertEqual(effect["tactical_effect"], "DELAY")
        self.assertEqual(effect["assessment"], EffectAssessmentStatus.INCONCLUSIVE.value)
        self.assertIsNone(effect["confidence"])
        self.assertEqual(effect["outcome_id"], outcome["outcome_id"])
        self.assertEqual(effect["mechanism_id"], stages["correlation"]["mechanism_id"])
        self.assertEqual(effect["objective_id"], stages["objective"]["objective_id"])

    def test_failed_isolate_has_no_mechanism_outcome_or_effect(self) -> None:
        stages = self.by_action["isolate"]["stages"]
        self.assertEqual(stages["execution"]["status"], "failed")
        self.assertEqual(stages["mechanism"]["status"], "not_observed")
        self.assertIsNone(stages["mechanism_postcondition"])
        self.assertEqual(stages["release"], [])
        self.assertIsNone(stages["outcome"])
        self.assertIsNone(stages["effect"])

    def test_redirect_release_reconciles_across_restart_and_lost_window_is_explicit(self) -> None:
        trace = self.by_action["redirect"]
        stages = trace["stages"]
        self.assertEqual(trace["first_boot"], "boot-1")
        self.assertEqual(stages["mechanism_postcondition"]["status"], "observed")
        self.assertEqual([(item["boot"], item["reconciliation"]) for item in stages["release"]], [("boot-2", "released")])
        self.assertEqual(stages["mechanism_final"]["status"], "released")
        # the pending observation died with boot-1; replay must not reconstruct it
        self.assertIsNone(stages["outcome"])
        self.assertIsNone(stages["effect"])
        self.assertIn("boot-1:pending_observation_lost_at_restart", trace["notes"])
        self.assertEqual(
            [(gap["decision_id"], gap["reason"]) for gap in self.result["restart_gaps"]],
            [(trace["decision_id"], "pending_observation_lost_at_restart")],
        )

    def test_no_stage_claims_success_or_causality(self) -> None:
        for trace in self.result["decisions"]:
            outcome = trace["stages"]["outcome"]
            effect = trace["stages"]["effect"]
            if outcome is not None:
                self.assertEqual(outcome["assessment"], "inconclusive")
                self.assertEqual(outcome["causal_support"], "inconclusive")
            if effect is not None:
                self.assertNotEqual(effect["assessment"], "supported")
                self.assertIsNone(effect["confidence"])


class CrossRestartOutcomeDedupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = normalize(run_golden_replay(load_fixture()))

    def test_same_outcome_is_not_counted_twice_after_restart(self) -> None:
        admissions = self.result["outcome_admissions"]
        self.assertEqual([(a["boot"], a["status"]) for a in admissions], [("boot-1", "admitted"), ("boot-2", "duplicate_suppressed")])
        # Without the identity ledger the two records look different: the G3
        # outcome_id depends on collector receipt time, which a restart changes.
        self.assertEqual(len({a["outcome_id"] for a in admissions}), 2)
        self.assertEqual(len({a["identity_key"] for a in admissions}), 1)
        self.assertEqual(admissions[1]["retained_outcome_id"], admissions[0]["outcome_id"])
        self.assertEqual(self.result["summary"]["outcomes_produced"], 2)
        self.assertEqual(self.result["summary"]["outcomes_counted"], 1)
        self.assertEqual(len(self.result["outcome_ledger"]["identities"]), 1)

    def test_retained_outcome_is_the_pre_restart_one(self) -> None:
        throttle = next(item for item in self.result["decisions"] if item["action"] == "throttle")
        self.assertEqual(throttle["deliveries"], ["boot-1", "boot-2"])
        self.assertIn("boot-2:identical_redelivery_ignored", throttle["notes"])
        self.assertIn("boot-2:outcome_duplicate_suppressed", throttle["notes"])
        self.assertEqual(throttle["stages"]["outcome"]["outcome_id"], self.result["outcome_admissions"][0]["outcome_id"])
        self.assertEqual(
            throttle["stages"]["outcome_identity_key"],
            outcome_identity_key(
                execution_id=throttle["stages"]["outcome"]["execution_id"],
                objective_id=throttle["stages"]["outcome"]["objective_id"],
            ),
        )

    def test_dedup_survives_replaying_the_whole_recording_again(self) -> None:
        fixture = load_fixture()
        boots = fixture["boots"]
        fixture["boots"] = boots + [
            {"boot": f"{boot['boot']}-again", "steps": copy.deepcopy(boot["steps"])} for boot in boots
        ]
        result = normalize(run_golden_replay(fixture))
        self.assertEqual(result["summary"]["outcomes_counted"], 1)
        self.assertEqual(len(result["outcome_ledger"]["identities"]), 1)
        self.assertEqual(
            [a["status"] for a in result["outcome_admissions"]],
            ["admitted", "duplicate_suppressed", "duplicate_suppressed", "duplicate_suppressed"],
        )
        throttle = next(item for item in result["decisions"] if item["action"] == "throttle")
        # the second pass cannot re-open G1a or re-release an already released mechanism
        self.assertIn("boot-1-again:probe_not_initial_transition_ignored", throttle["notes"])
        self.assertEqual([r["reconciliation"] for r in throttle["stages"]["release"]], ["released", "no_change"])
        self.assertEqual(throttle["stages"]["mechanism_postcondition"], load_expected()["decisions"][0]["stages"]["mechanism_postcondition"])


def _outcome(**overrides: object) -> OutcomeRecord:
    values = dict(
        incident_id="incident-a",
        decision_id="decision-a",
        execution_id="execution-a",
        mechanism_id="mechanism-a",
        objective_id="objective-a",
        observation_window={},
        baseline_metrics={},
        post_metrics={},
        adversary_response={},
        asset_impact={},
        noc_impact={},
        resource_impact={},
        operator_override={},
        termination_reason="observation_window_elapsed",
        observed_at="2026-01-01T00:00:00+00:00",
        outcome_id="outcome-a",
    )
    values.update(overrides)
    return OutcomeRecord(**values)


class OutcomeIdentityLedgerTests(unittest.TestCase):
    def test_identity_ignores_receipt_time_dependent_outcome_id(self) -> None:
        ledger = OutcomeIdentityLedger()
        self.assertEqual(ledger.admit(_outcome()).status, AdmissionStatus.ADMITTED)
        self.assertEqual(ledger.admit(_outcome()).status, AdmissionStatus.DUPLICATE_IDENTICAL)
        later = ledger.admit(_outcome(outcome_id="outcome-b", observed_at="2026-01-01T01:00:00+00:00"))
        self.assertEqual(later.status, AdmissionStatus.DUPLICATE_SUPPRESSED)
        self.assertEqual(later.retained_outcome_id, "outcome-a")
        self.assertFalse(later.counted)
        self.assertEqual(len(ledger), 1)

    def test_state_round_trip_keeps_identities_across_restart(self) -> None:
        ledger = OutcomeIdentityLedger(max_identities=8)
        ledger.admit(_outcome())
        restored = OutcomeIdentityLedger.from_mapping(json.loads(json.dumps(ledger.to_dict())))
        self.assertEqual(restored.to_dict(), ledger.to_dict())
        self.assertEqual(restored.admit(_outcome(outcome_id="outcome-z")).status, AdmissionStatus.DUPLICATE_SUPPRESSED)

    def test_capacity_exhaustion_fails_closed_without_forgetting(self) -> None:
        ledger = OutcomeIdentityLedger(max_identities=1)
        ledger.admit(_outcome())
        full = ledger.admit(_outcome(execution_id="execution-b", outcome_id="outcome-b"))
        self.assertEqual(full.status, AdmissionStatus.CAPACITY_EXHAUSTED)
        self.assertFalse(full.counted)
        self.assertEqual(ledger.admit(_outcome(outcome_id="outcome-c")).status, AdmissionStatus.DUPLICATE_SUPPRESSED)

    def test_tampered_or_oversized_state_is_rejected(self) -> None:
        ledger = OutcomeIdentityLedger(max_identities=2)
        ledger.admit(_outcome())
        state = ledger.to_dict()
        tampered = copy.deepcopy(state)
        tampered["identities"][0]["execution_id"] = "execution-other"
        with self.assertRaises(ValueError):
            OutcomeIdentityLedger.from_mapping(tampered)
        oversized = copy.deepcopy(state)
        oversized["max_identities"] = 0
        with self.assertRaises(ValueError):
            OutcomeIdentityLedger.from_mapping(oversized)
        with self.assertRaises(ValueError):
            OutcomeIdentityLedger.from_mapping({**state, "schema_version": "other"})

    def test_identity_collision_across_decisions_is_rejected(self) -> None:
        ledger = OutcomeIdentityLedger()
        ledger.admit(_outcome())
        with self.assertRaises(ValueError):
            ledger.admit(_outcome(decision_id="decision-b"))


class ReplayLiveBoundaryTests(unittest.TestCase):
    def test_replay_never_reaches_a_live_path(self) -> None:
        fixture = load_fixture()
        with live_paths_forbidden() as recorder:
            result = run_golden_replay(fixture)
        self.assertEqual(recorder.calls, [])
        self.assertEqual(normalize(result), load_expected())

    def test_guard_is_effective(self) -> None:
        # Negative control: the stubs really intercept the live entry points.
        with live_paths_forbidden() as recorder:
            with self.assertRaises(AssertionError):
                SubprocessReadOnlyRunner().run(("tc", "-j", "qdisc", "show", "dev", "br0"), timeout_seconds=1.0)
            with self.assertRaises(AssertionError):
                subprocess.run(["true"], check=False)
            with self.assertRaises(AssertionError):
                socket.socket().connect(("127.0.0.1", 9))
            with self.assertRaises(AssertionError):
                open(os.devnull, "w")
        self.assertEqual(
            recorder.calls,
            [
                "azazel_edge.outcome.postcondition.SubprocessReadOnlyRunner.run",
                "subprocess.run",
                "socket.socket.connect",
                "builtins.open:w",
            ],
        )

    def test_replay_modules_import_no_live_path(self) -> None:
        forbidden_modules = {
            "subprocess",
            "socket",
            "os",
            "shutil",
            "time",
            "pathlib",
            "io",
            "azazel_edge.arbiter",
            "azazel_edge.arbiter.action",
            "azazel_edge.control_plane",
            "azazel_edge.opencanary_redirect",
            "azazel_edge.runbooks",
            "azazel_edge_control",
        }
        forbidden_names = {
            "SubprocessReadOnlyRunner",
            "LinuxProcTelemetrySource",
            "LiveExecutionProvider",
            "run_live",
            "append_jsonl",
            "utc_now",
            "ActionArbiter",
        }
        for path in REPLAY_MODULES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        with self.subTest(module=path.name, imported=alias.name):
                            self.assertNotIn(alias.name.split(".")[0], forbidden_modules)
                            self.assertNotIn(alias.name, forbidden_modules)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    with self.subTest(module=path.name, imported=module):
                        self.assertNotIn(module, forbidden_modules)
                        self.assertFalse(module.startswith("azazel_edge_control"))
                    for alias in node.names:
                        with self.subTest(module=path.name, name=alias.name):
                            self.assertNotIn(alias.name, forbidden_names)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    with self.subTest(module=path.name, call=node.func.id):
                        self.assertNotIn(node.func.id, {"open", "exec", "eval", "__import__"})


class GoldenFixtureIntegrityTests(unittest.TestCase):
    def test_recorded_probe_must_be_read_only(self) -> None:
        with self.assertRaises(GoldenReplayError):
            RecordedProbeRunner([{"argv": ["tc", "qdisc", "del", "dev", "br0", "root"], "returncode": 0, "stdout": ""}])

    def test_unrecorded_probe_readback_fails_loudly(self) -> None:
        fixture = load_fixture()
        probe = next(step for step in fixture["boots"][0]["steps"] if step["op"] == "probe")
        probe["results"] = []
        with self.assertRaises(GoldenReplayError):
            run_golden_replay(fixture)

    def test_unknown_step_is_rejected(self) -> None:
        fixture = load_fixture()
        fixture["boots"][0]["steps"].append({"op": "execute", "epoch": 1.0})
        with self.assertRaises(GoldenReplayError):
            run_golden_replay(fixture)

    def test_duplicate_boot_id_is_rejected(self) -> None:
        fixture = load_fixture()
        fixture["boots"].append(copy.deepcopy(fixture["boots"][0]))
        with self.assertRaises(GoldenReplayError):
            run_golden_replay(fixture)


class ProbeTimestampInjectionTests(unittest.TestCase):
    """The replay-only probe timestamp must not change live G1a behaviour."""

    def _bundle(self):
        fixture = load_fixture()
        event = next(
            step["event"]
            for step in fixture["boots"][0]["steps"]
            if step["op"] == "event" and step["event"].get("defense", {}).get("action") == "throttle"
        )
        probe = next(step for step in fixture["boots"][0]["steps"] if step["op"] == "probe")
        return from_rust_event(event), RecordedProbeRunner(probe["results"])

    def test_default_still_uses_current_time(self) -> None:
        bundle, runner = self._bundle()
        with mock.patch("azazel_edge.outcome.postcondition.utc_now", return_value="2030-01-01T00:00:00+00:00"):
            verified = verify_mechanism_postcondition(execution=bundle.execution, mechanism=bundle.mechanism, runner=runner)
        self.assertEqual(verified.observed_at, "2030-01-01T00:00:00+00:00")

    def test_injected_time_only_changes_timestamp(self) -> None:
        bundle, runner = self._bundle()
        with mock.patch("azazel_edge.outcome.postcondition.utc_now", return_value="2030-01-01T00:00:00+00:00"):
            live = verify_mechanism_postcondition(execution=bundle.execution, mechanism=bundle.mechanism, runner=runner)
        replayed = verify_mechanism_postcondition(
            execution=bundle.execution,
            mechanism=bundle.mechanism,
            runner=runner,
            observed_at="2026-04-24T03:23:23.200000+00:00",
        )
        self.assertEqual(replayed.status, live.status)
        self.assertEqual(replayed.observed_at, "2026-04-24T03:23:23.200000+00:00")
        live_probe = dict(live.observed_parameters["postcondition_probe"])
        replay_probe = dict(replayed.observed_parameters["postcondition_probe"])
        live_probe.pop("observed_at")
        replay_probe.pop("observed_at")
        self.assertEqual(replay_probe, live_probe)

    def test_naive_or_malformed_timestamp_is_rejected(self) -> None:
        bundle, runner = self._bundle()
        for value in ("2026-04-24T03:23:23", "not-a-time"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                verify_mechanism_postcondition(
                    execution=bundle.execution, mechanism=bundle.mechanism, runner=runner, observed_at=value
                )


if __name__ == "__main__":
    unittest.main()
