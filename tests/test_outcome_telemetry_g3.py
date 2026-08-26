from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from azazel_edge.outcome.contracts import CausalSupport, OutcomeAssessment
from azazel_edge.outcome.telemetry import (
    LinuxProcTelemetrySource,
    OutcomeTelemetryCollector,
    OutcomeTelemetryPolicy,
    POLICY_SCHEMA_VERSION,
    TelemetrySample,
)


class FakeSource:
    def __init__(self) -> None:
        self.counter = 0

    def sample(self, *, interface: str, epoch: float) -> TelemetrySample:
        self.counter += 1
        base = self.counter * 100
        return TelemetrySample(
            epoch=epoch,
            observed_at=f"epoch:{epoch}",
            interface=interface,
            network={
                "rx_bytes": base,
                "rx_packets": self.counter * 10,
                "rx_errors": 0,
                "rx_dropped": self.counter,
                "tx_bytes": base * 2,
                "tx_packets": self.counter * 20,
                "tx_errors": 0,
                "tx_dropped": 0,
            },
            system={
                "load1": 0.5 + self.counter / 10,
                "memory_available_kib": 1_000_000 - self.counter * 1000,
            },
            coverage={
                "proc_net_dev": True,
                "proc_loadavg": True,
                "proc_meminfo": True,
                "proc_uptime": True,
            },
            evidence_ref=f"fake-sample:{self.counter}",
        )


def policy(*, post_seconds: float = 3.0) -> OutcomeTelemetryPolicy:
    return OutcomeTelemetryPolicy.from_mapping(
        {
            "schema_version": POLICY_SCHEMA_VERSION,
            "policy_version": "test-policy-v1",
            "actions": {
                "throttle": {
                    "metric": "source_ip_event_rate_hz",
                    "direction": "decrease",
                    "target_or_range": {},
                    "observation_window": {"pre_seconds": 3.0, "post_seconds": post_seconds},
                    "guardrails": [],
                }
            },
        },
        source_ref="unit-test",
    )


def rust_event(*, ts: str, trace: str, src_ip: str = "10.0.0.8") -> dict:
    return {
        "normalized": {
            "ts": ts,
            "src_ip": src_ip,
            "dst_ip": "10.0.0.1",
            "target_port": 22,
            "sid": 1001,
        },
        "defense": {
            "action": "throttle",
            "target": src_ip,
            "policy_reason": "test",
            "delay_ms": 1000,
        },
        "enforcement": {
            "mode": "enforced",
            "trace_id": trace,
            "selected_action": "throttle",
            "target": src_ip,
            "policy_reason": "test",
            "command_plan": [
                "tc qdisc replace dev br0 root handle 1a: tbf rate 256kbit burst 32kbit latency 1000ms"
            ],
            "rollback_plan": ["tc qdisc del dev br0 root handle 1a:"],
            "executed_count": 1,
            "failed_count": 0,
            "errors": [],
            "result": "applied",
            "metadata": {
                "release_task_id": f"release-{trace}",
                "release_due_epoch": 2000.0,
                "release_resource_key": "tc:root:br0",
                "release_owner_token": f"azazel-edge:release-{trace}",
                "release_tc_handle": "1a:",
                "release_ledger_state": "active",
            },
        },
        "pipeline": "rust_event_engine_v1",
    }


def activity_event(*, ts: str, trace: str, src_ip: str = "10.0.0.8") -> dict:
    event = rust_event(ts=ts, trace=trace, src_ip=src_ip)
    event["defense"] = {
        "action": "observe",
        "target": src_ip,
        "policy_reason": "activity-only",
        "delay_ms": 0,
    }
    event["enforcement"] = {
        "mode": "disabled",
        "trace_id": trace,
        "selected_action": "observe",
        "target": src_ip,
        "policy_reason": "activity-only",
        "command_plan": [],
        "rollback_plan": [],
        "executed_count": 0,
        "failed_count": 0,
        "errors": [],
        "result": "no_disruptive_action",
        "metadata": {"release_ledger_state": "not_applicable"},
    }
    return event


def redirect_event(*, ts: str, trace: str, src_ip: str = "10.0.0.8") -> dict:
    event = rust_event(ts=ts, trace=trace, src_ip=src_ip)
    owner = f"azazel-edge:release-{trace}"
    event["defense"]["action"] = "redirect"
    event["enforcement"].update(
        {
            "selected_action": "redirect",
            "command_plan": [
                f"nft insert rule inet azazel_edge prerouting ip saddr {src_ip} tcp dport 22 redirect to 12222 comment {owner}"
            ],
            "rollback_plan": [
                f"nft delete rule inet azazel_edge prerouting handle <owned:{owner}>"
            ],
            "metadata": {
                "release_task_id": f"release-{trace}",
                "release_due_epoch": 2000.0,
                "release_resource_key": f"nft:inet:azazel_edge:prerouting:{src_ip}:tcp:22",
                "release_owner_token": owner,
                "release_tc_handle": "",
                "release_ledger_state": "active",
            },
        }
    )
    return event


def release_event(*, trace: str, attempted_epoch: float) -> dict:
    return {
        "release": {
            "release_task_id": f"release-{trace}",
            "trace_id": trace,
            "action": "throttle",
            "resource_key": "tc:root:br0",
            "owner_token": f"azazel-edge:release-{trace}",
            "tc_handle": "1a:",
            "due_epoch": attempted_epoch - 1.0,
            "attempted_at_epoch": attempted_epoch,
            "status": "released",
            "result": "rollback_applied_and_absence_verified",
            "command_count": 1,
            "failed_count": 0,
            "errors": [],
            "postcondition": {"verified": True, "owned_state_present": False},
        },
        "pipeline": "rust_release_engine_v1",
        "source": "release_ledger",
    }


class LinuxProcTelemetrySourceTests(unittest.TestCase):
    def test_reads_procfs_without_subprocess_or_external_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "net").mkdir()
            (root / "net" / "dev").write_text(
                "Inter-| Receive | Transmit\n"
                " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
                " br0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n",
                encoding="utf-8",
            )
            (root / "loadavg").write_text("0.10 0.20 0.30 1/100 1\n", encoding="utf-8")
            (root / "meminfo").write_text(
                "MemTotal: 8000000 kB\nMemAvailable: 6000000 kB\nSwapTotal: 1000 kB\nSwapFree: 900 kB\n",
                encoding="utf-8",
            )
            (root / "uptime").write_text("123.45 12.34\n", encoding="utf-8")
            sample = LinuxProcTelemetrySource(root).sample(interface="br0", epoch=100.0)
            self.assertEqual(sample.network["rx_bytes"], 1000)
            self.assertEqual(sample.network["tx_dropped"], 4)
            self.assertEqual(sample.system["load1"], 0.10)
            self.assertEqual(sample.system["memory_available_kib"], 6000000)
            self.assertTrue(all(sample.coverage.values()))
            self.assertTrue(sample.evidence_ref.startswith("procfs-sample:"))

    def test_missing_proc_component_reduces_coverage_not_control(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "net").mkdir()
            sample = LinuxProcTelemetrySource(root).sample(interface="br0", epoch=100.0)
            self.assertFalse(any(sample.coverage.values()))
            self.assertEqual(sample.network, {})
            self.assertEqual(sample.system, {})


class OutcomeTelemetryPolicyTests(unittest.TestCase):
    def test_policy_has_no_implicit_action_objective(self) -> None:
        value = policy()
        self.assertIsNone(value.objective_for("redirect", "decision-1"))
        first = value.objective_for("throttle", "decision-1")
        second = value.objective_for("throttle", "decision-1")
        assert first is not None and second is not None
        self.assertEqual(first.objective_id, second.objective_id)
        self.assertEqual(first.policy_version, "test-policy-v1")

    def test_policy_rejects_unbounded_window(self) -> None:
        with self.assertRaises(ValueError):
            OutcomeTelemetryPolicy.from_mapping(
                {
                    "schema_version": POLICY_SCHEMA_VERSION,
                    "actions": {
                        "throttle": {
                            "metric": "x",
                            "direction": "increase",
                            "observation_window": {"pre_seconds": 1, "post_seconds": 9999},
                        }
                    },
                }
            )


class OutcomeTelemetryCollectorTests(unittest.TestCase):
    def _collector(self, *, post_seconds: float = 3.0, max_pending: int = 128) -> OutcomeTelemetryCollector:
        return OutcomeTelemetryCollector(
            source=FakeSource(),
            policy=policy(post_seconds=post_seconds),
            interface="br0",
            sample_interval_seconds=1.0,
            buffer_seconds=60.0,
            max_pending=max_pending,
        )

    def test_prebuffer_and_post_window_never_claim_effect(self) -> None:
        collector = self._collector()
        for epoch in (997.0, 998.0, 999.0):
            collector.record_sample(epoch=epoch)
        collector.observe_event(
            activity_event(ts="1970-01-01T00:16:39+00:00", trace="pre-a"),
            observed_epoch=999.2,
        )
        self.assertTrue(
            collector.observe_event(
                rust_event(ts="1970-01-01T00:16:40+00:00", trace="decision-a"),
                observed_epoch=1000.0,
            )
        )
        for epoch in (1001.0, 1002.0, 1003.0):
            collector.record_sample(epoch=epoch)
        collector.observe_event(
            activity_event(ts="1970-01-01T00:16:41+00:00", trace="post-a"),
            observed_epoch=1001.1,
        )
        records = collector.finalize_due(epoch=1003.1)
        self.assertEqual(len(records), 1)
        outcome = records[0]
        self.assertEqual(outcome.assessment, OutcomeAssessment.INCONCLUSIVE)
        self.assertEqual(outcome.causal_support, CausalSupport.INCONCLUSIVE)
        self.assertEqual(outcome.baseline_metrics["source_ip_event_count"], 1)
        self.assertEqual(outcome.post_metrics["source_ip_event_count"], 1)
        self.assertIn("interface_rx_bytes_delta", outcome.baseline_metrics)
        self.assertIn("interface_rx_bytes_delta", outcome.post_metrics)
        self.assertEqual(outcome.adversary_response["correlation_scope"], "source_ip")
        codes = {item["code"] for item in outcome.confounders}
        self.assertIn("source_ip_is_not_actor_identity", codes)
        self.assertIn("mechanism_postcondition_not_observed", codes)
        self.assertTrue(outcome.telemetry_coverage["policy_ref"].startswith("telemetry-policy:"))

    def test_no_policy_for_action_means_no_observation(self) -> None:
        collector = self._collector()
        self.assertFalse(
            collector.observe_event(
                redirect_event(ts="1970-01-01T00:16:40+00:00", trace="redirect-a"),
                observed_epoch=1000.0,
            )
        )
        self.assertEqual(collector.pending, {})

    def test_release_truncates_post_window_without_marking_effective(self) -> None:
        collector = self._collector(post_seconds=10.0)
        for epoch in (997.0, 998.0, 999.0):
            collector.record_sample(epoch=epoch)
        self.assertTrue(
            collector.observe_event(
                rust_event(ts="1970-01-01T00:16:40+00:00", trace="decision-r"),
                observed_epoch=1000.0,
            )
        )
        collector.record_sample(epoch=1001.0)
        self.assertTrue(
            collector.observe_event(
                release_event(trace="decision-r", attempted_epoch=1002.0),
                observed_epoch=1002.0,
            )
        )
        collector.record_sample(epoch=1002.0)
        outcome = collector.finalize_due(epoch=1002.1)[0]
        self.assertEqual(outcome.termination_reason, "owned_mechanism_released")
        self.assertTrue(outcome.telemetry_coverage["window_truncated_by_release"])
        self.assertEqual(outcome.assessment, OutcomeAssessment.INCONCLUSIVE)
        self.assertEqual(outcome.causal_support, CausalSupport.INCONCLUSIVE)

    def test_collector_started_too_late_reports_baseline_gap(self) -> None:
        collector = self._collector()
        collector.record_sample(epoch=999.9)
        self.assertTrue(
            collector.observe_event(
                rust_event(ts="1970-01-01T00:16:40+00:00", trace="late"),
                observed_epoch=1000.0,
            )
        )
        for epoch in (1001.0, 1002.0, 1003.0):
            collector.record_sample(epoch=epoch)
        outcome = collector.finalize_due(epoch=1003.1)[0]
        codes = {item["code"] for item in outcome.confounders}
        self.assertIn("insufficient_pre_samples", codes)
        self.assertLess(outcome.telemetry_coverage["pre_sample_ratio"], 1.0)

    def test_capacity_drop_and_duplicate_do_not_gain_control_authority(self) -> None:
        collector = self._collector(max_pending=1)
        first = rust_event(ts="1970-01-01T00:16:40+00:00", trace="one")
        self.assertTrue(collector.observe_event(first, observed_epoch=1000.0))
        self.assertFalse(collector.observe_event(first, observed_epoch=1000.1))
        self.assertFalse(
            collector.observe_event(
                rust_event(ts="1970-01-01T00:16:41+00:00", trace="two"),
                observed_epoch=1001.0,
            )
        )
        self.assertEqual(len(collector.pending), 1)

    def test_outcome_id_is_deterministic_for_execution_and_window(self) -> None:
        collector = self._collector()
        for epoch in (997.0, 998.0, 999.0):
            collector.record_sample(epoch=epoch)
        collector.observe_event(
            rust_event(ts="1970-01-01T00:16:40+00:00", trace="stable"),
            observed_epoch=1000.0,
        )
        for epoch in (1001.0, 1002.0, 1003.0):
            collector.record_sample(epoch=epoch)
        outcome = collector.finalize_due(epoch=1003.1)[0]
        self.assertTrue(outcome.outcome_id.startswith("outcome-"))
        self.assertEqual(outcome.observation_window["action_observed_epoch"], 1000.0)


if __name__ == "__main__":
    unittest.main()
