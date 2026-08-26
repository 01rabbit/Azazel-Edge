from __future__ import annotations

import unittest

from azazel_edge.outcome.telemetry import (
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
        return TelemetrySample(
            epoch=epoch,
            observed_at=str(epoch),
            interface=interface,
            network={
                "rx_bytes": self.counter * 100,
                "rx_packets": self.counter * 10,
                "rx_errors": 0,
                "rx_dropped": 0,
                "tx_bytes": self.counter * 200,
                "tx_packets": self.counter * 20,
                "tx_errors": 0,
                "tx_dropped": 0,
            },
            system={"load1": 0.1, "memory_available_kib": 1000000},
            coverage={"proc_net_dev": True, "proc_loadavg": True, "proc_meminfo": True},
            evidence_ref=f"sample:{self.counter}",
        )


def make_policy() -> OutcomeTelemetryPolicy:
    return OutcomeTelemetryPolicy.from_mapping(
        {
            "schema_version": POLICY_SCHEMA_VERSION,
            "policy_version": "adversarial-v1",
            "actions": {
                "throttle": {
                    "metric": "source_ip_event_rate_hz",
                    "direction": "observe",
                    "target_or_range": {},
                    "observation_window": {"pre_seconds": 2.0, "post_seconds": 2.0},
                    "guardrails": [],
                }
            },
        },
        source_ref="adversarial-test",
    )


def action_event(trace: str) -> dict:
    return {
        "normalized": {
            "ts": "1970-01-01T00:16:40+00:00",
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "target_port": 22,
            "sid": 1001,
        },
        "defense": {
            "action": "throttle",
            "target": "10.0.0.8",
            "policy_reason": "test",
            "delay_ms": 1000,
        },
        "enforcement": {
            "mode": "enforced",
            "trace_id": trace,
            "selected_action": "throttle",
            "target": "10.0.0.8",
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


def release_event(trace: str, *, owner: str | None = None) -> dict:
    return {
        "release": {
            "release_task_id": f"release-{trace}",
            "trace_id": trace,
            "action": "throttle",
            "resource_key": "tc:root:br0",
            "owner_token": owner or f"azazel-edge:release-{trace}",
            "tc_handle": "1a:",
            "due_epoch": 1000.5,
            "attempted_at_epoch": 1001.0,
            "status": "released",
            "result": "rollback_applied_and_absence_verified",
            "command_count": 1,
            "failed_count": 0,
            "errors": [],
            "postcondition": {"verified": True},
        },
        "pipeline": "rust_release_engine_v1",
    }


class G3AdversarialTests(unittest.TestCase):
    def collector(self, **kwargs) -> OutcomeTelemetryCollector:
        return OutcomeTelemetryCollector(
            source=FakeSource(),
            policy=make_policy(),
            interface="br0",
            sample_interval_seconds=1.0,
            buffer_seconds=10.0,
            **kwargs,
        )

    def test_finalized_execution_remains_replay_blocked_for_process_lifetime(self) -> None:
        collector = self.collector()
        collector.record_sample(epoch=998.0)
        collector.record_sample(epoch=999.0)
        event = action_event("replay")
        self.assertTrue(collector.observe_event(event, observed_epoch=1000.0))
        collector.record_sample(epoch=1001.0)
        collector.record_sample(epoch=1002.0)
        self.assertEqual(len(collector.finalize_due(epoch=1002.1)), 1)
        self.assertFalse(collector.observe_event(event, observed_epoch=1003.0))
        self.assertEqual(len(collector.pending), 0)

    def test_forged_release_owner_cannot_truncate_observation(self) -> None:
        collector = self.collector()
        self.assertTrue(collector.observe_event(action_event("owner"), observed_epoch=1000.0))
        pending = next(iter(collector.pending.values()))
        planned = pending.effective_end_epoch
        self.assertFalse(
            collector.observe_event(
                release_event("owner", owner="azazel-edge:release-forged"),
                observed_epoch=1001.0,
            )
        )
        self.assertEqual(pending.effective_end_epoch, planned)
        self.assertEqual(pending.termination_reason, "observation_window_elapsed")

    def test_seen_execution_capacity_fails_closed_for_evidence_only(self) -> None:
        collector = self.collector(max_seen_executions=1)
        self.assertTrue(collector.observe_event(action_event("one"), observed_epoch=1000.0))
        collector.record_sample(epoch=1001.0)
        collector.record_sample(epoch=1002.0)
        collector.finalize_due(epoch=1002.1)
        self.assertFalse(collector.observe_event(action_event("two"), observed_epoch=1003.0))
        self.assertEqual(len(collector.pending), 0)

    def test_buffer_shorter_than_policy_window_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OutcomeTelemetryCollector(
                source=FakeSource(),
                policy=make_policy(),
                interface="br0",
                sample_interval_seconds=1.0,
                buffer_seconds=1.0,
            )


if __name__ == "__main__":
    unittest.main()
