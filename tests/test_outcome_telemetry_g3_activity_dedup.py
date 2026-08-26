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
            system={"load1": 0.1, "memory_available_kib": 1_000_000},
            coverage={"proc_net_dev": True, "proc_loadavg": True, "proc_meminfo": True},
            evidence_ref=f"sample:{self.counter}",
        )


def make_policy() -> OutcomeTelemetryPolicy:
    return OutcomeTelemetryPolicy.from_mapping(
        {
            "schema_version": POLICY_SCHEMA_VERSION,
            "policy_version": "dedup-v1",
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
        source_ref="dedup-test",
    )


def event(*, trace: str, action: str, ts: str) -> dict:
    disruptive = action == "throttle"
    metadata = {"release_ledger_state": "not_applicable"}
    if disruptive:
        metadata = {
            "release_task_id": f"release-{trace}",
            "release_due_epoch": 2000.0,
            "release_resource_key": "tc:root:br0",
            "release_owner_token": f"azazel-edge:release-{trace}",
            "release_tc_handle": "1a:",
            "release_ledger_state": "active",
        }
    return {
        "normalized": {
            "ts": ts,
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "target_port": 22,
            "sid": 1001,
        },
        "defense": {
            "action": action,
            "target": "10.0.0.8",
            "policy_reason": "test",
            "delay_ms": 1000 if disruptive else 0,
        },
        "enforcement": {
            "mode": "enforced" if disruptive else "disabled",
            "trace_id": trace,
            "selected_action": action,
            "target": "10.0.0.8",
            "policy_reason": "test",
            "command_plan": [
                "tc qdisc replace dev br0 root handle 1a: tbf rate 256kbit burst 32kbit latency 1000ms"
            ] if disruptive else [],
            "rollback_plan": ["tc qdisc del dev br0 root handle 1a:"] if disruptive else [],
            "executed_count": 1 if disruptive else 0,
            "failed_count": 0,
            "errors": [],
            "result": "applied" if disruptive else "no_disruptive_action",
            "metadata": metadata,
        },
        "pipeline": "rust_event_engine_v1",
    }


class ActivityDedupTests(unittest.TestCase):
    def test_duplicate_activity_line_is_counted_once(self) -> None:
        collector = OutcomeTelemetryCollector(
            source=FakeSource(),
            policy=make_policy(),
            interface="br0",
            sample_interval_seconds=1.0,
            buffer_seconds=10.0,
        )
        collector.record_sample(epoch=998.0)
        collector.record_sample(epoch=999.0)
        self.assertTrue(
            collector.observe_event(
                event(trace="decision", action="throttle", ts="1970-01-01T00:16:40+00:00"),
                observed_epoch=1000.0,
            )
        )
        collector.record_sample(epoch=1001.0)
        duplicate = event(trace="same-activity", action="observe", ts="1970-01-01T00:16:41+00:00")
        collector.observe_event(duplicate, observed_epoch=1001.0)
        collector.observe_event(duplicate, observed_epoch=1001.1)
        collector.record_sample(epoch=1002.0)
        outcome = collector.finalize_due(epoch=1002.1)[0]
        self.assertEqual(outcome.post_metrics["source_ip_event_count"], 1)
        self.assertEqual(outcome.telemetry_coverage["post_activity_count"], 1)


if __name__ == "__main__":
    unittest.main()
