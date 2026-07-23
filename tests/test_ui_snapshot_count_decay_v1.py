from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from azazel_edge_ai import agent


class UiSnapshotCountDecayV1Tests(unittest.TestCase):
    def test_decay_helper_ages_toward_zero_and_is_bounded(self) -> None:
        window = agent.SURICATA_COUNT_DECAY_WINDOW_SEC
        # No elapsed time -> unchanged.
        self.assertEqual(agent._decay_suricata_count(10, 0), 10)
        # Half the window -> roughly halved.
        self.assertEqual(agent._decay_suricata_count(10, window / 2.0), 5)
        # Full window of quiet -> reclaimed to zero.
        self.assertEqual(agent._decay_suricata_count(10, window), 0)
        # Hard ceiling caps runaway values.
        self.assertEqual(agent._decay_suricata_count(10_000, 0), agent.SURICATA_COUNT_MAX)

    def test_idle_operation_returns_counts_toward_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "ui_snapshot.json"
            with patch.object(agent, "SNAPSHOT_PATH", snap):
                base = 1_000_000_000.0
                window = agent.SURICATA_COUNT_DECAY_WINDOW_SEC
                # Two info-severity (sev=3) benign events fired close together.
                with patch.object(agent.time, "time", return_value=base):
                    agent._update_ui_snapshot({"suricata_severity": 3, "ts": base})
                with patch.object(agent.time, "time", return_value=base + 1.0):
                    agent._update_ui_snapshot({"suricata_severity": 3, "ts": base + 1.0})
                after_burst = json.loads(snap.read_text())["suricata_info"]
                self.assertGreaterEqual(after_burst, 2)

                # A full decay window later, one more benign event: prior tally
                # has aged out to zero, leaving only the fresh event.
                idle_now = base + 1.0 + window
                with patch.object(agent.time, "time", return_value=idle_now):
                    agent._update_ui_snapshot({"suricata_severity": 3, "ts": idle_now})
                after_idle = json.loads(snap.read_text())["suricata_info"]
                self.assertEqual(after_idle, 1)

    def test_deferred_recent_decays_independently_of_lifetime_counter(self) -> None:
        """FIX A: deferred_recent (pill-tone signal) must decay to zero once
        deferrals stop, even though METRICS['deferred_count'] (lifetime, kept
        for audit) never decreases."""
        orig_deferred_count = agent.METRICS.get("deferred_count", 0)
        self.addCleanup(lambda: agent.METRICS.__setitem__("deferred_count", orig_deferred_count))
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "ui_snapshot.json"
            with patch.object(agent, "SNAPSHOT_PATH", snap):
                base = 2_000_000_000.0
                window = agent.DEFERRED_RECENT_DECAY_WINDOW_SEC

                # Simulate an attack burst that floods the LLM queue: bump the
                # lifetime deferred_count metric directly, as _route_llm does.
                with agent.METRICS_LOCK:
                    agent.METRICS["deferred_count"] = 3
                with patch.object(agent.time, "time", return_value=base):
                    agent._update_ui_snapshot({"suricata_severity": 1, "ts": base}, count_suricata=False)
                snap_data = json.loads(snap.read_text())
                self.assertEqual(snap_data["deferred_recent"], 3)
                self.assertEqual(snap_data["deferred_lifetime_at_snapshot"], 3)
                # The lifetime metric itself is untouched by the snapshot write.
                self.assertEqual(agent.METRICS["deferred_count"], 3)

                # No further deferrals; a full decay window of benign/quiet
                # operation later, deferred_recent must have aged to zero even
                # though the lifetime counter is still 3 (pinned high forever
                # was the bug this fixes).
                idle_now = base + window
                with patch.object(agent.time, "time", return_value=idle_now):
                    agent._update_ui_snapshot({"suricata_severity": 3, "ts": idle_now}, count_suricata=False)
                snap_data = json.loads(snap.read_text())
                self.assertEqual(snap_data["deferred_recent"], 0)
                self.assertEqual(agent.METRICS["deferred_count"], 3)


if __name__ == "__main__":
    unittest.main()
