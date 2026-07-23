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


if __name__ == "__main__":
    unittest.main()
