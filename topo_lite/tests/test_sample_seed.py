from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from db.repository import TopoLiteRepository
from sample_seed import SYNTHETIC_SCENARIO, seed_internal_lan_story


class SampleSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "sample.sqlite3"
        self.repository = TopoLiteRepository(self.database_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_seed_internal_lan_story_creates_correlated_runtime_state(self) -> None:
        payload = seed_internal_lan_story(self.repository)

        hosts = self.repository.list_hosts()
        events = self.repository.list_events()
        observations = self.repository.list_observations()
        scan_runs = self.repository.list_scan_runs()
        metadata = self.repository.list_metadata(prefix="synthetic_")

        self.assertEqual(payload["host_count"], 6)
        self.assertEqual(len(hosts), 6)
        self.assertEqual(len(events), 6)
        self.assertEqual(len(scan_runs), 2)
        self.assertEqual(metadata["synthetic_active"], "true")
        self.assertEqual(metadata["synthetic_scenario"], SYNTHETIC_SCENARIO)
        self.assertTrue(all("sample-seed" == row["source"] for row in observations))
        self.assertTrue(all(row["ip"].startswith("172.16.0.") for row in hosts))


if __name__ == "__main__":
    unittest.main()
