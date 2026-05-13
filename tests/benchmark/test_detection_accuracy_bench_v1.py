import json
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.benchmark.detection_accuracy import DetectionAccuracyBenchmark

CORPUS = Path(__file__).resolve().parent / "corpus"


class DetectionAccuracyBenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bench = DetectionAccuracyBenchmark(corpus_dir=CORPUS)

    def test_corpus_files_exist(self):
        label_files = list(CORPUS.glob("*.labels.json"))
        self.assertGreaterEqual(len(label_files), 5)

    def test_corpus_jsonl_pairs_exist(self):
        for label_file in CORPUS.glob("*.labels.json"):
            eve_file = label_file.with_name(label_file.name.replace(".labels.json", ".jsonl"))
            self.assertTrue(eve_file.exists())

    def test_detection_rate_meets_threshold(self):
        result = self.bench.run()
        self.assertGreaterEqual(result.detection_rate_pct, 85.0)

    def test_summary_is_json_serializable(self):
        serialized = json.dumps(self.bench.run().summary())
        self.assertIn("breach_rate_pct", serialized)

    def test_each_session_has_required_fields(self):
        result = self.bench.run()
        for s in result.sessions:
            self.assertTrue(s.session_id)
            self.assertTrue(s.action_taken)
            self.assertIsInstance(s.matched_sids, list)


if __name__ == "__main__":
    unittest.main()
