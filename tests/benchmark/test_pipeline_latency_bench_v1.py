import json
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.benchmark.pipeline_latency import PipelineLatencyBenchmark


class PipelineLatencyBenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bench = PipelineLatencyBenchmark(iterations=120, warmup=10)

    def test_t2_eve_parse_p95_under_5ms(self):
        p95 = self.bench.run().summary()["stages"]["T2_eve_parse"]["p95_ms"]
        self.assertLess(p95, 5.0)

    def test_t5_arbiter_p95_under_50ms(self):
        p95 = self.bench.run().summary()["stages"]["T5_arbiter"]["p95_ms"]
        self.assertLess(p95, 50.0)

    def test_total_pipeline_p95_under_100ms(self):
        total = self.bench.run().summary().get("total_pipeline_p95_ms", 9999)
        self.assertLess(total, 100.0)

    def test_summary_contains_all_stages(self):
        stages = self.bench.run().summary()["stages"]
        for stage in ["T2_eve_parse", "T3_evidence_dispatch", "T4_evaluators", "T5_arbiter"]:
            self.assertIn(stage, stages)

    def test_benchmark_output_is_json_serializable(self):
        serialized = json.dumps(self.bench.run().summary())
        self.assertIn("total_pipeline_mean_ms", serialized)


if __name__ == "__main__":
    unittest.main()
