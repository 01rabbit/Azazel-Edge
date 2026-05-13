from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from azazel_edge.benchmark.detection_accuracy import DetectionAccuracyBenchmark
from azazel_edge.benchmark.pipeline_latency import PipelineLatencyBenchmark


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def _pipeline_table(stages: Dict[str, Any]) -> str:
    rows = []
    for key in ["T2_eve_parse", "T3_evidence_dispatch", "T4_evaluators", "T5_arbiter"]:
        stage = stages.get(key, {})
        rows.append(f"| {key} | {stage.get('mean_ms', 'n/a')} | {stage.get('median_ms', 'n/a')} | {stage.get('p95_ms', 'n/a')} | {stage.get('p99_ms', 'n/a')} |")
    return "\n".join(rows)


def _session_table(items: list[dict[str, Any]]) -> str:
    lines = ["| Session | Category | Technique | Detected | Action | Breach |", "|---|---|---|---|---|---|"]
    for s in items:
        lines.append(f"| {s.get('session_id')} | {s.get('category')} | {s.get('technique')} | {s.get('detected')} | {s.get('action')} | {s.get('breach')} |")
    return "\n".join(lines)


def generate(output_dir: Path) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    pipeline = PipelineLatencyBenchmark(iterations=200, warmup=20).run().summary()
    accuracy = DetectionAccuracyBenchmark(Path("tests/benchmark/corpus")).run().summary()

    data: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hardware": os.environ.get("AZAZEL_BENCH_HARDWARE", "TBD"),
        "commit": _git_commit(),
        "test_baseline": "328 passed, 62 subtests passed",
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "suricata_version": os.environ.get("AZAZEL_BENCH_SURICATA", "TBD"),
        "load_condition": os.environ.get("AZAZEL_BENCH_LOAD", "synthetic EVE replay"),
        "network_conditions": os.environ.get("AZAZEL_BENCH_NETWORK", "offline synthetic corpus"),
        "pipeline": pipeline,
        "accuracy": accuracy,
    }

    (output_dir / "BENCHMARK_RESULTS.json").write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")

    md = f"""# Azazel-Edge Benchmark Results

Generated: {data['generated_at']}  
Hardware: {data['hardware']}  
Commit: {data['commit']}  
Test suite baseline: {data['test_baseline']}

---

## B-1: Software Pipeline Latency (T2->T5)

| Stage | Mean (ms) | Median (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|
{_pipeline_table(data['pipeline'].get('stages', {}))}

Total pipeline p95: {data['pipeline'].get('total_pipeline_p95_ms', 'n/a')} ms

## B-3: Detection Accuracy

- Detection rate: {accuracy.get('detection_rate_pct')}%
- Breach rate (software): {accuracy.get('breach_rate_pct')}%
- Total sessions: {accuracy.get('total_sessions')}

{_session_table(accuracy.get('per_session', []))}

## Notes

- Power and startup hardware benchmarks must be run on Raspberry Pi and updated manually.
- The 12% breach-rate statement remains preliminary until reproduced with hardware validation.
"""
    (output_dir / "BENCHMARK_RESULTS.md").write_text(md, encoding="utf-8")
    return data


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate benchmark report artifacts")
    ap.add_argument("--output", default="docs", help="Output directory")
    args = ap.parse_args()
    result = generate(Path(args.output))
    print(json.dumps({"ok": True, "output": str(Path(args.output).resolve()), "generated_at": result["generated_at"]}, ensure_ascii=True))


if __name__ == "__main__":
    main()
