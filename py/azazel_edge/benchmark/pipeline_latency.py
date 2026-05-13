from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

from azazel_edge.arbiter.action import ActionArbiter
from azazel_edge.evaluators.noc import NocEvaluator
from azazel_edge.evaluators.soc import SocEvaluator
from azazel_edge.evidence_plane.schema import EvidenceEvent
from azazel_edge.tactics_engine.eve_parser import EVEParser


@dataclass
class PipelineLatencyResult:
    iterations: int
    stage_timings_ms: Dict[str, List[float]] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"iterations": self.iterations, "stages": {}}
        for stage, timings in self.stage_timings_ms.items():
            if not timings:
                continue
            p95 = statistics.quantiles(timings, n=20)[18] if len(timings) >= 20 else max(timings)
            p99 = statistics.quantiles(timings, n=100)[98] if len(timings) >= 100 else max(timings)
            out["stages"][stage] = {
                "mean_ms": round(statistics.mean(timings), 3),
                "median_ms": round(statistics.median(timings), 3),
                "p95_ms": round(p95, 3),
                "p99_ms": round(p99, 3),
                "min_ms": round(min(timings), 3),
                "max_ms": round(max(timings), 3),
                "stdev_ms": round(statistics.stdev(timings), 3) if len(timings) > 1 else 0.0,
            }
        if out["stages"]:
            out["total_pipeline_mean_ms"] = round(sum(v["mean_ms"] for v in out["stages"].values()), 3)
            out["total_pipeline_p95_ms"] = round(sum(v["p95_ms"] for v in out["stages"].values()), 3)
        return out


class PipelineLatencyBenchmark:
    SYNTHETIC_EVE_PHISHING = (
        '{"timestamp":"2026-01-01T00:00:00.000000+0000","flow_id":1,'
        '"event_type":"alert","src_ip":"10.0.0.99","src_port":54321,'
        '"dest_ip":"172.16.0.1","dest_port":80,"proto":"TCP",'
        '"alert":{"action":"allowed","gid":1,"signature_id":9901201,'
        '"rev":1,"signature":"AZAZEL DISASTER phishing - fake government domain",'
        '"category":"social-engineering","severity":2}}'
    )

    SYNTHETIC_EVE_PORTSCAN = (
        '{"timestamp":"2026-01-01T00:00:01.000000+0000","flow_id":2,'
        '"event_type":"alert","src_ip":"10.0.0.50","src_port":12345,'
        '"dest_ip":"172.16.0.1","dest_port":22,"proto":"TCP",'
        '"alert":{"action":"allowed","gid":1,"signature_id":9901221,'
        '"rev":1,"signature":"AZAZEL SCAN internal host rapid port scan",'
        '"category":"network-scan","severity":2}}'
    )

    def __init__(self, iterations: int = 1000, warmup: int = 50):
        self.iterations = iterations
        self.warmup = warmup

    @staticmethod
    def _eve_to_event(parsed: Dict[str, Any]) -> EvidenceEvent:
        alert = parsed.get("alert") if isinstance(parsed.get("alert"), dict) else {}
        src = str(parsed.get("src_ip") or "-")
        dst = str(parsed.get("dest_ip") or "-")
        port = int(parsed.get("dest_port") or 0)
        proto = str(parsed.get("proto") or "-")
        sid = int(alert.get("signature_id") or alert.get("sid") or 0)
        severity = int(alert.get("severity") or 1)
        risk_score = min(100, 40 + severity * 20)
        confidence_raw = 85
        return EvidenceEvent.build(
            ts=str(parsed.get("timestamp") or ""),
            source="suricata_eve",
            kind=str(parsed.get("event_type") or "alert"),
            subject=f"{src}->{dst}:{port}/{proto}",
            severity=risk_score,
            confidence=confidence_raw / 100.0,
            attrs={
                "sid": sid,
                "src_ip": src,
                "dst_ip": dst,
                "target_port": port,
                "protocol": proto,
                "attack_type": str(alert.get("category") or ""),
                "category": str(alert.get("category") or ""),
                "risk_score": risk_score,
                "confidence_raw": confidence_raw,
                "signature": str(alert.get("signature") or ""),
            },
            status="alert",
            evidence_refs=[f"suricata_sid:{sid}"] if sid else [],
        )

    def run(self) -> PipelineLatencyResult:
        parser = EVEParser()
        noc_eval = NocEvaluator()
        soc_eval = SocEvaluator()
        arbiter = ActionArbiter()

        result = PipelineLatencyResult(
            iterations=self.iterations,
            stage_timings_ms={
                "T2_eve_parse": [],
                "T3_evidence_dispatch": [],
                "T4_evaluators": [],
                "T5_arbiter": [],
            },
        )

        payloads = [self.SYNTHETIC_EVE_PHISHING, self.SYNTHETIC_EVE_PORTSCAN]
        for i in range(self.warmup):
            parsed = parser.parse_line(payloads[i % 2])
            if parsed is None:
                continue
            event = self._eve_to_event(parsed)
            noc_eval.evaluate([event])
            soc_eval.evaluate([event])

        for i in range(self.iterations):
            raw = payloads[i % 2]

            t0 = time.perf_counter()
            parsed = parser.parse_line(raw)
            t1 = time.perf_counter()
            result.stage_timings_ms["T2_eve_parse"].append((t1 - t0) * 1000)
            if parsed is None:
                continue

            t0 = time.perf_counter()
            event = self._eve_to_event(parsed)
            event_payload = event.to_dict()
            t1 = time.perf_counter()
            result.stage_timings_ms["T3_evidence_dispatch"].append((t1 - t0) * 1000)

            t0 = time.perf_counter()
            noc_result = noc_eval.evaluate([event_payload])
            soc_result = soc_eval.evaluate([event_payload])
            t1 = time.perf_counter()
            result.stage_timings_ms["T4_evaluators"].append((t1 - t0) * 1000)

            t0 = time.perf_counter()
            arbiter.decide(noc_eval.to_arbiter_input(noc_result), soc_eval.to_arbiter_input(soc_result))
            t1 = time.perf_counter()
            result.stage_timings_ms["T5_arbiter"].append((t1 - t0) * 1000)

        return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure software pipeline latency (T2->T5)")
    ap.add_argument("--iterations", type=int, default=1000)
    ap.add_argument("--warmup", type=int, default=50)
    args = ap.parse_args()
    summary = PipelineLatencyBenchmark(iterations=args.iterations, warmup=args.warmup).run().summary()
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
