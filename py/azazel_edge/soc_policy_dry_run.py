from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.evaluators import SocEvaluator
from azazel_edge.evidence_plane import adapt_suricata_record
from azazel_edge.policy import load_soc_policy


def _load_events(path: Path, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows[-max(1, limit) :]


def _to_suricata_like_event(row: dict[str, Any]) -> dict[str, Any]:
    norm = row.get("normalized") if isinstance(row.get("normalized"), dict) else row
    return adapt_suricata_record(
        {
            "normalized": {
                "ts": str(norm.get("ts") or ""),
                "sid": int(norm.get("sid") or 0),
                "severity": int(norm.get("severity") or 3),
                "attack_type": str(norm.get("attack_type") or "unknown"),
                "category": str(norm.get("category") or "unknown"),
                "event_type": str(norm.get("event_type") or "alert"),
                "action": str(norm.get("action") or "allowed"),
                "protocol": str(norm.get("protocol") or "tcp"),
                "target_port": int(norm.get("target_port") or 0),
                "src_ip": str(norm.get("src_ip") or ""),
                "dst_ip": str(norm.get("dst_ip") or ""),
                "risk_score": int(norm.get("risk_score") or 0),
                "confidence": int(norm.get("confidence") or 50),
                "ingest_epoch": float(norm.get("ingest_epoch") or 0.0),
            }
        }
    )


def run(policy_path: Path, events_path: Path, limit: int) -> dict[str, Any]:
    policy = load_soc_policy(policy_path)
    suppression = policy.get("suppression_defaults") if isinstance(policy.get("suppression_defaults"), dict) else {}
    evaluator = SocEvaluator(suppression_policy=suppression)
    arbiter = ActionArbiter(policy=policy)

    raw_rows = _load_events(events_path, limit=limit)
    events = [_to_suricata_like_event(row) for row in raw_rows]
    soc = evaluator.evaluate(events)
    noc_stub = {
        "availability": {"label": "good", "evidence_ids": []},
        "path_health": {"label": "good", "evidence_ids": []},
        "device_health": {"label": "good", "evidence_ids": []},
        "capacity_health": {"label": "good", "evidence_ids": []},
        "client_inventory_health": {"label": "good", "evidence_ids": []},
        "config_drift_health": {"label": "good", "evidence_ids": []},
        "client_health": {"label": "good"},
        "summary": {},
        "evidence_ids": [],
    }
    arbiter_result = arbiter.decide(noc_stub, arbiter_input_from_soc(soc), client_impact={"score": 0, "critical_client_count": 0})
    return {
        "ok": True,
        "policy_version": policy.get("version"),
        "policy_hash": policy.get("hash"),
        "events_evaluated": len(events),
        "soc_summary": soc.get("summary", {}),
        "arbiter": arbiter_result,
    }


def arbiter_input_from_soc(soc: dict[str, Any]) -> dict[str, Any]:
    return {
        "suspicion": soc.get("suspicion", {"score": 0, "label": "low", "evidence_ids": []}),
        "confidence": soc.get("confidence", {"score": 0, "label": "low", "evidence_ids": []}),
        "technique_likelihood": soc.get("technique_likelihood", {"score": 0, "label": "low", "evidence_ids": []}),
        "blast_radius": soc.get("blast_radius", {"score": 0, "label": "low", "evidence_ids": []}),
        "summary": soc.get("summary", {}),
        "evidence_ids": soc.get("evidence_ids", []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Dry-run current SOC policy against local normalized events.")
    parser.add_argument("--policy", default="config/soc_policy.yaml")
    parser.add_argument("--events", default="/var/log/azazel-edge/normalized-events.jsonl")
    parser.add_argument("--limit", type=int, default=200)
    args = parser.parse_args()
    result = run(Path(args.policy), Path(args.events), max(1, args.limit))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

