#!/usr/bin/env python3
"""Offline, non-enforcing Black Hat Europe 2026 replay and evidence gate."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = "auditable_edge_socnoc"
ACTIONS = {"observe", "notify", "throttle", "redirect", "isolate"}

def validate(result: dict, explanation: dict, audit_path: Path) -> dict:
    execution = result.get("execution", {})
    arbiter = result.get("arbiter", {})
    problems = []
    for key, expected in (("mode", "deterministic_replay"), ("ai_used", False),
                          ("live_telemetry", False), ("local_only", True)):
        if execution.get(key) != expected:
            problems.append(f"execution.{key} must equal {expected!r}")
    if arbiter.get("action") not in ACTIONS:
        problems.append("arbiter.action is not one of the five bounded actions")
    if explanation.get("selected_action") != arbiter.get("action"):
        problems.append("explanation.selected_action does not match arbiter.action")
    for field in ("release_condition", "policy_profile", "config_hash", "trace_id"):
        if not explanation.get(field):
            problems.append(f"missing explanation.{field}")
    if not explanation.get("rejected_actions"):
        problems.append("missing rejected_actions")
    rejected = explanation.get("rejected_actions", [])
    reasons = explanation.get("why_not_others", [])
    if not isinstance(reasons, list) or any(not isinstance(item, dict) or not item.get("reason") for item in reasons):
        problems.append("rejected alternatives must include reasons")
    if rejected and not reasons:
        problems.append("missing why_not_others explanations")
    if explanation.get("trace_id") != execution.get("trace_id"):
        problems.append("trace_id mismatch")
    if not audit_path.is_file():
        problems.append("audit JSONL not generated")
        audit_lines = []
    else:
        audit_lines = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
    decisions = [row for row in audit_lines if row.get("kind") == "action_decision"]
    if not decisions:
        problems.append("no action_decision in audit")
    else:
        last = decisions[-1]
        if last.get("trace_id") != execution.get("trace_id"):
            problems.append("audit trace_id mismatch")
    return {"ok": not problems, "problems": problems,
            "action": arbiter.get("action"), "trace_id": execution.get("trace_id"),
            "audit_entries": len(audit_lines)}

def run(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bheurope-2026-") as temp:
        env = os.environ.copy()
        env["AZAZEL_DEMO_EXPLANATIONS_PATH"] = str(Path(temp) / "explanations.jsonl")
        env["AZAZEL_DEMO_AUDIT_PATH"] = str(Path(temp) / "audit.jsonl")
        env["AZAZEL_DEFENSE_ENFORCE"] = "0"
        env["AZAZEL_SOC_POLICY_PATH"] = str(ROOT / "config/soc_policy_profiles/demo.yaml")
        command = [sys.executable, str(ROOT / "bin/azazel-edge-scenario-replay"),
                   "run", SCENARIO, "--format", "json"]
        completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
        if completed.returncode:
            raise RuntimeError(f"replay failed ({completed.returncode}): {completed.stderr[-2000:]}")
        payload = json.loads(completed.stdout)
        if not payload.get("ok"):
            raise RuntimeError("replay returned ok=false")
        result = payload["result"]
        explanation_path = Path(env["AZAZEL_DEMO_EXPLANATIONS_PATH"])
        audit_path = Path(env["AZAZEL_DEMO_AUDIT_PATH"])
        explanations = [json.loads(x) for x in explanation_path.read_text().splitlines() if x.strip()]
        if not explanations:
            raise RuntimeError("no explanation JSONL generated")
        sys.path.insert(0, str(ROOT / "py"))
        from azazel_edge.audit.logger import P0AuditLogger
        chain = P0AuditLogger.verify_chain(audit_path)
        gate = validate(result, explanations[-1], audit_path)
        gate["chain_verification"] = chain
        gate["ok"] = gate["ok"] and chain.get("ok") is True and chain.get("entries", 0) > 0
        if not chain.get("ok"):
            gate["problems"].append(f"audit chain verification failed: {chain}")
        (out / "result.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        (out / "explanations.jsonl").write_bytes(explanation_path.read_bytes())
        (out / "audit.jsonl").write_bytes(audit_path.read_bytes())
        (out / "gate.json").write_text(json.dumps(gate, indent=2) + "\n")
        return gate

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("artifacts/bheurope-2026"))
    args = parser.parse_args()
    try:
        gate = run(args.out)
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(gate, indent=2))
    return 0 if gate["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
