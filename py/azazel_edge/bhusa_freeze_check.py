from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
DEFAULT_RECORD_PATH = "/tmp/azazel-edge-bhusa-rehearsal.jsonl"
DEFAULT_SCENARIO = "mixed_correlation_demo"
DEFAULT_TRACE_ID = f"demo:{DEFAULT_SCENARIO}"
README_PATH = ROOT_DIR / "README.md"
LIVE_BOUNDARY_PATH = ROOT_DIR / "docs" / "arsenal" / "bhusa-2026-live-boundary.md"
BOOTH_MESSAGE_PATH = ROOT_DIR / "docs" / "arsenal" / "bhusa-2026-booth-message.md"


def _run_command(cmd: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )


def _load_json(stdout: str, *, context: str) -> Dict[str, Any]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{context} returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{context} returned non-object JSON")
    return payload


def _evidence_paths(args: argparse.Namespace) -> tuple[str, str]:
    if args.explanations_path and args.audit_path:
        return args.explanations_path, args.audit_path
    record_path = Path(args.record_path)
    base = record_path.with_suffix("")
    explanations_path = args.explanations_path or f"{base}-demo-explanations.jsonl"
    audit_path = args.audit_path or f"{base}-demo-triage-audit.jsonl"
    return explanations_path, audit_path


def _git_value(*args: str) -> str:
    result = _run_command(["git", *args])
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"git {' '.join(args)} failed"
        raise ValueError(stderr)
    return result.stdout.strip()


def _git_dirty_files() -> List[str]:
    output = _git_value("status", "--short")
    if not output:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def _check_contains(path: Path, needle: str, description: str) -> Dict[str, Any]:
    if not path.exists():
        return {"ok": False, "description": description, "detail": f"missing file: {path}"}
    text = path.read_text(encoding="utf-8")
    if needle in text:
        return {"ok": True, "description": description, "detail": needle}
    return {"ok": False, "description": description, "detail": f"missing phrase: {needle}"}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-freeze-check",
        description="Run the local BHUSA 2026 freeze gate checks.",
    )
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO, help="Scenario to verify for the freeze gate.")
    parser.add_argument("--trace-id", default=DEFAULT_TRACE_ID, help="Expected trace ID for booth verification.")
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"Rehearsal JSONL path (default: {DEFAULT_RECORD_PATH})",
    )
    parser.add_argument(
        "--min-full-rehearsals",
        type=int,
        default=3,
        help="Minimum required successful full rehearsals.",
    )
    parser.add_argument(
        "--min-fallback-drills",
        type=int,
        default=1,
        help="Minimum required fallback-drill runs across the rehearsal log.",
    )
    parser.add_argument(
        "--require-clean-tree",
        action="store_true",
        help="Fail when git status is dirty.",
    )
    parser.add_argument(
        "--verify-services",
        action="store_true",
        help="Include booth service checks in the underlying booth verification.",
    )
    parser.add_argument(
        "--offline-doc-path",
        action="append",
        default=[],
        help="Optional path that must exist on the booth machine as offline documentation evidence.",
    )
    parser.add_argument(
        "--explanations-path",
        default=None,
        help="Optional explanation JSONL path for isolated booth verification evidence.",
    )
    parser.add_argument(
        "--audit-path",
        default=None,
        help="Optional audit JSONL path for isolated booth verification evidence.",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")
    return parser


def _run_booth_verify(args: argparse.Namespace) -> Dict[str, Any]:
    explanations_path, audit_path = _evidence_paths(args)
    cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-verify"),
        "--scenario",
        args.scenario,
        "--trace-id",
        args.trace_id,
        "--explanations-path",
        explanations_path,
        "--audit-path",
        audit_path,
        "--json",
    ]
    if not args.verify_services:
        cmd.append("--skip-services")
    result = _run_command(cmd)
    if result.returncode not in (0, 1):
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"booth verify failed: {stderr}")
    payload = _load_json(result.stdout, context="azazel-edge-bhusa-verify")
    payload["command"] = " ".join(cmd)
    return payload


def _run_rehearsal_summary(record_path: str) -> Dict[str, Any]:
    cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-rehearse"),
        "summary",
        "--record-path",
        record_path,
        "--json",
    ]
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"rehearsal summary failed: {stderr}")
    payload = _load_json(result.stdout, context="azazel-edge-bhusa-rehearse summary")
    payload["command"] = " ".join(cmd)
    return payload


def _find_variant(summary: Dict[str, Any], variant: str) -> Dict[str, Any]:
    for item in summary.get("variants", []):
        if item.get("variant") == variant:
            return item
    return {"variant": variant, "runs": 0, "passes": 0, "fallback_drills": 0, "avg_presenter_duration_sec": None}


def _build_report(args: argparse.Namespace) -> Dict[str, Any]:
    booth_verify = _run_booth_verify(args)
    rehearsal_summary = _run_rehearsal_summary(args.record_path)
    full_variant = _find_variant(rehearsal_summary, "full")

    branch = _git_value("branch", "--show-current")
    head_commit = _git_value("rev-parse", "--short", "HEAD")
    head_subject = _git_value("log", "-1", "--pretty=%s")
    dirty_files = _git_dirty_files()

    doc_checks = [
        _check_contains(
            README_PATH,
            "Azazel-Edge is not a production SIEM replacement",
            "README states Azazel-Edge is not a production SIEM replacement",
        ),
        _check_contains(
            BOOTH_MESSAGE_PATH,
            "optional AI assist for operator support",
            "booth docs describe AI as optional operator support",
        ),
        _check_contains(
            LIVE_BOUNDARY_PATH,
            "Normal operation | BHUSA 2026 booth path",
            "live boundary docs keep replay separate from normal live operation",
        ),
    ]
    offline_doc_checks: List[Dict[str, Any]] = []
    for raw in args.offline_doc_path:
        path = Path(raw)
        offline_doc_checks.append(
            {
                "path": raw,
                "ok": path.exists(),
                "detail": "present" if path.exists() else "missing",
            }
        )

    failures: List[str] = []
    if not booth_verify.get("ok"):
        failures.extend(str(item) for item in booth_verify.get("errors", []))
    if full_variant.get("passes", 0) < args.min_full_rehearsals:
        failures.append(
            f"successful full rehearsals below threshold: {full_variant.get('passes', 0)} < {args.min_full_rehearsals}"
        )
    if rehearsal_summary.get("fallback_drill_runs", 0) < args.min_fallback_drills:
        failures.append(
            f"fallback drill runs below threshold: {rehearsal_summary.get('fallback_drill_runs', 0)} < {args.min_fallback_drills}"
        )
    for item in doc_checks:
        if not item["ok"]:
            failures.append(f"{item['description']}: {item['detail']}")
    for item in offline_doc_checks:
        if not item["ok"]:
            failures.append(f"offline doc missing: {item['path']}")
    if args.require_clean_tree and dirty_files:
        failures.append(f"git worktree is dirty ({len(dirty_files)} paths)")

    manual_pending: List[str] = []
    if not args.offline_doc_path:
        manual_pending.append("offline booth docs presence was not checked; pass --offline-doc-path to validate on the device")
    if not args.require_clean_tree:
        manual_pending.append("git worktree cleanliness not enforced; pass --require-clean-tree for the final freeze gate")

    return {
        "ok": not failures,
        "scenario_id": args.scenario,
        "trace_id": args.trace_id,
        "git": {
            "branch": branch,
            "head_commit": head_commit,
            "head_subject": head_subject,
            "dirty": bool(dirty_files),
            "dirty_files": dirty_files,
        },
        "thresholds": {
            "min_full_rehearsals": args.min_full_rehearsals,
            "min_fallback_drills": args.min_fallback_drills,
        },
        "booth_verify": booth_verify,
        "rehearsal_summary": rehearsal_summary,
        "full_rehearsal_variant": full_variant,
        "doc_checks": doc_checks,
        "offline_doc_checks": offline_doc_checks,
        "manual_pending": manual_pending,
        "failures": failures,
    }


def _format_text(report: Dict[str, Any]) -> str:
    git = report["git"]
    full = report["full_rehearsal_variant"]
    lines = [
        "BHUSA 2026 FREEZE CHECK",
        f"scenario: {report['scenario_id']}",
        f"trace_id: {report['trace_id']}",
        f"git: branch={git['branch']} head={git['head_commit']} dirty={git['dirty']}",
        (
            "rehearsals: "
            f"full_passes={full.get('passes')} "
            f"full_runs={full.get('runs')} "
            f"fallback_drills={report['rehearsal_summary'].get('fallback_drill_runs')}"
        ),
        (
            "booth_verify: "
            f"ok={report['booth_verify'].get('ok')} "
            f"action={report['booth_verify'].get('demo', {}).get('action')} "
            f"policy={report['booth_verify'].get('demo', {}).get('policy_profile')}"
        ),
    ]
    for item in report["doc_checks"]:
        lines.append(f"doc_check: {item['description']} ok={item['ok']}")
    for item in report["offline_doc_checks"]:
        lines.append(f"offline_doc: path={item['path']} ok={item['ok']}")
    if report["manual_pending"]:
        lines.extend(f"manual_pending: {item}" for item in report["manual_pending"])
    if report["failures"]:
        lines.append("result: FAIL")
        lines.extend(f"failure: {item}" for item in report["failures"])
    else:
        lines.append("result: PASS")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = _build_report(args)
    except ValueError as exc:
        if args.json_output:
            print(json.dumps({"ok": False, "failures": [str(exc)]}, ensure_ascii=False, indent=2))
        else:
            print(f"result: FAIL\nfailure: {exc}")
        return 2

    if args.json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(_format_text(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
