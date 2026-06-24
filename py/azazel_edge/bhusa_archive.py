from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
DEFAULT_ARCHIVE_DIR = "/tmp/azazel-edge-bhusa-archive"
DEFAULT_RECORD_PATH = "/tmp/azazel-edge-bhusa-rehearsal.jsonl"
DEFAULT_SCENARIO = "mixed_correlation_demo"
DEFAULT_TRACE_ID = f"demo:{DEFAULT_SCENARIO}"
DEFAULT_EXPLANATIONS_PATH = "/tmp/azazel-edge-demo-explanations.jsonl"
DEFAULT_AUDIT_PATH = "/tmp/azazel-edge-demo-triage-audit.jsonl"


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
    if args.explanations_path != DEFAULT_EXPLANATIONS_PATH or args.audit_path != DEFAULT_AUDIT_PATH:
        return args.explanations_path, args.audit_path
    record_path = Path(args.record_path)
    base = record_path.with_suffix("")
    return f"{base}-demo-explanations.jsonl", f"{base}-demo-triage-audit.jsonl"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-archive",
        description="Build a BHUSA 2026 freeze/archive evidence package.",
    )
    parser.add_argument(
        "--archive-dir",
        default=DEFAULT_ARCHIVE_DIR,
        help=f"Archive output directory (default: {DEFAULT_ARCHIVE_DIR})",
    )
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"Rehearsal JSONL path (default: {DEFAULT_RECORD_PATH})",
    )
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO, help="Scenario to replay for archive evidence.")
    parser.add_argument("--trace-id", default=DEFAULT_TRACE_ID, help="Trace ID to audit-review for archive evidence.")
    parser.add_argument(
        "--explanations-path",
        default=DEFAULT_EXPLANATIONS_PATH,
        help=f"Explanation JSONL path for archive replay/audit evidence (default: {DEFAULT_EXPLANATIONS_PATH})",
    )
    parser.add_argument(
        "--audit-path",
        default=DEFAULT_AUDIT_PATH,
        help=f"Audit JSONL path for archive replay/audit evidence (default: {DEFAULT_AUDIT_PATH})",
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing archive directory.")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")
    return parser


def _git_snapshot() -> Dict[str, Any]:
    def read(*args: str) -> str:
        result = _run_command(["git", *args])
        if result.returncode != 0:
            raise ValueError(result.stderr.strip() or result.stdout.strip() or f"git {' '.join(args)} failed")
        return result.stdout.strip()

    status = read("status", "--short")
    return {
        "branch": read("branch", "--show-current"),
        "head_commit": read("rev-parse", "--short", "HEAD"),
        "head_subject": read("log", "-1", "--pretty=%s"),
        "dirty_files": [line for line in status.splitlines() if line.strip()],
    }


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run_report(archive_dir: Path, record_path: str, explanations_path: str, audit_path: str) -> Dict[str, Any]:
    report_dir = archive_dir / "readiness-report"
    cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-report"),
        "--record-path",
        record_path,
        "--report-dir",
        str(report_dir),
        "--explanations-path",
        explanations_path,
        "--audit-path",
        audit_path,
        "--force",
        "--json",
    ]
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"readiness report failed: {stderr}")
    payload = _load_json(result.stdout, context="azazel-edge-bhusa-report")
    payload["command"] = " ".join(cmd)
    return payload


def _run_demo_and_audit(args: argparse.Namespace, archive_dir: Path) -> Dict[str, Any]:
    explanations_path, audit_path = _evidence_paths(args)
    demo_cmd = [str(BIN_DIR / "azazel-edge-demo"), "run", args.scenario, "--format", "json"]
    demo_result = subprocess.run(
        demo_cmd,
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "AZAZEL_DEMO_EXPLANATIONS_PATH": explanations_path,
            "AZAZEL_DEMO_AUDIT_PATH": audit_path,
        },
    )
    if demo_result.returncode != 0:
        stderr = demo_result.stderr.strip() or demo_result.stdout.strip() or f"exit {demo_result.returncode}"
        raise ValueError(f"demo replay for archive failed: {stderr}")
    demo_json = _load_json(demo_result.stdout, context="azazel-edge-demo")
    _write_text(archive_dir / "evidence" / "demo-run.json", json.dumps(demo_json, ensure_ascii=False, indent=2) + "\n")

    compact_cmd = [
        str(BIN_DIR / "azazel-edge-audit-review"),
        "--explanations-path",
        explanations_path,
        "--audit-path",
        audit_path,
        "--trace-id",
        args.trace_id,
        "--compact",
    ]
    compact_result = _run_command(compact_cmd)
    if compact_result.returncode != 0:
        stderr = compact_result.stderr.strip() or compact_result.stdout.strip() or f"exit {compact_result.returncode}"
        raise ValueError(f"compact audit review for archive failed: {stderr}")
    _write_text(archive_dir / "evidence" / "audit-review-compact.txt", compact_result.stdout)

    return {
        "demo_command": " ".join(demo_cmd),
        "audit_compact_command": " ".join(compact_cmd),
        "audit_compact_output": compact_result.stdout.strip(),
        "selected_action": demo_json.get("result", {}).get("arbiter", {}).get("action"),
    }


def _build_archive(args: argparse.Namespace) -> Dict[str, Any]:
    archive_dir = Path(args.archive_dir)
    if archive_dir.exists():
        if not args.force:
            raise ValueError(f"archive directory already exists: {archive_dir}")
        shutil.rmtree(archive_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)

    explanations_path, audit_path = _evidence_paths(args)
    report = _run_report(archive_dir, args.record_path, explanations_path, audit_path)
    evidence = _run_demo_and_audit(args, archive_dir)
    git = _git_snapshot()

    commands_md = "\n".join(
        [
            "# BHUSA 2026 Archived Commands",
            "",
            "## Replay",
            f"`{evidence['demo_command']}`",
            "",
            "## Compact audit review",
            f"`{evidence['audit_compact_command']}`",
            "",
            "## Expected compact output snippet",
            "```text",
            evidence["audit_compact_output"],
            "```",
            "",
            "## Report command",
            f"`{report['command']}`",
            "",
        ]
    )
    _write_text(archive_dir / "ARCHIVED_COMMANDS.md", commands_md + "\n")
    _write_text(archive_dir / "git.json", json.dumps(git, ensure_ascii=False, indent=2) + "\n")

    payload = {
        "ok": True,
        "archive_dir": str(archive_dir),
        "report_dir": report["report_dir"],
        "status_json_path": report.get("status_json_path"),
        "status": report.get("status"),
        "commands_path": str(archive_dir / "ARCHIVED_COMMANDS.md"),
        "git_path": str(archive_dir / "git.json"),
        "evidence": evidence,
        "git": git,
    }
    _write_text(archive_dir / "archive.json", json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return payload


def _format_text(report: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "BHUSA 2026 ARCHIVE",
            f"archive_dir: {report['archive_dir']}",
            f"report_dir: {report['report_dir']}",
            f"commands_path: {report['commands_path']}",
            f"git_path: {report['git_path']}",
        ]
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = _build_archive(args)
    except ValueError as exc:
        if args.json_output:
            print(json.dumps({"ok": False, "errors": [str(exc)]}, ensure_ascii=False, indent=2))
        else:
            print(f"result: FAIL\nerror: {exc}")
        return 2

    if args.json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(_format_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
