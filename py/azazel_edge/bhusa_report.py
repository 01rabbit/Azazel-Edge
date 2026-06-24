from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
DEFAULT_REPORT_DIR = "/tmp/azazel-edge-bhusa-report"
DEFAULT_RECORD_PATH = "/tmp/azazel-edge-bhusa-rehearsal.jsonl"


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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-report",
        description="Generate a BHUSA 2026 readiness handoff report.",
    )
    parser.add_argument(
        "--report-dir",
        default=DEFAULT_REPORT_DIR,
        help=f"Output directory for REPORT.md and report.json (default: {DEFAULT_REPORT_DIR})",
    )
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"Rehearsal JSONL path (default: {DEFAULT_RECORD_PATH})",
    )
    parser.add_argument(
        "--verify-services",
        action="store_true",
        help="Include booth service checks in the freeze-check step.",
    )
    parser.add_argument(
        "--require-clean-tree",
        action="store_true",
        help="Require a clean git worktree in the freeze-check step.",
    )
    parser.add_argument(
        "--skip-github",
        action="store_true",
        help="Skip GitHub child issue lookups in the embedded readiness status snapshot.",
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
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing report directory.",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")
    return parser


def _run_bundle(bundle_dir: Path) -> Dict[str, Any]:
    cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-bundle"),
        "--output-dir",
        str(bundle_dir),
        "--force",
        "--json",
    ]
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"bundle generation failed: {stderr}")
    payload = _load_json(result.stdout, context="azazel-edge-bhusa-bundle")
    payload["command"] = " ".join(cmd)
    return payload


def _run_freeze_check(args: argparse.Namespace, bundle_dir: Path) -> Dict[str, Any]:
    explanations_path, audit_path = _evidence_paths(args)
    cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-freeze-check"),
        "--record-path",
        args.record_path,
        "--offline-doc-path",
        str(bundle_dir),
        "--explanations-path",
        explanations_path,
        "--audit-path",
        audit_path,
        "--json",
    ]
    if args.verify_services:
        cmd.append("--verify-services")
    if args.require_clean_tree:
        cmd.append("--require-clean-tree")
    result = _run_command(cmd)
    if result.returncode not in (0, 1):
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"freeze check failed to run: {stderr}")
    payload = _load_json(result.stdout, context="azazel-edge-bhusa-freeze-check")
    payload["command"] = " ".join(cmd)
    payload["exit_code"] = result.returncode
    return payload


def _run_status(args: argparse.Namespace) -> Dict[str, Any]:
    explanations_path, audit_path = _evidence_paths(args)
    cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-status"),
        "--record-path",
        args.record_path,
        "--explanations-path",
        explanations_path,
        "--audit-path",
        audit_path,
        "--json",
    ]
    if args.skip_github:
        cmd.append("--skip-github")
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"status snapshot failed: {stderr}")
    payload = _load_json(result.stdout, context="azazel-edge-bhusa-status")
    payload["command"] = " ".join(cmd)
    return payload


def _render_markdown(bundle: Dict[str, Any], freeze: Dict[str, Any], status: Dict[str, Any], report_dir: Path) -> str:
    git = freeze.get("git", {})
    full = freeze.get("full_rehearsal_variant", {})
    status_github = status.get("github", {})
    open_issues = [item for item in status_github.get("issues", []) if item.get("state") == "OPEN"]
    lines = [
        "# BHUSA 2026 Readiness Report",
        "",
        "## Snapshot",
        "",
        f"- Report directory: `{report_dir}`",
        f"- Git branch: `{git.get('branch', '')}`",
        f"- Git head: `{git.get('head_commit', '')}`",
        f"- Git subject: {git.get('head_subject', '')}",
        f"- Freeze gate: {'PASS' if freeze.get('ok') else 'FAIL'}",
        f"- Readiness state: `{status.get('overall_state')}`",
        f"- Days until session: `{status.get('days_until_session')}`",
        f"- Bundle documents: `{bundle.get('document_count', 0)}`",
        "",
        "## Booth Verification",
        "",
        f"- Booth verify ok: `{freeze.get('booth_verify', {}).get('ok')}`",
        f"- Action: `{freeze.get('booth_verify', {}).get('demo', {}).get('action')}`",
        f"- Policy profile: `{freeze.get('booth_verify', {}).get('demo', {}).get('policy_profile')}`",
        f"- Config hash: `{freeze.get('booth_verify', {}).get('demo', {}).get('config_hash')}`",
        "",
        "## Rehearsals",
        "",
        f"- Total runs: `{freeze.get('rehearsal_summary', {}).get('total_runs')}`",
        f"- Full runs: `{full.get('runs')}`",
        f"- Full passes: `{full.get('passes')}`",
        f"- Fallback drill runs: `{freeze.get('rehearsal_summary', {}).get('fallback_drill_runs')}`",
        f"- Average full duration: `{full.get('avg_presenter_duration_sec')}`",
        "",
        "## Child Issue State",
        "",
        f"- GitHub lookups enabled: `{status_github.get('enabled')}`",
        f"- Linked child issues: `{status_github.get('linked_issue_count')}`",
        f"- Open child issues: `{len(open_issues)}`",
        "",
    ]
    for item in open_issues:
        lines.append(f"- OPEN `#{item.get('number')}` {item.get('title')}")
    if status_github.get("warnings"):
        lines.extend(["", "## GitHub Warnings", ""])
        for item in status_github.get("warnings", []):
            lines.append(f"- {item}")
    lines.extend(
        [
            "",
        "## Documentation Checks",
        "",
        ]
    )
    for item in freeze.get("doc_checks", []):
        lines.append(f"- `{item.get('description')}`: `{'PASS' if item.get('ok') else 'FAIL'}`")
    lines.extend(["", "## Offline Bundle", ""])
    for item in bundle.get("documents", []):
        lines.append(f"- `{item.get('bundle_path')}` <- `{item.get('source')}`")
    if status.get("remaining_work"):
        lines.extend(["", "## Remaining Work", ""])
        for item in status.get("remaining_work", []):
            lines.append(f"- {item}")
    if freeze.get("manual_pending"):
        lines.extend(["", "## Manual Pending", ""])
        for item in freeze.get("manual_pending", []):
            lines.append(f"- {item}")
    if freeze.get("failures"):
        lines.extend(["", "## Failures", ""])
        for item in freeze.get("failures", []):
            lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def _build_report(args: argparse.Namespace) -> Dict[str, Any]:
    report_dir = Path(args.report_dir)
    if report_dir.exists():
        if not args.force:
            raise ValueError(f"report directory already exists: {report_dir}")
        for child in sorted(report_dir.iterdir(), reverse=True):
            if child.is_dir():
                import shutil
                shutil.rmtree(child)
            else:
                child.unlink()
    report_dir.mkdir(parents=True, exist_ok=True)

    bundle_dir = report_dir / "offline-bundle"
    bundle = _run_bundle(bundle_dir)
    freeze = _run_freeze_check(args, bundle_dir)
    status = _run_status(args)
    markdown = _render_markdown(bundle, freeze, status, report_dir)

    report_path = report_dir / "REPORT.md"
    json_path = report_dir / "report.json"
    status_path = report_dir / "status.json"
    report_path.write_text(markdown, encoding="utf-8")
    payload = {
        "ok": True,
        "report_dir": str(report_dir),
        "report_markdown_path": str(report_path),
        "report_json_path": str(json_path),
        "status_json_path": str(status_path),
        "bundle": bundle,
        "freeze_check": freeze,
        "status": status,
    }
    status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def _format_text(report: Dict[str, Any]) -> str:
    freeze = report["freeze_check"]
    return "\n".join(
        [
            "BHUSA 2026 READINESS REPORT",
            f"report_dir: {report['report_dir']}",
            f"report_markdown_path: {report['report_markdown_path']}",
            f"freeze_gate: {'PASS' if freeze.get('ok') else 'FAIL'}",
            f"bundle_documents: {report['bundle'].get('document_count')}",
        ]
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = _build_report(args)
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
