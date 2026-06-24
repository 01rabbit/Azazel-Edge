from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
DEFAULT_RECORD_PATH = "/tmp/azazel-edge-bhusa-rehearsal.jsonl"
DEFAULT_OUTPUT_ROOT = "/tmp/azazel-edge-bhusa-prep"


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


def _add_common_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"Rehearsal JSONL path (default: {DEFAULT_RECORD_PATH})",
    )
    parser.add_argument(
        "--output-root",
        default=DEFAULT_OUTPUT_ROOT,
        help=f"Output root directory (default: {DEFAULT_OUTPUT_ROOT})",
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-prep",
        description="One-shot orchestration entrypoint for BHUSA 2026 readiness helpers.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ops = sub.add_parser("ops-pack", help="Generate the operator/booth pack (bundle + report)")
    _add_common_paths(ops)
    ops.add_argument("--force", action="store_true", help="Replace existing output directories.")
    ops.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")

    freeze = sub.add_parser("freeze-pack", help="Generate the freeze pack (archive + freeze record)")
    _add_common_paths(freeze)
    freeze.add_argument("--force", action="store_true", help="Replace existing output directories.")
    freeze.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")

    repo_sync = sub.add_parser("repo-sync", help="Refresh repo-side BHUSA status and issue-tracking artifacts")
    _add_common_paths(repo_sync)
    repo_sync.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")

    daily = sub.add_parser(
        "daily-pack",
        help="Refresh repo-side status artifacts and generate the operator/booth pack",
    )
    _add_common_paths(daily)
    daily.add_argument("--force", action="store_true", help="Replace existing output directories.")
    daily.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")

    candidate = sub.add_parser(
        "candidate-pack",
        help="Refresh tracking artifacts, generate operator/freeze packs, and run the local freeze gate",
    )
    _add_common_paths(candidate)
    candidate.add_argument("--force", action="store_true", help="Replace existing output directories.")
    candidate.add_argument(
        "--verify-services",
        action="store_true",
        help="Include booth service checks in the freeze gate verification.",
    )
    candidate.add_argument(
        "--require-clean-tree",
        action="store_true",
        help="Fail the freeze gate when the git worktree is dirty.",
    )
    candidate.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")

    full = sub.add_parser("full-pack", help="Generate both the operator pack and the freeze pack")
    _add_common_paths(full)
    full.add_argument("--force", action="store_true", help="Replace existing output directories.")
    full.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")

    return parser


def _invoke(cmd: List[str], context: str) -> Dict[str, Any]:
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"{context} failed: {stderr}")
    payload = _load_json(result.stdout, context=context)
    payload["command"] = " ".join(cmd)
    return payload


def _build_candidate_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    status = report["repo_sync"]["status"]
    freeze_gate = report["freeze_gate"]
    github = status.get("github", {})
    open_issues = [item for item in github.get("issues", []) if item.get("state") == "OPEN"]
    freeze_gate_failures = list(freeze_gate.get("failures", []))
    freeze_gate_manual_pending = list(freeze_gate.get("manual_pending", []))
    remaining_work = list(status.get("remaining_work", []))
    blocker_count = len(open_issues) + len(freeze_gate_failures)
    return {
        "ready_for_freeze": bool(freeze_gate.get("ok")) and not open_issues,
        "overall_state": status.get("overall_state"),
        "freeze_gate_ok": bool(freeze_gate.get("ok")),
        "open_child_issue_count": len(open_issues),
        "remaining_work_count": len(remaining_work),
        "freeze_gate_failure_count": len(freeze_gate_failures),
        "manual_pending_count": len(freeze_gate_manual_pending),
        "blocker_count": blocker_count,
        "next_actions": remaining_work[:5],
    }


def _ops_pack(args: argparse.Namespace) -> Dict[str, Any]:
    root = Path(args.output_root)
    bundle_dir = root / "offline-bundle"
    report_dir = root / "report"
    shared = ["--record-path", args.record_path]
    bundle = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-bundle"),
            "--output-dir",
            str(bundle_dir),
            *(["--force"] if args.force else []),
            "--json",
        ],
        context="azazel-edge-bhusa-bundle",
    )
    report = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-report"),
            *shared,
            "--report-dir",
            str(report_dir),
            *(["--explanations-path", args.explanations_path] if args.explanations_path else []),
            *(["--audit-path", args.audit_path] if args.audit_path else []),
            *(["--force"] if args.force else []),
            "--json",
        ],
        context="azazel-edge-bhusa-report",
    )
    return {
        "ok": True,
        "mode": "ops-pack",
        "output_root": str(root),
        "bundle": bundle,
        "report": report,
    }


def _freeze_pack(args: argparse.Namespace) -> Dict[str, Any]:
    root = Path(args.output_root)
    archive_dir = root / "archive"
    freeze_dir = root / "freeze-record"
    archive = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-archive"),
            "--record-path",
            args.record_path,
            "--archive-dir",
            str(archive_dir),
            *(["--explanations-path", args.explanations_path] if args.explanations_path else []),
            *(["--audit-path", args.audit_path] if args.audit_path else []),
            *(["--force"] if args.force else []),
            "--json",
        ],
        context="azazel-edge-bhusa-archive",
    )
    freeze_record = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-freeze-record"),
            "--record-path",
            args.record_path,
            "--archive-dir",
            str(archive_dir),
            "--record-dir",
            str(freeze_dir),
            *(["--explanations-path", args.explanations_path] if args.explanations_path else []),
            *(["--audit-path", args.audit_path] if args.audit_path else []),
            *(["--force"] if args.force else []),
            "--json",
        ],
        context="azazel-edge-bhusa-freeze-record",
    )
    return {
        "ok": True,
        "mode": "freeze-pack",
        "output_root": str(root),
        "archive": archive,
        "freeze_record": freeze_record,
    }


def _repo_sync(args: argparse.Namespace) -> Dict[str, Any]:
    status = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-status"),
            "--record-path",
            args.record_path,
            *(["--explanations-path", args.explanations_path] if args.explanations_path else []),
            *(["--audit-path", args.audit_path] if args.audit_path else []),
            "--write-status-doc",
            "--json",
        ],
        context="azazel-edge-bhusa-status",
    )
    sync_links = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-issues"),
            "sync-links",
            "--write",
            "--json",
        ],
        context="azazel-edge-bhusa-issues sync-links",
    )
    parent_comment = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-issues"),
            "parent-comment",
            "--write",
            "--json",
        ],
        context="azazel-edge-bhusa-issues parent-comment",
    )
    progress_comment = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-issues"),
            "progress-comment",
            "--record-path",
            args.record_path,
            *(["--write"]),
            *(["--json"]),
        ],
        context="azazel-edge-bhusa-issues progress-comment",
    )
    return {
        "ok": True,
        "mode": "repo-sync",
        "output_root": str(Path(args.output_root)),
        "status": status,
        "sync_links": sync_links,
        "parent_comment": parent_comment,
        "progress_comment": progress_comment,
    }


def _format_text(report: Dict[str, Any]) -> str:
    lines = [
        "BHUSA 2026 PREP",
        f"mode: {report['mode']}",
        f"output_root: {report['output_root']}",
    ]
    if report["mode"] == "ops-pack":
        lines.append(f"bundle_dir: {report['bundle']['output_dir']}")
        lines.append(f"report_dir: {report['report']['report_dir']}")
    elif report["mode"] == "freeze-pack":
        lines.append(f"archive_dir: {report['archive']['archive_dir']}")
        lines.append(f"freeze_record_dir: {report['freeze_record']['record_dir']}")
    elif report["mode"] == "repo-sync":
        lines.append(f"status_doc_path: {report['status'].get('status_doc_path')}")
        lines.append(f"links_path: {report['sync_links'].get('links_path')}")
        lines.append(f"parent_comment_path: {report['parent_comment'].get('output_path')}")
        lines.append(f"progress_comment_path: {report['progress_comment'].get('output_path')}")
    elif report["mode"] == "daily-pack":
        lines.append(f"status_doc_path: {report['repo_sync']['status'].get('status_doc_path')}")
        lines.append(f"links_path: {report['repo_sync']['sync_links'].get('links_path')}")
        lines.append(f"parent_comment_path: {report['repo_sync']['parent_comment'].get('output_path')}")
        lines.append(f"progress_comment_path: {report['repo_sync']['progress_comment'].get('output_path')}")
        lines.append(f"bundle_dir: {report['ops_pack']['bundle']['output_dir']}")
        lines.append(f"report_dir: {report['ops_pack']['report']['report_dir']}")
    elif report["mode"] == "candidate-pack":
        summary = report["candidate_summary"]
        lines.append(f"status_doc_path: {report['repo_sync']['status'].get('status_doc_path')}")
        lines.append(f"links_path: {report['repo_sync']['sync_links'].get('links_path')}")
        lines.append(f"parent_comment_path: {report['repo_sync']['parent_comment'].get('output_path')}")
        lines.append(f"progress_comment_path: {report['repo_sync']['progress_comment'].get('output_path')}")
        lines.append(f"bundle_dir: {report['ops_pack']['bundle']['output_dir']}")
        lines.append(f"report_dir: {report['ops_pack']['report']['report_dir']}")
        lines.append(f"archive_dir: {report['freeze_pack']['archive']['archive_dir']}")
        lines.append(f"freeze_record_dir: {report['freeze_pack']['freeze_record']['record_dir']}")
        lines.append(f"freeze_gate_ok: {report['freeze_gate'].get('ok')}")
        lines.append(f"ready_for_freeze: {summary.get('ready_for_freeze')}")
        lines.append(f"open_child_issue_count: {summary.get('open_child_issue_count')}")
        lines.append(f"blocker_count: {summary.get('blocker_count')}")
    else:
        lines.append(f"ops_bundle_dir: {report['ops_pack']['bundle']['output_dir']}")
        lines.append(f"ops_report_dir: {report['ops_pack']['report']['report_dir']}")
        lines.append(f"freeze_archive_dir: {report['freeze_pack']['archive']['archive_dir']}")
        lines.append(f"freeze_record_dir: {report['freeze_pack']['freeze_record']['record_dir']}")
    return "\n".join(lines)


def _full_pack(args: argparse.Namespace) -> Dict[str, Any]:
    root = Path(args.output_root)
    ops_args = argparse.Namespace(
        record_path=args.record_path,
        output_root=str(root / "ops-pack"),
        explanations_path=args.explanations_path,
        audit_path=args.audit_path,
        force=args.force,
    )
    freeze_args = argparse.Namespace(
        record_path=args.record_path,
        output_root=str(root / "freeze-pack"),
        explanations_path=args.explanations_path,
        audit_path=args.audit_path,
        force=args.force,
    )
    ops_report = _ops_pack(ops_args)
    freeze_report = _freeze_pack(freeze_args)
    return {
        "ok": True,
        "mode": "full-pack",
        "output_root": str(root),
        "ops_pack": ops_report,
        "freeze_pack": freeze_report,
    }


def _daily_pack(args: argparse.Namespace) -> Dict[str, Any]:
    root = Path(args.output_root)
    repo_args = argparse.Namespace(
        record_path=args.record_path,
        output_root=str(root / "repo-sync"),
        explanations_path=args.explanations_path,
        audit_path=args.audit_path,
    )
    ops_args = argparse.Namespace(
        record_path=args.record_path,
        output_root=str(root / "ops-pack"),
        explanations_path=args.explanations_path,
        audit_path=args.audit_path,
        force=args.force,
    )
    repo_report = _repo_sync(repo_args)
    ops_report = _ops_pack(ops_args)
    return {
        "ok": True,
        "mode": "daily-pack",
        "output_root": str(root),
        "repo_sync": repo_report,
        "ops_pack": ops_report,
    }


def _candidate_pack(args: argparse.Namespace) -> Dict[str, Any]:
    root = Path(args.output_root)
    repo_args = argparse.Namespace(
        record_path=args.record_path,
        output_root=str(root / "repo-sync"),
        explanations_path=args.explanations_path,
        audit_path=args.audit_path,
    )
    ops_args = argparse.Namespace(
        record_path=args.record_path,
        output_root=str(root / "ops-pack"),
        explanations_path=args.explanations_path,
        audit_path=args.audit_path,
        force=args.force,
    )
    freeze_args = argparse.Namespace(
        record_path=args.record_path,
        output_root=str(root / "freeze-pack"),
        explanations_path=args.explanations_path,
        audit_path=args.audit_path,
        force=args.force,
    )
    repo_report = _repo_sync(repo_args)
    ops_report = _ops_pack(ops_args)
    status_with_freeze = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-status"),
            "--record-path",
            args.record_path,
            "--include-freeze-check",
            "--offline-doc-path",
            str(root / "ops-pack" / "offline-bundle"),
            *(["--explanations-path", args.explanations_path] if args.explanations_path else []),
            *(["--audit-path", args.audit_path] if args.audit_path else []),
            "--write-status-doc",
            "--json",
        ],
        context="azazel-edge-bhusa-status",
    )
    repo_report["status"] = status_with_freeze
    freeze_report = _freeze_pack(freeze_args)
    freeze_gate = _invoke(
        [
            str(BIN_DIR / "azazel-edge-bhusa-freeze-check"),
            "--record-path",
            args.record_path,
            "--offline-doc-path",
            str(root / "ops-pack" / "offline-bundle"),
            *(["--explanations-path", args.explanations_path] if args.explanations_path else []),
            *(["--audit-path", args.audit_path] if args.audit_path else []),
            *(["--verify-services"] if args.verify_services else []),
            *(["--require-clean-tree"] if args.require_clean_tree else []),
            "--json",
        ],
        context="azazel-edge-bhusa-freeze-check",
    )
    return {
        "ok": True,
        "mode": "candidate-pack",
        "output_root": str(root),
        "repo_sync": repo_report,
        "ops_pack": ops_report,
        "freeze_pack": freeze_report,
        "freeze_gate": freeze_gate,
        "candidate_summary": _build_candidate_summary(
            {
                "repo_sync": repo_report,
                "freeze_gate": freeze_gate,
            }
        ),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "ops-pack":
            report = _ops_pack(args)
        elif args.command == "repo-sync":
            report = _repo_sync(args)
        elif args.command == "daily-pack":
            report = _daily_pack(args)
        elif args.command == "candidate-pack":
            report = _candidate_pack(args)
        elif args.command == "freeze-pack":
            report = _freeze_pack(args)
        else:
            report = _full_pack(args)
    except ValueError as exc:
        if getattr(args, "json_output", False):
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
