from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
DEFAULT_RECORD_DIR = "/tmp/azazel-edge-bhusa-freeze-record"
DEFAULT_ARCHIVE_DIR = "/tmp/azazel-edge-bhusa-archive"
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


def _git_value(*args: str) -> str:
    result = _run_command(["git", *args])
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or result.stdout.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _git_dirty_files() -> List[str]:
    status = _git_value("status", "--short")
    return [line for line in status.splitlines() if line.strip()]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-freeze-record",
        description="Generate a concrete BHUSA 2026 freeze record for the current git state.",
    )
    parser.add_argument(
        "--record-dir",
        default=DEFAULT_RECORD_DIR,
        help=f"Freeze record directory (default: {DEFAULT_RECORD_DIR})",
    )
    parser.add_argument(
        "--archive-dir",
        default=DEFAULT_ARCHIVE_DIR,
        help=f"Archive directory to build or reuse (default: {DEFAULT_ARCHIVE_DIR})",
    )
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"Rehearsal JSONL path (default: {DEFAULT_RECORD_PATH})",
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
    parser.add_argument("--force", action="store_true", help="Replace an existing freeze record directory.")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")
    return parser


def _run_archive(args: argparse.Namespace) -> Dict[str, Any]:
    cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-archive"),
        "--record-path",
        args.record_path,
        "--archive-dir",
        args.archive_dir,
        *(["--explanations-path", args.explanations_path] if args.explanations_path else []),
        *(["--audit-path", args.audit_path] if args.audit_path else []),
        "--force",
        "--json",
    ]
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"archive generation failed: {stderr}")
    payload = _load_json(result.stdout, context="azazel-edge-bhusa-archive")
    payload["command"] = " ".join(cmd)
    return payload


def _render_markdown(record_dir: Path, archive: Dict[str, Any], git: Dict[str, Any]) -> str:
    status = archive.get("status", {})
    lines = [
        "# BHUSA 2026 Freeze Record",
        "",
        "## Candidate",
        "",
        f"- Branch: `{git['branch']}`",
        f"- Commit: `{git['head_commit']}`",
        f"- Subject: {git['head_subject']}",
        f"- Dirty worktree: `{'yes' if git['dirty_files'] else 'no'}`",
        "",
        "## Archive",
        "",
        f"- Archive dir: `{archive['archive_dir']}`",
        f"- Readiness report: `{archive['report_dir']}`",
        f"- Readiness status JSON: `{archive.get('status_json_path')}`",
        f"- Archived commands: `{archive['commands_path']}`",
        f"- Git snapshot: `{archive['git_path']}`",
        "",
        "## Readiness Snapshot",
        "",
        f"- Overall state: `{status.get('overall_state')}`",
        f"- Days until session: `{status.get('days_until_session')}`",
        f"- Remaining work items: `{len(status.get('remaining_work', []))}`",
        "",
        "## Compact audit snippet",
        "",
        "```text",
        archive["evidence"]["audit_compact_output"],
        "```",
        "",
        "## Notes",
        "",
        "- This record captures the current local candidate only.",
        "- Promote this candidate only after target booth-device verification is complete.",
    ]
    if git["dirty_files"]:
        lines.extend(["", "## Dirty Files", ""])
        for item in git["dirty_files"]:
            lines.append(f"- `{item}`")
    return "\n".join(lines) + "\n"


def _build_record(args: argparse.Namespace) -> Dict[str, Any]:
    record_dir = Path(args.record_dir)
    if record_dir.exists():
        if not args.force:
            raise ValueError(f"freeze record directory already exists: {record_dir}")
        shutil.rmtree(record_dir)
    record_dir.mkdir(parents=True, exist_ok=True)

    archive = _run_archive(args)
    git = {
        "branch": _git_value("branch", "--show-current"),
        "head_commit": _git_value("rev-parse", "--short", "HEAD"),
        "head_subject": _git_value("log", "-1", "--pretty=%s"),
        "dirty_files": _git_dirty_files(),
    }

    markdown = _render_markdown(record_dir, archive, git)
    markdown_path = record_dir / "FREEZE_RECORD.md"
    json_path = record_dir / "freeze-record.json"
    markdown_path.write_text(markdown, encoding="utf-8")

    payload = {
        "ok": True,
        "record_dir": str(record_dir),
        "freeze_record_markdown_path": str(markdown_path),
        "freeze_record_json_path": str(json_path),
        "archive": archive,
        "git": git,
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def _format_text(report: Dict[str, Any]) -> str:
    git = report["git"]
    return "\n".join(
        [
            "BHUSA 2026 FREEZE RECORD",
            f"record_dir: {report['record_dir']}",
            f"freeze_record_markdown_path: {report['freeze_record_markdown_path']}",
            f"branch: {git['branch']}",
            f"commit: {git['head_commit']}",
        ]
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report = _build_record(args)
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
