from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
DEFAULT_RECORD_PATH = "/tmp/azazel-edge-bhusa-rehearsal.jsonl"
DEFAULT_REPO = "01rabbit/Azazel-Edge"
DEFAULT_SESSION_DATE = "2026-08-05"
DEFAULT_LINKS_PATH = ROOT_DIR / "docs" / "issues" / "bhusa-2026-vegas-readiness" / "43-created-issue-links-placeholder.md"
DEFAULT_STATUS_DOC_PATH = ROOT_DIR / "docs" / "issues" / "bhusa-2026-vegas-readiness" / "15-status.md"
LINK_PATTERN = re.compile(r"\[#(?P<number>\d+)\s+[^\]]+\]\((?P<url>[^)]+)\)")


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


def _run_freeze_check(args: argparse.Namespace) -> Dict[str, Any]:
    explanations_path, audit_path = _evidence_paths(args)
    cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-freeze-check"),
        "--record-path",
        args.record_path,
        "--min-full-rehearsals",
        str(args.min_full_rehearsals),
        "--min-fallback-drills",
        str(args.min_fallback_drills),
        "--explanations-path",
        explanations_path,
        "--audit-path",
        audit_path,
        *[item for path in getattr(args, "offline_doc_path", []) for item in ("--offline-doc-path", path)],
        "--json",
    ]
    result = _run_command(cmd)
    if result.returncode not in (0, 1):
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"freeze check failed to run: {stderr}")
    payload = _load_json(result.stdout, context="azazel-edge-bhusa-freeze-check")
    payload["command"] = " ".join(cmd)
    payload["exit_code"] = result.returncode
    return payload


def _find_variant(summary: Dict[str, Any], variant: str) -> Dict[str, Any]:
    for item in summary.get("variants", []):
        if item.get("variant") == variant:
            return item
    return {"variant": variant, "runs": 0, "passes": 0, "fallback_drills": 0, "avg_presenter_duration_sec": None}


def _parse_issue_links(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    issues: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = LINK_PATTERN.search(line)
        if not match:
            continue
        issues.append({"number": int(match.group("number")), "url": match.group("url")})
    return issues


def _load_github_issue_map(repo: str) -> Dict[int, Dict[str, Any]]:
    cmd = ["gh", "issue", "list", "--repo", repo, "--limit", "100", "--json", "number,title,state,url"]
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"gh issue list failed: {stderr}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"gh issue list returned invalid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError("gh issue list returned non-array JSON")
    issues: Dict[int, Dict[str, Any]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            number = int(item.get("number"))
        except (TypeError, ValueError):
            continue
        normalized = dict(item)
        normalized["command"] = " ".join(cmd)
        issues[number] = normalized
    return issues


def _load_github_issues(repo: str, links: List[Dict[str, Any]]) -> Dict[str, Any]:
    issue_map = _load_github_issue_map(repo)
    issues: List[Dict[str, Any]] = []
    warnings: List[str] = []
    for item in links:
        number = item["number"]
        payload = issue_map.get(number)
        if payload is None:
            warnings.append(f"GitHub issue #{number} was linked locally but not returned by gh issue list")
            issues.append({"number": number, "url": item["url"], "state": "UNKNOWN"})
            continue
        issues.append(payload)
    return {"issues": issues, "warnings": warnings}


def _days_until_session(session_date: str) -> int:
    target = date.fromisoformat(session_date)
    return (target - date.today()).days


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-status",
        description="Summarize BHUSA 2026 readiness evidence, rehearsal progress, and child issue state.",
    )
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"Rehearsal JSONL path (default: {DEFAULT_RECORD_PATH})",
    )
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help="GitHub repo in owner/name format for child issue lookups.",
    )
    parser.add_argument(
        "--links-path",
        default=str(DEFAULT_LINKS_PATH),
        help="Markdown file containing created BHUSA child issue links.",
    )
    parser.add_argument(
        "--session-date",
        default=DEFAULT_SESSION_DATE,
        help=f"Session date in YYYY-MM-DD format (default: {DEFAULT_SESSION_DATE})",
    )
    parser.add_argument(
        "--min-full-rehearsals",
        type=int,
        default=3,
        help="Minimum successful full rehearsals required for readiness.",
    )
    parser.add_argument(
        "--min-fallback-drills",
        type=int,
        default=1,
        help="Minimum fallback drills required for readiness.",
    )
    parser.add_argument(
        "--include-freeze-check",
        action="store_true",
        help="Run the local freeze check in addition to reading recorded evidence.",
    )
    parser.add_argument(
        "--explanations-path",
        default=None,
        help="Optional explanation JSONL path to pass through when running --include-freeze-check.",
    )
    parser.add_argument(
        "--audit-path",
        default=None,
        help="Optional audit JSONL path to pass through when running --include-freeze-check.",
    )
    parser.add_argument(
        "--offline-doc-path",
        action="append",
        default=[],
        help="Optional offline documentation path to pass through when running --include-freeze-check.",
    )
    parser.add_argument(
        "--skip-github",
        action="store_true",
        help="Skip GitHub child issue lookups and report only local evidence.",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Emit the readiness status as repository-style Markdown instead of plain text.",
    )
    parser.add_argument(
        "--write-status-doc",
        action="store_true",
        help="Write the rendered Markdown status snapshot to --status-doc-path.",
    )
    parser.add_argument(
        "--status-doc-path",
        default=str(DEFAULT_STATUS_DOC_PATH),
        help=f"Markdown status doc path used with --write-status-doc (default: {DEFAULT_STATUS_DOC_PATH})",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")
    return parser


def _build_report(args: argparse.Namespace) -> Dict[str, Any]:
    rehearsal_summary = _run_rehearsal_summary(args.record_path)
    full_variant = _find_variant(rehearsal_summary, "full")

    git = {
        "branch": _git_value("branch", "--show-current"),
        "head_commit": _git_value("rev-parse", "--short", "HEAD"),
        "head_subject": _git_value("log", "-1", "--pretty=%s"),
        "dirty_files": _git_dirty_files(),
    }
    git["dirty"] = bool(git["dirty_files"])

    links = _parse_issue_links(Path(args.links_path))
    github = {
        "enabled": not args.skip_github,
        "repo": args.repo,
        "links_path": args.links_path,
        "linked_issue_count": len(links),
        "issues": [],
        "warnings": [],
    }
    if not args.skip_github:
        try:
            github_loaded = _load_github_issues(args.repo, links)
            github["issues"] = github_loaded["issues"]
            github["warnings"] = github_loaded["warnings"]
        except ValueError as exc:
            github["warnings"].append(
                f"gh lookup unavailable ({exc}); pass --skip-github to suppress"
            )

    freeze_check: Optional[Dict[str, Any]] = None
    if args.include_freeze_check:
        freeze_check = _run_freeze_check(args)

    open_issues = [item for item in github["issues"] if item.get("state") == "OPEN"]
    full_passes = int(full_variant.get("passes", 0))
    fallback_drills = int(rehearsal_summary.get("fallback_drill_runs", 0))

    remaining_work: List[str] = []
    if full_passes < args.min_full_rehearsals:
        remaining_work.append(f"record {args.min_full_rehearsals - full_passes} more successful full rehearsals")
    if fallback_drills < args.min_fallback_drills:
        remaining_work.append(f"record {args.min_fallback_drills - fallback_drills} more fallback drills")
    if github["enabled"]:
        remaining_work.extend(
            f"close child issue #{item.get('number')} ({item.get('title', 'unknown title')})" for item in open_issues
        )
        if github["warnings"]:
            remaining_work.append("repair GitHub issue visibility before using this as the final readiness source")
    else:
        remaining_work.append("GitHub issue state was skipped; rerun without --skip-github for final tracking")
    if freeze_check is None:
        remaining_work.append("run --include-freeze-check on the booth candidate when you want a live readiness gate")
    elif not freeze_check.get("ok"):
        remaining_work.append("resolve freeze-check failures before selecting the final booth freeze candidate")

    planning_ready = len(links) >= 8
    rehearsal_ready = full_passes >= args.min_full_rehearsals and fallback_drills >= args.min_fallback_drills
    overall_state = "planning-complete"
    if rehearsal_ready:
        overall_state = "rehearsal-ready"
    if rehearsal_ready and (args.skip_github or not open_issues) and (freeze_check is not None and freeze_check.get("ok")):
        overall_state = "freeze-ready"

    return {
        "ok": True,
        "overall_state": overall_state,
        "session_date": args.session_date,
        "days_until_session": _days_until_session(args.session_date),
        "git": git,
        "thresholds": {
            "min_full_rehearsals": args.min_full_rehearsals,
            "min_fallback_drills": args.min_fallback_drills,
        },
        "planning": {"linked_child_issues_ready": planning_ready},
        "rehearsal_summary": rehearsal_summary,
        "full_rehearsal_variant": full_variant,
        "github": github,
        "freeze_check": freeze_check,
        "remaining_work": remaining_work,
    }


def _format_text(report: Dict[str, Any]) -> str:
    git = report["git"]
    full = report["full_rehearsal_variant"]
    github = report["github"]
    open_issues = [item for item in github.get("issues", []) if item.get("state") == "OPEN"]
    lines = [
        "BHUSA 2026 STATUS",
        f"overall_state: {report['overall_state']}",
        f"session_date: {report['session_date']} ({report['days_until_session']} days remaining)",
        f"git: branch={git['branch']} head={git['head_commit']} dirty={git['dirty']}",
        (
            "rehearsals: "
            f"total={report['rehearsal_summary'].get('total_runs')} "
            f"full_passes={full.get('passes')}/{report['thresholds']['min_full_rehearsals']} "
            f"fallback_drills={report['rehearsal_summary'].get('fallback_drill_runs')}/{report['thresholds']['min_fallback_drills']}"
        ),
        (
            "github: "
            f"enabled={github.get('enabled')} "
            f"linked={github.get('linked_issue_count')} "
            f"open={len(open_issues)} "
            f"warnings={len(github.get('warnings', []))}"
        ),
    ]
    if report.get("freeze_check") is None:
        lines.append("freeze_check: not_run")
    else:
        lines.append(f"freeze_check: {'PASS' if report['freeze_check'].get('ok') else 'FAIL'}")
    if report["remaining_work"]:
        lines.append("remaining_work:")
        lines.extend(f"- {item}" for item in report["remaining_work"])
    return "\n".join(lines)


def _format_markdown(report: Dict[str, Any]) -> str:
    github = report["github"]
    open_issues = [item for item in github.get("issues", []) if item.get("state") == "OPEN"]
    closed_issues = [item for item in github.get("issues", []) if item.get("state") == "CLOSED"]
    lines = [
        "# Status",
        "",
        "Generated from the BHUSA 2026 readiness snapshot and parent roadmap #283.",
        "",
        "## Snapshot",
        "",
        f"- Overall state: `{report['overall_state']}`",
        f"- Session date: `{report['session_date']}`",
        f"- Days until session: `{report['days_until_session']}`",
        f"- Full rehearsal passes: `{report['full_rehearsal_variant'].get('passes')}` / `{report['thresholds']['min_full_rehearsals']}`",
        f"- Fallback drill runs: `{report['rehearsal_summary'].get('fallback_drill_runs')}` / `{report['thresholds']['min_fallback_drills']}`",
        f"- GitHub linked child issues: `{github.get('linked_issue_count')}`",
        f"- GitHub closed child issues: `{len(closed_issues)}`",
        f"- GitHub open child issues: `{len(open_issues)}`",
        "",
    ]
    if closed_issues:
        lines.extend(["## Closed Child Issues", ""])
        for item in closed_issues:
            lines.append(f"- #{item.get('number')} {item.get('title')}")
        lines.append("")
    if open_issues:
        lines.extend(["## Open Child Issues", ""])
        for item in open_issues:
            lines.append(f"- #{item.get('number')} {item.get('title')}")
        lines.append("")
    if report.get("freeze_check") is not None:
        lines.extend(
            [
                "## Freeze Check",
                "",
                f"- Gate result: `{'PASS' if report['freeze_check'].get('ok') else 'FAIL'}`",
                f"- Offline doc paths checked: `{len(report['freeze_check'].get('offline_doc_checks', []))}`",
                "",
            ]
        )
    if report["remaining_work"]:
        lines.extend(["## Remaining Work", ""])
        for item in report["remaining_work"]:
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


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

    markdown = _format_markdown(report)
    if args.write_status_doc:
        _write_text(Path(args.status_doc_path), markdown)
        report["status_doc_path"] = str(Path(args.status_doc_path))

    if args.json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.markdown:
        print(markdown.rstrip())
    else:
        print(_format_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
