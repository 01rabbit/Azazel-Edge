from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
ISSUE_DIR = ROOT_DIR / "docs" / "issues" / "bhusa-2026-vegas-readiness"
INDEX_PATH = ISSUE_DIR / "42-issue-body-index.md"
COMMENT_TEMPLATE_PATH = ISSUE_DIR / "13-parent-issue-comment-template.md"
PLACEHOLDER_PATH = ISSUE_DIR / "43-created-issue-links-placeholder.md"
DEFAULT_PARENT = 283
DEFAULT_REPO = "01rabbit/Azazel-Edge"
DEFAULT_RECORD_PATH = "/tmp/azazel-edge-bhusa-rehearsal.jsonl"
DEFAULT_TITLE_PREFIX = "[BHUSA 2026]"
DEFAULT_PROGRESS_PATH = ISSUE_DIR / "71-parent-progress-comment.md"
DEFAULT_PARENT_COMMENT_PATH = ISSUE_DIR / "72-parent-issue-comment.md"
ISSUE_FILES = (
    "01-demo-story-and-talk-track-lock.md",
    "02-deterministic-replay-readiness.md",
    "03-operator-decision-support-view.md",
    "04-audit-and-explanation-walkthrough.md",
    "05-live-tactical-boundary-and-fallback.md",
    "06-booth-rehearsal-and-failure-runbook.md",
    "07-docs-sync-blackhat-public-description.md",
    "08-final-release-freeze.md",
)


def _run_command(cmd: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )


def _read_issue_file(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    title = ""
    for line in lines:
        if line.startswith("# "):
            title = line[2:].strip()
            break
    if not title:
        raise ValueError(f"missing markdown title in {path}")
    return {
        "file": str(path.relative_to(ROOT_DIR)),
        "title": title,
        "body": text,
    }


def _load_issue_specs() -> List[Dict[str, Any]]:
    specs: List[Dict[str, Any]] = []
    for name in ISSUE_FILES:
        specs.append(_read_issue_file(ISSUE_DIR / name))
    return specs


def _build_create_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = sub.add_parser("create", help="Preview or create the BHUSA child issues")
    parser.add_argument("--parent", type=int, default=DEFAULT_PARENT, help="Parent roadmap issue number")
    parser.add_argument(
        "--repo",
        default="01rabbit/Azazel-Edge",
        help="GitHub repo in owner/name format",
    )
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="Optional label to add to every created issue; may be repeated",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually create issues with gh issue create. Without this flag, only preview is emitted.",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")


def _build_parent_comment_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = sub.add_parser("parent-comment", help="Render the parent issue comment with created child links")
    parser.add_argument(
        "--links-path",
        default=str(PLACEHOLDER_PATH),
        help="Markdown file containing created issue links",
    )
    parser.add_argument(
        "--output-path",
        default=str(DEFAULT_PARENT_COMMENT_PATH),
        help=f"Markdown path used with --write (default: {DEFAULT_PARENT_COMMENT_PATH})",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write the rendered parent issue comment markdown to --output-path",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")


def _build_progress_comment_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = sub.add_parser("progress-comment", help="Render a parent issue progress update from the current BHUSA status snapshot")
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help="GitHub repo in owner/name format",
    )
    parser.add_argument(
        "--record-path",
        default=DEFAULT_RECORD_PATH,
        help=f"Rehearsal JSONL path passed to azazel-edge-bhusa-status (default: {DEFAULT_RECORD_PATH})",
    )
    parser.add_argument(
        "--status-json-path",
        default=None,
        help="Optional existing status.json path to render instead of invoking azazel-edge-bhusa-status",
    )
    parser.add_argument(
        "--skip-github",
        action="store_true",
        help="Skip GitHub child issue lookups when invoking azazel-edge-bhusa-status",
    )
    parser.add_argument(
        "--output-path",
        default=str(DEFAULT_PROGRESS_PATH),
        help=f"Markdown path used with --write (default: {DEFAULT_PROGRESS_PATH})",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write the rendered progress comment markdown to --output-path",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")


def _build_sync_links_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = sub.add_parser("sync-links", help="Render or write the created child issue links doc from current GitHub issue state")
    parser.add_argument("--parent", type=int, default=DEFAULT_PARENT, help="Parent roadmap issue number")
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help="GitHub repo in owner/name format",
    )
    parser.add_argument(
        "--links-path",
        default=str(PLACEHOLDER_PATH),
        help="Markdown file to render or write",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write the rendered markdown to --links-path",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="Emit machine-readable JSON")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azazel-edge-bhusa-issues",
        description="Preview or create BHUSA 2026 Vegas-readiness child issues from repo docs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _build_create_parser(sub)
    _build_parent_comment_parser(sub)
    _build_progress_comment_parser(sub)
    _build_sync_links_parser(sub)
    return parser


def _create_issue(repo: str, title: str, body: str, labels: List[str]) -> Dict[str, Any]:
    cmd = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body]
    for label in labels:
        cmd.extend(["--label", label])
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"gh issue create failed for {title!r}: {stderr}")
    url = result.stdout.strip().splitlines()[-1].strip()
    return {"title": title, "url": url, "command": " ".join(cmd)}


def _create_or_preview(args: argparse.Namespace) -> Dict[str, Any]:
    specs = _load_issue_specs()
    preview_items: List[Dict[str, Any]] = []
    created_items: List[Dict[str, Any]] = []
    default_labels = [*args.label, f"parent:{args.parent}", "area:bhusa-2026"]

    for spec in specs:
        preview_items.append(
            {
                "title": spec["title"],
                "file": spec["file"],
                "labels": default_labels,
            }
        )
        if args.apply:
            created_items.append(_create_issue(args.repo, spec["title"], spec["body"], default_labels))

    placeholder_lines = ["# Created issue links", ""]
    if created_items:
        placeholder_lines.append("Populate this with created child issue links.")
        placeholder_lines.append("")
        for item in created_items:
            placeholder_lines.append(f"- [{item['title']}]({item['url']})")
    else:
        placeholder_lines.append("Populate this with created child issue links.")

    return {
        "ok": True,
        "mode": "apply" if args.apply else "preview",
        "repo": args.repo,
        "parent_issue": args.parent,
        "issue_count": len(specs),
        "issues": created_items if args.apply else preview_items,
        "placeholder_preview": "\n".join(placeholder_lines).strip() + "\n",
    }


def _render_parent_comment(args: argparse.Namespace) -> Dict[str, Any]:
    template = COMMENT_TEMPLATE_PATH.read_text(encoding="utf-8").rstrip()
    links_path = Path(args.links_path)
    links = ""
    if links_path.exists():
        lines = links_path.read_text(encoding="utf-8").splitlines()
        link_lines = [line for line in lines if line.strip().startswith("- [")]
        if link_lines:
            links = "# Created issue links\n\n" + "\n".join(link_lines)
    body = template
    if links:
        body = f"{template}\n\n{links}"
    if args.write:
        _write_text(Path(args.output_path), body + "\n")
    return {
        "ok": True,
        "links_path": str(links_path),
        "body": body + "\n",
        "output_path": args.output_path,
        "written": bool(args.write),
    }


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _load_child_issues(repo: str, parent: int) -> List[Dict[str, Any]]:
    cmd = [
        "gh",
        "issue",
        "list",
        "--repo",
        repo,
        "--limit",
        "100",
        "--json",
        "number,title,url,state",
    ]
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"gh issue list failed: {stderr}")
    payload = json.loads(result.stdout)
    if not isinstance(payload, list):
        raise ValueError("gh issue list returned non-array JSON")
    issues = [
        item
        for item in payload
        if isinstance(item, dict) and str(item.get("title") or "").startswith(DEFAULT_TITLE_PREFIX)
    ]
    issues.sort(key=lambda item: int(item.get("number", 0)))
    return issues


def _render_links_markdown(issues: List[Dict[str, Any]]) -> str:
    lines = ["# Created issue links", ""]
    for item in issues:
        state = str(item.get("state") or "UNKNOWN").upper()
        title = str(item.get("title") or "")
        if title.startswith(f"{DEFAULT_TITLE_PREFIX} "):
            title = title[len(DEFAULT_TITLE_PREFIX) + 1 :]
        lines.append(f"- [#{item.get('number')} — {title}]({item.get('url')}) `{state}`")
    lines.extend(
        [
            "",
            "Suggested workflow:",
            "",
            "1. run `bin/azazel-edge-bhusa-issues create`",
            "2. run `bin/azazel-edge-bhusa-issues create --apply` when needed for missing issues",
            "3. run `bin/azazel-edge-bhusa-issues sync-links --write` to refresh this file from GitHub",
            "4. run `bin/azazel-edge-bhusa-issues parent-comment`",
            "5. run `bin/azazel-edge-bhusa-issues progress-comment` for later roadmap updates",
            "",
        ]
    )
    return "\n".join(lines)


def _sync_links(args: argparse.Namespace) -> Dict[str, Any]:
    # Degrade gracefully when GitHub is unreachable (no `gh`, unauthenticated, or
    # offline) instead of hard-failing the whole repo-sync. This mirrors the
    # established pattern in bhusa_status._build (gh failure -> warning, not crash),
    # and keeps CI / offline-booth runs deterministic without live GitHub access.
    warnings: List[str] = []
    try:
        issues = _load_child_issues(args.repo, args.parent)
    except (ValueError, FileNotFoundError, OSError) as exc:
        issues = []
        warnings.append(f"gh issue list unavailable ({exc}); links rendered without live GitHub state")
    markdown = _render_links_markdown(issues)
    if args.write:
        _write_text(Path(args.links_path), markdown)
    return {
        "ok": True,
        "repo": args.repo,
        "parent_issue": args.parent,
        "links_path": args.links_path,
        "issue_count": len(issues),
        "issues": issues,
        "github_available": not warnings,
        "warnings": warnings,
        "markdown": markdown,
        "written": bool(args.write),
    }


def _load_status(args: argparse.Namespace) -> Dict[str, Any]:
    if args.status_json_path:
        payload = json.loads(Path(args.status_json_path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"status JSON must be an object: {args.status_json_path}")
        return payload

    cmd = [
        str(BIN_DIR / "azazel-edge-bhusa-status"),
        "--record-path",
        args.record_path,
        "--repo",
        args.repo,
        "--json",
    ]
    if args.skip_github:
        cmd.append("--skip-github")
    result = _run_command(cmd)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"status command failed: {stderr}")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise ValueError("status command returned non-object JSON")
    payload["command"] = " ".join(cmd)
    return payload


def _render_progress_comment(args: argparse.Namespace) -> Dict[str, Any]:
    status = _load_status(args)
    github = status.get("github", {})
    issues = list(github.get("issues", []))
    open_issues = [item for item in issues if item.get("state") == "OPEN"]
    closed_issues = [item for item in issues if item.get("state") == "CLOSED"]

    lines = [
        "## Vegas readiness progress update",
        "",
        f"- Overall state: `{status.get('overall_state')}`",
        f"- Days until session: `{status.get('days_until_session')}`",
        f"- Full rehearsal passes: `{status.get('full_rehearsal_variant', {}).get('passes')}` / `{status.get('thresholds', {}).get('min_full_rehearsals')}`",
        f"- Fallback drill runs: `{status.get('rehearsal_summary', {}).get('fallback_drill_runs')}` / `{status.get('thresholds', {}).get('min_fallback_drills')}`",
        f"- Linked child issues: `{github.get('linked_issue_count')}`",
        f"- Closed child issues: `{len(closed_issues)}`",
        f"- Open child issues: `{len(open_issues)}`",
        "",
    ]
    if closed_issues:
        lines.extend(["### Closed child issues", ""])
        for item in closed_issues:
            lines.append(f"- #{item.get('number')} {item.get('title')}")
        lines.append("")
    if open_issues:
        lines.extend(["### Open child issues", ""])
        for item in open_issues:
            lines.append(f"- #{item.get('number')} {item.get('title')}")
        lines.append("")
    if status.get("remaining_work"):
        lines.extend(["### Remaining work", ""])
        for item in status.get("remaining_work", []):
            lines.append(f"- {item}")
        lines.append("")
    body = "\n".join(lines).rstrip() + "\n"
    if args.write:
        _write_text(Path(args.output_path), body)
    return {
        "ok": True,
        "status": status,
        "body": body,
        "output_path": args.output_path,
        "written": bool(args.write),
    }


def _format_create_text(report: Dict[str, Any]) -> str:
    lines = [
        "BHUSA 2026 ISSUE PLAN",
        f"mode: {report['mode']}",
        f"repo: {report['repo']}",
        f"parent_issue: #{report['parent_issue']}",
        f"issue_count: {report['issue_count']}",
    ]
    for item in report["issues"]:
        if report["mode"] == "apply":
            lines.append(f"created: {item['title']} -> {item['url']}")
        else:
            lines.append(f"preview: {item['title']} ({item['file']})")
    lines.append("placeholder_preview:")
    lines.append(report["placeholder_preview"].rstrip())
    return "\n".join(lines)


def _format_parent_comment_text(report: Dict[str, Any]) -> str:
    return report["body"].rstrip()


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            report = _create_or_preview(args)
            if args.json_output:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(_format_create_text(report))
            return 0

        if args.command == "progress-comment":
            report = _render_progress_comment(args)
            if args.json_output:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(report["body"].rstrip())
            return 0

        if args.command == "sync-links":
            report = _sync_links(args)
            if args.json_output:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(report["markdown"].rstrip())
            return 0

        report = _render_parent_comment(args)
        if args.json_output:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(_format_parent_comment_text(report))
        return 0
    except ValueError as exc:
        if getattr(args, "json_output", False):
            print(json.dumps({"ok": False, "errors": [str(exc)]}, ensure_ascii=False, indent=2))
        else:
            print(f"result: FAIL\nerror: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
