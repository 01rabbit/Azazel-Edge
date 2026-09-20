from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


ROOT_DIR = Path(__file__).resolve().parents[2]
BIN_DIR = ROOT_DIR / "bin"
DEFAULT_RECORD_PATH = "/tmp/azazel-edge-bhusa-rehearsal.jsonl"
DEFAULT_REPO = "01rabbit/Azazel-Edge"
DEFAULT_SESSION_DATE = "2026-08-05"
DEFAULT_LINKS_PATH = ROOT_DIR / "docs" / "issues" / "bhusa-2026-vegas-readiness" / "43-created-issue-links-placeholder.md"
DEFAULT_STATUS_DOC_PATH = ROOT_DIR / "docs" / "issues" / "bhusa-2026-vegas-readiness" / "15-status.md"
LINK_PATTERN = re.compile(r"\[#(?P<number>\d+)\s+[^\]]+\]\((?P<url>[^)]+)\)")

#: How long the optional GitHub lookup may take before it is given up on.
#:
#: An enrichment source with no timeout is not optional: a hung `gh` would
#: hold the whole report open, which is the same outage as a crash with worse
#: symptoms.
GH_TIMEOUT_SEC = 20.0

#: Why the optional GitHub lookup produced nothing, as machine tokens.
#:
#: Separate values rather than one "unavailable" because an operator's next
#: action differs: `gh_not_installed` is a workstation that never had the CLI,
#: `gh_not_authenticated` is a credential to refresh, and `gh_rate_limited`
#: is a wait. Collapsing them would make the report say "something went wrong"
#: to someone who has to decide what to do about it.
GH_NOT_INSTALLED = "gh_not_installed"
GH_NOT_EXECUTABLE = "gh_not_executable"
GH_TIMED_OUT = "gh_timed_out"
GH_NOT_AUTHENTICATED = "gh_not_authenticated"
GH_RATE_LIMITED = "gh_rate_limited"
GH_FAILED = "gh_failed"
GH_UNPARSEABLE = "gh_returned_unparseable_output"


class GitHubUnavailable(Exception):
    """The optional enrichment source produced nothing, and why.

    Deliberately not a `ValueError`. A `ValueError` in this module means a
    *required* local check could not run, and the two must not share a handler:
    that is exactly how "GitHub is missing" came to be reported as a report
    that could not be produced -- or, worse, not reported at all.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


#: A source of `{issue number: payload}` for one repository.
#:
#: Injected so the degradation paths can be tested as themselves rather than
#: by arranging a workstation that lacks `gh`. A test that has to remove a
#: binary from `PATH` to reach a branch is a test that will stop reaching it
#: the day the runner image changes, silently.
IssueSource = Callable[[str], Dict[int, Dict[str, Any]]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")



def _run_command(
    cmd: List[str], *, timeout: Optional[float] = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
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


def _classify_gh_failure(stderr: str, stdout: str, returncode: int) -> str:
    """Name the failure an operator has to act on, from what `gh` said.

    Matched case-insensitively against both streams because `gh` has moved
    messages between them across versions, and a classifier that reads only
    one would report `gh_failed` for a credential problem it could have named.
    """

    text = f"{stderr}\n{stdout}".lower()
    if "rate limit" in text or "secondary rate" in text or "api rate" in text:
        return GH_RATE_LIMITED
    if (
        "authentication" in text
        or "not logged" in text
        or "gh auth login" in text
        or "requires authentication" in text
        or "bad credentials" in text
        or "401" in text
    ):
        return GH_NOT_AUTHENTICATED
    return GH_FAILED


def _load_github_issue_map(repo: str) -> Dict[int, Dict[str, Any]]:
    """The default enrichment source. Raises `GitHubUnavailable`, never escapes.

    Every way this can fail to produce data is a `GitHubUnavailable`. The
    defect this replaces was narrower than it looked: `FileNotFoundError` from
    a missing `gh` is not raised by `subprocess.run`'s return value but by the
    call itself, so the `except ValueError` around it never saw it and the
    traceback reached the operator instead of the report.
    """

    cmd = ["gh", "issue", "list", "--repo", repo, "--limit", "100", "--json", "number,title,state,url"]
    try:
        result = _run_command(cmd, timeout=GH_TIMEOUT_SEC)
    except FileNotFoundError as exc:
        raise GitHubUnavailable(GH_NOT_INSTALLED, f"gh is not on PATH: {exc}") from exc
    except PermissionError as exc:
        raise GitHubUnavailable(GH_NOT_EXECUTABLE, f"gh is not executable: {exc}") from exc
    except OSError as exc:
        raise GitHubUnavailable(GH_FAILED, f"gh could not be started: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitHubUnavailable(
            GH_TIMED_OUT, f"gh issue list exceeded {GH_TIMEOUT_SEC}s"
        ) from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        detail = stderr or stdout or f"exit {result.returncode}"
        raise GitHubUnavailable(
            _classify_gh_failure(stderr, stdout, result.returncode), detail
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise GitHubUnavailable(GH_UNPARSEABLE, f"invalid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise GitHubUnavailable(GH_UNPARSEABLE, "gh issue list returned non-array JSON")
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


def _load_github_issues(
    repo: str, links: List[Dict[str, Any]], *, issue_source: IssueSource
) -> Dict[str, Any]:
    issue_map = issue_source(repo)
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
        "--require-github",
        action="store_true",
        help=(
            "Treat GitHub child issue state as required: exit non-zero and set "
            "ok=false when it cannot be read. Off by default, because an "
            "optional enrichment source being absent does not make the local "
            "readiness evidence wrong."
        ),
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


def _build_report(
    args: argparse.Namespace,
    *,
    issue_source: Optional[IssueSource] = None,
    now: Optional[Callable[[], str]] = None,
) -> Dict[str, Any]:
    issue_source = issue_source or _load_github_issue_map
    now = now or _utc_now
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
    # `open_issue_count` and `closed_issue_count` start as None, not 0. An
    # absent external source must never render as "no open issues": that is
    # the sentence an operator would read as "nothing left to close", and it
    # would be produced by the lookup failing rather than by anything being
    # true about the repository.
    github: Dict[str, Any] = {
        "enabled": not args.skip_github,
        "availability": "skipped" if args.skip_github else "unavailable",
        "unavailable_reason": None if args.skip_github else GH_NOT_INSTALLED,
        "unavailable_detail": None,
        "observed_at": None,
        "repo": args.repo,
        "links_path": args.links_path,
        "linked_issue_count": len(links),
        "issues": [],
        "open_issue_count": None,
        "closed_issue_count": None,
        "warnings": [],
    }
    if args.skip_github:
        github["unavailable_reason"] = "skipped_by_operator"
    else:
        github["observed_at"] = now()
        try:
            github_loaded = _load_github_issues(
                args.repo, links, issue_source=issue_source
            )
        except GitHubUnavailable as exc:
            github["availability"] = "unavailable"
            github["unavailable_reason"] = exc.reason
            github["unavailable_detail"] = exc.detail
            github["warnings"].append(
                f"GitHub issue state is unavailable ({exc.reason}: {exc.detail}); "
                "the child-issue counts below are unknown, not zero"
            )
        else:
            github["availability"] = "available"
            github["unavailable_reason"] = None
            github["issues"] = github_loaded["issues"]
            github["warnings"] = github_loaded["warnings"]
            github["open_issue_count"] = sum(
                1 for item in github["issues"] if item.get("state") == "OPEN"
            )
            github["closed_issue_count"] = sum(
                1 for item in github["issues"] if item.get("state") == "CLOSED"
            )

    github_available = github["availability"] == "available"
    limitations: List[Dict[str, Any]] = []
    if not github_available:
        limitations.append(
            {
                "subject": "github_child_issue_state",
                "state": "unavailable",
                "reason": github["unavailable_reason"],
                "detail": github["unavailable_detail"],
                "observed_at": github["observed_at"],
                "effect": (
                    "child-issue counts are unknown; this report cannot say "
                    "whether any remain open"
                ),
            }
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
    if github_available:
        remaining_work.extend(
            f"close child issue #{item.get('number')} ({item.get('title', 'unknown title')})" for item in open_issues
        )
        if github["warnings"]:
            remaining_work.append("repair GitHub issue visibility before using this as the final readiness source")
    elif github["availability"] == "skipped":
        remaining_work.append("GitHub issue state was skipped; rerun without --skip-github for final tracking")
    else:
        remaining_work.append(
            f"GitHub issue state is unavailable ({github['unavailable_reason']}); "
            "child-issue readiness is unknown until it can be read"
        )
    if freeze_check is None:
        remaining_work.append("run --include-freeze-check on the booth candidate when you want a live readiness gate")
    elif not freeze_check.get("ok"):
        remaining_work.append("resolve freeze-check failures before selecting the final booth freeze candidate")

    planning_ready = len(links) >= 8
    rehearsal_ready = full_passes >= args.min_full_rehearsals and fallback_drills >= args.min_fallback_drills
    overall_state = "planning-complete"
    if rehearsal_ready:
        overall_state = "rehearsal-ready"
    # `freeze-ready` requires the external source to have answered. Reaching
    # it from `not open_issues` while the lookup failed would let an outage
    # promote the report to its strongest verdict -- the absence of evidence
    # read as evidence.
    if (
        rehearsal_ready
        and github_available
        and not open_issues
        and (freeze_check is not None and freeze_check.get("ok"))
    ):
        overall_state = "freeze-ready"

    # `ok` is about the *required* local checks, which all ran to get here. An
    # optional enrichment source being absent does not make the report wrong,
    # so it does not make `ok` false -- unless the operator said, with
    # --require-github, that a report without it is of no use to them.
    ok = True
    if getattr(args, "require_github", False) and not github_available:
        ok = False

    return {
        "ok": ok,
        "overall_state": overall_state,
        "limitations": limitations,
        "require_github": bool(getattr(args, "require_github", False)),
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


def _count_or_unknown(value: Optional[int]) -> str:
    """`unknown`, never `0`, when the source did not answer.

    The whole defect in one function. `0` and "we could not find out" render
    identically the moment either is allowed to be an integer, and the reader
    has no way back from the rendered form to which one it was.
    """

    return "unknown" if value is None else str(value)


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
            f"availability={github.get('availability')} "
            f"linked={github.get('linked_issue_count')} "
            f"open={_count_or_unknown(github.get('open_issue_count'))} "
            f"warnings={len(github.get('warnings', []))}"
        ),
    ]
    if github.get("availability") != "available":
        lines.append(
            f"github_unavailable_because: {github.get('unavailable_reason')}"
            + (f" ({github['unavailable_detail']})" if github.get("unavailable_detail") else "")
        )
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
        f"- GitHub child issue state: `{github.get('availability')}`",
        f"- GitHub closed child issues: `{_count_or_unknown(github.get('closed_issue_count'))}`",
        f"- GitHub open child issues: `{_count_or_unknown(github.get('open_issue_count'))}`",
        "",
    ]
    if report.get("limitations"):
        lines.extend(["## Limitations", ""])
        for item in report["limitations"]:
            observed = item.get("observed_at") or "not attempted"
            lines.append(
                f"- `{item.get('subject')}` is `{item.get('state')}` "
                f"(`{item.get('reason')}`, observed at `{observed}`): {item.get('effect')}"
            )
        lines.append("")
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

    # 3, not 2. Exit 2 means the report could not be produced; this means it
    # was produced and the operator asked to be failed when it is incomplete.
    # One code for both would make a script unable to tell "no readiness
    # evidence" from "readiness evidence without GitHub".
    return 0 if report.get("ok", True) else 3


if __name__ == "__main__":
    raise SystemExit(main())
