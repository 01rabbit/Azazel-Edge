#!/usr/bin/env python3
"""Laptop-side SSH orchestrator for the non-enforcing Azazel R0 Pi HIL gate."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import secrets
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REMOTE_RUNNER = Path(__file__).with_name("azazel_hil_remote.py")
# Redaction patterns.  Key names are bounded and every start position is anchored by a lookbehind;
# values are unbounded but every value scan stops at a delimiter that cannot occur inside it and
# matches never overlap, so each pattern stays linear on hostile output (no ReDoS) and never leaves
# the tail of a long secret behind.
PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----")
PEM_END_RE = re.compile(r"-----END [A-Z ]{0,40}PRIVATE KEY-----")
PEM_MARK = "[REDACTED PRIVATE KEY]"
# userinfo of an authority: up to the last '@' before the first '/', '?', '#' or whitespace.
# A scan stops at the next '/', and every later scheme start contains one, so the total work stays linear.
URL_CREDENTIAL_RE = re.compile(r"(?i)(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}://)[^/?#\s]+@")
_KEY_WORD = r"(?:password|passwd|passphrase|token|secret|authorization|api[_-]?key|private[_-]?key|credential)"
SECRET_KEY = r"(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]{0,256}?" + _KEY_WORD + r"[A-Za-z0-9_.-]{0,256}"
# Strings and arrays never fail: an unclosed one is redacted to the end of the line, so the engine
# never rescans the rest of the input from each later start (keeps hostile unclosed input linear).
_DQ = r"\"[^\"\\\n]*(?:\\.[^\"\\\n]*)*\"?"  # double-quoted string with escapes, up to its closing quote
_SQ = r"'[^'\\\n]*(?:\\.[^'\\\n]*)*'?"
_QUOTED_VALUE = _DQ + "|" + _SQ + r"|\[[^\]\n]*\]?|[^\s,}\]]+"
# JSON / Python repr members: "password": "x", 'password': 'x', "tokens": ["a", "b"], "token": 123.
QUOTED_SECRET_RE = re.compile(r"(?i)([\"'])(" + SECRET_KEY + r")\1([ \t]{0,16}:[ \t]{0,16})(?:" + _QUOTED_VALUE + r")")
# Command-line flags: --password x, --token "a b" (the next word or quoted string).
FLAG_SECRET_RE = re.compile(r"(?i)(?<![A-Za-z0-9_.-])(--[A-Za-z0-9_.-]{0,256}?" + _KEY_WORD + r"[A-Za-z0-9_.-]{0,256}[ \t]{1,16})(?![-\[])(?:"
                            + _DQ + "|" + _SQ + r"|\S+)")
# curl/wget style user:password credentials: -u user:pass, --user=user:pass.
USER_PASS_RE = re.compile(r"(?<!\S)((?:-u|--user|--proxy-user)(?:[ \t]{1,16}|=)[\"']?[^\s:\"']+:)(?!\[REDACTED)[^\s\"']+")
# YAML/env/plain: password: x, password = x, PASSWORD=x (rest of the line), or the next line after a bare "password:".
# The lookahead gate rejects ordinary words in one pass before the keyword search runs.
PLAIN_SECRET_RE = re.compile(r"(?i)(?<![A-Za-z0-9_.-])(?=[A-Za-z0-9_.-]{1,600}[ \t]{0,16}[:=])(" + SECRET_KEY
                             + r"[ \t]{0,16}[:=](?:[ \t]{0,16}|[ \t]{0,16}\n[ \t]{0,64}))(?!\[REDACTED)(?=\S)[^\n]+")
AUTH_RE = re.compile(r"(?im)^([ \t]{0,64}(?:authorization|proxy-authorization)[ \t]{0,16}[:=][ \t]{0,16})[^\n]*")
BEARER_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(bearer[ \t]{1,16})[^\s'\"]+")


def redact_pem(text: str) -> str:
    """Remove private-key blocks, including ones cut by a head/tail limit, with linear forward scans."""
    begin, end = PEM_BEGIN_RE.search(text), PEM_END_RE.search(text)
    parts: list[str] = []
    position = 0
    if end and (not begin or end.start() < begin.start()):  # orphan END: the BEGIN was cut off
        parts.append(PEM_MARK)
        position = end.end()
    while True:
        begin = PEM_BEGIN_RE.search(text, position)
        if not begin:
            parts.append(text[position:])
            return "".join(parts)
        parts.append(text[position:begin.start()])
        parts.append(PEM_MARK)
        end = PEM_END_RE.search(text, begin.end())
        if not end:  # orphan BEGIN: the END was cut off
            return "".join(parts)
        position = end.end()


def redact_text(value: str) -> str:
    value = redact_pem(value)
    value = URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", value)
    value = AUTH_RE.sub(r"\1[REDACTED]", value)
    value = BEARER_RE.sub(r"\1[REDACTED]", value)
    value = QUOTED_SECRET_RE.sub(r"\1\2\1\3\1[REDACTED]\1", value)
    value = FLAG_SECRET_RE.sub(r"\1[REDACTED]", value)
    value = USER_PASS_RE.sub(r"\1[REDACTED]", value)
    return PLAIN_SECRET_RE.sub(r"\1[REDACTED]", value)


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if re.search(r"(?i)(token|secret|password|private.?key)", str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
# Required evidence for a complete R0 bundle; a missing row makes the outcome INCOMPLETE.
# restart_reconciliation is opt-in, so its `skipped` still allows `completed`; any other required skip is INCOMPLETE.
OPT_IN_TESTS = ("restart_reconciliation",)
REQUIRED_TESTS = ("preflight.inventory", "prepare.repository", "prepare.dependencies", "prepare.offline_replay", "prepare.gate",
                  "bootstrap.dependencies", "profile.qwen3.5:0.8b", "profile.qwen3.5:2b",
                  "observer.retention_rotation_drop_backpressure", "restart_reconciliation", "postconditions.tc_nft_read_only")
# `full` exit codes (documented in docs/R0_PI_HIL_BRIDGE.md).
EXIT_COMPLETED, EXIT_FAILED, EXIT_STOPPED, EXIT_INCOMPLETE = 0, 1, 2, 3


def valid_session(value: str) -> str:
    if not SESSION_RE.fullmatch(value) or ".." in value:
        raise argparse.ArgumentTypeError("session must match [A-Za-z0-9][A-Za-z0-9._-]* and must not contain '..'")
    return value


def no_option(value: str) -> str:
    """Hosts and users are positional to OpenSSH; a leading '-' would be read as an option."""
    if not value or value.startswith("-"):
        raise argparse.ArgumentTypeError("must not be empty or start with '-'")
    return value


def session_id() -> str:
    return "r0-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(3)


SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=12"]


class RemoteError(RuntimeError):
    """An SSH/SCP transport step failed before the remote runner could report."""

    def __init__(self, step: str, completed: subprocess.CompletedProcess[str]) -> None:
        self.step = step
        self.returncode = completed.returncode or 2
        lines = [line.strip() for line in redact(completed.stderr or completed.stdout or "").splitlines() if line.strip()]  # redact, then cut
        # scp ends with a generic "Connection closed"; keep the preceding OpenSSH line that says why.
        self.detail = " / ".join(lines[-3:]) if lines else "no output"
        super().__init__(f"{step} failed (exit {completed.returncode}): {self.detail}")


def ssh_base(args: argparse.Namespace) -> list[str]:
    command = ["ssh", *SSH_OPTIONS, "-p", str(args.port)]
    if args.identity:
        command += ["-i", args.identity]
    return command


def scp_base(args: argparse.Namespace, *extra: str) -> list[str]:
    command = ["scp", *SSH_OPTIONS, *extra, "-P", str(args.port)]
    if args.identity:
        command += ["-i", args.identity]
    return command


def target(args: argparse.Namespace) -> str:
    return f"{args.user}@{args.target}" if args.user else args.target


def remote_call(args: argparse.Namespace, action: str, extra: list[str]) -> subprocess.CompletedProcess[str]:
    remote_dir = f".cache/azazel-hil/{args.session}"
    setup = subprocess.run(ssh_base(args) + ["--", target(args), f"mkdir -p $HOME/{shlex.quote(remote_dir)}"], text=True, capture_output=True)
    if setup.returncode:
        raise RemoteError("ssh (create remote session directory)", setup)
    upload = subprocess.run(scp_base(args) + ["--", str(REMOTE_RUNNER), f"{target(args)}:{remote_dir}/azazel_hil_remote.py"], text=True, capture_output=True)
    if upload.returncode:
        raise RemoteError("scp (upload remote runner)", upload)
    remote_argv = [action, "--session", args.session, "--repo", args.remote_repo]
    if getattr(args, "remote_python", None):
        remote_argv += ["--python", args.remote_python]
    remote_argv += extra
    # The remote login shell joins argv; quote every value so names and paths stay single arguments.
    command = ssh_base(args) + ["--", target(args), "python3", f"$HOME/{shlex.quote(remote_dir)}/azazel_hil_remote.py",
                                *(shlex.quote(item) for item in remote_argv)]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode == 255:
        raise RemoteError(f"ssh (remote {action})", result)
    return result


def stage_summary(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    for line in reversed((result.stdout or "").strip().splitlines()):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            return item
    return {}


def failure_reason(result: subprocess.CompletedProcess[str]) -> str:
    summary = stage_summary(result)
    rows = sorted((summary.get("tests") or {}).items(), key=lambda item: item[0] == "prepare.gate")  # root cause first, gate last
    failed = [f"{test_id}: {row.get('reason', '')}" for test_id, row in rows if row.get("status") == "failed"]
    if failed:
        return " | ".join(failed)
    lines = redact((result.stderr or "").strip()).splitlines()
    return lines[-1] if lines else f"remote runner exited {result.returncode} without a result summary"


def write_report(raw_dir: Path, report_path: Path, stopped: dict[str, str] | None = None) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    # Only the runner's event logs count; session state files (reconciliation/observer JSONL) are not events.
    for path in sorted(raw_dir.rglob("events.jsonl")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                events.append(redact(item))
    completed: dict[str, dict[str, Any]] = {}
    provenance: dict[str, Any] = {}
    for item in events:
        if item.get("kind") == "provenance":
            provenance.update(item.get("data", {}))
        if item.get("kind") == "test_end":
            completed[item.get("test_id", "unknown")] = item
    rows = sorted(completed.values(), key=lambda row: str(row.get("test_id")))
    passed = sum(row.get("status") == "passed" for row in rows)
    skipped = sum(row.get("status") == "skipped" for row in rows)
    unobserved = sum(row.get("status") == "unobserved" for row in rows)
    failed = len(rows) - passed - skipped - unobserved
    missing = [test_id for test_id in REQUIRED_TESTS if test_id not in completed]
    required_skips = [test_id for test_id in REQUIRED_TESTS
                      if completed.get(test_id, {}).get("status") == "skipped" and test_id not in OPT_IN_TESTS]
    if stopped:
        outcome, state = f"INCOMPLETE: stopped at stage `{stopped.get('stage')}`: {stopped.get('reason')}", "stopped"
    elif failed:
        outcome, state = "FAILED: see failed rows below", "failed"
    elif not events:
        outcome, state = "INCOMPLETE: no events were collected", "incomplete"
    elif missing or unobserved or required_skips:
        why = (([f"missing required tests: {', '.join(missing)}"] if missing else []) + ([f"{unobserved} unobserved"] if unobserved else [])
               + ([f"required tests skipped: {', '.join(required_skips)}"] if required_skips else []))
        outcome, state = "INCOMPLETE: " + "; ".join(why), "incomplete"
    else:
        outcome, state = "completed", "completed"
    runtime = provenance.get("runtime") if isinstance(provenance.get("runtime"), dict) else {}
    comparison = runtime.get("checkout_comparison") or {}
    python = provenance.get("remote_python") if isinstance(provenance.get("remote_python"), dict) else {}
    lines = ["# Azazel-Edge R0 Pi HIL result bundle", "",
             f"Session: `{raw_dir.name}`", "",
             f"Outcome: {redact(str(outcome)).replace(chr(10), ' ')[:400]}", "",
             "Safety: observation-only by default. No routing, firewall, qdisc, or M.I.O. execution was enabled.", "",
             "## Versions under test", "",
             "HIL validates the **checkout**, not the running `/opt/azazel-edge` runtime that systemd services execute.", "",
             f"- Checkout: `{provenance.get('repo', 'unknown')}` at `{provenance.get('git_sha', 'unavailable')}`",
             f"- Running runtime: `{runtime.get('root', '/opt/azazel-edge')}`; Git: {runtime.get('git_sha', 'unsupported')}; "
             f"{runtime.get('identity', 'unsupported: no runtime identity recorded')}"
             + (f" (identical {comparison.get('identical')}/{comparison.get('compared')}, different: {', '.join(comparison.get('different') or []) or 'none'},"
                f" missing: {', '.join(comparison.get('missing') or []) or 'none'})" if comparison else ""),
             f"- Remote Python for dependency/replay/observer checks: `{python.get('path', 'unknown')}` ({python.get('source', 'unknown')})", "",
             "## Result summary", "", "| Test | Status | Exit | Notes |", "|---|---:|---:|---|"]
    for row in rows:
        detail = row.get("detail", {})
        note = detail.get("reason") or detail.get("summary") or ""
        lines.append(f"| `{row.get('test_id')}` | {row.get('status')} | {row.get('exit_code', '')} | {str(note).replace('|', '/')[:180]} |")
    lines += ["", f"Passed: {passed}; skipped: {skipped}; unobserved: {unobserved}; failed: {failed}.", "",
              "`unobserved` means the read-only observation could not be made (for example no sudo for `nft`); it is not a pass.", "", "## Provenance", "", "```json", json.dumps(redact(provenance), sort_keys=True, indent=2), "```"]
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"passed": passed, "skipped": skipped, "unobserved": unobserved, "failed": failed, "events": len(events),
            "outcome": state, "missing": missing, "required_skipped": required_skips}


def collect(args: argparse.Namespace, stopped: dict[str, str] | None = None) -> int:
    return collect_summary(args, stopped)[0]


def collect_summary(args: argparse.Namespace, stopped: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    output = Path(args.output).expanduser().resolve() / args.session
    raw = output / "raw"
    report = output / "CHATGPT_PASTE.md"
    # Never leave a previous run's report or copied artifacts behind for this session.
    report.unlink(missing_ok=True)
    if raw.is_dir():
        shutil.rmtree(raw)
    raw.mkdir(parents=True, exist_ok=True)
    remote = f"{target(args)}:.cache/azazel-hil/{args.session}/"
    result = subprocess.run(scp_base(args, "-r") + ["--", remote, str(raw)], text=True, capture_output=True)
    if result.returncode:
        error = RemoteError("scp (collect session artifacts)", result)
        print(f"azazel-hil: session {args.session}: {error}", file=sys.stderr)
        # 255 is an OpenSSH transport failure; any other scp failure means the bundle could not be produced.
        return (255 if result.returncode == 255 else EXIT_STOPPED), {}
    copied_session = raw / args.session
    summary = write_report(copied_session if copied_session.is_dir() else raw, report, stopped)
    print(json.dumps({"session": args.session, "report": str(report), "raw": str(raw), **summary,
                      **({"stopped": stopped} if stopped else {})}, sort_keys=True))
    return 0, summary


def restart_arguments_error(args: argparse.Namespace) -> str | None:
    if args.allow_service_restart and not args.service:
        return "--allow-service-restart requires at least one --service"
    if args.service and not args.allow_service_restart:
        print("azazel-hil: warning: --service ignored without --allow-service-restart; no service will be restarted", file=sys.stderr)
    return None


def full(args: argparse.Namespace) -> int:
    print(f"azazel-hil: session {args.session} (reuse with --session {args.session} to resume or collect)", file=sys.stderr)
    stages = [("preflight", []), ("prepare", ["--no-update-repo"] if args.no_update_repo else []), ("bootstrap", ["--dry-run"]), ("run", [])]
    if args.allow_service_restart:
        stages[-1][1].extend(["--allow-service-restart"] + sum((["--service", x] for x in args.service), []))
    for action, extra in stages:
        try:
            result = remote_call(args, action, extra)
        except (OSError, RemoteError) as exc:
            code = exc.returncode if isinstance(exc, RemoteError) else 2
            stopped = {"stage": action, "reason": str(exc)}
        else:
            # Remote exit 1 = the stage ran but a test failed (evidence, keep going); >=2 = it could not proceed.
            if result.returncode in (0, 1):
                continue
            code, stopped = result.returncode, {"stage": action, "reason": failure_reason(result)}
        print(f"azazel-hil: session {args.session}: stopped at stage {action}: {stopped['reason']}", file=sys.stderr)
        print("azazel-hil: collecting the artifacts recorded so far", file=sys.stderr)
        collect(args, stopped)
        return code if code == 255 else EXIT_STOPPED
    code, summary = collect_summary(args)
    if code:
        return code
    if summary.get("outcome") == "failed":
        print(f"azazel-hil: session {args.session}: {summary['failed']} test(s) failed; see the report", file=sys.stderr)
        return EXIT_FAILED
    if summary.get("outcome") != "completed":
        print(f"azazel-hil: session {args.session}: evidence incomplete ({summary['unobserved']} unobserved,"
              f" missing: {', '.join(summary.get('missing') or []) or 'none'},"
              f" skipped: {', '.join(summary.get('required_skipped') or []) or 'none'}); see the report", file=sys.stderr)
        return EXIT_INCOMPLETE
    return EXIT_COMPLETED


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Safe laptop-to-Pi bridge for Azazel R0 HIL validation.")
    p.add_argument("--target", required=True, type=no_option, help="Pi hostname or IP; SSH host keys must already be trusted.")
    p.add_argument("--user", type=no_option, help="SSH user (otherwise SSH config/default is used)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--identity", help="Path to an SSH private key; its contents are never read or recorded.")
    p.add_argument("--remote-repo", default="~/Azazel-Edge", help="Existing Pi checkout; bootstrap never clones or modifies it.")
    p.add_argument("--remote-python", help="Pi interpreter that has the Edge dependencies (default: /opt/azazel-edge/venv/bin/python if present, else python3).")
    p.add_argument("--session", default=session_id(), type=valid_session, help="Reuse this value to resume an interrupted session.")
    p.add_argument("--output", default=str(ROOT / "artifacts" / "hil"), help="Mac destination for raw artifacts and report.")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("preflight", "prepare", "bootstrap", "run", "doctor", "full"):
        q = sub.add_parser(name)
        if name in ("prepare", "full"):
            q.add_argument("--no-update-repo", action="store_true", help="Check readiness without fetch/pull; full updates a clean main checkout by default.")
        if name == "bootstrap":
            q.add_argument("--dry-run", action="store_true")
            q.add_argument("--install-required", action="store_true", help="Reserved explicit opt-in; current runner needs no package installation.")
        if name in ("run", "full"):
            q.add_argument("--allow-service-restart", action="store_true", help="Permit explicitly named service restarts for reconciliation only.")
            q.add_argument("--service", action="append", default=[], help="Service name; required with --allow-service-restart.")
    sub.add_parser("collect")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "collect":
        return collect(args)
    if args.command in ("run", "full"):
        error = restart_arguments_error(args)
        if error:
            print(f"azazel-hil: {error}; nothing was run", file=sys.stderr)
            return EXIT_STOPPED
    if args.command == "full":
        return full(args)
    extra: list[str] = []
    if args.command == "bootstrap":
        extra = (["--dry-run"] if args.dry_run else []) + (["--install-required"] if args.install_required else [])
    if args.command == "prepare" and args.no_update_repo:
        extra = ["--no-update-repo"]
    if args.command == "run" and args.allow_service_restart:
        extra = ["--allow-service-restart"] + sum((["--service", x] for x in args.service), [])
    try:
        result = remote_call(args, args.command, extra)
    except (OSError, RemoteError) as exc:
        print(f"azazel-hil: session {args.session}: {redact(str(exc))}", file=sys.stderr)
        return exc.returncode if isinstance(exc, RemoteError) else 2
    print(redact(result.stdout))
    if result.stderr:
        print(redact(result.stderr), file=sys.stderr)
    if result.returncode:
        print(f"azazel-hil: session {args.session}: {args.command} failed: {failure_reason(result)}", file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
