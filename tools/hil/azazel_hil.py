#!/usr/bin/env python3
"""Laptop-side SSH orchestrator for the non-enforcing Azazel R0 Pi HIL gate."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import secrets
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REMOTE_RUNNER = Path(__file__).with_name("azazel_hil_remote.py")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
AUTH_RE = re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization)\s*[:=]\s*).*$")
BEARER_RE = re.compile(r"(?i)(bearer\s+)[^\s'\"]+")
TOKEN_ASSIGN_RE = re.compile(r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*=)\S+")


def redact(value: Any) -> Any:
    if isinstance(value, str):
        value = PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", value)
        value = AUTH_RE.sub(r"\1[REDACTED]", value)
        value = BEARER_RE.sub(r"\1[REDACTED]", value)
        return TOKEN_ASSIGN_RE.sub(r"\1[REDACTED]", value)
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if re.search(r"(?i)(token|secret|password|private.?key)", str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def session_id() -> str:
    return "r0-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(3)


SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=12"]


class RemoteError(RuntimeError):
    """An SSH/SCP transport step failed before the remote runner could report."""

    def __init__(self, step: str, completed: subprocess.CompletedProcess[str]) -> None:
        self.step = step
        self.returncode = completed.returncode or 2
        lines = [line.strip() for line in redact(completed.stderr or completed.stdout or "").splitlines() if line.strip()]
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
    setup = subprocess.run(ssh_base(args) + [target(args), f"mkdir -p $HOME/{shlex.quote(remote_dir)}"], text=True, capture_output=True)
    if setup.returncode:
        raise RemoteError("ssh (create remote session directory)", setup)
    upload = subprocess.run(scp_base(args) + [str(REMOTE_RUNNER), f"{target(args)}:{remote_dir}/azazel_hil_remote.py"], text=True, capture_output=True)
    if upload.returncode:
        raise RemoteError("scp (upload remote runner)", upload)
    remote_argv = [action, "--session", args.session, "--repo", args.remote_repo]
    if getattr(args, "remote_python", None):
        remote_argv += ["--python", args.remote_python]
    remote_argv += extra
    # The remote login shell joins argv; quote every value so names and paths stay single arguments.
    command = ssh_base(args) + [target(args), "python3", f"$HOME/{shlex.quote(remote_dir)}/azazel_hil_remote.py",
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
    tail = redact((result.stderr or "").strip()).splitlines()
    return tail[-1] if tail else f"remote runner exited {result.returncode} without a result summary"


def write_report(raw_dir: Path, report_path: Path, stopped: dict[str, str] | None = None) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for path in sorted(raw_dir.rglob("*.jsonl")):
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
    if stopped:
        outcome = f"INCOMPLETE: stopped at stage `{stopped.get('stage')}`: {stopped.get('reason')}"
    elif failed:
        outcome = "FAILED: see failed rows below"
    else:
        outcome = "completed"
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
    return {"passed": passed, "skipped": skipped, "unobserved": unobserved, "failed": failed, "events": len(events)}


def collect(args: argparse.Namespace, stopped: dict[str, str] | None = None) -> int:
    return collect_summary(args, stopped)[0]


def collect_summary(args: argparse.Namespace, stopped: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    output = Path(args.output).expanduser().resolve() / args.session
    raw = output / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    remote = f"{target(args)}:.cache/azazel-hil/{args.session}/"
    result = subprocess.run(scp_base(args, "-r") + [remote, str(raw)], text=True, capture_output=True)
    if result.returncode:
        error = RemoteError("scp (collect session artifacts)", result)
        print(f"azazel-hil: session {args.session}: {error}", file=sys.stderr)
        return result.returncode, {}
    copied_session = raw / args.session
    summary = write_report(copied_session if copied_session.is_dir() else raw, output / "CHATGPT_PASTE.md", stopped)
    print(json.dumps({"session": args.session, "report": str(output / "CHATGPT_PASTE.md"), "raw": str(raw), **summary,
                      **({"stopped": stopped} if stopped else {})}, sort_keys=True))
    return 0, summary


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
            if not result.returncode:
                continue
            code, stopped = result.returncode, {"stage": action, "reason": failure_reason(result)}
        print(f"azazel-hil: session {args.session}: stopped at stage {action}: {stopped['reason']}", file=sys.stderr)
        print("azazel-hil: collecting the artifacts recorded so far", file=sys.stderr)
        collect(args, stopped)
        return code or 2
    code, summary = collect_summary(args)
    if code == 0 and summary.get("failed"):
        print(f"azazel-hil: session {args.session}: {summary['failed']} test(s) failed; see the report", file=sys.stderr)
        return 1
    return code


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Safe laptop-to-Pi bridge for Azazel R0 HIL validation.")
    p.add_argument("--target", required=True, help="Pi hostname or IP; SSH host keys must already be trusted.")
    p.add_argument("--user", help="SSH user (otherwise SSH config/default is used)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--identity", help="Path to an SSH private key; its contents are never read or recorded.")
    p.add_argument("--remote-repo", default="~/Azazel-Edge", help="Existing Pi checkout; bootstrap never clones or modifies it.")
    p.add_argument("--remote-python", help="Pi interpreter that has the Edge dependencies (default: /opt/azazel-edge/venv/bin/python if present, else python3).")
    p.add_argument("--session", default=session_id(), help="Reuse this value to resume an interrupted session.")
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
