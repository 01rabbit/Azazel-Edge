#!/usr/bin/env python3
"""Laptop-side SSH orchestrator for the non-enforcing Azazel R0 Pi HIL gate."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import secrets
import shutil
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


def ssh_base(args: argparse.Namespace) -> list[str]:
    command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=12", "-p", str(args.port)]
    if args.identity:
        command += ["-i", args.identity]
    return command


def target(args: argparse.Namespace) -> str:
    return f"{args.user}@{args.target}" if args.user else args.target


def remote_call(args: argparse.Namespace, action: str, extra: list[str]) -> subprocess.CompletedProcess[str]:
    remote_dir = f".cache/azazel-hil/{args.session}"
    setup = ssh_base(args) + [target(args), f"mkdir -p $HOME/{remote_dir}"]
    subprocess.run(setup, text=True, capture_output=True, check=True)
    scp = ["scp", "-P", str(args.port)]
    if args.identity:
        scp += ["-i", args.identity]
    scp += [str(REMOTE_RUNNER), f"{target(args)}:~/{remote_dir}/azazel_hil_remote.py"]
    subprocess.run(scp, text=True, capture_output=True, check=True)
    command = ssh_base(args) + [target(args), "python3", f"$HOME/{remote_dir}/azazel_hil_remote.py", action,
                                "--session", args.session, "--repo", args.remote_repo]
    command += extra
    return subprocess.run(command, text=True, capture_output=True)


def write_report(raw_dir: Path, report_path: Path) -> dict[str, Any]:
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
    failed = len(rows) - passed - skipped
    lines = ["# Azazel-Edge R0 Pi HIL result bundle", "",
             f"Session: `{raw_dir.name}`", "",
             "Safety: observation-only by default. No routing, firewall, qdisc, or M.I.O. execution was enabled.", "",
             "## Result summary", "", "| Test | Status | Exit | Notes |", "|---|---:|---:|---|"]
    for row in rows:
        detail = row.get("detail", {})
        note = detail.get("reason") or detail.get("summary") or ""
        lines.append(f"| `{row.get('test_id')}` | {row.get('status')} | {row.get('exit_code', '')} | {str(note).replace('|', '/')[:180]} |")
    lines += ["", f"Passed: {passed}; skipped: {skipped}; failed: {failed}.", "", "## Provenance", "", "```json", json.dumps(redact(provenance), sort_keys=True, indent=2), "```"]
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"passed": passed, "skipped": skipped, "failed": failed, "events": len(events)}


def collect(args: argparse.Namespace) -> int:
    output = Path(args.output).expanduser().resolve() / args.session
    raw = output / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    remote = f"{target(args)}:~/.cache/azazel-hil/{args.session}/"
    scp = ["scp", "-r", "-P", str(args.port)]
    if args.identity:
        scp += ["-i", args.identity]
    result = subprocess.run(scp + [remote, str(raw)], text=True, capture_output=True)
    if result.returncode:
        print(redact(result.stderr), file=sys.stderr)
        return result.returncode
    copied_session = raw / args.session
    summary = write_report(copied_session if copied_session.is_dir() else raw, output / "CHATGPT_PASTE.md")
    print(json.dumps({"report": str(output / "CHATGPT_PASTE.md"), "raw": str(raw), **summary}, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Safe laptop-to-Pi bridge for Azazel R0 HIL validation.")
    p.add_argument("--target", required=True, help="Pi hostname or IP; SSH host keys must already be trusted.")
    p.add_argument("--user", help="SSH user (otherwise SSH config/default is used)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--identity", help="Path to an SSH private key; its contents are never read or recorded.")
    p.add_argument("--remote-repo", default="~/Azazel-Edge", help="Existing Pi checkout; bootstrap never clones or modifies it.")
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
        stages = [("preflight", []), ("prepare", ["--no-update-repo"] if args.no_update_repo else []), ("bootstrap", ["--dry-run"]), ("run", [])]
        if args.allow_service_restart:
            stages[-1][1] += ["--allow-service-restart"] + sum((["--service", x] for x in args.service), [])
        for action, extra in stages:
            result = remote_call(args, action, extra)
            if result.returncode:
                print(redact(result.stderr), file=sys.stderr)
                return result.returncode
        return collect(args)
    extra: list[str] = []
    if args.command == "bootstrap":
        extra = (["--dry-run"] if args.dry_run else []) + (["--install-required"] if args.install_required else [])
    if args.command == "prepare" and args.no_update_repo:
        extra = ["--no-update-repo"]
    if args.command == "run" and args.allow_service_restart:
        extra = ["--allow-service-restart"] + sum((["--service", x] for x in args.service), [])
    try:
        result = remote_call(args, args.command, extra)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(redact(str(exc)), file=sys.stderr)
        return 2
    print(redact(result.stdout))
    if result.stderr:
        print(redact(result.stderr), file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
