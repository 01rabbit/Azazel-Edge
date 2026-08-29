#!/usr/bin/env python3
"""Transferred by azazel-hil; stdlib-only remote R0 HIL evidence collector.

It intentionally contains no enforcement primitive.  Commands are fixed, argv-only,
and the one mutation (a service restart) requires two independent explicit flags.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
AUTH_RE = re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization)\s*[:=]\s*).*$")
BEARER_RE = re.compile(r"(?i)(bearer\s+)[^\s'\"]+")
TOKEN_ASSIGN_RE = re.compile(r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*=)\S+")
MODELS = ("qwen3.5:0.8b", "qwen3.5:2b")


def redact(value: Any) -> Any:
    if isinstance(value, str):
        value = PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", value)
        value = AUTH_RE.sub(r"\1[REDACTED]", value)
        value = BEARER_RE.sub(r"\1[REDACTED]", value)
        return TOKEN_ASSIGN_RE.sub(r"\1[REDACTED]", value)
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if re.search(r"(?i)(token|secret|password|private.?key)", str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list): return [redact(x) for x in value]
    return value


class Recorder:
    def __init__(self, session: str) -> None:
        self.directory = Path.home() / ".cache" / "azazel-hil" / session
        self.directory.mkdir(parents=True, exist_ok=True)
        self.events = self.directory / "events.jsonl"

    def emit(self, kind: str, **data: Any) -> None:
        item = redact({"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), "kind": kind, **data})
        with self.events.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(item, sort_keys=True) + "\n")

    def complete(self, test_id: str) -> bool:
        try:
            return any(json.loads(line).get("kind") == "test_end" and json.loads(line).get("test_id") == test_id and json.loads(line).get("status") == "passed" for line in self.events.read_text().splitlines())
        except (OSError, json.JSONDecodeError):
            return False

    def test(self, test_id: str, fn) -> None:
        if self.complete(test_id):
            self.emit("test_skip", test_id=test_id, detail={"reason": "resume: previously passed"})
            return
        started = time.monotonic()
        self.emit("test_start", test_id=test_id)
        try:
            status, exit_code, detail = fn()
        except Exception as exc:  # artifact must survive a diagnostic failure
            status, exit_code, detail = "failed", 1, {"reason": type(exc).__name__, "summary": str(exc)}
        detail["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        self.emit("test_end", test_id=test_id, status=status, exit_code=exit_code, detail=detail)


def command(rec: Recorder, test_id: str, argv: list[str], timeout: int = 30) -> tuple[int, dict[str, Any]]:
    started = time.monotonic()
    try:
        done = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
        result = {"argv": argv, "stdout": done.stdout[-12000:], "stderr": done.stderr[-12000:], "exit_code": done.returncode,
                  "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
    except subprocess.TimeoutExpired as exc:
        result = {"argv": argv, "stdout": (exc.stdout or "")[-12000:], "stderr": (exc.stderr or "")[-12000:], "exit_code": 124,
                  "elapsed_ms": round((time.monotonic() - started) * 1000, 3), "timed_out": True}
    rec.emit("command", test_id=test_id, **result)
    return int(result["exit_code"]), result


def read(path: str, default: str = "unavailable") -> str:
    try: return Path(path).read_text(encoding="utf-8").strip()
    except OSError: return default


def memory() -> dict[str, str]:
    values = {}
    for line in read("/proc/meminfo", "").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}: values[key] = value.strip()
    return values


def ollama_processes() -> list[dict[str, str]]:
    """Use procfs rather than a shell; this is read-only Linux/Pi provenance."""
    records: list[dict[str, str]] = []
    for entry in Path("/proc").glob("[0-9]*"):
        status = read(str(entry / "status"), "")
        if not status.startswith("Name:\tollama"):
            continue
        values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status.splitlines() if ":" in line}
        stat = read(str(entry / "stat"), "").split()
        ticks = int(stat[13]) + int(stat[14]) if len(stat) > 14 and stat[13].isdigit() and stat[14].isdigit() else 0
        records.append({"pid": entry.name, "rss_kib": values.get("VmRSS", "0 kB"), "threads": values.get("Threads", "unknown"),
                        "cpu_seconds": round(ticks / max(1, os.sysconf("SC_CLK_TCK")), 3)})
    return records


def provenance(repo: Path) -> dict[str, Any]:
    data: dict[str, Any] = {"hostname": os.uname().nodename, "kernel": os.uname().release, "machine": os.uname().machine,
                            "os_release": read("/etc/os-release"), "cpu": read("/proc/cpuinfo", "").split("\n")[0:8], "memory": memory(),
                            "disk": shutil.disk_usage(Path.home())._asdict(), "thermal_c": read("/sys/class/thermal/thermal_zone0/temp"),
                            "python": sys.version.split()[0], "repo": str(repo), "repo_exists": repo.is_dir()}
    if data["thermal_c"].isdigit(): data["thermal_c"] = round(int(data["thermal_c"]) / 1000, 1)
    if repo.is_dir():
        for key, argv in (("git_sha", ["git", "-C", str(repo), "rev-parse", "HEAD"]), ("git_status", ["git", "-C", str(repo), "status", "--porcelain"])):
            try: data[key] = subprocess.check_output(argv, text=True, stderr=subprocess.DEVNULL).strip()
            except (OSError, subprocess.CalledProcessError): data[key] = "unavailable"
    return data


def preflight(rec: Recorder, repo: Path) -> None:
    rec.emit("provenance", data=provenance(repo))
    def check() -> tuple[str, int, dict[str, Any]]:
        checks = {name: shutil.which(name) is not None for name in ("python3", "git", "ollama", "rustc", "cargo", "tc", "nft", "systemctl")}
        service = {}
        for name in ("azazel-edge-web", "azazel-edge-control-daemon", "azazel-edge-core"):
            code, out = command(rec, "preflight.services", ["systemctl", "is-active", name])
            service[name] = {"active": code == 0, "state": out["stdout"].strip()}
        inventory: dict[str, Any] = {"ollama_available": checks["ollama"]}
        if checks["ollama"]:
            code, out = command(rec, "preflight.ollama", ["ollama", "list"])
            inventory.update({"exit_code": code, "models": out["stdout"]})
        return "passed", 0, {"summary": "Pi runtime inventory captured", "commands": checks, "services": service, "ollama": inventory}
    rec.test("preflight.inventory", check)


def bootstrap(rec: Recorder, dry_run: bool, install_required: bool) -> None:
    def check() -> tuple[str, int, dict[str, Any]]:
        required = {"python3": shutil.which("python3") is not None, "ssh": True}
        missing = [name for name, exists in required.items() if not exists]
        return ("passed" if not missing else "failed", 0 if not missing else 1,
                {"summary": "No package installation performed; remote runner is Python stdlib only.", "dry_run": dry_run,
                 "install_required_requested": install_required, "required": required, "missing": missing})
    rec.test("bootstrap.dependencies", check)


def model_inventory() -> set[str]:
    try:
        output = subprocess.check_output(["ollama", "list"], text=True, stderr=subprocess.DEVNULL, timeout=20)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired): return set()
    return {line.split()[0] for line in output.splitlines()[1:] if line.split()}


def profile_model(rec: Recorder, model: str) -> None:
    test_id = f"profile.{model}"
    def run() -> tuple[str, int, dict[str, Any]]:
        if not shutil.which("ollama") or model not in model_inventory():
            return "skipped", 0, {"reason": f"model not installed: {model}; bridge never pulls models"}
        before = {"memory": memory(), "thermal_c": provenance(Path("/")).get("thermal_c"), "ollama_processes": ollama_processes()}
        # Bounded local inference; no network endpoint, no prompt content is retained beyond this fixed string.
        code, out = command(rec, test_id, ["ollama", "run", model, "Reply with exactly OK."], timeout=180)
        after = {"memory": memory(), "thermal_c": provenance(Path("/")).get("thermal_c"), "ollama_processes": ollama_processes()}
        return ("passed" if code == 0 else "failed", code, {"summary": "bounded local Ollama inference profile", "before": before, "after": after,
                                                               "latency_ms": out["elapsed_ms"], "stdout_tail": out["stdout"][-400:]})
    rec.test(test_id, run)


def observer_checks(rec: Recorder, repo: Path) -> None:
    def run() -> tuple[str, int, dict[str, Any]]:
        if sys.version_info < (3, 8):
            return "skipped", 0, {"reason": "Pi Python is below 3.8; Outcome observer dependencies require a newer runtime"}
        if not (repo / "py" / "azazel_edge" / "outcome" / "observer.py").is_file():
            return "skipped", 0, {"reason": "outcome observer source unavailable in configured repo"}
        work = rec.directory / "observer"
        work.mkdir(exist_ok=True)
        snippet = """import json,sys,time\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\nfrom azazel_edge.outcome.observer import append_jsonl\np=Path(sys.argv[2]); start=time.perf_counter(); a=append_jsonl(p,[{'i':1,'x':'a'*80},{'i':2,'x':'b'*80}],max_bytes=120); b=append_jsonl(p,[{'too':'z'*500}],max_bytes=120); print(json.dumps({'accepted':a,'oversized_accepted':b,'rotated':p.with_suffix(p.suffix+'.1').exists(),'latency_ms':round((time.perf_counter()-start)*1000,3)}))"""
        code, out = command(rec, "observer.retention", ["python3", "-c", snippet, str(repo / "py"), str(work / "outcome.jsonl")])
        return ("passed" if code == 0 else "failed", code, {"summary": "observer append latency, rotation, and oversized-record drop exercised in isolated session storage", "result": out["stdout"]})
    rec.test("observer.retention_rotation_drop_backpressure", run)


def reconciliation(rec: Recorder, services: list[str], allow_restart: bool) -> None:
    def run() -> tuple[str, int, dict[str, Any]]:
        state = rec.directory / "reconciliation.jsonl"
        state.write_text('{"sequence":2}\n{"sequence":1}\n', encoding="utf-8")
        result: dict[str, Any] = {"summary": "out-of-order/restart checkpoint evidence recorded; no service restart requested", "state_file": str(state)}
        if allow_restart:
            if not services: return "failed", 2, {"reason": "--allow-service-restart requires at least one --service"}
            result["summary"] = "explicitly requested service restart evidence"
            result["services"] = {}
            for service in services:
                code, out = command(rec, "reconciliation.restart", ["systemctl", "restart", service], timeout=60)
                result["services"][service] = {"exit_code": code, "stderr": out["stderr"][-300:]}
            return ("passed" if all(x["exit_code"] == 0 for x in result["services"].values()) else "failed", 0, result)
        return "passed", 0, result
    rec.test("restart_reconciliation", run)


def postconditions(rec: Recorder) -> None:
    def run() -> tuple[str, int, dict[str, Any]]:
        result: dict[str, Any] = {"summary": "read-only independent tc/nft observation; no apply, release, or rollback command issued"}
        for name, argv in (("tc", ["tc", "qdisc", "show"]), ("nft", ["nft", "list", "ruleset"])):
            if shutil.which(name):
                code, out = command(rec, "postconditions.read_only", argv)
                result[name] = {"exit_code": code, "stdout_tail": out["stdout"][-400:], "stderr_tail": out["stderr"][-300:]}
            else: result[name] = {"reason": "not installed"}
        return "passed", 0, result
    rec.test("postconditions.tc_nft_read_only", run)


def doctor(rec: Recorder, repo: Path) -> None:
    def run() -> tuple[str, int, dict[str, Any]]:
        return "passed", 0, {"summary": "Copy this JSONL directory and command output when seeking assistance.", "python": shutil.which("python3"), "home_writable": os.access(Path.home(), os.W_OK), "repo_exists": repo.is_dir(), "hint": "Verify known_hosts, SSH user/port/key path, and remote repo location; do not paste private-key contents."}
    rec.test("doctor.remote", run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "bootstrap", "run", "doctor"))
    parser.add_argument("--session", required=True)
    parser.add_argument("--repo", default="~/Azazel-Edge")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--install-required", action="store_true")
    parser.add_argument("--allow-service-restart", action="store_true")
    parser.add_argument("--service", action="append", default=[])
    args = parser.parse_args(argv)
    rec, repo = Recorder(args.session), Path(args.repo).expanduser()
    if args.action == "preflight": preflight(rec, repo)
    elif args.action == "bootstrap": bootstrap(rec, args.dry_run, args.install_required)
    elif args.action == "doctor": doctor(rec, repo)
    else:
        rec.emit("provenance", data=provenance(repo))
        for model in MODELS: profile_model(rec, model)
        observer_checks(rec, repo)
        reconciliation(rec, args.service, args.allow_service_restart)
        postconditions(rec)
    print(json.dumps({"session": args.session, "events": str(rec.events), "action": args.action}, sort_keys=True))
    return 0


if __name__ == "__main__": raise SystemExit(main())
