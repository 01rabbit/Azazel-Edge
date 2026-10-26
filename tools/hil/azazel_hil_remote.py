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
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

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
MODELS = ("qwen3.5:0.8b", "qwen3.5:2b")
# Fixed loopback endpoint: Ollama on the Pi runs in Docker and publishes 11434 on the host.
# The bridge only reads inventory (/api/version, /api/tags, /api/ps) and issues one bounded
# generate request per installed model.  It never pulls, deletes, or copies a model.
OLLAMA_API = "http://127.0.0.1:11434"
RUNTIME_ROOT = Path("/opt/azazel-edge")
RUNTIME_VENV_PYTHON = RUNTIME_ROOT / "venv" / "bin" / "python"
# Only Edge units may be restarted, and only with the explicit two-flag opt-in.
SERVICE_RE = re.compile(r"azazel-edge-[a-z0-9]+(?:-[a-z0-9]+)*(?:\.service)?")  # used with fullmatch only
SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
NFT_PATHS = ("/usr/sbin/nft", "/sbin/nft")  # fixed paths; nft is never resolved through PATH
OLLAMA_NUM_PREDICT = 16  # bounded generation length per measurement
OLLAMA_GENERATE_TIMEOUT = 180  # seconds; upper bound per measurement
RESTART_SETTLE_SECONDS = 15  # upper bound for a restarted unit to report active

# Files deployed verbatim from the checkout into /opt/azazel-edge (subset of
# installer/internal/verify_runtime_sync.sh), used only to say whether the running
# runtime matches the checkout under test.
RUNTIME_SYNC_FILES = (
    "py/azazel_edge/__init__.py", "py/azazel_edge/control_plane.py", "py/azazel_edge/path_schema.py",
    "py/azazel_edge_control/daemon.py", "py/azazel_edge_ai/agent.py", "azazel_edge_web/app.py",
    "rust/azazel-edge-core/Cargo.toml", "rust/azazel-edge-core/src/main.rs",
)


def tail(text: Any, limit: int) -> str:
    """Redact the whole text first, then truncate, so a limit can never split a secret past the redactor."""
    return redact(str(text or ""))[-limit:]


def valid_session(value: str) -> str:
    if not SESSION_RE.fullmatch(value) or ".." in value:
        raise argparse.ArgumentTypeError("session must match [A-Za-z0-9][A-Za-z0-9._-]* and must not contain '..'")
    return value


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
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
        result = {"argv": argv, "stdout": tail(done.stdout, 12000), "stderr": tail(done.stderr, 12000), "exit_code": done.returncode,
                  "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
    except subprocess.TimeoutExpired as exc:
        out_text = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else exc.stdout
        err_text = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else exc.stderr
        result = {"argv": argv, "stdout": tail(out_text, 12000), "stderr": tail(err_text, 12000), "exit_code": 124,
                  "elapsed_ms": round((time.monotonic() - started) * 1000, 3), "timed_out": True}
    rec.emit("command", test_id=test_id, **result)
    return int(result["exit_code"]), result


def find_tool(name: str) -> str | None:
    """Like shutil.which, but also looks in sbin, which is absent from a non-root SSH PATH on Debian."""
    found = shutil.which(name)
    if found: return found
    for directory in ("/usr/sbin", "/sbin", "/usr/local/sbin"):
        candidate = Path(directory) / name
        if os.access(candidate, os.X_OK): return str(candidate)
    return None


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


def resolve_python(explicit: str | None) -> dict[str, str]:
    """Pick the interpreter that owns the Edge dependencies (the /opt venv), not system python3."""
    if explicit:
        return {"path": explicit, "source": "--remote-python"}
    if os.access(RUNTIME_VENV_PYTHON, os.X_OK):
        return {"path": str(RUNTIME_VENV_PYTHON), "source": "default: runtime venv"}
    return {"path": "python3", "source": "default: python3 (runtime venv not found)"}


def git(repo: Path, *argv: str) -> tuple[int, str, str]:
    try:
        done = subprocess.run(["git", "-C", str(repo), *argv], text=True, capture_output=True, timeout=30, check=False)
        return done.returncode, done.stdout.strip(), done.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", f"{type(exc).__name__}: {exc}"


def runtime_identity(repo: Path, root: Path = RUNTIME_ROOT) -> dict[str, Any]:
    """Describe the deployed runtime that services actually execute; read-only."""
    data: dict[str, Any] = {"root": str(root), "exists": root.is_dir()}
    if not data["exists"]:
        data["identity"] = "unsupported: runtime root not present"
        return data
    if (root / ".git").exists():
        code, out, err = git(root, "rev-parse", "HEAD")
        data["git_sha"] = out if code == 0 else f"unavailable: {tail(err, 200)}"
    else:
        data["git_sha"] = "unsupported: runtime is an installer copy without Git metadata"
    identical, different, missing = [], [], []
    for rel in RUNTIME_SYNC_FILES:
        try:
            deployed = (root / rel).read_bytes()
        except OSError:
            missing.append(rel)
            continue
        try:
            source = (repo / rel).read_bytes()
        except OSError:
            missing.append(rel)
            continue
        (identical if deployed == source else different).append(rel)
    data["checkout_comparison"] = {"compared": len(RUNTIME_SYNC_FILES), "identical": len(identical), "different": different, "missing": missing}
    data["identity"] = ("matches checkout for compared files" if not different and not missing
                        else "differs from checkout or incomplete; HIL results describe the checkout, not the running runtime")
    return data


def provenance(repo: Path, python: dict[str, str] | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"hostname": os.uname().nodename, "kernel": os.uname().release, "machine": os.uname().machine,
                            "os_release": read("/etc/os-release"), "cpu": read("/proc/cpuinfo", "").split("\n")[0:8], "memory": memory(),
                            "disk": shutil.disk_usage(Path.home())._asdict(), "thermal_c": read("/sys/class/thermal/thermal_zone0/temp"),
                            "python": sys.version.split()[0], "repo": str(repo), "repo_exists": repo.is_dir()}
    if data["thermal_c"].isdigit(): data["thermal_c"] = round(int(data["thermal_c"]) / 1000, 1)
    if python is not None:
        data["remote_python"] = python
    if repo.is_dir():
        for key, argv in (("git_sha", ("rev-parse", "HEAD")), ("git_status", ("status", "--porcelain"))):
            code, out, err = git(repo, *argv)
            data[key] = out if code == 0 else f"unavailable: {tail(err, 300)}"
    data["runtime"] = runtime_identity(repo)
    return data


def _loopback_opener() -> urllib.request.OpenerDirector:
    """Opener with an explicit empty proxy map: environment proxies never redirect loopback traffic."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def ollama_get(path: str, timeout: float = 5.0) -> tuple[Any, str]:
    """Read-only GET against the fixed loopback Ollama API; returns (json, error)."""
    try:
        with _loopback_opener().open(OLLAMA_API + path, timeout=timeout) as response:  # noqa: S310 - fixed loopback URL
            return json.loads(response.read().decode("utf-8", "replace") or "null"), ""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, tail(f"{type(exc).__name__}: {exc}", 300)


def ollama_inventory() -> dict[str, Any]:
    version, error = ollama_get("/api/version")
    if error:
        return {"api": OLLAMA_API, "reachable": False, "reason": f"Ollama API unreachable: {error}"}
    tags, tags_error = ollama_get("/api/tags")
    models = sorted(str(m.get("name") or m.get("model")) for m in (tags or {}).get("models", []) if isinstance(m, dict))
    result: dict[str, Any] = {"api": OLLAMA_API, "reachable": True, "version": (version or {}).get("version", "unknown"), "models": models}
    if tags_error:
        result["tags_error"] = tags_error
    return result


def ollama_generate(model: str, timeout: int = OLLAMA_GENERATE_TIMEOUT) -> tuple[int, dict[str, Any]]:
    """One bounded local inference; equivalent of `ollama run MODEL PROMPT` without the CLI.

    keep_alive=0 asks Ollama to unload the model right after the measurement so the probe does
    not leave a model resident in the Pi's memory.
    """
    timeout = min(timeout, OLLAMA_GENERATE_TIMEOUT)
    body = json.dumps({"model": model, "prompt": "Reply with exactly OK.", "stream": False, "keep_alive": 0,
                       "options": {"num_predict": OLLAMA_NUM_PREDICT}}).encode()
    request = urllib.request.Request(OLLAMA_API + "/api/generate", data=body, headers={"Content-Type": "application/json"}, method="POST")
    started = time.monotonic()
    try:
        with _loopback_opener().open(request, timeout=timeout) as response:  # noqa: S310 - fixed loopback URL
            payload = json.loads(response.read().decode("utf-8", "replace"))
        code, out = 0, {"response_tail": tail(payload.get("response", ""), 400),
                        **{k: payload.get(k) for k in ("total_duration", "load_duration", "eval_count", "eval_duration") if k in payload}}
    except urllib.error.HTTPError as exc:
        code, out = 1, {"error": f"HTTP {exc.code}: {tail(exc.read().decode('utf-8', 'replace'), 300)}"}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        code, out = 1, {"error": tail(f"{type(exc).__name__}: {exc}", 300)}
    out["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return code, out


def preflight(rec: Recorder, repo: Path, python: dict[str, str]) -> None:
    rec.emit("provenance", data=provenance(repo, python))
    def check() -> tuple[str, int, dict[str, Any]]:
        checks = {name: find_tool(name) is not None for name in ("python3", "git", "ollama", "rustc", "cargo", "tc", "nft", "systemctl")}
        service = {}
        for name in ("azazel-edge-web", "azazel-edge-control-daemon", "azazel-edge-core"):
            code, out = command(rec, "preflight.services", ["systemctl", "is-active", name])
            service[name] = {"active": code == 0, "state": out["stdout"].strip()}
        inventory = ollama_inventory()
        rec.emit("ollama", test_id="preflight.inventory", **inventory)
        return "passed", 0, {"summary": "Pi runtime inventory captured", "commands": checks, "services": service, "ollama": inventory,
                             "remote_python": python}
    rec.test("preflight.inventory", check)


def bootstrap(rec: Recorder, dry_run: bool, install_required: bool) -> None:
    def check() -> tuple[str, int, dict[str, Any]]:
        required = {"python3": shutil.which("python3") is not None, "ssh": True}
        missing = [name for name, exists in required.items() if not exists]
        return ("passed" if not missing else "failed", 0 if not missing else 1,
                {"summary": "No package installation performed; remote runner is Python stdlib only.", "dry_run": dry_run,
                 "install_required_requested": install_required, "required": required, "missing": missing})
    rec.test("bootstrap.dependencies", check)


def git_failure(step: str, out: dict[str, Any]) -> str:
    lines = [line.strip() for line in (out.get("stderr") or out.get("stdout") or "").splitlines() if line.strip()]
    # Git puts the cause on its fatal:/error: line and advice after it; report the cause.
    cause = next((line for line in lines if line.startswith(("fatal:", "error:"))), lines[-1] if lines else "no output")
    return f"git {step} failed (exit {out.get('exit_code')}): {cause}"


def prepare(rec: Recorder, repo: Path, update_repo: bool, python: dict[str, str]) -> None:
    """Synchronize only a clean main checkout, then prove required runtime readiness."""
    def check() -> tuple[str, int, dict[str, Any]]:
        if not repo.is_dir() or not (repo / ".git").exists():
            return "failed", 2, {"reason": "configured remote repo is not a Git checkout", "repo": str(repo)}
        code, status = command(rec, "prepare.repository", ["git", "-C", str(repo), "status", "--porcelain"])
        if code:
            return "failed", 2, {"reason": git_failure("status", status), "repo": str(repo)}
        code_branch, branch = command(rec, "prepare.repository", ["git", "-C", str(repo), "branch", "--show-current"])
        if code_branch:
            return "failed", 2, {"reason": git_failure("branch --show-current", branch), "repo": str(repo)}
        if status["stdout"].strip():
            changed = status["stdout"].strip().splitlines()
            return "failed", 2, {"reason": f"refusing repository update: checkout has {len(changed)} uncommitted/untracked path(s)",
                                 "branch": branch["stdout"].strip(), "changed_paths": changed[:20]}
        if branch["stdout"].strip() != "main":
            return "failed", 2, {"reason": "refusing repository update: checkout must be on main", "branch": branch["stdout"].strip()}
        steps: dict[str, Any] = {"branch": "main", "update_requested": update_repo}
        if update_repo:
            fetch_code, fetch = command(rec, "prepare.repository", ["git", "-C", str(repo), "fetch", "origin", "main"], timeout=90)
            steps["fetch_exit"] = fetch_code
            if fetch_code:
                return "failed", 2, {"reason": git_failure("fetch origin main", fetch), **steps}
            pull_code, pull = command(rec, "prepare.repository", ["git", "-C", str(repo), "pull", "--ff-only", "origin", "main"], timeout=90)
            steps.update({"pull_exit": pull_code, "pull_output": tail(pull["stdout"], 500)})
            if pull_code:
                return "failed", 2, {"reason": git_failure("pull --ff-only origin main", pull), **steps}
        sha_code, sha = command(rec, "prepare.repository", ["git", "-C", str(repo), "rev-parse", "HEAD"])
        steps["git_sha"] = sha["stdout"].strip() if sha_code == 0 else "unavailable"
        return "passed", 0, {"summary": "clean main checkout verified and synchronized" if update_repo else "clean main checkout verified; repository update intentionally skipped", **steps}
    rec.test("prepare.repository", check)

    def dependencies() -> tuple[str, int, dict[str, Any]]:
        modules = ("flask", "requests", "yaml", "PIL", "rich", "textual")
        interpreter = python["path"]
        check_code, pip_check = command(rec, "prepare.dependencies", [interpreter, "-m", "pip", "check"])
        import_code, imports = command(rec, "prepare.dependencies", [interpreter, "-c", "import " + ",".join(modules)])
        rust = {}
        for name in ("rustc", "cargo"):
            if shutil.which(name):
                code, out = command(rec, "prepare.dependencies", [name, "--version"])
                rust[name] = {"exit_code": code, "version": out["stdout"].strip()}
            else:
                rust[name] = {"reason": "not installed"}
        ok = check_code == 0 and import_code == 0
        detail: dict[str, Any] = {"summary": f"Python dependency integrity and runtime imports checked with {interpreter}", "python": python,
                                  "pip_check_exit": check_code, "pip_check": tail(pip_check["stdout"], 500), "imports_exit": import_code, "rust": rust}
        if not ok:
            failed = pip_check if check_code else imports
            last = (failed["stderr"] or failed["stdout"]).strip().splitlines()
            detail["reason"] = (f"{'pip check' if check_code else 'runtime import'} failed with {interpreter}"
                                f" ({python['source']}): {last[-1] if last else 'no output'}")
        return ("passed" if ok else "failed", 0 if ok else 2, detail)
    rec.test("prepare.dependencies", dependencies)

    def replay() -> tuple[str, int, dict[str, Any]]:
        if not rec.complete("prepare.repository") or not rec.complete("prepare.dependencies"):
            return "skipped", 0, {"reason": "repository or dependency readiness gate did not pass"}
        code, out = command(rec, "prepare.offline_replay", [python["path"], str(repo / "bin" / "azazel-mio-evaluate")], timeout=60)
        return ("passed" if code == 0 else "failed", code, {"summary": "offline M.I.O. invariant replay before HIL; no network, model, or enforcement", "stdout_tail": tail(out["stdout"], 500)})
    rec.test("prepare.offline_replay", replay)

    def gate() -> tuple[str, int, dict[str, Any]]:
        ready = all(rec.complete(test_id) for test_id in ("prepare.repository", "prepare.dependencies", "prepare.offline_replay"))
        blocked = [test_id for test_id in ("prepare.repository", "prepare.dependencies", "prepare.offline_replay") if not rec.complete(test_id)]
        return ("passed" if ready else "failed", 0 if ready else 2,
                {"summary": "R0 start gate passed"} if ready else {"reason": "R0 start gate blocked by: " + ", ".join(blocked), "blocked_by": blocked})
    rec.test("prepare.gate", gate)


def thermal() -> Any:
    value = read("/sys/class/thermal/thermal_zone0/temp")
    return round(int(value) / 1000, 1) if value.isdigit() else value


def profile_model(rec: Recorder, model: str) -> None:
    test_id = f"profile.{model}"
    def run() -> tuple[str, int, dict[str, Any]]:
        inventory = ollama_inventory()
        if not inventory["reachable"]:
            return "skipped", 0, {"reason": f"{inventory['reason']}; model {model} not measured", "api": OLLAMA_API}
        if model not in inventory["models"]:
            return "skipped", 0, {"reason": f"model not installed: {model}; bridge never pulls models", "installed": inventory["models"]}
        before = {"memory": memory(), "thermal_c": thermal(), "ollama_processes": ollama_processes(), "loaded": ollama_get("/api/ps")[0]}
        # Bounded loopback inference; the fixed prompt is the only content sent.
        code, out = ollama_generate(model)
        rec.emit("ollama_generate", test_id=test_id, model=model, exit_code=code, **out)
        after = {"memory": memory(), "thermal_c": thermal(), "ollama_processes": ollama_processes(), "loaded": ollama_get("/api/ps")[0]}
        detail = {"summary": "bounded local Ollama inference profile via loopback HTTP API", "before": before, "after": after,
                  "latency_ms": out["elapsed_ms"], **{k: v for k, v in out.items() if k != "elapsed_ms"}}
        if code:
            detail["reason"] = f"Ollama generate failed: {out.get('error', 'unknown')}"
        return ("passed" if code == 0 else "failed", code, detail)
    rec.test(test_id, run)


def observer_checks(rec: Recorder, repo: Path, python: dict[str, str]) -> None:
    def run() -> tuple[str, int, dict[str, Any]]:
        if sys.version_info < (3, 8):
            return "skipped", 0, {"reason": "Pi Python is below 3.8; Outcome observer dependencies require a newer runtime"}
        if not (repo / "py" / "azazel_edge" / "outcome" / "observer.py").is_file():
            return "skipped", 0, {"reason": "outcome observer source unavailable in configured repo"}
        work = rec.directory / "observer"
        work.mkdir(exist_ok=True)
        snippet = """import json,sys,time\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\nfrom azazel_edge.outcome.observer import append_jsonl\np=Path(sys.argv[2]); start=time.perf_counter(); a=append_jsonl(p,[{'i':1,'x':'a'*80},{'i':2,'x':'b'*80}],max_bytes=120); b=append_jsonl(p,[{'too':'z'*500}],max_bytes=120); print(json.dumps({'accepted':a,'oversized_accepted':b,'rotated':p.with_suffix(p.suffix+'.1').exists(),'latency_ms':round((time.perf_counter()-start)*1000,3)}))"""
        code, out = command(rec, "observer.retention", [python["path"], "-c", snippet, str(repo / "py"), str(work / "outcome.jsonl")])
        detail = {"summary": "observer append latency, rotation, and oversized-record drop exercised in isolated session storage", "result": out["stdout"]}
        if code:
            last = out["stderr"].strip().splitlines()
            detail["reason"] = f"observer exercise failed with {python['path']}: {last[-1] if last else 'no output'}"
        return ("passed" if code == 0 else "failed", code, detail)
    rec.test("observer.retention_rotation_drop_backpressure", run)


def wait_active(rec: Recorder, service: str, limit: float = RESTART_SETTLE_SECONDS) -> str:
    """Poll `systemctl is-active` (read-only) until active or the bounded deadline passes."""
    deadline = time.monotonic() + min(limit, RESTART_SETTLE_SECONDS)
    while True:
        code, out = command(rec, "reconciliation.restart", ["systemctl", "is-active", service])
        state = out["stdout"].strip() or f"exit {code}"
        if code == 0 and state == "active" or time.monotonic() >= deadline:
            return state
        time.sleep(1)


def reconciliation(rec: Recorder, services: list[str], allow_restart: bool) -> None:
    def run() -> tuple[str, int, dict[str, Any]]:
        state = rec.directory / "reconciliation.jsonl"
        state.write_text('{"sequence":2}\n{"sequence":1}\n', encoding="utf-8")
        result: dict[str, Any] = {"reason": "service restart not requested (--allow-service-restart not given); only the out-of-order checkpoint file was written",
                                  "state_file": str(state)}
        if services and not allow_restart:
            result["reason"] += f"; --service {', '.join(services)} ignored without --allow-service-restart"
        if allow_restart:
            if not services: return "failed", 2, {"reason": "--allow-service-restart requires at least one --service"}
            rejected = [service for service in services if not SERVICE_RE.fullmatch(service)]
            if rejected:
                return "failed", 2, {"reason": "refusing restart of non-Edge unit(s): " + ", ".join(rejected) + "; only azazel-edge-* units are allowed"}
            result.pop("reason")
            result["summary"] = "explicitly requested service restart evidence"
            result["services"] = {}
            for service in services:
                # sudo -n never prompts: missing sudo rights fail visibly instead of hanging or being misreported.
                code, out = command(rec, "reconciliation.restart", ["sudo", "-n", "systemctl", "restart", service], timeout=60)
                entry = {"exit_code": code, "stderr": tail(out["stderr"], 300)}
                if code == 0:
                    # exit 0 only means systemd accepted the job; require the unit to come back active.
                    entry["active_after"] = wait_active(rec, service)
                result["services"][service] = entry
            problems = []
            for name, entry in result["services"].items():
                if entry["exit_code"] != 0:
                    problems.append(f"{name}: restart failed: {(entry['stderr'].strip().splitlines() or ['exit ' + str(entry['exit_code'])])[-1]}")
                elif entry["active_after"] != "active":
                    problems.append(f"{name}: not active within {RESTART_SETTLE_SECONDS}s after restart (state: {entry['active_after']})")
            if problems:
                result["reason"] = "; ".join(problems)
                return "failed", 2, result
            return "passed", 0, result
        return "skipped", 0, result
    rec.test("restart_reconciliation", run)


def postconditions(rec: Recorder) -> None:
    def run() -> tuple[str, int, dict[str, Any]]:
        result: dict[str, Any] = {"summary": "read-only independent tc/nft observation; no apply, release, or rollback command issued"}
        unobserved: list[str] = []
        # nft list needs CAP_NET_ADMIN; read it through non-interactive sudo and never count a refusal as an observation.
        nft = next((path for path in NFT_PATHS if os.access(path, os.X_OK)), None)
        tc = find_tool("tc")
        for name, argv in (("tc", [tc, "qdisc", "show"] if tc else None), ("nft", ["sudo", "-n", nft, "list", "ruleset"] if nft else None)):
            if argv:
                code, out = command(rec, "postconditions.read_only", argv)
                result[name] = {"exit_code": code, "observed": code == 0, "stdout_tail": tail(out["stdout"], 400), "stderr_tail": tail(out["stderr"], 300)}
                if code:
                    last = out["stderr"].strip().splitlines()
                    unobserved.append(f"{name}: {last[-1] if last else 'exit ' + str(code)}")
            else:
                result[name] = {"observed": False, "reason": "not installed"}
                unobserved.append(f"{name}: not installed")
        if unobserved:
            result["reason"] = "not observed (no read access is not evidence): " + "; ".join(unobserved)
            return "unobserved", 0, result
        return "passed", 0, result
    rec.test("postconditions.tc_nft_read_only", run)


def doctor(rec: Recorder, repo: Path, python: dict[str, str]) -> None:
    def run() -> tuple[str, int, dict[str, Any]]:
        return "passed", 0, {"summary": "Copy this JSONL directory and command output when seeking assistance.", "python": shutil.which("python3"), "remote_python": python, "home_writable": os.access(Path.home(), os.W_OK), "repo_exists": repo.is_dir(), "hint": "Verify known_hosts, SSH user/port/key path, and remote repo location; do not paste private-key contents."}
    rec.test("doctor.remote", run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "prepare", "bootstrap", "run", "doctor"))
    parser.add_argument("--session", required=True, type=valid_session)
    parser.add_argument("--repo", default="~/Azazel-Edge")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--install-required", action="store_true")
    parser.add_argument("--no-update-repo", action="store_true")
    parser.add_argument("--allow-service-restart", action="store_true")
    parser.add_argument("--service", action="append", default=[])
    parser.add_argument("--python", help="Interpreter with the Edge dependencies; default /opt/azazel-edge/venv/bin/python if present, else python3.")
    args = parser.parse_args(argv)
    if args.service and not args.allow_service_restart:
        print("azazel-hil-remote: warning: --service ignored without --allow-service-restart; no service will be restarted", file=sys.stderr)
    rec, repo = Recorder(args.session), Path(args.repo).expanduser()
    python = resolve_python(args.python)
    start = len(rec.events.read_text(encoding="utf-8").splitlines()) if rec.events.exists() else 0
    code = 0
    if args.action == "preflight": preflight(rec, repo, python)
    elif args.action == "bootstrap": bootstrap(rec, args.dry_run, args.install_required)
    elif args.action == "prepare":
        prepare(rec, repo, not args.no_update_repo, python)
        code = 0 if rec.complete("prepare.gate") else 2
    elif args.action == "doctor": doctor(rec, repo, python)
    else:
        rec.emit("provenance", data=provenance(repo, python))
        if not rec.complete("prepare.gate"):
            rec.test("run.precondition", lambda: ("failed", 2, {"reason": "run requires a passed prepare.gate in this session; use full or prepare first"}))
            code = 2
        elif args.allow_service_restart and not args.service:
            rec.test("run.precondition", lambda: ("failed", 2, {"reason": "--allow-service-restart requires at least one --service; nothing was run"}))
            code = 2
        else:
            for model in MODELS: profile_model(rec, model)
            observer_checks(rec, repo, python)
            reconciliation(rec, args.service, args.allow_service_restart)
            postconditions(rec)
    result = summary(rec, args.session, args.action, python, start)
    print(json.dumps(result, sort_keys=True))
    # 2 = the stage could not proceed (gate/precondition); 1 = it ran but a test failed.
    if code == 0 and any(row.get("status") == "failed" for row in result["tests"].values()):
        code = 1
    return code


def summary(rec: Recorder, session: str, action: str, python: dict[str, str], start: int) -> dict[str, Any]:
    """Machine-readable result of this invocation so the laptop can report why a stage stopped."""
    results: dict[str, Any] = {}
    for line in rec.events.read_text(encoding="utf-8").splitlines()[start:]:
        try: item = json.loads(line)
        except json.JSONDecodeError: continue
        if item.get("kind") == "test_end":
            detail = item.get("detail") or {}
            results[item.get("test_id")] = {"status": item.get("status"), "reason": detail.get("reason") or detail.get("summary", "")}
    return {"session": session, "events": str(rec.events), "action": action, "python": python, "tests": results}


if __name__ == "__main__": raise SystemExit(main())
