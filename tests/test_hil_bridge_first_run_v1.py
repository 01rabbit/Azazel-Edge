"""R0 HIL bridge must work on the first real Pi run and report failures honestly."""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hil = _load("azazel_hil_first_run", "tools/hil/azazel_hil.py")
remote = _load("azazel_hil_remote_first_run", "tools/hil/azazel_hil_remote.py")


@pytest.fixture()
def rec(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return remote.Recorder("r0-test")


def _ends(rec) -> dict:
    rows = [json.loads(line) for line in rec.events.read_text().splitlines()]
    return {row["test_id"]: row for row in rows if row["kind"] == "test_end"}


def _done(argv, code=0, stdout="", stderr=""):
    return {"argv": argv, "stdout": stdout, "stderr": stderr, "exit_code": code, "elapsed_ms": 1.0}


# 1. dependency checks use the runtime venv interpreter

def test_remote_python_prefers_runtime_venv_then_python3(tmp_path, monkeypatch):
    venv_python = tmp_path / "venv" / "bin" / "python"
    monkeypatch.setattr(remote, "RUNTIME_VENV_PYTHON", venv_python)
    assert remote.resolve_python(None)["path"] == "python3"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("#!/bin/sh\n")
    venv_python.chmod(0o755)
    chosen = remote.resolve_python(None)
    assert chosen["path"] == str(venv_python) and "venv" in chosen["source"]
    assert remote.resolve_python("/usr/bin/python3.13") == {"path": "/usr/bin/python3.13", "source": "--remote-python"}


def test_dependency_check_runs_with_selected_interpreter_and_reports_reason(rec, tmp_path, monkeypatch):
    seen = []

    def fake(rec_, test_id, argv, timeout=30):
        seen.append(argv)
        if argv[1:3] == ["-c", "import flask,requests,yaml,PIL,rich,textual"]:
            return 1, _done(argv, 1, stderr="ModuleNotFoundError: No module named 'textual'")
        return 0, _done(argv)

    monkeypatch.setattr(remote, "command", fake)
    monkeypatch.setattr(remote.shutil, "which", lambda name: None)
    python = {"path": "/opt/azazel-edge/venv/bin/python", "source": "default: runtime venv"}
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    remote.prepare(rec, repo, False, python)
    pythons = {argv[0] for argv in seen if argv[0] != "git"}
    assert pythons == {"/opt/azazel-edge/venv/bin/python"}
    ends = _ends(rec)
    assert ends["prepare.dependencies"]["status"] == "failed"
    assert "textual" in ends["prepare.dependencies"]["detail"]["reason"]
    assert ends["prepare.dependencies"]["detail"]["python"] == python
    assert "prepare.dependencies" in ends["prepare.gate"]["detail"]["reason"]


def test_laptop_passes_remote_python_quoted(monkeypatch, tmp_path):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, '{"session": "s"}\n', "")

    monkeypatch.setattr(hil.subprocess, "run", fake_run)
    args = hil.parser().parse_args(["--target", "pi", "--session", "r0-x", "--remote-python", "/opt/azazel-edge/venv/bin/python",
                                    "--remote-repo", "~/my repo", "prepare"])
    hil.remote_call(args, "prepare", [])
    ssh_cmd, scp_cmd, run_cmd = calls
    assert scp_cmd[0] == "scp" and "BatchMode=yes" in scp_cmd and "StrictHostKeyChecking=yes" in scp_cmd
    assert run_cmd[-2:] == ["--python", "/opt/azazel-edge/venv/bin/python"]
    assert "'~/my repo'" in run_cmd


# 2. full reports why it stopped, still collects, and keeps the session ID

def test_full_failure_prints_session_stage_reason_and_collects(monkeypatch, capsys):
    summary = {"session": "r0-x", "tests": {"prepare.repository": {"status": "passed", "reason": ""},
                                            "prepare.gate": {"status": "failed", "reason": "R0 start gate blocked by: prepare.dependencies"}}}

    def fake_remote_call(args, action, extra):
        code = 2 if action == "prepare" else 0
        return subprocess.CompletedProcess([], code, json.dumps(summary) + "\n", "")

    collected = {}
    monkeypatch.setattr(hil, "remote_call", fake_remote_call)
    monkeypatch.setattr(hil, "collect", lambda args, stopped=None: collected.setdefault("stopped", stopped) and 0)
    code = hil.main(["--target", "pi", "--session", "r0-x", "full"])
    err = capsys.readouterr().err
    assert code == 2
    assert "r0-x" in err and "stage prepare" in err and "prepare.gate: R0 start gate blocked" in err
    assert collected["stopped"]["stage"] == "prepare"


def test_full_ssh_failure_shows_openssh_error(monkeypatch, capsys):
    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 255, "", "Host key verification failed.\n")

    monkeypatch.setattr(hil.subprocess, "run", fake_run)
    code = hil.main(["--target", "pi", "--session", "r0-y", "full"])
    err = capsys.readouterr().err
    assert code == 255
    assert "stopped at stage preflight" in err and "Host key verification failed." in err and "r0-y" in err


def test_remote_prepare_exits_nonzero_with_summary_when_gate_blocked(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    code = remote.main(["prepare", "--session", "r0-z", "--repo", str(tmp_path / "missing"), "--python", "python3", "--no-update-repo"])
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert code == 2
    assert out["python"] == {"path": "python3", "source": "--remote-python"}
    assert out["tests"]["prepare.repository"]["status"] == "failed"
    assert "not a Git checkout" in out["tests"]["prepare.repository"]["reason"]


def test_report_marks_incomplete_unobserved_and_versions(tmp_path):
    raw = tmp_path / "r0-test"
    raw.mkdir()
    provenance = {"repo": "/home/pi/Azazel-Edge", "git_sha": "abc123", "remote_python": {"path": "/opt/azazel-edge/venv/bin/python", "source": "default: runtime venv"},
                  "runtime": {"root": "/opt/azazel-edge", "git_sha": "unsupported: runtime is an installer copy without Git metadata",
                              "identity": "differs from checkout", "checkout_comparison": {"compared": 2, "identical": 1, "different": ["a.py"], "missing": []}}}
    (raw / "events.jsonl").write_text("\n".join((
        json.dumps({"kind": "provenance", "data": provenance}),
        json.dumps({"kind": "test_end", "test_id": "postconditions.tc_nft_read_only", "status": "unobserved", "exit_code": 0, "detail": {"reason": "not observed"}}),
        json.dumps({"kind": "test_end", "test_id": "prepare.gate", "status": "failed", "exit_code": 2, "detail": {"reason": "blocked"}}),
    )) + "\n")
    summary = hil.write_report(raw, tmp_path / "out.md", {"stage": "prepare", "reason": "gate blocked"})
    body = (tmp_path / "out.md").read_text()
    assert summary["unobserved"] == 1 and summary["failed"] == 1 and summary["passed"] == 0
    assert "INCOMPLETE: stopped at stage `prepare`" in body
    assert "`/home/pi/Azazel-Edge` at `abc123`" in body
    assert "installer copy without Git metadata" in body and "different: a.py" in body
    assert "/opt/azazel-edge/venv/bin/python" in body


# 3. Ollama is observed through the loopback HTTP API, never pulled

class _FakeOllama(BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    bodies: list[dict] = []

    def log_message(self, *args):  # noqa: D401 - silence
        pass

    def _send(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.requests.append(("GET", self.path))
        self._send({"/api/version": {"version": "0.9.0"}, "/api/tags": {"models": [{"name": "qwen3.5:0.8b"}]},
                    "/api/ps": {"models": []}}.get(self.path, {}))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length))
        self.bodies.append(payload)
        self.requests.append(("POST", self.path))
        self._send({"response": "OK", "eval_count": 2, "model": payload["model"]})


@pytest.fixture()
def fake_ollama(monkeypatch):
    _FakeOllama.requests = []
    _FakeOllama.bodies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOllama)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(remote, "OLLAMA_API", f"http://127.0.0.1:{server.server_address[1]}")
    yield _FakeOllama.requests
    server.shutdown()
    server.server_close()


def test_ollama_profile_uses_http_api_and_skips_missing_model_without_pull(rec, fake_ollama, monkeypatch):
    monkeypatch.setattr(remote.shutil, "which", lambda name: None)  # no host CLI, as on the Pi
    for model in remote.MODELS:
        remote.profile_model(rec, model)
    ends = _ends(rec)
    assert ends["profile.qwen3.5:0.8b"]["status"] == "passed"
    assert ends["profile.qwen3.5:0.8b"]["detail"]["response_tail"] == "OK"
    assert ends["profile.qwen3.5:2b"]["status"] == "skipped"
    assert "never pulls" in ends["profile.qwen3.5:2b"]["detail"]["reason"]
    body = _FakeOllama.bodies[0]
    assert body["keep_alive"] == 0 and body["options"]["num_predict"] == 16 == remote.OLLAMA_NUM_PREDICT
    paths = {path for _, path in fake_ollama}
    assert "/api/pull" not in paths and ("POST", "/api/generate") in fake_ollama
    assert all(method == "GET" or path == "/api/generate" for method, path in fake_ollama)


def test_ollama_unreachable_is_skipped_with_reason(rec, monkeypatch):
    monkeypatch.setattr(remote, "OLLAMA_API", "http://127.0.0.1:9")
    remote.profile_model(rec, "qwen3.5:0.8b")
    detail = _ends(rec)["profile.qwen3.5:0.8b"]["detail"]
    assert _ends(rec)["profile.qwen3.5:0.8b"]["status"] == "skipped"
    assert "Ollama API unreachable" in detail["reason"]


# 4. restart and nft failures are failures / unobserved, never passes

def test_restart_uses_sudo_n_and_records_failure(rec, monkeypatch):
    seen = []

    def fake(rec_, test_id, argv, timeout=30):
        seen.append(argv)
        if "restart" in argv:
            return 1, _done(argv, 1, stderr="sudo: a password is required")
        return 3, _done(argv, 3, stdout="inactive\n")

    monkeypatch.setattr(remote, "command", fake)
    remote.reconciliation(rec, ["azazel-edge-core"], True)
    end = _ends(rec)["restart_reconciliation"]
    assert ["sudo", "-n", "systemctl", "restart", "azazel-edge-core"] in seen
    assert end["status"] == "failed" and end["exit_code"] != 0
    assert "password is required" in end["detail"]["reason"]


def test_restart_refuses_non_edge_units_and_requires_flag(rec, monkeypatch):
    seen = []
    monkeypatch.setattr(remote, "command", lambda *a, **k: seen.append(a) or (0, _done([])))
    remote.reconciliation(rec, ["ssh.service"], True)
    assert _ends(rec)["restart_reconciliation"]["status"] == "failed"
    assert seen == []
    rec.events.unlink()
    remote.reconciliation(rec, ["azazel-edge-core"], False)
    end = _ends(rec)["restart_reconciliation"]
    assert end["status"] == "skipped" and "not requested" in end["detail"]["reason"] and seen == []


def test_nft_without_privilege_is_unobserved_not_passed(rec, monkeypatch):
    seen = []

    def fake(rec_, test_id, argv, timeout=30):
        seen.append(argv)
        if "nft" in argv[-3]:
            return 1, _done(argv, 1, stderr="sudo: a password is required")
        return 0, _done(argv, 0, stdout="qdisc noqueue 0: dev lo root refcnt 2\n")

    monkeypatch.setattr(remote, "command", fake)
    monkeypatch.setattr(remote, "find_tool", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(remote.os, "access", lambda path, mode: path == "/usr/sbin/nft")
    remote.postconditions(rec)
    end = _ends(rec)["postconditions.tc_nft_read_only"]
    assert ["sudo", "-n", "/usr/sbin/nft", "list", "ruleset"] in seen
    assert end["status"] == "unobserved"
    assert end["detail"]["nft"]["observed"] is False and end["detail"]["tc"]["observed"] is True
    assert not rec.complete("postconditions.tc_nft_read_only")


# 5. honest git errors and checkout-vs-runtime identity

def test_git_failure_reports_real_error_not_uncommitted(rec, tmp_path, monkeypatch):
    def fake(rec_, test_id, argv, timeout=30):
        return 128, _done(argv, 128, stderr="fatal: detected dubious ownership in repository at '/home/pi/Azazel-Edge'")

    monkeypatch.setattr(remote, "command", fake)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    remote.prepare(rec, repo, False, {"path": "python3", "source": "x"})
    reason = _ends(rec)["prepare.repository"]["detail"]["reason"]
    assert "dubious ownership" in reason and "uncommitted" not in reason


def test_runtime_identity_compares_deployed_files_with_checkout(tmp_path):
    repo, runtime = tmp_path / "repo", tmp_path / "opt"
    for base in (repo, runtime):
        for rel in remote.RUNTIME_SYNC_FILES:
            (base / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / rel).write_text(rel)
    same = remote.runtime_identity(repo, runtime)
    assert same["checkout_comparison"]["identical"] == len(remote.RUNTIME_SYNC_FILES)
    assert same["git_sha"].startswith("unsupported")
    (runtime / remote.RUNTIME_SYNC_FILES[0]).write_text("older")
    changed = remote.runtime_identity(repo, runtime)
    assert changed["checkout_comparison"]["different"] == [remote.RUNTIME_SYNC_FILES[0]]
    assert "not the running runtime" in changed["identity"]
    assert remote.runtime_identity(repo, tmp_path / "absent")["identity"].startswith("unsupported")


def test_full_exits_nonzero_when_collected_report_has_failures(monkeypatch, capsys):
    monkeypatch.setattr(hil, "remote_call", lambda args, action, extra: subprocess.CompletedProcess([], 0, "{}\n", ""))
    monkeypatch.setattr(hil, "collect_summary", lambda args, stopped=None: (0, {"failed": 1, "outcome": "failed"}))
    assert hil.main(["--target", "pi", "--session", "r0-f", "full"]) == hil.EXIT_FAILED == 1
    assert "1 test(s) failed" in capsys.readouterr().err
    monkeypatch.setattr(hil, "collect_summary", lambda args, stopped=None: (0, {"failed": 0, "unobserved": 1, "outcome": "incomplete", "missing": []}))
    assert hil.main(["--target", "pi", "--session", "r0-f", "full"]) == hil.EXIT_INCOMPLETE == 3
    monkeypatch.setattr(hil, "collect_summary", lambda args, stopped=None: (0, {"failed": 0, "outcome": "completed"}))
    assert hil.main(["--target", "pi", "--session", "r0-f", "full"]) == 0


# Review follow-ups

def _full_events(raw, rows):
    raw.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps({"kind": "provenance", "data": {}})]
    lines += [json.dumps({"kind": "test_end", "test_id": test_id, "status": status, "exit_code": 0, "detail": {}}) for test_id, status in rows]
    (raw / "events.jsonl").write_text("\n".join(lines) + "\n")


def test_outcome_incomplete_on_unobserved_missing_or_empty(tmp_path):
    every = [(test_id, "passed") for test_id in hil.REQUIRED_TESTS]
    _full_events(tmp_path / "ok", every)
    assert hil.write_report(tmp_path / "ok", tmp_path / "ok.md")["outcome"] == "completed"
    _full_events(tmp_path / "unobs", every[:-1] + [("postconditions.tc_nft_read_only", "unobserved")])
    result = hil.write_report(tmp_path / "unobs", tmp_path / "unobs.md")
    assert result["outcome"] == "incomplete" and "INCOMPLETE" in (tmp_path / "unobs.md").read_text()
    _full_events(tmp_path / "missing", every[:-2])
    result = hil.write_report(tmp_path / "missing", tmp_path / "missing.md")
    assert result["outcome"] == "incomplete" and "restart_reconciliation" in result["missing"]
    (tmp_path / "empty").mkdir()
    result = hil.write_report(tmp_path / "empty", tmp_path / "empty.md")
    assert result["outcome"] == "incomplete" and "no events" in (tmp_path / "empty.md").read_text()
    _full_events(tmp_path / "bad", every[:-1] + [("postconditions.tc_nft_read_only", "failed")])
    assert hil.write_report(tmp_path / "bad", tmp_path / "bad.md")["outcome"] == "failed"


def test_restart_exit_zero_but_not_active_is_failed(rec, monkeypatch):
    clock = iter(range(0, 1000, 5))
    monkeypatch.setattr(remote.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(remote.time, "sleep", lambda seconds: None)
    states = []

    def fake(rec_, test_id, argv, timeout=30):
        if "restart" in argv:
            return 0, _done(argv)
        states.append(argv)
        return 3, _done(argv, 3, stdout="activating\n")

    monkeypatch.setattr(remote, "command", fake)
    remote.reconciliation(rec, ["azazel-edge-core"], True)
    end = _ends(rec)["restart_reconciliation"]
    assert end["status"] == "failed" and "not active" in end["detail"]["reason"]
    assert 1 <= len(states) <= remote.RESTART_SETTLE_SECONDS + 1


def test_restart_passes_once_unit_becomes_active(rec, monkeypatch):
    monkeypatch.setattr(remote.time, "sleep", lambda seconds: None)
    answers = iter(["activating", "active"])

    def fake(rec_, test_id, argv, timeout=30):
        if "restart" in argv:
            return 0, _done(argv)
        state = next(answers)
        return (0 if state == "active" else 3), _done(argv, stdout=state + "\n")

    monkeypatch.setattr(remote, "command", fake)
    remote.reconciliation(rec, ["azazel-edge-core.service"], True)
    end = _ends(rec)["restart_reconciliation"]
    assert end["status"] == "passed" and end["detail"]["services"]["azazel-edge-core.service"]["active_after"] == "active"


@pytest.mark.parametrize("name", ["azazel-edge-core;reboot", "../azazel-edge-core", "azazel-edge-x/../ssh", "azazel-edge-core@1",
                                  "azazel-edge-core.timer", "azazel-edge-core\n", "azazel-edge-core\nssh", "azazel-edge-core.service.service",
                                  "azazel-edge-", "ssh.service", "azazel-edge-Core"])
def test_service_name_must_fully_match(name):
    assert remote.SERVICE_RE.fullmatch(name) is None


@pytest.mark.parametrize("name", ["azazel-edge-core", "azazel-edge-control-daemon.service", "azazel-edge-web"])
def test_service_name_accepts_edge_units(name):
    assert remote.SERVICE_RE.fullmatch(name)


@pytest.mark.parametrize("module", [hil, remote])
def test_redaction_handles_truncated_pem_and_url_credentials(module):
    head_only = "log\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA"
    tail_only = "AAAAC3NzaC1lZDI1NTE5\n-----END OPENSSH PRIVATE KEY-----\nafter"
    assert "b3BlbnNzaC1rZXktdjEAAAA" not in module.redact(head_only) and "log" in module.redact(head_only)
    assert "AAAAC3NzaC1lZDI1NTE5" not in module.redact(tail_only) and "after" in module.redact(tail_only)
    cleaned = module.redact("fetch https://edge:s3cr3t@github.com/x.git and http://u:p@127.0.0.1:8080/")
    assert "s3cr3t" not in cleaned and "u:p@" not in cleaned and "github.com/x.git" in cleaned


def test_remote_redacts_before_truncating_command_output(rec, monkeypatch):
    secret = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "K" * 20000 + "\n-----END OPENSSH PRIVATE KEY-----\n"
    monkeypatch.setattr(remote.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, secret, ""))
    _, out = remote.command(rec, "t", ["x"])
    assert "K" * 50 not in out["stdout"] and "K" * 50 not in rec.events.read_text()
    assert remote.tail("token https://a:b@h/ " + "x" * 10, 1000).count("a:b") == 0


def test_ollama_bounds_and_proxy_bypass(monkeypatch):
    seen = {}

    class Opener:
        def open(self, request, timeout):
            seen["timeout"] = timeout
            seen["body"] = json.loads(request.data)
            raise remote.urllib.error.URLError("refused")

    monkeypatch.setattr(remote, "_loopback_opener", Opener)
    monkeypatch.setenv("http_proxy", "http://proxy.invalid:3128")
    code, out = remote.ollama_generate("qwen3.5:0.8b", timeout=10_000)
    assert code == 1 and seen["timeout"] == remote.OLLAMA_GENERATE_TIMEOUT == 180
    assert seen["body"]["options"]["num_predict"] == 16 and seen["body"]["keep_alive"] == 0


def test_ollama_ignores_environment_proxy(rec, fake_ollama, monkeypatch):
    # A proxy that refuses connections: the loopback measurement must not be routed through it.
    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    inventory = remote.ollama_inventory()
    assert inventory["reachable"] is True and inventory["models"] == ["qwen3.5:0.8b"]


def test_nft_runs_only_from_fixed_path(rec, monkeypatch):
    seen = []
    monkeypatch.setattr(remote, "command", lambda rec_, test_id, argv, timeout=30: seen.append(argv) or (0, _done(argv)))
    monkeypatch.setattr(remote, "find_tool", lambda name: "/opt/evil/" + name)
    monkeypatch.setattr(remote.os, "access", lambda path, mode: path == "/sbin/nft")
    remote.postconditions(rec)
    assert ["sudo", "-n", "/sbin/nft", "list", "ruleset"] in seen
    monkeypatch.setattr(remote.os, "access", lambda path, mode: False)
    rec.events.unlink()
    remote.postconditions(rec)
    assert _ends(rec)["postconditions.tc_nft_read_only"]["detail"]["nft"]["reason"] == "not installed"


@pytest.mark.parametrize("session", ["..", "a/../b", "../x", "a/b", "-x", ".", "a b", "a;b", "a..b"])
def test_session_ids_are_validated_on_both_sides(session, capsys):
    with pytest.raises(SystemExit):
        hil.parser().parse_args(["--target", "pi", "--session", session, "collect"])
    with pytest.raises(SystemExit):
        remote.main(["doctor", "--session", session])
    assert hil.valid_session("r0-20260829T010000Z-a1b2c3")


@pytest.mark.parametrize("flag", ["--target", "--user"])
def test_target_and_user_cannot_be_options(flag, monkeypatch):
    argv = ["--target", "pi", "--session", "r0-x", "preflight"]
    argv = [flag, "-oProxyCommand=x"] + [a for i, a in enumerate(argv) if not (flag == "--target" and i < 2)]
    with pytest.raises(SystemExit):
        hil.parser().parse_args(argv)
    calls = []
    monkeypatch.setattr(hil.subprocess, "run", lambda a, **k: calls.append(a) or subprocess.CompletedProcess(a, 0, "{}", ""))
    hil.remote_call(hil.parser().parse_args(["--target", "pi", "--session", "r0-x", "preflight"]), "preflight", [])
    assert all("--" in call and call.index("--") < call.index("pi") for call in (calls[0], calls[2]))
    assert calls[1].index("--") < len(calls[1]) - 2


def test_remote_subcommand_exits_nonzero_on_internal_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(remote, "find_tool", lambda name: None)
    monkeypatch.setattr(remote.shutil, "which", lambda name: None)
    assert remote.main(["bootstrap", "--session", "r0-b"]) == 1
    assert json.loads(capsys.readouterr().out)["tests"]["bootstrap.dependencies"]["status"] == "failed"


def test_collect_removes_stale_report_for_the_session(tmp_path, monkeypatch):
    output = tmp_path / "out"
    stale = output / "r0-s" / "CHATGPT_PASTE.md"
    stale.parent.mkdir(parents=True)
    stale.write_text("old run")
    (output / "r0-s" / "raw" / "r0-s").mkdir(parents=True)
    (output / "r0-s" / "raw" / "r0-s" / "events.jsonl").write_text("{}\n")
    monkeypatch.setattr(hil.subprocess, "run", lambda a, **k: subprocess.CompletedProcess(a, 255, "", "Connection refused"))
    args = hil.parser().parse_args(["--target", "pi", "--session", "r0-s", "--output", str(output), "collect"])
    assert hil.collect(args) == 255
    assert not stale.exists() and not (output / "r0-s" / "raw" / "r0-s").exists()


# Second review follow-ups

def test_required_skips_are_incomplete_but_opt_in_restart_skip_completes(tmp_path):
    every = [(test_id, "passed") for test_id in hil.REQUIRED_TESTS]
    restart_skipped = [(t, "skipped" if t == "restart_reconciliation" else s) for t, s in every]
    _full_events(tmp_path / "optin", restart_skipped)
    assert hil.write_report(tmp_path / "optin", tmp_path / "optin.md")["outcome"] == "completed"
    model_skipped = [(t, "skipped" if t in ("profile.qwen3.5:2b", "restart_reconciliation") else s) for t, s in every]
    _full_events(tmp_path / "model", model_skipped)
    result = hil.write_report(tmp_path / "model", tmp_path / "model.md")
    assert result["outcome"] == "incomplete" and result["required_skipped"] == ["profile.qwen3.5:2b"]
    assert "required tests skipped: profile.qwen3.5:2b" in (tmp_path / "model.md").read_text()


def test_full_returns_incomplete_for_required_skip(monkeypatch, capsys):
    monkeypatch.setattr(hil, "remote_call", lambda args, action, extra: subprocess.CompletedProcess([], 0, "{}\n", ""))
    monkeypatch.setattr(hil, "collect_summary", lambda args, stopped=None: (0, {"failed": 0, "unobserved": 0, "outcome": "incomplete",
                                                                                 "missing": [], "required_skipped": ["profile.qwen3.5:2b"]}))
    assert hil.main(["--target", "pi", "--session", "r0-s", "full"]) == hil.EXIT_INCOMPLETE
    assert "profile.qwen3.5:2b" in capsys.readouterr().err


@pytest.mark.parametrize("scp_code, expected", [(1, hil.EXIT_STOPPED), (2, hil.EXIT_STOPPED), (255, 255)])
def test_collect_failure_exit_codes(tmp_path, monkeypatch, scp_code, expected):
    monkeypatch.setattr(hil.subprocess, "run", lambda a, **k: subprocess.CompletedProcess(a, scp_code, "", "scp: no such file"))
    args = hil.parser().parse_args(["--target", "pi", "--session", "r0-c", "--output", str(tmp_path), "collect"])
    assert hil.main(["--target", "pi", "--session", "r0-c", "--output", str(tmp_path), "collect"]) == expected
    assert hil.collect(args) == expected


def test_full_collect_failure_after_successful_stages_is_stopped(tmp_path, monkeypatch):
    monkeypatch.setattr(hil, "remote_call", lambda args, action, extra: subprocess.CompletedProcess([], 0, "{}\n", ""))
    monkeypatch.setattr(hil.subprocess, "run", lambda a, **k: subprocess.CompletedProcess(a, 1, "", "scp: remote path missing"))
    assert hil.main(["--target", "pi", "--session", "r0-c", "--output", str(tmp_path), "full"]) == hil.EXIT_STOPPED


@pytest.mark.parametrize("module", [hil, remote])
def test_redaction_user_only_at_in_password_and_key_value_forms(module):
    cleaned = module.redact("https://deploy@github.com/x.git ssh://u:p@ss@w0rd@host/y and http://h/a@b")
    assert "deploy@" not in cleaned and "p@ss" not in cleaned and "w0rd" not in cleaned
    assert "github.com/x.git" in cleaned and "host/y" in cleaned and "http://h/a@b" in cleaned
    yaml_like = "password: hunter2 two\napi_key: abc123\nsecret_token:   zzz\nname: edge"
    cleaned = module.redact(yaml_like)
    assert "hunter2" not in cleaned and "abc123" not in cleaned and "zzz" not in cleaned and "name: edge" in cleaned
    as_json = json.dumps({"outer": "{\"password\": \"pa\\\"ss\", \"token\": 12345, \"authorization\": \"Basic QQ==\", \"user\": \"ok\"}"})
    cleaned = module.redact(json.loads(as_json)["outer"])
    assert "pa" not in cleaned.replace("password", "") and "12345" not in cleaned and "QQ==" not in cleaned and '"user": "ok"' in cleaned
    assert module.redact('{"client_secret":"s3"}') == '{"client_secret":"[REDACTED]"}'


def test_reconciliation_rejects_newline_suffixed_unit_without_running(rec, monkeypatch):
    seen = []
    monkeypatch.setattr(remote, "command", lambda *a, **k: seen.append(a) or (0, _done([])))
    remote.reconciliation(rec, ["azazel-edge-core\n"], True)
    end = _ends(rec)["restart_reconciliation"]
    assert end["status"] == "failed" and "non-Edge" in end["detail"]["reason"] and seen == []


@pytest.mark.parametrize("argv", [["--target=-oProxyCommand=x"], ["--target", "pi", "--user=-oProxyCommand=x"]])
def test_equals_form_option_injection_is_rejected(argv, capsys):
    with pytest.raises(SystemExit):
        hil.main(argv + ["--session", "r0-x", "preflight"])
    assert "must not be empty or start with '-'" in capsys.readouterr().err


@pytest.mark.parametrize("remote_code", [2, 3, 5, 127])
def test_stopped_stage_always_exits_2(monkeypatch, remote_code):
    monkeypatch.setattr(hil, "remote_call", lambda args, action, extra: subprocess.CompletedProcess([], remote_code, "", "boom"))
    monkeypatch.setattr(hil, "collect", lambda args, stopped=None: 0)
    assert hil.main(["--target", "pi", "--session", "r0-x", "full"]) == hil.EXIT_STOPPED == 2


def test_remote_stage_ssh_255_raises_redacted_remote_error(monkeypatch):
    answers = iter([0, 0, 255])

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, next(answers), "", "Authorization: Bearer leaked.tok\nssh: connection to https://u:pw@h reset\n")

    monkeypatch.setattr(hil.subprocess, "run", fake_run)
    args = hil.parser().parse_args(["--target", "pi", "--session", "r0-x", "run"])
    with pytest.raises(hil.RemoteError) as caught:
        hil.remote_call(args, "run", [])
    assert caught.value.returncode == 255 and "remote run" in caught.value.step
    assert "leaked.tok" not in str(caught.value) and "pw@" not in str(caught.value) and "connection to" in str(caught.value)


def test_allow_restart_without_service_stops_with_2_on_both_sides(tmp_path, monkeypatch, capsys):
    called = []
    monkeypatch.setattr(hil, "remote_call", lambda *a: called.append(a))
    assert hil.main(["--target", "pi", "--session", "r0-x", "full", "--allow-service-restart"]) == 2
    assert hil.main(["--target", "pi", "--session", "r0-x", "run", "--allow-service-restart"]) == 2
    assert called == []
    monkeypatch.setenv("HOME", str(tmp_path))
    rec = remote.Recorder("r0-x")
    rec.emit("test_end", test_id="prepare.gate", status="passed", exit_code=0, detail={})
    ran = []
    monkeypatch.setattr(remote, "profile_model", lambda *a: ran.append(a))
    assert remote.main(["run", "--session", "r0-x", "--allow-service-restart"]) == 2
    assert ran == []


def test_service_without_allow_warns_and_restarts_nothing(rec, monkeypatch, capsys):
    monkeypatch.setattr(hil, "remote_call", lambda args, action, extra: subprocess.CompletedProcess([], 0, "{}\n", "") if "--service" not in extra else pytest.fail("forwarded"))
    hil.main(["--target", "pi", "--session", "r0-x", "run", "--service", "azazel-edge-core"])
    assert "--service ignored without --allow-service-restart" in capsys.readouterr().err
    seen = []
    monkeypatch.setattr(remote, "command", lambda *a, **k: seen.append(a) or (0, _done([])))
    remote.reconciliation(rec, ["azazel-edge-core"], False)
    end = _ends(rec)["restart_reconciliation"]
    assert end["status"] == "skipped" and "ignored without --allow-service-restart" in end["detail"]["reason"] and seen == []


def test_report_counts_only_event_logs_not_state_files(tmp_path):
    raw = tmp_path / "r0-n"
    _full_events(raw, [("prepare.gate", "passed")])
    (raw / "reconciliation.jsonl").write_text('{"sequence":2}\n{"sequence":1}\n')
    (raw / "observer").mkdir()
    (raw / "observer" / "outcome.jsonl").write_text('{"kind": "test_end", "test_id": "fake", "status": "failed"}\n')
    result = hil.write_report(raw, tmp_path / "n.md")
    assert result["events"] == 2 and result["failed"] == 0 and "fake" not in (tmp_path / "n.md").read_text()


# Final review: linear-time redaction and remaining forms

_HOSTILE = ["a-", "a", " ", "\n", "a@", "a:", "x://", "x://a@", "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----",
            "password", "password:", "password=", "--password ", "\"password\":", "'token': '", "bearer ", "authorization: ",
            "a.b-c_", "[", "\"", "\\", "a=", "a:b ", "[REDACTED]@", "\"password\": \"", "\"password\": \"\\", "password:\n",
            "-u a:", "--token \"", "a" * 300 + ":", "a" * 300 + " ", "x://" + "a" * 50, "'token': '"]


@pytest.mark.parametrize("module", [hil, remote])
@pytest.mark.parametrize("size", [100_000, 1_000_000])
def test_redaction_is_linear_on_hostile_input(module, size):
    import time as _time
    for unit in _HOSTILE:
        text = (unit * (size // len(unit) + 1))[:size]
        started = _time.perf_counter()
        module.redact(text)
        elapsed = _time.perf_counter() - started
        assert elapsed < 5.0, (unit, size, elapsed)


@pytest.mark.parametrize("module", [hil, remote])
def test_redaction_nits_query_arrays_repr_and_flags(module):
    assert module.redact("https://example.com?x=a@b") == "https://example.com?x=a@b"
    assert module.redact("https://example.com/p#frag@x") == "https://example.com/p#frag@x"
    assert module.redact("https://u:p@h/") == "https://[REDACTED]@h/"
    assert module.redact('{"tokens": ["a", "b"], "n": 1}') == '{"tokens": "[REDACTED]", "n": 1}'
    assert module.redact("{'password': 'x', 'user': 'ok'}") == "{'password': '[REDACTED]', 'user': 'ok'}"
    assert "hunter2" not in module.redact("password = hunter2")
    flagged = module.redact("tool --password hunter2 --verbose --api-key=abc")
    assert "hunter2" not in flagged and "abc" not in flagged and "--verbose" in flagged
    assert "s3" not in module.redact("DB_PASSWORD=s3")



# Bounds must never leave part of a secret behind

@pytest.mark.parametrize("module", [hil, remote])
@pytest.mark.parametrize("length", [5000, 20000])
def test_long_secret_values_are_fully_redacted(module, length):
    secret = "Z" * length
    for text in (f"password: {secret}", f"PASSWORD={secret}", f"--token {secret}", f'{{"password": "{secret}"}}',
                 f"{{'secret': '{secret}'}}", f"Authorization: Basic {secret}", f"Bearer {secret}", f'--token "{secret} tail"'):
        cleaned = module.redact(text)
        assert "ZZ" not in cleaned, text[:40]


@pytest.mark.parametrize("module", [hil, remote])
def test_escaped_json_string_longer_than_old_bound_is_fully_redacted(module):
    value = ('ab\\"cd\\\\' * 600)[:4097]
    if value.endswith("\\") and not value.endswith("\\\\"):
        value = value[:-1] + "x"
    document = '{"password": "' + value + '", "user": "ok"}'
    cleaned = module.redact(document)
    assert cleaned == '{"password": "[REDACTED]", "user": "ok"}'


@pytest.mark.parametrize("module", [hil, remote])
def test_long_and_double_at_url_userinfo(module):
    userinfo = "u" * 500 + ":" + "p" * 499
    assert module.redact(f"https://{userinfo}@host/x") == "https://[REDACTED]@host/x"
    assert module.redact("https://user:p@ss@host/x") == "https://[REDACTED]@host/x"


@pytest.mark.parametrize("module", [hil, remote])
def test_seventy_character_key_prefix_and_suffix(module):
    prefix, suffix = "p" * 70, "s" * 70
    assert "hunter2" not in module.redact(f"{prefix}_password_{suffix}: hunter2")
    assert "hunter2" not in module.redact(f'{{"{prefix}_token": "hunter2"}}')
    assert "hunter2" not in module.redact(f"--{prefix}-secret hunter2")


@pytest.mark.parametrize("module", [hil, remote])
def test_newline_value_curl_user_and_quoted_flag(module):
    assert "hunter2" not in module.redact("password:\n  hunter2\n")
    cleaned = module.redact("curl -u bob:pw1 https://h/ && wget --user=alice:pw2 x")
    assert "pw1" not in cleaned and "pw2" not in cleaned and "bob:" in cleaned
    cleaned = module.redact('tool --token "a b" --verbose')
    assert "a b" not in cleaned and "--verbose" in cleaned
