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
        self.requests.append(("POST", self.path))
        self._send({"response": "OK", "eval_count": 2, "model": payload["model"]})


@pytest.fixture()
def fake_ollama(monkeypatch):
    _FakeOllama.requests = []
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
    assert _ends(rec)["restart_reconciliation"]["status"] == "passed" and seen == []


def test_nft_without_privilege_is_unobserved_not_passed(rec, monkeypatch):
    seen = []

    def fake(rec_, test_id, argv, timeout=30):
        seen.append(argv)
        if "nft" in argv[-3]:
            return 1, _done(argv, 1, stderr="sudo: a password is required")
        return 0, _done(argv, 0, stdout="qdisc noqueue 0: dev lo root refcnt 2\n")

    monkeypatch.setattr(remote, "command", fake)
    monkeypatch.setattr(remote, "find_tool", lambda name: f"/usr/sbin/{name}")
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
    monkeypatch.setattr(hil, "collect_summary", lambda args, stopped=None: (0, {"failed": 1}))
    assert hil.main(["--target", "pi", "--session", "r0-f", "full"]) == 1
    assert "1 test(s) failed" in capsys.readouterr().err
    monkeypatch.setattr(hil, "collect_summary", lambda args, stopped=None: (0, {"failed": 0, "unobserved": 1}))
    assert hil.main(["--target", "pi", "--session", "r0-f", "full"]) == 0
