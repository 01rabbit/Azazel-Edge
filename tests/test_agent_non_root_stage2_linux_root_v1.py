"""Edge#471 stage 2 with a real non-root agent process (Linux, root only).

The agent unit's ExecStart script runs as an unprivileged uid (no account
needed) with its directories prepared as tmpfiles.d / systemd would: the core
(root, this test) still reaches ai-bridge.sock, a P0 decision reaches the
audit chain and the P0 queue written by that uid, and the agent refuses the
shared runtime directory instead of writing or chmod'ing it. A container or
a CI runner is not a device.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not (sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs root on Linux (runs the agent as another uid)",
)

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from azazel_edge.service_objectives import so03_alert_queue  # noqa: E402

UNIT = ROOT / "systemd" / "azazel-edge-ai-agent.service"
FIXTURE = ROOT / "tests" / "fixtures" / "rust_core_event_v1.json"
AGENT_UID = 61020
WEB_GID = 61021


def _wait(pred, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.05)
    return bool(pred())


def _accepting(path: Path) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(path))
        return True
    except OSError:
        return False


def _rows(path: Path) -> list:
    try:
        return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    except FileNotFoundError:
        return []


@pytest.fixture
def layout():
    base = Path(tempfile.mkdtemp(prefix="azs2"))
    os.chmod(base, 0o755)
    dirs = {
        "ai": (base / "run-ai", AGENT_UID, AGENT_UID, 0o700),          # RuntimeDirectory=
        "run": (base / "run-agent", AGENT_UID, WEB_GID, 0o2750),       # tmpfiles.d
        "query": (base / "run-query", AGENT_UID, WEB_GID, 0o2750),     # tmpfiles.d
        "log": (base / "log-ai", AGENT_UID, WEB_GID, 0o2750),          # tmpfiles.d
        "state": (base / "state", AGENT_UID, AGENT_UID, 0o750),        # StateDirectory=
    }
    for path, uid, gid, mode in dirs.values():
        path.mkdir()
        os.chown(path, uid, gid)
        os.chmod(path, mode)
    try:
        yield base, {k: v[0] for k, v in dirs.items()}
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _env(base: Path, d: dict) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AZAZEL_")}
    env.update(so03_alert_queue.agent_environment(base / "unused"))
    env.update({
        "AZAZEL_AI_SOCKET": str(d["ai"] / "ai-bridge.sock"),
        "AZAZEL_AI_QUERY_SOCKET": str(d["query"] / "agent-query.sock"),
        "AZAZEL_AI_ADVISORY": str(d["run"] / "ai_advisory.json"),
        "AZAZEL_AI_METRICS": str(d["run"] / "ai_metrics.json"),
        "AZAZEL_AI_POLICY": str(d["run"] / "ai_runtime_policy.json"),
        "AZAZEL_AI_EVENT_LOG": str(d["log"] / "ai-events.jsonl"),
        "AZAZEL_AI_LLM_LOG": str(d["log"] / "ai-llm.jsonl"),
        "AZAZEL_AI_DEFERRED_LOG": str(d["log"] / "ai-deferred.jsonl"),
        "AZAZEL_AI_AUDIT_LOG": str(d["log"] / "ai-audit.jsonl"),
        "AZAZEL_DECISION_LOG_DIR": str(d["state"] / "decisions"),
        "AZAZEL_NORMALIZED_EVENT_LOG": str(base / "normalized-events.jsonl"),
        "HOME": "/nonexistent",
    })
    env.pop("AZAZEL_UI_SNAPSHOT", None)
    return env


def _start(base: Path, env: dict) -> subprocess.Popen:
    script = so03_alert_queue.agent_service_script(UNIT)
    try:
        probe = subprocess.run([sys.executable, "-c", "pass"], capture_output=True, text=True,
                               preexec_fn=lambda: (os.setgroups([]), os.setgid(AGENT_UID), os.setuid(AGENT_UID)))
        problem = probe.stderr[-300:] if probe.returncode != 0 else ""
    except OSError as exc:
        problem = str(exc)
    if problem:
        pytest.fail(f"uid {AGENT_UID} cannot run {sys.executable} (search permission on its path?): {problem}")

    def drop():
        os.setgroups([])
        os.setgid(AGENT_UID)
        os.setuid(AGENT_UID)
        os.umask(0o027)  # the unit's UMask=

    err = (base / "agent.stderr").open("w", encoding="utf-8")
    return subprocess.Popen([sys.executable, str(script)], env=env, cwd="/", stdout=subprocess.DEVNULL,
                            stderr=err, preexec_fn=drop)


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def test_the_agent_runs_as_its_own_uid_and_root_still_reaches_it(layout):
    base, d = layout
    proc = _start(base, _env(base, d))
    sock = d["ai"] / "ai-bridge.sock"
    try:
        assert _wait(lambda: _accepting(sock) or proc.poll() is not None)
        assert proc.poll() is None, (base / "agent.stderr").read_text(encoding="utf-8")
        st = os.lstat(sock)
        assert (st.st_uid, stat.S_IMODE(st.st_mode)) == (AGENT_UID, 0o600)
        event = json.loads(FIXTURE.read_text(encoding="utf-8"))
        event["defense"]["action"] = "isolate"
        event["enforcement"]["selected_action"] = "isolate"
        event["enforcement"]["mode"] = "dry_run"
        event["normalized"]["sid"] = 9471001
        from datetime import datetime, timezone
        event["normalized"]["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:  # as the core: root
            conn.connect(str(sock))
            conn.sendall((json.dumps(event) + "\n").encode("utf-8"))
        chain, queue = d["log"] / "core-decision-audit.jsonl", d["log"] / "p0-alert-queue.jsonl"
        assert _wait(lambda: any(r.get("record_type") == "alert" for r in _rows(queue)))
        assert [r["sid"] for r in _rows(chain)] == [9471001]
        for path in (chain, queue, d["run"] / "ai_metrics.json", d["log"] / "ai-events.jsonl"):
            st = os.lstat(path)
            assert st.st_uid == AGENT_UID, path
            assert not stat.S_IMODE(st.st_mode) & 0o007, path  # nothing for others
        # Readable by the Web UI's group through the setgid directories.
        assert os.lstat(d["run"] / "ai_metrics.json").st_gid == WEB_GID
        assert os.lstat(d["log"] / "ai-events.jsonl").st_gid == WEB_GID
        # The agent's snapshot fields are in its own file only.
        assert _wait(lambda: (d["run"] / "ai_snapshot.json").exists())
        # Edge#477: the v2 explanation of the core's decision, written by the
        # agent's uid, readable by the Web UI's group only (as azazel-web reads it).
        explanations = d["log"] / "decision-explanations.jsonl"
        assert _wait(lambda: bool(_rows(explanations)))
        st = os.lstat(explanations)
        assert (st.st_uid, st.st_gid) == (AGENT_UID, WEB_GID)
        assert stat.S_IMODE(st.st_mode) == 0o640
        row = _rows(explanations)[0]
        assert row["format_version"] == "v2" and row["selected_action"] == "isolate"
        web = subprocess.run(
            [sys.executable, "-I", "-c",
             "import json, sys; sys.path.insert(0, sys.argv[2]);"
             "from azazel_edge.explanations import validate_v2_explanation;"
             "rows = [json.loads(x) for x in open(sys.argv[1], encoding='utf-8') if x.strip()];"
             "print(rows[-1]['trace_id'], validate_v2_explanation(rows[-1]))",
             str(explanations), str(ROOT / "py")],
            capture_output=True, text=True, cwd="/",
            preexec_fn=lambda: (os.setgroups([]), os.setgid(WEB_GID), os.setuid(WEB_GID + 1)),
        )
        assert web.returncode == 0, web.stderr[-500:]
        assert web.stdout.split()[0] == row["trace_id"] and web.stdout.strip().endswith("[]")
        other = subprocess.run(
            [sys.executable, "-I", "-c", "open(__import__('sys').argv[1]).read()", str(explanations)],
            capture_output=True, text=True, cwd="/",
            preexec_fn=lambda: (os.setgroups([]), os.setgid(WEB_GID + 2), os.setuid(WEB_GID + 2)),
        )
        assert other.returncode != 0 and "Permission denied" in other.stderr
    finally:
        _stop(proc)


def test_the_agent_refuses_a_shared_directory_and_leaves_it_alone(layout):
    base, d = layout
    shared = base / "shared-run"
    shared.mkdir()
    os.chmod(shared, 0o770)  # /run/azazel-edge as the control daemon makes it
    env = _env(base, d)
    env["AZAZEL_AI_ADVISORY"] = str(shared / "ai_advisory.json")
    proc = _start(base, env)
    try:
        assert _wait(lambda: proc.poll() is not None, 20)
        assert proc.returncode not in (0, None)
        err = (base / "agent.stderr").read_text(encoding="utf-8")
        assert "owned by uid 0" in err or "writable" in err, err
        st = os.lstat(shared)
        assert (st.st_uid, stat.S_IMODE(st.st_mode)) == (0, 0o770)
        assert list(shared.iterdir()) == []
        assert not (d["ai"] / "ai-bridge.sock").exists()
    finally:
        _stop(proc)


def test_the_agent_refuses_a_directory_owned_by_another_account(layout):
    """The owner check alone: mode 0750 (nobody else can write) but another
    owner. The agent stops with that reason and changes nothing."""
    base, d = layout
    other = base / "other-run"
    other.mkdir()
    os.chown(other, AGENT_UID + 5, AGENT_UID + 5)
    os.chmod(other, 0o750)
    env = _env(base, d)
    env["AZAZEL_AI_ADVISORY"] = str(other / "ai_advisory.json")
    proc = _start(base, env)
    try:
        assert _wait(lambda: proc.poll() is not None, 20)
        assert proc.returncode not in (0, None)
        err = (base / "agent.stderr").read_text(encoding="utf-8")
        assert f"owned by uid {AGENT_UID + 5}" in err, err
        st = os.lstat(other)
        assert (st.st_uid, stat.S_IMODE(st.st_mode)) == (AGENT_UID + 5, 0o750)
    finally:
        _stop(proc)
