"""ai-bridge.sock is owner only and never takes the shared group (Edge#462).

``AZAZEL_RUNTIME_SOCKET_GROUP`` lets non-root members (Web UI helpers, local
CLI) reach the control daemon's ``control.sock``. It used to be applied to the
AI agent's ``ai-bridge.sock`` as well, so any member could connect and forge
core events. These tests pin that the agent's socket is 0600 with the agent's
own group even when the shared group is set (and even when the old
``AZAZEL_AI_SOCKET_MODE`` asks for more), that the agent leaves the runtime
directory's group as the control daemon set it, that ``control.sock`` keeps
the shared group, and that the root callers (Web UI manual query, core event
forwarding) still reach the agent.
"""

from __future__ import annotations

import grp
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))
sys.path.insert(0, str(ROOT))

from azazel_edge.service_objectives import so03_alert_queue  # noqa: E402
from azazel_edge_ai import agent as agent_mod  # noqa: E402

UNIT = ROOT / "systemd" / "azazel-edge-ai-agent.service"


def _other_group() -> tuple[str, int] | None:
    """A group this process may chown to that is not its own group."""

    own = os.getegid()
    if os.geteuid() == 0:
        for entry in grp.getgrall():
            if entry.gr_gid != own and entry.gr_gid != 0:
                return entry.gr_name, entry.gr_gid
        return None
    for gid in os.getgroups():
        if gid != own:
            try:
                return grp.getgrgid(gid).gr_name, gid
            except KeyError:
                continue
    return None


@pytest.fixture
def shared_group():
    found = _other_group()
    if found is None:
        pytest.skip("no second group this process can chown to")
    return found


@pytest.fixture
def run_dir():
    # Short path: AF_UNIX paths are limited to ~104 bytes on macOS.
    path = Path(tempfile.mkdtemp(prefix="aib"))
    try:
        yield path / "run"
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _wait(pred, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return bool(pred())


def _accepting(sock_path: Path) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(sock_path))
        return True
    except OSError:
        return False


class _AgentProc:
    """The agent unit's ExecStart script with the shared group configured."""

    def __init__(self, run: Path, group: str, **extra: str):
        work = run.parent / "work"
        work.mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ)
        self.env.update(so03_alert_queue.agent_environment(work))
        self.socket = run / "ai-bridge.sock"
        self.env["AZAZEL_AI_SOCKET"] = str(self.socket)
        self.env["AZAZEL_RUNTIME_SOCKET_GROUP"] = group
        self.env.update(extra)
        self.work = work
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "_AgentProc":
        script = so03_alert_queue.agent_service_script(UNIT)
        self.proc = subprocess.Popen([sys.executable, str(script)], env=self.env, cwd=str(self.work),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert _wait(lambda: _accepting(self.socket) or self.proc.poll() is not None), "agent did not start"
        assert self.proc.poll() is None, "agent exited"
        return self

    def __exit__(self, *exc) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)


def _control_daemon(monkeypatch, run: Path, group: str):
    from azazel_edge_control import daemon as control_daemon

    monkeypatch.setattr(control_daemon, "SOCKET_PATH", run / "control.sock")
    monkeypatch.setattr(control_daemon, "RUNTIME_SOCKET_GROUP", group)
    return control_daemon


# ------------------------------------------------------------ the agent alone


def test_the_agent_socket_is_owner_only_by_default():
    assert agent_mod.SOCKET_MODE == 0o600


def test_bind_never_chowns_and_never_grants_group_or_other(monkeypatch, run_dir, shared_group):
    name, gid = shared_group
    monkeypatch.setenv("AZAZEL_RUNTIME_SOCKET_GROUP", name)
    monkeypatch.setenv("AZAZEL_AI_SOCKET_MODE", "0666")
    chowned: list = []
    real_chown = os.chown
    monkeypatch.setattr(os, "chown", lambda *a, **k: (chowned.append(a), real_chown(*a, **k)))
    path = run_dir / "ai-bridge.sock"

    agent_mod._prepare_runtime_socket_dir(path)
    dir_gid = run_dir.stat().st_gid
    srv = agent_mod._bind_ai_socket(path)
    try:
        st = path.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600
        assert st.st_gid == os.getegid() != gid
        assert run_dir.stat().st_gid == dir_gid != gid
        assert all(call[-1] != gid for call in chowned)
        assert all(Path(call[0]) != run_dir for call in chowned)
    finally:
        srv.close()


def test_the_service_ignores_the_shared_group_and_the_old_mode(run_dir, shared_group):
    name, gid = shared_group
    with _AgentProc(run_dir, name, AZAZEL_AI_SOCKET_MODE="0666") as agent:
        st = agent.socket.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600
        assert st.st_gid == os.getegid() != gid
        assert run_dir.stat().st_gid != gid


# ------------------------------------------- next to the control daemon


def test_control_sock_keeps_the_shared_group(monkeypatch, run_dir, shared_group):
    name, gid = shared_group
    daemon = _control_daemon(monkeypatch, run_dir, name)
    sock = daemon.create_listener_socket()
    try:
        st = (run_dir / "control.sock").stat()
        assert st.st_gid == gid
        assert stat.S_IMODE(st.st_mode) == daemon.SOCKET_MODE == 0o660
        assert run_dir.stat().st_gid == gid
        assert stat.S_IMODE(run_dir.stat().st_mode) == daemon.RUNTIME_DIR_MODE
    finally:
        sock.close()


@pytest.mark.parametrize("daemon_first", [True, False])
def test_agent_and_daemon_do_not_fight_over_the_directory(monkeypatch, run_dir, shared_group, daemon_first):
    name, gid = shared_group
    daemon = _control_daemon(monkeypatch, run_dir, name)
    ctl = daemon.create_listener_socket() if daemon_first else None
    try:
        with _AgentProc(run_dir, name) as agent:
            if ctl is None:
                ctl = daemon.create_listener_socket()
            # Either start order: the directory and control.sock carry the
            # shared group, ai-bridge.sock does not.
            assert run_dir.stat().st_gid == gid
            assert stat.S_IMODE(run_dir.stat().st_mode) == daemon.RUNTIME_DIR_MODE
            assert (run_dir / "control.sock").stat().st_gid == gid
            st = agent.socket.stat()
            assert st.st_gid == os.getegid() != gid
            assert stat.S_IMODE(st.st_mode) == 0o600
            assert _accepting(agent.socket)
    finally:
        if ctl is not None:
            ctl.close()


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to act as a group member")
def test_a_group_member_reaches_control_sock_but_not_ai_bridge(monkeypatch, run_dir, shared_group):
    import pwd

    name, gid = shared_group
    try:
        member_uid = pwd.getpwnam("nobody").pw_uid
    except KeyError:
        pytest.skip("no unprivileged account")
    # Only the runtime directory decides: the temporary parent is passable.
    os.chmod(run_dir.parent, 0o711)
    daemon = _control_daemon(monkeypatch, run_dir, name)
    ctl = daemon.create_listener_socket()
    try:
        with _AgentProc(run_dir, name) as agent:
            probe = (
                "import os, socket, sys\n"
                f"os.setgroups([{gid}]); os.setgid({gid}); os.setuid({member_uid})\n"
                "out = []\n"
                "for p in sys.argv[1:]:\n"
                "    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
                "    try:\n"
                "        s.connect(p); out.append('ok')\n"
                "    except PermissionError:\n"
                "        out.append('denied')\n"
                "    finally:\n"
                "        s.close()\n"
                "print(' '.join(out))\n"
            )
            res = subprocess.run([sys.executable, "-I", "-c", probe, str(run_dir / "control.sock"), str(agent.socket)],
                                 capture_output=True, text=True, timeout=30)
            assert res.returncode == 0, res.stderr
            assert res.stdout.split() == ["ok", "denied"]
    finally:
        ctl.close()


# ------------------------------------------------- the legitimate callers


def test_the_web_ui_manual_query_still_reaches_the_agent(monkeypatch, run_dir, shared_group):
    # The Web UI runs as the same account as the agent (root in the units).
    name, _ = shared_group
    from azazel_edge_web import app as web_app

    with _AgentProc(run_dir, name) as agent:
        monkeypatch.setattr(web_app, "AI_SOCKET", agent.socket)
        result = web_app._send_ai_manual_query("What is the current state?")
    assert "ai_query_error" not in str(result.get("error", "")), result
    assert result.get("error") not in {"empty_ai_response", "ai_socket_not_found:" + str(agent.socket)}, result
    assert "ok" in result


def test_core_style_forwarding_still_reaches_the_agent(run_dir, shared_group):
    # As the core delivers: one connection per line, write, close.
    name, _ = shared_group
    with _AgentProc(run_dir, name) as agent:
        event = json.loads((ROOT / "tests" / "fixtures" / "rust_core_event_v1.json").read_text(encoding="utf-8"))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(agent.socket))
            conn.sendall((json.dumps(event) + "\n").encode("utf-8"))
        events_log = Path(agent.env["AZAZEL_AI_EVENT_LOG"])
        assert _wait(lambda: events_log.exists() and events_log.stat().st_size > 0)
