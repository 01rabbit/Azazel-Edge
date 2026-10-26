"""ai-bridge.sock is owner only, in its own private directory (Edge#462).

``AZAZEL_RUNTIME_SOCKET_GROUP`` lets non-root members (Web UI helpers, local
CLI) reach the control daemon's ``control.sock`` in ``/run/azazel-edge``
(0770, shared group, no sticky bit). The AI agent's ``ai-bridge.sock`` used to
live there with the shared group, so a member could connect and forge core
events, or rename it and bind a socket of its own at the path. These tests
pin that the socket now lives in a directory of its own (0700, the agent's
account; default ``/run/azazel-edge-ai``), that the agent refuses a directory
or path it cannot trust, that the socket is 0600 with the agent's own group
even when the shared group (and the old ``AZAZEL_AI_SOCKET_MODE``) is set,
that it is never group/other accessible while being bound, that the agent
leaves the shared runtime directory's group alone and ``control.sock`` keeps
the shared group, and that the root callers (Web UI manual query, core event
forwarding) reach the agent at the new default path.
"""

from __future__ import annotations

import grp
import json
import os
import re
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
CORE_UNIT = ROOT / "systemd" / "azazel-edge-core.service"
INSTALLER = ROOT / "installer" / "internal" / "install_migrated_tools.sh"
DEFAULT_SOCKET = "/run/azazel-edge-ai/ai-bridge.sock"
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


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
def base():
    # Short path: AF_UNIX paths are limited to ~104 bytes on macOS.
    path = Path(tempfile.mkdtemp(prefix="aib"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def run_dir(base):
    """The shared runtime directory (control.sock, the agent's state files)."""
    return base / "run"


def _ai_socket(base: Path) -> Path:
    return base / "ai" / "ai-bridge.sock"


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


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


class _AgentProc:
    """The agent unit's ExecStart script with the shared group configured."""

    def __init__(self, base: Path, group: str, socket_path: Path | None = None, **extra: str):
        work = base / "work"
        work.mkdir(parents=True, exist_ok=True)
        self.env = dict(os.environ)
        self.env.update(so03_alert_queue.agent_environment(work))
        self.socket = socket_path if socket_path is not None else _ai_socket(base)
        if str(self.socket) == DEFAULT_SOCKET:
            self.env.pop("AZAZEL_AI_SOCKET", None)  # the agent's own default
        else:
            self.env["AZAZEL_AI_SOCKET"] = str(self.socket)
        # The agent's state files in its own runtime directory (Edge#471 stage
        # 2: the agent no longer writes in the shared directory).
        self.env["AZAZEL_AI_ADVISORY"] = str(base / "agent" / "ai_advisory.json")
        self.env["AZAZEL_RUNTIME_SOCKET_GROUP"] = group
        self.env.update(extra)
        self.work = work
        self.stderr = work / "agent.stderr"
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "_AgentProc":
        script = so03_alert_queue.agent_service_script(UNIT)
        with self.stderr.open("w", encoding="utf-8") as err:
            self.proc = subprocess.Popen([sys.executable, str(script)], env=self.env, cwd=str(self.work),
                                         stdout=subprocess.DEVNULL, stderr=err)
        assert _wait(lambda: _accepting(self.socket) or self.proc.poll() is not None), "agent did not start"
        assert self.proc.poll() is None, "agent exited: " + self.stderr.read_text(encoding="utf-8", errors="replace")
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


# ------------------------------------------------------------ the defaults


def test_the_socket_and_directory_modes_are_owner_only():
    assert agent_mod.SOCKET_MODE == 0o600
    assert agent_mod.SOCKET_DIR_MODE == 0o700


def test_every_caller_defaults_to_the_private_directory():
    agent_src = (ROOT / "py" / "azazel_edge_ai" / "agent.py").read_text(encoding="utf-8")
    web_src = (ROOT / "azazel_edge_web" / "app.py").read_text(encoding="utf-8")
    core_src = (ROOT / "rust" / "azazel-edge-core" / "src" / "main.rs").read_text(encoding="utf-8")
    assert f'os.environ.get("AZAZEL_AI_SOCKET", "{DEFAULT_SOCKET}")' in agent_src
    # The Web UI does not use ai-bridge.sock any more (Edge#471 stage 1): the
    # same variable defaults to the agent's manual_query socket there.
    assert 'os.environ.get("AZAZEL_AI_SOCKET", "/run/azazel-edge-agent-query/agent-query.sock")' in web_src
    assert f'env::var("AZAZEL_AI_SOCKET").unwrap_or_else(|_| "{DEFAULT_SOCKET}".to_string())' in core_src
    assert so03_alert_queue.unit_environment(CORE_UNIT)["AZAZEL_AI_SOCKET"] == DEFAULT_SOCKET
    assert "AZAZEL_AI_SOCKET" not in so03_alert_queue.unit_environment(UNIT)
    # The socket is not in the shared runtime directory.
    assert Path(DEFAULT_SOCKET).parent != agent_mod.LEGACY_SOCKET_PATH.parent


def _gnu_sed() -> bool:
    if shutil.which("sed") is None:
        return False
    return subprocess.run(["sed", "--version"], capture_output=True).returncode == 0


@pytest.mark.skipif(not _gnu_sed(), reason="needs GNU sed (the installer runs on Linux)")
def test_the_installer_moves_the_old_path_out_of_the_shared_directory(base):
    src = INSTALLER.read_text(encoding="utf-8")
    loop = re.search(r'^for env_file in "\$SECURITY_ENV" "\$WEB_ENV"; do\n.*?^done\n', src, re.S | re.M)
    assert loop, "installer migration loop not found"
    sec, web, custom = base / "security", base / "web", base / "custom"
    sec.write_text("A=1\nAZAZEL_AI_SOCKET=/run/azazel-edge/ai-bridge.sock\n", encoding="utf-8")
    web.write_text('AZAZEL_AI_SOCKET="/run/azazel-edge/ai-bridge.sock"\nAZAZEL_X=/run/azazel-edge/ai-bridge.sock\n',
                   encoding="utf-8")
    custom.write_text("AZAZEL_AI_SOCKET=/srv/own/ai.sock\n", encoding="utf-8")
    script = (f"SECURITY_ENV={sec}\nWEB_ENV={web}\n" + loop.group(0)
              + f"SECURITY_ENV={custom}\nWEB_ENV={custom}\n" + loop.group(0))
    subprocess.run(["bash", "-c", script], check=True)
    assert sec.read_text(encoding="utf-8") == f"A=1\nAZAZEL_AI_SOCKET={DEFAULT_SOCKET}\n"
    assert web.read_text(encoding="utf-8") == (f'AZAZEL_AI_SOCKET="{DEFAULT_SOCKET}"\n'
                                               "AZAZEL_X=/run/azazel-edge/ai-bridge.sock\n")
    assert custom.read_text(encoding="utf-8") == "AZAZEL_AI_SOCKET=/srv/own/ai.sock\n"


# ------------------------------------------------------------ the agent alone


def test_the_directory_is_created_private_and_the_socket_owner_only(monkeypatch, base, shared_group):
    name, gid = shared_group
    monkeypatch.setenv("AZAZEL_RUNTIME_SOCKET_GROUP", name)
    monkeypatch.setenv("AZAZEL_AI_SOCKET_MODE", "0666")
    chowned: list = []
    real_chown = os.chown
    monkeypatch.setattr(os, "chown", lambda *a, **k: (chowned.append(a), real_chown(*a, **k)))
    path = _ai_socket(base)
    old = os.umask(0)  # the widest umask a unit could run with
    try:
        agent_mod._prepare_ai_socket_dir(path)
        srv = agent_mod._bind_ai_socket(path)
    finally:
        os.umask(old)
    try:
        d = os.lstat(path.parent)
        assert stat.S_ISDIR(d.st_mode) and _mode(path.parent) == 0o700 and d.st_uid == os.geteuid()
        st = os.lstat(path)
        assert stat.S_ISSOCK(st.st_mode)
        assert _mode(path) == 0o600
        assert st.st_uid == os.geteuid()
        assert st.st_gid == os.getegid() != gid
        assert all(call[-1] != gid for call in chowned)
    finally:
        srv.close()


def test_bind_runs_under_a_restrictive_umask_inside_the_private_directory(monkeypatch, base):
    path = _ai_socket(base)
    seen: dict = {}
    real_socket = socket.socket

    class Spy(real_socket):
        def bind(self, address):
            mask = os.umask(0o022)
            os.umask(mask)
            parent = Path(address).parent
            seen.update(umask=mask, dir_mode=_mode(parent), dir_uid=os.lstat(parent).st_uid)
            return super().bind(address)

    monkeypatch.setattr(socket, "socket", Spy)
    old = os.umask(0)
    try:
        agent_mod._prepare_ai_socket_dir(path)
        srv = agent_mod._bind_ai_socket(path)
        after = os.umask(0)
    finally:
        os.umask(old)
    srv.close()
    assert seen["umask"] == 0o177
    assert seen["dir_mode"] == 0o700 and seen["dir_uid"] == os.geteuid()
    assert after == 0  # restored


def test_a_stale_socket_is_replaced(base):
    path = _ai_socket(base)
    agent_mod._prepare_ai_socket_dir(path)
    agent_mod._bind_ai_socket(path).close()
    srv = agent_mod._bind_ai_socket(path)
    try:
        assert stat.S_ISSOCK(os.lstat(path).st_mode)
    finally:
        srv.close()


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_a_non_socket_entry_at_the_path_is_refused(base, kind):
    path = _ai_socket(base)
    agent_mod._prepare_ai_socket_dir(path)
    victim = base / "victim"
    victim.write_text("x", encoding="utf-8")
    if kind == "directory":
        path.mkdir()
    elif kind == "file":
        path.write_text("x", encoding="utf-8")
    else:
        path.symlink_to(victim)
    with pytest.raises(agent_mod.AISocketSetupError, match="not a socket"):
        agent_mod._bind_ai_socket(path)
    assert os.path.lexists(path)
    assert victim.read_text(encoding="utf-8") == "x"


@pytest.mark.parametrize("kind", ["symlink", "file", "wide"])
def test_an_untrusted_directory_is_refused_and_not_changed(base, kind):
    path = _ai_socket(base)
    victim = base / "victim"
    victim.mkdir()
    os.chmod(victim, 0o755)
    if kind == "symlink":
        path.parent.symlink_to(victim)
        match = "symlink"
    elif kind == "file":
        path.parent.write_text("x", encoding="utf-8")
        match = "not a directory"
    else:
        path.parent.mkdir()
        os.chmod(path.parent, 0o770)
        match = "must be 0700"
    with pytest.raises(agent_mod.AISocketSetupError, match=match):
        agent_mod._prepare_ai_socket_dir(path)
    assert _mode(victim) == 0o755
    if kind == "wide":
        assert _mode(path.parent) == 0o770


@pytest.mark.skipif(not IS_ROOT, reason="needs root to make a directory owned by another account")
def test_a_directory_owned_by_another_account_is_refused(base):
    import pwd

    path = _ai_socket(base)
    path.parent.mkdir()
    os.chmod(path.parent, 0o700)
    os.chown(path.parent, pwd.getpwnam("nobody").pw_uid, -1)
    with pytest.raises(agent_mod.AISocketSetupError, match="owned by uid"):
        agent_mod._prepare_ai_socket_dir(path)


def test_the_service_refuses_a_socket_in_the_shared_directory(monkeypatch, base, run_dir, shared_group):
    # As with an old config line pointing into /run/azazel-edge (0770 + group).
    name, _ = shared_group
    daemon = _control_daemon(monkeypatch, run_dir, name)
    ctl = daemon.create_listener_socket()
    try:
        agent = _AgentProc(base, name, socket_path=run_dir / "ai-bridge.sock")
        with pytest.raises(AssertionError, match="agent exited"):
            agent.__enter__()
        agent.__exit__(None, None, None)
        assert agent.proc.returncode not in (0, None)
        assert "must be 0700" in agent.stderr.read_text(encoding="utf-8")
        assert not os.path.lexists(run_dir / "ai-bridge.sock")
        assert _mode(run_dir) == daemon.RUNTIME_DIR_MODE  # not narrowed
        assert _accepting(run_dir / "control.sock")
    finally:
        ctl.close()


def test_the_service_ignores_the_shared_group_and_the_old_mode(base, shared_group):
    name, gid = shared_group
    with _AgentProc(base, name, AZAZEL_AI_SOCKET_MODE="0666") as agent:
        st = os.lstat(agent.socket)
        assert _mode(agent.socket) == 0o600
        assert st.st_gid == os.getegid() != gid
        assert _mode(agent.socket.parent) == 0o700
        assert os.lstat(agent.socket.parent).st_uid == os.geteuid()
        # The agent's own runtime directory does not take the group either,
        # and the agent creates nothing in the shared one (Edge#471 stage 2).
        assert os.lstat(base / "agent").st_gid != gid
        assert not os.path.lexists(base / "run")


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
def test_agent_and_daemon_do_not_fight_over_the_runtime_directory(monkeypatch, base, run_dir, shared_group,
                                                                  daemon_first):
    name, gid = shared_group
    daemon = _control_daemon(monkeypatch, run_dir, name)
    ctl = daemon.create_listener_socket() if daemon_first else None
    try:
        with _AgentProc(base, name) as agent:
            if ctl is None:
                ctl = daemon.create_listener_socket()
            # Either start order: the shared directory and control.sock carry
            # the shared group; ai-bridge.sock and its directory do not.
            assert run_dir.stat().st_gid == gid
            assert stat.S_IMODE(run_dir.stat().st_mode) == daemon.RUNTIME_DIR_MODE
            assert (run_dir / "control.sock").stat().st_gid == gid
            assert os.lstat(agent.socket).st_gid == os.getegid() != gid
            assert _mode(agent.socket) == 0o600
            assert _mode(agent.socket.parent) == 0o700
            assert _accepting(agent.socket)
    finally:
        if ctl is not None:
            ctl.close()


_MEMBER_PROBE = r"""
import json, os, socket, sys
gid, uid = int(sys.argv[1]), int(sys.argv[2])
os.setgroups([gid]); os.setgid(gid); os.setuid(uid)
control, ai = sys.argv[3], sys.argv[4]
out = {}
def attempt(name, fn):
    try:
        fn(); out[name] = "ok"
    except PermissionError:
        out[name] = "denied"
    except OSError as exc:
        out[name] = "error:" + type(exc).__name__
def connect(p):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(p)
    finally:
        s.close()
def bind_own(p):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind(p)
    finally:
        s.close()
attempt("connect_control", lambda: connect(control))
attempt("connect_ai", lambda: connect(ai))
attempt("rename_ai", lambda: os.rename(ai, ai + ".moved"))
attempt("unlink_ai", lambda: os.unlink(ai))
attempt("bind_beside_ai", lambda: bind_own(os.path.join(os.path.dirname(ai), "fake.sock")))
print(json.dumps(out))
"""


@pytest.mark.skipif(not IS_ROOT, reason="needs root to act as a group member")
def test_a_group_member_reaches_control_sock_but_cannot_reach_or_replace_ai_bridge(monkeypatch, base, run_dir,
                                                                                  shared_group):
    import pwd

    name, gid = shared_group
    try:
        member_uid = pwd.getpwnam("nobody").pw_uid
    except KeyError:
        pytest.skip("no unprivileged account")
    # Only the runtime directories decide: the temporary parent is passable.
    os.chmod(base, 0o711)
    daemon = _control_daemon(monkeypatch, run_dir, name)
    ctl = daemon.create_listener_socket()
    try:
        with _AgentProc(base, name) as agent:
            before = os.lstat(agent.socket)
            res = subprocess.run([sys.executable, "-I", "-c", _MEMBER_PROBE, str(gid), str(member_uid),
                                  str(run_dir / "control.sock"), str(agent.socket)],
                                 capture_output=True, text=True, timeout=30)
            assert res.returncode == 0, res.stderr
            out = json.loads(res.stdout)
            assert out["connect_control"] == "ok", out
            for key in ("connect_ai", "rename_ai", "unlink_ai", "bind_beside_ai"):
                assert out[key] == "denied", out
            after = os.lstat(agent.socket)
            assert (after.st_ino, after.st_uid) == (before.st_ino, before.st_uid)
            assert _accepting(agent.socket)
    finally:
        ctl.close()


# ------------------------------------------------- the legitimate callers


def test_the_web_ui_manual_query_still_reaches_the_agent(monkeypatch, base, shared_group):
    # A root caller (the agent's own account) may still send manual_query on
    # ai-bridge.sock; the Web UI itself uses the query socket (Edge#471).
    name, _ = shared_group
    from azazel_edge_web import app as web_app

    with _AgentProc(base, name) as agent:
        monkeypatch.setattr(web_app, "AI_SOCKET", agent.socket)
        result = web_app._send_ai_manual_query("What is the current state?")
    assert "ai_query_error" not in str(result.get("error", "")), result
    assert result.get("error") not in {"empty_ai_response", "ai_socket_not_found:" + str(agent.socket)}, result
    assert "ok" in result


def test_core_style_forwarding_still_reaches_the_agent(base, shared_group):
    # As the core delivers: one connection per line, write, close.
    name, _ = shared_group
    with _AgentProc(base, name) as agent:
        event = json.loads((ROOT / "tests" / "fixtures" / "rust_core_event_v1.json").read_text(encoding="utf-8"))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(agent.socket))
            conn.sendall((json.dumps(event) + "\n").encode("utf-8"))
        events_log = Path(agent.env["AZAZEL_AI_EVENT_LOG"])
        assert _wait(lambda: events_log.exists() and events_log.stat().st_size > 0)


@pytest.mark.skipif(not IS_ROOT or not sys.platform.startswith("linux"), reason="needs root on Linux (uses /run)")
def test_core_and_web_reach_the_agent_at_the_default_path(monkeypatch, base, rust_core_bin):
    default_dir = Path(DEFAULT_SOCKET).parent
    if os.path.lexists(default_dir):
        pytest.skip("the default socket directory already exists on this host")
    from azazel_edge_web import app as web_app

    try:
        with _AgentProc(base, "", socket_path=Path(DEFAULT_SOCKET)) as agent:
            assert "AZAZEL_AI_SOCKET" not in agent.env
            assert _mode(default_dir) == 0o700
            # A root manual_query on the default ai-bridge.sock path (the Web
            # UI's own default is the query socket since Edge#471).
            monkeypatch.setattr(web_app, "AI_SOCKET", Path(DEFAULT_SOCKET))
            result = web_app._send_ai_manual_query("What is the current state?")
            assert "ai_query_error" not in str(result.get("error", "")), result
            assert result.get("error") != "empty_ai_response", result
            # The release core with its unit's socket path (dry run, enforcement off).
            core_socket = Path(so03_alert_queue.unit_environment(CORE_UNIT)["AZAZEL_AI_SOCKET"])
            work = base / "core"
            work.mkdir()
            eve = work / "eve.json"
            eve.write_text("", encoding="utf-8")
            env = so03_alert_queue.core_environment(work, core_socket)
            err_path = work / "core.stderr"
            events_log = Path(agent.env["AZAZEL_AI_EVENT_LOG"])
            with err_path.open("w", encoding="utf-8") as err:
                core = subprocess.Popen([str(rust_core_bin)], cwd=str(work), env=env,
                                        stdout=subprocess.DEVNULL, stderr=err)
            try:
                assert _wait(lambda: "azazel-edge-core started" in err_path.read_text(encoding="utf-8",
                                                                                      errors="replace"))
                with eve.open("a", encoding="utf-8") as fh:
                    fh.write(so03_alert_queue._eve_line(1, 2, 22, 9_320_001) + "\n")
                assert _wait(lambda: events_log.exists() and events_log.stat().st_size > 0, timeout=30)
            finally:
                core.terminate()
                core.wait(timeout=10)
    finally:
        shutil.rmtree(default_dir, ignore_errors=True)
