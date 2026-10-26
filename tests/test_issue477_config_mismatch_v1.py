"""Edge#477: settings and behaviour that disagreed.

Pinned here:
- control.sock ``contain`` / ``disconnect`` / ``stage_open`` answer an explicit
  ``not_implemented`` (they used to append a log line and answer success), and
  the CLI's command-file fallback does not turn that answer into success;
- the Web UI's state SSE ends with an ``error`` event when the daemon's watch
  stream ends (``busy``, closed, no socket) instead of ending silently;
- the port 8082 status API call treats an HTTP error status as a failure
  (``curl --fail``), so an empty error reply is never "Containment activated";
- the Web UI reads the portal viewer's status under the unit name the control
  daemon starts.
"""

from __future__ import annotations

import functools
import json
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from _control_daemon_inproc import short_tmpdir  # noqa: E402
from azazel_edge import control_plane  # noqa: E402
from azazel_edge_control import daemon as control_daemon  # noqa: E402

import azazel_edge_web.app as webapp  # noqa: E402


@pytest.fixture
def tmpdir_short():
    path = short_tmpdir("a477")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _one_shot_server(path: Path, lines: list[bytes]):
    """A Unix socket that reads one request, sends ``lines`` and closes."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            for line in lines:
                conn.sendall(line)
        srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return t


# ------------------------------------------------ contain / disconnect (item 5)

@pytest.mark.parametrize("action", ["contain", "disconnect", "stage_open"])
def test_log_only_actions_answer_not_implemented(action, monkeypatch):
    ran = []
    monkeypatch.setattr(control_daemon.subprocess, "run", lambda *a, **k: ran.append(a) or None)
    res = control_daemon.execute_action(action, None)
    assert res["ok"] is False
    assert res["error"] == "not_implemented" and res["not_implemented"] is True
    assert res["action"] == action
    assert ran == []  # no script, no command
    assert action not in control_daemon.ACTION_SCRIPTS


def test_the_log_only_scripts_are_gone():
    scripts = ROOT / "py" / "azazel_edge_control" / "scripts"
    for name in ("contain.sh", "disconnect.sh", "stage_open.sh"):
        assert not (scripts / name).exists()
    # what the daemon still runs is still there
    for path in control_daemon.ACTION_SCRIPTS.values():
        assert Path(path).is_file(), path


def test_not_implemented_is_not_turned_into_success_by_the_command_file(monkeypatch, tmp_path):
    answer = {"ok": False, "action": "contain", "error": "not_implemented", "not_implemented": True}
    monkeypatch.setattr(control_plane, "send_action", lambda action, params=None, **kw: dict(answer))
    cmd = tmp_path / "ui_command.json"
    res = control_plane.send_action_with_fallback("contain", fallback_cmd_path=cmd)
    assert res["ok"] is False and res["error"] == "not_implemented"
    assert not cmd.exists()


def test_an_unreachable_daemon_still_uses_the_command_file(monkeypatch, tmp_path):
    # unchanged: the fallback is for a daemon that does not answer
    monkeypatch.setattr(control_plane, "send_action",
                        lambda action, params=None, **kw: {"ok": False, "error": "control socket not found: x"})
    cmd = tmp_path / "ui_command.json"
    res = control_plane.send_action_with_fallback("refresh", fallback_cmd_path=cmd)
    assert res["ok"] is True and res["fallback"] == "command_file"
    assert json.loads(cmd.read_text())["action"] == "refresh"


def test_not_implemented_end_to_end_over_control_sock(tmpdir_short, monkeypatch):
    """CLI path (control_plane) -> a socket answering like the daemon -> failure."""
    path = tmpdir_short / "c.sock"
    reply = json.dumps(control_daemon.execute_action("contain", None)).encode() + b"\n"
    t = _one_shot_server(path, [reply])
    res = control_plane.send_action("contain", socket_path=path)
    t.join(5)
    assert res["ok"] is False and res["error"] == "not_implemented"


# ------------------------------------------------------------ SSE busy (item 6)

def test_watch_snapshots_reports_busy(tmpdir_short):
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, [b'{"ok": false, "error": "busy"}\n'])
    errors: list[str] = []
    got = list(control_plane.watch_snapshots(socket_path=path, errors=errors))
    t.join(5)
    assert got == [] and errors == ["busy"]


def test_watch_snapshots_keeps_reading_after_a_non_snapshot_line(tmpdir_short):
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, [
        b'{"ok": false, "error": "snapshot_unavailable"}\n',
        b'{"ok": true, "snapshot": {"a": 1}}\n',
    ])
    errors: list[str] = []
    got = list(control_plane.watch_snapshots(socket_path=path, errors=errors))
    t.join(5)
    assert got == [{"a": 1}] and errors == ["stream_closed"]


def test_watch_snapshots_reports_a_missing_socket(tmpdir_short):
    errors: list[str] = []
    assert list(control_plane.watch_snapshots(socket_path=tmpdir_short / "none.sock", errors=errors)) == []
    assert errors == ["socket_missing"]


def _sse_events(body: str) -> list[tuple[str, dict]]:
    events = []
    for block in body.strip().split("\n\n"):
        name = data = ""
        for line in block.splitlines():
            if line.startswith("event: "):
                name = line[len("event: "):]
            elif line.startswith("data: "):
                data = line[len("data: "):]
        events.append((name, json.loads(data)))
    return events


def test_state_sse_sends_an_error_event_when_the_daemon_is_busy(tmpdir_short, monkeypatch):
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, [b'{"ok": false, "error": "busy"}\n'])
    monkeypatch.setattr(webapp, "load_token", lambda: None)
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    monkeypatch.setattr(webapp, "cp_watch_snapshots",
                        functools.partial(control_plane.watch_snapshots, socket_path=path))
    resp = webapp.app.test_client().get("/api/state/stream")
    body = resp.get_data(as_text=True)
    t.join(5)
    events = _sse_events(body)
    assert [name for name, _ in events] == ["ready", "error"]
    assert events[-1][1] == {"ok": False, "source": "state_stream", "error": "busy"}


def test_state_sse_ends_with_an_error_event_after_snapshots(monkeypatch):
    def fake_watch(interval_sec=1.0, errors=None):
        yield {"a": 1}
        errors.append("stream_closed")

    monkeypatch.setattr(webapp, "load_token", lambda: None)
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    monkeypatch.setattr(webapp, "cp_watch_snapshots", fake_watch)
    monkeypatch.setattr(webapp, "get_monitoring_state", lambda: {})
    monkeypatch.setattr(webapp, "get_portal_viewer_state", lambda: {})
    monkeypatch.setattr(webapp, "get_mode_state", lambda: {})
    body = webapp.app.test_client().get("/api/state/stream").get_data(as_text=True)
    names = [name for name, _ in _sse_events(body)]
    assert names == ["ready", "state", "error"]


# ------------------------------------------------------- port 8082 (item 3)

class _Done:
    def __init__(self, rc: int, out: bytes = b""):
        self.returncode = rc
        self.stdout = out


def test_status_api_call_fails_on_http_errors(monkeypatch):
    cmds = []

    def fake_run(cmd, **kw):
        cmds.append(cmd)
        return _Done(22)  # curl --fail: HTTP status >= 400

    monkeypatch.setattr(webapp.subprocess, "run", fake_run)
    res = webapp._status_api_json(host="127.0.0.1", path="/action/contain", method="POST",
                                  action="contain", empty_ok=True, empty_message="Containment activated")
    assert res is None
    assert "--fail" in cmds[0] and "--max-time" in cmds[0]
    assert cmds[0][-1] == "http://127.0.0.1:8082/action/contain"


def test_contain_without_a_status_api_is_a_failure(monkeypatch):
    monkeypatch.setattr(webapp.subprocess, "run", lambda cmd, **kw: _Done(7))  # connection refused
    res = webapp.execute_contain_action()
    assert res["ok"] is False and res["action"] == "contain"


def test_an_empty_2xx_reply_is_still_accepted_as_before(monkeypatch):
    monkeypatch.setattr(webapp.subprocess, "run", lambda cmd, **kw: _Done(0, b""))
    res = webapp.execute_contain_action()
    assert res == {"ok": True, "action": "contain", "message": "Containment activated"}


# --------------------------------------------------- portal viewer (item 4)

def test_the_web_ui_reads_the_unit_the_daemon_starts(monkeypatch):
    assert webapp.PORTAL_VIEWER_SERVICE == control_daemon.PORTAL_VIEWER_SERVICE
    asked = []
    monkeypatch.setattr(webapp, "_service_active", lambda name: asked.append(name) or False)
    webapp._portal_viewer_state_from_config({"bind": "127.0.0.1", "port": 6080})
    assert asked == [control_daemon.PORTAL_VIEWER_SERVICE]
    src = (ROOT / "azazel_edge_web" / "app.py").read_text(encoding="utf-8")
    assert '_service_active("azazel-portal-viewer.service")' not in src


def test_a_missing_portal_viewer_unit_is_reported_as_not_installed(monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 5, stdout="",
                                           stderr="Failed to start azazel-edge-portal-viewer.service: Unit azazel-edge-portal-viewer.service not found.")

    monkeypatch.setattr(control_daemon.subprocess, "run", fake_run)
    res = control_daemon.ensure_portal_viewer_ready(timeout_sec=1.0)
    assert res["ok"] is False
    assert "is not installed on this device" in res["error"]
