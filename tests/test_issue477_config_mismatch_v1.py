"""Edge#477: settings and behaviour that disagreed.

Pinned here:
- control.sock ``contain`` / ``disconnect`` / ``stage_open`` answer an explicit
  ``not_implemented`` (they used to append a log line and answer success);
- the CLI returns any daemon answer as it is (a refusal stays a failure) and
  writes the legacy command file only when the daemon is not reached; since
  nothing reads that file, the result is ``undelivered``, not success;
- the Web UI's state SSE ends with a ``stream_error`` event (with ``retry``)
  when the daemon's watch stream ends (``busy``, closed, no socket);
- port 8082: an HTTP error or unusable reply is the status API's refusal and
  a failure; only "nothing answers" (refused, timeout) falls back to
  ``uplink_disconnect``;
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


DAEMON_REFUSALS = [
    {"ok": False, "action": "contain", "error": "not_implemented", "not_implemented": True},
    {"ok": False, "error": "forbidden", "reason": "peer_not_allowed", "action": "refresh"},
    {"ok": False, "error": "busy"},
    {"ok": False, "error": "Rate limit exceeded (1 req/10sec)"},
    {"ok": False, "error": "Unknown action: nosuch"},
    {"ok": False, "stdout": "", "stderr": "boom", "ts": 1.0},  # a failed script
]


@pytest.mark.parametrize("answer", DAEMON_REFUSALS)
def test_a_daemon_refusal_is_returned_as_it_is(answer, monkeypatch, tmp_path):
    monkeypatch.setattr(control_plane, "send_action", lambda action, params=None, **kw: dict(answer))
    cmd = tmp_path / "ui_command.json"
    res = control_plane.send_action_with_fallback("refresh", fallback_cmd_path=cmd)
    assert res == answer
    assert not cmd.exists()


@pytest.mark.parametrize("answer", DAEMON_REFUSALS)
def test_a_daemon_refusal_over_the_socket_is_not_a_transport_error(answer, tmpdir_short, monkeypatch):
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, [json.dumps(answer).encode() + b"\n"])
    monkeypatch.setattr(control_plane, "send_action",
                        functools.partial(control_plane.send_action, socket_path=path))
    cmd = tmpdir_short / "ui_command.json"
    res = control_plane.send_action_with_fallback("refresh", fallback_cmd_path=cmd)
    t.join(5)
    assert res == answer and "transport_error" not in res
    assert not cmd.exists()


def test_an_unreachable_daemon_is_not_delivered_not_ok(monkeypatch, tmpdir_short):
    # no socket at all: the legacy command file is written, but nothing in
    # this repository reads it, so the result is not success
    monkeypatch.setattr(control_plane, "send_action",
                        functools.partial(control_plane.send_action, socket_path=tmpdir_short / "none.sock"))
    cmd = tmpdir_short / "ui_command.json"
    res = control_plane.send_action_with_fallback("refresh", fallback_cmd_path=cmd)
    assert res["ok"] is False and res["undelivered"] is True
    assert res["fallback"] == "command_file" and res["path"] == str(cmd)
    assert "not delivered" in res["error"]
    assert json.loads(cmd.read_text())["action"] == "refresh"


def test_a_daemon_that_closes_before_answering_is_a_transport_error(tmpdir_short, monkeypatch):
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, [])
    res = control_plane.send_action("refresh", socket_path=path)
    t.join(5)
    assert res["ok"] is False and res["transport_error"] is True


def test_nothing_in_the_repository_reads_ui_command_json():
    """The undelivered result above rests on this: if a reader is added, the
    fallback may be reported as delivered again."""
    hits = subprocess.run(["git", "grep", "-l", "ui_command", "--", ".", ":!tests", ":!docs"],
                          cwd=ROOT, capture_output=True, text=True)
    if hits.returncode not in (0, 1):
        pytest.skip("not a git checkout")
    # the candidate paths, and the writer's own docstring; no reader
    assert sorted(hits.stdout.split()) == ["py/azazel_edge/control_plane.py", "py/azazel_edge/path_schema.py"]


@pytest.mark.parametrize("result,expected", [
    ({"ok": False, "error": "not_implemented", "not_implemented": True},
     "• action not implemented: contain (nothing was done)"),
    ({"ok": False, "undelivered": True, "error": "x"},
     "• action not delivered: contain (control daemon not reached)"),
    ({"ok": False, "error": "forbidden"}, "• action failed: contain (forbidden)"),
    (None, "• action failed: contain (unexpected response)"),
])
def test_cli_wording(result, expected):
    assert control_plane.describe_action_failure(result, "contain") == expected


def test_cli_labels_mark_stage_open_and_contain_as_not_implemented():
    for rel in ("py/azazel_edge/cli_unified.py", "py/azazel_edge/cli_unified_textual.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "Stage-Open (未実装)" in src and "Contain (未実装)" in src
        assert "describe_action_failure(" in src


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
    assert [name for name, _ in events] == ["ready", "stream_error"]
    # a reconnect delay comes with it, so clients do not reconnect into busy
    assert f"retry: {webapp.STATE_STREAM_RETRY_MS}\nevent: stream_error\n" in body
    assert webapp.STATE_STREAM_RETRY_MS >= 5000
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
    assert names == ["ready", "state", "stream_error"]


# ------------------------------------------------------- port 8082 (item 3)

class _Done:
    def __init__(self, rc: int, out: bytes = b""):
        self.returncode = rc
        self.stdout = out


def test_an_http_error_from_8082_is_a_refusal(monkeypatch):
    cmds = []

    def fake_run(cmd, **kw):
        cmds.append(cmd)
        return _Done(22)  # curl --fail: HTTP status >= 400

    monkeypatch.setattr(webapp.subprocess, "run", fake_run)
    res = webapp._status_api_json(host="127.0.0.1", path="/action/contain", method="POST",
                                  action="contain", empty_ok=True, empty_message="Containment activated")
    assert res["ok"] is False and res["status_api_error"] is True and res["action"] == "contain"
    assert "HTTP error" in res["error"]
    assert "--fail" in cmds[0] and "--max-time" in cmds[0]
    assert cmds[0][-1] == "http://127.0.0.1:8082/action/contain"


@pytest.mark.parametrize("rc", [7, 28, 6])  # refused, timeout, cannot resolve
def test_nothing_answering_on_8082_is_none(rc, monkeypatch):
    monkeypatch.setattr(webapp.subprocess, "run", lambda cmd, **kw: _Done(rc))
    assert webapp._status_api_json(host="127.0.0.1", path="/", empty_ok=True) is None


def test_a_subprocess_timeout_is_nothing_answering(monkeypatch):
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 2)

    monkeypatch.setattr(webapp.subprocess, "run", fake_run)
    assert webapp._status_api_json(host="127.0.0.1", path="/") is None


@pytest.mark.parametrize("out", [b"", b"<html>nope</html>", b"[1, 2]"])
def test_an_unusable_reply_from_8082_is_a_refusal(out, monkeypatch):
    monkeypatch.setattr(webapp.subprocess, "run", lambda cmd, **kw: _Done(0, out))
    res = webapp._status_api_json(host="127.0.0.1", path="/action/disconnect", method="POST",
                                  action="disconnect", empty_ok=False)
    assert res["ok"] is False and res["status_api_error"] is True


def _disconnect_with(monkeypatch, rc, out=b""):
    monkeypatch.setattr(webapp.subprocess, "run", lambda cmd, **kw: _Done(rc, out))
    sent = []

    def fake_socket(action, params=None, timeout_sec=5.0):
        sent.append(action)
        return {"ok": True, "message": "Uplink disconnected"}

    monkeypatch.setattr(webapp, "_send_control_command_socket", fake_socket)
    return webapp.execute_disconnect_action(), sent


def test_disconnect_refused_by_8082_does_not_fall_back(monkeypatch):
    res, sent = _disconnect_with(monkeypatch, 22)
    assert res["ok"] is False and res["action"] == "disconnect" and "HTTP error" in res["error"]
    assert sent == []


@pytest.mark.parametrize("rc", [7, 28])
def test_disconnect_falls_back_only_when_nothing_answers(rc, monkeypatch):
    res, sent = _disconnect_with(monkeypatch, rc)
    assert sent == ["uplink_disconnect"]
    assert res["ok"] is True and res["via"] == "control_daemon"


def test_contain_without_a_status_api_is_a_failure(monkeypatch):
    monkeypatch.setattr(webapp.subprocess, "run", lambda cmd, **kw: _Done(7))  # connection refused
    res = webapp.execute_contain_action()
    assert res["ok"] is False and res["action"] == "contain"


def test_contain_refused_by_8082_is_a_failure_over_http(monkeypatch):
    monkeypatch.setattr(webapp.subprocess, "run", lambda cmd, **kw: _Done(22))
    monkeypatch.setattr(webapp, "load_token", lambda: None)
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    resp = webapp.app.test_client().post("/api/action/contain")
    assert resp.status_code == 500 and resp.get_json()["ok"] is False


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


def test_another_not_found_is_relayed_as_it_is(monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Failed to connect to bus: No such file or directory (not found)")

    monkeypatch.setattr(control_daemon.subprocess, "run", fake_run)
    res = control_daemon.ensure_portal_viewer_ready(timeout_sec=1.0)
    assert res["ok"] is False and "is not installed" not in res["error"]


def test_a_missing_portal_viewer_unit_is_reported_as_not_installed(monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 5, stdout="",
                                           stderr="Failed to start azazel-edge-portal-viewer.service: Unit azazel-edge-portal-viewer.service not found.")

    monkeypatch.setattr(control_daemon.subprocess, "run", fake_run)
    res = control_daemon.ensure_portal_viewer_ready(timeout_sec=1.0)
    assert res["ok"] is False
    assert "is not installed on this device" in res["error"]
