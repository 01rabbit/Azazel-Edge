"""Edge#477: settings and behaviour that disagreed.

Pinned here:
- control.sock ``contain`` / ``disconnect`` / ``stage_open`` answer an explicit
  ``not_implemented`` (they used to append a log line and answer success);
- the CLI returns any daemon answer as it is (a refusal or an unusable
  reply stays a failure); a request sent without a reply is
  ``delivery_unknown`` (it may have run) and is not handed on; only when the
  daemon was never reached (no socket, connect failed) is the legacy command
  file written, and since nothing reads it the result is ``undelivered``;
- the Web UI's state SSE ends with a ``stream_error`` event (with ``retry``)
  when the daemon's watch stream ends (``busy``, closed, no socket).

The port 8082 status API and the portal viewer had no provider for this
device and were removed from the Web UI and the daemon afterwards; that is
pinned in test_dead_refs_8082_portal_viewer_v1.py.
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


def _one_shot_server(path: Path, lines: list[bytes], delay_sec: float = 0.0):
    """A Unix socket that reads one request, waits ``delay_sec``, sends
    ``lines`` and closes."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            if delay_sec:
                threading.Event().wait(delay_sec)
            for line in lines:
                try:
                    conn.sendall(line)
                except OSError:
                    break  # the client has gone (it timed out)
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


def test_a_missing_socket_is_not_delivered_not_ok(monkeypatch, tmpdir_short):
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


def _via(monkeypatch, path):
    monkeypatch.setattr(control_plane, "send_action",
                        functools.partial(control_plane.send_action, socket_path=path))


def test_a_daemon_that_closes_before_answering_is_delivery_unknown(tmpdir_short, monkeypatch):
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, [])
    _via(monkeypatch, path)
    cmd = tmpdir_short / "ui_command.json"
    res = control_plane.send_action_with_fallback("refresh", fallback_cmd_path=cmd)
    t.join(5)
    assert res["ok"] is False and res["delivery_unknown"] is True
    assert "transport_error" not in res and "undelivered" not in res
    assert not cmd.exists()


def test_a_reply_after_the_timeout_is_delivery_unknown_and_not_handed_on(tmpdir_short, monkeypatch):
    """The daemon answers after 5 s, past the client's 1.5 s: it may have
    carried the action out, so no command file is written."""
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, [b'{"ok": true}\n'], delay_sec=5.0)
    _via(monkeypatch, path)
    cmd = tmpdir_short / "ui_command.json"
    res = control_plane.send_action_with_fallback("reboot", fallback_cmd_path=cmd)
    assert res["ok"] is False and res["delivery_unknown"] is True
    assert not cmd.exists()
    t.join(10)
    assert not cmd.exists()
    assert "may have been carried out" in control_plane.describe_action_failure(res, "reboot")


def test_a_connect_failure_is_not_delivered(tmpdir_short, monkeypatch):
    path = tmpdir_short / "c.sock"
    path.write_text("not a socket")  # exists, but connect fails
    _via(monkeypatch, path)
    cmd = tmpdir_short / "ui_command.json"
    res = control_plane.send_action_with_fallback("refresh", fallback_cmd_path=cmd)
    assert res["ok"] is False and res["undelivered"] is True
    assert cmd.exists()


@pytest.mark.parametrize("lines", [
    [b"this is not json\n"],
    [b'{"ok": true, "stdo'],              # a partial line, then closed
    [b"[" * 100000 + b"]" * 100000 + b"\n"],  # too deep to parse
    [b'["ok"]\n'],
])
def test_an_unusable_reply_is_returned_and_not_handed_on(lines, tmpdir_short, monkeypatch):
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, lines)
    _via(monkeypatch, path)
    cmd = tmpdir_short / "ui_command.json"
    res = control_plane.send_action_with_fallback("refresh", fallback_cmd_path=cmd)
    t.join(5)
    assert res["ok"] is False and res["error"].startswith("invalid response")
    assert not any(k in res for k in ("transport_error", "delivery_unknown", "undelivered"))
    assert not cmd.exists()


def test_a_send_failure_after_connect_is_delivery_unknown(tmpdir_short, monkeypatch):
    """connect succeeds, sendall breaks (BrokenPipeError): the daemon may have
    read part or all of it, so this is not "not delivered"."""
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, [])

    class _BrokenSendSocket(socket.socket):
        def sendall(self, *a, **k):
            raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(control_plane.socket, "socket", _BrokenSendSocket)
    _via(monkeypatch, path)
    cmd = tmpdir_short / "ui_command.json"
    res = control_plane.send_action_with_fallback("refresh", fallback_cmd_path=cmd)
    t.join(5)
    assert res["ok"] is False and res["delivery_unknown"] is True
    assert "transport_error" not in res and "undelivered" not in res
    assert not cmd.exists()


def test_a_partial_line_then_silence_is_an_invalid_response(tmpdir_short, monkeypatch):
    """The server sends part of a line and then says nothing (no newline, no
    close) until the client times out."""
    path = tmpdir_short / "c.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(1)
    done = threading.Event()

    def serve():
        conn, _ = srv.accept()
        with conn:
            conn.recv(4096)
            conn.sendall(b'{"ok": true, "std')
            done.wait(10)  # silent until the test is over
        srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    _via(monkeypatch, path)
    cmd = tmpdir_short / "ui_command.json"
    try:
        res = control_plane.send_action_with_fallback("refresh", fallback_cmd_path=cmd)
    finally:
        done.set()
        t.join(5)
    assert res["ok"] is False and res["error"].startswith("invalid response: incomplete reply")
    assert "received the request and may have carried it out" in res["error"]
    assert "may have carried it out" in control_plane.describe_action_failure(res, "refresh")
    assert not any(k in res for k in ("transport_error", "delivery_unknown", "undelivered"))
    assert not cmd.exists()


def test_an_unserializable_request_fails_before_sending(tmpdir_short, monkeypatch):
    path = tmpdir_short / "c.sock"
    t = _one_shot_server(path, [b'{"ok": true}\n'])
    cmd = tmpdir_short / "ui_command.json"
    res = control_plane.send_action_with_fallback("refresh", params={"x": object()}, fallback_cmd_path=cmd)
    assert res["ok"] is False and res["error"].startswith("request not serializable")
    assert not any(k in res for k in ("transport_error", "delivery_unknown", "undelivered"))
    assert not cmd.exists()
    # nothing was sent: the server is still waiting for a client
    direct = control_plane.send_action("refresh", socket_path=path)
    t.join(5)
    assert direct == {"ok": True}


def test_watch_snapshots_with_a_socket_that_cannot_be_created(tmpdir_short, monkeypatch):
    path = tmpdir_short / "c.sock"
    path.write_text("x")

    def no_socket(*a, **k):
        raise OSError("no sockets")

    monkeypatch.setattr(control_plane.socket, "socket", no_socket)
    errors: list[str] = []
    assert list(control_plane.watch_snapshots(socket_path=path, errors=errors)) == []
    assert errors == ["stream_error:OSError"]


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
    ({"ok": False, "delivery_unknown": True, "error": "x"},
     "• no reply from the control daemon: contain (it may have been carried out; "
     "check the state before running it again)"),
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
    monkeypatch.setattr(webapp, "get_mode_state", lambda: {})
    body = webapp.app.test_client().get("/api/state/stream").get_data(as_text=True)
    names = [name for name, _ in _sse_events(body)]
    assert names == ["ready", "state", "stream_error"]
