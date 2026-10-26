"""Edge#471 stage 1 with real peer uids (Linux, root only).

The tests run the control daemon's and the agent's real socket handlers in
this process and connect from child processes that switch to other uids, so
the uid each handler sees comes from the kernel (SO_PEERCRED), not from a
stub. No account is created: the Web UI account is mapped to a free uid.
These run in CI's root steps or a throwaway container; a container is not a
device.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not (sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs root on Linux (switches the probe's uid)",
)

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from _control_daemon_inproc import InProcessControlDaemon, short_tmpdir  # noqa: E402
from azazel_edge_ai import agent as agent_mod  # noqa: E402
from azazel_edge_control import daemon as control_daemon  # noqa: E402

WEB_UID = 61001
OTHER_UID = 61002

_PROBE = r"""
import json, os, socket, sys
uid, gid, path, payload = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
os.setgroups([]); os.setgid(gid); os.setuid(uid)
out = {}
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(path)
except PermissionError:
    print(json.dumps({"connect": "denied"})); sys.exit(0)
try:
    s.sendall(payload.encode() + b"\n")
except BrokenPipeError:
    pass
buf = b""
while b"\n" not in buf:
    c = s.recv(65536)
    if not c:
        break
    buf += c
out["connect"] = "ok"
out["reply"] = json.loads(buf.decode().splitlines()[0]) if buf else None
try:
    open(os.path.join(os.path.dirname(path), "planted"), "w").close(); out["write_dir"] = "ok"
except OSError:
    out["write_dir"] = "denied"
print(json.dumps(out))
"""


def _probe(uid: int, gid: int, path: Path, payload: dict) -> dict:
    res = subprocess.run([sys.executable, "-I", "-c", _PROBE, str(uid), str(gid), str(path), json.dumps(payload)],
                         capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


@pytest.fixture
def web_is(monkeypatch):
    monkeypatch.setattr(control_daemon, "account_uid", lambda name: WEB_UID if name == "azazel-web" else None)
    monkeypatch.setattr(agent_mod, "account_uid", lambda name: WEB_UID if name == "azazel-web" else None)


@pytest.fixture
def daemon(tmp_path, monkeypatch):
    with InProcessControlDaemon(tmp_path / "sot.json", tmp_path / "sot-events.jsonl") as d:
        os.chmod(d.dir, 0o711)
        os.chmod(d.socket_path, 0o666)  # only the peer table decides here
        yield d


def test_control_sock_peer_table_with_real_uids(daemon, web_is):
    sock = daemon.socket_path
    before = control_daemon.peer_refusal_counts()["total"]
    # The Web UI account: its actions run (this one fails validation, so it
    # was not refused), migrate_path_schema does not.
    r = _probe(WEB_UID, WEB_UID, sock, {"action": "sot_devices_replace", "params": {"devices": "x"}})
    assert r["reply"]["error"] == "devices_must_be_list", r
    r = _probe(WEB_UID, WEB_UID, sock, {"action": "migrate_path_schema", "params": {"dry_run": True}})
    assert r["reply"] == {**r["reply"], "ok": False, "error": "forbidden", "reason": "root_only"}
    r = _probe(WEB_UID, WEB_UID, sock, {"action": "path_schema_status"})
    assert r["reply"]["error"] == "forbidden"
    # Any other account: nothing.
    for action in ("get_snapshot", "mode_status", "sot_devices_replace"):
        r = _probe(OTHER_UID, OTHER_UID, sock, {"action": action})
        assert r["reply"]["error"] == "forbidden" and r["reply"]["reason"] == "peer_not_allowed", (action, r)
    after = control_daemon.peer_refusal_counts()
    assert after["total"] == before + 5
    assert after["by_uid"][str(OTHER_UID)] >= 3


def test_control_sock_unknown_web_account_leaves_only_root(daemon, monkeypatch):
    monkeypatch.setattr(control_daemon, "account_uid", lambda name: None)
    r = _probe(WEB_UID, WEB_UID, daemon.socket_path, {"action": "mode_status"})
    assert r["reply"]["reason"] == "peer_not_allowed"


@pytest.fixture
def query_base():
    # Directly under /tmp: pytest's own tmp_path parents are 0700 root.
    base = short_tmpdir("azq")
    os.chmod(base, 0o711)
    try:
        yield base
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def query_socket(query_base, monkeypatch, web_is):
    tmp_path = query_base
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: (WEB_UID, WEB_UID))
    answered = []
    monkeypatch.setattr(agent_mod, "_handle_manual_query_request",
                        lambda req: answered.append(req) or {"ok": True, "action": "manual_query", "answer": "a"})
    for name in ("_handle_event", "_record_forward_stats", "_handle_request_line"):
        monkeypatch.setattr(agent_mod, name, lambda *a, **k: pytest.fail("reached a non-query path"))
    path = tmp_path / "agent-query" / "agent-query.sock"
    srv = agent_mod._setup_query_socket(path)
    assert srv is not None
    srv.listen(8)
    stop = threading.Event()
    t = threading.Thread(target=agent_mod._query_accept_loop, args=(srv, stop), daemon=True)
    t.start()
    try:
        yield path, answered
    finally:
        stop.set()
        t.join(5)
        srv.close()


MANUAL = {"action": "manual_query", "params": {"question": "state?", "source": "webui"}}


def test_query_socket_layout(query_socket):
    path, _ = query_socket
    d, s = os.lstat(path.parent), os.lstat(path)
    assert (d.st_uid, d.st_gid, stat.S_IMODE(d.st_mode)) == (0, WEB_UID, 0o750)
    assert (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (0, WEB_UID, 0o660)


def test_query_socket_answers_the_web_account(query_socket):
    path, answered = query_socket
    r = _probe(WEB_UID, WEB_UID, path, MANUAL)
    assert r["connect"] == "ok" and r["reply"]["ok"] is True
    assert r["write_dir"] == "denied"  # cannot plant or replace anything beside the socket
    assert len(answered) == 1


def test_query_socket_gives_the_web_account_nothing_but_manual_query(query_socket):
    path, answered = query_socket
    core_event = json.loads((ROOT / "tests" / "fixtures" / "rust_core_event_v1.json").read_text(encoding="utf-8"))
    for payload in (core_event, {"schema": "azazel-edge/forward-stats/v1", "dropped": 0, "failed": 0, "sent": 0,
                                 "since": 0}, {"action": "refresh"}):
        r = _probe(WEB_UID, WEB_UID, path, payload)
        assert r["reply"]["error"] == "forbidden", r
    assert answered == []


def test_query_socket_is_out_of_reach_for_other_accounts(query_socket):
    path, answered = query_socket
    assert _probe(OTHER_UID, OTHER_UID, path, MANUAL) == {"connect": "denied"}
    # Even with the socket's group but another uid, the agent refuses.
    r = _probe(OTHER_UID, WEB_UID, path, MANUAL)
    assert r["reply"] == {"ok": False, "error": "forbidden", "reason": "peer_not_allowed"}
    assert answered == []


def test_query_socket_answers_root(query_socket):
    path, answered = query_socket
    r = _probe(0, 0, path, MANUAL)
    assert r["reply"]["ok"] is True


def test_query_directory_owned_by_another_account_is_refused(query_base, monkeypatch, web_is, caplog):
    """The owner check alone: the directory has exactly the expected group
    and mode, only its owner is wrong; it is refused for that reason and
    left untouched."""
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: (WEB_UID, WEB_UID))
    d = query_base / "agent-query"
    d.mkdir()
    os.chown(d, WEB_UID, WEB_UID)
    os.chmod(d, 0o750)
    st = os.lstat(d)
    assert (st.st_gid, stat.S_IMODE(st.st_mode)) == (WEB_UID, agent_mod.QUERY_SOCKET_DIR_MODE)
    with caplog.at_level("ERROR"):
        assert agent_mod._setup_query_socket(d / "agent-query.sock") is None
    assert any(f"owned by uid {WEB_UID}" in r.getMessage() for r in caplog.records), caplog.text
    st = os.lstat(d)
    assert (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (WEB_UID, WEB_UID, 0o750)
    assert list(d.iterdir()) == []
