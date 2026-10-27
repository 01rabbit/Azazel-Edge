"""Edge#471 stage 1: the Web UI runs as the non-root account azazel-web.

Pinned here:
- control.sock: the daemon reads the peer's uid from the kernel and applies a
  fixed per-account action table (root / the daemon's own account: all;
  azazel-web: exactly what the Web UI sends; anyone else, an unknown peer or
  an account that does not resolve: nothing, counted); migrate_path_schema
  is root only.
- the daemon's fixed operations moved from the Web UI: uplink_disconnect
  (no arguments, the daemon's own uplink, failures returned) and
  sot_devices_replace / sot_devices_patch (validated with SoTConfig before an
  atomic write; the daemon is the only SoT writer).
- the agent's manual_query socket: only root or azazel-web, only
  manual_query, nothing reaches the event / forward-stats / P0 paths.
- the Web UI: no `ip`, no `docker`, its own state directories, no /tmp
  fallbacks, visible token and runbook failures.
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
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from _control_daemon_inproc import InProcessControlDaemon, short_tmpdir  # noqa: E402
from azazel_edge import peercred  # noqa: E402
from azazel_edge_ai import agent as agent_mod  # noqa: E402
from azazel_edge_control import daemon as control_daemon  # noqa: E402

import azazel_edge_web.app as webapp  # noqa: E402

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
OWN_UID = os.geteuid()
WEB_UID = 54321 if OWN_UID != 54321 else 54322  # a uid that is neither root nor this process
OTHER_UID = WEB_UID + 1


@pytest.fixture
def tmpdir_short():
    path = short_tmpdir("azw")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def web_account(monkeypatch):
    """azazel-web resolves to WEB_UID (in both the daemon and the agent)."""
    monkeypatch.setattr(control_daemon, "account_uid", lambda name: WEB_UID if name == "azazel-web" else None)
    monkeypatch.setattr(agent_mod, "account_uid", lambda name: WEB_UID if name == "azazel-web" else None)


@pytest.fixture
def no_web_account(monkeypatch):
    monkeypatch.setattr(control_daemon, "account_uid", lambda name: None)
    monkeypatch.setattr(agent_mod, "account_uid", lambda name: None)


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    control_daemon.last_action_time.clear()
    yield
    control_daemon.last_action_time.clear()


# ------------------------------------------------------------ the peer table

# What the Web UI sends on control.sock today, from its own code: the HTTP
# action list (disconnect goes as uplink_disconnect), plus control_plane's
# snapshot reads, plus the fixed operations of stage 1. contain, release and
# stage_open are not Web UI actions (Edge#477: the port 8082 status API they
# went to has no provider for this device).
NOT_WEB_ACTIONS = {"contain", "release", "stage_open", "portal_viewer_open"}
EXPECTED_WEB_ACTIONS = (
    (set(webapp.ALLOWED_ACTIONS) - {"disconnect"})
    | {"get_snapshot", "watch_snapshot"}
    | {"uplink_disconnect", "sot_devices_replace", "sot_devices_patch"}
)


def test_the_web_ui_action_set_is_exactly_what_the_web_ui_sends():
    assert set(control_daemon.WEB_UI_ACTIONS) == EXPECTED_WEB_ACTIONS
    assert set(webapp.INTERNAL_CONTROL_ACTIONS) <= set(control_daemon.WEB_UI_ACTIONS)
    assert "migrate_path_schema" not in control_daemon.WEB_UI_ACTIONS
    assert control_daemon.ROOT_ONLY_ACTIONS == frozenset({"migrate_path_schema"})


def test_removed_actions_never_reach_the_socket(monkeypatch):
    sent = []
    monkeypatch.setattr(webapp, "_send_control_command_socket",
                        lambda action, params=None, timeout_sec=5.0: sent.append(action) or {"ok": True})
    assert not (NOT_WEB_ACTIONS & set(webapp.ALLOWED_ACTIONS))
    for action in sorted(NOT_WEB_ACTIONS):
        res = webapp.send_control_command(action)
        assert res["ok"] is False and res["error"] == "Unknown action"
    assert sent == []


@pytest.mark.parametrize("action", sorted(EXPECTED_WEB_ACTIONS))
def test_web_uid_gets_its_actions(web_account, action):
    assert control_daemon.peer_action_allowed(WEB_UID, action) == (True, "web_ui")


@pytest.mark.parametrize("action", ["migrate_path_schema", "path_schema_status", "mode_apply_default",
                                    "contain", "disconnect", "stage_open", "release", "portal_viewer_open",
                                    "anything_else", None, 7])
def test_web_uid_is_refused_everything_else(web_account, action):
    allowed, _rule = control_daemon.peer_action_allowed(WEB_UID, action)
    assert allowed is False


@pytest.mark.parametrize("action", sorted(EXPECTED_WEB_ACTIONS | {"path_schema_status", "mode_apply_default"}))
def test_root_gets_every_action(web_account, action):
    assert control_daemon.peer_action_allowed(0, action) == (True, "root")


def test_migrate_path_schema_is_root_only(web_account):
    assert control_daemon.peer_action_allowed(0, "migrate_path_schema") == (True, "root_only")
    for uid in (WEB_UID, OTHER_UID):
        assert control_daemon.peer_action_allowed(uid, "migrate_path_schema")[0] is False
    if OWN_UID != 0:
        # Not even the daemon's own (non-root, development) account.
        assert control_daemon.peer_action_allowed(OWN_UID, "migrate_path_schema")[0] is False


@pytest.mark.parametrize("action", ["get_snapshot", "mode_status", "wifi_connect", "sot_devices_replace"])
def test_any_other_uid_is_refused(web_account, action):
    assert control_daemon.peer_action_allowed(OTHER_UID, action) == (False, "peer_not_allowed")


def test_an_unknown_peer_is_refused(web_account):
    assert control_daemon.peer_action_allowed(None, "get_snapshot") == (False, "peer_uid_unknown")


def test_an_unresolvable_web_account_leaves_only_root(no_web_account):
    assert control_daemon.peer_action_allowed(WEB_UID, "get_snapshot")[0] is False
    assert control_daemon.peer_action_allowed(0, "get_snapshot")[0] is True


def test_nothing_in_the_table_comes_from_the_environment_or_the_request():
    src = (ROOT / "py" / "azazel_edge_control" / "daemon.py").read_text(encoding="utf-8")
    block = src[src.index("def peer_action_allowed"):src.index("def _count_refusal")]
    assert "environ" not in block and "params" not in block and "request" not in block


def _request(conn_factory, payload: dict | bytes) -> dict:
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with client:
        t = threading.Thread(target=control_daemon.handle_client, args=(server, None), daemon=True)
        t.start()
        data = payload if isinstance(payload, bytes) else (json.dumps(payload) + "\n").encode("utf-8")
        try:
            client.sendall(data)
        except BrokenPipeError:
            pass  # a peer with no action is answered before its request is read
        client.settimeout(10)
        buf = b""
        while b"\n" not in buf:
            chunk = client.recv(65536)
            if not chunk:
                break
            buf += chunk
        t.join(10)
    return json.loads(buf.decode("utf-8").splitlines()[0])


def _as_peer(monkeypatch, uid):
    monkeypatch.setattr(control_daemon, "peer_credentials", lambda conn: (uid, 4242))


def test_a_refused_peer_gets_forbidden_is_counted_and_nothing_runs(monkeypatch, web_account):
    ran = []
    monkeypatch.setattr(control_daemon, "execute_action", lambda *a, **k: ran.append(a) or {"ok": True})
    _as_peer(monkeypatch, OTHER_UID)
    before = control_daemon.peer_refusal_counts()
    reply = _request(None, {"action": "mode_status"})
    assert reply["ok"] is False and reply["error"] == "forbidden" and reply["reason"] == "peer_not_allowed"
    after = control_daemon.peer_refusal_counts()
    assert after["total"] == before["total"] + 1
    assert after["by_uid"][str(OTHER_UID)] == before["by_uid"].get(str(OTHER_UID), 0) + 1
    assert ran == []


def test_the_web_uid_is_refused_migrate_path_schema_over_the_socket(monkeypatch, web_account):
    ran = []
    monkeypatch.setattr(control_daemon, "execute_action", lambda *a, **k: ran.append(a) or {"ok": True})
    _as_peer(monkeypatch, WEB_UID)
    reply = _request(None, {"action": "migrate_path_schema", "params": {"dry_run": True}})
    assert reply["error"] == "forbidden" and reply["reason"] == "root_only"
    assert ran == []


def test_the_web_uid_reaches_an_allowed_action_over_the_socket(monkeypatch, web_account):
    seen = []
    monkeypatch.setattr(control_daemon, "execute_action",
                        lambda action, params=None, **k: seen.append((action, k.get("peer_uid"))) or {"ok": True})
    _as_peer(monkeypatch, WEB_UID)
    assert _request(None, {"action": "mode_status"}) == {"ok": True}
    assert seen == [("mode_status", WEB_UID)]


def test_watch_snapshot_is_checked_before_streaming(monkeypatch, web_account):
    monkeypatch.setattr(control_daemon, "stream_ui_snapshots", lambda *a, **k: pytest.fail("streamed"))
    _as_peer(monkeypatch, OTHER_UID)
    assert _request(None, {"action": "watch_snapshot"})["error"] == "forbidden"


def test_a_peer_the_kernel_cannot_identify_is_refused(monkeypatch, web_account):
    monkeypatch.setattr(control_daemon, "execute_action", lambda *a, **k: pytest.fail("ran"))
    _as_peer(monkeypatch, None)
    assert _request(None, {"action": "get_snapshot"})["reason"] == "peer_uid_unknown"


def test_requests_larger_than_one_read_are_read_whole(monkeypatch):
    seen = []
    monkeypatch.setattr(control_daemon, "execute_action",
                        lambda action, params=None, **k: seen.append(len(params["devices"])) or {"ok": True})
    _as_peer(monkeypatch, 0)
    devices = [{"id": f"d{i}", "note": "x" * 200} for i in range(200)]  # ~50 KiB
    assert _request(None, {"action": "sot_devices_replace", "params": {"devices": devices}}) == {"ok": True}
    assert seen == [200]


def test_an_oversized_request_is_refused(monkeypatch):
    monkeypatch.setattr(control_daemon, "MAX_REQUEST_BYTES", 1024)
    monkeypatch.setattr(control_daemon, "execute_action", lambda *a, **k: pytest.fail("ran"))
    _as_peer(monkeypatch, 0)
    reply = _request(None, ('{"action": "sot_devices_replace", "params": {"devices": ["' + "x" * 4096).encode())
    assert reply["error"] == "Request too large"


def test_the_kernel_reports_this_process_as_the_peer():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with a, b:
        uid, pid = peercred.peer_credentials(b)
    assert uid == OWN_UID
    if sys.platform.startswith("linux"):
        assert pid == os.getpid()


def test_account_uid_resolves_root_and_not_a_missing_account():
    assert peercred.account_uid("root") == 0
    assert peercred.account_uid("azazel-no-such-account-471") is None


# ------------------------------------------------- SoT edits in the daemon

def _sot_doc() -> dict:
    return {
        "devices": [{"id": "dev-1", "hostname": "c1", "ip": "172.16.0.10", "mac": "aa:bb:cc:dd:ee:10",
                     "criticality": "normal", "allowed_networks": ["lan-main"]}],
        "networks": [{"id": "lan-main", "cidr": "172.16.0.0/24", "zone": "lan", "gateway": "172.16.0.1"}],
        "services": [{"id": "svc-dns", "proto": "udp", "port": 53, "owner": "noc", "exposure": "internal"}],
        "expected_paths": [{"src": "lan-main", "dst": "wan", "service_id": "svc-dns", "via": "edge",
                            "policy": "allow"}],
    }


@pytest.fixture
def sot(monkeypatch, tmp_path):
    path = tmp_path / "sot.json"
    path.write_text(json.dumps(_sot_doc()), encoding="utf-8")
    audit = tmp_path / "log" / "sot-events.jsonl"
    monkeypatch.setenv("AZAZEL_SOT_PATH", str(path))
    monkeypatch.setattr(control_daemon, "SOT_AUDIT_LOG", audit)
    return path, audit


NEW_DEVICE = {"id": "dev-2", "hostname": "c2", "ip": "172.16.0.20", "mac": "aa:bb:cc:dd:ee:20",
              "criticality": "high", "allowed_networks": ["lan-main"]}


def test_replace_validates_and_writes_atomically(sot):
    path, audit = sot
    res = control_daemon.execute_action("sot_devices_replace", {"devices": [NEW_DEVICE],
                                                                "requested_by": {"actor": "op:alice"}}, peer_uid=WEB_UID)
    assert res["ok"] is True and res["diff"] == {"added": 1, "removed": 1, "updated": 0}
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert [d["id"] for d in saved["devices"]] == ["dev-2"]
    assert saved["networks"] == _sot_doc()["networks"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert [p.name for p in path.parent.iterdir() if p.name.endswith(".tmp")] == []
    row = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    assert row["kind"] == "sot_devices_replaced" and row["peer_uid"] == WEB_UID and row["actor"] == "op:alice"


def test_patch_merges_by_id(sot):
    path, _audit = sot
    res = control_daemon.execute_action("sot_devices_patch", {"devices": [{"id": "dev-1", "hostname": "renamed"}]})
    assert res["ok"] is True and res["diff"]["updated"] == 1
    dev = json.loads(path.read_text(encoding="utf-8"))["devices"][0]
    assert dev["hostname"] == "renamed" and dev["ip"] == "172.16.0.10"


@pytest.mark.parametrize("kind,params,error", [
    ("sot_devices_replace", {"devices": [{"id": "broken"}]}, "invalid_sot:"),
    ("sot_devices_replace", {"devices": "dev-1"}, "devices_must_be_list"),
    ("sot_devices_replace", {}, "devices_must_be_list"),
    ("sot_devices_replace", {"devices": [], "path": "/etc/shadow"}, "unexpected_params:path"),
    ("sot_devices_replace", ["not", "an", "object"], "params_must_be_object"),
    ("sot_devices_patch", {"devices": ["x"]}, "device_item_must_be_object"),
    ("sot_devices_patch", {"devices": [{"hostname": "no-id"}]}, "device_id_required"),
    ("sot_devices_patch", {"devices": [{"id": "dev-1", "ip": 5, "allowed_networks": "lan"}]}, "invalid_sot:"),
])
def test_invalid_edits_write_nothing(sot, kind, params, error):
    path, audit = sot
    before = path.read_bytes()
    res = control_daemon.execute_action(kind, params)
    assert res["ok"] is False and str(res["error"]).startswith(error), res
    assert path.read_bytes() == before
    assert not audit.exists()


def test_an_unreadable_sot_is_never_replaced_by_a_default(sot):
    path, audit = sot
    path.write_text("{not json", encoding="utf-8")
    res = control_daemon.execute_action("sot_devices_replace", {"devices": [NEW_DEVICE]})
    assert res["ok"] is False and res["error"].startswith("sot_unreadable")
    assert path.read_text(encoding="utf-8") == "{not json"


def test_a_failed_write_leaves_the_old_file_and_no_temporary(sot, monkeypatch):
    path, audit = sot
    before = path.read_bytes()

    def boom(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(control_daemon.os, "replace", boom)
    res = control_daemon.execute_action("sot_devices_replace", {"devices": [NEW_DEVICE]})
    assert res["ok"] is False and res["error"].startswith("sot_write_failed")
    assert path.read_bytes() == before
    assert [p.name for p in path.parent.iterdir() if p.name != "sot.json" and p.name != "log"] == []
    assert not audit.exists()


def test_yaml_sot_round_trip(monkeypatch, tmp_path):
    yaml = pytest.importorskip("yaml")
    path = tmp_path / "sot.yaml"
    path.write_text(yaml.safe_dump(_sot_doc()), encoding="utf-8")
    monkeypatch.setenv("AZAZEL_SOT_PATH", str(path))
    monkeypatch.setattr(control_daemon, "SOT_AUDIT_LOG", tmp_path / "a.jsonl")
    assert control_daemon.execute_action("sot_devices_patch", {"devices": [NEW_DEVICE]})["ok"] is True
    assert {d["id"] for d in yaml.safe_load(path.read_text(encoding="utf-8"))["devices"]} == {"dev-1", "dev-2"}


# ------------------------------------------------ uplink_disconnect

@pytest.fixture
def fake_net(monkeypatch, tmp_path):
    sysnet = tmp_path / "sys-class-net"
    (sysnet / "upl0").mkdir(parents=True)
    calls = tmp_path / "ip-calls.txt"
    ip = tmp_path / "ip"
    ip.write_text("#!/bin/sh\necho \"$@\" >> " + str(calls) + "\n"
                  "if [ -n \"$FAKE_IP_FAIL\" ]; then echo 'RTNETLINK answers: Operation not permitted' >&2; exit 2; fi\n",
                  encoding="utf-8")
    ip.chmod(0o755)
    monkeypatch.setattr(control_daemon, "SYS_CLASS_NET", sysnet)
    monkeypatch.setattr(control_daemon, "IP_COMMAND_CANDIDATES", (str(ip),))
    monkeypatch.setenv("AZAZEL_UP_IF", "upl0")
    # No internal LAN here (the daemon fails closed when it cannot tell; that
    # is tested in test_pi5_platform_layer_v1.py).
    monkeypatch.setattr(control_daemon, "internal_lan_interfaces", lambda *a, **kw: set())
    return calls


def test_uplink_disconnect_sets_the_configured_uplink_down(fake_net):
    res = control_daemon.execute_action("uplink_disconnect", None, request={"action": "uplink_disconnect", "ts": 1})
    assert res["ok"] is True and res["interface"] == "upl0"
    assert fake_net.read_text(encoding="utf-8").split() == ["link", "set", "dev", "upl0", "down"]


@pytest.mark.parametrize("request_", [
    {"action": "uplink_disconnect", "params": {"interface": "eth9"}},
    {"action": "uplink_disconnect", "params": {"iface": "upl0"}},
    {"action": "uplink_disconnect", "params": ["upl0"]},
    {"action": "uplink_disconnect", "params": "upl0"},
    {"action": "uplink_disconnect", "interface": "eth9"},
])
def test_uplink_disconnect_accepts_no_arguments(fake_net, request_):
    res = control_daemon.execute_action("uplink_disconnect", request_.get("params"), request=request_)
    assert res == {**res, "ok": False, "error": "uplink_disconnect_takes_no_parameters"}
    assert not fake_net.exists()


@pytest.mark.parametrize("value", ["../eth0", "eth0;reboot", "-x", "a" * 16, "", "..", "eth 0"])
def test_uplink_disconnect_refuses_an_implausible_configured_name(fake_net, monkeypatch, value):
    monkeypatch.setenv("AZAZEL_UP_IF", value)
    res = control_daemon.execute_action("uplink_disconnect", None, request={"action": "uplink_disconnect"})
    assert res["ok"] is False and res["error"] == "uplink_interface_config_invalid"
    assert not fake_net.exists()


def test_uplink_disconnect_reports_a_missing_interface(fake_net, monkeypatch):
    monkeypatch.setenv("AZAZEL_UP_IF", "nosuch0")
    res = control_daemon.execute_action("uplink_disconnect", None, request={"action": "uplink_disconnect"})
    assert res["ok"] is False and res["error"] == "uplink_interface_not_found:nosuch0"
    assert not fake_net.exists()


def test_uplink_disconnect_reports_the_command_failure(fake_net, monkeypatch):
    monkeypatch.setenv("FAKE_IP_FAIL", "1")
    res = control_daemon.execute_action("uplink_disconnect", None, request={"action": "uplink_disconnect"})
    assert res["ok"] is False and "Operation not permitted" in res["error"]


def test_the_web_ui_disconnect_uses_the_daemon_and_shows_its_failure(monkeypatch, tmp_path):
    sent = []

    def fake(action, params=None, timeout_sec=5.0):
        sent.append((action, params))
        return {"ok": False, "error": "uplink_interface_not_found:wlan0"}

    monkeypatch.setattr(webapp, "_send_control_command_socket", fake)
    res = webapp.execute_disconnect_action()
    assert sent == [("uplink_disconnect", None)]
    assert res["ok"] is False and "uplink_interface_not_found" in res["error"]
    monkeypatch.setattr(webapp, "_send_control_command_socket",
                        lambda action, params=None, timeout_sec=5.0: {"ok": True, "message": "Uplink disconnected"})
    assert webapp.execute_disconnect_action()["ok"] is True


def test_the_web_ui_disconnect_end_to_end_failure_is_a_500(monkeypatch, tmp_path):
    """Web UI -> real control.sock -> daemon: no such uplink -> HTTP 500 with the reason."""
    monkeypatch.setattr(webapp, "load_token", lambda: None)
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    monkeypatch.setenv("AZAZEL_UP_IF", "nosuch0")
    with InProcessControlDaemon(tmp_path / "sot.json", tmp_path / "sot-events.jsonl") as daemon:
        monkeypatch.setattr(webapp, "CONTROL_SOCKET", daemon.socket_path)
        resp = webapp.app.test_client().post("/api/action/disconnect")
    assert resp.status_code == 500
    assert "uplink_interface_not_found:nosuch0" in resp.get_json()["error"]


def test_the_web_ui_runs_neither_ip_nor_docker():
    src = (ROOT / "azazel_edge_web" / "app.py").read_text(encoding="utf-8")
    assert '"ip", "link"' not in src and "'ip', 'link'" not in src
    assert '"docker"' not in src and "'docker'" not in src


def test_monitoring_state_does_not_call_docker(monkeypatch):
    argv_seen = []

    def fake_run(argv, *a, **k):
        argv_seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 3, "", "")

    monkeypatch.setattr(webapp, "_dev_healthy_baseline", lambda: False)
    monkeypatch.setattr(webapp.subprocess, "run", fake_run)
    monkeypatch.setattr(webapp, "_ntfy_health_ok", lambda: False)
    state = webapp.get_monitoring_state()
    assert all(a[0] != "docker" for a in argv_seen), argv_seen
    assert state["container_check"] == "not_checked"
    assert state["opencanary"] == "OFF" and state["suricata"] == "OFF"


# ------------------------------------------------ the agent's query socket

def test_query_peers_are_root_and_the_web_account_only(web_account):
    assert agent_mod.query_peer_allowed(0) is True
    assert agent_mod.query_peer_allowed(WEB_UID) is True
    assert agent_mod.query_peer_allowed(OTHER_UID) is False
    assert agent_mod.query_peer_allowed(None) is False


def test_query_peers_without_the_web_account_are_root_only(no_web_account):
    assert agent_mod.query_peer_allowed(0) is True
    assert agent_mod.query_peer_allowed(WEB_UID) is False


def _query(monkeypatch, uid, payload) -> dict:
    monkeypatch.setattr(agent_mod, "peer_credentials", lambda conn: (uid, 777))
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with a:
        t = threading.Thread(target=agent_mod._handle_query_client, args=(b,), daemon=True)
        t.start()
        try:
            a.sendall(payload if isinstance(payload, bytes) else (json.dumps(payload) + "\n").encode("utf-8"))
        except BrokenPipeError:
            pass  # a refused peer is answered before its request is read
        a.settimeout(10)
        buf = b""
        while b"\n" not in buf:
            chunk = a.recv(65536)
            if not chunk:
                break
            buf += chunk
        t.join(10)
    return json.loads(buf.decode("utf-8").splitlines()[0])


@pytest.fixture
def agent_paths(monkeypatch):
    """Every path other than manual_query fails the test if reached."""
    answered = []
    monkeypatch.setattr(agent_mod, "_handle_manual_query_request",
                        lambda req: answered.append(req) or {"ok": True, "action": "manual_query", "answer": "x"})
    for name in ("_handle_event", "_record_forward_stats", "_handle_request_line"):
        monkeypatch.setattr(agent_mod, name, lambda *a, **k: pytest.fail("reached a non-query path"))
    return answered


MANUAL = {"action": "manual_query", "params": {"question": "state?", "sender": "op", "source": "webui", "context": {}}}


@pytest.mark.parametrize("uid", [0, WEB_UID])
def test_the_query_socket_answers_manual_query(monkeypatch, web_account, agent_paths, uid):
    assert _query(monkeypatch, uid, MANUAL)["ok"] is True
    assert agent_paths and agent_paths[0]["params"]["question"] == "state?"


def test_the_query_socket_refuses_other_peers(monkeypatch, web_account, agent_paths):
    reply = _query(monkeypatch, OTHER_UID, MANUAL)
    assert reply == {"ok": False, "error": "forbidden", "reason": "peer_not_allowed"}
    assert agent_paths == []


@pytest.mark.parametrize("payload", [
    json.loads((ROOT / "tests" / "fixtures" / "rust_core_event_v1.json").read_text(encoding="utf-8")),
    {"schema": "azazel-edge/forward-stats/v1", "dropped": 0, "failed": 0, "sent": 1, "since": 0},
    {"action": "manual_query", "schema": "azazel-edge/forward-stats/v1"},
    {"action": "MANUAL_QUERY"},
    {"action": "refresh"},
    ["manual_query"],
])
def test_the_query_socket_accepts_nothing_but_manual_query(monkeypatch, web_account, agent_paths, payload):
    reply = _query(monkeypatch, WEB_UID, payload)
    assert reply["ok"] is False and reply["error"] == "forbidden"
    assert agent_paths == []


def test_the_query_socket_refuses_garbage_and_oversize(monkeypatch, web_account, agent_paths):
    assert _query(monkeypatch, WEB_UID, b"{not json\n")["reason"] == "invalid_request"
    monkeypatch.setattr(agent_mod, "QUERY_MAX_REQUEST_BYTES", 64)
    assert _query(monkeypatch, WEB_UID, b'{"action": "manual_query", "x": "' + b"a" * 200)["reason"] == "request_too_large"
    assert agent_paths == []


def test_the_query_socket_is_not_created_without_the_web_account(monkeypatch, tmpdir_short):
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: None)
    assert agent_mod._setup_query_socket(tmpdir_short / "q" / "agent-query.sock") is None
    assert not (tmpdir_short / "q").exists()


def test_the_query_socket_directory_and_socket_modes(monkeypatch, tmpdir_short):
    gid = os.getegid()
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: (WEB_UID, gid))
    path = tmpdir_short / "q" / "agent-query.sock"
    srv = agent_mod._setup_query_socket(path)
    assert srv is not None
    try:
        dst = os.lstat(path.parent)
        assert stat.S_IMODE(dst.st_mode) == 0o750 and dst.st_gid == gid and dst.st_uid == OWN_UID
        sst = os.lstat(path)
        assert stat.S_ISSOCK(sst.st_mode) and stat.S_IMODE(sst.st_mode) == 0o660 and sst.st_gid == gid
    finally:
        srv.close()


def test_the_query_socket_refuses_a_symlinked_directory(monkeypatch, tmpdir_short):
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: (WEB_UID, os.getegid()))
    real = tmpdir_short / "elsewhere"
    real.mkdir()
    real.chmod(0o777)
    (tmpdir_short / "q").symlink_to(real)
    assert agent_mod._setup_query_socket(tmpdir_short / "q" / "agent-query.sock") is None
    assert stat.S_IMODE(real.stat().st_mode) == 0o777  # untouched through the link
    assert list(real.iterdir()) == []


def test_the_query_socket_refuses_a_non_socket_at_the_path(monkeypatch, tmpdir_short):
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: (WEB_UID, os.getegid()))
    (tmpdir_short / "q").mkdir()
    (tmpdir_short / "q" / "agent-query.sock").write_text("x", encoding="utf-8")
    assert agent_mod._setup_query_socket(tmpdir_short / "q" / "agent-query.sock") is None


def test_the_web_ui_defaults_to_the_query_socket():
    src = (ROOT / "azazel_edge_web" / "app.py").read_text(encoding="utf-8")
    assert 'os.environ.get("AZAZEL_AI_SOCKET", "/run/azazel-edge-agent-query/agent-query.sock")' in src
    agent_src = (ROOT / "py" / "azazel_edge_ai" / "agent.py").read_text(encoding="utf-8")
    assert 'os.environ.get("AZAZEL_AI_QUERY_SOCKET", "/run/azazel-edge-agent-query/agent-query.sock")' in agent_src


def test_ai_bridge_refuses_manual_query_once_the_query_socket_listens(monkeypatch):
    answered = []
    monkeypatch.setattr(agent_mod, "_handle_manual_query_request", lambda req: answered.append(req) or {"ok": True})
    monkeypatch.setattr(agent_mod, "_handle_event", lambda payload: pytest.fail("a query became an event"))
    line = json.dumps(MANUAL)
    assert agent_mod._handle_request_line(line) == {"ok": True}  # no query socket (e.g. no azazel-web account)
    agent_mod.QUERY_SOCKET_ACTIVE.set()
    try:
        reply = agent_mod._handle_request_line(line)
    finally:
        agent_mod.QUERY_SOCKET_ACTIVE.clear()
    assert reply == {"ok": False, "action": "manual_query", "error": "forbidden",
                     "reason": "manual_query_moved_to_query_socket"}
    assert len(answered) == 1


@pytest.mark.parametrize("mode,gid_delta", [(0o770, 0), (0o755, 0), (0o700, 0), (0o750, 1)])
def test_an_existing_query_directory_is_refused_not_fixed(monkeypatch, tmpdir_short, mode, gid_delta):
    own_gid = os.getegid()
    groups = [g for g in os.getgroups() if g != own_gid] or ([own_gid + 4242] if IS_ROOT else [])
    if gid_delta and not groups:
        pytest.skip("no second group to own the directory")
    want_gid = own_gid
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: (WEB_UID, want_gid))
    d = tmpdir_short / "q"
    d.mkdir()
    if gid_delta:
        os.chown(d, -1, groups[0])
    d.chmod(mode)
    before = os.lstat(d)
    assert agent_mod._setup_query_socket(d / "agent-query.sock") is None
    after = os.lstat(d)
    assert (after.st_mode, after.st_gid) == (before.st_mode, before.st_gid)
    assert list(d.iterdir()) == []


@pytest.mark.parametrize("route,body", [
    ("/api/ai/ask", {"question": "What is the current state?"}),
    ("/api/mattermost/command", None),
])
def test_ai_routes_reach_the_query_socket(monkeypatch, web_account, tmpdir_short, route, body):
    """B1: /api/ai/ask and the Mattermost command go through the query socket
    (a real socket served by the agent's query handler)."""
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: (WEB_UID, os.getegid()))
    monkeypatch.setattr(agent_mod, "account_uid", lambda name: OWN_UID if name == "azazel-web" else None)
    monkeypatch.setattr(agent_mod, "_handle_manual_query_request",
                        lambda req: {"ok": True, "action": "manual_query", "status": "completed",
                                     "answer": "via-query-socket", "user_message": "via-query-socket"})
    path = tmpdir_short / "q" / "agent-query.sock"
    srv = agent_mod._setup_query_socket(path)
    assert srv is not None
    srv.listen(4)
    stop = threading.Event()
    t = threading.Thread(target=agent_mod._query_accept_loop, args=(srv, stop), daemon=True)
    t.start()
    try:
        monkeypatch.setattr(webapp, "AI_SOCKET", path)  # the Web UI's default is this socket's real path
        monkeypatch.setattr(webapp, "load_token", lambda: None)
        monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
        monkeypatch.setattr(webapp, "MATTERMOST_COMMAND_TOKENS", ["cmd-token"])
        client = webapp.app.test_client()
        if route == "/api/ai/ask":
            resp = client.post(route, json=body)
        else:
            resp = client.post(route, data={"token": "cmd-token", "text": "state?", "user_name": "op"})
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert "via-query-socket" in resp.get_data(as_text=True)
    finally:
        stop.set()
        t.join(5)
        srv.close()


# ------------------------------------------------ the Web UI's own state

def test_web_state_defaults_are_its_own_directories():
    assert webapp.WEB_RUNTIME_DIR == Path("/run/azazel-edge-web")
    assert webapp.WEB_LOG_DIR == Path("/var/log/azazel-edge-web")
    assert webapp.WEB_STATE_DIR == Path("/var/lib/azazel-edge-web")
    src = (ROOT / "azazel_edge_web" / "app.py").read_text(encoding="utf-8")
    for var, default in [
        ("AZAZEL_RUNBOOK_EVENT_LOG", 'str(WEB_LOG_DIR / "runbook-events.jsonl")'),
        ("AZAZEL_TRIAGE_AUDIT_PATH", 'str(WEB_LOG_DIR / "triage-audit.jsonl")'),
        ("AZAZEL_TOPOLITE_SEED_MODE_PATH", 'str(WEB_RUNTIME_DIR / "topolite_seed_mode.json")'),
        ("AZAZEL_TRIAGE_SESSION_DIR", 'str(WEB_RUNTIME_DIR / "triage-sessions")'),
        ("AZAZEL_OPERATOR_PROGRESS_PATH", 'str(WEB_RUNTIME_DIR / "operator-progress.json")'),
        ("AZAZEL_DASHBOARD_TRENDS_PATH", 'str(WEB_RUNTIME_DIR / "dashboard-trends.jsonl")'),
    ]:
        assert f'os.environ.get("{var}", {default})' in src, var
    assert 'or str(WEB_LOG_DIR / "authz-events.jsonl")' in src
    assert 'or str(WEB_LOG_DIR / "aggregator-events.jsonl")' in src
    assert 'or str(WEB_STATE_DIR / "captive-allowlist.json")' in src
    for name in ("triage/session.py", "triage/engine.py"):
        text = (ROOT / "py" / "azazel_edge" / name).read_text(encoding="utf-8")
        assert '"/tmp' not in text, name


def test_triage_never_falls_back_to_tmp(tmp_path, monkeypatch):
    from azazel_edge.triage import TriageFlowEngine, TriageSessionStore
    from azazel_edge.triage.session import TriageStorageError

    blocker = tmp_path / "file"
    blocker.write_text("", encoding="utf-8")
    with pytest.raises(TriageStorageError):
        TriageSessionStore(base_dir=blocker / "sessions")
    monkeypatch.setenv("AZAZEL_TRIAGE_AUDIT_PATH", str(blocker / "triage-audit.jsonl"))
    with pytest.raises(TriageStorageError):
        TriageFlowEngine(store=TriageSessionStore(base_dir=tmp_path / "s"))


def test_triage_unavailable_says_why(monkeypatch):
    monkeypatch.setattr(webapp, "_TRIAGE_ENGINE", None)
    monkeypatch.setattr(webapp, "_TRIAGE_STORE", None)
    monkeypatch.setattr(webapp, "_TRIAGE_UNAVAILABLE_REASON", "triage audit x is not writable: denied")
    monkeypatch.setattr(webapp, "load_token", lambda: None)
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    resp = webapp.app.test_client().post("/api/triage/start", json={"intent_id": "wifi_connectivity"})
    assert resp.status_code == 503
    assert resp.get_json() == {"ok": False, "error": "triage_unavailable",
                               "reason": "triage audit x is not writable: denied"}


# ------------------------------------------------ tokens

def test_a_missing_token_file_is_reported(tmp_path):
    assert webapp._read_secret_file(tmp_path / "absent", label="t471_missing") == ""
    assert webapp.SECRET_FILE_STATUS["t471_missing"] == "missing"


@pytest.mark.skipif(IS_ROOT, reason="root reads a 0000 file")
def test_an_unreadable_token_file_is_reported_and_blocks_the_command(tmp_path, monkeypatch, caplog):
    f = tmp_path / "token"
    f.write_text("secret-value-not-logged", encoding="utf-8")
    f.chmod(0)
    try:
        with caplog.at_level("ERROR"):
            assert webapp._read_secret_file(f, label="mattermost_command_token") == ""
        assert webapp.SECRET_FILE_STATUS["mattermost_command_token"] == "unreadable"
        assert any("unreadable" in r.getMessage() for r in caplog.records)
        assert all("secret-value-not-logged" not in r.getMessage() for r in caplog.records)
        monkeypatch.setattr(webapp, "MATTERMOST_COMMAND_TOKENS", [])
        resp = webapp.app.test_client().post("/api/mattermost/command", data={"token": "x", "text": "q"})
        assert resp.status_code == 503
        assert "not readable" in resp.get_json()["text"]
    finally:
        f.chmod(0o600)
        webapp.SECRET_FILE_STATUS.pop("mattermost_command_token", None)
        webapp._SECRET_FILE_LOGGED.pop("mattermost_command_token", None)


def test_a_readable_token_file_is_ok(tmp_path):
    f = tmp_path / "token"
    f.write_text("abc\n", encoding="utf-8")
    assert webapp._read_secret_file(f, label="t471_ok") == "abc"
    assert webapp.SECRET_FILE_STATUS["t471_ok"] == "ok"


# ------------------------------------------------ the restart runbook

def test_a_controlled_exec_failure_as_non_root_is_explicit(monkeypatch):
    from azazel_edge import runbooks

    monkeypatch.setenv("AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC", "1")
    monkeypatch.setattr(runbooks.os, "geteuid", lambda: 999)
    monkeypatch.setattr(runbooks.subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(
        argv, 1, "", "Failed to restart azazel-edge-web.service: Interactive authentication required.\n"))
    res = runbooks.execute_runbook("rb.noc.service.restart.controlled", args={"service": "azazel-edge-web"},
                                   dry_run=False, approved=True, allow_controlled_exec=True)
    assert res["ok"] is False and res["exit_code"] == 1
    assert res["error"].startswith("controlled_exec_failed_without_root:")
    assert "Interactive authentication required" in res["error"]


# ------------------------------------------------ the unit

def _unit() -> dict:
    out: dict = {}
    for line in (ROOT / "systemd" / "azazel-edge-web.service").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#") and not line.startswith("["):
            k, v = line.split("=", 1)
            out.setdefault(k, []).append(v)
    return out


def test_the_web_unit_is_non_root_and_hardened():
    u = _unit()
    assert u["User"] == ["azazel-web"] and u["Group"] == ["azazel-web"]
    assert u["SupplementaryGroups"] == ["azazel-control"]
    assert u["NoNewPrivileges"] == ["yes"]
    assert u["CapabilityBoundingSet"] == [""] and u["AmbientCapabilities"] == [""]
    assert u["ProtectSystem"] == ["strict"] and u["ProtectHome"] == ["yes"] and u["PrivateTmp"] == ["yes"]
    assert u["RestrictAddressFamilies"] == ["AF_UNIX AF_INET AF_INET6 AF_NETLINK"]
    for key in ("RuntimeDirectory", "StateDirectory", "LogsDirectory"):
        assert u[key] == ["azazel-edge-web"], key
    port_lines = [v for v in u["Environment"] if v.strip('"').startswith("AZAZEL_WEB_PORT=")]
    assert len(port_lines) == 1 and int(port_lines[0].strip('"').split("=")[1]) > 1024
    assert "SupplementaryGroups" in u and "docker" not in " ".join(u["SupplementaryGroups"])


def test_other_units_stay_root():
    # The AI agent runs as azazel-agent since Edge#471 stage 2.
    for name in ("azazel-edge-control-daemon.service", "azazel-edge-core.service"):
        text = (ROOT / "systemd" / name).read_text(encoding="utf-8")
        assert "\nUser=" not in text, name


def test_authz_audit_failures_are_counted_in_health(monkeypatch, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("", encoding="utf-8")
    monkeypatch.setattr(webapp, "AUTHZ_AUDIT_LOG", blocker / "authz-events.jsonl")
    monkeypatch.setattr(webapp, "load_token", lambda: None)
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    client = webapp.app.test_client()
    before = client.get("/health").get_json()["audit_write_failures"]["authz"]
    client.get("/api/dashboard/trends")
    after = client.get("/health").get_json()["audit_write_failures"]["authz"]
    assert after >= before + 1


# ------------------------------------------------ review follow-ups

def test_the_daemons_own_uid_is_treated_as_root_and_documented(web_account):
    # Under the unit the daemon is root, so this equals the root rule; it is
    # pinned so de-rooting the daemon (stage 3+) has to revisit it.
    assert control_daemon.peer_action_allowed(OWN_UID, "get_snapshot") == (True, "root")
    assert control_daemon.peer_action_allowed(OWN_UID, "path_schema_status") == (True, "root")
    src = (ROOT / "py" / "azazel_edge_control" / "daemon.py").read_text(encoding="utf-8")
    block = src[src.index("def peer_action_allowed"):src.index("def peer_may_connect")]
    assert "uid == os.geteuid()" in block and "stops running as root" in block


def _connect_pair_without_sending(monkeypatch, uid):
    _as_peer(monkeypatch, uid)
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    t = threading.Thread(target=control_daemon.handle_client, args=(server, None), daemon=True)
    t.start()
    return client, t


def test_a_peer_with_no_action_is_refused_before_anything_is_read(monkeypatch, web_account):
    monkeypatch.setattr(control_daemon, "_read_request", lambda *a, **k: pytest.fail("read before the peer check"))
    client, t = _connect_pair_without_sending(monkeypatch, OTHER_UID)
    with client:
        client.settimeout(5)
        reply = json.loads(client.recv(65536).decode().splitlines()[0])
    t.join(5)
    assert reply["error"] == "forbidden" and reply["reason"] == "peer_not_allowed"
    assert not t.is_alive()


def test_a_slow_request_hits_a_total_deadline(monkeypatch, web_account):
    monkeypatch.setattr(control_daemon, "REQUEST_READ_TIMEOUT_SEC", 0.6)
    monkeypatch.setattr(control_daemon, "execute_action", lambda *a, **k: pytest.fail("ran"))
    client, t = _connect_pair_without_sending(monkeypatch, WEB_UID)
    started = time.monotonic()
    with client:
        stop = _dribble(client)  # one byte every 0.2 s: each read is fast, the request never ends
        client.settimeout(5)
        reply = client.recv(65536).decode()
        elapsed = time.monotonic() - started
        stop.set()
    t.join(5)
    assert "Request timeout" in reply
    assert elapsed < 1.5, elapsed  # the total deadline (0.6 s), not a per-read timeout


def _dribble(conn) -> threading.Event:
    stop = threading.Event()

    def run():
        while not stop.is_set():
            try:
                conn.sendall(b" ")
            except OSError:
                return
            stop.wait(0.2)

    threading.Thread(target=run, daemon=True).start()
    return stop


def test_concurrent_control_clients_are_capped(monkeypatch):
    monkeypatch.setattr(control_daemon, "_CLIENT_SLOTS", control_daemon._ClientSlots(1, 1, 1))
    monkeypatch.setattr(control_daemon, "peer_credentials", lambda conn: (0, 1))
    release = threading.Event()
    monkeypatch.setattr(control_daemon, "handle_client", lambda conn, addr: (release.wait(5), conn.close()))
    a1, b1 = socket.socketpair()
    a2, b2 = socket.socketpair()
    with a1, a2:
        assert control_daemon._dispatch_client(b1, None) is True
        assert control_daemon._dispatch_client(b2, None) is False
        a2.settimeout(5)
        assert b'"busy"' in a2.recv(1024)
        release.set()


def test_concurrent_query_clients_are_capped(monkeypatch, web_account, tmpdir_short):
    monkeypatch.setattr(agent_mod, "_QUERY_SLOTS", threading.BoundedSemaphore(1))
    monkeypatch.setattr(agent_mod, "peer_credentials", lambda conn: (WEB_UID, 1))
    release = threading.Event()
    monkeypatch.setattr(agent_mod, "_handle_manual_query_request",
                        lambda req: release.wait(5) and {"ok": True, "action": "manual_query"})
    path = tmpdir_short / "q.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(4)
    stop = threading.Event()
    t = threading.Thread(target=agent_mod._query_accept_loop, args=(srv, stop), daemon=True)
    t.start()
    try:
        first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        first.connect(str(path))
        first.sendall((json.dumps(MANUAL) + "\n").encode())
        time.sleep(0.3)
        second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        second.connect(str(path))
        second.settimeout(5)
        assert b'"busy"' in second.recv(1024)
        release.set()
        first.settimeout(5)
        assert json.loads(first.recv(65536).decode().splitlines()[0])["ok"] is True
        first.close()
        second.close()
    finally:
        release.set()
        stop.set()
        t.join(5)
        srv.close()


def test_a_slow_query_hits_a_total_deadline(monkeypatch, web_account, agent_paths):
    monkeypatch.setattr(agent_mod, "QUERY_READ_TIMEOUT_SEC", 0.6)
    monkeypatch.setattr(agent_mod, "peer_credentials", lambda conn: (WEB_UID, 1))
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    t = threading.Thread(target=agent_mod._handle_query_client, args=(b,), daemon=True)
    t.start()
    started = time.monotonic()
    with a:
        stop = _dribble(a)
        a.settimeout(5)
        reply = a.recv(65536).decode()
        elapsed = time.monotonic() - started
        stop.set()
    t.join(5)
    assert "request_timeout" in reply and elapsed < 1.5, (reply, elapsed)
    assert agent_paths == []


def test_the_query_socket_is_bound_under_umask_0117(monkeypatch, tmpdir_short):
    import types

    seen = []

    class Recorder(socket.socket):
        def bind(self, address):
            mask = os.umask(0)
            os.umask(mask)
            seen.append(mask)
            return super().bind(address)

    monkeypatch.setattr(agent_mod, "socket", types.SimpleNamespace(
        socket=Recorder, AF_UNIX=socket.AF_UNIX, SOCK_STREAM=socket.SOCK_STREAM, timeout=socket.timeout))
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: (WEB_UID, os.getegid()))
    srv = agent_mod._setup_query_socket(tmpdir_short / "q" / "agent-query.sock")
    assert srv is not None
    srv.close()
    assert seen == [0o117]


def test_an_sot_rewrite_keeps_the_files_mode_and_group(sot):
    path, _audit = sot
    path.chmod(0o640)
    gid = path.stat().st_gid
    assert control_daemon.execute_action("sot_devices_patch", {"devices": [NEW_DEVICE]})["ok"] is True
    st = path.stat()
    assert stat.S_IMODE(st.st_mode) == 0o640 and st.st_gid == gid


def test_a_new_sot_file_is_not_world_readable_when_root_and_the_group_exists(monkeypatch, tmp_path):
    path = tmp_path / "new-sot.json"
    monkeypatch.setattr(control_daemon.os, "geteuid", lambda: 0)
    monkeypatch.setattr(control_daemon.grp, "getgrnam", lambda name: types_ns(gr_gid=os.getegid()))
    assert control_daemon._sot_file_mode_and_group(path) == (0o640, os.getegid())
    monkeypatch.setattr(control_daemon.grp, "getgrnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
    assert control_daemon._sot_file_mode_and_group(path) == (0o644, None)


def types_ns(**kw):
    import types
    return types.SimpleNamespace(**kw)


def test_wazuh_fim_watches_the_web_ui_directories():
    src = (ROOT / "installer" / "internal" / "install_wazuh_agent.sh").read_text(encoding="utf-8")
    block = src[src.index("azazel_dirs = ["):src.index("]", src.index("azazel_dirs = ["))]
    for d in ("'/var/log/azazel-edge-web'", "'/var/lib/azazel-edge-web'", "'/etc/azazel-edge'"):
        assert d in block, d


def test_the_installer_never_widens_etc_azazel_edge():
    internal = ROOT / "installer" / "internal"
    for script in internal.glob("*.sh"):
        text = script.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "/etc/azazel-edge" not in stripped:
                continue
            assert "chmod 0755 /etc/azazel-edge" not in stripped, (script.name, line)
            if stripped.startswith("install -d") and "/etc/azazel-edge " in stripped + " " \
                    and not stripped.startswith("install -d /etc/azazel-edge/"):
                pytest.fail(f"{script.name}: unconditional install -d resets the mode: {line}")
    assert 'chmod 0600 "$CA_KEY"' in (internal / "install_local_ca.sh").read_text(encoding="utf-8")


def test_root_keeps_headroom_when_non_root_peers_hold_their_maximum(monkeypatch):
    slots = control_daemon._ClientSlots(4, 2, 1)
    monkeypatch.setattr(control_daemon, "_CLIENT_SLOTS", slots)
    release = threading.Event()
    monkeypatch.setattr(control_daemon, "handle_client", lambda conn, addr: (release.wait(5), conn.close()))
    who = {"uid": WEB_UID}
    monkeypatch.setattr(control_daemon, "peer_credentials", lambda conn: (who["uid"], 1))
    pairs = [socket.socketpair() for _ in range(5)]
    try:
        assert control_daemon._dispatch_client(pairs[0][1], None) is True
        assert control_daemon._dispatch_client(pairs[1][1], None) is True
        assert control_daemon._dispatch_client(pairs[2][1], None) is False  # the web's maximum
        pairs[2][0].settimeout(5)
        assert b'"busy"' in pairs[2][0].recv(1024)
        who["uid"] = 0
        assert control_daemon._dispatch_client(pairs[3][1], None) is True  # root still gets a slot
        assert control_daemon._dispatch_client(pairs[4][1], None) is True
        assert (slots.total, slots.nonroot) == (4, 2)
    finally:
        release.set()
        for a, b in pairs:
            a.close()
    deadline = time.monotonic() + 5
    while slots.total and time.monotonic() < deadline:
        time.sleep(0.02)
    assert (slots.total, slots.nonroot) == (0, 0)


def test_the_default_limits_leave_root_headroom():
    total, nonroot, watchers = control_daemon._CLIENT_SLOTS.limits
    assert nonroot < total and watchers < nonroot


def _watch(monkeypatch, uid):
    monkeypatch.setattr(control_daemon, "read_ui_snapshot", lambda: {"ok": True, "snapshot": {"x": 1}})
    _as_peer(monkeypatch, uid)
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    t = threading.Thread(target=control_daemon.handle_client, args=(server, None), daemon=True)
    t.start()
    client.sendall((json.dumps({"action": "watch_snapshot", "params": {"interval_sec": 0.2}}) + "\n").encode())
    client.settimeout(5)
    return client, t


def test_a_dead_idle_watcher_frees_its_slot(monkeypatch, web_account):
    slots = control_daemon._ClientSlots(32, 24, 16)
    monkeypatch.setattr(control_daemon, "_CLIENT_SLOTS", slots)
    client, t = _watch(monkeypatch, WEB_UID)
    first = json.loads(client.recv(65536).decode().splitlines()[0])
    assert first["snapshot"] == {"x": 1}
    assert slots.watchers == 1
    client.close()  # the snapshot never changes again: only the idle check can notice
    t.join(2.0)
    assert not t.is_alive()
    assert slots.watchers == 0


def test_non_root_watchers_are_capped_root_is_not(monkeypatch, web_account):
    slots = control_daemon._ClientSlots(32, 24, 1)
    monkeypatch.setattr(control_daemon, "_CLIENT_SLOTS", slots)
    c1, t1 = _watch(monkeypatch, WEB_UID)
    c1.recv(65536)
    c2, t2 = _watch(monkeypatch, WEB_UID)
    assert json.loads(c2.recv(65536).decode().splitlines()[0])["error"] == "busy"
    c3, t3 = _watch(monkeypatch, 0)
    assert "snapshot" in json.loads(c3.recv(65536).decode().splitlines()[0])
    for c in (c1, c2, c3):
        c.close()
    for t in (t1, t2, t3):
        t.join(2.0)
        assert not t.is_alive()
    assert slots.watchers == 0


def test_an_expired_deadline_is_a_timeout_not_a_negative_timeout():
    a, b = socket.socketpair()
    with a, b:
        with pytest.raises(socket.timeout):
            control_daemon._read_request(b, time.monotonic() - 1.0)


def test_watch_snapshots_closes_its_socket_when_the_consumer_stops(tmpdir_short):
    from azazel_edge import control_plane

    path = tmpdir_short / "c.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(1)
    got = {}

    def serve():
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.sendall(b'{"ok": true, "snapshot": {"a": 1}}\n')
        conn.settimeout(5)
        got["eof"] = conn.recv(10) == b""
        conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    gen = control_plane.watch_snapshots(socket_path=path)
    assert next(gen) == {"a": 1}
    gen.close()
    t.join(5)
    srv.close()
    assert got.get("eof") is True
