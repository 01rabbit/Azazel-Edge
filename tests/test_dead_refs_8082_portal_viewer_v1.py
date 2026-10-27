"""Edge#477: references to things nothing provides on this device, removed.

- The port 8082 "status API" (contain, release, stage_open, disconnect,
  details) came from Azazel-Gadget, where its first-minute process serves it
  on the gadget itself (its usb0 management address). No server for it ships
  in this repository or for this device, and on an Edge that address is not
  one of the device's, so the Web UI no longer asks it anything: contain, release
  and stage_open are not Web UI actions, disconnect is the control daemon's
  fixed ``uplink_disconnect`` (what it already was whenever 8082 did not
  answer) and details is the daemon's.
- The portal viewer (``azazel-edge-portal-viewer.service``, a browser behind
  noVNC) is not shipped; its Web UI routes, state field and button and the
  daemon's ``portal_viewer_open`` are removed.
- ntfy's health check no longer falls back to a default address; MGMT_IP
  is tried only when it is set.

Nothing new is enforced; the daemon still answers contain, disconnect and
stage_open with ``not_implemented``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from azazel_edge import cli_unified  # noqa: E402
from azazel_edge_control import daemon as control_daemon  # noqa: E402

import azazel_edge_web.app as webapp  # noqa: E402

APP = ROOT / "azazel_edge_web" / "app.py"
APP_JS = ROOT / "azazel_edge_web" / "static" / "app.js"
INDEX = ROOT / "azazel_edge_web" / "templates" / "index.html"
DAEMON = ROOT / "py" / "azazel_edge_control" / "daemon.py"
REMOVED_ACTIONS = ("contain", "release", "stage_open", "portal_viewer_open")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.fixture
def open_web(monkeypatch):
    monkeypatch.setattr(webapp, "load_token", lambda: None)
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    return webapp.app.test_client()


@pytest.fixture
def no_subprocess(monkeypatch):
    ran = []

    def fake_run(cmd, *a, **k):
        ran.append(list(cmd))
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(webapp.subprocess, "run", fake_run)
    return ran


# ------------------------------------------------------------ port 8082

# A quoted private 10.x address in the Web UI's code (the old status API host
# list and MGMT_IP default were one).
TEN_NET_LITERAL = re.compile(r"[\"']10\.\d+\.\d+\.\d+[\"']")


def test_nothing_in_the_web_ui_or_daemon_asks_port_8082_or_the_gadget_address():
    for path in (APP, DAEMON, APP_JS):
        src = _read(path)
        assert ":8082" not in src, path
        assert "STATUS_API_HOSTS" not in src, path
    for path in (APP, APP_JS):
        assert not TEN_NET_LITERAL.search(_read(path)), path
    for name in ("_status_api_json", "_first_status_api_response", "execute_contain_action",
                 "execute_release_action", "execute_stage_open_action"):
        assert not hasattr(webapp, name), name


@pytest.mark.parametrize("action", REMOVED_ACTIONS)
def test_removed_actions_are_unknown_over_http(open_web, no_subprocess, monkeypatch, action):
    sent = []
    monkeypatch.setattr(webapp, "_send_control_command_socket",
                        lambda action, params=None, timeout_sec=5.0: sent.append(action) or {"ok": True})
    assert action not in webapp.ALLOWED_ACTIONS
    resp = open_web.post(f"/api/action/{action}")
    assert resp.status_code == 404 and resp.get_json()["ok"] is False
    resp = open_web.post("/api/action", json={"action": action})
    assert resp.status_code == 403 and resp.get_json()["status"] == "error"
    assert sent == [] and no_subprocess == []


def test_disconnect_is_the_daemon_uplink_disconnect_only(open_web, no_subprocess, monkeypatch):
    sent = []

    def fake(action, params=None, timeout_sec=5.0):
        sent.append((action, params))
        return {"ok": False, "error": "uplink_interface_not_found:wlan0"}

    monkeypatch.setattr(webapp, "_send_control_command_socket", fake)
    resp = open_web.post("/api/action/disconnect")
    assert resp.status_code == 500
    body = resp.get_json()
    assert body["ok"] is False and "uplink_interface_not_found:wlan0" in body["error"]
    assert sent == [("uplink_disconnect", None)] and no_subprocess == []

    monkeypatch.setattr(webapp, "_send_control_command_socket",
                        lambda action, params=None, timeout_sec=5.0: {"ok": True, "message": "Uplink disconnected (eth9 down)"})
    res = webapp.execute_disconnect_action()
    assert res == {"ok": True, "action": "disconnect", "message": "Uplink disconnected (eth9 down)",
                   "via": "control_daemon"}


def test_details_goes_to_the_daemon(no_subprocess, monkeypatch):
    sent = []
    monkeypatch.setattr(webapp, "_send_control_command_socket",
                        lambda action, params=None, timeout_sec=5.0: sent.append(action) or {"ok": False, "error": "x"})
    assert webapp.send_control_command("details") == {"ok": False, "error": "x"}
    assert sent == ["details"] and no_subprocess == []


def test_the_daemon_still_answers_not_implemented():
    assert control_daemon.NOT_IMPLEMENTED_ACTIONS == frozenset({"contain", "disconnect", "stage_open"})
    for action in sorted(control_daemon.NOT_IMPLEMENTED_ACTIONS):
        res = control_daemon.execute_action(action, None, request={"action": action})
        assert res["ok"] is False and res["error"] == "not_implemented"


# ------------------------------------------------------------ portal viewer

def test_portal_viewer_routes_and_state_are_gone(open_web, monkeypatch):
    assert open_web.get("/api/portal-viewer").status_code == 404
    assert open_web.post("/api/portal-viewer/open", json={}).status_code == 404
    monkeypatch.setattr(webapp, "read_state", lambda: {"ok": True})
    monkeypatch.setattr(webapp, "get_monitoring_state", lambda: {})
    monkeypatch.setattr(webapp, "get_mode_state", lambda: {})
    body = open_web.get("/api/state").get_json()
    assert "portal_viewer" not in body
    assert not hasattr(webapp, "get_portal_viewer_state")


def test_the_dashboard_has_no_portal_contain_or_release_button():
    html, js = _read(INDEX), _read(APP_JS)
    for ident in ("portalAssistBtn", "containBtn", "releaseBtn"):
        assert ident not in html and ident not in js
    assert "/api/portal-viewer" not in js and "portal_viewer" not in js
    assert "executeAction(" not in js


def test_the_daemon_has_no_portal_viewer_open():
    src = _read(DAEMON)
    assert "portal_viewer_open" not in src and "portal-viewer" not in src
    assert "portal_viewer_open" not in control_daemon.WEB_UI_ACTIONS
    assert not hasattr(control_daemon, "ensure_portal_viewer_ready")
    res = control_daemon.execute_action("portal_viewer_open", {"timeout_sec": 1}, request={"action": "portal_viewer_open"})
    assert res["ok"] is False and res["error"] == "Unknown action: portal_viewer_open"


# ------------------------------------------------------------ ntfy and MGMT_IP

def _recording_urlopen(tried):
    def fake_urlopen(url, timeout=0):
        tried.append(url)
        raise OSError("refused")
    return fake_urlopen


def test_web_ui_ntfy_health_without_mgmt_ip_stays_on_loopback(monkeypatch):
    tried = []
    monkeypatch.setattr(webapp, "urlopen", _recording_urlopen(tried))
    monkeypatch.delenv("MGMT_IP", raising=False)
    assert webapp._ntfy_health_ok() is False
    assert tried == ["http://127.0.0.1:8081/v1/health", "http://localhost:8081/v1/health"]


def test_cli_ntfy_health_without_mgmt_ip_stays_on_loopback(monkeypatch):
    tried = []
    monkeypatch.setattr(cli_unified, "urlopen", _recording_urlopen(tried))
    monkeypatch.delenv("MGMT_IP", raising=False)
    assert cli_unified._ntfy_health_ok() is False
    assert tried == ["http://127.0.0.1:8081/v1/health"]


def test_no_mgmt_ip_default_address_is_left():
    for path in (APP, DAEMON, ROOT / "py" / "azazel_edge" / "cli_unified.py"):
        src = _read(path)
        # MGMT_IP is read only without a default address.
        for m in re.finditer(r'os\.environ\.get\("MGMT_IP"([^)]*)\)', src):
            assert m.group(1) in ("", ', ""'), (path, m.group(0))
        assert not re.search(r'get\("MGMT_IP"\) or "', src), path
