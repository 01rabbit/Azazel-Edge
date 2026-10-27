"""Mattermost not installed / not configured reads as such (Edge#477, #495).

Without a bot token and channel id or a webhook URL (the provisioning step
writes them only when Mattermost is installed), the Web UI used to answer a
send with HTTP 500 (the handoff with 502) and kept every "Open Mattermost"
link on the installer's port 8065 URL, which nothing serves. Now:

- sending (message, handoff) and reading back answer 503 with
  ``not_configured: true``, never success and never a generic server error;
- the status payloads say ``configured: false`` and carry no Mattermost URL,
  the reachability ping is not sent, and the pages offer no Mattermost link;
- a configured Mattermost that fails is still a failure (500 / 502).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import azazel_edge_web.app as webapp  # noqa: E402

OPEN_URL = "http://mm.example.invalid:8065/azazelops/channels/soc-noc"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(webapp, "load_token", lambda: None)
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", True)
    monkeypatch.setattr(webapp, "MATTERMOST_OPEN_URL", OPEN_URL)
    monkeypatch.setattr(webapp, "MATTERMOST_BOT_TOKEN", "")
    monkeypatch.setattr(webapp, "MATTERMOST_CHANNEL_ID", "")
    monkeypatch.setattr(webapp, "MATTERMOST_WEBHOOK_URL", "")
    monkeypatch.setitem(webapp._MATTERMOST_PING_CACHE, "ts", 0.0)
    monkeypatch.setitem(webapp._MATTERMOST_PING_CACHE, "value", (False, {"error": "not_checked"}))
    return webapp.app.test_client()


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("no request may be sent when Mattermost is not configured")

    monkeypatch.setattr(webapp, "urlopen", refuse)


def _assert_not_configured(resp):
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["ok"] is False and body["not_configured"] is True
    assert body["error"] == "mattermost_not_configured"
    assert "not installed or not configured" in body["message"]
    return body


def test_sending_a_message_is_503_not_configured(client, no_network):
    _assert_not_configured(client.post("/api/mattermost/message", json={"message": "hello"}))


def test_the_handoff_is_503_not_configured_and_keeps_the_pack(client, no_network):
    body = _assert_not_configured(
        client.post("/api/dashboard/handoff", json={"session_id": "mm-nc", "target": "mattermost"}))
    assert "brief_text" in body["handoff_brief_pack"]


def test_reading_back_is_503_not_configured(client, no_network):
    body = _assert_not_configured(client.get("/api/mattermost/messages"))
    assert body["items"] == []


def test_status_says_not_configured_and_has_no_url(client, no_network):
    resp = client.get("/api/mattermost/status")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["configured"] is False and body["reachable"] is False
    assert body["mode"] == "disabled"
    assert body["open_url"] == "" and body["base_url"] == ""
    assert body["ping"] == {"error": "mattermost_not_configured"}


def test_no_link_anywhere_when_not_configured(client, no_network):
    assert webapp._mattermost_open_url() == ""
    assert webapp._assist_handoff_payload()["mattermost"] == ""
    html = client.get("/ops-comm").get_data(as_text=True)
    assert OPEN_URL not in html and ":8065" not in html
    assert 'id="mattermostLink" href="#" hidden' in html


def test_the_pages_hide_the_link_when_not_configured():
    js = (ROOT / "azazel_edge_web" / "static" / "ops_comm.js").read_text(encoding="utf-8")
    assert "data.configured === false" in js and "link.hidden = true" in js
    app_js = (ROOT / "azazel_edge_web" / "static" / "app.js").read_text(encoding="utf-8")
    assert app_js.count("hidden = mattermost.configured === false") == 2


def test_a_configured_mattermost_keeps_its_link(client, monkeypatch):
    monkeypatch.setattr(webapp, "MATTERMOST_WEBHOOK_URL", "http://mm.example.invalid:8065/hooks/x")
    monkeypatch.setattr(webapp, "_mattermost_ping", lambda force=False: (True, {"status": "OK"}))
    body = client.get("/api/mattermost/status").get_json()
    assert body["configured"] is True and body["open_url"] == OPEN_URL and body["mode"] == "webhook"
    html = client.get("/ops-comm").get_data(as_text=True)
    assert f'id="mattermostLink" href="{OPEN_URL}" target=' in html


def test_a_configured_mattermost_that_fails_is_still_a_failure(client, monkeypatch):
    monkeypatch.setattr(webapp, "MATTERMOST_WEBHOOK_URL", "http://mm.example.invalid:8065/hooks/x")

    def refused(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(webapp, "urlopen", refused)
    resp = client.post("/api/mattermost/message", json={"message": "hello"})
    assert resp.status_code == 500 and resp.get_json()["ok"] is False
    assert "not_configured" not in resp.get_json()
    resp = client.post("/api/dashboard/handoff", json={"session_id": "mm-c", "target": "mattermost"})
    assert resp.status_code == 502 and resp.get_json()["ok"] is False


def test_asking_the_ai_without_sending_needs_no_mattermost(client, no_network, monkeypatch):
    monkeypatch.setattr(webapp, "_send_ai_manual_query", lambda **kw: {"ok": False, "error": "ai_socket_not_found"})
    resp = client.post("/api/mattermost/message",
                       json={"message": "hello", "ask_ai": True, "send_to_mattermost": False})
    assert resp.status_code == 200 and resp.get_json()["result"] is None
