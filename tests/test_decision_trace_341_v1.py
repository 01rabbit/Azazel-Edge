"""Decision-level trace in the Web UI (Edge#341).

GET /api/decision-trace (and /export) join, per core decision, the v2
explanation the agent writes and the core decision chain's record, read only,
with the chain verdict audit_review prints. These tests check the auth
(existing token and viewer role, nothing new), that nothing is written, that
nothing is made up (an alert whose event is not a core decision has no trace,
alerts of one decision share one), and that a missing explanation, a rotated
record and a tampered chain are said as such.
"""

from __future__ import annotations

import copy
import io
import json
import re
import sys
import threading
from contextlib import redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import azazel_edge_web.app as webapp  # noqa: E402
from azazel_edge import audit_review  # noqa: E402
from azazel_edge.explanations import trace as decision_trace  # noqa: E402
from azazel_edge.audit import P0AuditLogger  # noqa: E402
from azazel_edge.explanations import live  # noqa: E402
from azazel_edge.notify.core_decisions import CORE_DECISION_SOURCE, core_decision_payload  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "rust_core_event_v1.json"
VIEWER = {"X-Auth-Token": "viewer-token"}


def core_event(action: str = "isolate", sid: int = 9341001) -> dict:
    event = json.loads(FIXTURE.read_text(encoding="utf-8"))
    event["defense"]["action"] = action
    event["enforcement"]["selected_action"] = action
    event["normalized"]["sid"] = sid
    return event


def trace_of(event: dict) -> str:
    return core_decision_payload(event)[0]


def explain(path: Path, event: dict, *, max_bytes: int = 8 * 1024 * 1024) -> dict:
    writer = live.LiveDecisionExplanationWriter(path, max_bytes=max_bytes)
    rec = writer.record(event, {})
    assert rec is not None
    return rec


def chain_record(logger: P0AuditLogger, event: dict) -> None:
    trace_id, payload = core_decision_payload(event)
    logger.log_action_decision(trace_id=trace_id, source=CORE_DECISION_SOURCE, **payload)


@pytest.fixture
def web(tmp_path, monkeypatch):
    decision_trace.reset_caches()
    # Re-verify a changed chain at once (the interval has its own test).
    monkeypatch.setattr(decision_trace, "CHAIN_RECHECK_MIN_S", 0.0)
    logs = tmp_path / "ai"
    logs.mkdir()
    tokens = tmp_path / "auth_tokens.json"
    tokens.write_text(json.dumps({"tokens": [{"token": "viewer-token", "principal": "kiosk", "role": "viewer"}]}),
                      encoding="utf-8")
    monkeypatch.setattr(webapp, "AUTH_FAIL_OPEN", False)
    monkeypatch.setattr(webapp, "TOKEN_FILE", tmp_path / "no-web-token.txt")
    monkeypatch.setattr(webapp, "AUTH_TOKENS_FILE", tokens)
    monkeypatch.setattr(webapp, "AUTHZ_AUDIT_LOG", tmp_path / "authz.jsonl")
    monkeypatch.setattr(webapp, "DECISION_EXPLANATIONS_PATH", logs / "decision-explanations.jsonl")
    monkeypatch.setattr(webapp, "CORE_DECISION_AUDIT_PATH", logs / "core-decision-audit.jsonl")
    yield webapp.app.test_client(), logs
    decision_trace.reset_caches()


def get_trace(client, *trace_ids, path="/api/decision-trace", headers=VIEWER):
    query = "&".join(f"trace_id={t}" for t in trace_ids)
    return client.get(f"{path}?{query}", headers=headers)


# ------------------------------------------------------------------ auth

def test_trace_endpoints_need_the_existing_token(web):
    client, _ = web
    for path in ("/api/decision-trace", "/api/decision-trace/export"):
        response = client.get(f"{path}?trace_id=core-x")
        assert response.status_code == 403, path
        assert response.get_json().get("error") == "Unauthorized"
        assert get_trace(client, "core-x", path=path, headers={"X-Auth-Token": "wrong"}).status_code == 403


def test_a_viewer_token_is_enough_and_no_new_role_or_route_is_added(web):
    client, _ = web
    assert get_trace(client, "core-x").status_code == 200
    rules = {r.rule: r for r in webapp.app.url_map.iter_rules() if r.rule.startswith("/api/decision-trace")}
    assert set(rules) == {"/api/decision-trace", "/api/decision-trace/export"}
    for rule in rules.values():
        assert set(rule.methods) - {"HEAD", "OPTIONS"} == {"GET"}
    assert webapp._ROLE_RANK == {"viewer": 10, "operator": 20, "responder": 30, "admin": 40}
    src = (ROOT / "azazel_edge_web" / "app.py").read_text(encoding="utf-8")
    assert src.count('@app.route("/api/decision-trace') == 2
    for route in ('"/api/decision-trace"', '"/api/decision-trace/export"'):
        block = src[src.index(f"@app.route({route}"):][:200]
        assert '@require_token(min_role="viewer")' in block


def test_writes_are_refused(web):
    client, _ = web
    for method in ("post", "put", "delete", "patch"):
        assert getattr(client, method)("/api/decision-trace?trace_id=core-x", headers=VIEWER).status_code == 405


def test_bad_requests_are_refused(web):
    client, _ = web
    assert client.get("/api/decision-trace", headers=VIEWER).status_code == 400
    assert get_trace(client, "../etc/passwd").status_code == 400
    assert decision_trace.MAX_TRACE_IDS == 16
    response = get_trace(client, *[f"core-{i}" for i in range(17)])
    assert response.status_code == 400 and response.get_json()["error"] == "too_many_trace_ids"
    assert get_trace(client, *[f"core-{i}" for i in range(16)]).status_code == 200
    # fullmatch: a trailing newline (or anything after the id) is refused.
    for bad in ("core-abc%0A", "core-abc%0D", "core-abc%20x", "core-abc/x", "-core"):
        assert get_trace(client, bad).status_code == 400, bad
    assert decision_trace.valid_trace_id("core-abc") is True
    assert decision_trace.valid_trace_id("core-abc\n") is False
    assert decision_trace.valid_trace_id("x" * 129) is False


# ------------------------------------------------------------- read only

def _snapshot(directory: Path) -> dict:
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in sorted(directory.iterdir())}


def test_reading_a_trace_writes_nothing(web):
    client, logs = web
    event = core_event()
    explain(logs / "decision-explanations.jsonl", event)
    chain_record(P0AuditLogger(logs / "core-decision-audit.jsonl", max_bytes=1 << 20), event)
    before = _snapshot(logs)
    for path in ("/api/decision-trace", "/api/decision-trace/export"):
        assert get_trace(client, trace_of(event), path=path).status_code == 200
    assert _snapshot(logs) == before
    src = (ROOT / "py" / "azazel_edge" / "explanations" / "trace.py").read_text(encoding="utf-8")
    code = re.sub(r'""".*?"""', "", src, flags=re.S)
    assert not re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_APPEND|write_text|write_bytes|\.write\(|os\.replace|os\.rename"
                         r"|unlink|chmod|chown|mkdir", code)
    assert "os.O_RDONLY | _O_NOFOLLOW" in code


# ------------------------------------------------------- found and joined

def test_a_p0_decision_shows_its_explanation_and_verified_chain_record(web):
    client, logs = web
    event = core_event("isolate")
    rec = explain(logs / "decision-explanations.jsonl", event)
    chain_record(P0AuditLogger(logs / "core-decision-audit.jsonl", max_bytes=1 << 20), event)
    body = get_trace(client, trace_of(event)).get_json()
    assert body["read_only"] is True and body["format"] == decision_trace.FORMAT
    (trace,) = body["traces"]
    exp, chain = trace["explanation"], trace["chain_record"]
    assert exp["status"] == "found" and exp["segment"] == "active" and exp["records"] == 1
    assert exp["selected_action"] == "isolate" and exp["schema_valid"] is True
    # A dry run: never shown as applied.
    assert exp["not_applied"] is True and exp["applied_state"] == "not_applied"
    assert exp["applied_label"] == rec["release_condition"] == "NOT APPLIED - planned only (dry_run)"
    assert set(exp) <= decision_trace.EXPLANATION_KEYS and set(chain) <= decision_trace.CHAIN_KEYS
    assert chain["status"] == "found" and chain["integrity"] == "verified" and chain["segment"] == "active"
    assert chain["action"] == "isolate" and trace["consistency"] == {"action_matches": True}
    assert body["sources"]["chain"]["verified"] is True and body["sources"]["chain"]["scope"] == "from_genesis"
    # The same verdict as audit_review --json, and the same values for the
    # allowlisted fields it shares.
    out = io.StringIO()
    with redirect_stdout(out):
        rc = audit_review.main(["--explanations-path", str(logs / "decision-explanations.jsonl"),
                                "--audit-path", str(logs / "core-decision-audit.jsonl"),
                                "--trace-id", rec["trace_id"], "--json"])
    assert rc == 0
    cli = json.loads(out.getvalue())
    # Free text is never shown to viewers (allowlist): these CLI keys are left out.
    free_text = {"operator_wording", "release_condition", "why_not_others", "rejected_actions", "evidence_ids",
                 "schema_problems"}
    shared = (set(cli) - {"chain"}) & decision_trace.EXPLANATION_KEYS
    assert shared == {"trace_id", "ts", "selected_action", "policy_profile", "config_hash", "config_hash_basis",
                      "schema_valid", "capsule_signature_state"}
    assert not (free_text & set(exp))
    for key in shared:
        assert exp[key] == cli[key], key
    for ck, cv in cli["chain"].items():
        assert body["sources"]["chain"][ck] == cv, ck
    # Nothing new and personal: no event key, core trace id, target address or plan.
    text = json.dumps(chain)
    for absent in ("core_event_key", "core_trace_id", "target", "agent_received"):
        assert absent not in text, absent


def test_alerts_of_one_decision_share_one_trace_and_others_have_none(web, tmp_path, monkeypatch):
    client, logs = web
    event = core_event("isolate")
    explain(logs / "decision-explanations.jsonl", event)
    rows = [
        {"event": event, "advisory": {"ts": 1.0}},
        {"event": copy.deepcopy(event), "advisory": {"ts": 2.0}},  # the same EVE line delivered twice
        {"event": {"normalized": {"sid": 7, "src_ip": "10.0.0.9"}}, "advisory": {"ts": 3.0}},  # not a core decision
        {"advisory": {"ts": 4.0, "trace_id": "core-made-up"}},
    ]
    alerts = [webapp._normalize_alert_event(r) for r in rows]
    tid = trace_of(event)
    assert [a["decision_trace_id"] for a in alerts] == [tid, tid, "", ""]
    report = webapp._bundle_decision_traces(alerts)
    assert [t["trace_id"] for t in report["traces"]] == [tid]


def test_the_bundle_carries_the_traces_of_the_alerts_it_shows(web, tmp_path, monkeypatch):
    client, logs = web
    event = core_event("isolate")
    explain(logs / "decision-explanations.jsonl", event)
    events = tmp_path / "ai-events.jsonl"
    events.write_text("\n".join(json.dumps(r) for r in (
        {"event": event, "advisory": {"ts": 1.0}},
        {"event": {"normalized": {"sid": 1}}, "advisory": {"ts": 2.0}},
    )) + "\n", encoding="utf-8")
    monkeypatch.setattr(webapp, "AI_EVENT_LOG", events)
    monkeypatch.setattr(webapp, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(webapp, "FALLBACK_STATE_PATH", tmp_path / "fallback.json")
    monkeypatch.setattr(webapp, "cp_read_snapshot_payload", None)
    monkeypatch.setattr(webapp, "_mattermost_ping", lambda: (False, {}))
    body = client.get("/api/dashboard/bundle", headers=VIEWER).get_json()
    assert [a["decision_trace_id"] for a in body["evidence"]["recent_alerts"]] == [trace_of(event), ""]
    assert [t["trace_id"] for t in body["decision_traces"]["traces"]] == [trace_of(event)]


# --------------------------------------------------------- not made up

def test_a_decision_without_an_explanation_is_no_record(web):
    client, logs = web
    explain(logs / "decision-explanations.jsonl", core_event("isolate", sid=1))
    missing = trace_of(core_event("isolate", sid=2))
    (trace,) = get_trace(client, missing).get_json()["traces"]
    assert trace["explanation"]["status"] == "not_found"
    assert trace["explanation"]["rotated_file_present"] is False
    assert trace["chain_record"]["status"] == "not_found"
    assert "P0 decisions only" in trace["chain_record"]["note"]
    assert trace["consistency"] == {}


def test_missing_sources_are_said_never_an_empty_success(web):
    client, _ = web
    body = get_trace(client, "core-abc").get_json()
    assert body["sources"]["explanations"]["state"] == "missing"
    assert body["sources"]["chain"]["state"] == "missing"
    assert body["sources"]["chain"]["scope"] == "empty" and body["sources"]["chain"]["verified"] is False


def test_a_non_p0_decision_has_an_explanation_but_no_chain_record(web):
    client, logs = web
    event = core_event("notify")
    explain(logs / "decision-explanations.jsonl", event)
    (trace,) = get_trace(client, trace_of(event)).get_json()["traces"]
    assert trace["explanation"]["status"] == "found"
    assert trace["chain_record"]["status"] == "not_found"


# ---------------------------------------------------------------- rotated

def test_rotated_records_are_marked_as_in_the_older_file(web):
    client, logs = web
    first, second = core_event("isolate", sid=11), core_event("isolate", sid=12)
    exp = logs / "decision-explanations.jsonl"
    explain(exp, first, max_bytes=1)
    explain(exp, second, max_bytes=1)  # rotates the first record to .1
    assert (logs / "decision-explanations.jsonl.1").exists()
    chain = P0AuditLogger(logs / "core-decision-audit.jsonl", max_bytes=1)
    chain_record(chain, first)
    chain_record(chain, second)  # rotates the first record to .1
    body = get_trace(client, trace_of(first), trace_of(second)).get_json()
    old, new = body["traces"]
    assert old["explanation"]["segment"] == "rotated" and new["explanation"]["segment"] == "active"
    assert old["chain_record"]["segment"] == "rotated" and old["chain_record"]["file"] == "core-decision-audit.jsonl.1"
    assert new["chain_record"]["segment"] == "active"
    assert old["chain_record"]["integrity"] == new["chain_record"]["integrity"] == "verified"
    assert body["sources"]["explanations"]["files"] == ["decision-explanations.jsonl.1", "decision-explanations.jsonl"]


def test_a_record_rotated_out_is_no_record_with_the_reason(web):
    client, logs = web
    events = [core_event("isolate", sid=20 + i) for i in range(3)]
    exp = logs / "decision-explanations.jsonl"
    for event in events:
        explain(exp, event, max_bytes=1)  # keeps one rotated file: the first is gone
    chain = P0AuditLogger(logs / "core-decision-audit.jsonl", max_bytes=1)
    for event in events:
        chain_record(chain, event)
    body = get_trace(client, trace_of(events[0])).get_json()
    (trace,) = body["traces"]
    assert trace["explanation"]["status"] == "not_found"
    assert trace["explanation"]["rotated_file_present"] is True
    assert "rotated out" in trace["explanation"]["note"]
    assert trace["chain_record"]["status"] == "not_found"
    assert body["sources"]["chain"]["scope"] == "from_rotation_boundary"


def test_the_index_follows_a_growing_file_and_a_rotation(web):
    client, logs = web
    exp = logs / "decision-explanations.jsonl"
    a, b = core_event("isolate", sid=31), core_event("isolate", sid=32)
    explain(exp, a)
    assert get_trace(client, trace_of(b)).get_json()["traces"][0]["explanation"]["status"] == "not_found"
    explain(exp, b)
    assert get_trace(client, trace_of(b)).get_json()["traces"][0]["explanation"]["status"] == "found"
    explain(exp, core_event("isolate", sid=33), max_bytes=1)  # rotation: a and b move to .1
    seg = get_trace(client, trace_of(a)).get_json()["traces"][0]["explanation"]["segment"]
    assert seg == "rotated"


# ---------------------------------------------------------------- tampered

def _tamper(path: Path, index: int) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[index])
    row["action"] = "notify"
    lines[index] = json.dumps(row, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_a_tampered_chain_record_is_shown_as_tampered_and_the_rest_unverified(web):
    client, logs = web
    events = [core_event("isolate", sid=40 + i) for i in range(3)]
    exp = logs / "decision-explanations.jsonl"
    chain_path = logs / "core-decision-audit.jsonl"
    chain = P0AuditLogger(chain_path, max_bytes=1 << 20)
    for event in events:
        explain(exp, event)
        chain_record(chain, event)
    # Seen verified first, so the cache must notice the change.
    assert get_trace(client, trace_of(events[1])).get_json()["traces"][0]["chain_record"]["integrity"] == "verified"
    _tamper(chain_path, 1)
    body = get_trace(client, *[trace_of(e) for e in events]).get_json()
    integrity = [t["chain_record"]["integrity"] for t in body["traces"]]
    assert integrity == ["not_verified", "failed_here", "not_verified"]
    assert body["sources"]["chain"]["ok"] is False and body["sources"]["chain"]["verified"] is False
    assert body["sources"]["chain"]["error"] == "chain_hash_mismatch_at:2"
    # The tampered record no longer matches its explanation.
    assert body["traces"][1]["consistency"] == {"action_matches": False}
    # audit_review reports the same failure.
    assert audit_review.verify_audit_chain(chain_path)["error"] == "chain_hash_mismatch_at:2"


def test_an_unreadable_chain_is_unreadable_not_empty(web, monkeypatch):
    client, logs = web
    event = core_event()
    explain(logs / "decision-explanations.jsonl", event)

    def denied(path):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(audit_review, "verify_audit_chain", denied)
    (logs / "core-decision-audit.jsonl").write_text("{}\n", encoding="utf-8")
    body = get_trace(client, trace_of(event)).get_json()
    assert body["sources"]["chain"]["state"] == "unreadable"
    assert body["sources"]["chain"]["verified"] is False
    assert body["traces"][0]["chain_record"]["status"] == "source_unreadable"


# ----------------------------------------------------------------- export

def test_the_export_is_the_same_report_as_an_attachment(web):
    client, logs = web
    event = core_event("isolate")
    explain(logs / "decision-explanations.jsonl", event)
    chain_record(P0AuditLogger(logs / "core-decision-audit.jsonl", max_bytes=1 << 20), event)
    response = get_trace(client, trace_of(event), path="/api/decision-trace/export")
    assert response.status_code == 200
    assert re.fullmatch(r'attachment; filename="decision-trace-\d{8}T\d{6}Z\.json"',
                        response.headers["Content-Disposition"])
    assert response.headers["Cache-Control"] == "no-store"
    exported = json.loads(response.get_data(as_text=True))
    shown = get_trace(client, trace_of(event)).get_json()
    exported.pop("generated_at")
    shown.pop("generated_at")
    assert exported == shown


def test_api_reference_and_privilege_inventory_name_the_endpoints():
    api = (ROOT / "docs" / "API_REFERENCE.md").read_text(encoding="utf-8")
    inventory = (ROOT / "docs" / "architecture" / "privilege-inventory.md").read_text(encoding="utf-8")
    for doc in (api, inventory):
        assert "/api/decision-trace" in doc
        assert "core-decision-audit.jsonl" in doc


# ------------------------------------------------------------- console

def test_console_shows_the_decision_trace_with_text_only():
    js = (ROOT / "azazel_edge_web" / "static" / "sentinel.js").read_text(encoding="utf-8")
    block = js[js.index("decision-level trace (Edge#341)"):js.index("var EVD_FIELDS")]
    assert "innerHTML" not in block and "insertAdjacentHTML" not in block and "outerHTML" not in block
    assert "textContent" in block
    # The drawer's trace is the decision's, never an alert field.
    assert "txt('evdTrace', a." not in js
    assert "txt('evdTrace', view.traceId)" in js
    # Still event-driven: no request of its own.
    assert "fetch(" not in js and "XMLHttpRequest" not in js
    app_js = (ROOT / "azazel_edge_web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "decisionTraces: bundle.decision_traces || {}" in app_js


def test_console_markup_has_the_decision_trace_places():
    client = webapp.app.test_client()
    text = client.get("/?lang=en").get_data(as_text=True)
    for needle in ('id="evdDecisionTrace"', 'id="evDecisions"', 'id="evDecisionExport"', 'data-ev-view="decisions"',
                   'data-ev-panel="decisions"', 'id="evdTrace"'):
        assert needle in text, needle


# ----------------------------------------- no addresses or indicators

ADDRESSES = ("203.0.113.9", "192.0.2.10", "2001:db8::7", "evil.example.net", "d41d8cd98f00b204e9800998ecf8427e")


def _isolate_with_indicators() -> tuple:
    event = core_event("isolate", sid=9341099)
    event["normalized"]["src_ip"], event["normalized"]["dst_ip"] = "203.0.113.9", "192.0.2.10"
    event["defense"]["reason"] = "isolate 203.0.113.9:22 -> 192.0.2.10 via [2001:db8::7]:443 (ti evil.example.net)"
    advisory = {"second_pass": {"status": "completed", "soc": {
        "status": "critical",
        "reasons": ["TI match evil.example.net from 203.0.113.9", "hash d41d8cd98f00b204e9800998ecf8427e"],
        "ti_matches": [{"indicator": "evil.example.net", "ip": "203.0.113.9"}],
        "evidence_ids": ["ev-341-1"],
    }}}
    return event, advisory


def test_no_target_address_or_indicator_reaches_a_viewer(web, tmp_path, monkeypatch):
    client, logs = web
    event, advisory = _isolate_with_indicators()
    rec = live.LiveDecisionExplanationWriter(logs / "decision-explanations.jsonl").record(event, advisory)
    assert rec is not None
    raw = (logs / "decision-explanations.jsonl").read_text(encoding="utf-8")
    assert "203.0.113.9" in raw and "evil.example.net" in raw  # the record itself carries them
    chain_record(P0AuditLogger(logs / "core-decision-audit.jsonl", max_bytes=1 << 20), event)
    tid = trace_of(event)

    body = get_trace(client, tid).get_json()
    (trace,) = body["traces"]
    assert trace["explanation"]["status"] == "found" and trace["chain_record"]["status"] == "found"
    assert "operator_wording" not in trace["explanation"]
    assert "reason" not in trace["explanation"]
    _check_types(trace["explanation"], decision_trace.EXPLANATION_KEYS)
    exported = get_trace(client, tid, path="/api/decision-trace/export").get_data(as_text=True)

    events = tmp_path / "ai-events.jsonl"
    events.write_text(json.dumps({"event": event, "advisory": {"ts": 1.0}}) + "\n", encoding="utf-8")
    monkeypatch.setattr(webapp, "AI_EVENT_LOG", events)
    monkeypatch.setattr(webapp, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(webapp, "FALLBACK_STATE_PATH", tmp_path / "fallback.json")
    monkeypatch.setattr(webapp, "cp_read_snapshot_payload", None)
    monkeypatch.setattr(webapp, "_mattermost_ping", lambda: (False, {}))
    bundle = client.get("/api/dashboard/bundle", headers=VIEWER).get_json()["decision_traces"]
    assert [t["trace_id"] for t in bundle["traces"]] == [tid]

    for name, text in (("endpoint", json.dumps(body)), ("export", exported), ("bundle", json.dumps(bundle))):
        for needle in ADDRESSES + ("203.0.113", "192.0.2.10:", "operator_wording"):
            assert needle not in text, (name, needle)


FREE_TEXT = "FREE-TEXT 203.0.113.77 evil.example.org ip:2001:db8::7 10_0_0_1 hxxp[:]//x[.]y ２０３．０．１１３．７７ 3405803853"


def _poisoned_record(trace_id: str) -> dict:
    """An explanation whose every text field carries free text."""
    return {
        "ts": FREE_TEXT, "trace_id": trace_id, "format_version": "v2", "selected_action": FREE_TEXT,
        "reason": FREE_TEXT, "rejected_actions": [FREE_TEXT], "release_condition": FREE_TEXT,
        "policy_profile": FREE_TEXT, "config_hash": FREE_TEXT, "why_chosen": {"x": FREE_TEXT},
        "why_not_others": [{"action": FREE_TEXT, "reason": FREE_TEXT}], "evidence_ids": [FREE_TEXT],
        "next_checks": [FREE_TEXT], "operator_wording": FREE_TEXT,
        "machine": {"arbiter": {"applied_state": FREE_TEXT, "control_mode": FREE_TEXT,
                                "policy": {"hash_basis": FREE_TEXT}}},
        "trust_capsule": {"signature_state": FREE_TEXT},
    }


def _check_types(view: dict, keys: frozenset) -> None:
    assert set(view) <= keys, set(view) - keys
    for key, value in view.items():
        if key in ("records", "position", "sid", "severity", "schema_problem_count", "rejected_action_count",
                   "evidence_count"):
            assert isinstance(value, int) and not isinstance(value, bool), key
        elif key in ("not_applied", "schema_valid", "enforce_dry_run", "reconcile_stale"):
            assert isinstance(value, bool), key
        elif key == "applied_label":
            modes = "|".join(sorted(decision_trace.ENFORCEMENT_MODES | {"unknown"}))
            assert re.fullmatch(rf"(NOT APPLIED - planned only \(({modes})\)|NOT APPLIED - apply failed|)", value), value
        else:
            assert isinstance(value, str), key
            assert "FREE-TEXT" not in value and " " not in value, (key, value)


def test_free_text_of_any_field_never_reaches_a_viewer(web):
    client, logs = web
    tid = "core-0123456789abcdef0123456789abcdef"
    (logs / "decision-explanations.jsonl").write_text(json.dumps(_poisoned_record(tid)) + "\n", encoding="utf-8")
    row = {"kind": "action_decision", "trace_id": tid, "source": FREE_TEXT, "chain_prev": "", "action": FREE_TEXT,
           "decided_action": FREE_TEXT, "effective_action": "isolate", "enforcement_mode": FREE_TEXT,
           "enforcement_result": FREE_TEXT, "enforce_dry_run": "yes", "recorded_by": FREE_TEXT,
           "reconcile_stale": FREE_TEXT, "event_ts": FREE_TEXT, "sid": "9300001", "severity": True,
           "target": FREE_TEXT, "reason": FREE_TEXT, "policy_reason": FREE_TEXT, "ts": FREE_TEXT}
    row["chain_hash"] = P0AuditLogger._compute_chain_hash(row)
    (logs / "core-decision-audit.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    for path in ("/api/decision-trace", "/api/decision-trace/export"):
        text = get_trace(client, tid, path=path).get_data(as_text=True)
        for needle in ("FREE-TEXT", "203.0.113", "example", "2001:db8", "10_0_0_1", "hxxp", "２０３", "3405803853"):
            assert needle not in text, (path, needle)
    (trace,) = get_trace(client, tid).get_json()["traces"]
    exp, chain = trace["explanation"], trace["chain_record"]
    _check_types(exp, decision_trace.EXPLANATION_KEYS)
    _check_types(chain, decision_trace.CHAIN_KEYS)
    # Wrong type or form: left out, never coerced.
    for key in ("ts", "selected_action", "applied_state", "applied_label", "policy_profile", "config_hash",
                "config_hash_basis", "enforcement_mode"):
        assert key not in exp, key
    for key in ("sid", "severity", "action", "enforce_dry_run", "reconcile_stale", "recorded_by", "event_ts", "ts"):
        assert key not in chain, key
    assert chain["effective_action"] == "isolate" and chain["integrity"] == "verified"
    assert exp["rejected_action_count"] == 1 and exp["evidence_count"] == 1 and exp["schema_valid"] is False


def test_the_applied_label_is_built_from_enumerated_values_only():
    assert decision_trace.applied_label("not_applied", "dry_run") == "NOT APPLIED - planned only (dry_run)"
    assert decision_trace.applied_label("not_applied", None) == "NOT APPLIED - planned only (unknown)"
    assert decision_trace.applied_label("apply_failed", "enforced") == "NOT APPLIED - apply failed"
    assert decision_trace.applied_label("applied", "enforced") == ""
    assert decision_trace.applied_label("none", None) == ""
    src = (ROOT / "py" / "azazel_edge" / "explanations" / "trace.py").read_text(encoding="utf-8")
    assert "mask_text" not in src and "release_condition\")" not in src


# ----------------------------------------------------------------- load

def test_no_id_reads_nothing(web, monkeypatch):
    client, logs = web
    explain(logs / "decision-explanations.jsonl", core_event())

    def refuse(*args, **kwargs):
        raise AssertionError("nothing may be read without an id")

    monkeypatch.setattr(decision_trace, "_open", refuse)
    monkeypatch.setattr(audit_review, "verify_audit_chain", refuse)
    report = webapp._bundle_decision_traces([{"decision_trace_id": ""}, {}])
    assert report["ok"] is True and report["traces"] == []
    assert report["sources"] == {"explanations": {"state": "not_read"}, "chain": {"state": "not_read"}}


def test_the_chain_is_reverified_at_most_once_per_interval(web, monkeypatch):
    client, logs = web
    clock = [1000.0]
    monkeypatch.setattr(decision_trace, "_monotonic", lambda: clock[0])
    monkeypatch.setattr(decision_trace, "CHAIN_RECHECK_MIN_S", 5.0)
    calls = []
    real = audit_review.verify_audit_chain
    monkeypatch.setattr(audit_review, "verify_audit_chain", lambda p: calls.append(p) or real(p))
    a, b = core_event("isolate", sid=51), core_event("isolate", sid=52)
    chain = P0AuditLogger(logs / "core-decision-audit.jsonl", max_bytes=1 << 20)
    chain_record(chain, a)
    first = get_trace(client, trace_of(a)).get_json()
    assert first["sources"]["chain"]["recheck_pending"] is False and len(calls) == 1
    get_trace(client, trace_of(a))
    assert len(calls) == 1  # unchanged: not verified again
    chain_record(chain, b)
    clock[0] += 1.0
    early = get_trace(client, trace_of(b)).get_json()
    assert len(calls) == 1 and early["sources"]["chain"]["recheck_pending"] is True
    assert early["traces"][0]["chain_record"]["status"] == "not_found"
    clock[0] += 5.0
    late = get_trace(client, trace_of(b)).get_json()
    assert len(calls) == 2 and late["sources"]["chain"]["recheck_pending"] is False
    assert late["traces"][0]["chain_record"]["status"] == "found"


def test_a_rebuild_in_progress_does_not_block_other_requests(web, monkeypatch):
    client, logs = web
    a = core_event("isolate", sid=61)
    chain = P0AuditLogger(logs / "core-decision-audit.jsonl", max_bytes=1 << 20)
    chain_record(chain, a)
    assert get_trace(client, trace_of(a)).status_code == 200
    index = decision_trace._CHAINS[str(logs / "core-decision-audit.jsonl")]
    chain_record(chain, core_event("isolate", sid=62))
    assert index._build.acquire(blocking=False)  # another request is rebuilding
    try:
        body = get_trace(client, trace_of(a)).get_json()  # answers at once from the last snapshot
    finally:
        index._build.release()
    assert body["sources"]["chain"]["recheck_pending"] is True
    # An answer from before the change is not verified now.
    assert body["traces"][0]["chain_record"]["integrity"] == "pending"
    assert body["sources"]["chain"]["verified"] is False
    src = (ROOT / "py" / "azazel_edge" / "explanations" / "trace.py").read_text(encoding="utf-8")
    assert "self._build.acquire(blocking=blocking)" in src


def test_an_empty_chain_never_makes_a_record_verified():
    empty = {"ok": True, "verified": False, "scope": "empty", "error": ""}
    assert decision_trace._integrity(empty, 1) == "not_verified"
    assert decision_trace._integrity({"ok": True, "verified": True}, 1) == "verified"
    assert decision_trace._integrity({"ok": False, "verified": False, "error": "chain_hash_mismatch_at:3"}, 3) == "failed_here"


def test_a_failed_bundle_trace_returns_the_type_only(web, monkeypatch):
    def boom(ids):
        raise OSError(13, "denied: /var/log/azazel-edge/ai/secret-path")

    monkeypatch.setattr(webapp, "_decision_trace_report", boom)
    report = webapp._bundle_decision_traces([{"decision_trace_id": "core-abc"}])
    assert report == {"ok": False, "error": "PermissionError", "traces": []}


def _in_thread(fn, timeout: float = 20.0):
    """Run fn in a thread; fail (never hang) when it does not finish."""
    box: dict = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:  # pragma: no cover - reported below
            box["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    assert not t.is_alive(), "timed out"
    if "error" in box:
        raise box["error"]
    return box.get("value")


def test_a_query_right_after_tampering_is_never_verified(web, monkeypatch):
    client, logs = web
    clock = [5000.0]
    monkeypatch.setattr(decision_trace, "_monotonic", lambda: clock[0])
    monkeypatch.setattr(decision_trace, "CHAIN_RECHECK_MIN_S", 5.0)
    events = [core_event("isolate", sid=70 + i) for i in range(2)]
    chain_path = logs / "core-decision-audit.jsonl"
    chain = P0AuditLogger(chain_path, max_bytes=1 << 20)
    for event in events:
        chain_record(chain, event)
    assert get_trace(client, trace_of(events[1])).get_json()["traces"][0]["chain_record"]["integrity"] == "verified"
    _tamper(chain_path, 1)
    body = _in_thread(lambda: get_trace(client, trace_of(events[1])).get_json())
    assert body["traces"][0]["chain_record"]["integrity"] == "pending"
    assert body["sources"]["chain"]["verified"] is False and body["sources"]["chain"]["recheck_pending"] is True
    clock[0] += 6.0
    body = _in_thread(lambda: get_trace(client, trace_of(events[1])).get_json())
    assert body["traces"][0]["chain_record"]["integrity"] == "failed_here"


def test_two_concurrent_rebuilds_run_once_and_never_hang(web, monkeypatch):
    _, logs = web
    chain_path = logs / "core-decision-audit.jsonl"
    chain = P0AuditLogger(chain_path, max_bytes=1 << 20)
    chain_record(chain, core_event("isolate", sid=81))
    real = audit_review.verify_audit_chain
    entered, release = threading.Event(), threading.Event()
    calls = []

    def slow(path):
        calls.append(path)
        entered.set()
        assert release.wait(20), "never released"
        return real(path)

    monkeypatch.setattr(audit_review, "verify_audit_chain", slow)
    index = decision_trace._ChainIndex(chain_path)

    # First build: the second caller waits for it (nothing to answer from) and
    # gets the snapshot the first one built; verification runs once.
    results: list = []
    t1 = threading.Thread(target=lambda: results.append(index.current()), daemon=True)
    t1.start()
    assert entered.wait(20)
    t2 = threading.Thread(target=lambda: results.append(index.current()), daemon=True)
    t2.start()
    release.set()
    t1.join(20)
    t2.join(20)
    assert not t1.is_alive() and not t2.is_alive(), "timed out"
    assert len(calls) == 1
    assert results[0][0] is results[1][0] and all(pending is False for _, pending in results)

    # A rebuild after a change: the other caller answers at once (pending).
    monkeypatch.setattr(decision_trace, "CHAIN_RECHECK_MIN_S", 0.0)
    chain_record(chain, core_event("isolate", sid=82))
    entered.clear()
    release.clear()
    t3 = threading.Thread(target=lambda: results.append(index.current()), daemon=True)
    t3.start()
    assert entered.wait(20)
    snap, pending = _in_thread(index.current, timeout=5)
    assert pending is True and snap is results[0][0]
    release.set()
    t3.join(20)
    assert not t3.is_alive(), "timed out"
    assert len(calls) == 2 and results[-1][1] is False and results[-1][0] is not snap
