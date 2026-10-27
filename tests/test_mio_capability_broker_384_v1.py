"""#384: remaining Capability Broker contract gaps.

* closed request contract (exact request type, typed purpose IDs),
* cycle close: later requests refused, in-flight handlers yield ``stale``,
* audit projection: fixed field allowlist, closed reason grammar, no address
  or credential shape in any verbatim identifier,
* repository scan: every capability name the repo registers or the playbooks
  allow passes the read-only registry rules (no generic network, shell or
  write capability).
"""
from __future__ import annotations

import ast
import dataclasses
import json
import threading
import time
from pathlib import Path

import pytest

from azazel_edge.mio import (
    CapabilityBroker,
    CapabilityBrokerError,
    CapabilitySpec,
    DEFAULT_PLAYBOOKS,
    MioCapabilityRequest,
)
from azazel_edge.mio import broker as broker_module

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def _no_broker_thread_outlives_the_test():
    """Every handler a test blocks must be released by the test (try/finally);
    this fails the test if a broker worker thread is still alive afterwards,
    so no thread can leak into later tests."""
    before = set(threading.enumerate())
    yield
    leftover = [t for t in threading.enumerate() if t not in before and t.name.startswith("mio-cap-")]
    for t in leftover:
        t.join(5)
    alive = [t.name for t in leftover if t.is_alive()]
    assert not alive, f"broker worker threads outlived the test: {alive}"


def _handler(_args):
    return {"summary": "ok", "evidence_refs": ["ev:alert:1"], "source_timestamp": NOW - 1}


def _broker(caps=None, **kw):
    kw.setdefault("clock", lambda: NOW)
    kw.setdefault("max_total_calls", 16)
    return CapabilityBroker(caps or {"query_recent_alerts": CapabilitySpec(_handler)}, **kw)


def _req(capability="query_recent_alerts", arguments=None, **kw):
    return MioCapabilityRequest(kw.pop("request_id", "r1"), kw.pop("trace_id", "t1"), capability, arguments or {}, **kw)


# --- closed request contract ----------------------------------------------------------


def test_request_dataclass_is_frozen_and_closed():
    request = _req()
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.capability = "exec_shell"  # type: ignore[misc]
    with pytest.raises(TypeError):
        MioCapabilityRequest("r1", "t1", "query_recent_alerts", {}, execute=True)  # type: ignore[call-arg]


def test_duck_typed_or_subclassed_requests_are_invalid_and_never_reach_handler():
    calls = []
    broker = _broker({"query_recent_alerts": CapabilitySpec(lambda a: calls.append(a) or {})})

    class Sub(MioCapabilityRequest):
        pass

    class Duck:
        request_id = "r1"
        trace_id = "t1"
        capability = "query_recent_alerts"
        arguments = {}
        purpose_hypothesis_ids = ()
        max_age_seconds = None
        approved = True

    for request in (Duck(), Sub("r1", "t1", "query_recent_alerts", {}), {"capability": "query_recent_alerts"}, None):
        result = broker.submit(request)
        assert (result.status, result.error) == ("invalid", "request_type_invalid")
    assert calls == []
    with pytest.raises(CapabilityBrokerError):
        broker.execute(Duck())


@pytest.mark.parametrize(
    "purpose",
    [
        "h1",
        ("h1",) * 9,
        ("h1", 7),
        ("",),
        ("x" * 97,),
        ("h1\x00",),
        {"h1": 1},
        None,
    ],
)
def test_purpose_hypothesis_ids_are_typed_and_bounded(purpose):
    calls = []
    broker = _broker({"query_recent_alerts": CapabilitySpec(lambda a: calls.append(a) or {})})
    result = broker.submit(_req(purpose_hypothesis_ids=purpose))
    assert (result.status, result.error) == ("invalid", "invalid_purpose_hypothesis_ids")
    assert calls == []


def test_valid_purpose_hypothesis_ids_are_accepted():
    assert _broker().submit(_req(purpose_hypothesis_ids=("h1", "h2"))).status == "ok"


# --- cycle close (stale-cycle cancellation) -----------------------------------------


def test_closed_broker_refuses_new_requests_without_calling_handler():
    calls = []
    broker = _broker({"query_recent_alerts": CapabilitySpec(lambda a: calls.append(a) or {})})
    broker.close()
    broker.close()  # idempotent
    assert broker.closed
    result = broker.submit(_req())
    assert (result.status, result.error) == ("rejected", "broker_closed")
    assert calls == []
    assert broker.audit_records()[-1]["decision"] == "refused"


def test_close_wakes_in_flight_request_as_stale_without_data():
    started = threading.Event()
    release = threading.Event()

    def slow(_args):
        started.set()
        release.wait(5)
        return {"summary": "late", "evidence_refs": ["ev:late:1"], "source_timestamp": NOW}

    broker = _broker({"query_recent_alerts": CapabilitySpec(slow, timeout_seconds=10)})
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", broker.submit(_req())))
    t.start()
    try:
        assert started.wait(2)
        began = time.monotonic()
        broker.close()
        t.join(2)
        assert not t.is_alive()
        # Woken by close(), not by the 10 s capability timeout.
        assert time.monotonic() - began < 2
        result = out["r"]
        assert (result.status, result.error) == ("stale", "cycle_closed")
        assert result.data == {} and result.evidence_refs == () and not result.ok
        assert broker.quarantined() == 1
    finally:
        release.set()
    _wait_quarantine_drained(broker)


def _wait_quarantine_drained(broker):
    deadline = time.monotonic() + 2
    while broker.quarantined() and time.monotonic() < deadline:
        threading.Event().wait(0.01)
    assert broker.quarantined() == 0


def test_handler_finishing_after_close_is_discarded():
    gate = threading.Event()
    holder = {}

    def handler(_args):
        holder["broker"].close()  # the cycle is superseded while the handler runs
        gate.set()
        return {"summary": "data from a superseded cycle", "source_timestamp": NOW}

    broker = _broker({"query_recent_alerts": CapabilitySpec(handler, timeout_seconds=2)})
    holder["broker"] = broker
    result = broker.submit(_req())
    assert gate.is_set()
    assert (result.status, result.error) == ("stale", "cycle_closed")
    assert result.data == {} and result.evidence_refs == ()
    _wait_quarantine_drained(broker)
    # execute() returns stale as data (it only raises for refusals).
    assert broker_module.CapabilityStatus.STALE.value not in broker_module.REFUSAL_STATUSES


# --- audit projection -----------------------------------------------------------------


ADDRESS_OR_SECRET_IDS = [
    "10.0.0.5",
    "ev:10.0.0.5:22",
    "fe80::1",
    "aa:bb:cc:dd:ee:ff",
    "host-192-168-1-20",
    "sk-live-SUPERSECRET0123456789abcdef",
    "AKIAABCDEFGHIJKLMNOP",
]


@pytest.mark.parametrize("value", ADDRESS_OR_SECRET_IDS)
def test_audit_never_records_addresses_or_credentials_verbatim(value):
    sink = []

    def handler(_args):
        return {"summary": "x", "evidence_refs": [value, "ev:alert:1"], "source_timestamp": NOW}

    broker = _broker({"query_recent_alerts": CapabilitySpec(handler)}, audit_sink=sink.append)
    result = broker.submit(_req(request_id=value, trace_id=value, purpose_hypothesis_ids=(value, "h1")))
    assert result.status == "ok"
    record = sink[-1]
    dumped = json.dumps(record)
    assert value not in dumped
    assert record["request_id"].startswith("h:") and record["trace_id"].startswith("h:")
    assert record["purpose_hypothesis_ids"][0].startswith("h:") and record["purpose_hypothesis_ids"][1] == "h1"
    assert record["evidence_refs"][1] == "ev:alert:1" and record["evidence_refs"][0].startswith("h:")


def test_audit_keeps_ordinary_opaque_ids():
    sink = []
    _broker(audit_sink=sink.append).submit(_req(request_id="c1:req:1", trace_id="trace-1", purpose_hypothesis_ids=("h1",)))
    record = sink[-1]
    assert (record["request_id"], record["trace_id"], record["purpose_hypothesis_ids"]) == ("c1:req:1", "trace-1", ["h1"])
    assert record["evidence_refs"] == ["ev:alert:1"]


def test_audit_records_have_exactly_the_allowlisted_fields():
    sink = []
    broker = _broker(audit_sink=sink.append)
    broker.submit(_req())
    broker.submit(_req("exec_shell"))
    broker.submit(_req(arguments={"question": "q", "zz": 1}))
    broker.submit(object())
    broker.close()
    broker.submit(_req())
    assert len(sink) == 5
    for record in sink:
        assert tuple(record) == broker_module.AUDIT_RECORD_FIELDS


def test_audit_reason_follows_closed_grammar():
    class Weird(Exception):
        pass

    Weird.__name__ = "Weird 10.0.0.5 pw=hunter2"

    def boom(_args):
        raise Weird("pw=hunter2 10.0.0.5")

    sink = []
    result = _broker({"query_recent_alerts": CapabilitySpec(boom)}, audit_sink=sink.append).submit(_req())
    assert result.status == "error"
    assert sink[-1]["reason"] == "reason_redacted"
    dumped = json.dumps(sink)
    assert "10.0.0.5" not in dumped and "hunter2" not in dumped


# --- repository scan: no generic network / shell / write capability ------------------


def _literal_capability_names() -> set[str]:
    """Capability names registered with string literals anywhere in py/ and bin/.

    Scope: literal names in ``{"name": CapabilitySpec(...)}``,
    ``caps["name"] = CapabilitySpec(...)`` and ``dict(name=CapabilitySpec(...))``.
    Names computed at runtime come from fixtures (scanned separately) and are
    refused at broker construction by the same registry rules anyway.
    """
    names: set[str] = set()
    for base in (ROOT / "py", ROOT / "bin"):
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in {"", ".py"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if "CapabilitySpec" not in text or path.name == "broker.py":
                continue
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Dict):
                    for key, value in zip(node.keys, node.values):
                        if _is_literal(key) and _is_spec_call(value):
                            names.add(key.value)
                elif isinstance(node, ast.Assign) and _is_spec_call(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Subscript) and _is_literal(target.slice):
                            names.add(target.slice.value)
                elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "dict":
                    names.update(kw.arg for kw in node.keywords if kw.arg and _is_spec_call(kw.value))
    return names


def _is_literal(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_spec_call(node) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return getattr(func, "id", "") == "CapabilitySpec" or getattr(func, "attr", "") == "CapabilitySpec"


def _fixture_capability_names() -> set[str]:
    names: set[str] = set()
    for path in (ROOT / "tests" / "fixtures").rglob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get("capabilities"), dict):
            names.update(k for k in payload["capabilities"] if isinstance(k, str))
    return names


def test_every_capability_the_repo_names_passes_read_only_registry_rules():
    names = set(_literal_capability_names()) | _fixture_capability_names()
    for playbook in DEFAULT_PLAYBOOKS.values():
        names.update(playbook.allowed_capabilities)
    assert names, "scan found no capability names"
    for name in sorted(names):
        broker_module._frozen_spec(name, CapabilitySpec(_handler))
        tokens = set(name.split("_"))
        assert not tokens & broker_module.FORBIDDEN_NAME_TOKENS, name
        assert not any(stem in name for stem in broker_module.FORBIDDEN_NAME_STEMS), name


@pytest.mark.parametrize(
    "name",
    ["query_network_socket", "get_shell", "read_and_write", "query_http_status", "lookup_dns_then_connect", "get_remote_url"],
)
def test_generic_network_shell_or_write_capabilities_cannot_be_registered(name):
    with pytest.raises(CapabilityBrokerError):
        CapabilityBroker({name: CapabilitySpec(_handler)})


# --- review follow-ups ----------------------------------------------------------------


def test_finished_handler_is_never_seen_as_timeout(monkeypatch):
    """The worker must mark itself done before it wakes the submitter.

    The hooked event blocks the worker inside ``set()`` until submit() has
    returned. With the old order (wake, then done) the submitter would wake,
    see done=False and report a timeout; with the fixed order it sees done.
    """
    submit_returned = threading.Event()

    class HookedEvent(threading.Event):
        def set(self):
            super().set()
            if threading.current_thread().name.startswith("mio-cap-"):
                submit_returned.wait(2)

    monkeypatch.setattr(broker_module, "_Event", HookedEvent)
    broker = _broker({"query_recent_alerts": CapabilitySpec(_handler, timeout_seconds=5)})
    try:
        result = broker.submit(_req())
    finally:
        submit_returned.set()
    assert (result.status, result.error) == ("ok", "")
    assert result.data == {"summary": "ok"}
    _wait_quarantine_drained(broker)


def _blocking_caps(n, release, entered, **spec_kw):
    def slow(_args):
        entered.release()
        release.wait(5)
        return {}

    return {f"query_slow_{chr(97 + i)}": CapabilitySpec(slow, timeout_seconds=10, **spec_kw) for i in range(n)}


def test_quarantine_bound_holds_when_close_strands_every_running_handler():
    # Reviewer repro: max_quarantined=1, max_in_flight=16, max_concurrency=8.
    release = threading.Event()
    entered = threading.Semaphore(0)

    def slow(_args):
        entered.release()
        release.wait(5)
        return {}

    broker = _broker(
        {"query_slow": CapabilitySpec(slow, timeout_seconds=10, max_concurrency=8, max_calls_per_cycle=8)},
        max_quarantined=1, max_in_flight=16,
    )
    results = []
    threads = [threading.Thread(target=lambda i=i: results.append(broker.submit(_req("query_slow", request_id=f"r{i}")))) for i in range(8)]
    try:
        for t in threads:
            t.start()
        assert entered.acquire(timeout=2)
        # Seven are refused at once; wait for them (the admitted one stays blocked).
        deadline = time.monotonic() + 2
        while len(results) < 7 and time.monotonic() < deadline:
            threading.Event().wait(0.01)
        assert len(results) == 7
        broker.close()
        for t in threads:
            t.join(2)
        assert broker.quarantined() <= broker.quarantine_limit() == 1
        statuses = sorted((r.status, r.error) for r in results)
        assert statuses.count(("stale", "cycle_closed")) == 1
        assert statuses.count(("rejected", "broker_overloaded")) == 7
    finally:
        release.set()
    _wait_quarantine_drained(broker)


def test_running_plus_quarantined_workers_never_exceed_limit():
    release = threading.Event()
    entered = threading.Semaphore(0)
    caps = _blocking_caps(3, release, entered)
    caps["query_hang"] = CapabilitySpec(lambda _: release.wait(5) and {}, timeout_seconds=0.02)
    broker = _broker(caps, max_quarantined=2, max_in_flight=4)
    t = None
    try:
        assert broker.submit(_req("query_hang")).status == "timeout"  # one quarantined
        assert broker.quarantined() == 1
        t = threading.Thread(target=broker.submit, args=(_req("query_slow_a"),))
        t.start()
        assert entered.acquire(timeout=2)  # one running
        refused = broker.submit(_req("query_slow_b"))
        assert (refused.status, refused.error) == ("rejected", "broker_quarantine_full")
        broker.close()
        t.join(2)
        assert broker.quarantined() == 2 == broker.quarantine_limit()
    finally:
        release.set()
        if t is not None:
            t.join(5)
    _wait_quarantine_drained(broker)


def test_per_capability_live_workers_never_exceed_max_concurrency():
    release = threading.Event()
    entered = threading.Semaphore(0)

    def handler(_args):
        entered.release()
        release.wait(5)
        return {}

    broker = _broker({"query_slow": CapabilitySpec(handler, timeout_seconds=0.05, max_concurrency=2, max_calls_per_cycle=8)})
    try:
        assert broker.submit(_req("query_slow")).status == "timeout"
        out = {}
        t = threading.Thread(target=lambda: out.setdefault("r", broker.submit(_req("query_slow", request_id="r2"))))
        t.start()
        t.join(2)
        assert out["r"].status == "timeout"
        assert broker.submit(_req("query_slow", request_id="r3")).error == "capability_quarantined"
        assert broker.quarantined() == 2
    finally:
        release.set()
    _wait_quarantine_drained(broker)


ADDRESS_OR_PERSON_IDS = [
    "c0a80105",
    "ev:c0a80105",
    "3232235777",
    "ev:3232235777",
    "001122334455",
    "aabbccddeeff",
    "ev:aabbccddeeff",
    "10x0x0x1",
    "ev:10:0:0:1",
    "ev:10-0-0-1",
    "Bearer_abcdefghijklmnop1234",
    "bearer_abcdefghijklmnop1234",
    "alice-laptop.corp",
    "alice-laptop",
    "user_john_smith",
    "john",
    "deadbeefdeadbeef",
    "trace-0x2d46936d1d47a084:alice",
]


@pytest.mark.parametrize("value", ADDRESS_OR_PERSON_IDS)
def test_audit_digests_ids_outside_the_closed_schema(value):
    assert broker_module._audit_id(value).startswith("h:")
    sink = []

    def handler(_args):
        return {"summary": "x", "evidence_refs": [value], "source_timestamp": NOW}

    broker = _broker({"query_recent_alerts": CapabilitySpec(handler)}, audit_sink=sink.append)
    assert broker.submit(_req(request_id=value, trace_id=value, purpose_hypothesis_ids=(value,))).status == "ok"
    assert value not in json.dumps(sink[-1])


REPO_PRODUCED_IDS = [
    # evidence plane event id (make_event_id)
    "sha256:" + "ab" * 32,
    # Edge core trace id (calc_trace_id) and lifecycle-derived cycle / request ids
    "trace-0x2d46936d1d47a084",
    "trace-0x1f",
    "trace-0x2d46936d1d47a084:e1:c3",
    "trace-0x2d46936d1d47a084:e1:c3:req:2",
    # fixtures, replay and evaluation
    "ev:auth:0001", "ev:flow:0001", "ev:noc:0001", "ev:soc:0001", "ev:ssh:1", "ev:alert:1",
    "trace-golden-activity-1", "trace-golden-redirect-3", "trace-golden-v2", "trace-test-1", "trace-1",
    "mio-fixture-auth-1", "mio-fixture-auth-1:cycle", "mio-fixture-auth-1:cycle:req:1",
    "replay:g5-golden-replay-v1:req:1",
    "evaluation:recorded-qwen-2b-accepted:req:1", "evaluation:stale-evidence:req:2",
    "frame-golden-v1", "frame-1", "c1:req:1", "h1", "g1", "r1", "t1",
]


@pytest.mark.parametrize("value", REPO_PRODUCED_IDS)
def test_repo_produced_ids_stay_verbatim(value):
    assert broker_module._audit_id(value) == value


def test_repo_fixture_ids_stay_verbatim():
    seen = set()
    for path in (ROOT / "tests" / "fixtures" / "mio").rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        for key in ("trace_id", "cycle_id", "event_id", "frame_id", "scenario_id", "fixture_id", "hypothesis_id"):
            for chunk in text.split(f'"{key}"')[1:]:
                value = chunk.split('"')[1] if chunk.lstrip(" :").startswith('"') else ""
                if value:
                    seen.add(value)
    assert seen
    kept = {v for v in seen if broker_module._audit_id(v) == v}
    # Digested on purpose: a placeholder hypothesis id, a fixture-only fake
    # "sha256:" id that is not a real digest, and a long id that the mio
    # redaction long-token rule flags (the redaction layer wins).
    expected_digested = {"existing-or-short-id", "sha256:fixture-ssh-1", "empty-recommendation-captured-381"}
    assert seen - kept <= expected_digested, sorted(seen - kept)


def test_audit_error_fallback_follows_the_allowlist(monkeypatch):
    sink = []
    broker = _broker(audit_sink=sink.append)

    def broken(*_a, **_k):
        raise RuntimeError("projection failed")

    monkeypatch.setattr(broker, "_record_audit", broken)
    assert broker.submit(_req()).status == "ok"
    record = sink[-1]
    assert tuple(record) == broker_module.AUDIT_RECORD_FIELDS
    assert record["reason"] == "audit_error" and record["status"] == "ok"
