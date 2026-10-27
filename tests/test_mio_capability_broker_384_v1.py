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
    """Capability names registered with string literals anywhere in py/ and bin/."""
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
                        if (
                            isinstance(key, ast.Constant) and isinstance(key.value, str)
                            and isinstance(value, ast.Call) and getattr(value.func, "id", "") == "CapabilitySpec"
                        ):
                            names.add(key.value)
    return names


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
