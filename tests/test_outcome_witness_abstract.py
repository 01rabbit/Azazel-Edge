"""Explicit transport contracts; ephemeral crypto, no namespace/role transitions."""

import hashlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from auth_input_helpers import make_policy
from test_outcome_live_origin import frame, signed_frame
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier
from azazel_edge.outcome import input_transport as t, input_witness as w
from azazel_edge.outcome.journal import OutcomeJournalError, _json


def policy(tmp_path):
    p, key, *_ = make_policy(tmp_path)
    return TrustPolicy(
        dict(
            p.data,
            schema_version=t.SCHEMA,
            origin_registration_sha256="f" * 64,
            witness_transport=t.transport(
                p.data["scope_ref"], dict(device=4, inode=123)
            ),
        )
    ), key


def test_policy_v4_digest_binds_canonical_transport_and_copies_nested_input(tmp_path):
    p, _ = policy(tmp_path)
    raw = _json(dict(p.data))
    value = __import__("json").loads(raw)
    q = TrustPolicy(value)
    value["witness_transport"]["network_namespace"]["inode"] = 456
    assert _json(dict(q.data)) == raw and q.digest == hashlib.sha256(raw).hexdigest()
    for target in (
        q.data["witness_transport"],
        q.data["witness_transport"]["network_namespace"],
    ):
        for mutation in (
            lambda: target.update(extra=1),
            lambda: target.clear(),
            lambda: target.pop(next(iter(target))),
            lambda: target.__setitem__(next(iter(target)), None),
            lambda: target.__ior__({"extra": 1}),
        ):
            with pytest.raises(TypeError):
                mutation()
    for target in (
        q.data["witness_transport"],
        q.data["witness_transport"]["network_namespace"],
    ):
        target.__init__({"unexpected": "replacement"})
    assert _json(dict(q.data)) == raw and q.digest == hashlib.sha256(raw).hexdigest()
    changed = TrustPolicy(
        dict(
            p.data,
            witness_transport=t.transport(
                p.data["scope_ref"], dict(device=4, inode=456)
            ),
        )
    )
    assert changed.digest != p.digest
    assert (
        t.transport("scope-b", dict(device=4, inode=123))["name"]
        != p.data["witness_transport"]["name"]
    )


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "extra",
        "kind",
        "name",
        "scope",
        "ns_extra",
        "ns_missing",
        "bool",
        "float",
        "zero",
        "negative",
        "overflow",
        "v3",
        "v1",
        "missing_registration",
    ],
)
def test_exact_policy_transport_refuses_malformed_or_implicit_downgrade(
    tmp_path, fault
):
    p, _ = policy(tmp_path)
    value = __import__("json").loads(_json(dict(p.data)))
    transport = value["witness_transport"]
    if fault == "missing":
        del value["witness_transport"]
    elif fault == "extra":
        transport["fallback"] = "pathname"
    elif fault in ("kind", "name"):
        transport[fault] += "-other"
    elif fault == "scope":
        value["scope_ref"] = "other-scope"
    elif fault == "ns_extra":
        transport["network_namespace"]["path"] = "/proc/self/ns/net"
    elif fault == "ns_missing":
        del transport["network_namespace"]["device"]
    elif fault in ("bool", "float", "zero", "negative", "overflow"):
        transport["network_namespace"]["inode"] = dict(
            bool=True, float=123.0, zero=0, negative=-1, overflow=2**64
        )[fault]
    elif fault in ("v1", "v3"):
        value["schema_version"] = "outcome-input-trust/" + fault
    elif fault == "missing_registration":
        del value["origin_registration_sha256"]
    with pytest.raises(OutcomeJournalError):
        TrustPolicy(value)


@pytest.mark.parametrize("fault", ["wrongns", "missing", "nonlinux"])
def test_both_endpoints_refuse_before_socket_store_or_pathname_access(
    tmp_path, monkeypatch, fault
):
    p, _ = policy(tmp_path)
    monkeypatch.setattr(t.sys, "platform", "linux" if fault != "nonlinux" else "darwin")
    stat = Mock(return_value=SimpleNamespace(st_dev=4, st_ino=124))
    if fault == "missing":
        stat.side_effect = FileNotFoundError()
    monkeypatch.setattr(t.os, "stat", stat)
    socket, store, parent = Mock(), Mock(), Mock()
    monkeypatch.setattr(w.socket, "socket", socket)
    monkeypatch.setattr(w, "WitnessStore", store)
    monkeypatch.setattr(w, "open_parent", parent)
    monkeypatch.setattr(w.os, "geteuid", lambda: p.data["observer_uid"])
    with pytest.raises(OutcomeJournalError):
        w.WitnessClient(p).call("read")
    monkeypatch.setattr(w.os, "geteuid", lambda: p.data["witness_uid"])
    with pytest.raises(OutcomeJournalError):
        w.serve(p, tmp_path / "key", initialize=True)
    socket.assert_not_called()
    store.assert_not_called()
    parent.assert_not_called()


def test_matching_namespace_address_is_exact_bounded_public_bytes(
    tmp_path, monkeypatch
):
    p, _ = policy(tmp_path)
    monkeypatch.setattr(t.sys, "platform", "linux")
    monkeypatch.setattr(
        t.os, "stat", lambda path: SimpleNamespace(st_dev=4, st_ino=123)
    )
    address = t.abstract_address(p)
    assert (
        address
        == b"\0azazel-edge-witness-v1-"
        + hashlib.sha256(p.data["scope_ref"].encode()).hexdigest().encode()
    )
    assert len(address) <= 108


def test_v4_keeps_real_signed_native_lifecycle_and_registration_binding(tmp_path):
    p, key = policy(tmp_path)
    verifier = SourceVerifier(p)
    raw = b""
    for n, kind in enumerate(("session_prepare", "session_start", "session_end"), 1):
        raw += signed_frame(p, key, frame(kind, n - 1), n, verifier.head)
        verifier.verify(raw)
    assert verifier.live_state.closed
    altered = __import__("json").loads(raw.splitlines()[-1])
    altered["event"]["capture_origin"]["registration_sha256"] = "e" * 64
    with pytest.raises(OutcomeJournalError):
        SourceVerifier(p).verify(
            b"".join(raw.splitlines(keepends=True)[:-1]) + _json(altered) + b"\n"
        )
