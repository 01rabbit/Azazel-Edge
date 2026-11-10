"""Signature provenance, explicit trust context and fail-closed client checks."""

import builtins
import copy
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("cryptography")
from azazel_edge.outcome.input_auth import (
    TrustPolicy,
    SourceVerifier,
    SignedCaptureWriter,
    sign,
    private_key,
    SOURCE_DOMAIN,
    SOURCE_SCHEMA,
    read_regular,
    public_hex,
)
from azazel_edge.outcome.input_witness import (
    WitnessClient,
    RESPONSE_DOMAIN,
    validate_state,
)
from azazel_edge.outcome.journal import OutcomeJournalError, _json, ZERO_HASH
from auth_input_helpers import make_policy
from test_outcome_telemetry_g3 import rust_event


def signed(policy, key, *, seq=1, prev=ZERO_HASH, **overrides):
    p = policy.data
    core = dict(
        schema_version=SOURCE_SCHEMA,
        scope_ref=p["scope_ref"],
        producer_ref=p["producer_ref"],
        stream_ref=p["stream_ref"],
        boot_ref="boot-a",
        seq=seq,
        prev=prev,
        event=rust_event(ts="2026-01-01T00:00:00Z", trace="event-" + str(seq)),
    )
    core.update(overrides)
    wire = {**core, "signature": sign(key, SOURCE_DOMAIN, core)}
    return _json(wire) + b"\n"


def test_public_verification_and_cached_prefix_never_forge_source(tmp_path):
    p, pk, _, _, _ = make_policy(tmp_path)
    raw = signed(p, pk)
    v = SourceVerifier(p)
    tip = v.verify(raw)
    assert tip["seq"] == 1 and tip["size"] == len(raw)
    assert json.loads(v.unwrap(raw))["pipeline"] == "rust_event_engine_v1"
    assert v.verify(raw) == tip
    second = signed(p, pk, seq=2, prev=tip["head"])
    assert v.verify(raw + second)["seq"] == 2
    with pytest.raises(OSError):
        v.verify(raw)
    with pytest.raises(TypeError):
        p.data["scope_ref"] = "mutated"


@pytest.mark.parametrize(
    "fault",
    [
        "event",
        "sig",
        "key",
        "seq",
        "prev",
        "scope",
        "producer",
        "stream",
        "boot",
        "extra",
        "duplicate",
        "whitespace",
        "tail",
        "oversize",
        "overflow",
    ],
)
def test_modified_forged_or_ambiguous_source_refused(tmp_path, fault):
    p, pk, wk, _, _ = make_policy(tmp_path)
    raw = signed(p, pk)
    wire = json.loads(raw)
    if fault == "event":
        wire["event"]["normalized"]["sid"] = 999
    elif fault == "sig":
        wire["signature"] = "0" * 128
    elif fault == "key":
        raw = signed(p, wk)
    elif fault in ("seq", "prev", "scope", "producer", "stream", "boot"):
        field = {
            "scope": "scope_ref",
            "producer": "producer_ref",
            "stream": "stream_ref",
            "boot": "boot_ref",
        }.get(fault, fault)
        value = (
            2
            if fault == "seq"
            else (
                "1" * 64
                if fault == "prev"
                else "other" if fault != "boot" else "../unsafe"
            )
        )
        raw = signed(p, pk, **{field: value})
    elif fault == "extra":
        wire["extra"] = True
    elif fault == "duplicate":
        raw = raw.replace(b'"seq":1', b'"seq":1,"seq":1')
    elif fault == "whitespace":
        raw = b" " + raw
    elif fault == "tail":
        raw = raw[:-1]
    elif fault == "oversize":
        raw = signed(p, pk, event={"value": "x" * 65536})
    else:
        raw = raw.replace(b'"seq":1', b'"seq":1e400')
    if fault in ("event", "sig", "extra"):
        raw = _json(wire) + b"\n"
    with pytest.raises(OSError):
        SourceVerifier(p).verify(raw)


def test_reorder_delete_duplicate_and_cross_generation_chain_refused(tmp_path):
    p, pk, _, _, _ = make_policy(tmp_path)
    one = signed(p, pk)
    head = hashlib.sha256(one[:-1]).hexdigest()
    two = signed(p, pk, seq=2, prev=head)
    assert SourceVerifier(p).verify(one + two)["seq"] == 2
    for data in (two + one, one + one, two):
        with pytest.raises(OSError):
            SourceVerifier(p).verify(data)
    v = SourceVerifier(p)
    v.verify(one)
    with pytest.raises(OSError):
        v.verify(signed(p, pk, event={"different": "signed fork"}))


@pytest.mark.skipif(
    os.geteuid() == 0,
    reason="capture writer is intentionally non-root; exercised under its actual UID in Linux boundary tests",
)
def test_capture_writer_role_key_durability_and_external_mutation(tmp_path):
    p, pk, _, private, _ = make_policy(tmp_path)
    path = Path(p.data["source_path"])
    path.touch(mode=0o644)
    key = tmp_path / "private"
    key.write_bytes(private)
    key.chmod(0o600)
    with SignedCaptureWriter(p, key, boot_ref="boot-a") as writer:
        result = writer.append({"test": "capture"})
        assert result["seq"] == 1
        assert SourceVerifier(p).verify(path.read_bytes()) == result
        with pytest.raises(OSError):
            SignedCaptureWriter(p, key, boot_ref="boot-a")
    with SignedCaptureWriter(p, key, boot_ref="boot-b") as writer:
        assert writer.append({"test": "next boot, sequence retained"})["seq"] == 2
        path.write_bytes(path.read_bytes().replace(b"capture", b"changed"))
        with pytest.raises(OSError):
            writer.append({"test": "no retry"})
        assert writer.poisoned
    with pytest.raises(OSError):
        SignedCaptureWriter(p, key, boot_ref="boot-c")


@pytest.mark.parametrize(
    "fault", ["missing", "mode", "symlink", "hardlink", "wrong_key", "ancestor"]
)
def test_signing_key_not_optional_or_silently_replaced(tmp_path, fault):
    p, _, _, material, other = make_policy(tmp_path)
    key = tmp_path / "private"
    if fault != "missing":
        key.write_bytes(other if fault == "wrong_key" else material)
        key.chmod(0o600)
    if fault == "ancestor":
        tmp_path.chmod(0o777)
    if fault == "mode":
        key.chmod(0o644)
    elif fault == "symlink":
        key.rename(tmp_path / "moved")
        key.symlink_to(tmp_path / "moved")
    elif fault == "hardlink":
        os.link(key, tmp_path / "link")
    with pytest.raises(OSError):
        private_key(key, p.data["producer_public_key"])


def test_requested_crypto_profile_missing_is_not_unsigned_fallback(tmp_path):
    p, *_ = make_policy(tmp_path)
    path = tmp_path / "policy"
    path.write_bytes(_json(dict(p.data)))
    path.chmod(0o644)
    real = builtins.__import__

    def missing(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("injected absent profile")
        return real(name, *args, **kwargs)

    with patch("builtins.__import__", missing):
        with pytest.raises(OSError, match="preprovisioned"):
            from azazel_edge.outcome.input_auth import crypto

            crypto()


def state():
    return dict(
        journal_seq=0,
        journal_head=ZERO_HASH,
        journal_size=0,
        journal_sha256=hashlib.sha256(b"").hexdigest(),
        journal_device=0,
        journal_inode=0,
        source_seq=0,
        source_head=ZERO_HASH,
        source_size=0,
        source_sha256=hashlib.sha256(b"").hexdigest(),
    )


def response(p, wk, request, **overrides):
    core = dict(
        schema_version="outcome-input-witness-response/v1",
        trust_sha256=p.digest,
        op=request["op"],
        nonce=request["nonce"],
        counter=1,
        anchor_head="a" * 64,
        state=state(),
    )
    core.update(overrides)
    return {**core, "signature": sign(wk, RESPONSE_DOMAIN, core)}


@pytest.mark.parametrize(
    "fault",
    [
        "nonce",
        "context",
        "signature",
        "domain",
        "key",
        "counter",
        "backward",
        "state",
        "extra",
    ],
)
def test_fresh_challenge_pinned_role_key_and_counters_required(tmp_path, fault):
    observer = os.geteuid() or 65534
    p, pk, wk, _, _ = make_policy(
        tmp_path, observer=observer, witness=0, producer=65533
    )
    with patch("os.geteuid", return_value=observer):
        client = WitnessClient(p)
    request = dict(op="read", nonce="a" * 64, counter=0, anchor_head=ZERO_HASH)
    wire = response(p, wk, request)
    assert client.accept(wire, request)["journal_seq"] == 0
    bad = copy.deepcopy(wire)
    if fault == "nonce":
        bad = response(p, wk, request, nonce="b" * 64)
    elif fault == "context":
        bad = response(p, wk, request, trust_sha256="b" * 64)
    elif fault == "signature":
        bad["signature"] = "0" * 128
    elif fault == "domain":
        bad["signature"] = sign(
            wk, SOURCE_DOMAIN, {k: v for k, v in bad.items() if k != "signature"}
        )
    elif fault == "key":
        bad = response(p, pk, request)
    elif fault == "counter":
        bad = response(p, wk, request, counter=True)
    elif fault == "backward":
        client.counter = 2
    elif fault == "state":
        bad = response(p, wk, request, state={**state(), "journal_seq": True})
    else:
        bad["extra"] = True
    with pytest.raises(OSError):
        client.accept(bad, request)


@pytest.mark.parametrize(
    "change",
    [
        {"observer_uid": 0, "witness_uid": 0},
        {"input_max_records": True},
        {"source_path": "relative"},
        {"stream_ref": "../x"},
        {"producer_public_key": "0"},
        {"anchor_max_records": 1},
        {"observer_uid": 0, "witness_uid": 1234, "producer_uid": 1000},
        {"producer_uid": 0, "witness_uid": 1234, "observer_uid": 65534},
    ],
)
def test_invalid_public_trust_configuration_refused(tmp_path, change):
    p, *_ = make_policy(tmp_path)
    with pytest.raises(OSError):
        TrustPolicy({**p.data, **change})


def test_auth_cli_never_downgrades_to_legacy_path():
    from azazel_edge.outcome import telemetry

    with patch.object(telemetry, "run_live") as live:
        with pytest.raises(SystemExit):
            telemetry.main(["--policy", "unused", "--input-auth-policy", "/untrusted"])
        assert not live.called
        telemetry.main(["--policy", "unused"])
        assert live.call_args.kwargs["authentication_policy"] is None
