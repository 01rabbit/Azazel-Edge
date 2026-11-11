"""Pure synthetic public config fixtures, no Root/VM/authentication claim."""

import hashlib
import json
from pathlib import Path
import sys

import pytest
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_transport import transport
from auth_input_helpers import make_policy

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_binding as b


def fixture(tmp_path, monkeypatch):
    policy, *_ = make_policy(tmp_path, producer=61001, observer=61002, witness=0)
    trust = dict(
        policy.data,
        schema_version="outcome-input-trust/v3",
        origin_registration_sha256="f" * 64,
    )
    origin = dict(
        schema_version="outcome-live-origin-registration/v4",
        mode="live-core",
        **{
            k: trust[k]
            for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
        },
    )
    files = {
        "trust.json": json.dumps(trust).encode(),
        "origin.json": json.dumps(origin).encode(),
    }
    calls = []
    monkeypatch.setattr(b.g, "guard", lambda: calls.append("guard"))
    monkeypatch.setattr(b.os, "geteuid", lambda: 0)
    monkeypatch.setenv(b.FLAG, "1")

    def read(path, **kwargs):
        calls.append((path, kwargs))
        assert path in {b.g.BUNDLE / "trust.json", b.g.BUNDLE / "origin.json"}
        return files[path.name], None

    monkeypatch.setattr(b, "read_regular", read)
    return trust, origin, files, calls


def test_fixed_public_only_read_and_separate_observed_configured_digests(
    tmp_path, monkeypatch
):
    trust, origin, files, calls = fixture(tmp_path, monkeypatch)
    result = b.public_auth_binding()
    assert calls == [
        "guard",
        (b.g.BUNDLE / "trust.json", dict(owner=0, max_bytes=8192)),
        (b.g.BUNDLE / "origin.json", dict(owner=0, max_bytes=16384)),
    ]
    assert (
        result["trust_file_sha256"] == hashlib.sha256(files["trust.json"]).hexdigest()
    )
    assert (
        result["origin_file_sha256"] == hashlib.sha256(files["origin.json"]).hexdigest()
    )
    assert (
        result["origin_registration_sha256"] == "f" * 64 != result["origin_file_sha256"]
    )
    assert result["trust_sha256"] == TrustPolicy(trust).digest
    assert result["scope"] == "public_root_config_continuity_only"
    assert result["source_path"] == trust["source_path"]


@pytest.mark.parametrize(
    "file,key,value",
    [
        ("trust.json", "producer_uid", True),
        ("trust.json", "observer_uid", 123),
        ("trust.json", "source_path", "../input"),
        ("trust.json", "schema_version", "outcome-input-trust/v1"),
        ("origin.json", "schema_version", "old"),
        ("origin.json", "mode", "replay"),
        ("origin.json", "scope_ref", 12),
        ("origin.json", "producer_public_key", "0" * 64),
    ],
)
def test_typed_public_context_refusals(tmp_path, monkeypatch, file, key, value):
    _, _, files, _ = fixture(tmp_path, monkeypatch)
    item = json.loads(files[file])
    item[key] = value
    files[file] = json.dumps(item).encode()
    with pytest.raises((ValueError, OSError)):
        b.public_auth_binding()


@pytest.mark.parametrize("raw", [b"[]", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"partial"'])
def test_origin_malformed_strict_public_parse_refuses(tmp_path, monkeypatch, raw):
    _, _, files, _ = fixture(tmp_path, monkeypatch)
    files["origin.json"] = raw
    with pytest.raises((ValueError, OSError)):
        b.public_auth_binding()


@pytest.mark.parametrize("file", ["trust.json", "origin.json"])
def test_changed_public_bytes_change_snapshot_even_same_context(
    tmp_path, monkeypatch, file
):
    _, _, files, _ = fixture(tmp_path, monkeypatch)
    before = b.public_auth_binding()
    files[file] += b"\n"
    after = b.public_auth_binding()
    assert before != after
    assert before["scope_ref"] == after["scope_ref"]


@pytest.mark.parametrize("fault", ["guard", "uid", "flag", "read"])
def test_guard_and_protected_read_failure_never_fallback(tmp_path, monkeypatch, fault):
    _, _, _, calls = fixture(tmp_path, monkeypatch)

    def refuse(*a, **k):
        raise OSError("synthetic protected material failure")

    if fault == "guard":
        monkeypatch.setattr(b.g, "guard", refuse)
    if fault == "uid":
        monkeypatch.setattr(b.os, "geteuid", lambda: 61002)
    if fault == "flag":
        monkeypatch.delenv(b.FLAG)
    if fault == "read":
        monkeypatch.setattr(b, "read_regular", refuse)
    with pytest.raises((ValueError, OSError)):
        b.public_auth_binding()
    if fault in {"guard", "uid", "flag"}:
        assert all(type(item) is str for item in calls)


def test_public_paths_are_only_metadata_never_additional_read_selectors(
    tmp_path, monkeypatch
):
    _, _, files, calls = fixture(tmp_path, monkeypatch)
    value = json.loads(files["trust.json"])
    value["source_path"] = "/nonexistent/metadata-only/input"
    value["journal_directory"] = "/nonexistent/metadata-only/journal"
    files["trust.json"] = json.dumps(value).encode()
    result = b.public_auth_binding()
    assert result["source_path"] == value["source_path"]
    assert result["journal_directory"] == value["journal_directory"]
    assert len(calls) == 3


def test_explicit_v4_transport_is_retained_as_public_metadata_only(
    tmp_path, monkeypatch
):
    _, _, files, calls = fixture(tmp_path, monkeypatch)
    value = json.loads(files["trust.json"])
    selected = transport(
        value["scope_ref"],
        dict(cookie=71, kernel_boot_id="095d28ff-ca7d-4b08-9e4b-e36a62db4810"),
    )
    value.update(schema_version="outcome-input-trust/v4", witness_transport=selected)
    files["trust.json"] = json.dumps(value).encode()
    observed = b.public_auth_binding()
    assert observed["trust_schema"] == "outcome-input-trust/v4"
    assert observed["witness_transport"] == selected
    assert observed["trust_sha256"] == TrustPolicy(value).digest and len(calls) == 3
