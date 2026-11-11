"""Offline public artifact gates; no real manager, key or executable access."""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")
from auth_input_helpers import make_policy
from azazel_edge.outcome import commission_precheck as check
from azazel_edge.outcome import input_live
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_service import public_receipt
from azazel_edge.outcome.journal import _json


@pytest.fixture
def artifacts(tmp_path, monkeypatch):
    root = Path("/protected/bundle")
    p, producer_key, *_ = make_policy(
        tmp_path, producer=61001, observer=61002, witness=0
    )
    image = b"\x7fELFsynthetic-never-executed"
    r = dict(
        schema_version="outcome-live-origin-registration/v4",
        mode="live-core",
        **{
            k: p.data[k]
            for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
        },
        binary_path="/protected/core",
        binary_sha256=hashlib.sha256(image).hexdigest(),
        launcher_uid=0,
        ai_socket_uid=0,
        capture_apparmor_profile="capture-test",
        native_apparmor_profile="native-test",
        environment={
            "AZAZEL_" + k: v
            for k, v in dict(
                EVE_PATH="/protected/eve",
                NORMALIZED_EVENT_LOG="/protected/log",
                FORWARD_AI="0",
                FORWARD_LOG="0",
                EVENT_STDOUT="off",
                DEFENSE_ENFORCE="0",
                DEFENSE_DRY_RUN="1",
                DEFENSE_RELEASE_LEDGER="/protected/ledger",
                REDIRECT_POLICY_PATH="/protected/redirect",
                PROTECTED_FLOWS_PATH="/protected/flows",
                EVE_FROM_START="0",
            ).items()
        },
    )
    reads = []
    state = SimpleNamespace(r=r, image=image, source=b"", mode=0o100755, root=root)

    def enroll():
        state.p = TrustPolicy(
            {
                **p.data,
                "schema_version": "outcome-input-trust/v3",
                "origin_registration_sha256": hashlib.sha256(_json(r)).hexdigest(),
                "source_path": str(root / "input"),
                "journal_directory": str(root / "observer"),
                "anchor_directory": str(root / "witness/anchors"),
                "socket_path": str(root / "socket/witness.sock"),
            }
        )
        state.receipt = _json(public_receipt(root, state.p, r))

    state.producer_key = producer_key
    state.enroll = enroll
    enroll()

    def read(path, **kwargs):
        path = str(path)
        reads.append((path, kwargs))
        # Every other path (including both private keys) fails the test.
        data = {
            str(root / "origin.json"): _json(r),
            str(root / "provisioned.json"): state.receipt,
            "/protected/core": state.image,
            str(root / "input"): state.source,
        }[path]
        assert len(data) <= kwargs["max_bytes"]
        return data, SimpleNamespace(st_mode=state.mode)

    # Model the public schema branch here; real root path checks are Linux tests.
    monkeypatch.setattr("os.geteuid", lambda: 61001)
    monkeypatch.setattr(check, "require_root", lambda: None)
    monkeypatch.setattr(check.TrustPolicy, "from_file", lambda *a, **k: state.p)
    monkeypatch.setattr(check, "read_regular", read)
    monkeypatch.setattr(input_live, "read_regular", read)
    state.reads = reads
    return state


def run(state):
    return check.precheck(state.root, expected_trust_sha256=state.p.digest)


def test_inventory_is_deterministic_public_only_and_never_admission(artifacts):
    s = artifacts
    first = run(s)
    assert run(s) == first
    assert first["status"] == "PRECHECK_ONLY"
    assert first["authorizes_transition"] is False
    assert (
        "legacy_tc_provenance_and_exclusive_writer_coordination" in first["unresolved"]
    )
    assert "private_role_keys_and_actual_role_access" in first["unresolved"]
    assert set(first).isdisjoint(
        {"environment", "producer_public_key", "witness_public_key"}
    )
    assert all("key.raw" not in path for path, _ in s.reads)
    assert len(s.reads) == 8


def test_wrong_external_trust_pin_refuses_before_other_artifacts(artifacts):
    with pytest.raises(OSError, match="trust digest"):
        check.precheck(artifacts.root, expected_trust_sha256="a" * 64)
    assert artifacts.reads == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("AZAZEL_DEFENSE_ENFORCE", "1"),
        ("AZAZEL_DEFENSE_ENFORCE", "unknown"),
        ("AZAZEL_DEFENSE_DRY_RUN", "0"),
        ("AZAZEL_DEFENSE_DRY_RUN", "unknown"),
        ("AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO", "true"),
    ],
)
def test_unsafe_environment_cannot_be_prechecked(artifacts, field, value):
    artifacts.r["environment"][field] = value
    artifacts.enroll()
    with pytest.raises(OSError, match="disabled enforcement"):
        run(artifacts)


def test_registration_change_cannot_reuse_pin(artifacts):
    artifacts.r["native_apparmor_profile"] = "changed"
    with pytest.raises(OSError, match="digest mismatch"):
        run(artifacts)


@pytest.mark.parametrize(
    "fault", ["downgrade", "profile", "extra", "receipt", "image", "mode", "source"]
)
def test_artifact_or_history_fault_refuses_without_result(artifacts, fault):
    s = artifacts
    if fault == "downgrade":
        s.r["schema_version"] = "outcome-live-origin-registration/v3"
        del s.r["native_apparmor_profile"]
        s.enroll()
    elif fault == "profile":
        s.r["native_apparmor_profile"] = "unconfined"
        s.enroll()
    elif fault == "extra":
        s.r["operator_approved_exclusive_writer"] = True
        s.enroll()
    elif fault == "receipt":
        s.receipt = b"{}"
    elif fault == "image":
        s.image += b"changed"
    elif fault == "mode":
        s.mode |= 0o4000
    else:
        s.source = b"malformed\n"
    with pytest.raises((OSError, ValueError)):
        run(s)


@pytest.mark.parametrize(
    "failure", ["unsafe permission", "symlink", "identity changed"]
)
def test_protected_read_refusal_propagates_without_repair(
    artifacts, monkeypatch, failure
):
    def refuse(*a, **k):
        raise OSError(failure)

    monkeypatch.setattr(check, "read_regular", refuse)
    with pytest.raises(OSError, match=failure):
        run(artifacts)


def test_cli_failure_never_echoes_artifact_or_secret_details(monkeypatch, capsys):
    def refuse(*a, **k):
        raise OSError("secret details must not appear")

    monkeypatch.setattr(check, "precheck", refuse)
    assert (
        check.main(["--bundle", "/protected", "--expected-trust-sha256", "a" * 64]) == 1
    )
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == "commission PRECHECK refused\n"


def test_authentic_unclosed_session_refuses_without_resume(artifacts):
    from azazel_edge.outcome.input_auth import SOURCE_SCHEMA, SOURCE_DOMAIN, sign
    from azazel_edge.outcome.journal import ZERO_HASH

    s = artifacts
    core = dict(
        schema_version=SOURCE_SCHEMA,
        **{k: s.p.data[k] for k in ("scope_ref", "producer_ref", "stream_ref")},
        boot_ref="precheck-boot",
        seq=1,
        prev=ZERO_HASH,
        event=dict(
            pipeline="rust_live_origin_v1",
            source="capture_producer",
            capture_lifecycle=dict(state="prepare"),
            capture_origin=dict(
                schema_version="outcome-registered-origin/v2",
                mode="live-core",
                registration_sha256=s.p.data["origin_registration_sha256"],
                session_ref="a" * 32,
                seq=0,
                kind="session_prepare",
            ),
        ),
    )
    s.source = (
        _json({**core, "signature": sign(s.producer_key, SOURCE_DOMAIN, core)}) + b"\n"
    )
    original = s.source
    with pytest.raises(OSError, match="unclosed signed history"):
        run(s)
    assert s.source == original
