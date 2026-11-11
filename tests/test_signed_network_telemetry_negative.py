"""Pure synthetic negative pretest; unchanged real SourceVerifier/crypto only."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys

import pytest
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier
from azazel_edge.outcome.input_transport import transport
from azazel_edge.outcome.journal import OutcomeJournalError, ZERO_HASH, _json
from auth_input_helpers import make_policy

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_negative as negative

BOOT = "095d28ff-ca7d-4b08-9e4b-e36a62db4810"


def policy(tmp_path, *, abstract=False):
    value, *_ = make_policy(tmp_path, producer=61001, observer=61002, witness=0)
    return TrustPolicy(
        dict(
            value.data,
            schema_version="outcome-input-trust/v4"
            if abstract
            else "outcome-input-trust/v3",
            origin_registration_sha256="e" * 64,
            **(
                {
                    "witness_transport": transport(
                        value.data["scope_ref"],
                        dict(
                            cookie=71,
                            kernel_boot_id="095d28ff-ca7d-4b08-9e4b-e36a62db4810",
                        ),
                    )
                }
                if abstract
                else {}
            ),
        )
    )


@pytest.mark.parametrize("session", ["1" * 32, "a" * 32])
@pytest.mark.parametrize("boot", [BOOT, "a95d28ff-ca7d-4b08-9e4b-e36a62db4810"])
@pytest.mark.parametrize("abstract", [False, True], ids=["pathname", "abstract"])
def test_real_source_verifier_reaches_exact_crypto_refusal_without_acceptance(
    tmp_path, session, boot, abstract
):
    public = policy(tmp_path, abstract=abstract)
    fixture = negative.synthetic_prepare_frame(
        public, kernel_boot_id=boot, session_ref=session
    )
    verifier = SourceVerifier(public)
    before = verifier.tip(), verifier.live_state
    with pytest.raises(OutcomeJournalError, match="^authentication signature invalid$"):
        verifier.verify(fixture.wire)
    assert (verifier.tip(), verifier.live_state) == before
    assert verifier.raw == b"" and verifier.seq == 0 and verifier.head == ZERO_HASH
    assert fixture.fixture_kind == "SYNTHETIC_INVALID_SIGNATURE_PREPARE"
    assert fixture.expected_refusal == negative.EXPECTED_REFUSAL
    with pytest.raises(FrozenInstanceError):
        fixture.wire = b"replaced"
    wire = json.loads(fixture.wire)
    assert fixture.wire == _json(wire) + b"\n" and fixture.wire.count(b"\n") == 1
    assert set(wire) == {
        "schema_version",
        "scope_ref",
        "producer_ref",
        "stream_ref",
        "boot_ref",
        "seq",
        "prev",
        "event",
        "signature",
    }
    assert all(
        wire[k] == public.data[k] for k in ("scope_ref", "producer_ref", "stream_ref")
    )
    assert (
        wire["seq"] == 1
        and wire["prev"] == ZERO_HASH
        and wire["boot_ref"] == boot.replace("-", "")
    )
    origin = wire["event"]["capture_origin"]
    assert origin == dict(
        schema_version="outcome-registered-origin/v2",
        registration_sha256="e" * 64,
        mode="live-core",
        session_ref=session,
        seq=0,
        kind="session_prepare",
    )
    assert wire["event"]["capture_lifecycle"] == {"state": "prepare"}
    assert len(bytes.fromhex(wire["signature"])) == 64


@pytest.mark.parametrize(
    "boot", [None, True, 1, BOOT.upper(), BOOT.replace("-", ""), "not-uuid"]
)
def test_invalid_raw_boot_refuses_before_frame(tmp_path, boot):
    with pytest.raises((OutcomeJournalError, ValueError)):
        negative.synthetic_prepare_frame(
            policy(tmp_path), kernel_boot_id=boot, session_ref="1" * 32
        )


@pytest.mark.parametrize("session", [None, True, 1, "1" * 31, "A" * 32, "g" * 32])
def test_invalid_native_session_refuses_before_frame(tmp_path, session):
    with pytest.raises(OutcomeJournalError):
        negative.synthetic_prepare_frame(
            policy(tmp_path), kernel_boot_id=BOOT, session_ref=session
        )


def test_only_closed_current_public_trust_context_accepted(tmp_path):
    public = policy(tmp_path)
    with pytest.raises(OutcomeJournalError):
        negative.synthetic_prepare_frame(
            dict(public.data), kernel_boot_id=BOOT, session_ref="1" * 32
        )
    changed = TrustPolicy(dict(public.data, observer_uid=61003))
    with pytest.raises(OutcomeJournalError):
        negative.synthetic_prepare_frame(
            changed, kernel_boot_id=BOOT, session_ref="1" * 32
        )
    legacy = dict(public.data, schema_version="outcome-input-trust/v1")
    legacy.pop("origin_registration_sha256")
    with pytest.raises(OutcomeJournalError):
        negative.synthetic_prepare_frame(
            TrustPolicy(legacy), kernel_boot_id=BOOT, session_ref="1" * 32
        )


def test_builder_is_deterministic_and_reads_no_key_or_config_paths(
    tmp_path, monkeypatch
):
    public = policy(tmp_path)

    def no_io(*a, **k):
        pytest.fail("pure builder must not perform IO or sign")

    import builtins
    import azazel_edge.outcome.input_auth as auth

    monkeypatch.setattr(builtins, "open", no_io)
    monkeypatch.setattr(Path, "open", no_io)
    monkeypatch.setattr(auth, "private_key", no_io)
    monkeypatch.setattr(auth, "sign", no_io)
    one = negative.synthetic_prepare_frame(
        public, kernel_boot_id=BOOT, session_ref="1" * 32
    )
    two = negative.synthetic_prepare_frame(
        public, kernel_boot_id=BOOT, session_ref="1" * 32
    )
    assert one == two
