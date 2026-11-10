"""Confinement registration and early gates; kernel proof lives in the VM job."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from auth_input_helpers import make_policy
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_live import validate_registration
from azazel_edge.outcome.confinement import profile_name, capture_image, enforce_capture


def registration(tmp_path):
    p, *_ = make_policy(tmp_path, producer=61001, observer=61002, witness=0)
    p = TrustPolicy(
        {
            **dict(p.data),
            "schema_version": "outcome-input-trust/v3",
            "origin_registration_sha256": "f" * 64,
        }
    )
    r = dict(
        schema_version="outcome-live-origin-registration/v3",
        mode="live-core",
        **{
            k: p.data[k]
            for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
        },
        binary_path="/protected/core",
        binary_sha256="a" * 64,
        launcher_uid=0,
        ai_socket_uid=0,
        capture_apparmor_profile="edge400-capture",
        environment={
            "AZAZEL_" + k: str(v)
            for k, v in dict(
                EVE_PATH="/protected/eve",
                NORMALIZED_EVENT_LOG="/protected/log",
                FORWARD_AI="0",
                FORWARD_LOG="0",
                EVENT_STDOUT="off",
                DEFENSE_ENFORCE="0",
                DEFENSE_DRY_RUN="1",
                DEFENSE_RELEASE_LEDGER="/protected/ledger",
                REDIRECT_POLICY_PATH="/protected/redirection",
                PROTECTED_FLOWS_PATH="/protected/protected",
                EVE_FROM_START="0",
            ).items()
        },
    )
    return p, r


def test_confined_registration_is_exact_and_explicit(tmp_path):
    p, r = registration(tmp_path)
    with patch("os.geteuid", return_value=61001):
        assert validate_registration(p, r) == r


@pytest.mark.parametrize(
    "fault",
    ["missing", "legacy", "unknown", "empty", "space", "slash", "newline", "bool"],
)
def test_confined_registration_rejects_omission_downgrade_and_injection(
    tmp_path, fault
):
    p, r = registration(tmp_path)
    if fault == "missing":
        del r["capture_apparmor_profile"]
    elif fault == "legacy":
        r["schema_version"] = "outcome-live-origin-registration/v2"
    elif fault == "unknown":
        r["extra"] = True
    else:
        r["capture_apparmor_profile"] = {
            "empty": "",
            "space": "name other",
            "slash": "/profile",
            "newline": "name\n",
            "bool": False,
        }[fault]
    with patch("os.geteuid", return_value=61001), pytest.raises(OSError):
        validate_registration(p, r)


@pytest.mark.parametrize(
    "value", ["", "unconfined", "-name", "a b", "a/b", "a\nb", "a" * 129, None, True, 1]
)
def test_profile_name_cannot_inject_argv_or_policy(value):
    with pytest.raises(OSError):
        profile_name(value)


@pytest.mark.parametrize(
    "label",
    [
        "unconfined",
        "edge400-capture (complain)",
        "other (enforce)",
        "edge400-capture (unconfined)",
        "edge400-capture//hat (enforce)",
    ],
)
def test_enforcement_requires_the_exact_kernel_label(label):
    with patch.object(Path, "read_text", return_value=label), pytest.raises(OSError):
        enforce_capture("edge400-capture")


def test_exact_enforcing_label_is_accepted():
    with patch.object(Path, "read_text", return_value="edge400-capture (enforce)\n"):
        enforce_capture("edge400-capture")


def test_capture_alias_is_fixed_and_cannot_substitute_another_interpreter(tmp_path):
    python = tmp_path / "python"
    python.write_bytes(b"interpreter")
    with (
        patch.object(Path, "read_text", return_value="Y"),
        patch(
            "azazel_edge.outcome.confinement.read_regular",
            side_effect=[(b"interpreter", None), (b"other", None)],
        ),
        pytest.raises(OSError),
    ):
        capture_image(python, "edge400-capture")
    with (
        patch.object(Path, "read_text", return_value="Y"),
        patch(
            "azazel_edge.outcome.confinement.read_regular",
            return_value=(b"interpreter", None),
        ) as read,
    ):
        alias, metadata = capture_image(python, "edge400-capture")
        assert (
            alias == python.with_name("edge-capture")
            and metadata["profile"] == "edge400-capture"
        )
        assert (
            read.call_args.kwargs["owner"] == 0
            and read.call_args.kwargs["mode"] == 0o755
        )


@pytest.mark.parametrize("enabled", ["N", "", "unknown"])
def test_missing_kernel_support_has_no_fallback(tmp_path, enabled):
    with patch.object(Path, "read_text", return_value=enabled), pytest.raises(OSError):
        capture_image(tmp_path / "python", "edge400-capture")


def test_receiver_refuses_context_before_channel_or_key_use():
    from azazel_edge.outcome import input_live

    policy = SimpleNamespace(data={"producer_uid": 61001})
    with (
        patch.object(input_live.sys, "platform", "linux"),
        patch("os.geteuid", return_value=61001),
        patch.object(input_live, "harden_receiver"),
        patch.object(Path, "read_text", return_value="unconfined"),
        patch.object(input_live, "SignedCaptureWriter") as writer,
        pytest.raises(OSError),
    ):
        input_live.receive(
            policy,
            {"capture_apparmor_profile": "edge400-capture"},
            Path("/not-read"),
            "boot",
            -1,
            "session",
        )
    writer.assert_not_called()


def test_witness_refuses_context_before_opening_key_or_store():
    from azazel_edge.outcome import input_witness

    with (
        patch.object(Path, "read_text", return_value="unconfined"),
        patch.object(input_witness, "serve") as serve,
        pytest.raises(OSError),
    ):
        input_witness.main(
            [
                "--policy",
                "/not-read",
                "--private-key",
                "/not-read",
                "--apparmor-profile",
                "edge400-witness",
            ]
        )
    serve.assert_not_called()


@pytest.mark.parametrize(
    "value", ['[false,"core-profile"]', '[true,"core-profile"]', '[true,""]']
)
def test_native_memfd_confinement_is_not_admitted_by_guessing(value):
    from azazel_edge.outcome.service_switch import _security

    with pytest.raises(OSError):
        _security({"AppArmorProfile": value})


def test_native_registration_requires_both_exact_enrolled_profiles(tmp_path):
    from azazel_edge.outcome.input_live import native_arguments

    p, r = registration(tmp_path)
    r.update(
        schema_version="outcome-live-origin-registration/v4",
        native_apparmor_profile="edge400-native",
    )
    with patch("os.geteuid", return_value=61001):
        assert validate_registration(p, r) == r
        assert native_arguments(r) == ["--native-apparmor-profile", "edge400-native"]
        for fault in [
            {"schema_version": "outcome-live-origin-registration/v3"},
            {"native_apparmor_profile": "unconfined"},
            {"native_apparmor_profile": "edge400-capture"},
            {"native_apparmor_profile": "bad --health"},
            {"native_apparmor_profile": "name//hat"},
        ]:
            with pytest.raises(OSError):
                validate_registration(p, {**r, **fault})
        for key in [
            "capture_apparmor_profile",
            "native_apparmor_profile",
            "ai_socket_uid",
        ]:
            bad = dict(r)
            del bad[key]
            with pytest.raises(OSError):
                validate_registration(p, bad)
