"""SYNTHETIC API receipts/identities; no real observer, signal or workload trial."""

import hashlib
import json
import os
from pathlib import Path
import signal
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_normal_stop as n
from azazel_edge.outcome.input_control_stop import ObserverControlStop
from azazel_edge.outcome.telemetry import POLICY_SCHEMA_VERSION

BOOT = "00000000-0000-4000-8000-000000000001"


def prepared(tmp_path, monkeypatch):
    from auth_input_helpers import make_policy

    trust, *_ = make_policy(tmp_path)
    policy_path = tmp_path / "telemetry-policy.json"
    policy_path.write_text(
        json.dumps(
            dict(
                schema_version=POLICY_SCHEMA_VERSION,
                policy_version="synthetic-disabled",
                actions={},
            )
        )
    )
    identity = dict(
        pid=123,
        start_ticks=456,
        boot_id=BOOT,
        native_tid=123,
        clock_domain={"established": False},
    )
    monkeypatch.setattr(n, "_identity", lambda: dict(identity))
    monkeypatch.setattr(
        n.input_auth.TrustPolicy, "from_file", lambda *args, **kwargs: trust
    )
    handlers = []
    monkeypatch.setattr(n.signal, "getsignal", lambda signum: "prior-handler")
    monkeypatch.setattr(
        n.signal, "signal", lambda signum, handler: handlers.append(handler)
    )
    options = {
        "--policy": str(policy_path),
        "--interface": "lo",
        "--sample-interval-seconds": "0.05",
        "--journal-boot-id": BOOT,
    }
    config = dict(
        metadata=dict(
            run_id="synthetic",
            arm="original_on",
            input_sha256="a" * 64,
            code_sha256="b" * 64,
            core_sha256="c" * 64,
            interpreter_sha256="d" * 64,
        ),
        policy_path=str(tmp_path / "trust"),
        normal_stop=dict(
            profile="stop_only", receipt_path=str(tmp_path / "completion.json")
        ),
    )
    captured = n.CapturedControl(config, options)
    receipt = ObserverControlStop(
        scope_ref=trust.data["scope_ref"],
        trust_sha256=trust.digest,
        journal_policy_sha256=hashlib.sha256(
            captured.journal_policy.encode()
        ).hexdigest(),
        journal_boot_id=BOOT,
        input_offset=100,
        input_sha256="1" * 64,
        journal_sequence_before=4,
        journal_sequence_after=7,
        journal_head_after="2" * 64,
        journal_bytes_after=1000,
        pending_windows_before=2,
        pending_windows_lost=2,
        committed_outcomes=0,
        lost_before=0,
        lost_after=2,
    )
    return config, options, receipt, handlers, identity


def test_flag_handler_only_sets_idempotent_boolean_without_io_or_clock(monkeypatch):
    flag = n.StopFlag()
    monkeypatch.setattr(
        n, "_clock_anchor", lambda: pytest.fail("signal handler sampled a clock")
    )
    assert flag.is_set() is False
    flag.handler(signal.SIGTERM, None)
    flag.handler(signal.SIGTERM, None)
    assert flag.is_set() is True


def test_scoped_forwarder_calls_real_api_once_and_preserves_actual_result(
    tmp_path, monkeypatch
):
    config, options, receipt, handlers, _ = prepared(tmp_path, monkeypatch)
    calls = []

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        handlers[-1](signal.SIGTERM, None)
        assert kwargs["stop_requested"]() is True
        return receipt

    monkeypatch.setattr(n.telemetry, "run_live", original)
    with n.capture_control(config, options) as captured:
        result = n.telemetry.run_live(input_path="actual-original-argument")
        assert result is receipt
        assert captured.require_result() == receipt.to_dict()
    assert n.telemetry.run_live is original
    assert handlers[-1] == "prior-handler"
    assert len(calls) == 1 and calls[0][1]["input_path"] == "actual-original-argument"
    assert captured.restored is True


def test_real_api_exception_propagates_identically_and_restores_handler(
    tmp_path, monkeypatch
):
    config, options, _, handlers, _ = prepared(tmp_path, monkeypatch)
    error = OSError("SYNTHETIC original closure failure")

    def fail(**kwargs):
        raise error

    monkeypatch.setattr(n.telemetry, "run_live", fail)
    with pytest.raises(OSError) as caught:
        with n.capture_control(config, options):
            n.telemetry.run_live()
    assert caught.value is error
    assert n.telemetry.run_live is fail
    assert handlers[-1] == "prior-handler"
    assert not Path(config["normal_stop"]["receipt_path"]).exists()


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "dict",
        "wrong_boot",
        "wrong_trust",
        "wrong_policy",
        "no_request",
        "twice",
    ],
)
def test_no_false_receipt_from_exit_zero_wrong_scope_or_repeated_forward(
    tmp_path, monkeypatch, fault
):
    from dataclasses import replace

    config, options, receipt, _, _ = prepared(tmp_path, monkeypatch)
    captured = n.CapturedControl(config, options)
    captured.flag.handler(None, None)
    if fault == "none":
        result = None
    elif fault == "dict":
        result = receipt.to_dict()
    elif fault == "wrong_boot":
        result = replace(receipt, journal_boot_id="other-boot")
    elif fault == "wrong_trust":
        result = replace(receipt, trust_sha256="f" * 64)
    elif fault == "wrong_policy":
        result = replace(receipt, journal_policy_sha256="f" * 64)
    else:
        result = receipt
    assert captured.run_live(lambda **kwargs: result) is result
    if fault == "twice":
        with pytest.raises(ValueError, match="exactly once"):
            captured.run_live(lambda **kwargs: result)
    else:
        if fault == "no_request":
            captured.flag.requested = False
        with pytest.raises(ValueError):
            captured.require_result()


def test_completion_after_restored_handler_retains_real_body_and_null_stop_only_sidecars(
    tmp_path, monkeypatch
):
    config, options, receipt, _, identity = prepared(tmp_path, monkeypatch)
    captured = n.CapturedControl(config, options)
    captured.flag.handler(None, None)
    captured.run_live(lambda **kwargs: receipt)
    captured.restored = True
    result = n.publish_completion(captured)
    raw = Path(config["normal_stop"]["receipt_path"]).read_bytes()
    assert json.loads(raw) == result
    assert result["control_stop"] == receipt.to_dict()
    assert result["identity"] == identity
    assert result["sidecars"] == dict(phase=None, calls=None, context=None)
    assert (
        result["api_return_anchor"]["monotonic_after_ns"]
        <= result["completion_anchor"]["monotonic_before_ns"]
    )
    assert captured.published is True
    with pytest.raises(ValueError):
        n.publish_completion(captured)
    assert Path(config["normal_stop"]["receipt_path"]).read_bytes() == raw


@pytest.mark.parametrize(
    "fault", ["handler_unrestored", "pid", "start", "boot", "phase_close"]
)
def test_completion_requires_actual_handler_incarnation_and_sidecar_close(
    tmp_path, monkeypatch, fault
):
    config, options, receipt, _, identity = prepared(tmp_path, monkeypatch)
    captured = n.CapturedControl(config, options)
    captured.flag.handler(None, None)
    captured.run_live(lambda **kwargs: receipt)
    captured.restored = fault != "handler_unrestored"
    if fault in ("pid", "start", "boot"):
        identity[{"pid": "pid", "start": "start_ticks", "boot": "boot_id"}[fault]] = (
            "changed"
        )
    if fault == "phase_close":
        config["normal_stop"]["profile"] = "phase_and_clock"
    with pytest.raises(ValueError):
        n.publish_completion(
            captured,
            phase_recorder=SimpleNamespace(closed=True, fd=None, incomplete=True),
        )
    assert not Path(config["normal_stop"]["receipt_path"]).exists()


@pytest.mark.parametrize("fault", ["write", "fsync", "close"])
def test_completion_file_failure_cannot_publish_success_even_if_bytes_remain(
    tmp_path, monkeypatch, fault
):
    from signed_network_phase_recording import ModuleProxy

    config, options, receipt, _, _ = prepared(tmp_path, monkeypatch)
    captured = n.CapturedControl(config, options)
    captured.flag.handler(None, None)
    captured.run_live(lambda **kwargs: receipt)
    captured.restored = True
    error = OSError("SYNTHETIC receipt file failure")

    def fail(*args, **kwargs):
        if fault == "close":
            os.close(args[0])
        raise error

    monkeypatch.setattr(n, "os", ModuleProxy(os, **{fault: fail}))
    with pytest.raises(OSError) as caught:
        n.publish_completion(captured)
    assert caught.value is error
    assert captured.published is False


def test_handler_restore_failure_does_not_claim_successful_restore_or_publish(
    tmp_path, monkeypatch
):
    config, options, receipt, _, _ = prepared(tmp_path, monkeypatch)
    calls = []

    def install(signum, handler):
        calls.append(handler)
        if handler == "prior-handler":
            raise OSError("SYNTHETIC handler restore failure")

    monkeypatch.setattr(n.signal, "signal", install)
    monkeypatch.setattr(n.telemetry, "run_live", lambda **kwargs: receipt)
    with pytest.raises(OSError):
        with n.capture_control(config, options) as captured:
            captured.flag.handler(None, None)
            assert n.telemetry.run_live() is receipt
    assert captured.restored is False
    with pytest.raises(ValueError):
        n.publish_completion(captured)
    assert not Path(config["normal_stop"]["receipt_path"]).exists()
