"""Synthetic runtime/mocked receipt channels; no actual native commissioning."""

import base64
from copy import deepcopy
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_edge.outcome import input_live, native_close_receipts as receipts
from azazel_edge.outcome import service_entry, service_switch
from azazel_edge.outcome.journal import OutcomeJournalError, _json


def registration():
    return dict(
        schema_version="outcome-live-origin-registration/v4",
        environment={
            "AZAZEL_LIVE_ORIGIN_ACCOUNTING": "v1",
            "AZAZEL_EVENT_STDOUT": "off",
            "AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS": "v1",
        },
    )


@pytest.mark.parametrize(
    "fault", ["empty", "unknown", "accounting", "stdout", "legacy_registration"]
)
def test_registered_combination_is_strict(fault):
    r = registration()
    if fault == "empty":
        r["environment"]["AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS"] = ""
    elif fault == "unknown":
        r["environment"]["AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS"] = "v2"
    elif fault == "accounting":
        r["environment"].pop("AZAZEL_LIVE_ORIGIN_ACCOUNTING")
    elif fault == "stdout":
        r["environment"]["AZAZEL_EVENT_STDOUT"] = "full"
    else:
        r["schema_version"] = "outcome-live-origin-registration/v3"
    with pytest.raises(OutcomeJournalError):
        receipts.enabled(r)


def test_default_has_no_receipt_profile():
    assert receipts.enabled(registration()) is True
    assert receipts.enabled({"environment": {}}) is False


@pytest.mark.parametrize("mode", ["valid", "short", "full", "oversize"])
def test_receiver_publication_is_one_nonblocking_attempt_not_an_exit_gate(
    monkeypatch, mode
):
    calls = []
    monkeypatch.setattr(os, "set_blocking", lambda fd, value: calls.append((fd, value)))

    def write(fd, raw):
        calls.append((fd, raw))
        if mode == "full":
            raise BlockingIOError()
        return len(raw) - (mode == "short")

    monkeypatch.setattr(os, "write", write)
    value = {"diagnostic": "x" * 4000} if mode == "oversize" else {"diagnostic": True}
    assert receipts.emit_pipe(value) is (mode == "valid")
    if mode == "oversize":
        assert calls == []
    else:
        assert calls[0] == (1, False)
        assert len(calls) == 2 and calls[1][1] == _json(value) + b"\n"


@pytest.mark.parametrize("fault", ["normal", "partial", "oversize", "leaked"])
def test_pipe_custody_retains_actual_raw_bytes_and_eof(fault):
    read, write = os.pipe()
    pipe = os.fdopen(read, "rb", buffering=0)
    raw = b'{"ready":true}\n'
    os.write(write, raw)
    assert receipts.first_line(pipe, timeout=0.05) == raw
    tail = b"{}\n" if fault != "partial" else b"{"
    if fault == "oversize":
        tail = b"x" * 65
    os.write(write, tail)
    if fault != "leaked":
        os.close(write)
    result = receipts.stream(pipe, initial=raw, limit=64, exited=True, timeout=0.01)
    assert base64.b64decode(result["raw_b64"]) == (raw + tail)[:64]
    assert result["eof"] is (fault in ("normal", "partial"))
    assert result["over_limit"] is (fault == "oversize")
    if fault == "leaked":
        os.close(write)
    pipe.close()


def test_first_line_timeout_and_no_child_do_not_fabricate_eof():
    read, write = os.pipe()
    with os.fdopen(read, "rb", buffering=0) as pipe:
        assert receipts.first_line(pipe, timeout=0.001) == b""
        assert receipts.stream(pipe, initial=b"", limit=64, exited=False) == dict(
            raw_b64="", eof=False, over_limit=False
        )
    os.close(write)


def refusal_context():
    policy = SimpleNamespace(
        data={"origin_registration_sha256": "a" * 64}, digest="b" * 64
    )
    tip = dict(seq=3, head="c" * 64, size=100, sha256="d" * 64)
    verifier = SimpleNamespace(
        tip=lambda: deepcopy(tip), live_state=SimpleNamespace(session="e" * 32)
    )
    return service_switch.UnclosedSignedHistory(policy, registration(), verifier), tip


def test_typed_managed_gate_preserves_error_and_public_verified_context():
    error, tip = refusal_context()
    assert isinstance(error, OutcomeJournalError)
    assert str(error) == "unclosed signed history; no connected restart"
    assert error.source_checkpoint == tip


@pytest.mark.parametrize("profile,root", [(True, True), (False, True), (True, False)])
def test_managed_refusal_uses_same_typed_branch_no_reread_or_spawn(
    monkeypatch, profile, root
):
    error, tip = refusal_context()
    if not profile:
        error.registration["environment"].pop("AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS")

    def refuse(*args):
        raise error

    monkeypatch.setattr(service_entry, "ready", refuse)
    monkeypatch.setattr(
        service_entry,
        "launch",
        lambda *args: pytest.fail("native/receiver spawn attempted"),
    )
    monkeypatch.setattr(os, "geteuid", lambda: 0 if root else 123)
    monkeypatch.setenv("INVOCATION_ID", "f" * 32)
    output = io.StringIO()
    monkeypatch.setattr(receipts.sys, "stdout", output)
    with pytest.raises(service_switch.UnclosedSignedHistory) as caught:
        service_entry.run(Path("/synthetic"), "boot-ref")
    assert caught.value is error
    if not (profile and root):
        assert output.getvalue() == ""
        return
    report = json.loads(output.getvalue())
    assert report["schema_version"] == "outcome-managed-restart-refusal/v1"
    assert report["stage"] == "managed_ready_unclosed_history"
    assert report["source_checkpoint"] == tip
    assert report["attempted_session_ref"] is None
    assert report["core_spawn_attempted"] is report["receiver_spawn_attempted"] is False
    assert report["invocation_id"] == "f" * 32
    assert report["prior_session_ref"] == "e" * 32
    assert output.getvalue().encode() == _json(report) + b"\n"


def test_generic_managed_failure_is_never_reclassified(monkeypatch):
    def refuse(*args):
        raise OutcomeJournalError("unclosed signed history; no connected restart")

    monkeypatch.setattr(service_entry, "ready", refuse)
    output = io.StringIO()
    monkeypatch.setattr(receipts.sys, "stdout", output)
    with pytest.raises(OutcomeJournalError):
        service_entry.run(Path("/synthetic"), "boot")
    assert output.getvalue() == ""


@pytest.mark.parametrize(
    "fault",
    [
        "normal",
        "normal_cost",
        "writer_close",
        "terminal_fsync",
        "extra_tail",
        "partial_tail",
        "unclean",
    ],
)
def test_receiver_report_follows_verified_eof_append_and_successful_writer_close(
    monkeypatch, capsys, fault
):
    import socket
    import struct
    from azazel_edge.outcome.live_protocol import LiveState, signed_live_event

    r = registration()
    if fault == "normal_cost":
        r["environment"].update(
            AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING="v1",
            AZAZEL_LIVE_ORIGIN_LOAD_COST="v1",
        )
    r["launcher_uid"] = 0
    policy = SimpleNamespace(
        data={"producer_uid": 61001, "origin_registration_sha256": "a" * 64},
        digest="b" * 64,
    )
    lifecycle = dict(
        schema_version="outcome-live-origin-lifecycle/v2", accounting_profile="v1"
    )
    start = dict(
        schema_version="outcome-live-origin/v1",
        session_ref="c" * 32,
        seq=1,
        kind="session_start",
        event=dict(
            pipeline="rust_live_origin_v1",
            source="rust_core",
            capture_lifecycle={**lifecycle, "state": "start"},
        ),
    )
    end = deepcopy(start)
    end.update(seq=2, kind="session_end")
    end["event"]["capture_lifecycle"] = {
        **lifecycle,
        "state": "end",
        "counts": dict(
            produced=0, admitted=0, enqueued=0, written=0, dropped=0, inflight=0
        ),
    }
    raw = _json(start) + b"\n" + _json(end) + b"\n"
    if fault == "extra_tail":
        raw += _json(start) + b"\n"
    if fault == "partial_tail":
        raw += b"{"

    class Channel:
        family = socket.AF_UNIX
        type = socket.SOCK_STREAM

        def __init__(self, *args, **kwargs):
            self.parts = iter((raw, b""))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def fileno(self):
            return 91

        def getsockopt(self, *args):
            return struct.pack("3i", 42, 0, 0)

        def recv(self, *args):
            return next(self.parts)

    state = dict(closed=False, appends=[], reports=[])

    class Writer:
        def __init__(self, *args, **kwargs):
            initial = (
                LiveState(session="d" * 32, seq=1, closed=False)
                if fault == "unclean"
                else LiveState()
            )
            self.verifier = SimpleNamespace(
                live_state=initial,
                tip=lambda: dict(
                    seq=len(state["appends"]), head="e" * 64, size=1, sha256="f" * 64
                ),
            )

        def __enter__(self):
            return self

        def __exit__(self, *args):
            if fault == "writer_close":
                raise OSError("close failed")
            state["closed"] = True

        def append(self, event):
            if (
                fault == "terminal_fsync"
                and event["capture_origin"]["kind"] == "session_end"
            ):
                raise OSError("fsync failed")
            self.verifier.live_state = signed_live_event(
                event, "a" * 64, self.verifier.live_state
            )
            state["appends"].append(event)
            return self.verifier.tip()

    def report(value):
        if value["schema_version"] in (
            "outcome-live-receiver-close-receipt/v1",
            "outcome-live-receiver-close-receipt/v2",
        ):
            assert state["closed"]
        state["reports"].append(deepcopy(value))
        return True

    monkeypatch.setattr(input_live.sys, "platform", "linux")
    monkeypatch.setattr(input_live.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(input_live.socket, "socket", Channel)
    monkeypatch.setattr(input_live, "SignedCaptureWriter", Writer)
    monkeypatch.setattr(input_live, "harden_receiver", lambda *args: None)
    monkeypatch.setattr(os, "geteuid", lambda: 61001)
    monkeypatch.setattr(os, "getppid", lambda: 42)
    monkeypatch.setattr(os, "set_inheritable", lambda *args: None)
    monkeypatch.setattr(receipts, "emit_pipe", report)
    if fault in ("normal", "normal_cost"):
        input_live.receive(policy, r, None, "boot", 91, "c" * 32)
    else:
        with pytest.raises(OSError):
            input_live.receive(policy, r, None, "boot", 91, "c" * 32)
    if fault in ("normal", "normal_cost"):
        assert capsys.readouterr().out == '{"ready":true}\n'
        assert len(state["reports"]) == 1
        report = state["reports"][0]
        assert (
            report["clean_eof_observed"]
            is report["terminal_append_fsync_completed"]
            is report["source_writer_close_completed"]
            is True
        )
        assert report["source_checkpoint"]["seq"] == 3
        if fault == "normal_cost":
            assert report["schema_version"] == "outcome-live-receiver-close-receipt/v2"
            assert report["cost"]["complete"] is True
            assert report["cost"]["phases"]["source_append"]["count"] == 3
            assert report["cost"]["phases"]["receive_wait"]["count"] == 2
        else:
            assert "cost" not in report
    elif fault == "unclean":
        assert capsys.readouterr().out == ""
        assert state["appends"] == []
        assert len(state["reports"]) == 1
        assert state["reports"][0]["reason"] == "unclean_prior_session"
    else:
        assert state["reports"] == []


@pytest.mark.parametrize(
    "fault",
    [
        "valid",
        "missing",
        "extra",
        "wrong_session",
        "bool",
        "negative",
        "overflow",
        "reversed",
        "bad_hash",
        "release",
    ],
)
def test_finite_ingress_origins_are_strict_session_bound_and_never_release_spans(fault):
    from azazel_edge.outcome.live_protocol import validate_ingress_origin

    origin = dict(
        schema_version="azazel-edge/ingress-origin/v1",
        range_ref="a" * 32,
        device=1,
        inode=2,
        start_offset=0,
        end_offset=10,
        raw_sha256="b" * 64,
    )
    event = {"ingress_origin": origin}
    kind = "decision_execution"
    if fault == "missing":
        event = {}
    elif fault == "extra":
        origin["derived_success"] = True
    elif fault == "wrong_session":
        origin["range_ref"] = "c" * 32
    elif fault == "bool":
        origin["device"] = True
    elif fault == "negative":
        origin["start_offset"] = -1
    elif fault == "overflow":
        origin["end_offset"] = 2**63
    elif fault == "reversed":
        origin["end_offset"] = 0
    elif fault == "bad_hash":
        origin["raw_sha256"] = "z" * 64
    elif fault == "release":
        kind = "release"
    if fault == "valid":
        validate_ingress_origin(event, "a" * 32, kind, required=True)
    else:
        with pytest.raises(OutcomeJournalError):
            validate_ingress_origin(event, "a" * 32, kind, required=True)
    # Opt-out without a span remains exactly the previous input format.
    validate_ingress_origin({}, "a" * 32, "decision_execution")


@pytest.mark.parametrize(
    "fault", ["valid", "absent", "empty", "no_close", "legacy_reg"]
)
def test_finite_ingress_profile_is_explicit_and_preserves_receipt_versions(fault):
    r = registration()
    r["environment"]["AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING"] = "v1"
    if fault == "absent":
        r["environment"].pop("AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING")
    elif fault == "empty":
        r["environment"]["AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING"] = ""
    elif fault == "no_close":
        r["environment"].pop("AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS")
    elif fault == "legacy_reg":
        r["schema_version"] = "outcome-live-origin-registration/v3"
    if fault in ("valid", "absent"):
        assert receipts.ingress_enabled(r) is (fault == "valid")
    else:
        with pytest.raises(OutcomeJournalError):
            receipts.ingress_enabled(r)
