"""Synthetic accounting frames and mocked receiver; no actual native capture."""

import copy
import json
import struct
from types import SimpleNamespace

import pytest

from azazel_edge.outcome import input_live
from azazel_edge.outcome.live_protocol import (
    LiveState,
    native_frame,
    signed_live_event,
    validate_lifecycle,
)
from test_outcome_live_origin import enrolled, frame, signed_frame
from azazel_edge.outcome.input_auth import SourceVerifier


def accounted_frame(kind, seq, count=0, session="a" * 32):
    wire = frame(kind, seq, session)
    lifecycle = wire["event"]["capture_lifecycle"]
    lifecycle.update(
        schema_version="outcome-live-origin-lifecycle/v2", accounting_profile="v1"
    )
    if kind == "session_end":
        lifecycle["counts"] = dict(
            produced=count,
            admitted=count,
            enqueued=count,
            written=count,
            dropped=0,
            inflight=0,
        )
    return wire


def test_signed_accounting_sessions_count_activity_and_reset_without_changing_legacy(
    tmp_path,
):
    policy, key = enrolled(tmp_path)
    verifier = SourceVerifier(policy)
    raw = b""
    wires = [
        frame("session_prepare", 0),
        accounted_frame("session_start", 1),
        frame("decision_execution", 2),
        accounted_frame("session_end", 3, 1),
        frame("session_prepare", 0, "b" * 32),
        accounted_frame("session_start", 1, session="b" * 32),
        accounted_frame("session_end", 2, session="b" * 32),
    ]
    original = copy.deepcopy(wires)
    for seq, wire in enumerate(wires, 1):
        raw += signed_frame(policy, key, wire, seq, verifier.head)
        verifier.verify(raw)
    assert wires == original
    assert verifier.live_state.closed and verifier.live_state.accounting_profile == "v1"
    assert verifier.live_state.activity_count == 0
    legacy = native_frame(frame("session_start", 1), LiveState())
    legacy = native_frame(frame("decision_execution", 2), legacy)
    assert legacy.accounting_profile is None and legacy.activity_count == 0
    assert native_frame(frame("session_end", 3), legacy).closed


@pytest.mark.parametrize(
    "counter", ["produced", "admitted", "enqueued", "written", "dropped", "inflight"]
)
@pytest.mark.parametrize("value", [True, False, -1, 2**63, 1.0, "1", None])
def test_counter_types_and_range_are_exact(counter, value):
    event = accounted_frame("session_end", 2)["event"]
    event["capture_lifecycle"]["counts"][counter] = value
    with pytest.raises(OSError):
        validate_lifecycle(event, "session_end")


@pytest.mark.parametrize(
    "fault",
    [
        "missing_counter",
        "extra_counter",
        "unequal",
        "dropped",
        "inflight",
        "wrong_count",
        "missing_profile",
        "unknown_profile",
        "unknown_schema",
        "extra_payload",
        "extra_event",
        "prepare_profile",
    ],
)
def test_accounted_lifecycle_rejects_unmeasured_or_inconsistent_terminal(fault):
    event = accounted_frame("session_end", 2, 1)["event"]
    lifecycle = event["capture_lifecycle"]
    if fault == "missing_counter":
        del lifecycle["counts"]["produced"]
    elif fault == "extra_counter":
        lifecycle["counts"]["late"] = 0
    elif fault == "unequal":
        lifecycle["counts"]["admitted"] = 0
    elif fault in ("dropped", "inflight"):
        lifecycle["counts"][fault] = 1
    elif fault == "missing_profile":
        del lifecycle["accounting_profile"]
    elif fault == "unknown_profile":
        lifecycle["accounting_profile"] = "v2"
    elif fault == "unknown_schema":
        lifecycle["schema_version"] = "outcome-live-origin-lifecycle/v3"
    elif fault == "extra_payload":
        lifecycle["complete"] = True
    elif fault == "extra_event":
        event["complete"] = True
    elif fault == "prepare_profile":
        event = accounted_frame("session_prepare", 0)["event"]
    with pytest.raises(OSError):
        validate_lifecycle(
            event,
            "session_prepare" if fault == "prepare_profile" else "session_end",
            activity_count=0 if fault == "wrong_count" else 1,
        )


@pytest.mark.parametrize("counted_start", [False, True])
def test_profile_cannot_be_added_removed_or_switched_at_end(counted_start):
    start = (
        accounted_frame("session_start", 1)
        if counted_start
        else frame("session_start", 1)
    )
    end = (
        frame("session_end", 2) if counted_start else accounted_frame("session_end", 2)
    )
    with pytest.raises(OSError):
        native_frame(end, native_frame(start, LiveState()))


def test_accounted_activity_overflow_and_signed_prefix_are_not_repaired(tmp_path):
    start = native_frame(accounted_frame("session_start", 1), LiveState())
    exhausted = LiveState(start.sessions, start.session, 1, False, "v1", 2**63 - 1)
    with pytest.raises(OSError):
        native_frame(frame("decision_execution", 2), exhausted)
    policy, key = enrolled(tmp_path)
    verifier = SourceVerifier(policy)
    raw = b""
    for seq, wire in enumerate(
        [
            frame("session_prepare", 0),
            accounted_frame("session_start", 1),
            frame("decision_execution", 2),
        ],
        1,
    ):
        raw += signed_frame(policy, key, wire, seq, verifier.head)
        verifier.verify(raw)
    before = bytes(raw)
    bad = signed_frame(
        policy, key, accounted_frame("session_end", 3, 0), 4, verifier.head
    )
    with pytest.raises(OSError):
        verifier.verify(raw + bad)
    assert raw == before and verifier.seq == 3
    assert not verifier.live_state.closed and verifier.live_state.activity_count == 1


@pytest.mark.parametrize("value", ["", "v2", True, None, 1])
def test_registration_accounting_opt_in_is_strict(value):
    with pytest.raises(OSError):
        input_live.accounting_profile(
            {"environment": {"AZAZEL_LIVE_ORIGIN_ACCOUNTING": value}}
        )


def test_registration_missing_opt_in_is_legacy():
    assert input_live.accounting_profile({"environment": {}}) is None
    assert (
        input_live.accounting_profile(
            {"environment": {"AZAZEL_LIVE_ORIGIN_ACCOUNTING": "v1"}}
        )
        == "v1"
    )


def receiver(monkeypatch, wires, *, registered=True, tail=b""):
    """Drive original receiver with fake OS/channel/writer, never a real Source."""
    appended = []
    policy = SimpleNamespace(
        data={"producer_uid": 1000, "origin_registration_sha256": "f" * 64}
    )
    registration = {
        "launcher_uid": 0,
        "environment": {"AZAZEL_LIVE_ORIGIN_ACCOUNTING": "v1"} if registered else {},
    }

    class Writer:
        def __init__(self, *args, **kwargs):
            self.verifier = SimpleNamespace(live_state=LiveState())

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def append(self, event):
            self.verifier.live_state = signed_live_event(
                event, "f" * 64, self.verifier.live_state
            )
            appended.append(copy.deepcopy(event))

    class Channel:
        family = input_live.socket.AF_UNIX
        type = input_live.socket.SOCK_STREAM

        def __init__(self, **kwargs):
            self.parts = [
                b"".join(json.dumps(w).encode() + b"\n" for w in wires) + tail,
                b"",
            ]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def fileno(self):
            return 9

        def getsockopt(self, *args):
            return struct.pack("3i", input_live.os.getppid(), 0, 0)

        def recv(self, size):
            return self.parts.pop(0)

    monkeypatch.setattr(input_live.sys, "platform", "linux")
    monkeypatch.setattr(input_live.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(input_live.os, "set_inheritable", lambda *args: None)
    monkeypatch.setattr(input_live, "harden_receiver", lambda uid: None)
    monkeypatch.setattr(input_live.socket, "socket", Channel)
    monkeypatch.setattr(input_live.socket, "SO_PEERCRED", 17, raising=False)
    monkeypatch.setattr(input_live, "SignedCaptureWriter", Writer)
    return appended, lambda: input_live.receive(
        policy, registration, None, "mock-boot", 9, "a" * 32
    )


@pytest.mark.parametrize("registered,counted", [(True, False), (False, True)])
def test_receiver_refuses_enrolled_profile_downgrade_before_signing_start(
    monkeypatch, registered, counted
):
    start = (
        accounted_frame("session_start", 1) if counted else frame("session_start", 1)
    )
    appended, run = receiver(monkeypatch, [start], registered=registered)
    with pytest.raises(OSError):
        run()
    assert [e["capture_origin"]["kind"] for e in appended] == ["session_prepare"]


@pytest.mark.parametrize("tail", [b"{}\n", b"{"])
def test_receiver_accounted_terminal_waits_for_clean_eof(monkeypatch, tail):
    appended, run = receiver(
        monkeypatch,
        [accounted_frame("session_start", 1), accounted_frame("session_end", 2)],
        tail=tail,
    )
    with pytest.raises(OSError):
        run()
    assert [e["capture_origin"]["kind"] for e in appended] == [
        "session_prepare",
        "session_start",
    ]


def test_receiver_appends_terminal_only_after_valid_counted_stream_and_eof(monkeypatch):
    appended, run = receiver(
        monkeypatch,
        [
            accounted_frame("session_start", 1),
            frame("decision_execution", 2),
            accounted_frame("session_end", 3, 1),
        ],
    )
    run()
    assert [e["capture_origin"]["kind"] for e in appended] == [
        "session_prepare",
        "session_start",
        "decision_execution",
        "session_end",
    ]
    assert appended[-1]["capture_lifecycle"]["counts"]["written"] == 1


@pytest.mark.parametrize(
    "fault", ["count_mismatch", "missing_terminal", "gap", "replay"]
)
def test_receiver_accounted_failure_preserves_only_authenticated_prefix(
    monkeypatch, fault
):
    wires = [accounted_frame("session_start", 1), frame("decision_execution", 2)]
    if fault == "count_mismatch":
        wires.append(accounted_frame("session_end", 3, 0))
    elif fault == "gap":
        wires.append(accounted_frame("session_end", 4, 1))
    elif fault == "replay":
        wires.append(frame("decision_execution", 2))
    appended, run = receiver(monkeypatch, wires)
    with pytest.raises(OSError):
        run()
    assert [e["capture_origin"]["kind"] for e in appended] == [
        "session_prepare",
        "session_start",
        "decision_execution",
    ]


def test_accounted_release_and_decision_are_separate_preserved_activity_records():
    from test_outcome_release_g1b import release_event

    release = release_event("throttle")
    release["enforcement_status"] = dict(
        enforce_enabled=True, dry_run=False, high_impact_auto=False
    )
    wires = [
        accounted_frame("session_start", 1),
        frame("decision_execution", 2),
        frame("release", 3, event=release),
        accounted_frame("session_end", 4, 2),
    ]
    original = copy.deepcopy(wires)
    state = LiveState()
    for wire in wires:
        state = native_frame(wire, state)
    assert state.closed and state.activity_count == 2 and wires == original


@pytest.mark.parametrize("kind,seq", [("session_start", 1), ("session_end", 2)])
def test_resume_accounted_lifecycle_requires_verified_mode_and_is_not_activity(
    tmp_path, kind, seq
):
    from azazel_edge.outcome.input_resume import decode_input, objective_identity

    policy, key = enrolled(tmp_path)
    raw = signed_frame(policy, key, accounted_frame(kind, seq), 1, "0" * 64)
    decoded = SourceVerifier.unwrap(raw)
    event = decode_input(decoded, allow_live_lifecycle=True)
    assert objective_identity(event, None) == (None, None)
    with pytest.raises(OSError):
        decode_input(decoded)
    event["capture_lifecycle"]["accounting_profile"] = "unknown"
    with pytest.raises(OSError):
        decode_input(json.dumps(event).encode(), allow_live_lifecycle=True)
