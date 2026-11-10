"""Provider reports preserve status; provenance never upgrades mechanism/effect."""

import copy
import json

import pytest

pytest.importorskip("cryptography")
from auth_input_helpers import make_policy
from test_outcome_input_auth import signed
from test_outcome_telemetry_g3 import rust_event
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier
from azazel_edge.outcome.live_protocol import LiveState, native_frame
from azazel_edge.outcome.adapter import from_rust_event


def frame(kind, seq, session="a" * 32, event=None):
    if event is None:
        if kind in ("session_prepare", "session_start", "session_end"):
            event = dict(
                pipeline="rust_live_origin_v1",
                source="capture_producer" if kind == "session_prepare" else "rust_core",
                capture_lifecycle=dict(
                    state={
                        "session_prepare": "prepare",
                        "session_start": "start",
                        "session_end": "end",
                    }[kind]
                ),
            )
        else:
            event = rust_event(ts="2026-11-10T00:00:00Z", trace="test")
            event["source"] = "suricata_eve"
            event["enforcement_status"] = dict(
                enforce_enabled=True, dry_run=False, high_impact_auto=False
            )
    return dict(
        schema_version="outcome-live-origin/v1",
        session_ref=session,
        seq=seq,
        kind=kind,
        event=event,
    )


def enrolled(tmp_path):
    p, key, *_ = make_policy(tmp_path)
    return (
        TrustPolicy(
            {
                **dict(p.data),
                "schema_version": "outcome-input-trust/v3",
                "origin_registration_sha256": "f" * 64,
            }
        ),
        key,
    )


def signed_frame(p, key, wire, seq, prev):
    event = copy.deepcopy(wire["event"])
    event["capture_origin"] = dict(
        schema_version="outcome-registered-origin/v2",
        registration_sha256=p.data["origin_registration_sha256"],
        mode="live-core",
        **{k: wire[k] for k in ("session_ref", "seq", "kind")}
    )
    return signed(p, key, seq=seq, prev=prev, event=event)


def test_signed_live_facts_and_clean_sessions_preserve_actual_report(tmp_path):
    p, key = enrolled(tmp_path)
    v = SourceVerifier(p)
    data = b""
    for n, wire in enumerate(
        [
            frame("session_prepare", 0),
            frame("session_start", 1),
            frame("decision_execution", 2),
            frame("session_end", 3),
            frame("session_prepare", 0, "b" * 32),
            frame("session_start", 1, "b" * 32),
            frame("session_end", 2, "b" * 32),
        ],
        1,
    ):
        data += signed_frame(p, key, wire, n, v.head)
        v.verify(data)
    assert v.live_state.closed and len(v.live_state.sessions) == 2
    event = json.loads(data.splitlines()[2])["event"]
    assert {k: x for k, x in event.items() if k != "capture_origin"} == frame(
        "decision_execution", 2
    )["event"]
    bundle = from_rust_event(event)
    # Synthetic provider report proves neither independent mechanism nor effect.
    assert bundle.execution.status.value == "applied"
    assert bundle.mechanism.status.value == "unverified"


@pytest.mark.parametrize(
    "fault",
    [
        "before_start",
        "gap",
        "replay",
        "wrong_session",
        "nested_start",
        "after_end",
        "old_session",
        "unknown",
        "readonly",
        "bad_count",
        "bad_posture",
        "extra",
        "bool_seq",
        "bad_metadata",
        "provenance",
    ],
)
def test_native_live_continuity_and_fact_type_fail_closed(fault):
    state = native_frame(frame("session_start", 1), LiveState())
    wire = frame("decision_execution", 2)
    if fault == "before_start":
        state = LiveState()
    elif fault == "gap":
        wire["seq"] = 3
    elif fault == "replay":
        wire["seq"] = 1
    elif fault == "wrong_session":
        wire["session_ref"] = "b" * 32
    elif fault == "nested_start":
        wire = frame("session_start", 1, "b" * 32)
    elif fault in ("after_end", "old_session"):
        state = native_frame(frame("session_end", 2), state)
        if fault == "old_session":
            wire = frame("session_start", 1)
    elif fault == "unknown":
        wire["kind"] = "receipt_reconstruction"
    elif fault == "readonly":
        wire["event"]["enforcement"]["metadata"]["capture_only"] = True
    elif fault == "bad_count":
        wire["event"]["enforcement"]["executed_count"] = True
    elif fault == "bad_posture":
        wire["event"]["enforcement_status"]["dry_run"] = 0
    elif fault == "extra":
        wire["path"] = "/arbitrary"
    elif fault == "bool_seq":
        wire["seq"] = True
    elif fault == "bad_metadata":
        wire["event"]["enforcement"]["metadata"] = []
    elif fault == "provenance":
        wire["event"]["capture_origin"] = {}
    with pytest.raises(OSError):
        native_frame(wire, state)


@pytest.mark.parametrize(
    "fault", ["registration", "mode", "kind", "seq", "marker", "session"]
)
def test_valid_signature_cannot_change_registered_live_origin(tmp_path, fault):
    p, key = enrolled(tmp_path)
    v = SourceVerifier(p)
    first = signed_frame(p, key, frame("session_prepare", 0), 1, v.head)
    v.verify(first)
    first += signed_frame(p, key, frame("session_start", 1), 2, v.head)
    v.verify(first)
    wire = frame("decision_execution", 2)
    raw = signed_frame(p, key, wire, 3, v.head)
    event = json.loads(raw)["event"]
    m = event["capture_origin"]
    if fault == "registration":
        m["registration_sha256"] = "0" * 64
    elif fault == "mode":
        m["mode"] = "readonly-core"
    elif fault == "kind":
        m["kind"] = "session_start"
    elif fault == "seq":
        m["seq"] = 3
    elif fault == "marker":
        event.pop("capture_origin")
    elif fault == "session":
        m["session_ref"] = "b" * 32
    with pytest.raises(OSError):
        v.verify(first + signed(p, key, seq=3, prev=v.head, event=event))
    assert v.seq == 2 and v.live_state.seq == 1


@pytest.mark.parametrize(
    "mode,result,executed,failed",
    [
        ("dry_run", "dry_run", 0, 0),
        ("policy_gated", "blocked", 0, 0),
        ("enforced", "failed", 0, 1),
        ("enforced", "partial_failure", 1, 1),
        ("enforced", "applied", 2, 0),
    ],
)
def test_live_record_is_not_synonym_for_applied(mode, result, executed, failed):
    wire = frame("decision_execution", 2)
    wire["event"]["enforcement"].update(
        mode=mode, result=result, executed_count=executed, failed_count=failed
    )
    original = copy.deepcopy(wire)
    native_frame(wire, native_frame(frame("session_start", 1), LiveState()))
    assert wire == original


def test_release_report_stays_a_distinct_provider_record(tmp_path):
    from test_outcome_release_g1b import release_event

    p, key = enrolled(tmp_path)
    v = SourceVerifier(p)
    data = b""
    release = release_event("throttle")
    release["enforcement_status"] = dict(
        enforce_enabled=True, dry_run=False, high_impact_auto=False
    )
    wires = [
        frame("session_prepare", 0),
        frame("session_start", 1),
        frame("release", 2, event=release),
        frame("session_end", 3),
    ]
    for n, wire in enumerate(wires, 1):
        data += signed_frame(p, key, wire, n, v.head)
        v.verify(data)
    kept = json.loads(data.splitlines()[2])["event"]
    assert kept["capture_origin"]["kind"] == "release"
    assert {k: x for k, x in kept.items() if k != "capture_origin"} == release
    assert "normalized" not in kept and v.live_state.closed
