"""SituationFrame contract acceptance (#383).

Covers schema/provenance ownership, canonical serialization, serialized-size
and build-latency budgets under worst-case fixtures, optional Knowledge/AZ-06
unavailability, and trace isolation. The frame is advisory-only; none of these
tests touch the deterministic arbiter/enforcement path.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from azazel_edge.mio import contracts
from azazel_edge.mio.contracts import (
    PROVENANCE_GROUPS,
    PROVENANCE_SOURCES,
    SITUATION_FRAME_CAPS,
    SITUATION_FRAME_MAX_SERIALIZED_BYTES,
    SITUATION_FRAME_SCHEMA_OWNER,
    SITUATION_FRAME_SCHEMA_VERSION,
    MioSituationFrame,
)
from azazel_edge.mio.frame_builder import MioSituationFrameBuilder

FIXTURES = Path(__file__).parent / "fixtures" / "mio"
GOLDEN = FIXTURES / "situation_frame_canonical_v1.json"
DOC = Path(__file__).resolve().parents[1] / "docs" / "architecture" / "mio-situation-frame.md"

# Generous CI regression guard for one worst-case build. This is NOT the Pi
# target (see docs): container/laptop timings are not Raspberry Pi evidence.
CI_LATENCY_GUARD_SECONDS = 2.0


def _golden_inputs() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))["input"]


def _build(inputs: dict) -> MioSituationFrame:
    return MioSituationFrameBuilder().build(**inputs)


def _worst_case_inputs(*, text: str = "x", events: int = 20000) -> dict:
    """Synthetic worst case: high traffic, max-length reasons/ids, many refs."""
    long = (text * 600)[:600]
    return {
        "events": [{"event_id": f"ev:{i:06d}:" + long, "ts": "2026-01-01T00:00:00Z", "attrs": {"msg": long}} for i in range(events)],
        "noc_evaluation": {
            "summary": {"status": "critical", "reasons": [f"{long}{i}:detail" for i in range(64)], "degraded_mode": True},
            "evidence_ids": [f"noc:{i}:{long}" for i in range(200)],
        },
        "soc_evaluation": {
            "summary": {"status": "critical", "reasons": [f"{long}{i}:detail" for i in range(64)]},
            "suspicion": {"label": long}, "confidence": {"label": long}, "blast_radius": {"label": long},
            "security_visibility_state": {"status": long},
            "evidence_ids": [f"soc:{i}:{long}" for i in range(200)],
        },
        "current_defensive_state": "ISOLATE",
        "mission": long,
        "trace_id": "trace-" + long,
        "frame_id": "frame-" + long,
        "created_at": "2026-01-01T00:00:01Z",
        "knowledge_refs": [f"kn:{i}:{long}" for i in range(200)],
        "knowledge_status": "available",
        "explicit_unknowns": [f"u{i}{long}" for i in range(200)],
        "explicit_contradictions": [f"c{i}{long}" for i in range(200)],
    }


# --- schema / provenance ownership -----------------------------------------

def test_schema_version_and_owner_are_explicit_and_serialized():
    frame = _build(_golden_inputs())
    assert SITUATION_FRAME_SCHEMA_VERSION == "mio.situation_frame.v1"
    assert SITUATION_FRAME_SCHEMA_OWNER == contracts.__name__
    assert frame.to_dict()["schema_version"] == SITUATION_FRAME_SCHEMA_VERSION
    doc = DOC.read_text(encoding="utf-8")
    assert SITUATION_FRAME_SCHEMA_VERSION in doc
    assert SITUATION_FRAME_SCHEMA_OWNER in doc
    assert str(SITUATION_FRAME_MAX_SERIALIZED_BYTES) in doc


def test_golden_pins_field_set_so_schema_changes_require_version_bump():
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    frame = _build(golden["input"])
    assert golden["schema_version"] == SITUATION_FRAME_SCHEMA_VERSION
    assert sorted(frame.to_dict()) == sorted(golden["expected_frame"])
    assert frame.to_canonical_json().decode("ascii") == golden["expected_canonical_json"]
    assert frame.canonical_digest() == golden["expected_sha256"]


def test_every_material_fact_group_has_bounded_provenance():
    frame = _build(_golden_inputs())
    prov = frame.to_dict()["provenance"]
    for group in ("known_facts", "unknowns", "contradictions", "evidence_refs", "knowledge_refs"):
        if getattr(frame, group):
            assert prov.get(group), group
    assert set(prov) <= set(PROVENANCE_GROUPS)
    assert all(set(sources) <= set(PROVENANCE_SOURCES) for sources in prov.values())
    assert prov["evidence_refs"] == ["evidence_plane", "noc_evaluation", "soc_evaluation"]


@pytest.mark.parametrize("bad", [{"known_facts": ["model"]}, {"made_up_group": ["caller"]}, ["caller"]])
def test_provenance_vocabulary_is_closed(bad):
    with pytest.raises(ValueError, match="invalid_provenance"):
        MioSituationFrame.build(frame_id="f", trace_id="t", created_at="2026-01-01T00:00:00Z", mission="m", current_defensive_state="OBSERVE", threat_level="LOW", provenance=bad)


# --- canonical serialization ------------------------------------------------

def test_canonical_bytes_are_deterministic_sorted_and_compact():
    a = _build(_golden_inputs()).to_canonical_json()
    b = _build(_golden_inputs()).to_canonical_json()
    assert a == b
    parsed = json.loads(a)
    assert list(parsed) == sorted(parsed)
    assert list(parsed["provenance"]) == sorted(parsed["provenance"])
    assert b", " not in a and b": " not in a
    assert a == json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def test_canonical_bytes_escape_non_ascii_and_control_text():
    frame = MioSituationFrame.build(frame_id="f", trace_id="t", created_at="2026-01-01T00:00:00Z", mission="ミッション\u0000‮", current_defensive_state="OBSERVE", threat_level="LOW")
    raw = frame.to_canonical_json()
    assert raw.isascii()
    assert json.loads(raw)["mission"] == "ミッション\u0000‮"


def test_round_trip_preserves_frame_and_bytes():
    frame = _build(_golden_inputs())
    again = MioSituationFrame.from_dict(json.loads(frame.to_canonical_json()))
    assert again == frame
    assert again.to_canonical_json() == frame.to_canonical_json()


def test_round_trip_preserves_truncation_metadata():
    frame = _build(_worst_case_inputs(events=100))
    assert frame.truncated is True
    assert MioSituationFrame.from_dict(frame.to_dict()) == frame


def test_from_dict_rejects_unknown_schema_version():
    payload = _build(_golden_inputs()).to_dict()
    payload["schema_version"] = "mio.situation_frame.v0"
    with pytest.raises(ValueError, match="unsupported_situation_frame_schema_version"):
        MioSituationFrame.from_dict(payload)


def test_event_order_permutation_with_same_snapshot_is_stable():
    inputs = _golden_inputs()
    reordered = dict(inputs, events=list(reversed(inputs["events"])))
    a, b = _build(inputs), _build(reordered)
    # Evidence refs keep input order (replay fidelity); every derived state is identical.
    assert set(a.evidence_refs) == set(b.evidence_refs)
    assert (a.known_facts, a.unknowns, a.freshness_seconds, a.provenance) == (b.known_facts, b.unknowns, b.freshness_seconds, b.provenance)


# --- serialized-size / build-latency budgets --------------------------------

@pytest.mark.parametrize("text", ["x", "あ", "\U0001F600", "\u0000"], ids=["ascii", "bmp", "astral", "control"])
def test_worst_case_fixture_stays_within_serialized_byte_budget(text):
    frame = _build(_worst_case_inputs(text=text, events=5000))
    size = len(frame.to_canonical_json())
    assert size <= SITUATION_FRAME_MAX_SERIALIZED_BYTES
    assert frame.truncated is True
    for name, cap in SITUATION_FRAME_CAPS.items():
        assert len(getattr(frame, name)) <= cap


def test_input_traffic_volume_does_not_grow_frame():
    small = _build(_worst_case_inputs(events=2000))
    large = _build(_worst_case_inputs(events=50000))
    assert len(large.to_canonical_json()) <= SITUATION_FRAME_MAX_SERIALIZED_BYTES
    assert len(large.to_canonical_json()) == len(small.to_canonical_json())


def test_worst_case_build_latency_is_recorded_and_under_generous_ci_guard(record_testsuite_property):
    inputs = _worst_case_inputs(text="\U0001F600", events=50000)
    samples = []
    for _ in range(3):
        started = time.perf_counter()
        frame = _build(inputs)
        samples.append(time.perf_counter() - started)
    best_ms = round(min(samples) * 1000, 3)
    record_testsuite_property("situation_frame_worst_case_build_ms", best_ms)
    record_testsuite_property("situation_frame_worst_case_bytes", len(frame.to_canonical_json()))
    # Measure-and-record; the assert is only a coarse regression guard.
    assert min(samples) < CI_LATENCY_GUARD_SECONDS


# --- optional Knowledge / AZ-06 unavailable ---------------------------------

@pytest.mark.parametrize("status", ["unavailable", "timeout", "malformed", "garbage"])
def test_knowledge_unavailable_builds_marks_unknown_and_drops_refs(status):
    inputs = dict(_golden_inputs(), knowledge_refs=["kn:fabricated"], knowledge_status=status)
    frame = _build(inputs)
    expected = "malformed" if status == "garbage" else status
    assert frame.knowledge_status == expected
    assert frame.knowledge_refs == ()
    assert f"KNOWLEDGE_{expected.upper()}" in frame.unknowns
    assert "knowledge_refs" not in frame.to_dict()["provenance"]
    assert "kn:fabricated" not in frame.to_canonical_json().decode("ascii")


def test_knowledge_absent_is_explicit_not_empty_confidence():
    inputs = dict(_golden_inputs(), knowledge_refs=[])
    inputs.pop("knowledge_status", None)
    frame = _build(inputs)
    assert frame.knowledge_status == "not_provided"
    assert frame.knowledge_refs == ()
    assert not any(u.startswith("KNOWLEDGE_") for u in frame.unknowns)


def test_az06_absent_builds_without_deception_context():
    frame = _build(_golden_inputs())
    assert frame.deception_status == "not_provided"
    assert not any(u.startswith("DECEPTION_") for u in frame.unknowns)


@pytest.mark.parametrize("status", ["unavailable", "timeout"])
def test_az06_unavailable_is_an_explicit_unknown(status):
    frame = _build(dict(_golden_inputs(), deception_status=status))
    assert frame.deception_status == status
    assert f"DECEPTION_{status.upper()}" in frame.unknowns


# --- trace isolation --------------------------------------------------------

def _trace_inputs(n: int) -> dict:
    inputs = _golden_inputs()
    return dict(
        inputs,
        trace_id=f"trace-{n}",
        frame_id=f"frame-{n}",
        events=[{"event_id": f"ev:{n}:{i}", "ts": "2026-01-01T00:00:00Z"} for i in range(8)],
        noc_evaluation=dict(inputs["noc_evaluation"], evidence_ids=[f"noc:{n}"]),
        soc_evaluation=dict(inputs["soc_evaluation"], evidence_ids=[f"soc:{n}"]),
        knowledge_refs=[f"kn:{n}"],
        explicit_unknowns=[f"U_{n}"],
    )


def test_concurrent_frames_for_different_traces_do_not_mix():
    builder = MioSituationFrameBuilder()  # shared instance on purpose
    expected = {n: builder.build(**_trace_inputs(n)).to_canonical_json() for n in range(64)}
    with ThreadPoolExecutor(max_workers=16) as pool:
        frames = list(pool.map(lambda n: (n, builder.build(**_trace_inputs(n))), list(range(64)) * 4))
    for n, frame in frames:
        assert frame.trace_id == f"trace-{n}"
        assert frame.to_canonical_json() == expected[n]
        foreign = [ref for ref in frame.evidence_refs + frame.knowledge_refs if ref.split(":")[1] != str(n)]
        assert foreign == []


def test_frame_is_immune_to_later_input_mutation():
    inputs = _trace_inputs(1)
    frame = _build(inputs)
    before = frame.to_canonical_json()
    inputs["events"].append({"event_id": "ev:999:x", "ts": "2026-01-01T00:00:00Z"})
    inputs["knowledge_refs"].append("kn:999")
    inputs["explicit_unknowns"].append("U_999")
    assert frame.to_canonical_json() == before
