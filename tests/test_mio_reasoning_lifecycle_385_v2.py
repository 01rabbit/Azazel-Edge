"""#385 follow-up: fixed stale-result reason codes, ticket-bound trace
isolation under threads, material supersession, and the structured-only
no-model handoff (mio.no_model_handoff.v2)."""
from __future__ import annotations

from dataclasses import replace
import json
import threading
from pathlib import Path

import pytest

from azazel_edge.mio import (
    BoundedReasoningLoop,
    DEFAULT_PLAYBOOKS,
    MioCapabilityResult,
    MioHypothesis,
    MioSituationFrame,
    ReasoningState,
)
from azazel_edge.mio.handoff import NO_MODEL_HANDOFF_SCHEMA_VERSION, build_no_model_handoff
from azazel_edge.mio.lifecycle import (
    STALE_ALREADY_COMPLETED,
    STALE_CANCELLED,
    STALE_PRE_RESTART,
    STALE_RESULT_REASONS,
    STALE_SUPERSEDED,
    STALE_TICKET_MISMATCH,
    STALE_UNKNOWN_OR_EVICTED,
    CycleTicket,
    ReasoningCoordinator,
)

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_RICH = ROOT / "tests" / "fixtures" / "mio" / "no_model_handoff_v2_rich.json"
PLAYBOOK = DEFAULT_PLAYBOOKS["auth-ambiguity-v1"]


def frame(**overrides):
    payload = dict(
        frame_id="frame-1",
        trace_id="trace-1",
        created_at="2026-08-23T00:00:00Z",
        mission="Protect availability while investigating SSH ambiguity",
        current_defensive_state="observe",
        threat_level="high",
        known_facts=["20 SSH failures in 60s", "same source"],
        unknowns=["admin automation status"],
        evidence_refs=["ev:ssh:1", "ev:ssh:2"],
    )
    payload.update(overrides)
    return MioSituationFrame.build(**payload)


class FakeBroker:
    def names(self):
        return ("query_flow_summary",)

    def execute(self, request):
        return MioCapabilityResult(request.request_id, request.capability, True, {"flow": "bursty"}, ("ev:flow:1",))


class Outcome:
    """Minimal outcome stand-in; its fields must never pick the reason code."""

    def __init__(self, tag):
        self.state = ReasoningState.COMPLETE
        self.hypotheses = ()
        self.recommendation = None
        self.reason = "current"
        self.tag = tag


# --- fixed stale-result reason codes -----------------------------------------

def test_every_discard_path_uses_a_fixed_reason_code():
    coord = ReasoningCoordinator(max_retained_cycles=2)
    seen = {}

    sup = coord.begin(frame())
    cancelled = coord.begin(frame(threat_level="critical"))
    seen["superseded"] = coord.complete(sup, Outcome("s"))

    assert coord.cancel("trace-1") is True
    seen["cancelled"] = coord.complete(cancelled, Outcome("c"))

    done = coord.begin(frame(trace_id="B"))
    assert coord.complete(done, Outcome("ok")).accepted is True
    seen["twice"] = coord.complete(done, Outcome("again"))
    assert coord.current("B").tag == "ok"  # the second completion did not replace it

    for i in range(4):  # evict the oldest finished cycles
        t = coord.begin(frame(trace_id=f"E{i}"))
        coord.complete(t, Outcome(i))
    seen["evicted"] = coord.complete(sup, Outcome("evicted"))

    snap_coord = ReasoningCoordinator()
    pre = snap_coord.begin(frame(trace_id="R"))
    restored = ReasoningCoordinator.restore(snap_coord.snapshot())
    seen["pre_restart"] = restored.complete(pre, Outcome("pre"))

    assert {k: r.reason for k, r in seen.items()} == {
        "superseded": STALE_SUPERSEDED,
        "cancelled": STALE_CANCELLED,
        "twice": STALE_ALREADY_COMPLETED,
        "evicted": STALE_UNKNOWN_OR_EVICTED,
        "pre_restart": STALE_PRE_RESTART,
    }
    assert all(not r.accepted and r.outcome is None and r.reason in STALE_RESULT_REASONS for r in seen.values())
    assert restored.current("R") is None
    discarded = [r for r in coord.audit() + restored.audit() if r["event"] == "stale_result_discarded"]
    # The evicted cycle has no record left, so its discard is only counted.
    assert {r["reason"] for r in discarded} == {STALE_SUPERSEDED, STALE_CANCELLED, STALE_ALREADY_COMPLETED, STALE_PRE_RESTART}
    assert coord.unattributed_discards() == {STALE_UNKNOWN_OR_EVICTED: 1}


def test_pre_restart_ticket_is_stale_even_after_many_restarts():
    coord = ReasoningCoordinator()
    t = coord.begin(frame())
    for _ in range(3):
        coord = ReasoningCoordinator.restore(coord.snapshot())
    assert coord.epoch == 3
    assert coord.stale_check(t)() is True and coord.is_current(t) is False
    result = coord.complete(t, Outcome("late"))
    assert (result.accepted, result.reason) == (False, STALE_PRE_RESTART)
    # A ticket can never claim a future epoch either.
    future = replace(t, epoch=coord.epoch + 1)
    assert coord.complete(future, Outcome("future")).reason == STALE_TICKET_MISMATCH  # the record has another epoch
    unknown = replace(t, cycle_id="trace-1:e9:c9", epoch=coord.epoch + 1)
    assert coord.complete(unknown, Outcome("future")).reason == STALE_UNKNOWN_OR_EVICTED


# --- trace isolation -------------------------------------------------------------

def test_ticket_naming_another_traces_cycle_is_discarded():
    coord = ReasoningCoordinator()
    a = coord.begin(frame(trace_id="A"))
    coord.begin(frame(trace_id="B"))
    forged = replace(a, trace_id="B")
    assert coord.stale_check(forged)() is True and coord.is_current(forged) is False
    result = coord.complete(forged, Outcome("forged"))
    assert (result.accepted, result.reason) == (False, STALE_TICKET_MISMATCH)
    assert coord.current("A") is None and coord.current("B") is None
    assert coord.is_current(a)  # A's own cycle is untouched
    assert coord.complete(a, Outcome("a")).accepted is True
    assert coord.current("A").tag == "a" and coord.current("B") is None
    other_frame = replace(a, frame_id="frame-x")
    assert coord.complete(other_frame, Outcome("x")).reason == STALE_TICKET_MISMATCH
    assert coord.current("A").tag == "a"


def test_threads_racing_supersession_cancel_and_completion_never_leak_across_traces():
    coord = ReasoningCoordinator(max_traces=64, max_retained_cycles=4096, max_audit_events=100000)
    traces = [f"T{i}" for i in range(8)]
    rounds = 30
    barrier = threading.Barrier(len(traces) * 2)
    errors = []

    def owner(trace_id):
        barrier.wait()
        for n in range(rounds):
            # Every round is a material change (new evidence ref) for this trace only.
            f = frame(trace_id=trace_id, frame_id=f"f{n}", evidence_refs=["ev:ssh:1", f"ev:{trace_id}:{n}"])
            ticket = coord.begin(f)
            result = coord.complete(ticket, Outcome((trace_id, n)))
            if result.reason not in STALE_RESULT_REASONS | {"current"}:
                errors.append(result.reason)

    def interferer(trace_id):
        barrier.wait()
        for _ in range(rounds):
            coord.cancel(trace_id)

    threads = [threading.Thread(target=owner, args=(t,)) for t in traces] + [threading.Thread(target=interferer, args=(t,)) for t in traces]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    for trace_id in traces:
        current = coord.current(trace_id)
        assert current is None or current.tag[0] == trace_id
        rows = coord.audit(trace_id)
        assert rows and {r["trace_id"] for r in rows} == {trace_id}
        assert all(r["cycle_id"].startswith(f"{trace_id}:e0:c") for r in rows)
        accepted = [r for r in rows if r["event"] == "result_accepted"]
        assert len({r["cycle_id"] for r in accepted}) == len(accepted)
    cycle_ids = [c.ticket.cycle_id for c in coord._cycles.values()]
    assert len(cycle_ids) == len(set(cycle_ids))


# --- material supersession ---------------------------------------------------------

def test_non_material_change_never_supersedes_or_cancels():
    actor = {"actor_key": "actor:0001", "first_seen": "2026-08-23T00:00:00Z", "last_seen": "2026-08-23T00:00:10Z", "event_count": 3, "max_severity": 70, "protocols": ["tcp"], "target_ports": [22], "event_kinds": ["ssh"], "evidence_refs": ["ev:ssh:1"]}
    coord = ReasoningCoordinator()
    t = coord.begin(frame(actors=[actor]))
    later = dict(actor, last_seen="2026-08-23T00:05:00Z", event_count=40, evidence_refs=["ev:ssh:1", "ev:ssh:9"])
    again = coord.begin(frame(frame_id="frame-2", created_at="2026-08-23T00:05:00Z", freshness_seconds=5, actors=[later], known_facts=["same source", "20 SSH failures in 60s"]))
    assert again.deduplicated is True and again.cycle_id == t.cycle_id
    assert coord.is_current(t) and coord.stale_check(t)() is False and coord.cancel_check(t)() is False
    assert coord.complete(t, Outcome("kept")).accepted is True
    # A material change (new port) does supersede.
    moved = coord.begin(frame(actors=[dict(actor, target_ports=[22, 3389])]))
    assert moved.deduplicated is False and coord.current("trace-1") is None


# --- structured-only no-model handoff -------------------------------------------------

FREE_TEXT = "ZZFREE"


def _rich_frame():
    return frame(
        current_defensive_state="throttle",
        mission=f"{FREE_TEXT} mission",
        noc_summary=f"{FREE_TEXT} noc",
        soc_summary=f"{FREE_TEXT} soc",
        known_facts=[f"{FREE_TEXT} fact 1", f"{FREE_TEXT} fact 2"],
        unknowns=[f"{FREE_TEXT} unknown", "NOC_DEGRADED_MODE", "SOC_VISIBILITY=DEGRADED"],
        contradictions=[f"{FREE_TEXT} contradiction", "HIGH_SOC_RISK_WITH_FRAGILE_NOC"],
        knowledge_status="unavailable",
        actions=[{"role": "current", "action": "THROTTLE", "decision_ref": "dec-1", "applied_state": "applied", "mode": "dry_run"}],
    )


def _rich_hypotheses():
    return [
        MioHypothesis.from_mapping({"hypothesis_id": "h-attack", "statement": f"{FREE_TEXT} statement", "status": "strengthened", "supporting_evidence_refs": ["ev:ssh:1"], "assumptions": [f"{FREE_TEXT} assumption"], "falsification_conditions": [f"{FREE_TEXT} condition"], "expected_observations": [f"{FREE_TEXT} obs"], "missing_evidence": [f"{FREE_TEXT} gap"]}, ordinal=1),
        MioHypothesis.from_mapping({"hypothesis_id": "h-benign", "statement": f"{FREE_TEXT} other", "status": "weakened", "contradicting_evidence_refs": ["ev:ssh:2"], "falsification_conditions": [f"{FREE_TEXT} c1", f"{FREE_TEXT} c2"]}, ordinal=2),
    ]


def test_rich_handoff_matches_golden_and_copies_no_free_text():
    handoff = build_no_model_handoff(_rich_frame(), reason="budget_exhausted", playbook=PLAYBOOK, hypotheses=_rich_hypotheses())
    raw = handoff.to_canonical_json()
    assert FREE_TEXT not in raw.decode()
    assert raw == GOLDEN_RICH.read_bytes().rstrip(b"\n")
    payload = handoff.to_dict()
    assert payload["schema_version"] == NO_MODEL_HANDOFF_SCHEMA_VERSION
    assert payload["unknown_markers"] == ["KNOWLEDGE_UNAVAILABLE", "NOC_DEGRADED_MODE", "SOC_VISIBILITY=DEGRADED"]
    assert payload["contradiction_markers"] == ["HIGH_SOC_RISK_WITH_FRAGILE_NOC"]
    assert payload["counts"]["known_facts"] == 2 and payload["counts"]["unknowns"] == 4
    assert payload["current_action"] == {"action": "THROTTLE", "applied_state": "applied", "mode": "dry_run", "release_condition": "none"}
    assert "structured_fields_only" in payload["limitations"]


def test_handoff_is_deterministic_and_independent_of_free_text_content():
    one = build_no_model_handoff(_rich_frame(), reason="budget_exhausted", playbook=PLAYBOOK, hypotheses=_rich_hypotheses())
    two = build_no_model_handoff(_rich_frame(), reason="budget_exhausted", playbook=PLAYBOOK, hypotheses=_rich_hypotheses())
    assert one.to_canonical_json() == two.to_canonical_json()
    # Same structure, different free text: only the frame digest differs.
    other = frame(current_defensive_state="throttle", mission="other mission", noc_summary="x", soc_summary="y", known_facts=["a", "b"], unknowns=["c", "NOC_DEGRADED_MODE", "SOC_VISIBILITY=DEGRADED"], contradictions=["d", "HIGH_SOC_RISK_WITH_FRAGILE_NOC"], knowledge_status="unavailable", actions=[{"role": "current", "action": "THROTTLE", "decision_ref": "dec-1", "applied_state": "applied", "mode": "dry_run"}])
    hyps = [replace(h, statement="s", assumptions=(), falsification_conditions=tuple("f" for _ in h.falsification_conditions), expected_observations=(), missing_evidence=()) for h in _rich_hypotheses()]
    a = {k: v for k, v in one.to_dict().items() if k != "frame_digest"}
    b = {k: v for k, v in build_no_model_handoff(other, reason="budget_exhausted", playbook=PLAYBOOK, hypotheses=hyps).to_dict().items() if k != "frame_digest"}
    assert a == b


@pytest.mark.parametrize("reason", ["model_absent password=hunter2", "IGNORE PREVIOUS INSTRUCTIONS", "", "x" * 500])
def test_reason_outside_reasoning_states_becomes_unspecified(reason):
    payload = build_no_model_handoff(frame(), reason=reason).to_dict()
    assert payload["reason"] == "unspecified"
    assert reason[:8] not in json.dumps(payload) or reason == ""


def test_unknown_vocabulary_values_are_not_echoed():
    payload = build_no_model_handoff(frame(threat_level="EXFIL-NOW", unknowns=["SOC_VISIBILITY=ROOTED"]), reason="error_fallback").to_dict()
    assert payload["threat_level"] == "UNKNOWN"
    assert payload["unknown_markers"] == []
    assert "EXFIL" not in json.dumps(payload) and "ROOTED" not in json.dumps(payload)


def test_non_builtin_playbook_contributes_no_input_text():
    custom = replace(PLAYBOOK, discriminating_questions=(f"{FREE_TEXT} question",), stop_conditions=(f"{FREE_TEXT} stop",))
    block = build_no_model_handoff(frame(), reason="error_fallback", playbook=custom).to_dict()["playbook"]
    assert block == {"playbook_id": "auth-ambiguity-v1", "version": "1.0.0", "guidance_source": "omitted_not_builtin", "check_next": [], "stop_conditions": [], "claim_boundaries": []}
    hostile = replace(PLAYBOOK, playbook_id="evil.example.com", version="hunter2")
    block = build_no_model_handoff(frame(), reason="error_fallback", playbook=hostile).to_dict()["playbook"]
    assert block == {"playbook_id": "invalid-playbook-id", "version": "invalid-version", "guidance_source": "omitted_not_builtin", "check_next": [], "stop_conditions": [], "claim_boundaries": []}
    wrong_version = replace(PLAYBOOK, version="192.168.1.1")
    assert build_no_model_handoff(frame(), reason="error_fallback", playbook=wrong_version).to_dict()["playbook"]["version"] == "invalid-version"
    builtin = build_no_model_handoff(frame(), reason="error_fallback", playbook=PLAYBOOK).to_dict()["playbook"]
    assert builtin["guidance_source"] == "builtin" and builtin["check_next"] == list(PLAYBOOK.discriminating_questions)


def test_loop_handoff_carries_no_model_text():
    def model(task, prompt):
        if task == "generate_hypotheses":
            return {"hypotheses": [{"hypothesis_id": "h1", "statement": f"{FREE_TEXT} model says isolate", "supporting_evidence_refs": ["ev:ssh:1"], "falsification_conditions": [f"{FREE_TEXT} cond"]}]}
        return {"garbage": FREE_TEXT}

    outcome = BoundedReasoningLoop(model=model, broker=FakeBroker()).run(frame=_rich_frame(), playbook=PLAYBOOK, cycle_id="c1")
    assert outcome.handoff is not None
    raw = outcome.handoff.to_canonical_json().decode()
    assert FREE_TEXT not in raw
    for key in ("recommended_action", "executable", "approved", "command"):
        assert f'"{key}"' not in raw


# --- review follow-ups (#508) -------------------------------------------------------

HOSTILE_IDS = [
    "192.168.1.1", "0300.0250.0001.0001", "0xc0a80101", "c0a80101", "3232235777",
    "aabbccddeeff", "aa:bb:cc:dd:ee:ff", "2001:db8::1", "fe80::1",
    "evil.example.com", "host.internal", "password", "hunter2",
]
_HOSTILE_PARTS = {"192.168", "0300.0250", "c0a80101", "3232235777", "aabbccddeeff", "aa:bb", "2001:db8", "fe80::", "evil.example", "host.internal", "password", "hunter2"}


def _assert_clean(raw: str):
    leaked = [p for p in _HOSTILE_PARTS if p in raw]
    assert leaked == [], leaked


@pytest.mark.parametrize("value", HOSTILE_IDS)
@pytest.mark.parametrize("field", ["trace_id", "frame_id", "evidence_ref", "hypothesis_id", "supporting_ref", "contradicting_ref", "playbook_id", "playbook_version"])
def test_hostile_ids_never_reach_the_handoff(field, value):
    kw, hyp, pb = {}, {"hypothesis_id": "h1", "statement": "s", "falsification_conditions": ["c"]}, PLAYBOOK
    if field in ("trace_id", "frame_id"):
        kw[field] = value
    elif field == "evidence_ref":
        kw["evidence_refs"] = ["ev:ssh:1", value]
    elif field == "hypothesis_id":
        hyp["hypothesis_id"] = value
    elif field == "supporting_ref":
        hyp["supporting_evidence_refs"] = [value]
    elif field == "contradicting_ref":
        hyp["contradicting_evidence_refs"] = [value]
    elif field == "playbook_id":
        pb = replace(PLAYBOOK, playbook_id=value)
    else:
        pb = replace(PLAYBOOK, version=value)
    h = MioHypothesis.from_mapping(hyp, ordinal=1)
    payload = build_no_model_handoff(frame(**kw), reason="error_fallback", playbook=pb, hypotheses=[h]).to_dict()
    raw = json.dumps(payload)
    _assert_clean(raw)
    # Fixed placeholders, and the summary carries the placeholder too.
    if field == "trace_id":
        assert payload["trace_id"] == "invalid-trace-id" and "invalid-trace-id" in payload["summary"]
    if field == "frame_id":
        assert payload["frame_id"] == "invalid-frame-id"
    if field == "evidence_ref":
        assert payload["evidence_refs"] == ["ev:ssh:1", "[redacted:evidence_ref]"]
    if field == "hypothesis_id":
        assert payload["model_proposed_hypotheses"][0]["hypothesis_id"] == "hypothesis-1"


@pytest.mark.parametrize("value", ["trace-1", "mio-shadow", "evaluation-trace", "mio-fixture-auth-1", "trace-golden-v2"])
def test_repo_trace_id_shapes_are_kept(value):
    payload = build_no_model_handoff(frame(trace_id=value, frame_id=f"{value}:frame"), reason="error_fallback").to_dict()
    assert payload["trace_id"] == value and payload["frame_id"] == f"{value}:frame"


@pytest.mark.parametrize("ref", ["ev:ssh:1", "ev:flow:1", "ev:auth:1", "sha256:" + "a" * 64, "suricata_sid:2001219", "flow:1234567890123456"])
def test_repo_evidence_ref_shapes_are_kept(ref):
    assert build_no_model_handoff(frame(evidence_refs=[ref]), reason="error_fallback").to_dict()["evidence_refs"] == [ref]


def test_forged_tickets_write_nothing_into_the_victims_audit():
    coord = ReasoningCoordinator(max_audit_events=16)
    victim = coord.begin(frame(trace_id="victim"))
    before = coord.audit("victim")
    forged = [
        CycleTicket("victim", "victim:e0:c999", 0, "frame-1", "0" * 64),       # unknown cycle
        replace(victim, frame_id="frame-x"),                                    # mismatch on a real cycle
        replace(victim, material_digest="f" * 64),
        CycleTicket("victim", victim.cycle_id, 7, "frame-1", victim.material_digest),  # future epoch
    ]
    for _ in range(200):  # flooding must not evict the victim's rows
        for t in forged:
            assert coord.complete(t, Outcome("forged")).accepted is False
    assert coord.audit("victim") == before
    assert all(r.get("trace_id") in (None, "victim") for r in coord.audit())
    assert len(coord.audit()) == len(before)
    assert coord.unattributed_discards() == {STALE_TICKET_MISMATCH: 600, STALE_UNKNOWN_OR_EVICTED: 200}
    assert coord.is_current(victim) and coord.complete(victim, Outcome("v")).accepted is True


def test_replaying_a_real_stale_ticket_writes_one_row_only():
    coord = ReasoningCoordinator(max_audit_events=16)
    old = coord.begin(frame())
    coord.begin(frame(threat_level="critical"))
    for _ in range(100):
        assert coord.complete(old, Outcome("late")).reason == STALE_SUPERSEDED
    rows = [r for r in coord.audit("trace-1") if r["event"] == "stale_result_discarded"]
    assert len(rows) == 1 and rows[0]["cycle_id"] == old.cycle_id
    assert [r["event"] for r in coord.audit("trace-1")][:2] == ["cycle_started", "cycle_superseded"]


@pytest.mark.parametrize("bad", [
    {"cycle_id": []}, {"cycle_id": {}}, {"trace_id": []}, {"frame_id": {}},
    {"material_digest": None}, {"epoch": "0"}, {"epoch": True}, {"epoch": 0.0},
])
def test_malformed_ticket_fields_are_a_mismatch_not_an_exception(bad):
    coord = ReasoningCoordinator()
    real = coord.begin(frame())
    ticket = replace(real, **bad)
    result = coord.complete(ticket, Outcome("x"))
    assert (result.accepted, result.reason) == (False, STALE_TICKET_MISMATCH)
    assert coord.stale_check(ticket)() is True and coord.cancel_check(ticket)() is False and coord.is_current(ticket) is False
    assert coord.is_current(real) and coord.audit("trace-1") == coord.audit("trace-1")[:1]


@pytest.mark.parametrize("ticket", [None, "trace-1:e0:c1", {"cycle_id": "trace-1:e0:c1"}])
def test_non_ticket_objects_are_a_mismatch(ticket):
    coord = ReasoningCoordinator()
    coord.begin(frame())
    assert coord.complete(ticket, Outcome("x")).reason == STALE_TICKET_MISMATCH


@pytest.mark.parametrize("trace_id", [[], {}, None])
def test_cancel_with_unhashable_trace_is_false(trace_id):
    coord = ReasoningCoordinator()
    coord.begin(frame())
    assert coord.cancel(trace_id) is False


def test_threads_racing_with_snapshot_and_restore_keep_traces_apart():
    coord = ReasoningCoordinator(max_traces=64, max_retained_cycles=4096, max_audit_events=100000)
    traces = [f"T{i}" for i in range(6)]
    tickets: dict[str, list] = {t: [] for t in traces}
    stop = threading.Event()
    snaps = []

    def owner(trace_id):
        for n in range(25):
            ticket = coord.begin(frame(trace_id=trace_id, frame_id=f"f{n}", evidence_refs=["ev:ssh:1", f"ev:{trace_id}:{n}"]))
            tickets[trace_id].append(ticket)
            coord.complete(ticket, Outcome((trace_id, n)))

    def snapshotter():
        while not stop.is_set():
            snaps.append(coord.snapshot())

    snap_thread = threading.Thread(target=snapshotter)
    snap_thread.start()
    owners = [threading.Thread(target=owner, args=(t,)) for t in traces]
    for t in owners:
        t.start()
    for t in owners:
        t.join()
    stop.set()
    snap_thread.join()
    snaps.append(coord.snapshot())
    for snap in snaps:  # every concurrent snapshot is consistent and restorable
        restored = ReasoningCoordinator.restore(snap)
        for trace_id in traces:
            assert restored.current(trace_id) is None
            assert {r["trace_id"] for r in restored.audit(trace_id)} <= {trace_id}
            assert all(r["cycle_id"].startswith(f"{trace_id}:e0:c") for r in restored.audit(trace_id) if "cycle_id" in r)
    restored = ReasoningCoordinator.restore(snaps[-1])
    for trace_id in traces:
        last = tickets[trace_id][-1]
        assert restored.complete(last, Outcome("late")).reason == STALE_PRE_RESTART
        fresh = restored.begin(frame(trace_id=trace_id))
        assert fresh.cycle_id.startswith(f"{trace_id}:e1:c")
        assert restored.complete(fresh, Outcome((trace_id, "new"))).accepted
        assert restored.current(trace_id).tag == (trace_id, "new")
