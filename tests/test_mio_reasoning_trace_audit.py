"""#389: trace identity, per-cycle working memory, durable minimized audit,
sensitive-data echo, retention/quota failure."""
from __future__ import annotations

import errno
import json
import os
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
from azazel_edge.mio.handoff import build_no_model_handoff
from azazel_edge.mio.lifecycle import ReasoningCoordinator
from azazel_edge.mio.redaction import contains_sensitive, redact_text
from azazel_edge.mio.trace_audit import (
    MAX_RECORD_BYTES,
    CycleWorkingMemory,
    OsAuditFS,
    TraceAuditSink,
    WorkingMemoryExpired,
    cycle_belongs_to,
    encode_record,
    is_valid_id,
    project_outcome,
    record_cycle,
    require_id,
)

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = DEFAULT_PLAYBOOKS["auth-ambiguity-v1"]
KEY = b"k" * 32

SECRETS = (
    "hunter2-Pa55",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab",
    "AKIAABCDEFGHIJKLMNOP",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXZhbHVl",
    "alice.tanaka@example.co.jp",
    "s3ss10n-c00kie-v4lue",
)
SECRET_TEXT = (
    f"password={SECRETS[0]} token {SECRETS[1]} {SECRETS[2]} Authorization: Bearer {SECRETS[3]} "
    f"user {SECRETS[4]} Cookie: {SECRETS[5]}"
)


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


class Broker:
    def __init__(self, data=None):
        self.data = data or {"flow": "bursty"}

    def names(self):
        return ("query_flow_summary",)

    def execute(self, request):
        return MioCapabilityResult(request.request_id, request.capability, True, dict(self.data), ("ev:flow:1",))


def model(*, echo=""):
    def run(task, prompt):
        if task == "generate_hypotheses":
            return {"hypotheses": [
                {"hypothesis_id": "h-attack", "statement": "Credential attack " + echo, "supporting_evidence_refs": ["ev:ssh:1"], "falsification_conditions": ["admin automation " + echo]},
                {"hypothesis_id": "h-benign", "statement": "Admin automation", "supporting_evidence_refs": ["ev:ssh:2"], "falsification_conditions": ["protocol shift"]},
            ]}
        if task == "identify_evidence_gaps":
            return {"evidence_gaps": [{"gap_id": "g1", "question": "Flow? " + echo, "discriminates_hypothesis_ids": ["h-attack", "h-benign"], "capability": "query_flow_summary", "priority": 90}]}
        if task == "update_hypotheses":
            first = run("generate_hypotheses", prompt)["hypotheses"]
            return {"hypotheses": [
                dict(first[0], status="strengthened", supporting_evidence_refs=["ev:ssh:1", "ev:flow:1"]),
                dict(first[1], status="weakened", contradicting_evidence_refs=["ev:flow:1"]),
            ]}
        if task == "recommend":
            return {"summary": "Observe " + echo, "recommended_action": "NOTIFY", "rationale": "Flow evidence " + echo, "evidence_refs": ["ev:ssh:1", "ev:flow:1"]}
        raise AssertionError(task)
    return run


def run_cycle(f, m, broker=None):
    coord = ReasoningCoordinator()
    ticket = coord.begin(f)
    loop = BoundedReasoningLoop(model=m, broker=broker or Broker())
    outcome = loop.run(frame=f, playbook=PLAYBOOK, cycle_id=ticket.cycle_id, cancel_check=coord.cancel_check(ticket), stale_check=coord.stale_check(ticket))
    return coord, ticket, outcome


# --- identity -------------------------------------------------------------------

def test_coordinator_minted_ids_match_grammar_and_belong_to_trace():
    coord, ticket, outcome = run_cycle(frame(), model())
    assert outcome.state is ReasoningState.COMPLETE
    assert is_valid_id("cycle_id", ticket.cycle_id) and cycle_belongs_to(ticket.cycle_id, "trace-1")
    assert not cycle_belongs_to(ticket.cycle_id, "trace-2")
    assert not cycle_belongs_to(ticket.cycle_id, "trace")  # prefix of another trace is not ownership
    assert is_valid_id("advisory_id", outcome.recommendation.advisory_id)


@pytest.mark.parametrize("value", [
    "trace-1:e0:c1:advisory",
    "edge-dec:trace-1:e0:c1:advisory",
    "edge-dec:",
    "EDGE-DEC:abc",
    "edge-dec:abc\n",
    "decision-123",
])
def test_mio_advisory_or_malformed_ids_are_not_edge_decision_refs(value):
    assert not is_valid_id("edge_decision_ref", value)
    with pytest.raises(ValueError):
        require_id("edge_decision_ref", value)
    _, ticket, outcome = run_cycle(frame(), model())
    with pytest.raises(ValueError):
        project_outcome(ticket=ticket, outcome=outcome, key=KEY, edge_decision_ref=value)


def test_edge_decision_ref_is_linked_not_minted():
    _, ticket, outcome = run_cycle(frame(), model())
    rec = project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=frame(), edge_decision_ref="edge-dec:42")
    assert rec["edge_decision_ref"] == "edge-dec:42"
    assert rec["authority"] == "advisory_only"
    assert rec["recommendation"]["executable"] is False


def test_model_emitted_fake_ids_are_digested_not_recorded():
    def m(task, prompt):
        out = model()(task, prompt)
        if task == "generate_hypotheses":
            out["hypotheses"][0]["hypothesis_id"] = "edge-dec:999"
        return out
    f = frame()
    _, ticket, outcome = run_cycle(f, m)
    rec = project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f)
    blob = encode_record(rec).decode()
    assert "edge-dec:999" not in blob
    assert any(h["hypothesis_id"].startswith("h:") for h in rec["hypotheses"])


def test_unknown_evidence_ref_from_model_is_digested():
    def m(task, prompt):
        out = model()(task, prompt)
        if task == "recommend":
            out["evidence_refs"] = ["ev:ssh:1", "ev:invented:7"]
        return out
    f = frame()
    _, ticket, outcome = run_cycle(f, m)
    rec = project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f)
    assert "ev:invented:7" not in encode_record(rec).decode()


def test_restart_mints_new_epoch_ids_never_reusing_old_cycle_ids():
    coord = ReasoningCoordinator()
    old = coord.begin(frame())
    restored = ReasoningCoordinator.restore(coord.snapshot())
    new = restored.begin(frame(frame_id="frame-9", known_facts=["changed"]))
    assert old.cycle_id != new.cycle_id and ":e1:" in new.cycle_id
    assert not restored.is_current(old)


# --- working memory -------------------------------------------------------------

def test_working_memory_is_bounded_and_namespaced():
    coord = ReasoningCoordinator()
    a = CycleWorkingMemory(coord, coord.begin(frame(trace_id="A")), max_items=2, max_bytes=64)
    b = CycleWorkingMemory(coord, coord.begin(frame(trace_id="B")))
    a.put("frame_projection", {"x": 1})
    assert b.get("frame_projection") is None
    a.put("pending", [1])
    with pytest.raises(ValueError, match="item_limit"):
        a.put("third", 1)
    with pytest.raises(ValueError, match="byte_limit"):
        a.put("pending", "y" * 80)
    with pytest.raises(ValueError, match="invalid_working_memory_key"):
        a.put("Bad Key", 1)


def test_working_memory_expires_on_supersession():
    coord = ReasoningCoordinator()
    mem = CycleWorkingMemory(coord, coord.begin(frame()))
    mem.put("raw_model_response", "unvalidated")
    coord.begin(frame(frame_id="frame-2", known_facts=["new material fact"]))
    assert len(mem) == 0 and mem.expired_reason == "cycle_not_current"
    with pytest.raises(WorkingMemoryExpired):
        mem.get("raw_model_response")


def test_working_memory_expires_on_cancel_and_on_completion():
    coord = ReasoningCoordinator()
    mem = CycleWorkingMemory(coord, coord.begin(frame()))
    mem.put("k", 1)
    coord.cancel("trace-1")
    with pytest.raises(WorkingMemoryExpired):
        mem.put("k", 2)

    coord2, ticket, outcome = run_cycle(frame(), model())
    mem2 = CycleWorkingMemory(coord2, ticket)
    mem2.put("k", 1)
    assert coord2.complete(ticket, outcome).accepted
    with pytest.raises(WorkingMemoryExpired):
        mem2.get("k")


def test_working_memory_logical_timeout_is_deterministic():
    coord = ReasoningCoordinator()
    mem = CycleWorkingMemory(coord, coord.begin(frame()), max_steps=3)
    mem.put("k", 1)
    mem.tick(); mem.tick()
    assert mem.get("k") == 1
    mem.tick()
    assert mem.expired_reason == "step_budget_exhausted"
    with pytest.raises(WorkingMemoryExpired):
        mem.get("k")


def test_working_memory_does_not_survive_restart():
    coord = ReasoningCoordinator()
    ticket = coord.begin(frame())
    mem = CycleWorkingMemory(coord, ticket)
    mem.put("raw_model_response", "x")
    snap = coord.snapshot()
    assert b"raw_model_response" not in snap
    restored = ReasoningCoordinator.restore(snap)
    with pytest.raises(WorkingMemoryExpired):
        CycleWorkingMemory(restored, ticket).get("raw_model_response")


# --- projection -----------------------------------------------------------------

def test_projection_is_deterministic_bounded_and_text_free():
    f = frame()
    _, ticket, outcome = run_cycle(f, model())
    a = encode_record(project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f))
    b = encode_record(project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f))
    assert a == b and len(a) <= MAX_RECORD_BYTES
    rec = json.loads(a)
    assert rec["schema"] == "mio.trace_audit.v1"
    assert rec["trace_id"] == "trace-1" and rec["cycle_id"] == ticket.cycle_id
    assert rec["playbook"]["playbook_id"] == "auth-ambiguity-v1"
    assert rec["broker"][0]["result"] == "ok" and rec["broker"][0]["evidence_refs"] == ["ev:flow:1"]
    assert set(rec["recommendation"]["summary"]) == {"digest", "chars"}
    for text in ("Credential attack", "Observe", "Flow evidence", "bursty", "SSH failures", "Protect availability"):
        assert text not in a.decode()
    # A different key changes digests only, never structure.
    c = json.loads(encode_record(project_outcome(ticket=ticket, outcome=outcome, key=b"z" * 32, frame=f)))
    assert c["recommendation"]["summary"]["digest"] != rec["recommendation"]["summary"]["digest"]
    assert c["trace_id"] == rec["trace_id"]


def test_projection_is_size_bounded_for_maximal_outcome():
    f = frame(known_facts=[f"fact {i}" for i in range(64)], evidence_refs=[f"ev:{i}:" + "x" * 100 for i in range(64)])
    _, ticket, outcome = run_cycle(f, model(echo="y" * 400))
    assert len(encode_record(project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f))) <= MAX_RECORD_BYTES


# --- sensitive-data echo --------------------------------------------------------

def _assert_no_secret(blob: str):
    for s in SECRETS:
        assert s not in blob, s


@pytest.mark.parametrize("where", ["frame", "broker", "model"])
def test_secrets_never_echo_into_audit_projection(where):
    f = frame(known_facts=["20 SSH failures", SECRET_TEXT], noc_summary=SECRET_TEXT, mission=SECRET_TEXT) if where == "frame" else frame()
    broker = Broker({"flow": SECRET_TEXT, "headers": {"Authorization": "Bearer " + SECRETS[3]}}) if where == "broker" else None
    m = model(echo=SECRET_TEXT) if where == "model" else model()
    _, ticket, outcome = run_cycle(f, m, broker)
    blob = encode_record(project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f)).decode()
    _assert_no_secret(blob)


def test_secret_shaped_ids_are_digested():
    f = frame(trace_id="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab", evidence_refs=["ev:ssh:1", SECRETS[2]])
    _, ticket, outcome = run_cycle(f, model())
    blob = encode_record(project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f)).decode()
    _assert_no_secret(blob)


def test_secrets_never_echo_into_no_model_handoff():
    f = frame(known_facts=[SECRET_TEXT], unknowns=[SECRET_TEXT], contradictions=[SECRET_TEXT])
    hyp = MioHypothesis.from_mapping({"hypothesis_id": "h1", "statement": SECRET_TEXT, "falsification_conditions": [SECRET_TEXT]}, ordinal=1)
    blob = build_no_model_handoff(f, reason="model_absent", playbook=PLAYBOOK, hypotheses=[hyp]).to_canonical_json().decode()
    _assert_no_secret(blob)
    assert "[redacted:" in blob


def test_secrets_never_echo_into_loop_handoff_when_model_echoes_input():
    def m(task, prompt):
        if task == "generate_hypotheses":
            return {"hypotheses": [{"hypothesis_id": "h1", "statement": SECRET_TEXT, "falsification_conditions": [SECRET_TEXT], "supporting_evidence_refs": ["ev:ssh:1"]}]}
        return {"garbage": SECRET_TEXT}  # invalid output echoing sensitive input
    f = frame(known_facts=[SECRET_TEXT])
    coord, ticket, outcome = run_cycle(f, m)
    assert outcome.handoff is not None
    _assert_no_secret(outcome.handoff.to_canonical_json().decode())
    _assert_no_secret(encode_record(project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f)).decode())


def test_redaction_keeps_operational_text():
    text = "20 SSH failures from 192.0.2.10 to edge-gw-1 within 60s"
    assert redact_text(text) == text and not contains_sensitive(text)


# --- durable sink, retention and quota ------------------------------------------

class FakeFS:
    """In-memory filesystem with an injectable quota and failures."""

    def __init__(self, quota=None, fail_rename=False, fail_errno=None):
        self.files: dict[str, bytes] = {}
        self.quota = quota
        self.fail_rename = fail_rename
        self.fail_errno = fail_errno
        self.fsyncs = 0

    def size(self, path):
        return len(self.files.get(path, b""))

    def append_fsync(self, path, data):
        if self.fail_errno is not None:
            raise OSError(self.fail_errno, os.strerror(self.fail_errno))
        if self.quota is not None and sum(map(len, self.files.values())) + len(data) > self.quota:
            raise OSError(errno.EDQUOT, "quota")
        self.files[path] = self.files.get(path, b"") + data
        self.fsyncs += 1

    def rename(self, src, dst):
        if self.fail_rename:
            raise OSError(errno.EIO, "io")
        self.files[dst] = self.files.pop(src)

    def remove(self, path):
        del self.files[path]

    def exists(self, path):
        return path in self.files


def _record(i=0):
    return {"schema": "mio.trace_audit.v1", "seq": i, "pad": "x" * 900}


def test_sink_appends_with_fsync_and_rotates_within_bounded_total():
    fs = FakeFS()
    sink = TraceAuditSink("/audit/mio.jsonl", max_file_bytes=MAX_RECORD_BYTES, max_files=3, fs=fs)
    for i in range(40):
        assert sink.append(_record(i)).written
    assert fs.fsyncs == 40 and sink.advisory_allowed()
    assert set(fs.files) <= {"/audit/mio.jsonl", "/audit/mio.jsonl.1", "/audit/mio.jsonl.2"}
    assert sum(map(len, fs.files.values())) <= MAX_RECORD_BYTES * 3
    newest = [json.loads(line)["seq"] for line in fs.files["/audit/mio.jsonl"].splitlines()]
    assert newest[-1] == 39


@pytest.mark.parametrize("fs, reason", [
    (FakeFS(quota=2000), "append_failed:edquot"),
    (FakeFS(fail_errno=errno.ENOSPC), "append_failed:enospc"),
    (FakeFS(fail_errno=errno.EROFS), "append_failed:erofs"),
])
def test_quota_or_disk_full_fails_closed_for_advisory_only(fs, reason):
    sink = TraceAuditSink("/audit/mio.jsonl", fs=fs)
    results = [sink.append(_record(i)) for i in range(5)]  # never raises
    assert not results[-1].written and results[-1].reason == reason
    assert sink.advisory_allowed() is False
    assert sink.stats()["dropped"] >= 1 and sink.stats()["drop_reasons"][reason] >= 1
    assert record_cycle(sink, lambda: _record()) is False
    sink.reset_degraded()  # explicit operator action
    assert sink.advisory_allowed() is True


def test_rotation_failure_drops_and_degrades():
    fs = FakeFS(fail_rename=True)
    sink = TraceAuditSink("/audit/mio.jsonl", max_file_bytes=MAX_RECORD_BYTES, max_files=2, fs=fs)
    outcomes = [sink.append(_record(i)).reason for i in range(10)]
    assert "rotation_failed:oserror" in outcomes
    assert sink.advisory_allowed() is False
    assert sum(map(len, fs.files.values())) <= MAX_RECORD_BYTES  # never grows past the cap


def test_oversize_or_unencodable_record_is_dropped_not_truncated():
    sink = TraceAuditSink("/audit/mio.jsonl", fs=FakeFS())
    assert sink.append({"pad": "x" * (MAX_RECORD_BYTES + 1)}).reason == "record_too_large"
    sink.reset_degraded()
    assert sink.append({"bad": float("nan")}).reason == "unencodable_record"


def test_projection_failure_withholds_advisory_without_raising():
    sink = TraceAuditSink("/audit/mio.jsonl", fs=FakeFS())
    def boom():
        raise RuntimeError("bug")
    assert record_cycle(sink, boom) is False
    assert sink.stats()["drop_reasons"] == {"projection_failed": 1}


def test_real_filesystem_append_is_private_jsonl(tmp_path):
    path = tmp_path / "mio-trace.jsonl"
    sink = TraceAuditSink(str(path), fs=OsAuditFS())
    f = frame()
    _, ticket, outcome = run_cycle(f, model())
    assert record_cycle(sink, lambda: project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f)) is True
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0]["cycle_id"] == ticket.cycle_id


def test_trace_audit_is_not_on_the_deterministic_path():
    src = (ROOT / "py" / "azazel_edge" / "mio" / "trace_audit.py").read_text(encoding="utf-8")
    imports = [line for line in src.splitlines() if line.startswith(("import ", "from "))]
    assert all("arbiter" not in l and "enforce" not in l and "deception" not in l for l in imports), imports
    assert "os.environ" not in src and "getenv" not in src
    for p in (ROOT / "py" / "azazel_edge").rglob("*.py"):
        if "mio" in p.parts:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        assert "trace_audit" not in text and "mio.redaction" not in text, p
