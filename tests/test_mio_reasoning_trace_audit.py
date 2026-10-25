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
from azazel_edge.mio.redaction import contains_sensitive, contains_token_like, redact_text
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
    # Place the invented ref directly into the outcome's recommendation and a
    # hypothesis, so the filter (not upstream grounding) is what is tested.
    import dataclasses
    f2 = frame()
    _, ticket, ok = run_cycle(f2, model())
    rec = dataclasses.replace(ok.recommendation, evidence_refs=("ev:ssh:1", "ev:invented:7"))
    hyp = dataclasses.replace(ok.hypotheses[0], supporting_evidence_refs=("ev:invented:7",))
    outcome = dataclasses.replace(ok, recommendation=rec, hypotheses=(hyp,) + ok.hypotheses[1:])
    blob = encode_record(project_outcome(ticket=ticket, outcome=outcome, key=KEY, frame=f2)).decode()
    assert "ev:invented:7" not in blob
    assert '"ev:ssh:1"' in blob  # an Edge-issued ref is kept verbatim


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
        self.dir_syncs = 0
        self.removed: list[str] = []

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
        self.removed.append(path)
        del self.files[path]

    def exists(self, path):
        return path in self.files

    def sync_dir(self, path):
        self.dir_syncs += 1


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


DETERMINISTIC_PATHS = (
    "py/azazel_edge/arbiter",
    "py/azazel_edge/tactics_engine",
    "py/azazel_edge/evaluators",
    "py/azazel_edge/correlation",
    "py/azazel_edge/sensors",
    "py/azazel_edge/control_plane.py",
    "py/azazel_edge/policy.py",
    "py/azazel_edge/decision_layers.py",
    "py/azazel_edge/soc_policy_dry_run.py",
    "bin/azazel-edge-control-daemon",
)


def _imports(src: str) -> set[str]:
    import ast
    found: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = ("." * node.level) + (node.module or "")
            found.add(base)
            found.update(f"{base}.{a.name}" for a in node.names)
    return found


def test_deterministic_modules_do_not_import_trace_audit_or_redaction():
    files = []
    for rel in DETERMINISTIC_PATHS:
        p = ROOT / rel
        assert p.exists(), rel
        files.extend(sorted(p.rglob("*.py")) if p.is_dir() else [p])
    assert len(files) >= 10
    for p in files:
        src = p.read_text(encoding="utf-8", errors="replace")
        try:
            names = _imports(src)
        except SyntaxError:  # shell wrapper scripts
            names = set()
        bad = {n for n in names if "trace_audit" in n or "redaction" in n or n.endswith("mio") or ".mio." in n + "."}
        assert not bad, (p, bad)
        assert "trace_audit" not in src and "TraceAuditSink" not in src, p


def test_trace_audit_imports_no_authority_or_env():
    src = (ROOT / "py" / "azazel_edge" / "mio" / "trace_audit.py").read_text(encoding="utf-8")
    names = _imports(src)
    assert not {n for n in names if any(w in n for w in ("arbiter", "enforce", "deception", "control_plane"))}
    assert "os.environ" not in src and "getenv" not in src


# --- review follow-ups: redaction coverage and false positives ---------------------

@pytest.mark.parametrize("text, secret", [
    ("パスワード：hunter2", "hunter2"),
    ("暗証番号は 4321", "4321"),
    ("秘密鍵=abcd1234", "abcd1234"),
    ("トークン: tok-xyz", "tok-xyz"),
    ("ｐａｓｓｗｏｒｄ＝hunter2", "hunter2"),
    ("pаsswоrd=hunter2", "hunter2"),  # Cyrillic а/о
    ("pass​word=hunter2", "hunter2"),
    ('password="correct horse battery staple"', "horse battery"),
    ("password is hunter2", "hunter2"),
    ("pw: hunter2", "hunter2"),
    ("pass=hunter2", "hunter2"),
    ("passwd=hunter2", "hunter2"),
    ("passw0rd=hunter2", "hunter2"),
    ("Bearer abc", "abc"),
    ("bearer: x9", "x9"),
    ("eyJhbGc.eyJzdWI.sg", "eyJzdWI"),
    ("key sk-abcdef123456", "sk-abcdef123456"),
    ("xoxb-1234-abcdefgh", "xoxb-1234-abcdefgh"),
    ("ghp_abcdefghij12", "ghp_abcdefghij12"),
    ("AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
    ("ftp://user:p@ss@files.example/x", "p@ss"),
    ("https://bob:hunter2@example.com/", "hunter2"),
    ("x-api-key: v4lue", "v4lue"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEsecret\n-----END RSA PRIVATE KEY-----", "MIIEsecret"),
    ("-----BEGIN PRIVATE KEY-----\nMIIEtruncated", "MIIEtruncated"),  # cut before END
])
def test_redaction_covers_variants(text, secret):
    out = redact_text(text)
    assert secret not in out and "[redacted:" in out, out


def test_private_key_rule_masks_block_without_trailing_text():
    out = redact_text("before -----BEGIN EC PRIVATE KEY-----\nAAAA\nBBBB\n-----END EC PRIVATE KEY----- after")
    assert out == "before [redacted:private_key] after"
    assert "AAAA" not in redact_text("-----BEGIN EC PRIVATE KEY-----\nAAAA\nBBBB")


def test_x_api_key_label_is_redacted_whole():
    assert redact_text("x-api-key: v") == "[redacted:secret_kv]"


@pytest.mark.parametrize("text", [
    "sha256 " + "ab" * 32,
    "sha1 " + "0f" * 20,
    "md5 " + "c" * 32,
    "ev:flow:" + "1" * 32,
    "ev:flow:abcdefabcdefabcdefabcdefabcdefabcdefab",
    "/var/lib/azazel-edge/mio/trace-audit/2026-10-25/mio-trace.jsonl",
    "ev:auth:1",
    "20 SSH failures from 192.0.2.10 to edge-gw-1 within 60s",
])
def test_redaction_false_positives_kept(text):
    assert redact_text(text) == text


def test_handoff_validates_ids_and_redacts_everything_else():
    f = frame(trace_id="trace-1", evidence_refs=["ev:ssh:1", "ghp_ABCDEFGHIJKLMNOPQRST", "password=hunter2"])
    hyp = MioHypothesis.from_mapping({"hypothesis_id": "password=hunter2", "statement": "s", "falsification_conditions": ["c"]}, ordinal=1)
    payload = build_no_model_handoff(f, reason="model_absent password=hunter2", playbook=PLAYBOOK, hypotheses=[hyp]).to_dict()
    blob = json.dumps(payload)
    assert "hunter2" not in blob and "ghp_ABCDEFGHIJKLMNOPQRST" not in blob
    assert payload["model_proposed_hypotheses"][0]["hypothesis_id"] == "invalid-hypothesis-id-1"
    assert payload["evidence_refs"][0] == "ev:ssh:1"
    assert payload["trace_id"] == "trace-1"


def test_handoff_replaces_invalid_trace_id():
    f = frame(trace_id="token=s3cr3t-value")
    payload = build_no_model_handoff(f, reason="model_absent").to_dict()
    assert "s3cr3t" not in json.dumps(payload)
    assert payload["trace_id"] == "invalid-trace-id"


# --- review follow-ups: sink hardening and mutants ----------------------------------

def test_real_append_uses_o_append_nofollow_and_fsyncs_each_record(tmp_path, monkeypatch):
    seen_flags, fsyncs = [], []
    real_open, real_fsync = os.open, os.fsync

    def spy_open(path, flags, *a, **kw):
        if str(path).endswith(".jsonl"):
            seen_flags.append(flags)
        return real_open(path, flags, *a, **kw)

    def spy_fsync(fd):
        fsyncs.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os, "open", spy_open)
    monkeypatch.setattr(os, "fsync", spy_fsync)
    sink = TraceAuditSink(str(tmp_path / "a.jsonl"))
    for i in range(3):
        assert sink.append(_record(i)).written
    assert seen_flags and all(fl & os.O_APPEND and fl & os.O_NOFOLLOW for fl in seen_flags)
    assert len(fsyncs) >= 3 + 1  # one per record, plus the directory after create


def test_real_append_refuses_symlink_and_fifo(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    sink = TraceAuditSink(str(link))
    assert not sink.append(_record()).written and not sink.advisory_allowed()
    assert target.read_bytes() == b""
    fifo = tmp_path / "fifo.jsonl"
    os.mkfifo(fifo)
    sink2 = TraceAuditSink(str(fifo))
    assert not sink2.append(_record()).written and not sink2.advisory_allowed()


def test_real_append_repairs_mode_and_torn_tail(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_bytes(b'{"torn":')
    os.chmod(path, 0o644)
    assert TraceAuditSink(str(path)).append(_record(1)).written
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    lines = path.read_bytes().split(b"\n")
    assert lines[0] == b'{"torn":' and json.loads(lines[1])["seq"] == 1


def test_partial_write_is_truncated_back(tmp_path, monkeypatch):
    path = tmp_path / "a.jsonl"
    sink = TraceAuditSink(str(path))
    assert sink.append(_record(0)).written
    before = path.read_bytes()
    real_write = os.write
    calls = {"n": 0}

    def flaky(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:
            return real_write(fd, bytes(data[:10]))
        raise OSError(errno.ENOSPC, "full")

    monkeypatch.setattr(os, "write", flaky)
    res = sink.append(_record(1))
    monkeypatch.setattr(os, "write", real_write)
    assert res.reason == "append_failed:enospc"
    assert path.read_bytes() == before


def test_sink_catches_any_exception_and_rejects_non_mapping():
    class Boom(FakeFS):
        def append_fsync(self, path, data):
            raise RecursionError("deep")
    sink = TraceAuditSink("/a.jsonl", fs=Boom())
    assert sink.append(_record()).reason == "append_failed:exception"
    sink.reset_degraded()
    assert sink.append(["not", "a", "mapping"]).reason == "non_mapping_record"
    deep: dict = {}
    cur = deep
    for _ in range(5000):
        cur["x"] = {}
        cur = cur["x"]
    sink.reset_degraded()
    assert sink.append(deep).reason == "unencodable_record"


def test_rotation_deletes_only_the_oldest_and_shifts_in_order():
    fs = FakeFS()
    sink = TraceAuditSink("/a.jsonl", max_file_bytes=MAX_RECORD_BYTES, max_files=3, fs=fs)
    for i in range(30):
        assert sink.append(_record(i)).written
    seqs = {p: [json.loads(l)["seq"] for l in fs.files[p].splitlines()] for p in fs.files}
    assert max(seqs["/a.jsonl.2"]) < min(seqs["/a.jsonl.1"])
    assert max(seqs["/a.jsonl.1"]) < min(seqs["/a.jsonl"])
    assert seqs["/a.jsonl"][-1] == 29
    # contiguous: nothing but the oldest file's records was ever lost
    all_seqs = sorted(s for v in seqs.values() for s in v)
    assert all_seqs == list(range(all_seqs[0], 30))
    assert fs.dir_syncs >= 1


def test_record_cycle_respects_degraded_even_if_write_succeeds():
    fs = FakeFS(fail_errno=errno.ENOSPC)
    sink = TraceAuditSink("/a.jsonl", fs=fs)
    assert record_cycle(sink, lambda: _record()) is False
    fs.fail_errno = None  # disk recovered, but no operator reset yet
    assert sink.append(_record()).written is True
    assert record_cycle(sink, lambda: _record()) is False
    sink.reset_degraded()
    assert record_cycle(sink, lambda: _record()) is True


# --- follow-up: ordinary SOC text is not masked (#389) -----------------------------

@pytest.mark.parametrize("text", [
    "pin: 3 hosts",
    "auth: failed for admin",
    "auth=none",
    "secret: leaked in repo",
    "token: expired",
    "pass: 12 fail: 3",
    "(pw: rejected)",
    "bearer token reuse across hosts",
    "mfa auth: denied, retry later",
    "time 12:30 @ site",
])
def test_ordinary_soc_text_is_not_masked(text):
    assert redact_text(text) == text


@pytest.mark.parametrize("text, expected", [
    ("(pw: hunter2)", "([redacted:secret_kv])"),
    ("[token: abc123]", "[[redacted:secret_kv]]"),
    ("pin: 1234", "[redacted:secret_kv]"),
    ("auth=s3cr3t", "[redacted:secret_kv]"),
    ("secret: hunter2", "[redacted:secret_kv]"),
    ("Bearer abc)", "[redacted:bearer]"),  # no opener before the label: mask through ")"
    ("password: failed", "[redacted:secret_kv]"),  # strong label always masks
    ("ftp://user:pa ss@host/x", "ftp://[redacted:url_userinfo]@host/x"),
    ("暗証番号 1234", "[redacted:secret_kv]"),
    ("ssh admin:hunter2@10.0.0.1", "ssh [redacted:url_userinfo]@10.0.0.1"),
    ("mailto:alice@example.com", "mailto:[redacted:email]"),
    ("contact alice@example.com", "contact [redacted:email]"),
])
def test_secrets_still_masked_without_eating_brackets(text, expected):
    assert redact_text(text) == expected


@pytest.mark.parametrize("value", [
    "-----BEGIN PRIVATE KEY-----\nMIIE",
    "x -----BEGIN RSA PRIVATE KEY-----\nAAA\n-----END RSA PRIVATE KEY-----",
    "eyJhbGc.eyJzdWI.sg",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.",
])
def test_contains_token_like_detects_private_key_and_jwt(value):
    assert contains_token_like(value)


def test_contains_token_like_ignores_label_rules_and_refs():
    for value in ("ev:auth:1", "password=x", "trace-1", "ab" * 32):
        assert not contains_token_like(value), value


def test_rotation_removes_exactly_the_oldest_slot():
    fs = FakeFS()
    sink = TraceAuditSink("/a.jsonl", max_file_bytes=MAX_RECORD_BYTES, max_files=3, fs=fs)
    for i in range(30):
        assert sink.append(_record(i)).written
    assert fs.removed and set(fs.removed) == {"/a.jsonl.2"}
    fs1 = FakeFS()
    single = TraceAuditSink("/b.jsonl", max_file_bytes=MAX_RECORD_BYTES, max_files=1, fs=fs1)
    for i in range(10):
        assert single.append(_record(i)).written
    assert set(fs1.files) == {"/b.jsonl"} and set(fs1.removed) == {"/b.jsonl"}
    assert len(fs1.files["/b.jsonl"]) <= MAX_RECORD_BYTES


# --- #449 review: weak-label relaxation must not leak ----------------------------

@pytest.mark.parametrize("text, secret", [
    ("pin: 1234 please", "1234"),
    ("pin: 4821 ok", "4821"),
    ("token: expired abc123", "abc123"),
    ("token: valid Zm9vYmFy", "Zm9vYmFy"),
    ("pw: failed 2024!", "2024"),
    ("pw: none hunter2", "hunter2"),
    ("auth: ok hunter2", "hunter2"),
    ("secret: none mysecret", "mysecret"),
    ("pass: 12 hunter2", "hunter2"),
    ("auth: none password=x", "password=x"),
    ("bearer token abcdef123456", "abcdef123456"),
    ("bearer token hunter", "hunter"),
    ("pin: 1234", "1234"),
    ("pin: 12", "12"),
    ("auth: admin", "admin"),
])
def test_weak_label_value_with_any_unknown_word_is_masked(text, secret):
    out = redact_text(text)
    assert secret not in out and "[redacted:" in out, out


@pytest.mark.parametrize("text, tail", [
    ("pw: p)ss", "ss"),
    ("password=pa]ss", "ss"),
    ("token=abc}def", "def"),
    ("password: hunter2) trailing", "trailing"),
])
def test_closing_bracket_without_opener_does_not_end_value(text, tail):
    out = redact_text(text)
    assert tail not in out and out.startswith("[redacted:"), out


def test_closing_bracket_ends_value_only_after_matching_opener():
    assert redact_text("(password: hunter2) next") == "([redacted:secret_kv]) next"
    assert redact_text("{token=abc123} ok") == "{[redacted:secret_kv]} ok"
    assert redact_text('(password: "a)b") x') == "([redacted:secret_kv]) x"


def test_bearer_token_skips_only_the_word_token():
    assert redact_text("bearer token") == "bearer token"
    assert redact_text("bearer token reuse across hosts") == "bearer token reuse across hosts"
    assert redact_text("Authorization: Bearer token abc123") == "[redacted:auth_header]"


def test_pin_count_needs_a_pin_specific_unit_word():
    assert redact_text("pin: 3 hosts") == "pin: 3 hosts"
    assert "12" not in redact_text("pin: 12 fail")  # "fail" is a unit for other labels, not for PIN
    assert "12" not in redact_text("pin: 12 accounts")
    assert redact_text("pass: 12 accounts") == "pass: 12 accounts"
