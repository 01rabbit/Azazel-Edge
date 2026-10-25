"""SO-04 start half: the core's rollback_started audit-chain record (Edge#414).

The end event of "rollback starts within 5 seconds of expiry" is an
audit-chain record naming the lease that states rollback has begun. These tests
check that the harness measures to that record, that a missing or late-ordered
record can never read as a pass, and -- when the core is built -- that the real
core writes a chain the Python verifier accepts.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.audit.logger import P0AuditLogger  # noqa: E402
from azazel_edge.service_objectives import record as rec  # noqa: E402
from azazel_edge.service_objectives import so04_lease_rollback as so04  # noqa: E402

CORE = ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
OFFSET0 = 1_700_000_000 * 10**9  # wall minus monotonic, in ns
SPEC = rec.OBJECTIVE_SPECS["SO-04"]["rollback_start_after_expiry"]


def _leases(n: int = 3):
    out = []
    for i in range(n):
        action = so04.ACTION_TYPES[i % len(so04.ACTION_TYPES)]
        due = 1_700_000_100.0 + i
        lease = so04.make_lease(action, i, 1_700_000_000.0, due)
        lease["_phase"] = "nominal"
        out.append(lease)
    return out


def _due_mono(lease) -> int:
    return round(lease["due_epoch"] * 1e9) - OFFSET0


def _start_row(lease, *, delay_ns: int, attempt: int = 1) -> dict:
    mono = _due_mono(lease) + delay_ns
    return {
        "kind": so04.ROLLBACK_STARTED_KIND,
        "record_schema": so04.ROLLBACK_STARTED_SCHEMA,
        "release_task_id": lease["task_id"],
        "trace_id": lease["trace_id"],
        "attempt": attempt,
        "lease_due_epoch_ns": round(lease["due_epoch"] * 1e9),
        "started_monotonic_ns": mono,
        "started_wall_epoch_ns": mono + OFFSET0,
    }


def _observations(leases, *, delay_ns=200_000_000, seen_before_outcome=True):
    starts, outcomes = {}, {}
    for i, lease in enumerate(leases):
        row = _start_row(lease, delay_ns=delay_ns)
        starts[lease["task_id"]] = {"observed_monotonic_ns": row["started_monotonic_ns"] + 1_000_000, "chain_line": i, "row": row}
        outcomes[lease["task_id"]] = {
            "observed_monotonic_ns": row["started_monotonic_ns"] + 5_000_000,
            "release": {"release_task_id": lease["task_id"], "attempted_at_epoch": lease["due_epoch"] + 0.1, "status": "retry_pending", "result": "release_attempt_failed"},
            "start_record_seen": seen_before_outcome,
        }
    return starts, outcomes


def _write_chain(path: Path, rows) -> None:
    logger = P0AuditLogger(path)
    # P0AuditLogger refuses unknown kinds, so chain the rows the way the core
    # does: same canonical form, same chain fields.
    prev = ""
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            r = dict(row, ts="2026-01-01T00:00:00.000+00:00", source="test", chain_prev=prev)
            r["chain_hash"] = logger._compute_chain_hash(r)
            prev = r["chain_hash"]
            fh.write(json.dumps(r, ensure_ascii=True, separators=(",", ":")) + "\n")


def _part(samples, prereqs, *, gaps=True):
    spec_gaps = SPEC["gaps"] if gaps else ()
    return rec.build_part(
        name="rollback_start_after_expiry",
        pass_rule={"kind": rec.RULE_EVERY_SAMPLE_MAX, "bound_ms": SPEC["bound_ms"]},
        required_samples=len(samples) if not gaps else SPEC["required_samples"],
        samples=samples,
        prerequisites=prereqs,
        gaps=[rec.gap(g, "") for g in spec_gaps],
    )


def _other_prereqs():
    return [rec.prerequisite(p, True, "") for p in SPEC["prerequisites"] if not p.startswith("rollback_start_")]


# ----------------------------------------------------------- sample building


def test_end_is_when_the_start_record_appears_not_when_the_outcome_does(tmp_path):
    leases = _leases()
    starts, outcomes = _observations(leases)
    samples = so04.build_samples(leases, starts, outcomes, OFFSET0)
    for lease, s in zip(leases, samples):
        assert s["start_monotonic_ns"] == _due_mono(lease)
        assert s["end_monotonic_ns"] == starts[lease["task_id"]]["observed_monotonic_ns"]
        assert s["elapsed_ms"] == pytest.approx(201.0)
        assert s["edge_recorded_start_monotonic_ns"] == starts[lease["task_id"]]["row"]["started_monotonic_ns"]
        assert s["start_record_before_outcome"] is True
        assert set(s) <= rec.SAMPLE_FIELDS["SO-04"]
    chain = tmp_path / "release-ledger.rollback-audit.jsonl"
    _write_chain(chain, [starts[l["task_id"]]["row"] for l in leases])
    prereqs, offsets = so04.start_record_prerequisites(leases, starts, samples, chain, OFFSET0)
    assert {p["id"]: p["met"] for p in prereqs} == {
        "rollback_start_chain_verifies": True,
        "rollback_start_recorded_before_outcome": True,
    }
    assert offsets == []


def test_chain_path_matches_the_core():
    assert so04.rollback_audit_path(Path("/var/lib/azazel-edge/release-ledger.json")) == Path(
        "/var/lib/azazel-edge/release-ledger.rollback-audit.jsonl"
    )
    source = (ROOT / "rust" / "azazel-edge-core" / "src" / "release.rs").read_text(encoding="utf-8")
    assert '"{stem}.rollback-audit.jsonl"' in source
    assert f'ROLLBACK_STARTED_SCHEMA: &str = "{so04.ROLLBACK_STARTED_SCHEMA}"' in source
    assert f'ROLLBACK_STARTED_KIND: &str = "{so04.ROLLBACK_STARTED_KIND}"' in source


def test_missing_start_record_is_unfinished_and_unmet(tmp_path):
    leases = _leases()
    starts, outcomes = _observations(leases)
    del starts[leases[1]["task_id"]]
    outcomes[leases[1]["task_id"]]["start_record_seen"] = False
    samples = so04.build_samples(leases, starts, outcomes, OFFSET0)
    assert samples[1]["end_monotonic_ns"] is None and samples[1]["elapsed_ms"] is None
    chain = tmp_path / "chain.jsonl"
    _write_chain(chain, [starts[l["task_id"]]["row"] for l in leases if l["task_id"] in starts])
    prereqs, _ = so04.start_record_prerequisites(leases, starts, samples, chain, OFFSET0)
    met = {p["id"]: p["met"] for p in prereqs}
    assert met["rollback_start_recorded_before_outcome"] is False
    # Real table: the remaining gaps keep it not_measurable.
    part = _part(samples, _other_prereqs() + prereqs)
    assert part["verdict"] == rec.VERDICT_NOT_MEASURABLE
    # With every gap closed and every prerequisite met, a missing record is
    # still a violation of the pass rule: fail, never pass.
    met_all = [rec.prerequisite(p, True, "") for p in SPEC["prerequisites"]]
    assert _part(samples, met_all, gaps=False)["verdict"] == rec.VERDICT_FAIL


def test_no_chain_at_all_is_not_measurable(tmp_path):
    leases = _leases()
    samples = so04.build_samples(leases, {}, {}, OFFSET0)
    prereqs, _ = so04.start_record_prerequisites(leases, {}, samples, tmp_path / "absent.jsonl", OFFSET0)
    assert all(p["met"] is False for p in prereqs)
    assert _part(samples, _other_prereqs() + prereqs, gaps=False)["verdict"] == rec.VERDICT_NOT_MEASURABLE


def test_start_record_after_its_outcome_is_not_measurable(tmp_path):
    leases = _leases()
    starts, outcomes = _observations(leases, seen_before_outcome=False)
    samples = so04.build_samples(leases, starts, outcomes, OFFSET0)
    chain = tmp_path / "chain.jsonl"
    _write_chain(chain, [starts[l["task_id"]]["row"] for l in leases])
    prereqs, _ = so04.start_record_prerequisites(leases, starts, samples, chain, OFFSET0)
    assert {p["id"]: p["met"] for p in prereqs}["rollback_start_recorded_before_outcome"] is False
    assert _part(samples, _other_prereqs() + prereqs, gaps=False)["verdict"] == rec.VERDICT_NOT_MEASURABLE


def test_late_start_record_fails_once_the_gaps_are_closed(tmp_path):
    leases = _leases()
    starts, outcomes = _observations(leases, delay_ns=6 * 10**9)
    samples = so04.build_samples(leases, starts, outcomes, OFFSET0)
    met_all = [rec.prerequisite(p, True, "") for p in SPEC["prerequisites"]]
    assert _part(samples, met_all, gaps=False)["verdict"] == rec.VERDICT_FAIL
    on_time = so04.build_samples(leases, *_observations(leases), OFFSET0)
    assert _part(on_time, met_all, gaps=False)["verdict"] == rec.VERDICT_PASS


def test_tampered_or_mismatched_start_record_fails_the_chain_prerequisite(tmp_path):
    leases = _leases()
    starts, outcomes = _observations(leases)
    samples = so04.build_samples(leases, starts, outcomes, OFFSET0)
    chain = tmp_path / "chain.jsonl"
    _write_chain(chain, [starts[l["task_id"]]["row"] for l in leases])
    lines = chain.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["attempt"] = 9
    lines[1] = json.dumps(row, separators=(",", ":"))
    chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    prereqs, _ = so04.start_record_prerequisites(leases, starts, samples, chain, OFFSET0)
    assert {p["id"]: p["met"] for p in prereqs}["rollback_start_chain_verifies"] is False

    starts2 = copy.deepcopy(starts)
    starts2[leases[0]["task_id"]]["row"]["trace_id"] = "someone-else"
    _write_chain(chain, [starts2[l["task_id"]]["row"] for l in leases])
    prereqs, _ = so04.start_record_prerequisites(leases, starts2, samples, chain, OFFSET0)
    assert {p["id"]: p["met"] for p in prereqs}["rollback_start_chain_verifies"] is False


def test_a_wall_clock_step_seen_in_a_start_record_is_reported(tmp_path):
    leases = _leases()
    starts, outcomes = _observations(leases)
    starts[leases[2]["task_id"]]["row"]["started_wall_epoch_ns"] += 10**9
    samples = so04.build_samples(leases, starts, outcomes, OFFSET0)
    chain = tmp_path / "chain.jsonl"
    _write_chain(chain, [starts[l["task_id"]]["row"] for l in leases])
    _, offsets = so04.start_record_prerequisites(leases, starts, samples, chain, OFFSET0)
    assert offsets == [leases[2]["task_id"]]


# ------------------------------------------------------------------- the tail


def _outcome_line(lease) -> str:
    return json.dumps({"pipeline": "rust_release_engine_v1", "release": {"release_task_id": lease["task_id"], "attempted_at_epoch": lease["due_epoch"], "status": "retry_pending", "result": "x"}}) + "\n"


def test_tail_sees_a_start_record_written_before_the_outcome(tmp_path):
    lease = _leases(1)[0]
    events, chain = tmp_path / "events.jsonl", tmp_path / "chain.jsonl"
    tail = so04._Tail(events, chain, {lease["task_id"]})
    _write_chain(chain, [_start_row(lease, delay_ns=0)])
    events.write_text(_outcome_line(lease), encoding="utf-8")
    # Even when the outcome is read in the same pass, before the chain is.
    tail.poll_events()
    assert tail.outcomes[lease["task_id"]]["start_record_seen"] is True
    assert tail.done()


def test_tail_flags_a_start_record_written_after_the_outcome(tmp_path):
    lease = _leases(1)[0]
    events, chain = tmp_path / "events.jsonl", tmp_path / "chain.jsonl"
    tail = so04._Tail(events, chain, {lease["task_id"]})
    events.write_text(_outcome_line(lease), encoding="utf-8")
    tail.poll_chain()
    tail.poll_events()
    _write_chain(chain, [_start_row(lease, delay_ns=0)])
    tail.poll_chain()
    assert tail.outcomes[lease["task_id"]]["start_record_seen"] is False
    assert lease["task_id"] in tail.starts
    samples = so04.build_samples([lease], tail.starts, tail.outcomes, OFFSET0)
    assert samples[0]["start_record_before_outcome"] is False


# -------------------------------------------------------------- the validator


def _so04_record(samples, prereqs):
    start = _part(samples, prereqs)
    completion = rec.build_part(
        name="rollback_completion",
        pass_rule={"kind": rec.RULE_EVERY_SAMPLE_MAX, "bound_ms": 0.0},
        required_samples=150,
        samples=[],
        prerequisites=[rec.prerequisite("per_action_completion_bound_declared", False, "")],
        gaps=[rec.gap("OF-05", "")],
    )
    return rec.build_record(
        objective_id="SO-04",
        title="t",
        started_monotonic_ns=0,
        started_at=rec.utc_now(),
        product_configuration={},
        clock={"name": "CLOCK_MONOTONIC"},
        sample_rule={},
        parts=[start, completion],
        method="test",
    )


def test_validator_requires_the_start_record_prerequisites():
    leases = _leases()
    samples = so04.build_samples(leases, *_observations(leases), OFFSET0)
    record = _so04_record(samples, _other_prereqs())
    errors = rec.validate_record(record)
    assert any("mandatory prerequisite 'rollback_start_chain_verifies' omitted" in e for e in errors), errors
    assert any("mandatory prerequisite 'rollback_start_recorded_before_outcome' omitted" in e for e in errors), errors
    assert "SO04-END-RECORD-NOT-AUDIT-CHAIN" not in SPEC["gaps"]


def test_validator_recomputes_the_order_from_the_samples():
    leases = _leases()
    starts, outcomes = _observations(leases)
    outcomes[leases[0]["task_id"]]["start_record_seen"] = False
    samples = so04.build_samples(leases, starts, outcomes, OFFSET0)
    # Declares the ordering met although a sample shows the record came late.
    record = _so04_record(samples, [rec.prerequisite(p, True, "") for p in SPEC["prerequisites"]])
    errors = rec.validate_record(record)
    assert any("'rollback_start_recorded_before_outcome' declared met but the samples do not show it" in e for e in errors), errors


# ------------------------------------------------------- the real core binary


@pytest.mark.skipif(not (CORE.is_file() and os.access(CORE, os.X_OK)), reason="the release binary is not built; run cargo build --release --manifest-path rust/azazel-edge-core/Cargo.toml")
def test_real_core_writes_a_verifiable_start_record_before_each_outcome(tmp_path):
    now = time.time()
    leases = [so04.make_lease(a, i, now - 10, now - 1) for i, a in enumerate(so04.ACTION_TYPES)]
    ledger = tmp_path / "release-ledger.json"
    events = tmp_path / "events.jsonl"
    eve = tmp_path / "eve.json"
    eve.write_text("", encoding="utf-8")
    ledger.write_text(json.dumps({"schema_version": so04.LEDGER_SCHEMA, "tasks": leases}), encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "AZAZEL_EVE_PATH": str(eve),
        "AZAZEL_FORWARD_AI": "false",
        "AZAZEL_NORMALIZED_EVENT_LOG": str(events),
        "AZAZEL_DEFENSE_RELEASE_LEDGER": str(ledger),
        "AZAZEL_EVENT_STDOUT": "off",
        "AZAZEL_REDIRECT_POLICY_PATH": str(ROOT / "config" / "redirect_policy.yaml"),
    }
    chain = so04.rollback_audit_path(ledger)
    tail = so04._Tail(events, chain, {l["task_id"] for l in leases})
    proc = subprocess.Popen([str(CORE)], cwd=str(tmp_path), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not tail.done():
            tail.poll_chain()
            tail.poll_events()
            time.sleep(0.002)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    assert tail.done(), (tail.starts.keys(), tail.outcomes.keys(), proc.stderr.read()[-500:])
    assert all(o["start_record_seen"] for o in tail.outcomes.values())
    verified = P0AuditLogger.verify_chain(chain)
    assert verified["ok"] is True and verified["entries"] >= len(leases), verified
    assert oct(chain.stat().st_mode & 0o777) == "0o600"
    for lease in leases:
        row = tail.starts[lease["task_id"]]["row"]
        assert so04.start_record_problems(row, lease) == []
        assert row["trace_id"] == lease["trace_id"]
        assert row["started_monotonic_ns"] <= tail.starts[lease["task_id"]]["observed_monotonic_ns"]
        # The core's monotonic stamp is on the clock the harness reads.
        assert abs(row["started_monotonic_ns"] - time.monotonic_ns()) < 60 * 10**9
    # Nothing in the run enabled enforcement.
    first = json.loads(events.read_text(encoding="utf-8").splitlines()[0])
    assert first["enforcement_status"]["enforce_enabled"] is False
