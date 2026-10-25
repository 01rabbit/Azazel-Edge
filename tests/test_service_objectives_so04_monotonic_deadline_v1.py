"""SO-04: a lease's monotonic deadline, and when the wall-clock gap may close (Edge#414).

The core declares each lease's expiry on the wall clock and on CLOCK_BOOTTIME
and expires it at whichever passes first. The harness measures a sample from
the monotonic deadline, and ``SO04-LEASE-EXPIRY-ON-WALL-CLOCK`` may be left out
of a record only when every sample shows, by recomputation, that its lease
expired on that deadline. These tests check that the label alone never closes
the gap, and -- when the core is built on Linux -- that the real core expires a
lease on its monotonic deadline while its wall deadline is an hour away.
"""

from __future__ import annotations

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
SPEC = rec.OBJECTIVE_SPECS["SO-04"]["rollback_start_after_expiry"]
GAP = "SO04-LEASE-EXPIRY-ON-WALL-CLOCK"
BOOT = "0f0e0d0c-0b0a-4908-8706-050403020100"
OTHER_BOOT = "1f1e1d1c-1b1a-4918-9716-151413121110"
OFFSET0 = 1_700_000_000 * 10**9
CREATED_BOOT = 5_000 * 10**9


def _leases(n: int = 3):
    out = []
    for i in range(n):
        action = so04.ACTION_TYPES[i % len(so04.ACTION_TYPES)]
        created, due = 1_700_000_000.0, 1_700_000_100.0 + i
        lease = so04.make_lease(
            action, i, created, due,
            due_boottime_ns=CREATED_BOOT + round((due - created) * 1e9),
            due_boot_id=BOOT,
        )
        lease["_phase"] = "nominal"
        out.append(lease)
    return out


def _row(lease, *, delay_ns: int, expiry_clock: str = "monotonic", boot: str = BOOT) -> dict:
    boot_stamp = lease["due_boottime_ns"] + delay_ns
    return {
        "kind": so04.ROLLBACK_STARTED_KIND,
        "record_schema": so04.ROLLBACK_STARTED_SCHEMA,
        "release_task_id": lease["task_id"],
        "trace_id": lease["trace_id"],
        "attempt": 1,
        "lease_due_epoch_ns": round(lease["due_epoch"] * 1e9),
        "lease_due_boottime_ns": lease["due_boottime_ns"],
        "lease_boot_id": lease["due_boot_id"],
        "expiry_clock": expiry_clock,
        "started_monotonic_ns": round(lease["due_epoch"] * 1e9) - OFFSET0 + delay_ns,
        "started_boottime_ns": boot_stamp,
        "started_wall_epoch_ns": round(lease["due_epoch"] * 1e9) + delay_ns,
        "boot_id": boot,
    }


def _observe(leases, *, delay_ns=200_000_000, **row_kw):
    starts, outcomes = {}, {}
    for i, lease in enumerate(leases):
        row = _row(lease, delay_ns=delay_ns, **row_kw)
        starts[lease["task_id"]] = {
            "observed_monotonic_ns": row["started_monotonic_ns"] + 1_000_000,
            "observed_boottime_ns": row["started_boottime_ns"] + 1_000_000,
            "chain_line": i,
            "row": row,
        }
        outcomes[lease["task_id"]] = {
            "observed_monotonic_ns": row["started_monotonic_ns"] + 5_000_000,
            "release": {"release_task_id": lease["task_id"], "attempted_at_epoch": lease["due_epoch"] + 0.2, "status": "retry_pending", "result": "x"},
            "start_record_seen": True,
        }
    return starts, outcomes


def _samples(leases=None, **kw):
    leases = leases or _leases()
    return so04.build_samples(leases, *_observe(leases, **kw), OFFSET0)


def _record(samples, *, with_gap: bool):
    gaps = [g for g in SPEC["gaps"] if with_gap or g != GAP]
    start = rec.build_part(
        name="rollback_start_after_expiry",
        pass_rule={"kind": rec.RULE_EVERY_SAMPLE_MAX, "bound_ms": SPEC["bound_ms"]},
        required_samples=SPEC["required_samples"],
        samples=samples,
        prerequisites=[rec.prerequisite(p, True, "") for p in SPEC["prerequisites"]],
        gaps=[rec.gap(g, "") for g in gaps],
    )
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
        clock={"name": "CLOCK_BOOTTIME"},
        sample_rule={},
        parts=[start, completion],
        method="test",
    )


def _gap_errors(record):
    return [e for e in rec.validate_record(record) if f"mandatory gap {GAP!r} omitted" in e]


# ------------------------------------------------------------ sample building


def test_a_monotonic_lease_is_measured_from_its_monotonic_deadline():
    leases = _leases()
    starts, outcomes = _observe(leases)
    samples = so04.build_samples(leases, starts, outcomes, OFFSET0)
    for lease, s in zip(leases, samples):
        assert s["sample_clock"] == "CLOCK_BOOTTIME"
        assert s["start_monotonic_ns"] == lease["due_boottime_ns"]
        assert s["end_monotonic_ns"] == starts[lease["task_id"]]["observed_boottime_ns"]
        assert s["elapsed_ms"] == pytest.approx(201.0)
        assert s["expiry_clock"] == "monotonic"
        assert set(s) <= rec.SAMPLE_FIELDS["SO-04"]
        assert so04.start_record_problems(starts[lease["task_id"]]["row"], lease) == []
    assert rec.so04_monotonic_expiry_observed(samples) is True


def test_a_legacy_lease_is_measured_on_the_wall_deadline_and_keeps_the_gap():
    lease = so04.make_lease("isolate", 1, 1_700_000_000.0, 1_700_000_100.0)
    assert "due_boottime_ns" not in lease and "due_boot_id" not in lease
    row = {
        "kind": so04.ROLLBACK_STARTED_KIND, "record_schema": so04.ROLLBACK_STARTED_SCHEMA,
        "release_task_id": lease["task_id"], "trace_id": lease["trace_id"], "attempt": 1,
        "lease_due_epoch_ns": round(lease["due_epoch"] * 1e9), "lease_due_boottime_ns": None,
        "expiry_clock": "legacy", "started_monotonic_ns": 1, "started_wall_epoch_ns": 1,
    }
    starts = {lease["task_id"]: {"observed_monotonic_ns": round(lease["due_epoch"] * 1e9) - OFFSET0 + 10**8, "observed_boottime_ns": 7, "chain_line": 0, "row": row}}
    samples = so04.build_samples([lease], starts, {}, OFFSET0)
    assert samples[0]["sample_clock"] == "CLOCK_MONOTONIC"
    assert samples[0]["start_monotonic_ns"] == round(lease["due_epoch"] * 1e9) - OFFSET0
    assert samples[0]["lease_due_boottime_ns"] is None
    assert so04.start_record_problems(row, lease) == []
    assert rec.so04_monotonic_expiry_observed(samples) is False


def test_a_start_record_disagreeing_with_the_monotonic_deadline_is_malformed():
    lease = _leases(1)[0]
    row = _row(lease, delay_ns=0)
    row["lease_due_boottime_ns"] += 1
    assert "lease_due_boottime_ns disagrees with the ledger" in so04.start_record_problems(row, lease)
    row = _row(lease, delay_ns=0)
    row["lease_boot_id"] = OTHER_BOOT
    assert "lease_boot_id disagrees with the ledger" in so04.start_record_problems(row, lease)


# -------------------------------------------------------------- the validator


def test_the_gap_may_be_left_out_only_when_every_sample_expired_on_the_monotonic_deadline():
    samples = _samples()
    assert _gap_errors(_record(samples, with_gap=False)) == []
    # Declaring the gap anyway is allowed; it only keeps the verdict blocked.
    assert _gap_errors(_record(samples, with_gap=True)) == []
    # The remaining hostile-load gap keeps the part not_measurable.
    assert _record(samples, with_gap=False)["verdict"] == rec.VERDICT_NOT_MEASURABLE


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda s: s.update(expiry_clock="wall"), id="the core says the wall deadline fired"),
        pytest.param(lambda s: s.update(expiry_clock="boot_changed"), id="the boot changed"),
        pytest.param(lambda s: s.update(expiry_clock="legacy"), id="legacy lease"),
        # The label says monotonic, but the observed fields do not show it.
        # Both core stamps a nanosecond before their deadlines, so only the
        # monotonic-deadline check can catch it.
        pytest.param(
            lambda s: s.update(
                edge_recorded_start_boottime_ns=s["lease_due_boottime_ns"] - 1,
                edge_recorded_start_wall_epoch_ns=round(s["due_epoch"] * 1e9) - 1,
            ),
            id="core started before the monotonic deadline",
        ),
        pytest.param(lambda s: s.update(edge_recorded_start_wall_epoch_ns=s["edge_recorded_start_wall_epoch_ns"] + 10**9), id="the wall deadline fired a second earlier"),
        # The core's stamp after the harness saw the record: only the upper
        # bound can catch it (a later stamp only widens the monotonic
        # overshoot, so the wall check still holds).
        pytest.param(
            lambda s: s.update(edge_recorded_start_boottime_ns=s["end_monotonic_ns"] + 1),
            id="core stamp later than the observed end",
        ),
        pytest.param(lambda s: s.update(start_record_boot_id=OTHER_BOOT), id="record written in another boot"),
        pytest.param(lambda s: s.update(sample_clock="CLOCK_MONOTONIC"), id="measured on another clock"),
        pytest.param(lambda s: s.update(start_monotonic_ns=s["start_monotonic_ns"] + 1, elapsed_ms=round((s["end_monotonic_ns"] - s["start_monotonic_ns"] - 1) / 1e6, 3)), id="start is not the monotonic deadline"),
        pytest.param(lambda s: s.update(edge_recorded_start_boottime_ns=None), id="no core boottime stamp"),
        pytest.param(lambda s: s.update(end_monotonic_ns=None, elapsed_ms=None), id="never ended"),
    ],
)
def test_one_sample_not_showing_a_monotonic_expiry_keeps_the_gap_mandatory(mutate):
    samples = _samples()
    mutate(samples[1])
    assert rec.so04_monotonic_expiry_observed(samples) is False
    record = _record(samples, with_gap=False)
    assert _gap_errors(record), rec.validate_record(record)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE


def test_no_samples_never_close_the_gap():
    assert rec.so04_monotonic_expiry_observed([]) is False
    assert _gap_errors(_record([], with_gap=False))


def test_targets_and_sample_counts_are_unchanged():
    assert SPEC["bound_ms"] == 5000.0
    assert SPEC["required_samples"] == 150
    assert GAP in SPEC["gaps"] and SPEC["gaps_closed_by_samples"] == (GAP,)
    assert set(rec.GAP_CLOSERS) == {GAP}


def test_the_wall_attribution_tolerance_matches_the_core():
    source = (ROOT / "rust" / "azazel-edge-core" / "src" / "release.rs").read_text(encoding="utf-8")
    assert f"WALL_ATTRIBUTION_TOLERANCE_NS: i128 = {rec.SO04_WALL_ATTRIBUTION_TOLERANCE_NS:_};" in source


# ------------------------------------------------------- the real core binary


def _run_core(tmp_path, leases, wanted_rows):
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
    tail = so04._Tail(events, chain, {l["task_id"] for l in wanted_rows})
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
    assert P0AuditLogger.verify_chain(chain)["ok"] is True
    return tail


_LINUX_CORE = pytest.mark.skipif(
    not (CORE.is_file() and os.access(CORE, os.X_OK) and so04.boottime_ns() is not None and so04.boot_id()),
    reason="needs the release binary and a Linux CLOCK_BOOTTIME / boot id",
)


@_LINUX_CORE
def test_real_core_expires_a_lease_on_its_monotonic_deadline_while_the_wall_one_is_an_hour_away(tmp_path):
    now, boot_now, this_boot = time.time(), so04.boottime_ns(), so04.boot_id()
    # As after the wall clock was stepped back an hour: the wall deadline is
    # far off, the monotonic one passed a second ago.
    leases = [
        so04.make_lease(a, i, now - 10, now + 3600, due_boottime_ns=boot_now - 10**9, due_boot_id=this_boot)
        for i, a in enumerate(so04.ACTION_TYPES)
    ]
    # Another boot's deadline: counted as passed.
    rebooted = so04.make_lease("isolate", 7, now - 10, now + 3600, due_boottime_ns=boot_now + 3600 * 10**9, due_boot_id=OTHER_BOOT)
    # Not yet due on either clock: must not start.
    pending = so04.make_lease("isolate", 8, now - 10, now + 3600, due_boottime_ns=boot_now + 3600 * 10**9, due_boot_id=this_boot)
    tail = _run_core(tmp_path, leases + [rebooted, pending], leases + [rebooted])
    for lease in leases:
        row = tail.starts[lease["task_id"]]["row"]
        assert so04.start_record_problems(row, lease) == []
        assert row["expiry_clock"] == "monotonic"
        assert row["lease_due_boottime_ns"] == lease["due_boottime_ns"]
        assert row["started_boottime_ns"] >= lease["due_boottime_ns"]
        assert row["started_boottime_ns"] <= tail.starts[lease["task_id"]]["observed_boottime_ns"]
        assert tail.outcomes[lease["task_id"]]["release"]["expiry_clock"] == "monotonic"
    assert tail.starts[rebooted["task_id"]]["row"]["expiry_clock"] == "boot_changed"
    assert pending["task_id"] not in tail.starts
    samples = so04.build_samples(leases, tail.starts, tail.outcomes, 0)
    assert all(s["sample_clock"] == "CLOCK_BOOTTIME" for s in samples)
    assert rec.so04_monotonic_expiry_observed(samples) is True


@_LINUX_CORE
def test_real_core_keeps_a_legacy_lease_on_its_wall_deadline(tmp_path):
    now = time.time()
    due = so04.make_lease("isolate", 1, now - 10, now - 1)
    not_due = so04.make_lease("isolate", 2, now - 10, now + 3600)
    tail = _run_core(tmp_path, [due, not_due], [due])
    row = tail.starts[due["task_id"]]["row"]
    assert row["expiry_clock"] == "legacy"
    assert row["lease_clock"] == "wall_clock"
    assert row["lease_due_boottime_ns"] is None
    assert not_due["task_id"] not in tail.starts
