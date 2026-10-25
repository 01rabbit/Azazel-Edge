"""SO-04 completion half against Edge's per-action completion bounds (OF-05, Edge#414).

The bounds are provisional declarations read from
``config/service_objectives/rollback_completion_bounds.json``. These tests check
that the harness and the validator read the file rather than the record, that
an undeclared action type can never pass, that the provisional status keeps the
part ``not_measurable``, and that the measurement never touches owned state it
did not create.
"""

from __future__ import annotations

import copy
import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.service_objectives import declarations as decl  # noqa: E402
from azazel_edge.service_objectives import record as rec  # noqa: E402
from azazel_edge.service_objectives import so04_lease_rollback as so04  # noqa: E402
from azazel_edge.service_objectives import so04_rollback_completion as comp  # noqa: E402

OFFSET0 = 1_700_000_000 * 10**9
SPEC = rec.OBJECTIVE_SPECS["SO-04"]["rollback_completion"]
START_SPEC = rec.OBJECTIVE_SPECS["SO-04"]["rollback_start_after_expiry"]


# ------------------------------------------------------------- the declaration


def test_declaration_is_provisional_container_derived_and_cites_its_basis():
    d = decl.load_rollback_completion_bounds()
    assert d["problems"] == []
    assert d["path"] == "config/service_objectives/rollback_completion_bounds.json"
    assert d["bounds_ms"] == {"throttle": 5000.0, "isolate": 5000.0, "redirect": 5000.0}
    assert set(d["statuses"].values()) == {decl.PROVISIONAL}
    raw = json.loads(decl.ROLLBACK_COMPLETION_BOUNDS_PATH.read_text(encoding="utf-8"))
    for entry in raw["bounds"]:
        assert entry["hardware_class"] == "container-aarch64, not hardware"
        basis = entry["basis"]
        assert basis["sample_count"] >= SPEC["required_samples"] // len(decl.ROLLBACK_ACTION_TYPES)
        # The stated margin rule reproduces the bound.
        assert entry["bound_ms"] == math.ceil(2 * basis["max_observed_ms"] / 1000) * 1000
        # Every sample of the basis completed.
        assert basis["completed"] == basis["sample_count"]
    assert "undeclared" not in raw
    assert decl.undeclared_action_types(d) == []


def test_declared_action_types_match_the_harness_and_the_core():
    assert decl.ROLLBACK_ACTION_TYPES == so04.ACTION_TYPES


def _write(tmp_path, entries, schema=decl.ROLLBACK_COMPLETION_BOUNDS_SCHEMA):
    p = tmp_path / "bounds.json"
    p.write_text(json.dumps({"schema": schema, "bounds": entries}), encoding="utf-8")
    return p


def _entry(action="isolate", bound=5000, **over):
    e = {
        "action_type": action,
        "bound_ms": bound,
        "status": "provisional",
        "hardware_class": "container-aarch64, not hardware",
        "basis": {"method": "m", "sample_count": 150, "max_observed_ms": 1000.0, "margin_rule": "r"},
    }
    e.update(over)
    return e


@pytest.mark.parametrize(
    "bad",
    [
        _entry(bound=-1),
        _entry(bound=float("inf")),
        _entry(bound=True),
        _entry(status="final"),
        _entry(status=None),
        _entry(action="reboot"),
        _entry(hardware_class=""),
        _entry(basis={"method": "m"}),
        _entry(bound=500),  # below its own max_observed_ms
    ],
)
def test_a_malformed_entry_declares_nothing(tmp_path, bad):
    d = decl.load_rollback_completion_bounds(_write(tmp_path, [bad]))
    assert d["bounds_ms"] == {}
    assert d["problems"]


def test_a_duplicate_action_declares_neither(tmp_path):
    d = decl.load_rollback_completion_bounds(_write(tmp_path, [_entry(bound=5000), _entry(bound=9000)]))
    assert "isolate" not in d["bounds_ms"]


def test_a_missing_or_foreign_file_declares_nothing(tmp_path):
    assert decl.load_rollback_completion_bounds(tmp_path / "absent.json")["bounds_ms"] == {}
    assert decl.load_rollback_completion_bounds(_write(tmp_path, [_entry()], schema="other/v1"))["bounds_ms"] == {}


# ------------------------------------------------------------- the pass rule


def test_per_action_rule_counts_undeclared_and_over_bound_as_violations():
    bounds = {"isolate": 5000.0}
    ok = rec.evaluate_every_sample_max_per_action([{"action_type": "isolate", "elapsed_ms": 4999.0}], bounds)
    assert ok["holds"] and ok["violations"] == 0
    over = rec.evaluate_every_sample_max_per_action([{"action_type": "isolate", "elapsed_ms": 5000.1}], bounds)
    assert not over["holds"]
    undeclared = rec.evaluate_every_sample_max_per_action([{"action_type": "throttle", "elapsed_ms": 1.0}], bounds)
    assert not undeclared["holds"] and undeclared["undeclared_action_samples"] == 1
    unfinished = rec.evaluate_every_sample_max_per_action([{"action_type": "isolate", "elapsed_ms": None}], bounds)
    assert not unfinished["holds"] and unfinished["unfinished_samples"] == 1
    assert not rec.evaluate_every_sample_max_per_action([], bounds)["holds"]


# ------------------------------------------------------------- samples


def _leases(per_type=2):
    out = []
    for i in range(per_type):
        for action in decl.ROLLBACK_ACTION_TYPES:
            iface = comp.throttle_iface(i) if action == "throttle" else so04.IFACE
            lease = so04.make_lease(action, i, 1_700_000_000.0, 1_700_000_100.0 + i, iface=iface)
            lease["_phase"] = "nominal"
            out.append(lease)
    return out


def _observed(leases, *, delay_ms=500.0, skip=()):
    completed, outcomes, installed, absent = {}, {}, {}, {}
    for lease in leases:
        tid = lease["task_id"]
        installed[tid] = True
        if lease["action"] in skip:
            outcomes[tid] = [{"status": "retry_pending", "result": "release_attempt_failed"}]
            absent[tid] = True  # still present
            continue
        release = {"status": "released", "result": comp.COMPLETED_RESULT}
        outcomes[tid] = [release]
        completed[tid] = {"observed_monotonic_ns": round(lease["due_epoch"] * 1e9) - OFFSET0 + int(delay_ms * 1e6), "release": release}
        absent[tid] = False
    return completed, outcomes, installed, absent


def test_throttle_leases_each_own_their_interface():
    leases = [l for l in _leases(3) if l["action"] == "throttle"]
    assert len({l["iface"] for l in leases}) == 3
    for l in leases:
        assert l["resource_key"] == f"tc:root:{l['iface']}"
        assert len(l["iface"]) <= 15


def test_build_samples_measures_to_the_completing_outcome():
    leases = _leases()
    bounds = {"isolate": 5000.0, "redirect": 6000.0}
    samples = comp.build_samples(leases, *_observed(leases, skip=("throttle",)), bounds, OFFSET0)
    by_action = {}
    for s in samples:
        by_action.setdefault(s["action_type"], []).append(s)
        assert s["owned_state_installed"] is True
    for s in by_action["isolate"] + by_action["redirect"]:
        assert s["elapsed_ms"] == 500.0
        assert s["completion_result"] == comp.COMPLETED_RESULT
        assert s["owned_state_absent_after_run"] is True
    for s in by_action["throttle"]:
        assert s["elapsed_ms"] is None and s["end_monotonic_ns"] is None
        assert s["completion_bound_ms"] is None
        assert s["completion_result"] == "release_attempt_failed"


# ------------------------------------------------------------- the validator


def _start_part():
    return rec.build_part(
        name="rollback_start_after_expiry",
        pass_rule={"kind": rec.RULE_EVERY_SAMPLE_MAX, "bound_ms": START_SPEC["bound_ms"]},
        required_samples=START_SPEC["required_samples"],
        samples=[],
        prerequisites=[rec.prerequisite(p, False, "") for p in START_SPEC["prerequisites"]],
        gaps=[rec.gap(g, "") for g in START_SPEC["gaps"]],
        per_action_required=START_SPEC["per_action_samples"],
    )


def _record(samples, *, declaration=None, gaps=None, prereqs=None):
    d = declaration or decl.load_rollback_completion_bounds()
    part = rec.build_part(
        name="rollback_completion",
        pass_rule=comp.pass_rule(d),
        required_samples=SPEC["required_samples"],
        samples=samples,
        prerequisites=prereqs if prereqs is not None else [rec.prerequisite(p, True, "") for p in SPEC["prerequisites"]],
        gaps=gaps if gaps is not None else [rec.gap(g, "") for g in SPEC["gaps"]],
        per_action_required=SPEC["per_action_samples"],
    )
    return rec.build_record(
        objective_id="SO-04",
        title="t",
        started_monotonic_ns=0,
        started_at=rec.utc_now(),
        product_configuration={},
        clock={"name": "CLOCK_MONOTONIC"},
        sample_rule={},
        parts=[_start_part(), part],
        method="test",
    )


def _full_samples(skip=()):
    leases = _leases(50)
    d = decl.load_rollback_completion_bounds()
    return comp.build_samples(leases, *_observed(leases, skip=skip), d["bounds_ms"], OFFSET0)


@pytest.fixture
def no_throttle(monkeypatch, tmp_path):
    """A declaration file without a throttle bound."""

    path = _write(tmp_path, [_entry("isolate", 5000), _entry("redirect", 5000)])
    monkeypatch.setattr(decl, "ROLLBACK_COMPLETION_BOUNDS_PATH", path)
    return path


def test_record_cites_the_declaration_and_validates():
    record = _record(_full_samples())
    part = record["parts"][1]
    d = decl.load_rollback_completion_bounds()
    assert part["pass_rule"]["declaration"] == d["path"]
    assert part["pass_rule"]["declaration_sha256"] == d["sha256"]
    assert rec.validate_record(json.loads(json.dumps(record))) == []
    # Every action type declared and every sample within its bound: still the
    # provisional gap keeps it from passing.
    assert part["pass_rule"]["evaluated"]["holds"] is True
    assert part["verdict"] == rec.VERDICT_NOT_MEASURABLE


def test_a_bound_declared_met_against_a_file_without_it_is_refused(no_throttle):
    record = _record(_full_samples(skip=("throttle",)))
    errors = rec.validate_record(json.loads(json.dumps(record)))
    # The harness declared the bound prerequisite met; the file says otherwise.
    assert any("'per_action_completion_bound_declared' declared met" in e for e in errors), errors
    assert record["parts"][1]["verdict"] == rec.VERDICT_NOT_MEASURABLE


def test_undeclared_throttle_keeps_the_part_not_measurable_even_if_every_sample_completes(no_throttle):
    samples = _full_samples()
    prereqs = [rec.prerequisite(p, p != "per_action_completion_bound_declared", "") for p in SPEC["prerequisites"]]
    record = _record(samples, prereqs=prereqs)
    assert rec.validate_record(json.loads(json.dumps(record))) == []
    part = record["parts"][1]
    assert part["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert part["pass_rule"]["evaluated"]["undeclared_action_samples"] == 50


def test_provisional_gap_is_mandatory_and_blocks_even_a_complete_declaration(monkeypatch, tmp_path):
    full = _write(tmp_path, [_entry(a, 6000) for a in decl.ROLLBACK_ACTION_TYPES])
    monkeypatch.setattr(decl, "ROLLBACK_COMPLETION_BOUNDS_PATH", full)
    d = decl.load_rollback_completion_bounds()
    assert decl.undeclared_action_types(d) == []
    samples = comp.build_samples(_leases(50), *_observed(_leases(50)), d["bounds_ms"], OFFSET0)
    record = _record(samples, declaration=d)
    assert rec.validate_record(json.loads(json.dumps(record))) == []
    assert record["parts"][1]["verdict"] == rec.VERDICT_NOT_MEASURABLE
    # Dropping the provisional gap is refused, and still not a pass.
    stripped = _record(samples, declaration=d, gaps=[rec.gap(g, "") for g in SPEC["gaps"] if g != "SO04-COMPLETION-BOUND-PROVISIONAL"])
    errors = rec.validate_record(json.loads(json.dumps(stripped)))
    assert any("mandatory gap 'SO04-COMPLETION-BOUND-PROVISIONAL' omitted" in e for e in errors), errors


def test_a_record_with_looser_bounds_than_the_file_is_rejected():
    record = _record(_full_samples(skip=("throttle",)))
    tampered = copy.deepcopy(record)
    tampered["parts"][1]["pass_rule"]["bounds_ms"] = {"isolate": 1e12, "redirect": 1e12, "throttle": 1e12}
    errors = rec.validate_record(tampered)
    assert any("pass_rule.bounds_ms" in e for e in errors), errors


def test_a_record_against_another_version_of_the_file_is_rejected():
    record = _record(_full_samples(skip=("throttle",)))
    record["parts"][1]["pass_rule"]["declaration_sha256"] = "0" * 64
    errors = rec.validate_record(record)
    assert any("pass_rule.declaration" in e for e in errors), errors


def test_validator_recomputes_installed_and_readback_from_samples():
    samples = _full_samples(skip=("throttle",))
    samples[0]["owned_state_installed"] = False
    done = next(s for s in samples if s["end_monotonic_ns"] is not None)
    done["owned_state_absent_after_run"] = False
    errors = rec.validate_record(json.loads(json.dumps(_record(samples))))
    assert any("'owned_state_installed_before_expiry' declared met" in e for e in errors), errors
    assert any("'completion_confirmed_by_readback' declared met" in e for e in errors), errors


def test_over_bound_completion_is_counted():
    leases = _leases(50)
    d = decl.load_rollback_completion_bounds()
    bounds = {"isolate": 5000.0, "redirect": 6000.0}
    samples = comp.build_samples(leases, *_observed(leases, delay_ms=5500.0, skip=("throttle",)), bounds, OFFSET0)
    ev = rec.evaluate_every_sample_max_per_action(samples, bounds)
    # isolate (5000 ms) violated, redirect (6000 ms) holds, throttle undeclared.
    assert ev["per_action"]["isolate"]["violations"] == 50
    assert ev["per_action"]["redirect"]["violations"] == 0
    assert ev["per_action"]["throttle"]["violations"] == 50


# ------------------------------------------------------------- the measurement


def test_measure_without_a_core_is_not_measurable_and_runs_nothing():
    part = comp.measure(core=Path("/nonexistent"), version=None, leases_per_type=50)
    assert part["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert part["samples"] == []
    met = {p["id"]: p["met"] for p in part["prerequisites"]}
    assert set(met) == set(SPEC["prerequisites"])
    assert met["core_binary_present"] is False
    assert met["owned_state_installed_before_expiry"] is False


def test_owned_state_refuses_an_existing_azazel_edge_table(monkeypatch):
    owned = comp.OwnedState()
    owned.tc = owned.nft = owned.ip = "/bin/true"
    monkeypatch.setattr(comp.os, "geteuid", lambda: 0)
    calls = []

    class _Done:
        def __init__(self, rc):
            self.returncode, self.stdout, self.stderr = rc, "", ""

    def fake_run(argv, stdin=None):
        calls.append(argv)
        return _Done(0)  # "nft list table inet azazel_edge" succeeds: it exists

    monkeypatch.setattr(comp, "_run", fake_run)
    reason = owned.unavailable_reason()
    assert reason and "already exists" in reason
    # Nothing was created after the table was found.
    assert all("add" not in argv for argv in calls)


def test_cleanup_removes_only_what_the_harness_created(monkeypatch):
    owned = comp.OwnedState()
    owned.tc = owned.nft = owned.ip = "/bin/true"
    calls = []
    monkeypatch.setattr(comp, "_run", lambda argv, stdin=None: calls.append(argv))
    owned.cleanup()
    assert calls == []
    owned.created_ifaces = ["so04c000"]
    owned.created_table = True
    owned.cleanup()
    assert calls == [["/bin/true", "link", "del", "so04c000"], ["/bin/true", "delete", "table", "inet", "azazel_edge"]]


def test_completion_harness_never_enables_enforcement():
    source = Path(comp.__file__).read_text(encoding="utf-8")
    assert '"AZAZEL_DEFENSE_ENFORCE":' not in source
    assert "env.pop(key, None)" in source


# ------------------------------------------------- review follow-ups (Edge#440)

BOOT = "11111111-2222-3333-4444-555555555555"
BOOT0 = 5_000_000_000_000


def _mono_leases(per_type=50):
    out = []
    for i in range(per_type):
        for action in decl.ROLLBACK_ACTION_TYPES:
            iface = comp.throttle_iface(i) if action == "throttle" else so04.IFACE
            due = 1_700_000_100.0 + i * 0.1
            lease = so04.make_lease(
                action, i, 1_700_000_000.0, due, iface=iface,
                due_boottime_ns=BOOT0 + round((due - 1_700_000_000.0) * 1e9), due_boot_id=BOOT,
            )
            lease["_phase"] = "nominal"
            out.append(lease)
    return out


def _start_records(leases, delay_ns=100_000_000):
    return {
        l["task_id"]: {
            "kind": "rollback_started",
            "release_task_id": l["task_id"],
            "expiry_clock": "monotonic",
            "boot_id": BOOT,
            "started_boottime_ns": l["due_boottime_ns"] + delay_ns,
            "started_wall_epoch_ns": round(l["due_epoch"] * 1e9) + delay_ns,
        }
        for l in leases
    }


def _mono_observed(leases, *, delay_ms=500.0, skip=()):
    completed, outcomes, installed, absent = {}, {}, {}, {}
    for lease in leases:
        tid = lease["task_id"]
        installed[tid] = True
        if lease["action"] in skip:
            outcomes[tid] = [{"status": "retry_pending", "result": "release_attempt_failed"}]
            absent[tid] = True
            continue
        release = {"status": "released", "result": comp.COMPLETED_RESULT}
        outcomes[tid] = [release]
        completed[tid] = {
            "observed_boottime_ns": lease["due_boottime_ns"] + int(delay_ms * 1e6),
            "observed_monotonic_ns": 0,  # a different clock: must not be used
            "release": release,
        }
        absent[tid] = False
    return completed, outcomes, installed, absent


@pytest.mark.parametrize("monotonic", [True, False])
def test_both_halves_start_identically(monotonic):
    leases = _mono_leases(2) if monotonic else _leases(2)
    start_samples = so04.build_samples(leases, {}, {}, OFFSET0)
    comp_samples = comp.build_samples(leases, {}, {}, {}, {}, {}, OFFSET0)
    for a, b in zip(start_samples, comp_samples):
        assert a["sample_id"] == b["sample_id"]
        assert a["start_monotonic_ns"] == b["start_monotonic_ns"]
        assert a["sample_clock"] == b["sample_clock"]
        assert a["start_event"] == b["start_event"]
    if monotonic:
        assert all(s["start_monotonic_ns"] == s["lease_due_boottime_ns"] for s in comp_samples)


def test_completion_end_is_read_on_the_start_clock():
    leases = _mono_leases(1)
    samples = comp.build_samples(leases, *_mono_observed(leases), {}, OFFSET0, _start_records(leases))
    assert all(s["sample_clock"] == "CLOCK_BOOTTIME" and s["elapsed_ms"] == 500.0 for s in samples)


def _gap_ids(part):
    return [g["id"] for g in part["gaps"]]


def test_wall_clock_gap_closes_only_when_every_sample_recomputes():
    d = {"path": "p", "sha256": "s", "bounds_ms": {a: 6000.0 for a in decl.ROLLBACK_ACTION_TYPES}}
    leases = _mono_leases()
    samples = comp.build_samples(leases, *_mono_observed(leases), d["bounds_ms"], OFFSET0, _start_records(leases))
    assert rec.so04_monotonic_expiry_observed(samples)
    part = comp.build_completion_part(d, samples, [])
    assert "SO04-LEASE-EXPIRY-ON-WALL-CLOCK" not in _gap_ids(part)
    assert "SO04-COMPLETION-BOUND-PROVISIONAL" in _gap_ids(part)
    # One unfinished (throttle) lease keeps it open.
    open_samples = comp.build_samples(leases, *_mono_observed(leases, skip=("throttle",)), d["bounds_ms"], OFFSET0, _start_records(leases))
    assert "SO04-LEASE-EXPIRY-ON-WALL-CLOCK" in _gap_ids(comp.build_completion_part(d, open_samples, []))
    # Legacy (wall-only) leases keep it open too.
    legacy = _full_samples(skip=("throttle",))
    assert "SO04-LEASE-EXPIRY-ON-WALL-CLOCK" in _gap_ids(comp.build_completion_part(d, legacy, []))


def test_validator_refuses_a_dropped_wall_clock_gap_the_samples_do_not_close():
    samples = _full_samples(skip=("throttle",))  # legacy leases
    gaps = [rec.gap(g, "") for g in SPEC["gaps"] if g != "SO04-LEASE-EXPIRY-ON-WALL-CLOCK"]
    errors = rec.validate_record(json.loads(json.dumps(_record(samples, gaps=gaps))))
    assert any("mandatory gap 'SO04-LEASE-EXPIRY-ON-WALL-CLOCK' omitted" in e for e in errors), errors


def test_validator_accepts_a_wall_clock_gap_closed_by_samples():
    leases = _mono_leases()
    d = decl.load_rollback_completion_bounds()
    samples = comp.build_samples(leases, *_mono_observed(leases, skip=("throttle",)), d["bounds_ms"], OFFSET0, _start_records(leases))
    # Throttle unfinished: the gap may not be dropped.
    gaps = [rec.gap(g, "") for g in SPEC["gaps"] if g != "SO04-LEASE-EXPIRY-ON-WALL-CLOCK"]
    errors = rec.validate_record(json.loads(json.dumps(_record(samples, gaps=gaps))))
    assert any("'SO04-LEASE-EXPIRY-ON-WALL-CLOCK' omitted" in e for e in errors), errors


def test_completion_tail_ignores_released_with_another_result(tmp_path):
    lease = _leases(1)[0]
    events, chain = tmp_path / "e.jsonl", tmp_path / "c.jsonl"
    tail = comp._CompletionTail(events, chain, {lease["task_id"]}, lambda: 7)
    line = lambda result: json.dumps({"pipeline": "rust_release_engine_v1", "release": {
        "release_task_id": lease["task_id"], "status": "released", "result": result}}) + "\n"
    events.write_text(line("owned_state_already_absent"), encoding="utf-8")
    tail.poll()
    assert lease["task_id"] not in tail.completed
    assert len(tail.outcomes[lease["task_id"]]) == 1
    with events.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"pipeline": "rust_release_engine_v1", "release": {
            "release_task_id": lease["task_id"], "status": "retry_pending", "result": comp.COMPLETED_RESULT}}) + "\n")
    tail.poll()
    assert lease["task_id"] not in tail.completed
    with events.open("a", encoding="utf-8") as fh:
        fh.write(line(comp.COMPLETED_RESULT))
    tail.poll()
    assert tail.completed[lease["task_id"]]["observed_boottime_ns"] == 7
    assert tail.done()


def test_completion_tail_reads_the_first_start_record(tmp_path):
    lease = _leases(1)[0]
    events, chain = tmp_path / "e.jsonl", tmp_path / "c.jsonl"
    chain.write_text(
        json.dumps({"kind": "rollback_started", "release_task_id": lease["task_id"], "attempt": 1}) + "\n"
        + json.dumps({"kind": "rollback_started", "release_task_id": lease["task_id"], "attempt": 2}) + "\n",
        encoding="utf-8",
    )
    tail = comp._CompletionTail(events, chain, {lease["task_id"]}, lambda: None)
    tail.poll()
    assert tail.starts[lease["task_id"]]["attempt"] == 1


def test_non_root_is_unavailable(monkeypatch):
    monkeypatch.setattr(comp.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(comp, "_run", lambda *a, **k: pytest.fail("ran a tool as non-root"))
    reason = comp.OwnedState().unavailable_reason()
    assert reason and "not running as root" in reason


def test_validator_judges_with_the_file_bounds_not_the_record_bounds(monkeypatch, tmp_path):
    tight = _write(tmp_path, [_entry(a, 1, basis={"method": "m", "sample_count": 1, "max_observed_ms": 0.5, "margin_rule": "r"})
                              for a in decl.ROLLBACK_ACTION_TYPES])
    monkeypatch.setattr(decl, "ROLLBACK_COMPLETION_BOUNDS_PATH", tight)
    loose = {"path": decl.load_rollback_completion_bounds()["path"], "sha256": decl.load_rollback_completion_bounds()["sha256"],
             "bounds_ms": {a: 6000.0 for a in decl.ROLLBACK_ACTION_TYPES}}
    leases = _leases(50)
    samples = comp.build_samples(leases, *_observed(leases), loose["bounds_ms"], OFFSET0)
    record = _record(samples, declaration=loose)
    assert record["parts"][1]["pass_rule"]["evaluated"]["holds"] is True
    errors = rec.validate_record(json.loads(json.dumps(record)))
    # The 1 ms bounds in the file do not hold; the record's 6000 ms are ignored.
    assert any("pass_rule.evaluated: disagrees with the samples" in e for e in errors), errors


def test_per_action_counts_are_required_not_only_the_total():
    samples = [{"action_type": "isolate", "elapsed_ms": 1.0}] * 100 + [{"action_type": "redirect", "elapsed_ms": 1.0}] * 50
    ok = {"holds": True}
    assert rec.derive_verdict(prerequisites=[], gaps=[], required_samples=150, samples=samples, evaluated=ok) == rec.VERDICT_PASS
    assert rec.derive_verdict(
        prerequisites=[], gaps=[], required_samples=150, samples=samples, evaluated=ok, per_action_required=50
    ) == rec.VERDICT_NOT_MEASURABLE
    assert rec.per_action_shortfall(samples, 50) == {"throttle": 0}
    balanced = samples[:50] + samples[100:] + [{"action_type": "throttle", "elapsed_ms": 1.0}] * 50
    assert rec.derive_verdict(
        prerequisites=[], gaps=[], required_samples=150, samples=balanced, evaluated=ok, per_action_required=50
    ) == rec.VERDICT_PASS
    assert SPEC["per_action_samples"] == START_SPEC["per_action_samples"] == so04.LEASES_PER_TYPE == 50


def test_validator_rejects_a_record_that_drops_the_per_action_rule():
    record = _record(_full_samples(skip=("throttle",)))
    del record["parts"][1]["sample_rule"]["per_action_required"]
    errors = rec.validate_record(json.loads(json.dumps(record)))
    assert any("per_action_required" in e for e in errors), errors


class _Res:
    def __init__(self, rc, stderr=""):
        self.returncode, self.stdout, self.stderr = rc, "", stderr


def test_install_touches_nothing_when_the_table_appears_after_the_check(monkeypatch):
    owned = comp.OwnedState()
    owned.tc = owned.nft = owned.ip = "/bin/true"
    calls = []

    def fake_run(argv, stdin=None):
        calls.append(argv)
        if argv[1:3] == ["create", "table"]:
            return _Res(1, "File exists")
        return _Res(0)

    monkeypatch.setattr(comp, "_run", fake_run)
    problems = owned.install(_leases(1))
    assert problems and "create table" in problems[0]
    assert owned.created_table is False and owned.created_ifaces == []
    calls.clear()
    owned.cleanup()
    assert calls == []


def test_install_never_adopts_an_existing_interface_but_tracks_a_timed_out_add(monkeypatch):
    owned = comp.OwnedState()
    owned.tc = owned.nft = owned.ip = "/bin/true"
    leases = [l for l in _leases(2) if l["action"] == "throttle"]
    existing = {leases[0]["iface"]}
    made = set()

    def fake_run(argv, stdin=None):
        if argv[1:3] == ["link", "show"]:
            return _Res(0 if argv[-1] in existing | made else 1)
        if argv[1:3] == ["link", "add"]:
            made.add(argv[3])
            return _Res(comp.TIMEOUT_RC, "timed out")
        return _Res(0)

    monkeypatch.setattr(comp, "_run", fake_run)
    problems = owned.install(leases)
    assert any("already exists" in p for p in problems)
    assert owned.created_ifaces == [leases[1]["iface"]]
    assert owned.created_table is True


def test_install_uses_create_for_table_and_chains(monkeypatch):
    owned = comp.OwnedState()
    owned.tc = owned.nft = owned.ip = "/bin/true"
    seen = []
    monkeypatch.setattr(comp, "_run", lambda argv, stdin=None: (seen.append((argv, stdin)), _Res(0))[1])
    owned.install([l for l in _leases(1) if l["action"] != "throttle"])
    assert seen[0][0][1:3] == ["create", "table"]
    script = seen[1][1]
    assert "add table" not in script and "add chain" not in script
    assert script.count("create chain") == 2


def test_sigterm_during_a_run_cleans_up_and_restores_handlers():
    import signal

    cleaned = []
    before = signal.getsignal(signal.SIGTERM)
    with pytest.raises(SystemExit):
        with comp._CleanupOnSignal(lambda: cleaned.append(1)):
            signal.raise_signal(signal.SIGTERM)
    assert cleaned and signal.getsignal(signal.SIGTERM) is before


def test_run_timeout_is_a_failure_not_an_exception(monkeypatch):
    def boom(*a, **k):
        raise comp.subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(comp.subprocess, "run", boom)
    assert comp._run(["x"]).returncode == comp.TIMEOUT_RC


def test_a_failed_create_table_aborts_before_the_core_starts(monkeypatch, tmp_path):
    owned = comp.OwnedState()
    owned.tc = owned.nft = owned.ip = "/bin/true"
    monkeypatch.setattr(comp, "_run", lambda argv, stdin=None: _Res(1, "File exists") if argv[1:3] == ["create", "table"] else _Res(0))
    monkeypatch.setattr(comp.subprocess, "Popen", lambda *a, **k: pytest.fail("core started"))
    import random

    samples, prereqs = comp._measure_with_owned_state(so04, owned, tmp_path / "core", 2, random.Random(0), 10, {})
    assert samples == []
    met = {p["id"]: p["met"] for p in prereqs}
    assert set(met) == set(SPEC["prerequisites"]) - {"per_action_completion_bound_declared"}
    assert met["core_binary_present"] is True and not any(v for k, v in met.items() if k != "core_binary_present")
