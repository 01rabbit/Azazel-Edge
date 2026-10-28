"""SO-11: the SO-03, SO-04 start and SO-07 pass rules at 100% and 120% of the
declared ingress quota (Edge#414), and its record specification.

Most tests build an SO-11 record by hand and try to get something past the
validator that the harness never measured: a looser row, a missing gap, a
quota load that was not offered or did not shed, a boot id in a sample. The
real-core tests (skipped without a built core) run each referenced row for a
few samples under the load.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.service_objectives import __main__ as cli  # noqa: E402
from azazel_edge.service_objectives import record as rec  # noqa: E402
from azazel_edge.service_objectives import so04_lease_rollback as so04  # noqa: E402
from azazel_edge.service_objectives import so11_quota_load as so11  # noqa: E402
from azazel_edge.service_objectives.declarations import load_ingress_quotas  # noqa: E402

SPECS = rec.OBJECTIVE_SPECS["SO-11"]
QUOTA = load_ingress_quotas()["quotas"]["core_eve_reader"]
BOOT = "0f0e0d0c-0b0a-4908-8706-050403020100"
WIN0 = 10 * 10**9  # load window start, on both clocks in these tests
WARM = so11.WARMUP_MS * 10**6


@pytest.fixture
def clean_owner(monkeypatch):
    monkeypatch.setattr(rec, "owner_block", lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True})


# ----------------------------------------------------------- hand-made parts


def _quota_block():
    return {k: QUOTA[q] for k, q in {
        "non_alert_per_sec": "value", "non_alert_burst": "non_alert_burst", "alerts_per_poll": "alerts_per_poll",
        "examine_per_poll": "examine_per_poll", "poll_work_limit_ms": "poll_work_limit_ms", "max_line_bytes": "max_line_bytes",
        "backlog_bound_bytes": "backlog_bound_bytes", "alert_backlog_bound_bytes": "alert_backlog_bound_bytes",
    }.items()}


def _summary(shed: int, cumulative: int, *, alerts_shed: int = 0):
    return {"ingress_shed": {
        "emitted_epoch": 1.0, "shed_total": shed, "admitted": 2500, "alerts_admitted": 0, "examined": 2500 + shed,
        "oversized_lines_skipped": 0, "oversized_possible_alerts": 0, "cumulative_shed_total": cumulative,
        "cumulative_oversized_lines_skipped": 0, "alerts_shed": alerts_shed,
        "shed_by_type": {"flow": shed}, "shed_by_reason": {"non_alert_rate": shed, "backlog": 0},
        "quota": _quota_block(), "interval_end": "audit_interval",
    }}


def _obs(factor: float, *, seconds: float = 60.0):
    decl = load_ingress_quotas()
    share = QUOTA["value"] * factor / len(so11.NON_ALERT_KINDS)
    end = WIN0 + int(seconds * 1e9)
    audit = [_summary(500, 500), _summary(500, 1000)] if factor > 1 else []
    return {
        "ingress": "core_eve_reader", "quota_path": decl["path"], "quota_sha256": decl["sha256"],
        "quota_value": QUOTA["value"], "quota_status": QUOTA["status"], "quota_hardware_class": QUOTA["hardware_class"],
        "load_factor": factor, "offered_non_alert_lines_per_s": QUOTA["value"] * factor,
        "non_alert_kinds": list(so11.NON_ALERT_KINDS), "line_bytes": so11.LINE_BYTES, "warmup_ms": so11.WARMUP_MS,
        "window_start_monotonic_ns": WIN0, "window_end_monotonic_ns": end,
        "window_start_boottime_ns": WIN0, "window_end_boottime_ns": end,
        "written": {k: int(share * seconds) for k in so11.NON_ALERT_KINDS}, "written_bytes": 1,
        "writer_error": None, "ingress_audit": audit, "ingress_audit_rotated": False,
    }


def _so07_samples():
    from azazel_edge.audit.logger import VALID_KINDS

    out = []
    t = WIN0 + WARM + 10**9
    for kind in sorted(VALID_KINDS):
        for point in rec.SO07_INJECTION_POINTS:
            for pad in rec.SO07_RECORD_PADS:
                out.append({
                    "sample_id": f"{kind}/{point}/pad{pad}", "record_kind": kind, "injection_point": point,
                    "record_pad_bytes": pad, "pause_at_seq": None, "start_monotonic_ns": t, "end_monotonic_ns": t + 10**7,
                    "elapsed_ms": 10.0, "start_event": "kill", "end_event": "restart", "reported_complete": 3,
                    "reported_complete_record_absent": [], "unreported_record_present": 0, "problems": [],
                    "chain_after_restart": {"ok": True}, "violations": 0,
                })
                t += 2 * 10**7
    return out


def _so04_samples():
    out = []
    for i in range(150):
        action = so04.ACTION_TYPES[i % 3]
        due_boot = WIN0 + WARM + 10**9 + i * 10**8
        due_epoch = 1_700_000_000.0 + i * 0.1
        lease = so04.make_lease(action, i, 1_700_000_000.0 - 5, due_epoch, due_boottime_ns=due_boot, due_boot_id=BOOT)
        edge = due_boot + 2 * 10**8
        row = {
            "kind": so04.ROLLBACK_STARTED_KIND, "record_schema": so04.ROLLBACK_STARTED_SCHEMA,
            "release_task_id": lease["task_id"], "trace_id": lease["trace_id"], "attempt": 1,
            "lease_due_epoch_ns": round(due_epoch * 1e9), "lease_due_boottime_ns": due_boot, "lease_boot_id": BOOT,
            "expiry_clock": "monotonic", "started_monotonic_ns": edge, "started_boottime_ns": edge,
            "started_wall_epoch_ns": round(due_epoch * 1e9) + 2 * 10**8, "boot_id": BOOT,
        }
        starts = {lease["task_id"]: {"observed_monotonic_ns": edge + 10**6, "observed_boottime_ns": edge + 10**6, "chain_line": i, "row": row}}
        outcomes = {lease["task_id"]: {"observed_monotonic_ns": edge + 5 * 10**6, "release": {"attempted_at_epoch": due_epoch + 0.2, "status": "retry_pending", "result": "x"}, "start_record_seen": True}}
        out += [so11.strip_boot_ids(s) for s in so04.build_samples([lease], starts, outcomes, 0)]
    return out


def _so03_samples():
    # Hand-made SO-03 samples cannot show the P0 queue record the validator
    # recomputes the end from, so they are unfinished (end None).
    t = WIN0 + WARM + 10**9
    return [
        {"sample_id": f"d-{i}", "start_monotonic_ns": t + i * 10**7, "end_monotonic_ns": None,
         "elapsed_ms": None, "start_event": "append", "end_event": "enqueue"}
        for i in range(200)
    ]


def _taken(name):
    spec = SPECS[name]
    obj = spec["references"][0]
    samples = {"SO-03": _so03_samples, "SO-04": _so04_samples, "SO-07": _so07_samples}[obj]()
    if obj == "SO-07":
        observed = rec._so07_observed_prerequisites(samples)
    elif obj == "SO-04":
        observed = rec._so04_observed_prerequisites(samples)
    else:
        observed = rec.so03_observed_prerequisites(samples)
    prereqs = [rec.prerequisite(p, observed.get(p, True), "test") for p in spec["prerequisites"]]
    return {"core_version": "test", "samples": samples, "prerequisites": prereqs, "quota_load": _obs(spec["load_factor"])}


def _record(takes=None):
    takes = takes or {}
    parts = [so11.build_so11_part(name, takes.get(name) or _taken(name)) for name in SPECS]
    return rec.build_record(
        objective_id="SO-11", title="t", started_monotonic_ns=0, started_at=rec.utc_now(),
        product_configuration={"product": "azazel-edge", "row_class": "virtual-lab", "hardware_evidence": False},
        clock={"name": "CLOCK_MONOTONIC"}, sample_rule={}, parts=parts, method="test",
    )


def _part(record, name):
    return next(p for p in record["parts"] if p["name"] == name)


def _forge_pass(record):
    for part in record["parts"]:
        part["gaps"] = []
        for p in part["prerequisites"]:
            p["met"] = True
        part["verdict"] = rec.VERDICT_PASS
    record["verdict"] = rec.VERDICT_PASS
    record["evidence_class"] = "gate"
    return record


# ------------------------------------------------------------ the table


def test_each_part_copies_its_referenced_row_and_cannot_be_looser():
    assert sorted(SPECS) == sorted(f"{k}_{lvl}" for k, _, _ in rec.SO11_REFERENCED_ROWS for lvl, _ in rec.SO11_LEVELS)
    assert [f for _, f in rec.SO11_LEVELS] == [1.0, 1.2]
    for name, spec in SPECS.items():
        ref = rec.OBJECTIVE_SPECS[spec["references"][0]][spec["references"][1]]
        for key in ("kind", "bound_ms", "required_samples"):
            assert spec[key] == ref[key], (name, key)
        assert spec.get("per_action_samples", 0) == ref.get("per_action_samples", 0)
        assert spec["row_class"] == "virtual-lab"
        assert "SO11-QUOTA-PROVISIONAL" in spec["gaps"]
        assert "SO11-QUOTA-PROVISIONAL" not in spec["gaps_closed_by_samples"]
        assert set(rec.SO11_LOAD_PREREQUISITES) <= set(spec["prerequisites"])
        assert (rec.SO11_OVERLOAD_PREREQUISITE in spec["prerequisites"]) == (spec["load_factor"] > 1.0)
        dropped = set(ref["prerequisites"]) - set(spec["prerequisites"])
        assert dropped <= {"load_phase_applied"}
    assert "SO11-SO04-COMPLETION-NOT-RERUN" in SPECS["so04_start_at_quota"]["gaps"]
    assert rec.CI_DECLARED_PREREQUISITES["SO-11"] == frozenset()
    # Nothing closes the provisional quota gap.
    assert "SO11-QUOTA-PROVISIONAL" not in rec.GAP_CLOSERS and "SO11-QUOTA-PROVISIONAL" not in rec.PART_GAP_CLOSERS


def test_the_harness_offers_the_declared_quota_and_sheds_only_over_it():
    assert so11.NON_ALERT_KINDS == ("flow", "dns", "stats", "http")
    # The warm-up empties the bucket at 120%: burst / (1.2 - 1.0) x quota.
    assert so11.WARMUP_MS / 1000.0 >= QUOTA["non_alert_burst"] / (0.2 * QUOTA["value"])
    assert so11.RATE_TOLERANCE <= 0.1


# ---------------------------------------------------- the quota recomputation


def test_a_load_offered_as_declared_holds_every_load_prerequisite():
    for factor in (1.0, 1.2):
        problems = so11.quota_load_problems(_so03_samples(), _obs(factor), factor)
        assert all(not v for v in problems.values()), problems
    assert rec.SO11_OVERLOAD_PREREQUISITE in so11.quota_load_problems([], _obs(1.2), 1.2)
    assert rec.SO11_OVERLOAD_PREREQUISITE not in so11.quota_load_problems([], _obs(1.0), 1.0)


@pytest.mark.parametrize(
    "factor, mutate, prereq",
    [
        (1.2, lambda o: o.update(quota_sha256="0" * 64), "ingress_load_offered_at_level"),
        (1.2, lambda o: o.update(load_factor=1.0), "ingress_load_offered_at_level"),
        (1.0, lambda o: o["written"].update(flow=int(o["written"]["flow"] * 0.8)), "ingress_load_offered_at_level"),
        (1.2, lambda o: o.update(window_end_monotonic_ns=WIN0 + WARM - 1), "ingress_load_offered_at_level"),
        (1.2, lambda o: o.update(window_start_monotonic_ns=WIN0 + 2 * WARM), "ingress_load_offered_at_level"),
        (1.0, lambda o: o.update(writer_error="OSError"), "ingress_load_offered_at_level"),
        (1.2, lambda o: o["ingress_audit"][0]["ingress_shed"].update(alerts_shed=1), "alerts_never_shed"),
        (1.2, lambda o: o["ingress_audit"][0]["ingress_shed"]["shed_by_type"].update(alert=1), "alerts_never_shed"),
        (1.2, lambda o: o["ingress_audit"][0]["ingress_shed"]["quota"].update(non_alert_per_sec=999999), "core_ingress_audit_consistent"),
        (1.2, lambda o: o["ingress_audit"][1]["ingress_shed"].update(cumulative_shed_total=1), "core_ingress_audit_consistent"),
        (1.2, lambda o: o.update(ingress_audit_rotated=True), "core_ingress_audit_consistent"),
        (1.2, lambda o: o.update(ingress_audit=[]), rec.SO11_OVERLOAD_PREREQUISITE),
        (1.2, lambda o: [r["ingress_shed"]["shed_by_reason"].update(non_alert_rate=0) for r in o["ingress_audit"]], rec.SO11_OVERLOAD_PREREQUISITE),
    ],
)
def test_a_load_not_shown_fails_its_prerequisite(factor, mutate, prereq):
    obs = _obs(factor)
    mutate(obs)
    assert so11.quota_load_problems(_so03_samples(), obs, factor)[prereq]


def test_a_sample_outside_the_load_window_fails_the_offered_prerequisite():
    early = _so03_samples()
    early[0]["start_monotonic_ns"] = WIN0 + WARM - 1  # during the warm-up
    late = _so03_samples()
    late[-1]["end_monotonic_ns"] = WIN0 + 61 * 10**9  # after the load stopped
    for samples in (early, late, []):
        assert so11.quota_load_problems(samples, _obs(1.0), 1.0)["ingress_load_offered_at_level"]
    # SO-04 samples are checked on CLOCK_BOOTTIME.
    obs = _obs(1.0)
    obs["window_start_boottime_ns"] = None
    assert so11.quota_load_problems(_so04_samples(), obs, 1.0)["ingress_load_offered_at_level"]
    assert not so11.quota_load_problems(_so04_samples(), _obs(1.0), 1.0)["ingress_load_offered_at_level"]


def test_no_observation_or_no_quota_holds_nothing(monkeypatch):
    assert all(so11.quota_load_problems(_so03_samples(), None, 1.2).values())
    monkeypatch.setattr(so11, "load_ingress_quotas", lambda: {"quotas": {}, "problems": ["x"], "path": "p", "sha256": None})
    assert all(so11.quota_load_problems(_so03_samples(), _obs(1.2), 1.2).values())


# --------------------------------------------------------------- the record


def test_a_full_hand_made_record_is_valid_and_never_more_than_not_measurable(clean_owner):
    record = _record()
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert record["evidence_class"] == "diagnostic_only"
    for part in record["parts"]:
        assert "SO11-QUOTA-PROVISIONAL" in {g["id"] for g in part["gaps"]}
        assert part["verdict"] == rec.VERDICT_NOT_MEASURABLE
    # The SO-04 and SO-07 parts are blocked by the quota alone; their load and
    # row prerequisites all hold, and the monotonic-expiry gap is closed
    # without any boot id in the record.
    for name in ("so04_start_at_quota", "so04_start_at_120pct_of_quota", "so07_at_quota", "so07_at_120pct_of_quota"):
        part = _part(record, name)
        assert all(p["met"] for p in part["prerequisites"]), part["prerequisites"]
        assert part["pass_rule"]["evaluated"]["holds"] is True
    assert {g["id"] for g in _part(record, "so04_start_at_quota")["gaps"]} == {"SO11-QUOTA-PROVISIONAL", "SO11-SO04-COMPLETION-NOT-RERUN"}
    assert "boot_id" not in json.dumps(record)


def test_omitting_the_provisional_quota_gap_is_refused_and_cannot_pass(clean_owner):
    record = _record()
    for part in record["parts"]:
        part["gaps"] = [g for g in part["gaps"] if g["id"] != "SO11-QUOTA-PROVISIONAL"]
    errors = rec.validate_record(record)
    assert sum("mandatory gap 'SO11-QUOTA-PROVISIONAL' omitted" in e for e in errors) == 6, errors
    forged = _forge_pass(_record())
    errors = rec.validate_record(forged)
    assert any("record supports 'not_measurable'" in e for e in errors), errors


def test_a_looser_bound_or_fewer_samples_is_refused(clean_owner):
    record = _record()
    part = _part(record, "so03_at_120pct_of_quota")
    part["pass_rule"]["bound_ms"] = 1e9
    part["sample_rule"]["required_samples"] = 1
    errors = rec.validate_record(record)
    assert any("bound_ms: SO-11 requires 2000.0" in e for e in errors), errors
    assert any("required_samples: SO-11 requires 200" in e for e in errors), errors


def test_a_load_prerequisite_declared_met_but_not_shown_is_refused(clean_owner):
    takes = {"so07_at_120pct_of_quota": _taken("so07_at_120pct_of_quota")}
    takes["so07_at_120pct_of_quota"]["quota_load"]["ingress_audit"] = []
    record = _record(takes)
    part = _part(record, "so07_at_120pct_of_quota")
    assert not next(p for p in part["prerequisites"] if p["id"] == rec.SO11_OVERLOAD_PREREQUISITE)["met"]
    assert rec.validate_record(record) == []
    for p in part["prerequisites"]:
        p["met"] = True
    errors = rec.validate_record(record)
    assert any("'quota_shed_at_overload' declared met but the quota_load observation does not show it" in e for e in errors), errors


def test_a_part_without_its_quota_load_holds_no_load_prerequisite(clean_owner):
    record = _record()
    part = _part(record, "so07_at_quota")
    del part["quota_load"]
    errors = rec.validate_record(record)
    assert any("'ingress_load_offered_at_level' declared met" in e for e in errors), errors


def test_quota_load_is_only_for_so11_and_boot_ids_are_not_sample_fields(clean_owner):
    record = _record()
    sample = _part(record, "so04_start_at_quota")["samples"][0]
    sample["lease_boot_id"] = BOOT
    errors = rec.validate_record(record)
    assert any("unknown field(s) ['lease_boot_id']" in e for e in errors), errors
    other = rec.build_record(
        objective_id="SO-07", title="t", started_monotonic_ns=0, started_at=rec.utc_now(),
        product_configuration={}, clock={"name": "CLOCK_MONOTONIC"}, sample_rule={},
        parts=[rec.build_part(name="reported_complete_implies_record_present", pass_rule={"kind": rec.RULE_ZERO_VIOLATIONS},
                              required_samples=110, samples=_so07_samples(), prerequisites=[], gaps=[], quota_load=_obs(1.0))],
        method="test",
    )
    assert any("quota_load: only an object, and only on ['SO-11'] parts" in e for e in rec.validate_record(other))


def test_the_monotonic_expiry_gap_needs_the_same_boot_in_every_sample(clean_owner):
    takes = {"so04_start_at_quota": _taken("so04_start_at_quota")}
    takes["so04_start_at_quota"]["samples"][5]["same_boot_as_lease"] = False
    record = _record(takes)
    gaps = {g["id"] for g in _part(record, "so04_start_at_quota")["gaps"]}
    assert "SO04-LEASE-EXPIRY-ON-WALL-CLOCK" in gaps
    assert rec.validate_record(record) == []
    _part(record, "so04_start_at_quota")["gaps"] = [g for g in _part(record, "so04_start_at_quota")["gaps"] if g["id"] != "SO04-LEASE-EXPIRY-ON-WALL-CLOCK"]
    assert any("mandatory gap 'SO04-LEASE-EXPIRY-ON-WALL-CLOCK' omitted" in e for e in rec.validate_record(record))
    # The SO-04 record's own closer is unchanged: without boot ids it never closes.
    assert not rec.so04_monotonic_expiry_observed(_so04_samples())


def test_strip_boot_ids_keeps_only_whether_the_boot_matched():
    row = {"sample_id": "x", "lease_boot_id": BOOT, "start_record_boot_id": BOOT}
    assert so11.strip_boot_ids(row) == {"sample_id": "x", "same_boot_as_lease": True}
    assert so11.strip_boot_ids(dict(row, start_record_boot_id="other"))["same_boot_as_lease"] is False
    assert so11.strip_boot_ids({"sample_id": "x", "lease_boot_id": "", "start_record_boot_id": ""})["same_boot_as_lease"] is False


def test_ci_exit_for_a_clean_gap_blocked_record_and_for_a_load_not_shown(clean_owner):
    record = _record()
    # The hand-made SO-03 samples are unfinished and do not show the P0 path:
    # red, never green.
    assert rec.ci_exit_code_for(record, rec.validate_record(record)) == rec.EXIT_NOT_EXECUTED
    record["parts"] = [p for p in record["parts"] if not p["name"].startswith("so03")]
    assert any("must evaluate exactly" in e for e in rec.validate_record(record))


def test_without_a_core_every_part_is_not_executed_and_the_record_is_valid(tmp_path, clean_owner):
    record = so11.run(core_bin=tmp_path / "no-core")
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert len(record["parts"]) == 6
    assert len(rec.not_executed_reasons(record)) == 6
    assert rec.ci_exit_code_for(record, []) == rec.EXIT_NOT_EXECUTED
    assert record["run"]["host"] == "not recorded"
    assert record["product_configuration"]["hardware_evidence"] is False


def test_cli_knows_so11(tmp_path, monkeypatch, clean_owner):
    assert "SO-11" in cli.parse_objectives("SO-11")
    monkeypatch.setattr(so11, "run", lambda **kw: _record())
    out = tmp_path / "recs"
    assert cli.main(["run", "--objective", "SO-11", "--out-dir", str(out)]) == rec.EXIT_NOT_MEASURABLE
    assert cli.main(["validate", "--ci", "--objective", "SO-11", str(out)]) == rec.EXIT_NOT_EXECUTED


def test_ci_runs_so11_only_on_main_or_by_hand_and_refuses_skips():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = ci.split("\n  service-objectives-so11:\n", 1)[1].split("\n  dependency-review:\n", 1)[0]
    assert "github.ref == 'refs/heads/main'" in job and "workflow_dispatch" in job
    assert "run --ci" in job and "--objective SO-11" in job
    assert "validate --ci --objective SO-11" in " ".join(job.split()) and "--expect-commit" in job
    assert "cargo build --release" in job and "if-no-files-found: error" in job
    assert "sudo" not in job


# ------------------------------------------------------------- the real core


def test_real_core_so04_start_under_120pct_sheds_and_measures(rust_core_bin):
    taken = so11._so04_start(rust_core_bin, 1.2, QUOTA, seed=5, leases_per_type=2)
    samples = taken["samples"]
    assert len(samples) == 6 and all(isinstance(s.get("elapsed_ms"), float) for s in samples)
    assert all("lease_boot_id" not in s and "start_record_boot_id" not in s for s in samples)
    problems = so11.quota_load_problems(samples, taken["quota_load"], 1.2)
    assert not any(problems.values()), problems
    # wall_clock_stable_during_run reports the host's wall clock (a VM may be
    # adjusted mid-run); it is the harness's finding, not this test's.
    assert all(p["met"] for p in taken["prerequisites"] if p["id"] != "wall_clock_stable_during_run"), taken["prerequisites"]


def test_real_core_so07_under_the_quota_load(rust_core_bin):
    taken = so11._so07(rust_core_bin, 1.0, QUOTA, seed=5, kinds=["action_decision"])
    assert taken["core_started"]
    assert len(taken["samples"]) == len(rec.SO07_INJECTION_POINTS) * len(rec.SO07_RECORD_PADS)
    assert all(s["violations"] == 0 for s in taken["samples"])
    problems = so11.quota_load_problems(taken["samples"], taken["quota_load"], 1.0)
    assert not any(problems.values()), problems


def test_real_core_so03_under_120pct(rust_core_bin):
    taken = so11._so03(rust_core_bin, 1.2, QUOTA, seed=5, samples=6)
    samples = taken["samples"]
    assert len(samples) == 6
    assert all(rec.so03_end_observed(s) for s in samples)
    problems = so11.quota_load_problems(samples, taken["quota_load"], 1.2)
    assert not any(problems.values()), problems
