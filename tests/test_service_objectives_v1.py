"""Service-objective harnesses (Edge#414) and their record validator.

The validator is what stops a run from "skipping green", so most tests here try
to get a non-measurement past it and expect it to refuse.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.service_objectives import record as rec  # noqa: E402
from azazel_edge.service_objectives import __main__ as cli  # noqa: E402
from azazel_edge.service_objectives import so03_alert_queue, so04_lease_rollback, so07_audit_ordering  # noqa: E402


@pytest.fixture
def clean_owner(monkeypatch):
    monkeypatch.setattr(
        rec,
        "owner_block",
        lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True},
    )


def _sample(i: int, elapsed_ms: float) -> dict:
    start = 1_000_000_000 + i * 10_000_000
    end = start + int(elapsed_ms * 1e6)
    return {"sample_id": f"s{i}", "start_monotonic_ns": start, "end_monotonic_ns": end, "elapsed_ms": round((end - start) / 1e6, 3)}


def _latency_record(samples, *, required=3, prerequisites=None, gaps=None, bound=2000.0) -> dict:
    part = rec.build_part(
        name="latency",
        pass_rule={"kind": rec.RULE_EVERY_SAMPLE_MAX, "bound_ms": bound},
        required_samples=required,
        samples=samples,
        prerequisites=list(prerequisites or []),
        gaps=list(gaps or []),
    )
    return rec.build_record(
        objective_id="SO-03",
        title="t",
        started_monotonic_ns=0,
        started_at=rec.utc_now(),
        product_configuration={"product": "azazel-edge"},
        clock={"name": "CLOCK_MONOTONIC"},
        sample_rule={"required_samples": required},
        parts=[part],
        method="test",
    )


# ------------------------------------------------------------------ validator


def test_conformant_record_passes_validation(clean_owner):
    record = _latency_record([_sample(i, 10.0) for i in range(3)])
    assert record["verdict"] == rec.VERDICT_PASS
    assert record["evidence_class"] == "gate"
    assert rec.validate_record(record) == []


def test_bound_violation_is_fail_not_pass(clean_owner):
    record = _latency_record([_sample(0, 10.0), _sample(1, 2000.5), _sample(2, 1.0)])
    assert record["verdict"] == rec.VERDICT_FAIL
    assert record["parts"][0]["pass_rule"]["evaluated"]["violations"] == 1
    assert rec.validate_record(record) == []


def test_unfinished_sample_counts_as_violation(clean_owner):
    s = _sample(1, 5.0)
    s["end_monotonic_ns"] = None
    s["elapsed_ms"] = None
    record = _latency_record([_sample(0, 1.0), s, _sample(2, 1.0)])
    assert record["verdict"] == rec.VERDICT_FAIL


def test_sample_shortfall_is_not_measurable(clean_owner):
    record = _latency_record([_sample(0, 1.0)], required=200)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert record["evidence_class"] == "diagnostic_only"
    assert rec.validate_record(record) == []


def test_zero_samples_is_never_pass(clean_owner):
    record = _latency_record([], required=1)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    forged = copy.deepcopy(record)
    forged["verdict"] = forged["parts"][0]["verdict"] = rec.VERDICT_PASS
    forged["evidence_class"] = "gate"
    assert any("verdict" in e for e in rec.validate_record(forged))


def test_unmet_prerequisite_blocks_pass(clean_owner):
    record = _latency_record([_sample(i, 1.0) for i in range(3)], prerequisites=[rec.prerequisite("x", False, "absent")])
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    forged = copy.deepcopy(record)
    forged["verdict"] = forged["parts"][0]["verdict"] = rec.VERDICT_PASS
    forged["evidence_class"] = "gate"
    errors = rec.validate_record(forged)
    assert any("record supports 'not_measurable'" in e for e in errors)


def test_blocking_gap_blocks_pass_and_nonblocking_does_not(clean_owner):
    blocked = _latency_record([_sample(i, 1.0) for i in range(3)], gaps=[rec.gap("G", "missing record")])
    assert blocked["verdict"] == rec.VERDICT_NOT_MEASURABLE
    informational = _latency_record([_sample(i, 1.0) for i in range(3)], gaps=[rec.gap("G", "note", blocks_verdict=False)])
    assert informational["verdict"] == rec.VERDICT_PASS


def test_forged_pass_over_violating_samples_is_rejected(clean_owner):
    record = _latency_record([_sample(0, 1.0), _sample(1, 9999.0), _sample(2, 1.0)])
    forged = copy.deepcopy(record)
    forged["parts"][0]["pass_rule"]["evaluated"]["holds"] = True
    forged["verdict"] = forged["parts"][0]["verdict"] = rec.VERDICT_PASS
    forged["evidence_class"] = "gate"
    errors = rec.validate_record(forged)
    assert any("disagrees with the samples" in e for e in errors)
    assert any("record supports 'fail'" in e for e in errors)


def test_not_measurable_without_a_reason_is_rejected(clean_owner):
    record = _latency_record([_sample(i, 1.0) for i in range(3)])
    forged = copy.deepcopy(record)
    forged["verdict"] = forged["parts"][0]["verdict"] = rec.VERDICT_NOT_MEASURABLE
    forged["evidence_class"] = "diagnostic_only"
    assert any("not_measurable without" in e for e in rec.validate_record(forged))


def test_top_verdict_must_be_worst_part(clean_owner):
    record = _latency_record([_sample(i, 1.0) for i in range(3)])
    extra = rec.build_part(
        name="completion",
        pass_rule={"kind": rec.RULE_EVERY_SAMPLE_MAX, "bound_ms": 0.0},
        required_samples=1,
        samples=[],
        prerequisites=[rec.prerequisite("bound_declared", False, "OF-05")],
        gaps=[],
    )
    record["parts"].append(extra)
    assert any("parts support 'not_measurable'" in e for e in rec.validate_record(record))


def test_pass_on_modified_tree_is_downgraded(monkeypatch):
    monkeypatch.setattr(rec, "owner_block", lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "b" * 40, "worktree_clean": False})
    record = _latency_record([_sample(i, 1.0) for i in range(3)])
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert rec.validate_record(record) == []
    forged = copy.deepcopy(record)
    forged["parts"][0]["prerequisites"] = []
    forged["verdict"] = forged["parts"][0]["verdict"] = rec.VERDICT_PASS
    forged["evidence_class"] = "gate"
    assert any("unmodified tree" in e for e in rec.validate_record(forged))


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda r: r.pop("verdict"), "verdict"),
        (lambda r: r.update(objective_id="SO-99"), "objective_id"),
        (lambda r: r.update(schema="other"), "schema"),
        (lambda r: r["owner"].update(repository="someone/else"), "owner.repository"),
        (lambda r: r["parts"][0]["samples"][0].update(end_monotonic_ns=1), "end precedes start"),
        (lambda r: r["parts"][0]["samples"][0].update(elapsed_ms=123.0), "elapsed_ms disagrees"),
        (lambda r: r["parts"][0]["samples"][0].update(start_monotonic_ns=1.5), "integer"),
        (lambda r: r.update(parts=[]), "at least one part"),
        (lambda r: r["parts"][0]["pass_rule"].update(kind="vibes"), "kind"),
    ],
)
def test_malformed_records_are_rejected(clean_owner, mutate, needle):
    record = _latency_record([_sample(i, 1.0) for i in range(3)])
    mutate(record)
    errors = rec.validate_record(record)
    assert errors and any(needle in e for e in errors), errors


def test_zero_violation_rule_counts_malformed_samples(clean_owner):
    good = {"sample_id": "a", "start_monotonic_ns": 1, "end_monotonic_ns": 2, "violations": 0}
    bad = {"sample_id": "b", "start_monotonic_ns": 1, "end_monotonic_ns": 2, "violations": -1}
    ev = rec.evaluate_zero_violations([good, bad])
    assert ev["holds"] is False and ev["violations"] == 1


def test_exit_codes_reserve_zero_for_pass():
    assert rec.exit_code_for(rec.VERDICT_PASS) == 0
    assert rec.exit_code_for(rec.VERDICT_FAIL) != 0
    assert rec.exit_code_for(rec.VERDICT_NOT_MEASURABLE) != 0
    assert rec.exit_code_for("skipped") != 0


# ------------------------------------------------------------------- SO-03


def test_so03_measures_real_path_and_reports_gaps():
    record = so03_alert_queue.run(samples=20, seed=7)
    assert rec.validate_record(record) == []
    assert record["objective_id"] == "SO-03"
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    part = record["parts"][0]
    assert part["pass_rule"]["bound_ms"] == 2000.0
    assert part["sample_rule"]["required_samples"] == 200
    prereq = {p["id"]: p for p in part["prerequisites"]}
    # Probed on every run, not assumed: the enqueue record does not name the decision.
    assert prereq["enqueue_record_names_decision_id"]["met"] is False
    assert prereq["visual_voice_delivery_queue_declared"]["met"] is False
    assert prereq["synthetic_decisions_are_p0_stand_ins"]["met"] is True
    assert {g["id"] for g in part["gaps"]} >= {"SO03-NO-VISUAL-VOICE-QUEUE", "SO03-ENQUEUE-RECORD-LACKS-DECISION-ID"}
    for s in part["samples"]:
        assert s["action"] == "notify" and s["level"] == "critical"
        assert s["end_monotonic_ns"] >= s["start_monotonic_ns"]
        assert s["enqueue_record_names_decision"] is False


def test_so03_full_sample_count_is_still_not_a_pass():
    record = so03_alert_queue.run(seed=1)
    assert len(record["parts"][0]["samples"]) == 200
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert rec.validate_record(record) == []


# ------------------------------------------------------------------- SO-04


def test_so04_missing_core_binary_is_not_measurable(tmp_path):
    record = so04_lease_rollback.run(core_bin=tmp_path / "absent-core")
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    start, completion = record["parts"]
    assert start["samples"] == []
    assert {p["id"]: p["met"] for p in start["prerequisites"]}["core_binary_present"] is False
    assert completion["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert [g["id"] for g in completion["gaps"]] == ["OF-05"]


def test_so04_completion_half_can_never_pass():
    record = so04_lease_rollback.run(core_bin=Path("/nonexistent"))
    completion = record["parts"][1]
    assert completion["name"] == "rollback_completion"
    assert completion["samples"] == []
    assert completion["verdict"] != rec.VERDICT_PASS
    assert record["verdict"] != rec.VERDICT_PASS


def test_so04_lease_matches_rust_release_task_shape():
    assert so04_lease_rollback._fnv1a64(b"") == 0xCBF29CE484222325
    assert so04_lease_rollback._fnv1a64(b"a") == 0xAF63DC4C8601EC8C
    for action in so04_lease_rollback.ACTION_TYPES:
        lease = so04_lease_rollback.make_lease(action, 3, 100.0, 105.0)
        assert lease["task_id"].startswith("release-") and len(lease["task_id"]) == 24
        assert lease["owner_token"] == "azazel-edge:" + lease["task_id"]
        assert lease["status"] == "active"
        assert lease["due_epoch"] >= lease["created_epoch"]
        if action == "throttle":
            assert lease["tc_handle"].endswith(":") and lease["expected_rate_bps"] > 0
        else:
            assert lease["tc_handle"] == ""


def test_so04_harness_never_enables_enforcement():
    source = Path(so04_lease_rollback.__file__).read_text(encoding="utf-8")
    assert '"AZAZEL_DEFENSE_ENFORCE":' not in source
    assert "env.pop(key, None)" in source


# ------------------------------------------------------------------- SO-07


def test_so07_kills_real_writer_and_finds_no_lost_report():
    record = so07_audit_ordering.run(seed=3, kinds=["action_decision"])
    assert rec.validate_record(record) == []
    part = record["parts"][0]
    assert len(part["samples"]) == len(so07_audit_ordering.INJECTION_POINTS) * len(so07_audit_ordering.RECORD_PADS)
    for s in part["samples"]:
        assert s["problems"] == [], s
        assert s["violations"] == 0
        assert s["reported_complete_record_absent"] == []
    after_report = [s for s in part["samples"] if s["injection_point"] == "after_report"]
    assert all(s["reported_complete"] >= 1 for s in after_report)
    # One kind out of eleven is a coverage shortfall, so this is not a pass.
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    unmet = [p["id"] for p in part["prerequisites"] if not p["met"]]
    assert unmet == ["every_record_kind_at_every_injection_point"]


def test_so07_record_absent_after_report_is_counted():
    absent = {"sample_id": "k/p", "start_monotonic_ns": 1, "end_monotonic_ns": 2, "violations": 1}
    assert rec.evaluate_zero_violations([absent])["holds"] is False


# ------------------------------------------------------------------- CLI


def test_cli_run_writes_record_and_exits_nonzero_when_not_measurable(tmp_path, capsys):
    code = cli.main(["run", "--objective", "SO-04", "--core-bin", str(tmp_path / "none"), "--out-dir", str(tmp_path / "out")])
    assert code == rec.EXIT_NOT_MEASURABLE
    files = list((tmp_path / "out").glob("SO-04-*.json"))
    assert len(files) == 1
    assert rec.load_and_validate(files[0]) == []
    assert cli.main(["validate", str(tmp_path / "out")]) == rec.EXIT_NOT_MEASURABLE


def test_cli_validate_with_no_records_is_not_a_pass(tmp_path):
    assert cli.main(["validate", str(tmp_path)]) == rec.EXIT_INVALID


def test_cli_harness_crash_leaves_a_not_measurable_record(tmp_path, monkeypatch):
    def boom(args):
        def raise_():
            raise RuntimeError("harness exploded")

        return {"SO-03": raise_}

    monkeypatch.setattr(cli, "_harnesses", boom)
    code = cli.main(["run", "--objective", "SO-03", "--out-dir", str(tmp_path)])
    assert code == rec.EXIT_NOT_MEASURABLE
    record = json.loads(next(tmp_path.glob("SO-03-*.json")).read_text(encoding="utf-8"))
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert "harness exploded" in record["parts"][0]["prerequisites"][0]["detail"]


def test_cli_rejects_a_tampered_record(tmp_path, clean_owner):
    record = _latency_record([_sample(i, 1.0) for i in range(3)], required=200)
    record["verdict"] = record["parts"][0]["verdict"] = rec.VERDICT_PASS
    record["evidence_class"] = "gate"
    path = tmp_path / "SO-03-x.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    assert cli.main(["validate", str(path)]) == rec.EXIT_INVALID
