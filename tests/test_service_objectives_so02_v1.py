"""SO-02 (Edge#414): source/interface failure visible on the operator surface.

The lab itself needs root and network namespaces, so it runs in the
service-objective job, not here. These tests pin the table, the refusals, the
measurement loop (against a fake lab), and above all the validator: an end the
sample's own fields do not show is never counted, and a virtual-lab record can
never claim to be hardware evidence.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.service_objectives import __main__ as cli  # noqa: E402
from azazel_edge.service_objectives import record as rec  # noqa: E402
from azazel_edge.service_objectives import so02_source_failure as so02  # noqa: E402

PROC = rec.SO02_CAPTURE_PROCESS
IFACE = rec.SO02_CAPTURE_INTERFACE
SPEC = rec.OBJECTIVE_SPECS["SO-02"]["source_failure_visible"]


@pytest.fixture
def clean_owner(monkeypatch):
    monkeypatch.setattr(
        rec,
        "owner_block",
        lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True},
    )


@pytest.fixture
def no_gap_table(monkeypatch):
    """The SO-02 row with its gaps closed and only the recomputed prerequisites,
    so the pass/fail mechanics can be exercised. Never the real table."""

    row = dict(SPEC, gaps=(), prerequisites=("every_injection_from_healthy_baseline", "every_lab_source_type_sampled"))
    monkeypatch.setitem(rec.OBJECTIVE_SPECS, "SO-02", {"source_failure_visible": row})


def _sample(i: int, source_type: str, elapsed_ms: float) -> dict:
    entry = rec.SO02_SURFACE[source_type]
    start = 10_000_000_000 + i * 1_000_000_000
    end = start + int(elapsed_ms * 1e6)
    return {
        "sample_id": f"so02-{source_type}-{i:02d}",
        "start_monotonic_ns": start,
        "end_monotonic_ns": end,
        "elapsed_ms": round((end - start) / 1e6, 3),
        "start_event": "injection",
        "end_event": "surface names source failed",
        "source_type": source_type,
        "source_id": entry["source_id"],
        "injection": "x",
        "surface": "GET /api/state",
        "surface_field": entry["field"],
        "baseline_healthy": True,
        "baseline_poll_started_monotonic_ns": start - 50_000_000,
        "baseline_surface_value": "ON" if source_type == PROC else ["usb0"],
        "end_poll_started_monotonic_ns": start + max(1, int(elapsed_ms * 1e6) // 2),
        "end_surface_value": "OFF" if source_type == PROC else ["br0", "usb0"],
        "polls_after_injection": 3,
        "poll_errors_after_injection": 0,
        "recovered": True,
    }


def _samples(elapsed=lambda i: 500.0):
    return [_sample(i, rec.SO02_LAB_SOURCE_TYPES[i % 2], elapsed(i)) for i in range(20)]


def _record(samples, *, prerequisites=None, gaps=None, config=None) -> dict:
    spec = rec.OBJECTIVE_SPECS["SO-02"]["source_failure_visible"]
    observed = rec.so02_observed_prerequisites(samples)
    if prerequisites is None:
        prerequisites = [rec.prerequisite(p, observed.get(p, True), "") for p in spec["prerequisites"]]
    if gaps is None:
        gaps = [rec.gap(g, "x") for g in spec["gaps"]]
    # The harness ends only observed samples; mirror that.
    samples = [dict(s) for s in samples]
    for s in samples:
        if not rec.so02_failure_observed(s):
            s["end_monotonic_ns"] = None
            s["elapsed_ms"] = None
    part = rec.build_part(
        name="source_failure_visible",
        pass_rule={"kind": rec.RULE_EVERY_SAMPLE_MAX, "bound_ms": spec["bound_ms"]},
        required_samples=spec["required_samples"],
        samples=samples,
        prerequisites=prerequisites,
        gaps=gaps,
    )
    return rec.build_record(
        objective_id="SO-02",
        title="t",
        started_monotonic_ns=0,
        started_at=rec.utc_now(),
        product_configuration=config if config is not None else {"product": "azazel-edge", "row_class": "virtual-lab", "hardware_evidence": False},
        clock={"name": "CLOCK_MONOTONIC"},
        sample_rule={"required_samples": spec["required_samples"]},
        parts=[part],
        method="test",
    )


def _forge(record: dict, verdict: str = rec.VERDICT_PASS) -> dict:
    record = copy.deepcopy(record)
    record["owner"] = {"repository": rec.OWNING_REPOSITORY, "commit": "c" * 40, "worktree_clean": True}
    for part in record["parts"]:
        part["verdict"] = verdict
        part["pass_rule"]["evaluated"]["holds"] = verdict == rec.VERDICT_PASS
    record["verdict"] = verdict
    record["evidence_class"] = "gate"
    return record


# ------------------------------------------------------------------ the table


def test_table_is_the_assignment_row():
    assert SPEC["bound_ms"] == 10000.0 == so02.BOUND_MS
    assert SPEC["required_samples"] == 20 == so02.REQUIRED_SAMPLES
    assert SPEC["row_class"] == "virtual-lab"
    assert rec.SO02_PER_SOURCE_TYPE_SAMPLES * len(rec.SO02_LAB_SOURCE_TYPES) == SPEC["required_samples"]
    assert set(SPEC["gaps"]) == {
        "SO02-NOT-NEXUS-INTEGRATED",
        "SO02-SOURCE-TYPES-UNDECLARED",
        "SO02-NO-COMMISSIONED-INTERFACE-IDENTITY",
    }
    assert "SO-02" in cli._harnesses(type("A", (), {"seed": None, "core_bin": ""})())


# ------------------------------------------------------------- the validator


def test_real_table_record_is_valid_and_not_measurable(clean_owner):
    record = _record(_samples())
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert record["evidence_class"] == "diagnostic_only"


def test_forged_pass_on_real_table_is_refused(clean_owner):
    errors = rec.validate_record(_forge(_record(_samples())))
    assert any("record supports 'not_measurable'" in e for e in errors), errors


def test_mechanics_pass_within_bound(clean_owner, no_gap_table):
    record = _record(_samples())
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_PASS


def test_one_sample_over_ten_seconds_is_fail(clean_owner, no_gap_table):
    record = _record(_samples(lambda i: 33_000.0 if i == 1 else 500.0))
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_FAIL
    errors = rec.validate_record(_forge(record))
    assert any("disagrees with the samples" in e or "record supports 'fail'" in e for e in errors), errors


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(end_surface_value="ON"),                         # surface never said failed
        lambda s: s.update(end_surface_value=["usb0"]),                     # (interface sample) source not named
        lambda s: s.update(source_id="eth0"),                                # another source
        lambda s: s.update(surface_field="noc_summary.status"),             # another field
        lambda s: s.update(end_poll_started_monotonic_ns=s["start_monotonic_ns"] - 1),  # poll begun before injection
        lambda s: s.update(baseline_surface_value="OFF"),                   # was already failed
        lambda s: s.update(baseline_surface_value=["br0"]),                 # (interface) was already failed
        lambda s: s.update(baseline_healthy=False),
        lambda s: s.update(baseline_poll_started_monotonic_ns=s["start_monotonic_ns"] + 1),
        lambda s: s.update(source_type="feed_unreachable"),
    ],
)
def test_end_not_shown_by_the_fields_is_refused_and_never_counted(clean_owner, no_gap_table, mutate):
    samples = _samples()
    # Mutate one sample of each type; at least one of them is affected.
    for idx in (0, 1):
        mutate(samples[idx])
    affected = [i for i in (0, 1) if not rec.so02_failure_observed(samples[i])]
    assert affected
    # A record that keeps the end anyway is rejected.
    honest = _record(_samples())
    forged = copy.deepcopy(honest)
    for i in affected:
        forged["parts"][0]["samples"][i] = samples[i]
    errors = rec.validate_record(forged)
    assert any("do not show the surface naming the source failed" in e for e in errors), errors
    # Recorded honestly (no end), the sample is unfinished: never a pass.
    record = _record(samples)
    assert record["verdict"] != rec.VERDICT_PASS
    assert rec.validate_record(_forge(record)) != []


def test_one_type_short_is_not_measurable(clean_owner, no_gap_table):
    samples = [_sample(i, PROC if i < 11 else IFACE, 500.0) for i in range(20)]
    assert rec.so02_observed_prerequisites(samples)["every_lab_source_type_sampled"] is False
    record = _record(samples)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert rec.validate_record(record) == []
    forged = _record(samples, prerequisites=[rec.prerequisite(p, True, "") for p in rec.OBJECTIVE_SPECS["SO-02"]["source_failure_visible"]["prerequisites"]])
    errors = rec.validate_record(_forge(forged))
    assert any("'every_lab_source_type_sampled' declared met" in e for e in errors), errors


def test_shortfall_is_not_measurable(clean_owner, no_gap_table):
    record = _record(_samples()[:19])
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE


@pytest.mark.parametrize(
    "config, needle",
    [
        ({"row_class": "hardware-only", "hardware_evidence": False}, "row_class"),
        ({"row_class": "virtual-lab", "hardware_evidence": True}, "hardware_evidence"),
        ({"row_class": "virtual-lab"}, "hardware_evidence"),
        ({}, "row_class"),
    ],
)
def test_virtual_lab_record_never_claims_hardware(clean_owner, config, needle):
    errors = rec.validate_record(_record(_samples(), config=dict(config, product="azazel-edge")))
    assert any(needle in e for e in errors), errors


def test_omitted_gap_is_refused(clean_owner):
    record = _record(_samples(), gaps=[])
    errors = rec.validate_record(_forge(record))
    assert any("mandatory gap 'SO02-NOT-NEXUS-INTEGRATED' omitted" in e for e in errors), errors


def test_unknown_sample_field_is_refused(clean_owner):
    record = _record(_samples())
    record["parts"][0]["samples"][0]["verdict_override"] = "pass"
    assert any("unknown field" in e for e in rec.validate_record(record))


# --------------------------------------------------------------- the harness


def test_not_root_is_not_measurable_and_builds_nothing(clean_owner, monkeypatch):
    monkeypatch.setattr(so02.os, "geteuid", lambda: 1000)

    def no_lab(*a, **k):
        raise AssertionError("the lab must not be built")

    monkeypatch.setattr(so02, "_Lab", no_lab)
    record = so02.run()
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    part = record["parts"][0]
    assert part["samples"] == []
    prereq = {p["id"]: p for p in part["prerequisites"]}
    assert prereq["lab_built"]["met"] is False and "not root" in prereq["lab_built"]["detail"]
    assert record["product_configuration"]["hardware_evidence"] is False


def test_live_capture_is_never_touched(clean_owner, monkeypatch):
    monkeypatch.setattr(
        so02,
        "preflight",
        lambda: {"problems": [], "live_capture": ["suricata already running (pid [42])"], "suricata_version": "", "gunicorn_version": "", "tools": {"suricata": "/x"}},
    )

    def no_lab(*a, **k):
        raise AssertionError("the lab must not be built while a capture is live")

    monkeypatch.setattr(so02, "_Lab", no_lab)
    record = so02.run()
    assert rec.validate_record(record) == []
    prereq = {p["id"]: p for p in record["parts"][0]["prerequisites"]}
    assert prereq["no_live_capture_touched"]["met"] is False
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE


class _FakePoller:
    """Answers wait_for from a script: per call, the delay after begun_after_ns
    and the row content, or None for "nothing seen"."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def wait_for(self, predicate, *, begun_after_ns, timeout_s):
        self.calls.append(begun_after_ns)
        step = self.script.pop(0)
        if step is None:
            return None, 0, 0
        delay_ns, row = step
        row = dict(row, s=begun_after_ns + delay_ns, e=begun_after_ns + delay_ns + 1_000_000, ok=True)
        assert predicate(row), row
        return row, 2, 0


class _FakeLab:
    def __init__(self):
        self.events = []

    def inject(self, source_type):
        self.events.append(("inject", source_type))

    def recover(self, source_type):
        self.events.append(("recover", source_type))
        return True


HEALTHY = {"suricata": "ON", "uplinks": ["usb0"]}


def test_measure_times_from_injection_to_the_failed_poll():
    lab = _FakeLab()
    poller = _FakePoller(
        [
            (1, HEALTHY), (5_000_000, {"suricata": "OFF", "uplinks": ["usb0"]}),
            (1, HEALTHY), (30_000_000_000, {"suricata": "ON", "uplinks": ["br0", "usb0"]}),
        ]
    )
    rows = []
    so02._measure(lab, poller, 2, rows)
    assert [r["source_type"] for r in rows] == [PROC, IFACE]
    assert lab.events == [("inject", PROC), ("recover", PROC), ("inject", IFACE), ("recover", IFACE)]
    for r in rows:
        assert rec.so02_failure_observed(r)
        assert r["end_poll_started_monotonic_ns"] >= r["start_monotonic_ns"]
    assert 5 <= rows[0]["elapsed_ms"] < 10
    assert rows[1]["elapsed_ms"] > 30_000


def test_measure_never_ends_a_sample_without_a_failed_poll():
    lab = _FakeLab()
    poller = _FakePoller([(1, HEALTHY), None])
    rows = []
    so02._measure(lab, poller, 1, rows)
    assert rows[0]["end_monotonic_ns"] is None and rows[0]["elapsed_ms"] is None
    assert lab.events == [("inject", PROC), ("recover", PROC)]


def test_measure_stops_without_a_healthy_baseline_and_injects_nothing():
    lab = _FakeLab()
    poller = _FakePoller([None])
    rows = []
    so02._measure(lab, poller, 20, rows)
    assert len(rows) == 1 and rows[0]["baseline_healthy"] is False and rows[0]["end_monotonic_ns"] is None
    assert lab.events == []
    assert rec.so02_observed_prerequisites(rows)["every_injection_from_healthy_baseline"] is False


def test_children_get_a_fresh_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_DEV_HEALTHY_BASELINE", "1")
    monkeypatch.setenv("AZAZEL_DEMO_FAST", "1")
    lab = so02._Lab(tmp_path, "/usr/bin/suricata")
    assert "AZAZEL_DEV_HEALTHY_BASELINE" not in lab.env
    assert "AZAZEL_DEMO_FAST" not in lab.env
    assert (tmp_path / "first_minute.yaml").read_text(encoding="utf-8").strip() == "suppress_auto_wifi: false"
    tokens = (tmp_path / "auth_tokens.json").read_text(encoding="utf-8")
    assert '"role": "viewer"' in tokens


@pytest.mark.parametrize(
    "source_type, field, value",
    [
        (PROC, "end_surface_value", "ON"),
        (PROC, "end_surface_value", "UNKNOWN"),
        (PROC, "baseline_surface_value", "OFF"),
        (PROC, "baseline_surface_value", "UNKNOWN"),
        (IFACE, "end_surface_value", ["usb0"]),
        (IFACE, "end_surface_value", None),
        (IFACE, "baseline_surface_value", ["br0", "usb0"]),
        (IFACE, "baseline_surface_value", None),
    ],
)
def test_each_type_is_judged_on_its_own_field(source_type, field, value):
    sample = _sample(0, source_type, 500.0)
    assert rec.so02_failure_observed(sample)
    sample[field] = value
    assert not rec.so02_failure_observed(sample)


def test_forged_end_is_recomputed_as_unfinished(clean_owner, no_gap_table):
    """The end is dropped from the recomputation, not only reported: the
    derived verdict is fail (an unfinished sample is a violation)."""

    record = _forge(_record(_samples()))
    record["parts"][0]["samples"][0]["end_surface_value"] = "ON"
    errors = rec.validate_record(record)
    assert any("record supports 'fail'" in e for e in errors), errors
