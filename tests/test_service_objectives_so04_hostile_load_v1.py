"""SO-04 under the declared hostile load (Edge#414, OF-06, Edge#412).

``config/service_objectives/hostile_load_profile.json`` declares the load SO-04
leases expire under. Every rate in it is derived from the OF-06 ingress quota,
and ``SO04-HOSTILE-LOAD-UNDECLARED`` may be left out of a part only when the
validator's own recomputation shows the profile applied for every sample. These
tests check the profile's derivation, the recomputation and its negatives (a
part without the load never closes the gap), the validator wiring, the line
shapes the driver writes, and -- when the core is built on Linux -- that the
real core sheds, skips and decides what the driver writes as the observation
says.
"""

from __future__ import annotations

import copy
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.service_objectives import declarations as decl  # noqa: E402
from azazel_edge.service_objectives import record as rec  # noqa: E402
from azazel_edge.service_objectives import so04_hostile_load as hl  # noqa: E402
from azazel_edge.service_objectives import so04_lease_rollback as so04  # noqa: E402
from azazel_edge.service_objectives import so04_rollback_completion as comp  # noqa: E402

GAP = "SO04-HOSTILE-LOAD-UNDECLARED"
PROVISIONAL_GAP = "SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL"
CORE = ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
CORE_MAIN = ROOT / "rust" / "azazel-edge-core" / "src" / "main.rs"
START_SPEC = rec.OBJECTIVE_SPECS["SO-04"]["rollback_start_after_expiry"]
COMP_SPEC = rec.OBJECTIVE_SPECS["SO-04"]["rollback_completion"]
PROFILE = decl.load_hostile_load_profile()
QUOTA = PROFILE["quota"]
WS0 = 10_000 * 10**9
WALL0 = 1_700_000_000.0
DURATION_S = 9.0


def _doc():
    return json.loads(decl.HOSTILE_LOAD_PROFILE_PATH.read_text(encoding="utf-8"))


def _load(tmp_path: Path, doc, quota_doc=None):
    path = tmp_path / "hostile_load_profile.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    quota_path = None
    if quota_doc is not None:
        quota_path = tmp_path / "ingress_quota.json"
        quota_path.write_text(json.dumps(quota_doc), encoding="utf-8")
    return decl.load_hostile_load_profile(path, quota_path=quota_path)


# ------------------------------------------------------------------ profile


def test_the_profile_is_valid_provisional_and_derived_from_the_quota():
    assert PROFILE["problems"] == []
    doc = _doc()
    assert doc["status"] == "provisional" and "not hardware" in doc["hardware_class"]
    assert doc["derived_from"] == "config/service_objectives/ingress_quota.json"
    assert "pending owner confirmation" in doc["owner_defaults"]["status"]
    assert PROFILE["quota_sha256"] == decl.load_ingress_quotas()["sha256"]
    by_name = {p["name"]: p for p in PROFILE["phases"]}
    # 120% of the non-alert quota, over the quota.
    assert by_name["non_alert_flood"]["non_alert_lines_per_s"] == round(QUOTA["value"] * 1.2) > QUOTA["value"]
    # One full per-poll alert budget per default poll interval: the poll cap.
    assert by_name["alert_flood"]["rates_per_s"]["alert"] == QUOTA["alerts_per_poll"] * 1000 // doc["core_default_poll_ms"]
    malformed = by_name["malformed_mix"]
    assert malformed["rates_per_s"]["invalid_utf8"] > 0 and malformed["rates_per_s"]["oversized"] > 0
    assert malformed["oversized_line_bytes"] > QUOTA["max_line_bytes"]
    # The warm-up empties the bucket before the first lease expires.
    for p in PROFILE["phases"]:
        over = p["non_alert_lines_per_s"] - QUOTA["value"]
        if over > 0:
            assert PROFILE["warmup_ms"] * over >= 1000 * QUOTA["non_alert_burst"]


def test_the_default_poll_interval_is_the_cores():
    src = CORE_MAIN.read_text(encoding="utf-8")
    m = re.search(r'poll_ms: env::var\("AZAZEL_EVE_POLL_MS"\)[^,]*?\.unwrap_or\((\d+)\)', src)
    assert m, "the core's poll default moved; re-derive the profile"
    assert int(m.group(1)) == _doc()["core_default_poll_ms"]


@pytest.mark.parametrize(
    "mutate, expect",
    [
        pytest.param(lambda d: d["phases"][0]["rates_per_s"].update(flow=700), "rates_per_s.flow", id="a rate not derived from the quota"),
        pytest.param(lambda d: d["phases"][3]["rates_per_s"].update(alert=4000), "rates_per_s.alert", id="alert flood off the poll cap"),
        pytest.param(lambda d: d["phases"][1].update(oversized_line_bytes=10), "oversized_line_bytes", id="oversized size not derived"),
        pytest.param(lambda d: d["phases"].pop(1), "no phase mixes invalid UTF-8 and oversized", id="no malformed phase"),
        pytest.param(lambda d: d["phases"].pop(3), "no phase offers alerts at the poll cap", id="no alert flood"),
        pytest.param(lambda d: [d["phases"].pop(0) for _ in range(3)], "above the quota", id="no non-alert flood"),
        pytest.param(lambda d: d["phases"].pop(2), "no backlog phase", id="no backlog phase"),
        pytest.param(lambda d: d["phases"][2].update(burst_interval_ms=100), "no backlog phase", id="backlog bursts below twice the bound"),
        pytest.param(lambda d: d["phases"][2].update(burst_interval_ms=-1), "burst_interval_ms", id="negative burst interval"),
        pytest.param(lambda d: d.update(rate_tolerance=0.3), "rate_tolerance", id="rate tolerance above 0.2"),
        pytest.param(lambda d: d.update(shed_tolerance=0.5), "shed_tolerance", id="shed tolerance above 0.2"),
        pytest.param(lambda d: d.update(leases_per_phase_per_action=0), "leases_per_phase_per_action", id="no phase sample floor"),
        pytest.param(lambda d: d.update(min_hostile_share=0), "min_hostile_share", id="no hostile share"),
        pytest.param(lambda d: d.update(status="confirmed"), "not exactly 'confirmed'", id="confirmed while the owner status is pending"),
        pytest.param(
            lambda d: d.update(status="confirmed") or d["owner_defaults"].update(status="confirmed by the owner"),
            "not exactly 'confirmed'", id="owner status not exactly confirmed",
        ),
        pytest.param(
            lambda d: d.update(status="confirmed") or d["owner_defaults"].update(status="confirmed", confirmed_phase_factors=decl.phase_factors(d["phases"]))
            or d["phases"][0].update(non_alert_factor=1.6, rates_per_s=dict(d["phases"][0]["rates_per_s"], flow=1000, dns=1000, stats=1000, http=1000)),
            "confirmed_phase_factors", id="factors changed after the confirmation",
        ),
        pytest.param(lambda d: d.update(warmup_ms=1000), "warmup_ms", id="warm-up too short to empty the bucket"),
        pytest.param(lambda d: d.update(quiet_gap_ms=2000), "quiet_gap_ms", id="phases could share a summary"),
        pytest.param(lambda d: d.update(audit_attribution_slack_ms=500), "audit_interval_ms", id="slack below the audit interval"),
        pytest.param(lambda d: d["phases"][0].update(non_alert_kinds=["flow", "dns", "stats", "http", "invalid_utf8", "bogus"]), "non_alert_kinds", id="unknown kind"),
        pytest.param(lambda d: d["phases"][0].update(non_alert_kinds=["flow", "dns", "stats", "http", "invalid_utf8", "flow"]), "non_alert_kinds", id="duplicate kind"),
        pytest.param(lambda d: d["phases"][0].update(non_alert_factor=1.0004), "split equally", id="non-whole share"),
        pytest.param(lambda d: d["phases"][0].update(name="nominal"), "nominal", id="phase named nominal"),
        pytest.param(lambda d: d["phases"].append(copy.deepcopy(d["phases"][0])), "declared twice", id="duplicate phase"),
        pytest.param(lambda d: d.update(status="final"), "status", id="unknown status"),
        pytest.param(lambda d: d.update(ingress="other_reader"), "no valid quota", id="unknown ingress"),
        pytest.param(lambda d: d.update(derived_from="elsewhere.json"), "derived_from", id="not derived from the quota file"),
        pytest.param(lambda d: d.update(rate_tolerance=0.9), "rate_tolerance", id="tolerance too loose"),
        pytest.param(lambda d: d.update(schema="x"), "schema", id="wrong schema"),
    ],
)
def test_a_profile_not_derived_from_the_quota_declares_nothing(tmp_path, mutate, expect):
    doc = _doc()
    mutate(doc)
    loaded = _load(tmp_path, doc)
    assert loaded["phases"] == []
    assert any(expect in p for p in loaded["problems"]), loaded["problems"]


def test_a_changed_quota_invalidates_the_profile_until_it_is_re_derived(tmp_path):
    quota_doc = json.loads(decl.INGRESS_QUOTA_PATH.read_text(encoding="utf-8"))
    doc = _doc()
    # The same profile, pointed at a copy of the quota file (outside the tree).
    doc["derived_from"] = str((tmp_path / "ingress_quota.json").resolve())
    quota_doc["quotas"][0]["value"] = 2000
    loaded = _load(tmp_path, doc, quota_doc)
    assert loaded["phases"] == [] and any("rates_per_s.flow" in p for p in loaded["problems"]), loaded["problems"]
    # Unchanged, the copy re-derives the same rates.
    quota_doc["quotas"][0]["value"] = QUOTA["value"]
    assert _load(tmp_path, doc, quota_doc)["problems"] == []


def test_an_unreadable_profile_declares_nothing(tmp_path):
    loaded = decl.load_hostile_load_profile(tmp_path / "absent.json")
    assert loaded["phases"] == [] and loaded["problems"]


# ------------------------------------------------------------ recomputation


def _audit_record(*, emitted, shed_total, by_backlog=0, level=0, admitted=0, alerts_admitted=0, oversized=0, cum_shed, cum_over, alerts_shed=0, quota=None):
    q = dict(quota or QUOTA)
    return {
        "source": "core_ingress",
        "pipeline": "rust_ingress_v1",
        "ingress_shed": {
            "schema": "azazel-edge/ingress-shed/v1",
            "emitted_epoch": emitted,
            "shed_total": shed_total,
            "shed_by_reason": {"non_alert_rate": shed_total - by_backlog, "backlog": by_backlog},
            "max_shed_level": level,
            "admitted": admitted,
            "alerts_admitted": alerts_admitted,
            "alerts_shed": alerts_shed,
            "oversized_lines_skipped": oversized,
            "oversized_possible_alerts": 0,
            "cumulative_shed_total": cum_shed,
            "cumulative_oversized_lines_skipped": cum_over,
            "quota": {k: q[v] for k, v in hl._QUOTA_BLOCK_KEYS.items()},
        },
    }


NON_ALERT = ("flow", "dns", "stats", "http", "invalid_utf8")


def _excess(written):
    return sum(written[c] for c in NON_ALERT) - (QUOTA["value"] * DURATION_S + QUOTA["non_alert_burst"])


def _observation():
    """A hostile_load block that shows the tree's profile applied as declared.

    Shed is 1.3 times the excess (container runs: 1.28-1.96), capped below
    what was written; a backlog phase sheds half of it for the backlog.
    """

    phases, audit = [], []
    cum_shed = cum_over = 0
    gap_ns = int((DURATION_S + PROFILE["quiet_gap_ms"] / 1000) * 1e9)
    for i, p in enumerate(PROFILE["phases"]):
        ws = WS0 + i * gap_ns
        wall = WALL0 + i * gap_ns / 1e9
        written = {c: int(float(r) * DURATION_S) for c, r in p["rates_per_s"].items()}
        phases.append({
            "name": p["name"],
            "window_start_boottime_ns": ws,
            "window_end_boottime_ns": ws + int(DURATION_S * 1e9),
            "window_start_wall_epoch": wall,
            "window_end_wall_epoch": wall + DURATION_S,
            "written": written,
            "written_bytes": 1,
            "alert_sid_base": hl.alert_sid_base(i),
            "alerts_decided": written["alert"],
        })
        over = p["non_alert_lines_per_s"] > QUOTA["value"]
        if over or written["oversized"]:
            na = sum(written[c] for c in NON_ALERT)
            shed = min(int(_excess(written) * 1.3), na - 1000) if over else 0
            backlog = shed // 2 if p["backlog_phase"] else 0
            cum_shed += shed
            cum_over += written["oversized"]
            audit.append(_audit_record(
                emitted=wall + DURATION_S / 2, shed_total=shed, by_backlog=backlog, level=2 if backlog else 0,
                admitted=na - shed + written["alert"], alerts_admitted=written["alert"],
                oversized=written["oversized"], cum_shed=cum_shed, cum_over=cum_over,
            ))
    return {
        "profile_path": PROFILE["path"],
        "profile_sha256": PROFILE["sha256"],
        "quota_path": PROFILE["quota_path"],
        "quota_sha256": PROFILE["quota_sha256"],
        "clock": "CLOCK_BOOTTIME",
        "phases": phases,
        "ingress_audit": audit,
        "ingress_audit_rotated": False,
    }


def _samples(obs):
    """The harness's split: per phase and action type the declared count, then nominal (hostile first)."""

    out = []
    warm = PROFILE["warmup_ms"] * 1_000_000
    per = PROFILE["leases_per_phase_per_action"]
    for o in obs["phases"]:
        for action in so04.ACTION_TYPES:
            for k in range(per):
                out.append({
                    "sample_id": f"{o['name']}-{action}-{k}",
                    "action_type": action,
                    "condition": {"load": o["name"]},
                    "sample_clock": "CLOCK_BOOTTIME",
                    "start_monotonic_ns": o["window_start_boottime_ns"] + warm + 500_000_000 + k * 100_000_000,
                })
    for action in so04.ACTION_TYPES:
        for k in range(50 - per * len(obs["phases"])):
            out.append({"sample_id": f"n-{action}-{k}", "action_type": action, "condition": {"load": "nominal"}, "sample_clock": "CLOCK_BOOTTIME", "start_monotonic_ns": 1 + k})
    return out


def _resum(obs):
    """Re-derive the cumulative totals after a mutation, so only the mutated count differs."""

    cum = 0
    for r in obs["ingress_audit"]:
        cum += r["ingress_shed"]["shed_total"]
        r["ingress_shed"]["cumulative_shed_total"] = cum


def _shed_one_line_each(o, s):
    for r in o["ingress_audit"]:
        r["ingress_shed"].update(shed_total=1, shed_by_reason={"non_alert_rate": 1, "backlog": 0})
    _resum(o)


def _backlog_off(o, s):
    b = _phase(o, "backlog_flood")
    for r in o["ingress_audit"]:
        if b["window_start_wall_epoch"] <= r["ingress_shed"]["emitted_epoch"] <= b["window_end_wall_epoch"]:
            r["ingress_shed"]["shed_by_reason"] = {"non_alert_rate": r["ingress_shed"]["shed_total"], "backlog": 0}
            r["ingress_shed"]["max_shed_level"] = 0


def _admitted_over_quota(o, s):
    r = o["ingress_audit"][0]["ingress_shed"]
    r["admitted"] = r["alerts_admitted"] + QUOTA["value"] * 100


def test_the_profile_applied_as_declared_closes_the_gap():
    obs = _observation()
    assert hl.hostile_load_problems(_samples(obs), obs) == []
    assert hl.hostile_load_applied(_samples(obs), obs) is True
    assert rec.so04_hostile_load_applied(_samples(obs), {"hostile_load": obs}) is True


def _phase(obs, name):
    return next(o for o in obs["phases"] if o["name"] == name)


def _audit_for(obs, name):
    o = _phase(obs, name)
    return [r for r in obs["ingress_audit"] if o["window_start_wall_epoch"] <= r["ingress_shed"]["emitted_epoch"] <= o["window_end_wall_epoch"]]


NEGATIVES = [
    pytest.param(lambda o, s: o["phases"].pop(), "not applied", id="a phase never applied"),
    pytest.param(lambda o, s: _phase(o, "non_alert_flood")["written"].update(flow=int(500 * DURATION_S)), "flow lines", id="non-alert written below the declared rate"),
    pytest.param(lambda o, s: _phase(o, "alert_flood")["written"].update(alert=int(2000 * DURATION_S)), "alert lines", id="alert flood below the poll cap"),
    pytest.param(lambda o, s: _phase(o, "malformed_mix")["written"].update(invalid_utf8=0), "invalid_utf8 lines", id="no invalid UTF-8 written"),
    pytest.param(lambda o, s: _phase(o, "non_alert_flood")["written"].update(invalid_utf8=5), "invalid_utf8 lines", id="lines of a class the phase does not declare"),
    pytest.param(lambda o, s: _phase(o, "alert_flood").update(alerts_decided=_phase(o, "alert_flood")["alerts_decided"] - 1), "decided", id="an alert written but not decided"),
    pytest.param(lambda o, s: o.update(ingress_audit=[]), "non-alert lines shed", id="the core recorded no shedding"),
    pytest.param(
        lambda o, s: [r["ingress_shed"].update(shed_total=0, shed_by_reason={"non_alert_rate": 0, "backlog": 0}, cumulative_shed_total=0) for r in o["ingress_audit"]],
        "non-alert lines shed", id="the core shed nothing over the quota",
    ),
    pytest.param(lambda o, s: o["ingress_audit"][0]["ingress_shed"].update(alerts_shed=1), "alerts_shed", id="an alert shed"),
    pytest.param(lambda o, s: o["ingress_audit"][0]["ingress_shed"].update(oversized_possible_alerts=1), "oversized_possible_alerts", id="an oversized alert"),
    pytest.param(lambda o, s: o["ingress_audit"][0]["ingress_shed"]["quota"].update(non_alert_per_sec=99999), "quota block", id="the core ran another quota"),
    pytest.param(lambda o, s: o["ingress_audit"][-1]["ingress_shed"].update(cumulative_shed_total=10**9), "cumulative", id="a summary missing from the audit"),
    pytest.param(
        lambda o, s: [r["ingress_shed"].update(oversized_lines_skipped=0, cumulative_oversized_lines_skipped=0) for r in o["ingress_audit"]],
        "oversized lines written", id="oversized lines not skipped by the core",
    ),
    pytest.param(lambda o, s: o.update(ingress_audit_rotated=True), "rotated", id="audit rotated"),
    pytest.param(lambda o, s: o.update(profile_sha256="0" * 64), "does not cite", id="another profile"),
    pytest.param(lambda o, s: o.update(quota_sha256="0" * 64), "does not cite", id="another quota"),
    pytest.param(lambda o, s: o.update(clock="CLOCK_MONOTONIC"), "not on CLOCK_BOOTTIME", id="windows on another clock"),
    pytest.param(
        lambda o, s: _phase(o, "malformed_mix").update(window_end_boottime_ns=_phase(o, "malformed_mix")["window_start_boottime_ns"] + 10**9),
        "shorter than the warm-up", id="a phase applied for less than the warm-up",
    ),
    pytest.param(
        lambda o, s: s[1].update(start_monotonic_ns=_phase(o, s[1]["condition"]["load"])["window_start_boottime_ns"] + 1),
        "inside the", id="a lease expired before the warm-up ended",
    ),
    pytest.param(
        lambda o, s: s[1].update(start_monotonic_ns=_phase(o, s[1]["condition"]["load"])["window_end_boottime_ns"] + 1),
        "inside the", id="a lease expired after the load stopped",
    ),
    pytest.param(lambda o, s: s[1].update(sample_clock="CLOCK_MONOTONIC"), "inside the", id="a sample on another clock"),
    pytest.param(lambda o, s: s[1]["condition"].update(load="eve_flood"), "neither nominal", id="an undeclared load"),
    pytest.param(lambda o, s: [x["condition"].update(load="nominal") for x in s if x["action_type"] == "isolate"], "0 isolate leases", id="an action type never under a phase"),
    # Review M1: a forged record with one line shed per summary (cumulative
    # totals made consistent) must not pass as the excess shed.
    pytest.param(_shed_one_line_each, "at least", id="one line shed per summary, cumulative consistent"),
    pytest.param(_admitted_over_quota, "above the quota", id="the core admitted more than the quota"),
    # Review M2: the record's samples mostly nominal.
    pytest.param(lambda o, s: [x["condition"].update(load="nominal") for x in s[:141]], "below the declared share", id="141 of 150 samples nominal"),
    pytest.param(lambda o, s: s[0]["condition"].update(load="nominal"), "at least 10 declared", id="one phase one lease short"),
    # Review M3: the backlog phase without the core's backlog shedding.
    pytest.param(_backlog_off, "backlog shedding did not act", id="backlog phase shed only by rate"),
]


@pytest.mark.parametrize("mutate, expect", NEGATIVES)
def test_the_gap_stays_unless_every_check_holds(mutate, expect):
    obs = _observation()
    samples = _samples(obs)
    mutate(obs, samples)
    problems = hl.hostile_load_problems(samples, obs)
    assert any(expect in p for p in problems), problems
    assert hl.hostile_load_applied(samples, obs) is False


def test_a_part_without_the_load_never_closes_the_gap():
    obs = _observation()
    samples = _samples(obs)
    assert hl.hostile_load_applied(samples, None) is False
    assert rec.so04_hostile_load_applied(samples, {}) is False
    assert hl.hostile_load_applied([], obs) is False
    # The old harness-chosen flood: every lease nominal or "eve_flood", no profile.
    old = [dict(s, condition={"load": "eve_flood"}) for s in samples]
    assert hl.hostile_load_applied(old, {"phases": [], "ingress_audit": []}) is False


def test_an_invalid_profile_in_the_tree_never_closes_the_gap():
    obs = _observation()
    broken = dict(PROFILE, problems=["x"], phases=[])
    assert hl.hostile_load_problems(_samples(obs), obs, broken)[0].startswith("the hostile-load profile is not valid")


# ---------------------------------------------------------------- validator


def _record(obs, *, start_gaps, comp_gaps=None, with_load=True):
    start = rec.build_part(
        name="rollback_start_after_expiry",
        pass_rule={"kind": rec.RULE_EVERY_SAMPLE_MAX, "bound_ms": START_SPEC["bound_ms"]},
        required_samples=START_SPEC["required_samples"],
        samples=[],
        prerequisites=[rec.prerequisite(p, True, "") for p in START_SPEC["prerequisites"]],
        gaps=[rec.gap(g, "") for g in start_gaps],
        per_action_required=START_SPEC["per_action_samples"],
        hostile_load=obs if with_load else None,
    )
    completion = comp.unmeasured_part("test")
    return start, completion


def _with_samples(part, samples):
    # Samples carrying only what the hostile-load recomputation reads, plus
    # the common fields the validator needs.
    full = []
    for s in samples:
        full.append(dict(s, end_monotonic_ns=s["start_monotonic_ns"] + 10**8, elapsed_ms=100.0, start_event="e", end_event="e", due_epoch=1.0))
    part["samples"] = full
    part["pass_rule"]["evaluated"] = rec.evaluate_rule(part["pass_rule"], full)
    return part


def _validate(start, completion):
    record = rec.build_record(
        objective_id="SO-04", title="t", started_monotonic_ns=0, started_at=rec.utc_now(),
        product_configuration={}, clock={"name": "CLOCK_BOOTTIME"}, sample_rule={}, parts=[start, completion], method="test",
    )
    return [e for e in rec.validate_record(record) if "SO04-HOSTILE-LOAD" in e or "hostile_load" in e]


def test_the_validator_lets_the_gap_out_only_when_its_recomputation_holds():
    obs = _observation()
    others = [g for g in START_SPEC["gaps"] if g != GAP]
    start, completion = _record(obs, start_gaps=others)
    _with_samples(start, _samples(obs))
    assert _validate(start, completion) == []
    # Without the load observation the same samples must keep the gap.
    start, completion = _record(obs, start_gaps=others, with_load=False)
    _with_samples(start, _samples(obs))
    assert any(f"mandatory gap {GAP!r} omitted" in e for e in _validate(start, completion))
    # With the load short of its declared rate, too.
    bad = _observation()
    _phase(bad, "non_alert_flood")["written"]["flow"] = 1
    start, completion = _record(bad, start_gaps=others)
    _with_samples(start, _samples(bad))
    assert any(f"mandatory gap {GAP!r} omitted" in e for e in _validate(start, completion))


def test_the_completion_part_keeps_its_provisional_bound_gap():
    assert GAP in COMP_SPEC["gaps_closed_by_samples"]
    assert "SO04-COMPLETION-BOUND-PROVISIONAL" in COMP_SPEC["gaps"]
    assert "SO04-COMPLETION-BOUND-PROVISIONAL" not in COMP_SPEC["gaps_closed_by_samples"]
    assert "SO04-COMPLETION-BOUND-PROVISIONAL" not in rec.GAP_CLOSERS
    assert "SO04-COMPLETION-BOUND-PROVISIONAL" not in rec.PART_GAP_CLOSERS
    assert rec.PART_GAP_CLOSERS == {GAP: rec.so04_hostile_load_applied, PROVISIONAL_GAP: rec.so04_hostile_load_profile_confirmed}
    for spec in (START_SPEC, COMP_SPEC):
        assert PROVISIONAL_GAP in spec["gaps"] and PROVISIONAL_GAP in spec["gaps_closed_by_samples"]
    assert rec.CI_DECLARED_PREREQUISITES["SO-04"] == frozenset()


def test_hostile_load_is_an_object_and_only_on_so04_parts():
    obs = _observation()
    start, completion = _record(obs, start_gaps=list(START_SPEC["gaps"]))
    start["hostile_load"] = "applied"
    assert any("hostile_load" in e for e in _validate(start, completion))
    so07 = rec.build_part(
        name="reported_complete_implies_record_present",
        pass_rule={"kind": rec.RULE_ZERO_VIOLATIONS}, required_samples=110, samples=[],
        prerequisites=[], gaps=[], hostile_load=obs,
    )
    record = rec.build_record(
        objective_id="SO-07", title="t", started_monotonic_ns=0, started_at=rec.utc_now(),
        product_configuration={}, clock={"name": "x"}, sample_rule={}, parts=[so07], method="test",
    )
    assert any("hostile_load" in e for e in rec.validate_record(record))


def test_the_harness_reports_the_gap_with_its_reasons():
    gaps = so04.hostile_load_gap([], None, PROFILE)
    assert [g["id"] for g in gaps] == [PROVISIONAL_GAP, GAP]
    obs = _observation()
    # Applied as declared, but the profile in the tree is still provisional.
    assert [g["id"] for g in so04.hostile_load_gap(_samples(obs), obs, PROFILE)] == [PROVISIONAL_GAP]
    part = comp.unmeasured_part("test")
    assert {GAP, PROVISIONAL_GAP} <= {g["id"] for g in part["gaps"]}


# ------------------------------------------------- provisional profile gap


def _confirmed_tree(tmp_path, monkeypatch, *, owner_status="confirmed"):
    """A temporary declaration with status confirmed, made the tree's profile."""

    doc = _doc()
    doc["status"] = "confirmed"
    doc["owner_defaults"]["status"] = owner_status
    doc["owner_defaults"]["confirmed_phase_factors"] = decl.phase_factors(doc["phases"])
    path = tmp_path / "hostile_load_profile.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setattr(decl, "HOSTILE_LOAD_PROFILE_PATH", path)
    return decl.load_hostile_load_profile()


def _cite(obs, profile):
    obs["profile_path"], obs["profile_sha256"] = profile["path"], profile["sha256"]
    return obs


def test_a_provisional_profile_never_closes_its_gap():
    assert PROFILE["status"] == "provisional"
    obs = _observation()
    assert hl.profile_confirmed_problems(obs) and hl.profile_confirmed(_samples(obs), obs) is False
    assert rec.so04_hostile_load_profile_confirmed(_samples(obs), {"hostile_load": obs}) is False


def test_a_confirmed_profile_in_the_tree_closes_its_gap(tmp_path, monkeypatch):
    confirmed = _confirmed_tree(tmp_path, monkeypatch)
    assert confirmed["problems"] == [] and confirmed["status"] == "confirmed"
    obs = _cite(_observation(), confirmed)
    assert hl.profile_confirmed_problems(obs) == []
    assert rec.so04_hostile_load_profile_confirmed(_samples(obs), {"hostile_load": obs}) is True
    # Through the validator: both hostile-load gaps may now be left out.
    others = [g for g in START_SPEC["gaps"] if g not in (GAP, PROVISIONAL_GAP)]
    start, completion = _record(obs, start_gaps=others)
    _with_samples(start, _samples(obs))
    assert _validate(start, completion) == []


def test_a_record_taken_against_the_provisional_profile_keeps_the_gap(tmp_path, monkeypatch):
    obs = _observation()  # cites the provisional file's digest
    confirmed = _confirmed_tree(tmp_path, monkeypatch)
    assert any("was not taken against" in p for p in hl.profile_confirmed_problems(obs))
    # Same path, another version of the file: the digest alone must keep it.
    stale = _cite(_observation(), confirmed)
    stale["profile_sha256"] = PROFILE["sha256"]
    assert any("was not taken against" in p for p in hl.profile_confirmed_problems(stale))
    others = [g for g in START_SPEC["gaps"] if g not in (GAP, PROVISIONAL_GAP)]
    start, completion = _record(obs, start_gaps=others)
    _with_samples(start, _samples(obs))
    assert any(f"mandatory gap {PROVISIONAL_GAP!r} omitted" in e for e in rec.validate_record(rec.build_record(
        objective_id="SO-04", title="t", started_monotonic_ns=0, started_at=rec.utc_now(),
        product_configuration={}, clock={"name": "CLOCK_BOOTTIME"}, sample_rule={}, parts=[start, completion], method="test",
    )))


def test_confirmed_with_pending_owner_defaults_declares_nothing(tmp_path, monkeypatch):
    confirmed = _confirmed_tree(tmp_path, monkeypatch, owner_status="pending owner confirmation")
    assert confirmed["phases"] == [] and any("not exactly 'confirmed'" in p for p in confirmed["problems"])
    obs = _cite(_observation(), confirmed)
    assert hl.profile_confirmed(_samples(obs), obs) is False


def test_a_part_without_samples_or_load_never_closes_the_provisional_gap(tmp_path, monkeypatch):
    confirmed = _confirmed_tree(tmp_path, monkeypatch)
    obs = _cite(_observation(), confirmed)
    assert hl.profile_confirmed([], obs) is False
    assert hl.profile_confirmed(_samples(obs), None) is False


# ------------------------------------------------------------------- driver


def test_the_plan_samples_every_phase_for_every_action_type():
    plan = hl.plan(50, PROFILE)
    per = PROFILE["leases_per_phase_per_action"]
    for action in so04.ACTION_TYPES:
        mine = [p for p in plan if p[0] == action]
        assert len(mine) == 50
        for phase in PROFILE["phases"]:
            assert sum(1 for p in mine if p[2] == phase["name"]) == per
    # The harness's split meets the validator's floors.
    hostile = sum(1 for p in plan if p[2] != hl.NOMINAL)
    assert hostile >= PROFILE["min_hostile_share"] * len(plan)
    assert per * len(PROFILE["phases"]) <= START_SPEC["per_action_samples"]
    assert len({(a, i) for a, i, _ in plan}) == len(plan)


def test_the_schedule_puts_each_phase_lease_after_the_warm_up_and_inside_the_window():
    plan = hl.plan(50, PROFILE)
    conds = [p[2] for p in plan]
    dues, windows = hl.schedule(conds, 1000.0, random.Random(1), PROFILE)
    assert [w[0] for w in windows] == [p["name"] for p in PROFILE["phases"]]
    prev_end = max(d for d, c in zip(dues, conds) if c == hl.NOMINAL)
    for name, start, end in windows:
        assert start - prev_end >= PROFILE["quiet_gap_ms"] / 1000.0 - hl.LEASE_SPACING_S
        mine = [d for d, c in zip(dues, conds) if c == name]
        assert min(mine) >= start + PROFILE["warmup_ms"] / 1000.0 + hl.WINDOW_MARGIN_S
        assert max(mine) + PROFILE["hold_after_ms"] / 1000.0 == pytest.approx(end)
        prev_end = end


def test_without_a_valid_profile_every_lease_is_nominal():
    plan = hl.plan(4, {"phases": []})
    assert {p[2] for p in plan} == {hl.NOMINAL}
    dues, windows = hl.schedule([p[2] for p in plan], 0.0, random.Random(0), {"phases": []})
    assert windows == [] and len(dues) == len(plan)


def test_the_line_shapes_are_what_the_core_must_shed_skip_or_decide():
    malformed = next(i for i, p in enumerate(PROFILE["phases"]) if p["name"] == "malformed_mix")
    lines = hl._Lines(malformed, PROFILE["line_bytes"], PROFILE["phases"][malformed]["oversized_line_bytes"])
    bad = lines.make("invalid_utf8", 3)
    with pytest.raises(UnicodeDecodeError):
        bad.decode("utf-8")
    with pytest.raises(ValueError):
        json.loads(bad.decode("utf-8", errors="replace"))
    big = lines.make("oversized", 1)
    assert len(big) > QUOTA["max_line_bytes"] and big.endswith(b"\n") and big.count(b"\n") == 1
    assert b'"event_type":"alert"' not in big
    alert = json.loads(lines.make("alert", 7))
    assert alert["event_type"] == "alert"
    assert hl.alert_sid_base(malformed) <= alert["alert"]["signature_id"] < hl.alert_sid_base(malformed) + hl.ALERT_SID_VARIANTS
    for cls in ("flow", "dns", "stats", "http", "alert"):
        line = lines.make(cls, 11)
        assert line.endswith(b"\n") and abs(len(line) - PROFILE["line_bytes"]) <= 2
        assert json.loads(line)["event_type"] == cls


def test_the_alert_counter_counts_decided_alerts_per_phase(tmp_path):
    log = tmp_path / "normalized-events.jsonl"
    rows = [
        {"normalized": {"sid": hl.alert_sid_base(0) + 3}, "pipeline": "rust_event_engine_v1"},
        {"normalized": {"sid": hl.alert_sid_base(2) + 49}, "pipeline": "rust_event_engine_v1"},
        {"normalized": {"sid": hl.alert_sid_base(2) + 50}, "pipeline": "rust_event_engine_v1"},  # not a harness sid
        {"release": {}, "pipeline": "rust_release_engine_v1"},
    ]
    log.write_text("".join(json.dumps(r) + "\n" for r in rows) + '{"partial', encoding="utf-8")
    counter = hl.AlertCounter(log)
    counter.poll()
    assert counter.by_sid_base == {hl.alert_sid_base(0): 1, hl.alert_sid_base(2): 1}


@pytest.mark.skipif(not (CORE.is_file() and os.access(CORE, os.X_OK) and sys.platform.startswith("linux")), reason="needs the release core on Linux")
def test_the_real_core_sheds_skips_and_decides_what_the_driver_writes():
    """A short malformed_mix window against the real core: the observation the
    recomputation reads must agree with what the core recorded."""

    malformed = next(p for p in PROFILE["phases"] if p["name"] == "malformed_mix")
    profile = dict(PROFILE, phases=[malformed])
    with tempfile.TemporaryDirectory(prefix="so04h-test-") as tmp:
        work = Path(tmp)
        eve, events = work / "eve.json", work / "normalized-events.jsonl"
        eve.write_text("", encoding="utf-8")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "AZAZEL_EVE_PATH": str(eve),
            "AZAZEL_FORWARD_AI": "false",
            "AZAZEL_NORMALIZED_EVENT_LOG": str(events),
            "AZAZEL_DEFENSE_RELEASE_LEDGER": str(work / "release-ledger.json"),
            "AZAZEL_EVENT_STDOUT": "off",
        }
        now = time.time()
        load = hl.HostileLoad(eve, profile, [(malformed["name"], now + 0.5, now + 6.5)], so04.boottime_ns)
        counter = hl.AlertCounter(events)
        proc = subprocess.Popen([str(CORE)], cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            load.start()
            load.join(timeout=30)
            hl.drain(counter, load, timeout_s=30.0, audit_interval_s=QUOTA["audit_interval_ms"] / 1000.0, alive=lambda: proc.poll() is None)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        obs = hl.observation(profile, load, counter, work, monotonic=True)
    phase = obs["phases"][0]
    assert phase["written"]["alert"] > 0 and phase["alerts_decided"] == phase["written"]["alert"]
    shed, problems = hl._audit_problems(obs["ingress_audit"], QUOTA)
    assert problems == [] and shed
    assert sum(r["oversized_lines_skipped"] for r in shed) == phase["written"]["oversized"] > 0
    assert sum(r["shed_total"] for r in shed) > 0
    assert all(r["alerts_shed"] == 0 for r in shed)


def test_a_burst_phase_is_written_in_bursts(tmp_path):
    """The backlog phase must reach the core as bursts, not as a smooth stream."""

    phase = {
        "name": "burst", "oversized_line_bytes": 0, "burst_interval_ms": 500,
        "rates_per_s": {c: 0 for c in decl.HOSTILE_LINE_CLASSES} | {"flow": 200},
    }
    profile = {"phases": [phase], "line_bytes": 100}
    eve = tmp_path / "eve.json"
    eve.write_bytes(b"")
    now = time.time()
    load = hl.HostileLoad(eve, profile, [("burst", now, now + 1.3)], lambda: time.monotonic_ns())
    sizes = set()
    load.start()
    while load.is_alive():
        sizes.add(eve.read_bytes().count(b"\n"))
        time.sleep(0.01)
    sizes.add(eve.read_bytes().count(b"\n"))
    # Lines per burst: 200/s * 0.5 s = 100; only whole bursts are ever seen.
    assert sizes <= {0, 100, 200}, sizes
    assert load.observed[0]["written"]["flow"] == 200


def _ci_record(tmp_path, *, gaps=("SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL",), mutate=None):
    obs = _observation()
    samples = _samples(obs)
    if mutate:
        mutate(obs, samples)
    record = {
        "objective_id": "SO-04",
        "parts": [
            {"name": "rollback_start_after_expiry", "samples": samples, "hostile_load": obs, "gaps": [{"id": g} for g in gaps]},
            {"name": "rollback_completion", "samples": samples, "hostile_load": obs,
             "gaps": [{"id": "SO04-COMPLETION-BOUND-PROVISIONAL"}] + [{"id": g} for g in gaps]},
        ],
    }
    path = tmp_path / "SO-04-x.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return tmp_path


def test_the_ci_check_passes_only_the_declared_load_with_provisional_gaps(tmp_path):
    assert hl.check_records([_ci_record(tmp_path)]) == []
    assert hl.main([str(tmp_path)]) == 0


@pytest.mark.parametrize(
    "kwargs, expect",
    [
        pytest.param({"gaps": ("SO04-HOSTILE-LOAD-UNDECLARED",)}, "gaps beyond", id="hostile-load gap left in"),
        pytest.param({"gaps": ("SO04-LEASE-EXPIRY-ON-WALL-CLOCK",)}, "gaps beyond", id="another gap left in"),
        pytest.param({"mutate": _shed_one_line_each}, "at least", id="the recomputation fails"),
    ],
)
def test_the_ci_check_fails_otherwise(tmp_path, kwargs, expect):
    problems = hl.check_records([_ci_record(tmp_path, **kwargs)])
    assert any(expect in p for p in problems), problems
    assert hl.main([str(tmp_path)]) == 1


def test_the_ci_check_fails_without_a_record(tmp_path):
    assert hl.check_records([tmp_path]) == ["no SO-04 record found"]


@pytest.mark.parametrize("ratio, closes", [(0.85, False), (0.95, True), (1.0, True)])
def test_the_shed_floor_is_the_excess_less_the_declared_tolerance(ratio, closes):
    """Review M1: one phase's shed just below / above (1 - shed_tolerance) x excess."""

    assert PROFILE["shed_tolerance"] == pytest.approx(0.1)
    obs = _observation()
    phase = _phase(obs, "non_alert_flood")
    record = next(r["ingress_shed"] for r in obs["ingress_audit"] if phase["window_start_wall_epoch"] <= r["ingress_shed"]["emitted_epoch"] <= phase["window_end_wall_epoch"])
    shed = int(_excess(phase["written"]) * ratio)
    record.update(shed_total=shed, shed_by_reason={"non_alert_rate": shed, "backlog": 0})
    _resum(obs)
    problems = hl.hostile_load_problems(_samples(obs), obs)
    assert (problems == []) is closes, problems
