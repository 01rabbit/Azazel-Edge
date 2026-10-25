"""The Core ingress quota declaration (OF-06, Edge#414).

``config/service_objectives/ingress_quota.json`` mirrors the limits the core
compiles in (a core unit test keeps them equal). These tests check that the
declaration is provisional, container-derived and cites its basis, that a
malformed or inflated entry declares nothing, and that nothing here adds a
setting that could raise or switch off the bound.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.service_objectives import declarations as decl  # noqa: E402
from azazel_edge.service_objectives import so11_ingress_probe as probe  # noqa: E402

CORE_INGRESS = ROOT / "rust" / "azazel-edge-core" / "src" / "ingress.rs"
CORE_MAIN = ROOT / "rust" / "azazel-edge-core" / "src" / "main.rs"


def _doc():
    return json.loads(decl.INGRESS_QUOTA_PATH.read_text(encoding="utf-8"))


def _write(tmp_path: Path, doc) -> Path:
    path = tmp_path / "ingress_quota.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_the_declaration_is_provisional_container_derived_and_cites_its_basis():
    loaded = decl.load_ingress_quotas()
    assert loaded["problems"] == []
    quota = loaded["quotas"]["core_eve_reader"]
    assert quota["unit"] == "eve_non_alert_lines_per_second"
    assert "Alerts are never shed and never rate-limited" in quota["applies_to"]
    assert quota["status"] == "provisional"
    assert "not hardware" in quota["hardware_class"]
    basis = quota["basis"]
    assert basis["runs"] == len(basis["observed_lines_per_s"])
    assert basis["min_observed_lines_per_s"] == min(basis["observed_lines_per_s"])
    assert quota["value"] <= basis["min_observed_lines_per_s"] / 2
    # The SO-04 harness used to flood at 2000 alerts/s against this value; its
    # hostile load is now derived from it (hostile_load_profile.json).
    assert quota["value"] >= 2000
    assert loaded["sha256"]


def test_the_declaration_matches_the_compiled_limits():
    quota = decl.load_ingress_quotas()["quotas"]["core_eve_reader"]
    src = CORE_INGRESS.read_text(encoding="utf-8")
    block = src[src.index("pub const DECLARED"):]
    block = block[: block.index("};")]

    def num(name):
        m = re.search(rf"{name}: ([0-9_ *]+),", block) or re.search(rf"{name}: Duration::from_(millis|secs)\(([0-9_]+)\),", block)
        assert m, name
        if m.lastindex == 2:
            return int(m.group(2).replace("_", "")) * (1000 if m.group(1) == "secs" else 1)
        return eval(m.group(1).replace("_", ""), {})  # digits, spaces and * only

    assert num("non_alert_per_sec") == quota["value"]
    assert num("non_alert_burst") == quota["non_alert_burst"]
    assert num("alerts_per_poll") == quota["alerts_per_poll"]
    assert num("examine_per_poll") == quota["examine_per_poll"]
    assert num("poll_work_limit") == quota["poll_work_limit_ms"]
    assert num("max_line_bytes") == quota["max_line_bytes"]
    assert num("audit_interval") == quota["audit_interval_ms"]
    assert num("audit_log_cap_bytes") == quota["audit_log_cap_bytes"]
    assert num("backlog_bound_bytes") == quota["backlog_bound_bytes"]
    assert num("alert_backlog_bound_bytes") == quota["alert_backlog_bound_bytes"]


def test_no_setting_raises_or_disables_the_bound():
    ingress = CORE_INGRESS.read_text(encoding="utf-8").split("#[cfg(test)]")[0]
    main = CORE_MAIN.read_text(encoding="utf-8")
    assert "env::" not in ingress and "std::env" not in ingress
    assert "IngressReader::new(offset, IngressLimits::DECLARED)" in main
    assert not re.search(r"AZAZEL_[A-Z_]*(INGRESS|QUOTA|SHED)", main)


@pytest.mark.parametrize(
    "mutate, problem",
    [
        (lambda q: q.update(status="final"), "status"),
        (lambda q: q.update(unit="bytes"), "unit"),
        (lambda q: q.update(value=0), "value"),
        (lambda q: q.update(value=True), "value"),
        (lambda q: q.update(alerts_per_poll=-1), "alerts_per_poll"),
        (lambda q: q.pop("max_line_bytes"), "max_line_bytes"),
        (lambda q: q.pop("hardware_class"), "hardware_class"),
        (lambda q: q.pop("basis"), "basis"),
        (lambda q: q["basis"].pop("margin_rule"), "margin_rule"),
        (lambda q: q.update(value=q["basis"]["min_observed_lines_per_s"] + 1), "above the basis"),
    ],
)
def test_a_bad_entry_declares_nothing(tmp_path, mutate, problem):
    doc = _doc()
    mutate(doc["quotas"][0])
    loaded = decl.load_ingress_quotas(_write(tmp_path, doc))
    assert loaded["quotas"] == {}
    assert any(problem in p for p in loaded["problems"]), loaded["problems"]


def test_a_duplicate_ingress_declares_neither(tmp_path):
    doc = _doc()
    doc["quotas"].append(copy.deepcopy(doc["quotas"][0]))
    loaded = decl.load_ingress_quotas(_write(tmp_path, doc))
    assert loaded["quotas"] == {}
    assert any("declared twice" in p for p in loaded["problems"])


def test_a_missing_or_foreign_file_declares_nothing(tmp_path):
    assert decl.load_ingress_quotas(tmp_path / "absent.json")["quotas"] == {}
    assert decl.load_ingress_quotas(_write(tmp_path, {"schema": "other", "quotas": []}))["quotas"] == {}
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert decl.load_ingress_quotas(bad)["quotas"] == {}


def test_the_probe_without_a_quota_is_not_measurable(monkeypatch, tmp_path):
    monkeypatch.setattr(probe, "load_ingress_quotas", lambda: {"path": "x", "sha256": None, "quotas": {}, "problems": ["absent"]})
    result = probe.run(tmp_path / "no-core")
    assert result["verdict"] == "not_measurable"
    assert result["gaps"][0]["id"] == "SO11-NO-DECLARED-QUOTA"


def test_probe_lines_are_padded_and_typed():
    w = probe._Writer(Path("/dev/null"), 1, 0)
    alert = json.loads(w._line(0, "alert"))
    flow = json.loads(w._line(1, "flow"))
    assert w.alert_rate == probe.ALERT_RATE
    assert alert["event_type"] == "alert" and "alert" in alert
    assert flow["event_type"] == "flow" and "alert" not in flow
    assert abs(len(w._line(2, "alert")) - probe.LINE_BYTES) < 50
