"""Offline guard/accounting controls plus explicitly opt-in Linux namespace trial."""
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

import network_measure_driver as driver
from azazel_edge.benchmark.benefit import BenefitInputError, SAFETY_FIELDS, manifest_digest
from test_benefit_comparison import manifest as base_manifest


def registration(source_commit="a" * 40, core_sha256="b" * 64):
    value = base_manifest()
    value.update(experiment_id="isolated-network-local-pilot", phase="pilot", evidence_kind="recorded_lab",
                 horizon_seconds=5, baseline="c0", candidate="flow_throttle")
    value["provenance"]["repo_commits"] = {"01rabbit/Azazel-Edge": source_commit}
    value["arms"] = [dict(id=arm, role="local_core_observe_only" if arm == "c0" else "existing_flow_scoped_throttle",
                          source_commit=source_commit, config_sha256=manifest_digest(driver.plan(arm, core_sha256)),
                          environment_id="fresh_disposable_linux_netns") for arm in driver.ARMS]
    value["assignments"] = [dict(id=f"{pair}-{arm}", pair_id=str(pair), arm=arm,
        scenario="fixed_service_upload_and_legitimate_tcp", seed=pair, order=(index + pair) % 2)
        for pair in range(2) for index, arm in enumerate(driver.ARMS)]
    safety = {a["id"]: dict.fromkeys(SAFETY_FIELDS, 0) for a in value["assignments"]}
    return value, safety


def test_frozen_plan_budget_safety_and_c0_first_refuse_before_work():
    value, safety = registration()
    assert len(driver.validate(value, safety, driver.SCOPE, "b" * 64)) == 4
    for fault in ("unknown", "positive", "changed_plan", "horizon", "runs", "scope", "hash", "candidate_first", "fictional_role"):
        m, s = copy.deepcopy(value), copy.deepcopy(safety)
        scope, core = driver.SCOPE, "b" * 64
        if fault == "unknown": s[next(iter(s))] = None
        if fault == "positive": s[next(iter(s))]["protected_escape"] = 1
        if fault == "changed_plan": m["arms"][1]["config_sha256"] = "f" * 64
        if fault == "horizon": m["horizon_seconds"] = 30
        if fault == "runs": m["assignments"].pop()
        if fault == "scope": scope = ""
        if fault == "hash": core = ""
        if fault == "fictional_role": m["arms"][1]["role"] = "bounded_block"
        if fault == "candidate_first":
            for a in m["assignments"]:
                if a["pair_id"] == "0": a["order"] = 1 - a["order"]
        with pytest.raises(BenefitInputError): driver.validate(m, s, scope, core)


def peer_audits():
    origin, deadline = 1_000_000_000, 6_000_000_000
    service = dict(kind="audit", nonce="run", started_ns=1, ended_ns=deadline,
                   origin_ns=origin, deadline_ns=deadline, goal_ns=None, legitimate_accepted=6)
    client = dict(kind="client", nonce="run", ended_ns=deadline, objective_ack=True,
                  transactions=[dict(id="legitimate-" + str(i), elapsed_seconds=.3 + i * .6,
                                     duration_ms=1, error=False) for i in range(6)])
    return origin, deadline, service, client


def test_client_ack_never_substitutes_for_service_commit_and_lost_horizon_refuses(monkeypatch):
    monkeypatch.setattr(driver, "read_boot_id", lambda: "unit-test-boot")
    m, safety = registration()
    origin, deadline, service, client = peer_audits()
    capture, receipt = driver.measured_capture(m, m["assignments"][0], "run", safety["0-c0"], origin, deadline, service, client)
    assert receipt["protected_goal_seconds"] is None and receipt["horizon_verified"]
    assert receipt["legitimate_transactions"] == 6
    for fault in ("missing", "early", "nonce", "duplicates", "service_count"):
        s, c = copy.deepcopy(service), copy.deepcopy(client)
        if fault == "missing": s = {}
        if fault == "early": s["ended_ns"] = deadline - 1
        if fault == "nonce": c["nonce"] = "other"
        if fault == "duplicates": c["transactions"][1]["id"] = c["transactions"][0]["id"]
        if fault == "service_count": s["legitimate_accepted"] = 0
        with pytest.raises(BenefitInputError):
            driver.measured_capture(m, m["assignments"][0], "run", safety["0-c0"], origin, deadline, s, c)


def test_failure_preserves_durable_intent_denominator_and_refuses_overwrite(tmp_path, monkeypatch):
    m, safety = registration()
    output = tmp_path / "new"
    monkeypatch.setattr(driver, "prerequisites", lambda *args: {})
    def lost(*args):
        rows = [json.loads(row) for row in (output / "runs.jsonl").read_text().splitlines()]
        assert rows[-1]["event"]["op"] == "start"
        raise RuntimeError("synthetic unit-only missing audit")
    monkeypatch.setattr(driver, "one_run", lost)
    with pytest.raises(RuntimeError):
        driver.run_trial(m, output, safety_by_assignment=safety, scope_acknowledgment=driver.SCOPE,
                         expected_core_sha256="b" * 64)
    failure = json.loads((output / "failure.json").read_text())
    assert failure["snapshot"]["observations"]["runs"] == []
    assert [row["status"] for row in failure["snapshot"]["assignments"]].count("running") == 1
    assert len(failure["snapshot"]["assignments"]) == 4
    assert not list(output.glob("capture-*.json"))
    with pytest.raises(FileExistsError):
        driver.run_trial(m, output, safety_by_assignment=safety, scope_acknowledgment=driver.SCOPE,
                         expected_core_sha256="b" * 64)


def test_no_optin_never_runs_namespace_commands(monkeypatch, tmp_path):
    monkeypatch.setattr(driver, "command", lambda *args, **kwargs: pytest.fail("must refuse before commands"))
    m, safety = registration()
    with pytest.raises(BenefitInputError, match="opt-in"):
        driver.run_trial(m, tmp_path / "none", safety_by_assignment=safety,
                         scope_acknowledgment=driver.SCOPE, expected_core_sha256="b" * 64)
    assert not (tmp_path / "none").exists()


@pytest.mark.skipif(os.environ.get("EDGE_NETWORK_MEASURE_TESTS") != "1", reason="requires reviewed disposable Linux network enforcement opt-in")
def test_actual_c0_and_existing_flow_throttle_network_trial(tmp_path):
    core_sha = os.environ["EDGE_NETWORK_MEASURE_CORE_SHA256"]
    source = os.environ["EDGE_NETWORK_MEASURE_SOURCE_COMMIT"]
    m, safety = registration(source, core_sha)
    # Root/operator must review these closed-lab zeros; they are not product safety observations.
    assert os.environ.get("EDGE_NETWORK_MEASURE_REVIEWED_SCOPE") == driver.SCOPE
    report = driver.run_trial(m, tmp_path / "network-trial", safety_by_assignment=safety,
                             scope_acknowledgment=driver.SCOPE, expected_core_sha256=core_sha, allow_netns=True)
    assert report["comparison"]["assigned_runs"] == 4 and report["comparison"]["complete_pairs"] == 2
    assert report["comparison"]["claim_status"] == "mechanical_only"
    assert report["production_origin_admitted"] is False


def test_owned_readback_requires_exact_tuple_protocol_rate_burst_and_owner():
    parts = [{"match": {"left": {"payload": {"field": field, "protocol": protocol}}, "right": value}}
             for field, value, protocol in (("saddr", driver.ATK, "ip"), ("daddr", driver.SERVER, "ip"),
                                           ("dport", driver.PORT, "tcp"))]
    parts += [{"limit": dict(rate=16, rate_unit="kbytes", burst=16, burst_unit="kbytes", per="second", inv=True)}, {"drop": None}]
    rule = dict(comment="owner", chain="throttle", expr=parts)
    driver.verify_owned_rule(rule, "owner")
    for fault in ("owner", "tuple", "rate", "burst", "drop"):
        broken = copy.deepcopy(rule)
        if fault == "owner": broken["comment"] = "foreign"
        if fault == "tuple": broken["expr"][1]["match"]["right"] = "10.91.3.99"
        if fault == "rate": broken["expr"][3]["limit"]["rate"] = 32
        if fault == "burst": broken["expr"][3]["limit"]["burst"] = 32
        if fault == "drop": broken["expr"].pop()
        with pytest.raises(BenefitInputError): driver.verify_owned_rule(broken, "owner")
