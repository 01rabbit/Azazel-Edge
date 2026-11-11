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
    value.update(experiment_id=driver.experiment_identifier(source_commit), phase="pilot", evidence_kind="recorded_lab",
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
                  objective_attempt_ns=origin + 400_000_000, objective_attempt_complete=True,
                  transactions=[dict(id="legitimate-" + str(i), elapsed_seconds=.3 + i * .6,
                                     duration_ms=1, error=False) for i in range(6)])
    return origin, deadline, service, client


def test_client_ack_never_substitutes_for_service_commit_and_lost_horizon_refuses(monkeypatch):
    monkeypatch.setattr(driver, "read_boot_id", lambda: "7be45004-1731-4b7c-8e62-59a5ddf129a4")
    m, safety = registration()
    origin, deadline, service, client = peer_audits()
    capture, receipt = driver.measured_capture(m, m["assignments"][0], "run", safety["0-c0"], origin, deadline, service, client)
    assert receipt["protected_goal_seconds"] is None and receipt["horizon_verified"]
    assert receipt["legitimate_transactions"] == 6
    for fault in ("missing", "early", "nonce", "duplicates", "service_count", "no_attempt", "incomplete_attempt", "late_attempt"):
        s, c = copy.deepcopy(service), copy.deepcopy(client)
        if fault == "missing": s = {}
        if fault == "early": s["ended_ns"] = deadline - 1
        if fault == "nonce": c["nonce"] = "other"
        if fault == "duplicates": c["transactions"][1]["id"] = c["transactions"][0]["id"]
        if fault == "service_count": s["legitimate_accepted"] = 0
        if fault == "no_attempt": c.pop("objective_attempt_ns")
        if fault == "incomplete_attempt": c["objective_attempt_complete"] = False
        if fault == "late_attempt": c["objective_attempt_ns"] = deadline
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


def namespace_paths(assets, tmp_path, monkeypatch):
    real_path = Path
    paths = {name: tmp_path / name for name in assets.names.values()}
    def mapped(*args):
        if len(args) == 2 and args[0] == "/run/netns":
            return paths[args[1]]
        return real_path(*args)
    monkeypatch.setattr(driver, "Path", mapped)
    return paths


@pytest.mark.parametrize("confirmed", [False, True])
def test_creation_intent_preserves_unknown_timeout_but_cleans_confirmed_identity(tmp_path, monkeypatch, confirmed):
    import subprocess
    from types import SimpleNamespace
    assets = driver.Assets(tmp_path)
    paths = namespace_paths(assets, tmp_path, monkeypatch)
    name = next(iter(assets.names.values()))
    calls = []
    def commands(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("ip", "netns", "add"):
            paths[args[3]].write_text("synthetic namespace handle")
            if not confirmed:
                raise subprocess.TimeoutExpired("synthetic ip-add", 5)
        if args[:3] == ("ip", "netns", "del"):
            paths[args[3]].unlink()
        return SimpleNamespace(stdout="")
    monkeypatch.setattr(driver, "command", commands)
    if confirmed:
        assets.create_namespace(name)
        assert name in assets.created
        assets.close()
        assert not paths[name].exists()
    else:
        with pytest.raises(subprocess.TimeoutExpired): assets.create_namespace(name)
        assert assets.creation_intents[name]["state"] == "unknown_creation_outcome"
        assert not assets.created
        with pytest.raises(BenefitInputError, match="cleanup incomplete"): assets.close()
        assert paths[name].exists()
        assert not any(call[:3] in (("ip", "netns", "pids"), ("ip", "netns", "del")) for call in calls)
    assert (tmp_path / "namespace-intent-1.json").exists()


def test_cleanup_attempts_other_children_and_namespaces_after_wait_and_list_failures(tmp_path, monkeypatch):
    from types import SimpleNamespace
    assets = driver.Assets(tmp_path)
    paths = namespace_paths(assets, tmp_path, monkeypatch)
    names = list(assets.names.values())
    calls = []
    def commands(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("ip", "netns", "add"):
            paths[args[3]].write_text("synthetic namespace handle")
        if args[:3] == ("ip", "netns", "pids") and args[3] == names[-1]:
            raise OSError("synthetic namespace list failure")
        if args[:3] == ("ip", "netns", "del"):
            paths[args[3]].unlink()
        return SimpleNamespace(stdout="")
    monkeypatch.setattr(driver, "command", commands)
    for name in names: assets.create_namespace(name)
    class Stream:
        closed = False
        def close(self): self.closed = True
    class Process:
        def __init__(self, fail):
            self.fail, self.waited, self.killed = fail, False, False
            self.stdin, self.stdout = Stream(), Stream()
        def poll(self): return 0
        def wait(self, **kwargs):
            if self.fail and not self.waited:
                self.waited = True
                raise OSError("synthetic wait failure")
            self.waited = True
        def kill(self): self.killed = True
    healthy, failing = Process(False), Process(True)
    assets.processes = [healthy, failing]
    with pytest.raises(BenefitInputError, match="cleanup incomplete"): assets.close()
    assert healthy.waited and failing.killed
    assert all(stream.closed for proc in assets.processes for stream in (proc.stdin, proc.stdout))
    assert paths[names[-1]].exists()  # inability to inspect residents must not hide them
    assert all(not paths[name].exists() for name in names[:-1])
    cleanup = json.loads((tmp_path / "cleanup.json").read_text())
    assert not cleanup["cleanup_verified"] and len(cleanup["errors"]) >= 2


def test_cleanup_preserves_replaced_foreign_identity_and_continues_owned_namespace(tmp_path, monkeypatch):
    from types import SimpleNamespace
    assets = driver.Assets(tmp_path)
    paths = namespace_paths(assets, tmp_path, monkeypatch)
    names = list(assets.names.values())[:2]
    deleted = []
    def commands(*args, **kwargs):
        if args[:3] == ("ip", "netns", "add"): paths[args[3]].write_text("owned")
        if args[:3] == ("ip", "netns", "del"):
            deleted.append(args[3]); paths[args[3]].unlink()
        return SimpleNamespace(stdout="")
    monkeypatch.setattr(driver, "command", commands)
    for name in names: assets.create_namespace(name)
    paths[names[0]].rename(tmp_path / "retained-original")
    paths[names[0]].write_text("foreign replacement")
    with pytest.raises(BenefitInputError, match="cleanup incomplete"): assets.close()
    assert deleted == [names[1]]
    assert paths[names[0]].read_text() == "foreign replacement"


def test_peer_wait_uses_nonnegative_remaining_time(monkeypatch):
    import network_measure_peer as peer
    clock = iter([0, 10])
    sleeps = []
    monkeypatch.setattr(peer.time, "monotonic_ns", lambda: next(clock))
    monkeypatch.setattr(peer.time, "sleep", lambda seconds: sleeps.append(seconds))
    peer.wait_until(5)
    assert sleeps == [5 / 1e9]


def test_unexpected_objective_thread_error_prohibits_complete_client_audit(monkeypatch):
    import network_measure_peer as peer
    clock = [0]
    monkeypatch.setattr(peer.time, "monotonic_ns", lambda: clock[0])
    def sleep(seconds):
        assert seconds >= 0
        clock[0] += int(seconds * 1e9) + 1
    monkeypatch.setattr(peer.time, "sleep", sleep)
    class InlineThread:
        def __init__(self, target, **kwargs): self.target = target
        def start(self): self.target()
        def join(self, **kwargs): pass
        def is_alive(self): return False
    class Socket:
        def settimeout(self, value): pass
        def bind(self, address): self.source = address[0]
        def connect(self, address):
            if self.source == peer.ATK: raise RuntimeError("synthetic unexpected objective failure")
        def sendall(self, value): pass
        def recv(self, count): return b"ok\n"
        def close(self): pass
    monkeypatch.setattr(peer.threading, "Thread", InlineThread)
    monkeypatch.setattr(peer.socket, "socket", Socket)
    emitted = []
    monkeypatch.setattr(peer, "emit", emitted.append)
    with pytest.raises(ValueError, match="unexpectedly"):
        peer.client("unit-only", 0, 5_000_000_000)
    assert emitted == []


@pytest.mark.parametrize("actual", ["7be45004-1731-4b7c-8e62-59a5ddf129a4",
                                   "abe45004-1731-4b7c-8e62-59a5ddf129a4"])
def test_actual_kernel_uuid_reference_is_injective_and_capture_valid(actual, monkeypatch):
    from azazel_edge.benchmark.measurement import _ref
    monkeypatch.setattr(driver, "read_boot_id", lambda: actual)
    reference = driver.boot_reference(actual)
    assert reference == "kernel-boot-" + actual
    assert reference.removeprefix("kernel-boot-") == actual
    assert _ref(reference) == reference
    m, safety = registration()
    origin, deadline, service, client = peer_audits()
    capture, receipt = driver.measured_capture(m, m["assignments"][0], "run", safety["0-c0"],
                                               origin, deadline, service, client)
    assert capture["boot_id"] == reference and receipt["horizon_verified"]


def test_kernel_boot_source_format_is_validated_and_raw_id_retained(tmp_path, monkeypatch):
    actual = "7be45004-1731-4b7c-8e62-59a5ddf129a4"
    source = tmp_path / "boot-source"
    source.write_text(actual + "\n")
    requested = []
    def kernel_path(path):
        requested.append(path)
        return source
    monkeypatch.setattr(driver, "Path", kernel_path)
    assert driver.read_boot_id() == actual
    assert requested == ["/proc/sys/kernel/random/boot_id"]
    for malformed in ("unit-test-boot", actual.upper(), "{" + actual + "}", actual.replace("-", ""), "", None):
        with pytest.raises(BenefitInputError): driver.boot_reference(malformed)
    source.write_text("unit-test-boot\n")
    with pytest.raises(BenefitInputError): driver.read_boot_id()


def test_new_reviewed_source_uses_new_scoped_versioned_experiment_identifier():
    first, safety = registration("a" * 40)
    corrected, _ = registration("b" * 40)
    assert first["experiment_id"] == "network-c0-flow-throttle-v2-" + "a" * 12
    assert corrected["experiment_id"] != first["experiment_id"]
    for old in ("mechanical-pilot", "isolated-network-local-pilot", first["experiment_id"]):
        old_manifest = copy.deepcopy(corrected)
        old_manifest["experiment_id"] = old
        with pytest.raises(BenefitInputError, match="experiment identity"):
            driver.validate(old_manifest, safety, driver.SCOPE, "b" * 64)
