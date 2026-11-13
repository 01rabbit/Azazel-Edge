"""SYNTHETIC kernel/Root receipts. Real pure SoT validation, no daemon or BPF."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_edge.benchmark import authority_ingress as a
from azazel_edge.benchmark import authority_ingress_collection as intake
from azazel_edge.benchmark import safety_collection
from azazel_edge.outcome.journal import _json

CORPUS = json.loads(
    (Path(__file__).parent / "fixtures/authority-ingress/v1/cases.json").read_bytes()
)
BOOT = "00000000-0000-4000-8000-000000000001"


def wire(value):
    return _json(value) + b"\n"


def build(case_id="root_patch"):
    recipe = next(x for x in CORPUS["cases"] if x["case_id"] == case_id)
    positive = case_id in ("root_patch", "observer_loss", "missing_readback")
    denied = case_id in ("advisory_dac_denied", "spoofed_root_dac_denied")
    before = CORPUS["before_sot_utf8"].encode()
    audit = b""
    after = before
    if positive:
        candidate = json.loads(before)
        candidate["devices"][0]["hostname"] = "client-1-observed"
        after = (
            json.dumps(a.SoTConfig.from_dict(candidate).to_dict(), indent=2) + "\n"
        ).encode()
        audit = wire(
            dict(
                kind="sot_devices_patched",
                ts=1.5,
                source="control_daemon",
                peer_uid=0,
                path="/run/lab/sot.json",
                device_count=1,
                patched_count=1,
                diff=dict(added=0, removed=0, updated=1),
            )
        )
    endpoint = dict(
        path="/run/lab/control.sock",
        parent_before=dict(device=4, inode=80, uid=0, gid=2000, mode=0o750, nlink=2),
        socket_before=dict(device=4, inode=90, uid=0, gid=2000, mode=0o660, nlink=1),
        before_sample_ns=30,
        after_sample_ns=750,
        control_gid=2000,
    )
    endpoint.update(
        parent_after=deepcopy(endpoint["parent_before"]),
        socket_after=deepcopy(endpoint["socket_before"]),
    )
    actor = dict(
        pid=60,
        uid=1000 if denied else 0,
        gid=1000 if denied else 0,
        groups=[],
        start_ticks=5,
        pidns_device=4,
        pidns_inode=42,
        netns_inode=99,
        code_sha256="c" * 64,
        started_ns=50,
        exited_ns=600,
        returncode=0,
        forced=False,
        error=None,
    )
    config = dict(
        pidns_device=4,
        pidns_inode=42,
        actor_start_ticks=5,
        started_ns=100,
        deadline_ns=1000,
        actor_tgid=60,
        actor_uid=actor["uid"],
        user_hz=100,
        max_events=16,
    )
    path = (
        "/run/lab/unrelated.sock" if case_id == "unrelated_path" else endpoint["path"]
    )
    event = dict(
        at_ns=300,
        start_ns=50_000_001,
        client_inode=70,
        peer_inode=0 if denied else 91 if case_id == "unrelated_path" else 90,
        tgid=60,
        tid=60,
        uid=actor["uid"],
        peer_major=0,
        peer_minor=0 if denied else 4,
        netns_inode=99,
        ret=-13 if denied else 0,
        addr_len=len(path) + 3,
        path=path,
        reserved=0,
    )
    probe = dict(
        schema_version="edge-authority-ingress-probe/v1",
        architecture="aarch64",
        started_ns=100,
        finished_ns=1050,
        configuration=deepcopy(config),
        events=[event],
        counters=dict(
            observed=1, emitted=1, overflow=0, identity_failure=0, read_failure=0
        ),
        partial_reasons=[],
        link_identity=dict(
            fd=7,
            type=2,
            link_id=8,
            prog_id=9,
            attach_type=25,
            target_obj_id=0,
            target_btf_id=10,
        ),
    )
    if case_id == "observer_loss":
        probe.update(partial_reasons=["observer_link_lost"], link_identity=None)
    raws = dict(
        sot_before_raw=before,
        sot_after_raw=after,
        audit_before_raw=b"",
        audit_after_raw=audit,
    )
    samples = {"before": {}, "after": {}}
    for phase in samples:
        for index, kind in enumerate(("sot", "audit")):
            value = raws[kind + "_" + phase + "_raw"]
            identity = dict(
                device=4,
                inode=10
                + index
                + (10 if positive and phase == "after" and kind == "sot" else 0),
                uid=0,
                gid=0,
                mode=0o644,
                nlink=1,
                size=len(value),
                mtime_ns=2 if positive and phase == "after" else 1,
                ctime_ns=2 if positive and phase == "after" else 1,
            )
            samples[phase][kind] = dict(
                sha256=a._sha(value),
                read_started_ns=10 if phase == "before" else 800,
                read_finished_ns=20 if phase == "before" else 810,
                identity=identity,
            )
    if case_id == "missing_readback":
        raws["sot_after_raw"] = None
        samples["after"]["sot"] = None
    plan = dict(
        schema_version="edge-authority-ingress-plan/v1",
        capture_id="SYNTHETIC-authority-capture",
        case_id=case_id,
        kernel_boot_id=BOOT,
        request_utf8=recipe["request_utf8"],
        request_sha256=a._sha(recipe["request_utf8"].encode()),
        requested_path=path,
        target_paths=dict(sot="/run/lab/sot.json", audit="/run/lab/sot-events.jsonl"),
        control_endpoint=endpoint,
        actor=actor,
        server=dict(
            pid=50,
            uid=0,
            start_ticks=4,
            code_sha256="d" * 64,
            started_ns=1,
            handlers_joined_ns=650,
            exited_ns=700,
            returncode=0,
            forced=False,
            error=None,
        ),
        go=dict(release_before_ns=150, release_after_ns=160),
        configuration=config,
        samples=samples,
        probe_sha256=a._sha(wire(probe)),
        observer_source_sha256="a" * 64,
        observer_object_sha256="b" * 64,
    )
    # Monotonic receipts are real nanosecond-scale relative times; leader birth
    # remains the separately represented kernel 50_000_001ns/startticks5.
    for owner, fields in (
        (actor, ("started_ns", "exited_ns")),
        (plan["server"], ("started_ns", "handlers_joined_ns", "exited_ns")),
        (plan["go"], ("release_before_ns", "release_after_ns")),
        (endpoint, ("before_sample_ns", "after_sample_ns")),
        (config, ("started_ns", "deadline_ns")),
        (probe, ("started_ns", "finished_ns")),
        (probe["configuration"], ("started_ns", "deadline_ns")),
        (event, ("at_ns",)),
    ):
        for field in fields:
            owner[field] *= 1_000_000
    for phase in samples.values():
        for descriptor in phase.values():
            if descriptor is not None:
                descriptor["read_started_ns"] *= 1_000_000
                descriptor["read_finished_ns"] *= 1_000_000
    plan["probe_sha256"] = a._sha(wire(probe))
    return dict(plan=plan, probe=probe, **raws)


def evaluate(case):
    plan = wire(case["plan"])
    return a.verify_authority_ingress_observation(
        plan,
        expected_plan_sha256=a._sha(plan),
        probe_raw=wire(case["probe"]) if case["probe"] is not None else None,
        **{k: v for k, v in case.items() if k.endswith("_raw")},
    )


def refresh(case):
    case["plan"]["probe_sha256"] = (
        a._sha(wire(case["probe"])) if case["probe"] is not None else None
    )
    for phase in ("before", "after"):
        for kind in ("sot", "audit"):
            value = case[kind + "_" + phase + "_raw"]
            if value is not None and case["plan"]["samples"][phase][kind] is not None:
                descriptor = case["plan"]["samples"][phase][kind]
                descriptor["sha256"] = a._sha(value)
                descriptor["identity"]["size"] = len(value)


@pytest.mark.parametrize("recipe", CORPUS["cases"], ids=lambda x: x["case_id"])
def test_six_frozen_recipes_synthetic_kernel_and_samples(recipe):
    case = build(recipe["case_id"])
    original = deepcopy(case)
    result = evaluate(case)
    expected = recipe["expected"]
    assert case == original
    assert result["object_changes"] == expected["object_changes"]
    assert (
        result["sampled_originals_unchanged"] is expected["sampled_originals_unchanged"]
    )
    assert (
        result["permitted_hostname_patch_consistent"]
        is expected["permitted_hostname_patch_consistent"]
    )
    assert result["connection_disposition"] == (
        "unrelated_path_observed"
        if recipe["case_id"] == "unrelated_path"
        else expected["connection_observation"]
    )
    assert result["coverage_disposition"] == (
        "unknown"
        if recipe["case_id"] in ("observer_loss", "missing_readback")
        else "finite_case_consistent"
    )
    assert len(result["verified_connection_events"]) == 1
    assert (
        result["application_peer_refusal_verified"] is False
        and result["qualified_safety_count"] is None
    )
    assert all(result[key] is False for key in a.safety.FLAGS)


@pytest.mark.parametrize(
    "fault",
    [
        "missing_probe",
        "bad_stats",
        "missing_link",
        "cleanup",
        "bad_lifecycle",
        "missing_sot",
        "bad_sot_hash",
        "bad_endpoint",
    ],
)
def test_independent_known_changes_and_connections_never_globally_wiped(fault):
    case = build()
    if fault == "missing_probe":
        case["probe"] = None
    elif fault == "bad_stats":
        case["probe"]["counters"] = None
    elif fault == "missing_link":
        case["probe"]["link_identity"] = None
    elif fault == "cleanup":
        case["probe"]["partial_reasons"] = ["observer_cleanup_unverified"]
    elif fault == "bad_lifecycle":
        case["plan"]["server"]["returncode"] = 1
    elif fault == "missing_sot":
        case["sot_after_raw"] = None
        case["plan"]["samples"]["after"]["sot"] = None
    elif fault == "bad_sot_hash":
        case["plan"]["samples"]["after"]["sot"]["sha256"] = "f" * 64
    elif fault == "bad_endpoint":
        case["plan"]["control_endpoint"]["socket_after"]["inode"] = 91
    if fault != "bad_sot_hash":
        refresh(case)
    result = evaluate(case)
    assert result["object_changes"]["audit"] is True
    assert result["sampled_originals_unchanged"] is False
    assert result["coverage_disposition"] == "unknown"
    if fault not in ("missing_probe", "bad_endpoint"):
        assert result["connection_disposition"] == "control_connected"
    if fault == "bad_endpoint":
        assert len(result["verified_connection_events"]) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_uid",
        "wrong_pid",
        "wrong_start",
        "wrong_netns",
        "bad_addrlen",
        "nul_path",
        "abstract_path",
        "after_exit",
        "before_go",
        "bool_ret",
        "wrong_config",
    ],
)
def test_bad_kernel_binding_unknown_not_daemon_admission(fault):
    case = build()
    event = case["probe"]["events"][0]
    if fault == "wrong_uid":
        event["uid"] = 1000
    elif fault == "wrong_pid":
        event["tgid"] = 61
    elif fault == "wrong_start":
        event["start_ns"] += 10_000_000
    elif fault == "wrong_netns":
        event["netns_inode"] += 1
    elif fault == "bad_addrlen":
        event["addr_len"] -= 1
    elif fault == "nul_path":
        event["path"] += "\x00"
    elif fault == "abstract_path":
        event["path"] = "@control"
    elif fault == "after_exit":
        event["at_ns"] = case["plan"]["actor"]["exited_ns"] + 1
    elif fault == "before_go":
        event["at_ns"] = case["plan"]["go"]["release_before_ns"] - 1
    elif fault == "bool_ret":
        event["ret"] = False
    elif fault == "wrong_config":
        case["probe"]["configuration"]["pidns_inode"] += 1
    refresh(case)
    result = evaluate(case)
    assert result["connection_disposition"] == "unknown"
    assert result["permitted_hostname_patch_consistent"] is None
    assert result["object_changes"]["sot"] is True


@pytest.mark.parametrize("fault", ["inode", "major", "minor", "path_reuse"])
def test_peer_filesystem_incarnation_not_inferred_from_path(fault):
    case = build()
    event = case["probe"]["events"][0]
    if fault == "inode":
        event["peer_inode"] += 1
    elif fault == "major":
        event["peer_major"] += 1
    elif fault == "minor":
        event["peer_minor"] += 1
    else:
        case["plan"]["control_endpoint"]["socket_after"]["inode"] += 1
    refresh(case)
    result = evaluate(case)
    assert result["connection_disposition"] == "unknown"
    assert len(result["verified_connection_events"]) == 1
    assert result["permitted_hostname_patch_consistent"] is None


def test_linux_device_encoding_replays_independent_of_host_os():
    case = build()
    major, minor = 259, 65537
    encoded = (
        ((major & 0xFFF) << 8)
        | ((major & 0xFFFFF000) << 32)
        | (minor & 0xFF)
        | ((minor & 0xFFFFFF00) << 12)
    )
    for phase in ("before", "after"):
        case["plan"]["control_endpoint"]["socket_" + phase]["device"] = encoded
    case["probe"]["events"][0].update(peer_major=major, peer_minor=minor)
    refresh(case)
    assert evaluate(case)["connection_disposition"] == "control_connected"


@pytest.mark.parametrize(
    "fault",
    [
        "extra_device_change",
        "wrong_audit_path",
        "wrong_peer_uid",
        "bool_diff",
        "malformed_audit",
        "audit_missing",
    ],
)
def test_patch_readback_must_bind_full_typed_derivative_and_actual_audit(fault):
    case = build()
    if fault == "extra_device_change":
        after = json.loads(case["sot_after_raw"])
        after["devices"][0]["criticality"] = "high"
        case["sot_after_raw"] = wire(after)
    elif fault == "audit_missing":
        case["audit_after_raw"] = None
        case["plan"]["samples"]["after"]["audit"] = None
    elif fault == "malformed_audit":
        case["audit_after_raw"] = b"malformed\n"
    else:
        audit = json.loads(case["audit_after_raw"])
        if fault == "wrong_audit_path":
            audit["path"] = "/run/lab/other.json"
        elif fault == "wrong_peer_uid":
            audit["peer_uid"] = 1000
        elif fault == "bool_diff":
            audit["diff"]["updated"] = True
        case["audit_after_raw"] = wire(audit)
    refresh(case)
    result = evaluate(case)
    assert result["object_changes"]["sot"] is True
    assert result["permitted_hostname_patch_consistent"] is None
    assert result["connection_disposition"] == "control_connected"


@pytest.mark.parametrize(
    "fault",
    [
        "empty_made_missing",
        "unknown_read",
        "wrong_owner",
        "late_before",
        "early_after",
        "changed_metadata",
    ],
)
def test_sampled_negative_equality_is_not_inferred(fault):
    case = build("advisory_dac_denied")
    d = case["plan"]["samples"]["after"]["audit"]
    if fault == "empty_made_missing":
        case["audit_after_raw"] = None
    elif fault == "unknown_read":
        d["sha256"] = "f" * 64
    elif fault == "wrong_owner":
        d["identity"]["uid"] = 1000
    elif fault == "late_before":
        case["plan"]["samples"]["before"]["audit"]["read_finished_ns"] = (
            case["plan"]["go"]["release_before_ns"] + 1
        )
    elif fault == "early_after":
        d["read_started_ns"] = case["plan"]["server"]["exited_ns"] - 1
    elif fault == "changed_metadata":
        d["identity"]["mtime_ns"] += 1
    result = evaluate(case)
    assert result["sampled_originals_unchanged"] is (
        False if fault == "changed_metadata" else None
    )
    assert result["application_peer_refusal_verified"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "bool",
        "duplicate",
        "depth",
        "nonfinite",
        "oversize",
        "wrong_hash",
        "request_mutated",
    ],
)
def test_global_plan_errors_never_mean_refusal(fault):
    case = build()
    if fault == "bool":
        case["plan"]["actor"]["pid"] = True
    elif fault == "request_mutated":
        case["plan"]["request_utf8"] = "{}\n"
        case["plan"]["request_sha256"] = a._sha(b"{}\n")
    raw = wire(case["plan"])
    if fault == "duplicate":
        raw = b'{"case_id":"other",' + raw[1:]
    elif fault == "depth":
        raw = b'{"x":' + b"[" * 34 + b"0" + b"]" * 34 + b"}\n"
    elif fault == "nonfinite":
        raw = raw.replace(b'"started_ns":100000000', b'"started_ns":1e400', 1)
    elif fault == "oversize":
        raw = b" " * 32769
    pin = "a" * 64 if fault == "wrong_hash" else a._sha(raw)
    with pytest.raises(a.AuthorityIngressInputError):
        a.verify_authority_ingress_observation(
            raw,
            expected_plan_sha256=pin,
            probe_raw=None,
            sot_before_raw=None,
            sot_after_raw=None,
            audit_before_raw=None,
            audit_after_raw=None,
        )


def test_pure_diagnostic_no_files_processes_or_persistence(monkeypatch):
    import builtins
    import subprocess

    case = build()

    def forbidden(*args, **kwargs):
        raise AssertionError("pure verifier attempted side effects")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert evaluate(case)["permitted_hostname_patch_consistent"] is True


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "reader_root",
        "reader_actor",
        "boot",
        "enrollment_pin",
        "none_binding",
        "close",
        "final_race",
    ],
)
def test_synthetic_sealed_collector_independent_reader_and_failures(monkeypatch, fault):
    case = build("missing_readback" if fault == "none_binding" else "root_patch")
    files = {"/sealed/plan": wire(case["plan"]), "/sealed/probe": wire(case["probe"])}
    paths = dict(plan="/sealed/plan", probe="/sealed/probe")
    for kind in ("sot", "audit"):
        for phase in ("before", "after"):
            name = kind + "_" + phase
            value = case[name + "_raw"]
            paths[name] = "/sealed/" + name if value is not None else None
            if value is not None:
                files[paths[name]] = value
    if fault == "none_binding":
        paths["sot_after"] = "/sealed/sot_before"
    enrollment = dict(
        schema_version="edge-authority-ingress-enrollment/v1",
        plan_sha256=a._sha(files["/sealed/plan"]),
        reader_uid=65533,
        kernel_boot_id=BOOT,
        paths=paths,
    )
    files["/sealed/enrollment"] = wire(enrollment)
    calls = []

    class Held:
        checks = 0

        def read(self, path, maximum):
            calls.append(path)
            assert len(files[path]) <= maximum
            return files[path]

        def verify(self):
            self.checks += 1
            if fault == "final_race" and self.checks == 2:
                raise ValueError("SYNTHETIC final metadata failure")

        def close(self):
            calls.append("closed")
            return ["OSError"] if fault == "close" else []

    uid = (
        0
        if fault == "reader_root"
        else case["plan"]["actor"]["uid"]
        if fault == "reader_actor"
        else 65533
    )
    monkeypatch.setattr(intake, "os", SimpleNamespace(geteuid=lambda: uid))
    monkeypatch.setattr(
        safety_collection,
        "_kernel_boot_id",
        lambda: "other" if fault == "boot" else BOOT,
    )
    monkeypatch.setattr(safety_collection, "_HeldFiles", Held)
    args = dict(
        expected_enrollment_sha256="a" * 64
        if fault == "enrollment_pin"
        else a._sha(files["/sealed/enrollment"]),
        expected_plan_sha256=enrollment["plan_sha256"],
    )
    if fault:
        with pytest.raises(safety_collection.SafetyCollectionError):
            intake.collect_authority_ingress_observation("/sealed/enrollment", **args)
    else:
        result = intake.collect_authority_ingress_observation(
            "/sealed/enrollment", **args
        )
        assert result["evaluation"]["permitted_hostname_patch_consistent"] is True
        assert set(calls[:-1]) == set(files)
    assert calls[-1] == "closed"


def test_conflicting_exact_leader_start_in_same_coarse_tick_withholds_consistency():
    case = build()
    second = dict(
        case["probe"]["events"][0],
        start_ns=50_000_002,
        at_ns=case["probe"]["events"][0]["at_ns"] + 1,
    )
    case["probe"]["events"].append(second)
    case["probe"]["counters"].update(observed=2, emitted=2)
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_connection_events"]) == 2
    assert "kernel_start_identity_conflict" in result["reasons"]
    assert result["coverage_disposition"] == "unknown"
    assert result["object_changes"] == {"sot": True, "audit": True}


def test_boottime_birth_after_monotonic_event_is_not_a_cross_clock_rejection():
    case = build()
    event = case["probe"]["events"][0]
    # Kernel leader birth is BOOTTIME; event entry is MONOTONIC. A suspend
    # offset can legitimately make birth numerically larger, even with zero
    # time-namespace offsets. Root proc-tick identity is separately pinned.
    event["start_ns"] = event["at_ns"] + 1_000_000_001
    tick = event["start_ns"] // 10_000_000
    case["plan"]["actor"]["start_ticks"] = tick
    case["plan"]["configuration"]["actor_start_ticks"] = tick
    case["probe"]["configuration"]["actor_start_ticks"] = tick
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_connection_events"]) == 1
    assert result["connection_disposition"] == "control_connected"
    assert result["coverage_disposition"] == "finite_case_consistent"
    assert result["object_changes"]["sot"] is True


@pytest.mark.parametrize("count", [None, True, 0, 2])
def test_patch_audit_count_is_exact_actual_writer_integer_one(count):
    case = build()
    audit = json.loads(case["audit_after_raw"])
    if count is None:
        audit.pop("patched_count")
    else:
        audit["patched_count"] = count
    case["audit_after_raw"] = wire(audit)
    refresh(case)
    result = evaluate(case)
    assert result["permitted_hostname_patch_consistent"] is None
    assert result["object_changes"]["sot"] is True


def test_real_unchanged_sot_writer_audit_shape_binds_readback(tmp_path, monkeypatch):
    # Local software-writer contract only: peer UID is a direct test argument,
    # NOT a claim of real socket admission or actual Root ownership.
    from azazel_edge_control import daemon

    case = build()
    sot, audit = tmp_path / "sot.json", tmp_path / "sot-events.jsonl"
    sot.write_bytes(case["sot_before_raw"])
    audit.write_bytes(b"")
    monkeypatch.setenv("AZAZEL_SOT_PATH", str(sot))
    monkeypatch.setattr(daemon, "SOT_AUDIT_LOG", audit)
    request = json.loads(case["plan"]["request_utf8"])
    result = daemon._sot_devices_edit(
        "sot_devices_patch", request["params"], peer_uid=0
    )
    assert result["ok"] is True
    actual = json.loads(audit.read_bytes())
    assert actual["patched_count"] == 1
    case["plan"]["target_paths"] = {"sot": str(sot), "audit": str(audit)}
    case["sot_after_raw"], case["audit_after_raw"] = (
        sot.read_bytes(),
        audit.read_bytes(),
    )
    refresh(case)
    assert evaluate(case)["permitted_hostname_patch_consistent"] is True
