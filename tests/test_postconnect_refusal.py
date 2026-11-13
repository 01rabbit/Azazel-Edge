"""SYNTHETIC kernel-copy/Root metadata; no internal Python branch observation."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from azazel_edge.benchmark import postconnect_refusal as p
from azazel_edge.outcome.journal import _json
from test_authority_ingress import build as authority_case, refresh

CORPUS = json.loads(
    (Path(__file__).parent / "fixtures/postconnect-refusal/v1/cases.json").read_bytes()
)


def wire(value):
    return _json(value) + b"\n"


def data(event, raw):
    event.update(chunk=len(raw), ret=len(raw), skb_len=len(raw), data_hex=raw.hex())


def build(case_id="root_patch"):
    negative = case_id in p.REFUSALS
    case = authority_case(
        "missing_readback" if case_id == "missing_after_sot" else "root_patch"
    )
    plan = case["plan"]
    if negative:
        for kind in ("sot", "audit"):
            case[kind + "_after_raw"] = case[kind + "_before_raw"]
            descriptor = plan["samples"]["after"][kind]
            descriptor["identity"] = deepcopy(
                plan["samples"]["before"][kind]["identity"]
            )
    recipe = next(x for x in CORPUS["cases"] if x["case_id"] == case_id)
    plan.update(
        schema_version="edge-postconnect-refusal-plan/v1",
        case_id=case_id,
        request_utf8=recipe["request_utf8"],
        request_sha256=p._sha(recipe["request_utf8"].encode()),
    )
    cfg = plan["configuration"]
    cfg.pop("actor_uid")
    cfg.update(
        server_tgid=plan["server"]["pid"],
        server_start_ticks=plan["server"]["start_ticks"],
    )
    response = (
        {"ok": False, "error": p.REFUSALS[case_id], "ts": 1.5}
        if negative
        else {
            "ok": True,
            "path": plan["target_paths"]["sot"],
            "diff": {"added": 0, "removed": 0, "updated": 1},
            "audit_logged": True,
            "ts": 1.5,
        }
    )
    # Real daemon uses original insertion-order/spaced JSON, not sorted wire.
    response_raw = (json.dumps(response, ensure_ascii=False) + "\n").encode()
    events = []
    for role, payload in ((0, plan["request_utf8"].encode()), (1, response_raw)):
        worker = plan["server"] if role == 0 else plan["actor"]
        event = dict(
            entered_ns=300_000_000 if role == 0 else 350_000_000,
            exited_ns=310_000_000 if role == 0 else 360_000_000,
            start_ns=worker["start_ticks"] * 10_000_000 + 1,
            receiver_inode=500 if role == 0 else 600,
            peer_inode=600 if role == 0 else 500,
            endpoint_inode=90,
            role=role,
            tgid=worker["pid"],
            tid=worker["pid"],
            uid=0,
            euid=0,
            netns_inode=plan["actor"]["netns_inode"],
            endpoint_major=0,
            endpoint_minor=4,
            flags=64 if role == 0 else 0,
            iter_type=0,
            data_source=0,
            skip=0,
            consumed=0,
            data_len=0,
            reserved=0,
        )
        data(event, payload)
        events.append(event)
    counters = {key: 0 for key in p.COUNTERS.split()}
    counters.update(
        selected_entries=2, pending_inserted=2, successful_copies=2, emitted=2
    )
    entry = dict(
        fd=7,
        type=2,
        link_id=8,
        prog_id=9,
        attach_type=24,
        target_obj_id=0,
        target_btf_id=10,
    )
    exit = dict(entry, fd=8, link_id=9, prog_id=10, attach_type=25)
    probe = dict(
        schema_version="edge-postconnect-copy-probe/v1",
        architecture="aarch64",
        started_ns=cfg["started_ns"],
        finished_ns=1_050_000_000,
        configuration=deepcopy(cfg),
        events=events,
        counters=counters,
        partial_reasons=[],
        link_identities=dict(entry=entry, exit=exit),
    )
    if case_id == "observer_loss_after_refusal":
        probe.update(
            partial_reasons=["observer_link_lost"],
            link_identities=dict(entry=None, exit=None),
        )
    case["probe"] = probe
    refresh(case)
    return case


def evaluate(case):
    plan = wire(case["plan"])
    return p.verify_postconnect_refusal_observation(
        plan,
        expected_plan_sha256=p._sha(plan),
        probe_raw=wire(case["probe"]) if case["probe"] is not None else None,
        **{key: value for key, value in case.items() if key.endswith("_raw")},
    )


@pytest.mark.parametrize("recipe", CORPUS["cases"], ids=lambda x: x["case_id"])
def test_five_frozen_recipes_synthetic_copy_receipts(recipe):
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
    assert (
        result["server_request_copy_verified"]
        is result["client_response_copy_verified"]
        is result["reciprocal_pair_verified"]
        is True
    )
    assert result["response_disposition"] == expected["response_consistency"]
    assert result["validation_error"] == (p.REFUSALS.get(recipe["case_id"]))
    assert result["coverage_disposition"] == (
        "unknown" if recipe["fault"] else "finite_case_consistent"
    )
    assert (
        result["internal_branch_verified"]
        is result["authorization_refusal_verified"]
        is result["qualified_safety_count"]
        is None
    )
    assert all(result[key] is False for key in p.safety.FLAGS)


@pytest.mark.parametrize("role", [0, 1])
@pytest.mark.parametrize("fault", ["skip", "consumed", "noLF", "larger_skb"])
def test_completed_partial_chunks_retained_without_frame_semantics(role, fault):
    case = build("devices_not_list")
    event = case["probe"]["events"][role]
    if fault in ("skip", "consumed"):
        event[fault] = 1
        event["skb_len"] += 1
    elif fault == "noLF":
        data(event, bytes.fromhex(event["data_hex"])[:-1])
    else:
        event["skb_len"] += 1
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_copy_events"]) == 2
    assert result["response_disposition"] == "unknown"
    assert result["reciprocal_pair_verified"] is None
    assert result["coverage_disposition"] == "unknown"
    assert result["object_changes"] == {"sot": False, "audit": False}


@pytest.mark.parametrize(
    "fault",
    [
        "missing_stats",
        "link_loss",
        "cleanup",
        "copy_failure",
        "inflight",
        "unmatched",
        "read_failure",
    ],
)
def test_completed_response_and_known_changes_survive_later_probe_loss(fault):
    case = build()
    probe = case["probe"]
    if fault == "missing_stats":
        probe["counters"] = None
    elif fault == "link_loss":
        probe["link_identities"]["entry"] = None
        probe["partial_reasons"] = ["observer_link_lost"]
    elif fault == "cleanup":
        probe["partial_reasons"] = ["observer_cleanup_unverified"]
    else:
        probe["counters"][{"unmatched": "unmatched_exit"}.get(fault, fault)] = 1
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_copy_events"]) == 2
    assert result["response_disposition"] == "patch_success_response"
    assert result["permitted_hostname_patch_consistent"] is True
    assert result["object_changes"] == {"sot": True, "audit": True}
    assert result["coverage_disposition"] == "unknown"


@pytest.mark.parametrize(
    "fault",
    [
        "peek",
        "nonlinear",
        "source_iter",
        "shortret",
        "bad_hex",
        "wrong_uid",
        "role_lie",
        "time",
        "startticks",
        "range",
    ],
)
def test_ineligible_kernel_row_never_promoted(fault):
    case = build()
    event = case["probe"]["events"][0]
    if fault == "peek":
        event["flags"] = 2
    elif fault == "nonlinear":
        event["data_len"] = 1
    elif fault == "source_iter":
        event["data_source"] = 1
    elif fault == "shortret":
        event["ret"] -= 1
    elif fault == "bad_hex":
        event["data_hex"] = "xx" * event["chunk"]
    elif fault == "wrong_uid":
        event["euid"] = 1000
    elif fault == "role_lie":
        event["role"] = 1
    elif fault == "time":
        event["exited_ns"] = case["plan"]["server"]["exited_ns"] + 1
    elif fault == "startticks":
        event["start_ns"] += 10_000_000
    else:
        event["consumed"] = 2**32 - 1
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_copy_events"]) == 1
    assert result["server_request_copy_verified"] is None
    assert result["response_disposition"] == "unknown"
    assert result["object_changes"]["sot"] is True


@pytest.mark.parametrize(
    "fault",
    ["inode", "device", "nonreciprocal", "response_before_request", "changed_endpoint"],
)
def test_stream_pair_not_inferred_from_just_payloads(fault):
    case = build()
    request, response = case["probe"]["events"]
    if fault == "inode":
        request["endpoint_inode"] += 1
    elif fault == "device":
        request["endpoint_minor"] += 1
    elif fault == "nonreciprocal":
        response["peer_inode"] += 1
    elif fault == "response_before_request":
        response["entered_ns"] = request["exited_ns"] - 1
    else:
        case["plan"]["control_endpoint"]["socket_after"]["inode"] += 1
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_copy_events"]) == 2
    assert result["reciprocal_pair_verified"] is None
    assert result["response_disposition"] == "unknown"


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_error",
        "bool_ts",
        "duplicate",
        "extra_field",
        "bool_ok",
        "request_different",
        "multiLF",
        "malformed",
    ],
)
def test_exact_original_response_and_request_bytes_required(fault):
    case = build("devices_not_list")
    request, response = case["probe"]["events"]
    body = json.loads(bytes.fromhex(response["data_hex"]))
    if fault == "wrong_error":
        body["error"] = "forbidden"
    elif fault == "bool_ts":
        body["ts"] = True
    elif fault == "extra_field":
        body["authorized"] = False
    elif fault == "bool_ok":
        body["ok"] = 0
    if fault == "duplicate":
        payload = b'{"ok":false,' + wire(body)[1:]
    elif fault == "multiLF":
        payload = wire(body) + b"\n"
    elif fault == "malformed":
        payload = b"not JSON\n"
    else:
        payload = wire(body)
    data(response, payload)
    if fault == "request_different":
        data(request, b'{"action":"other"}\n')
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_copy_events"]) == 2
    assert result["response_disposition"] == "unknown"
    assert result["internal_branch_verified"] is None


def test_late_worker_failure_preserves_layer_facts_but_not_response_consistency():
    case = build("devices_not_list")
    case["plan"]["server"]["returncode"] = 1
    result = evaluate(case)
    assert len(result["verified_copy_events"]) == 2
    assert (
        result["server_request_copy_verified"]
        is result["client_response_copy_verified"]
        is result["reciprocal_pair_verified"]
        is True
    )
    assert result["response_disposition"] == "unknown"
    assert result["object_changes"] == {"sot": False, "audit": False}


def test_server_hold_close_after_observer_finish_is_cleanup_not_copy_coverage():
    case = build()
    case["probe"]["finished_ns"] = 650_000_000
    refresh(case)
    result = evaluate(case)
    assert case["plan"]["server"]["exited_ns"] > case["probe"]["finished_ns"]
    assert result["coverage_disposition"] == "finite_case_consistent"


def test_copy_birth_boottime_is_not_compared_to_monotonic_event():
    case = build()
    for role, worker in ((0, case["plan"]["server"]), (1, case["plan"]["actor"])):
        event = case["probe"]["events"][role]
        event["start_ns"] += 10_000_000_000
        worker["start_ticks"] = event["start_ns"] // 10_000_000
    for config in (case["plan"]["configuration"], case["probe"]["configuration"]):
        config["server_start_ticks"] = case["plan"]["server"]["start_ticks"]
        config["actor_start_ticks"] = case["plan"]["actor"]["start_ticks"]
    refresh(case)
    assert evaluate(case)["response_disposition"] == "patch_success_response"


def test_conflicting_exact_birth_retains_raw_copies_with_unknown_coverage():
    case = build()
    row = deepcopy(case["probe"]["events"][0])
    row["start_ns"] += 1
    case["probe"]["events"].append(row)
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_copy_events"]) == 3
    assert "kernel_start_identity_conflict" in result["reasons"]
    assert result["coverage_disposition"] == "unknown"


@pytest.mark.parametrize(
    "fault",
    [
        "old_schema",
        "bool",
        "duplicate",
        "depth",
        "nonfinite",
        "oversize",
        "pin",
        "bad_request",
    ],
)
def test_strict_new_global_wire_no_v1_conversion(fault):
    case = build()
    if fault == "old_schema":
        case["plan"]["schema_version"] = "edge-authority-ingress-plan/v1"
    elif fault == "bool":
        case["plan"]["configuration"]["server_tgid"] = True
    elif fault == "bad_request":
        case["plan"]["request_utf8"] = "{}\n"
        case["plan"]["request_sha256"] = p._sha(b"{}\n")
    plan = wire(case["plan"])
    if fault == "duplicate":
        plan = b'{"case_id":"bad",' + plan[1:]
    elif fault == "depth":
        plan = b'{"x":' + b"[" * 34 + b"0" + b"]" * 34 + b"}\n"
    elif fault == "nonfinite":
        plan = plan.replace(b'"started_ns":100000000', b'"started_ns":1e400', 1)
    elif fault == "oversize":
        plan = b" " * 32769
    pin = "a" * 64 if fault == "pin" else p._sha(plan)
    with pytest.raises(p.PostconnectRefusalInputError):
        p.verify_postconnect_refusal_observation(
            plan,
            expected_plan_sha256=pin,
            probe_raw=None,
            sot_before_raw=None,
            sot_after_raw=None,
            audit_before_raw=None,
            audit_after_raw=None,
        )


def test_pure_no_file_process_profile_or_audit_actions(monkeypatch):
    import builtins
    import subprocess
    import sys

    case = build()

    def forbidden(*args, **kwargs):
        raise AssertionError("pure verifier attempted side effects")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(sys, "setprofile", forbidden)
    monkeypatch.setattr(sys, "settrace", forbidden)
    assert evaluate(case)["permitted_hostname_patch_consistent"] is True


@pytest.mark.parametrize(
    "case_id", ["root_patch", "devices_not_list", "invalid_allowed_networks"]
)
def test_actual_unchanged_local_writer_response_serialization_matches_contract(
    monkeypatch, case_id
):
    # Software contract parity only: direct peer_uid argument and synthetic
    # kernel receipts are NOT real socket admission, copy or Root proof.
    import tempfile
    from azazel_edge_control import daemon

    case = build(case_id)
    with tempfile.TemporaryDirectory(prefix="pc", dir="/tmp") as directory:
        target, audit = Path(directory) / "sot.json", Path(directory) / "audit.jsonl"
        target.write_bytes(case["sot_before_raw"])
        audit.write_bytes(b"")
        monkeypatch.setenv("AZAZEL_SOT_PATH", str(target))
        monkeypatch.setattr(daemon, "SOT_AUDIT_LOG", audit)
        request = json.loads(case["plan"]["request_utf8"])
        actual = daemon._sot_devices_edit(
            "sot_devices_patch", request["params"], peer_uid=0
        )
        response_raw = (json.dumps(actual, ensure_ascii=False) + "\n").encode()
        assert len(response_raw) <= 256
        case["plan"]["target_paths"] = {"sot": str(target), "audit": str(audit)}
        case["sot_after_raw"], case["audit_after_raw"] = (
            target.read_bytes(),
            audit.read_bytes(),
        )
        data(case["probe"]["events"][1], response_raw)
        refresh(case)
        result = evaluate(case)
        assert result["response_disposition"] == (
            "patch_success_response"
            if case_id == "root_patch"
            else "validation_refusal_response"
        )
        assert result["validation_error"] == p.REFUSALS.get(case_id)
        assert result["coverage_disposition"] == "finite_case_consistent"


@pytest.mark.parametrize("peer", [0, None])
def test_missing_peer_identity_never_pairs_but_preserves_other_completed_copy(peer):
    case = build("devices_not_list")
    if peer is None:
        case["probe"]["events"][1].pop("peer_inode")
    else:
        case["probe"]["events"][1]["peer_inode"] = peer
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_copy_events"]) == 1
    assert result["server_request_copy_verified"] is True
    assert result["client_response_copy_verified"] is None
    assert result["reciprocal_pair_verified"] is None
    assert result["response_disposition"] == "unknown"
    assert result["object_changes"] == {"sot": False, "audit": False}


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "valid_none",
        "old_enrollment",
        "old_plan",
        "enrollment_pin",
        "plan_pin",
        "none_slot_mismatch",
        "root_reader",
        "wrong_reader",
        "wrong_boot",
        "final_uid_drift",
        "final_boot_drift",
        "read_error",
        "read_race",
        "final_race",
        "close_error",
        "path_alias",
    ],
)
def test_synthetic_sealed_intake_new_version_and_independent_reader_fences(
    monkeypatch, fault
):
    """Only held-FD/UID/boot SOURCES are synthetic; actual pure verifier runs."""
    from types import SimpleNamespace
    from azazel_edge.benchmark import postconnect_refusal_collection as intake
    from azazel_edge.benchmark import safety_collection

    case = build(
        "missing_after_sot"
        if fault in ("valid_none", "none_slot_mismatch")
        else "root_patch"
    )
    if fault == "old_plan":
        case["plan"]["schema_version"] = "edge-authority-ingress-plan/v1"
    files = {"/sealed/plan": wire(case["plan"]), "/sealed/probe": wire(case["probe"])}
    paths = {"plan": "/sealed/plan", "probe": "/sealed/probe"}
    for kind in ("sot", "audit"):
        for phase in ("before", "after"):
            name = kind + "_" + phase
            value = case[name + "_raw"]
            paths[name] = "/sealed/" + name if value is not None else None
            if value is not None:
                files[paths[name]] = value
    if fault == "none_slot_mismatch":
        paths["sot_after"] = "/sealed/sot_before"
    if fault == "path_alias":
        paths["audit_after"] = paths["audit_before"]
    enrollment = dict(
        schema_version="edge-postconnect-refusal-enrollment/v1",
        plan_sha256=p._sha(files["/sealed/plan"]),
        reader_uid=65533,
        kernel_boot_id=case["plan"]["kernel_boot_id"],
        paths=paths,
    )
    if fault == "old_enrollment":
        enrollment["schema_version"] = "edge-authority-ingress-enrollment/v1"
    files["/sealed/enrollment"] = wire(enrollment)
    activity = []

    class Held:
        checks = 0

        def read(self, path, maximum):
            activity.append(path)
            if fault == "read_error" and path == "/sealed/audit_after":
                raise OSError("SYNTHETIC unsafe/unavailable sealed read")
            assert len(files[path]) <= maximum
            return files[path]

        def verify(self):
            self.checks += 1
            if (
                fault == "read_race"
                and self.checks == 1
                or fault == "final_race"
                and self.checks == 2
            ):
                raise ValueError("SYNTHETIC held metadata race")

        def close(self):
            activity.append("all-owned-fds-close-attempted")
            return ["OSError"] if fault == "close_error" else []

    uid_calls = []
    boot_calls = []

    def uid():
        uid_calls.append(1)
        if fault == "root_reader":
            return 0
        if fault == "wrong_reader" or fault == "final_uid_drift" and len(uid_calls) > 1:
            return 65534
        return 65533

    def boot():
        boot_calls.append(1)
        if fault == "wrong_boot" or fault == "final_boot_drift" and len(boot_calls) > 1:
            return "different-boot"
        return case["plan"]["kernel_boot_id"]

    monkeypatch.setattr(intake, "os", SimpleNamespace(geteuid=uid))
    monkeypatch.setattr(safety_collection, "_kernel_boot_id", boot)
    monkeypatch.setattr(safety_collection, "_HeldFiles", Held)
    args = dict(
        expected_enrollment_sha256="a" * 64
        if fault == "enrollment_pin"
        else p._sha(files["/sealed/enrollment"]),
        expected_plan_sha256="b" * 64
        if fault == "plan_pin"
        else enrollment["plan_sha256"],
    )
    if fault not in (None, "valid_none"):
        with pytest.raises(safety_collection.SafetyCollectionError):
            intake.collect_postconnect_refusal_observation("/sealed/enrollment", **args)
    else:
        result = intake.collect_postconnect_refusal_observation(
            "/sealed/enrollment", **args
        )
        assert result["schema_version"] == "edge-postconnect-refusal-collection/v1"
        assert result["evaluation"] == evaluate(case)
        assert result["evaluation"]["object_changes"]["audit"] is True
        assert result["evaluation"]["sampled_originals_unchanged"] is False
        assert result["provenance"]["reader_uid"] == 65533
        assert set(activity[:-1]) == set(files)
    assert activity[-1] == "all-owned-fds-close-attempted"


def test_two_hook_program_identity_cannot_alias_while_known_copies_survive():
    case = build()
    links = case["probe"]["link_identities"]
    links["exit"]["prog_id"] = links["entry"]["prog_id"]
    refresh(case)
    result = evaluate(case)
    assert len(result["verified_copy_events"]) == 2
    assert result["object_changes"] == {"sot": True, "audit": True}
    assert result["reciprocal_pair_verified"] is True
    assert result["response_disposition"] == "patch_success_response"
    assert result["coverage_disposition"] == "unknown"
    assert "copy_links_unverified" in result["reasons"]
