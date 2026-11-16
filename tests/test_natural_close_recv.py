"""SYNTHETIC only: new recv/copy facts and original metadata; no kernel claim."""

from copy import deepcopy
import json
from pathlib import Path
import pytest
from azazel_edge.benchmark import natural_close_recv as p
from azazel_edge.outcome.journal import _json
from test_postconnect_authorization import build as prior_synthetic
from test_authority_ingress import refresh

CORPUS = json.loads(
    (Path(__file__).parent / "fixtures/natural-close/v1/cases.json").read_bytes()
)


def wire(value):
    return _json(value) + b"\n"


def recount(case):
    rows = case["probe"]["events"]
    counts = {key: 0 for key in p.COUNTERS.split()}
    counts.update(
        recv_selected=sum(r["kind"] == 0 for r in rows),
        recv_completed=sum(r["kind"] == 2 for r in rows),
        successful_copies=sum(r["kind"] == 1 for r in rows),
        emitted=len(rows),
    )
    counts["selected_entries"] = counts["pending_inserted"] = counts[
        "successful_copies"
    ]
    case["probe"]["counters"] = counts
    refresh(case)


def build(case_id="root_only_refused", *, missing_peer=True):
    base_id = (
        case_id
        if case_id
        in (
            "own_uid_patch",
            "root_only_refused",
            "spoofed_root_refused",
            "missing_after_sot",
        )
        else "root_only_refused"
    )
    case = prior_synthetic(base_id)
    plan = case["plan"]
    probe = case["probe"]
    recipe = next(r for r in CORPUS["cases"] if r["case_id"] == case_id)
    plan.update(
        schema_version="edge-natural-close-plan/v1",
        case_id=case_id,
        request_utf8=recipe["request_utf8"],
        request_sha256=p._sha(recipe["request_utf8"].encode()),
    )
    plan["configuration"]["max_events"] = 32
    probe["configuration"] = deepcopy(plan["configuration"])
    rows = []
    for old in probe["events"]:
        role = old["role"]
        token = old["entered_ns"] - 20_000_000
        common = dict(
            old,
            token=token,
            kind=1,
            fd=7 + role,
            requested_len=65536 if role == 0 else 4096,
            peer_status=1,
            endpoint_status=1,
            reserved2=0,
        )
        copy = deepcopy(common)
        if role == 1 and missing_peer:
            for row in (common, copy):
                row.update(
                    peer_inode=None,
                    peer_status=2,
                    endpoint_inode=None,
                    endpoint_major=None,
                    endpoint_minor=None,
                    endpoint_status=2,
                )
        entry = dict(
            common,
            kind=0,
            entered_ns=token,
            exited_ns=0,
            flags=0,
            iter_type=0,
            data_source=0,
            skip=0,
            chunk=0,
            consumed=0,
            skb_len=0,
            data_len=0,
            ret=0,
            data_hex="",
        )
        exit = dict(
            entry,
            kind=2,
            exited_ns=old["exited_ns"] + 10_000_000,
            ret=old["chunk"],
            peer_status=0,
            endpoint_status=0,
            peer_inode=None,
            endpoint_inode=None,
            endpoint_major=None,
            endpoint_minor=None,
        )
        if case_id == "partial_read_close" and role == 1:
            for row in (entry, copy, exit):
                row["requested_len"] = 16
            copy.update(chunk=16, ret=16, data_hex=copy["data_hex"][:32])
            exit["ret"] = 16
        if case_id == "actor_death" and role == 1:
            rows.append(entry)
        else:
            rows.extend((entry, copy, exit))
    probe.update(
        schema_version="edge-natural-close-probe/v1", events=rows, partial_reasons=[]
    )
    links = {}
    for i, (name, attach) in enumerate(p.LINKS):
        links[name] = dict(
            fd=7 + i,
            type=2,
            link_id=10 + i,
            prog_id=20 + i,
            attach_type=attach,
            target_obj_id=0,
            target_btf_id=30 + (0 if name.startswith("recv") else 1),
        )
    probe["link_identities"] = links
    recount(case)
    if case_id == "actor_death":
        plan["actor"].update(returncode=-9, forced=True)
        probe["counters"]["recv_inflight"] = 1
        probe["partial_reasons"] = ["pending_not_empty"]
    if case_id == "observer_stop_after_copy":
        probe["link_identities"]["recv_exit"] = None
        probe["partial_reasons"] = ["observer_link_lost"]
    refresh(case)
    return case


def evaluate(case):
    raw = wire(case["plan"])
    return p.verify_natural_close_recv_observation(
        raw,
        expected_plan_sha256=p._sha(raw),
        probe_raw=wire(case["probe"]) if case["probe"] is not None else None,
        **{key: value for key, value in case.items() if key.endswith("_raw")},
    )


@pytest.mark.parametrize("case_id", [r["case_id"] for r in CORPUS["cases"]])
def test_frozen_seven_synthetic_cases(case_id):
    case = build(case_id)
    original = deepcopy(case)
    r = evaluate(case)
    assert original == case
    assert r["reciprocal_pair_verified"] is None
    assert r["root_only_refusal_response_consistent"] is None
    assert (
        r["internal_branch_verified"]
        is r["authorization_refusal_verified"]
        is r["qualified_safety_count"]
        is None
    )
    assert all(r[k] is False for k in p.safety.FLAGS)
    assert r["server_request_completion_verified"] is True
    assert r["client_response_completion_verified"] is (
        None if case_id == "actor_death" else True
    )
    assert r["client_response_frame_verified"] is (
        None if case_id in ("actor_death", "partial_read_close") else True
    )
    assert r["clean_lifecycle_verified"] is (None if case_id == "actor_death" else True)
    assert r["coverage_disposition"] == (
        "bounded_individual_observation" if case_id in p.NORMAL else "unknown"
    )
    if case_id == "missing_after_sot":
        assert r["object_changes"] == {"sot": None, "audit": True}
        assert r["sampled_originals_unchanged"] is False
    elif case_id == "own_uid_patch":
        assert r["permitted_hostname_patch_consistent"] is True
    else:
        assert r["sampled_originals_unchanged"] is True


def test_readable_optional_peer_never_qualifies_pair_or_backfills_missing_peer():
    case = build(missing_peer=False)
    r = evaluate(case)
    assert (
        r["reciprocal_pair_verified"]
        is r["root_only_refusal_response_consistent"]
        is None
    )
    assert r["coverage_disposition"] == "bounded_individual_observation"
    assert "peer_pairing_unqualified_lockless_optional_metadata" in r["reasons"]
    for row in case["probe"]["events"]:
        if row["kind"] == 1 and row["role"] == 1:
            row.update(peer_status=2, peer_inode=None)
    refresh(case)
    r = evaluate(case)
    assert r["client_response_frame_verified"] is True
    assert r["reciprocal_pair_verified"] is None
    assert r["root_only_refusal_response_consistent"] is None
    assert r["coverage_disposition"] == "bounded_individual_observation"


@pytest.mark.parametrize("missing", [0, 1, 2])
def test_missing_invocation_fact_never_reconstructed(missing):
    case = build()
    case["probe"]["events"] = [
        r
        for r in case["probe"]["events"]
        if not (r["role"] == 1 and r["kind"] == missing)
    ]
    recount(case)
    r = evaluate(case)
    assert r["client_response_completion_verified"] is None
    assert r["client_response_frame_verified"] is None
    assert r["coverage_disposition"] == "unknown"
    assert r["server_request_completion_verified"] is True
    assert len(r["raw_protocol_copy_events"]) == (1 if missing == 1 else 2)


@pytest.mark.parametrize("kind", [0, 1, 2])
@pytest.mark.parametrize(
    "fault", ["token", "fd", "inode", "start", "uid", "namespace", "time"]
)
def test_same_invocation_identity_binding_not_timestamp_guess(kind, fault):
    case = build()
    row = next(
        r for r in case["probe"]["events"] if r["role"] == 1 and r["kind"] == kind
    )
    if fault == "token":
        row["token"] -= 1
        if kind != 1:
            row["entered_ns"] = row["token"]
    elif fault == "fd":
        row["fd"] += 1
    elif fault == "inode":
        row["receiver_inode"] += 1
    elif fault == "start":
        row["start_ns"] += 1
    elif fault == "uid":
        row["uid"] = 0
    elif fault == "namespace":
        row["netns_inode"] += 1
    else:
        row["exited_ns"] = case["plan"]["actor"]["exited_ns"] + 1
    refresh(case)
    r = evaluate(case)
    assert r["client_response_completion_verified"] is None
    assert r["client_response_frame_verified"] is None
    assert r["coverage_disposition"] == "unknown"
    assert r["sampled_originals_unchanged"] is True


@pytest.mark.parametrize("kind", [0, 1, 2])
def test_duplicate_invocation_facts_never_merged_or_selected(kind):
    case = build()
    row = next(
        r for r in case["probe"]["events"] if r["role"] == 1 and r["kind"] == kind
    )
    case["probe"]["events"].append(deepcopy(row))
    recount(case)
    r = evaluate(case)
    assert r["client_response_completion_verified"] is None
    assert r["coverage_disposition"] == "unknown"
    assert len(r["verified_events"]) == 7


@pytest.mark.parametrize("ret", [0, -11, -4, -512, 1, 65536])
def test_return_alone_never_proves_copy_bytes_or_frame(ret):
    case = build()
    row = next(r for r in case["probe"]["events"] if r["kind"] == 2 and r["role"] == 1)
    row["ret"] = ret
    refresh(case)
    r = evaluate(case)
    assert r["client_response_completion_verified"] is None
    assert r["client_response_frame_verified"] is None
    assert r["response_disposition"] == "unknown"
    assert len(r["raw_protocol_copy_events"]) == 2


@pytest.mark.parametrize("ret", [0, -11, -4, -512])
def test_measured_eof_or_error_is_preserved_without_byte_claim(ret):
    case = build()
    case["probe"]["events"] = [
        r for r in case["probe"]["events"] if not (r["kind"] == 1 and r["role"] == 1)
    ]
    row = next(r for r in case["probe"]["events"] if r["kind"] == 2 and r["role"] == 1)
    row["ret"] = ret
    recount(case)
    r = evaluate(case)
    assert row in r["verified_events"]
    assert r["client_response_completion_verified"] is None
    assert r["coverage_disposition"] == "unknown"


@pytest.mark.parametrize(
    "fault",
    [
        "skip",
        "consumed",
        "missingLF",
        "larger_skb",
        "different_response",
        "source_iterator",
        "nonlinear",
    ],
)
def test_copy_content_and_complete_frame_remain_separate(fault):
    case = build()
    row = next(r for r in case["probe"]["events"] if r["kind"] == 1 and r["role"] == 1)
    if fault in ("skip", "consumed"):
        row[fault] = 1
        row["skb_len"] += 1
    elif fault == "missingLF":
        row["data_hex"] = row["data_hex"][:-2] + "20"
    elif fault == "larger_skb":
        row["skb_len"] += 1
    elif fault == "different_response":
        raw = bytes.fromhex(row["data_hex"]).replace(b"root_only", b"wrongrole")
        row["data_hex"] = raw.hex()
    elif fault == "source_iterator":
        row["data_source"] = 1
    else:
        row["data_len"] = 1
    refresh(case)
    r = evaluate(case)
    assert r["client_response_frame_verified"] is None
    assert r["response_disposition"] == "unknown"
    assert r["coverage_disposition"] == "unknown"
    if fault not in ("source_iterator", "nonlinear"):
        assert r["client_response_completion_verified"] is True


@pytest.mark.parametrize(
    "fault",
    [
        "peer",
        "endpoint",
        "peer_read_error",
        "endpoint_read_error",
        "unavailable_with_value",
        "exit_echo_peer",
    ],
)
def test_optional_fresh_identity_missing_is_not_backfilled(fault):
    case = build(missing_peer=False)
    copy = next(r for r in case["probe"]["events"] if r["kind"] == 1 and r["role"] == 1)
    if fault in ("peer", "peer_read_error", "unavailable_with_value"):
        copy.update(
            peer_status=3 if fault == "peer_read_error" else 2,
            peer_inode=999 if fault == "unavailable_with_value" else None,
        )
    elif fault in ("endpoint", "endpoint_read_error"):
        copy.update(
            endpoint_status=3 if fault == "endpoint_read_error" else 2,
            endpoint_inode=None,
            endpoint_major=None,
            endpoint_minor=None,
        )
    else:
        row = next(
            r for r in case["probe"]["events"] if r["kind"] == 2 and r["role"] == 1
        )
        row.update(peer_status=1, peer_inode=500)
    refresh(case)
    r = evaluate(case)
    assert r["reciprocal_pair_verified"] is None
    assert r["root_only_refusal_response_consistent"] is None
    if fault not in ("unavailable_with_value", "exit_echo_peer"):
        assert r["client_response_completion_verified"] is True
        assert len(r["raw_protocol_copy_events"]) == 2
    else:
        assert r["client_response_completion_verified"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "missingprobe",
        "stats",
        "link",
        "partial",
        "malformed_row",
        "workerfailed",
        "missingafter",
        "changedafter",
    ],
)
def test_partial_collection_retains_independent_facts(fault):
    case = build()
    if fault == "missingprobe":
        case["probe"] = None
    elif fault == "stats":
        case["probe"]["counters"] = None
    elif fault == "link":
        case["probe"]["link_identities"]["recv_exit"] = None
    elif fault == "partial":
        case["probe"]["partial_reasons"] = ["observer_link_lost"]
    elif fault == "malformed_row":
        case["probe"]["events"].append(None)
    elif fault == "workerfailed":
        case["plan"]["server"]["returncode"] = 1
    elif fault == "missingafter":
        case["sot_after_raw"] = None
        case["plan"]["samples"]["after"]["sot"] = None
    else:
        case["plan"]["samples"]["after"]["audit"]["identity"]["mtime_ns"] += 1
    refresh(case)
    r = evaluate(case)
    assert r["coverage_disposition"] == "unknown"
    if fault not in ("missingprobe", "malformed_row"):
        assert r["client_response_completion_verified"] is True
        assert r["client_response_frame_verified"] is True
        assert len(r["raw_protocol_copy_events"]) == 2
    if fault == "malformed_row":
        assert r["client_response_completion_verified"] is None
        assert len(r["raw_protocol_copy_events"]) == 2
    if fault == "missingafter":
        assert r["sampled_originals_unchanged"] is None
    elif fault == "changedafter":
        assert r["sampled_originals_unchanged"] is False
    else:
        assert r["sampled_originals_unchanged"] is True


@pytest.mark.parametrize(
    "fault",
    [
        "oldplan",
        "oldprobe",
        "badmap",
        "badnamespace",
        "uid",
        "missingidentity",
        "oversize",
        "pin",
    ],
)
def test_new_global_wire_and_role_not_coerced(fault):
    case = build()
    if fault == "oldplan":
        case["plan"]["schema_version"] = "edge-postconnect-authorization-plan/v1"
    elif fault == "oldprobe":
        case["probe"]["schema_version"] = "edge-postconnect-uid-copy-probe/v1"
        refresh(case)
        assert evaluate(case)["verified_events"] == []
        return
    elif fault == "badmap":
        case["plan"]["identity_profile"]["uid_map"] = "0 1000 65536"
    elif fault == "badnamespace":
        case["plan"]["identity_profile"]["actor_userns_inode"] += 1
    elif fault == "uid":
        case["plan"]["configuration"]["actor_uid"] = 0
    elif fault == "missingidentity":
        case["plan"].pop("identity_profile")
    raw = b" " * 32769 if fault == "oversize" else wire(case["plan"])
    with pytest.raises(p.NaturalCloseRecvInputError):
        p.verify_natural_close_recv_observation(
            raw,
            expected_plan_sha256="a" * 64 if fault == "pin" else p._sha(raw),
            probe_raw=None,
            sot_before_raw=None,
            sot_after_raw=None,
            audit_before_raw=None,
            audit_after_raw=None,
        )


def test_pure_evaluator_no_io_callback_or_source_mutation(monkeypatch):
    import builtins
    import subprocess
    import sys

    case = build("own_uid_patch")
    original = deepcopy(case)

    def forbidden(*args, **kwargs):
        raise AssertionError("pure evaluation attempted side effects")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(sys, "settrace", forbidden)
    monkeypatch.setattr(sys, "setprofile", forbidden)
    assert evaluate(case)["permitted_hostname_patch_consistent"] is True
    assert case == original


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
    from azazel_edge.benchmark import natural_close_recv_collection as intake
    from azazel_edge.benchmark import safety_collection

    case = build(
        "missing_after_sot"
        if fault in ("valid_none", "none_slot_mismatch")
        else "own_uid_patch"
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
        schema_version="edge-natural-close-enrollment/v1",
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
            intake.collect_natural_close_recv_observation("/sealed/enrollment", **args)
    else:
        result = intake.collect_natural_close_recv_observation(
            "/sealed/enrollment", **args
        )
        assert result["schema_version"] == "edge-natural-close-collection/v1"
        assert result["evaluation"] == evaluate(case)
        assert result["evaluation"]["object_changes"]["audit"] is True
        assert result["evaluation"]["sampled_originals_unchanged"] is False
        assert result["provenance"]["reader_uid"] == 65533
        assert set(activity[:-1]) == set(files)
    assert activity[-1] == "all-owned-fds-close-attempted"


@pytest.mark.parametrize("kind", [0, 1, 2])
def test_malformed_same_token_sibling_taints_only_that_invocation(kind):
    case = build()
    row = deepcopy(
        next(r for r in case["probe"]["events"] if r["role"] == 1 and r["kind"] == kind)
    )
    row["reserved"] = 1
    case["probe"]["events"].append(row)
    refresh(case)
    result = evaluate(case)
    assert result["client_response_completion_verified"] is None
    assert result["client_response_frame_verified"] is None
    assert result["server_request_completion_verified"] is True
    assert result["server_request_frame_verified"] is True
    assert len(result["raw_protocol_copy_events"]) == 2
    assert result["coverage_disposition"] == "unknown"


@pytest.mark.parametrize(
    "invalid",
    [None, {}, {"role": True, "token": 330000000}, {"role": 1, "token": True}],
)
def test_unscopable_malformed_row_blocks_composition_but_retains_raw_copies(invalid):
    case = build()
    case["probe"]["events"].append(invalid)
    refresh(case)
    result = evaluate(case)
    assert result["receiver_completions"] == []
    assert result["server_request_completion_verified"] is None
    assert result["client_response_completion_verified"] is None
    assert len(result["raw_protocol_copy_events"]) == 2
    assert len(result["verified_events"]) == 6
    assert result["sampled_originals_unchanged"] is True


def test_same_role_kernel_birth_conflict_taints_all_role_invocations():
    case = build()
    rows = []
    for row in case["probe"]["events"]:
        if row["role"] == 1:
            sibling = deepcopy(row)
            sibling["token"] += 1
            sibling["start_ns"] += (
                1  # Still same coarse ticks; different exact identity.
            )
            if sibling["kind"] != 1:
                sibling["entered_ns"] = sibling["token"]
            rows.append(sibling)
    case["probe"]["events"].extend(rows)
    recount(case)
    result = evaluate(case)
    assert "kernel_start_identity_conflict" in result["reasons"]
    assert result["client_response_completion_verified"] is None
    assert result["client_response_frame_verified"] is None
    assert result["server_request_completion_verified"] is True
    assert len(result["raw_protocol_copy_events"]) == 3
    assert result["coverage_disposition"] == "unknown"


@pytest.mark.parametrize(
    "case_id", ["own_uid_patch", "root_only_refused", "spoofed_root_refused"]
)
def test_all_optional_metadata_available_remains_unqualified_pair(case_id):
    case = build(case_id, missing_peer=False)
    result = evaluate(case)
    assert result["reciprocal_pair_verified"] is None
    assert result["root_only_refusal_response_consistent"] is None
    assert result["server_request_completion_verified"] is True
    assert result["client_response_completion_verified"] is True
    assert result["coverage_disposition"] == "bounded_individual_observation"
    assert all(
        row["peer_status"] == row["endpoint_status"] == 1
        for row in result["raw_protocol_copy_events"]
    )
    assert result["raw_protocol_copy_events"] == [
        row for row in case["probe"]["events"] if row["kind"] == 1
    ]
