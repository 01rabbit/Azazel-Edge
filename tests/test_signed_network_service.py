"""Synthetic offline service-origin tests, never a real runtime result."""

import sys
from pathlib import Path
import pytest
from azazel_edge.benchmark.benefit import BenefitInputError

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_service as service_bridge
import signed_network_recording as r


def test_service_origin_translation_preserves_original_audits():
    import copy
    from test_network_measure_driver import peer_audits, registration

    m, safety = registration()
    origin, deadline, service, client = peer_audits()
    client_origin = origin + 1_250_000_000
    client["objective_attempt_ns"] = client_origin + 400_000_000
    originals = copy.deepcopy((service, client))
    capture, receipt, binding = service_bridge.service_capture(
        m,
        m["assignments"][0],
        "run",
        safety["0-c0"],
        origin_ns=origin,
        deadline_ns=deadline,
        client_origin_ns=client_origin,
        service=service,
        client=client,
        kernel_boot_id="7be45004-1731-4b7c-8e62-59a5ddf129a4",
    )
    assert (service, client) == originals
    assert capture["legitimate_transactions"][0]["elapsed_seconds"] == 1.55
    assert (
        capture["legitimate_transactions"][0]["duration_ms"]
        == client["transactions"][0]["duration_ms"]
    )
    assert receipt["protected_goal_seconds"] is None
    assert binding["original_client_audit_sha256"] == r.manifest_digest(client)
    with pytest.raises(BenefitInputError, match="origins"):
        service_bridge.service_capture(
            m,
            m["assignments"][0],
            "run",
            safety["0-c0"],
            origin_ns=origin,
            deadline_ns=deadline,
            client_origin_ns=origin,
            service=service,
            client=client,
            kernel_boot_id="7be45004-1731-4b7c-8e62-59a5ddf129a4",
        )


@pytest.mark.parametrize("fault", ["reverse", "bool", "missing"])
def test_clock_bracket_malformed_refuses(fault):
    anchor = dict(monotonic_before_ns=10, epoch_ns=100, monotonic_after_ns=12)
    if fault == "reverse":
        anchor["monotonic_after_ns"] = 9
    elif fault == "bool":
        anchor["epoch_ns"] = True
    else:
        anchor.pop("epoch_ns")
    with pytest.raises(BenefitInputError):
        service_bridge.clock_origin(anchor, 11)


def test_clock_mapping_preserves_actual_brackets_and_uncertainty():
    anchor = dict(
        monotonic_before_ns=1_000_000_000,
        epoch_ns=100_000_000_000,
        monotonic_after_ns=1_002_000_000,
    )
    assert service_bridge.clock_origin(anchor, 1_001_000_000) == (100, 1)
    binding = service_bridge.clock_binding(anchor, anchor, 1_001_000_000)
    assert binding == dict(
        edge_epoch_origin=100, controller_epoch_origin=100, uncertainty_ms=2
    )
    slow = dict(anchor, monotonic_after_ns=1_020_000_000)
    assert service_bridge.clock_binding(slow, slow, 1_001_000_000)["uncertainty_ms"] > 5


def root_receipt(event):
    import json
    from azazel_edge.outcome import from_rust_event
    from azazel_edge.outcome.nft_flow_evidence import QUERY
    from test_outcome_nft_flow_evidence import payload

    return dict(
        argv=list(QUERY),
        returncode=0,
        stdout=json.dumps(payload(from_rust_event(event).execution.scope)),
        stderr="",
        root_uid=0,
        root_pid=123,
        kernel_boot_id=KERNEL,
        netns_inode=456,
        source_identity=dict(SOURCE),
        query_started_at="1970-01-01T00:01:40.100000+00:00",
        query_ended_at="1970-01-01T00:01:40.110000+00:00",
        capture_boundary="actual_root_SubprocessReadOnlyRunner_inside_owned_netns",
        source="live_root_query_recorded_once_for_pure_projection",
    )


SOURCE = dict(
    source_revision="a" * 40, helper_sha256="b" * 64, network_driver_sha256="c" * 64
)

KERNEL = "7be45004-1731-4b7c-8e62-59a5ddf129a4"


def test_original_live_outcome_and_augmented_root_projection_stay_separate(tmp_path):
    from test_signed_network_recording import collect, POLICY
    import network_measure_driver as network

    path = tmp_path / "calls"
    event, outcomes = collect(path)
    receipt = root_receipt(event)
    before = r.canonical(receipt)
    step = service_bridge.recorded_root_probe(
        receipt,
        event=event,
        kernel_boot_id=KERNEL,
        namespace_inode=456,
        source_identity=dict(SOURCE),
    )
    projection = r.replay_calls(
        r.read_calls(path),
        policy=POLICY,
        boot=network.boot_reference(KERNEL),
        root_probe=step,
    )
    assert r.canonical(receipt) == before
    assert projection["live_outcomes"] == [o.to_dict() for o in outcomes]
    assert (
        projection["plain_replay"]["decisions"][0]["stages"]["mechanism"]["status"]
        == "unverified"
    )
    trace = projection["root_augmented_replay"]["decisions"][0]
    assert trace["stages"]["mechanism_postcondition"]["status"] == "observed"
    assert trace["stages"]["outcome"]["causal_support"] == "inconclusive"


@pytest.mark.parametrize(
    "fault",
    [
        "argv",
        "owner_uid",
        "bool_uid",
        "short_source",
        "uppercase_source",
        "extra_source",
        "namespace",
        "boot",
        "source",
        "raw",
        "time",
        "exit",
    ],
)
def test_root_receipt_wrong_bindings_refuse(fault):
    from test_outcome_nft_flow_evidence import event

    e = event()
    receipt = root_receipt(e)
    if fault == "argv":
        receipt["argv"][-1] = "other"
    elif fault == "owner_uid":
        receipt["root_uid"] = 61002
    elif fault == "bool_uid":
        receipt["root_uid"] = False
    elif fault == "short_source":
        receipt["source_identity"]["helper_sha256"] = "b" * 63
    elif fault == "uppercase_source":
        receipt["source_identity"]["helper_sha256"] = "B" * 64
    elif fault == "extra_source":
        receipt["source_identity"]["other"] = "unknown"
    elif fault == "namespace":
        receipt["netns_inode"] = 999
    elif fault == "boot":
        receipt["kernel_boot_id"] = "wrong"
    elif fault == "source":
        receipt["source_identity"] = {}
    elif fault == "raw":
        receipt["stdout"] = {}
    elif fault == "time":
        receipt["query_ended_at"] = "1970-01-01T00:01:39+00:00"
    else:
        receipt["returncode"] = 1
    with pytest.raises(BenefitInputError):
        service_bridge.recorded_root_probe(
            receipt,
            event=e,
            kernel_boot_id=KERNEL,
            namespace_inode=456,
            source_identity=dict(SOURCE),
        )


def test_existing_measurement_keeps_missing_release_withheld(tmp_path):
    from test_signed_network_recording import collect, POLICY
    from test_network_measure_driver import peer_audits, registration
    from azazel_edge.benchmark.measurement import measure_experiment
    import network_measure_driver as network

    manifest, safety = registration()
    for arm in manifest["arms"]:
        if arm["id"] == "c0":
            arm["role"] = "observe_only"
    manifest["provenance"]["policy_sha256"] = r.manifest_digest(POLICY)
    for a in manifest["assignments"]:
        old = a["id"]
        a["id"] = "assignment-" + old
        a["pair_id"] = "pair-" + a["pair_id"]
        safety[a["id"]] = safety.pop(old)
    assignment = manifest["assignments"][1]
    origin, deadline, service, client = peer_audits()
    client["objective_attempt_ns"] = origin + 1_650_000_000
    capture, _, _ = service_bridge.service_capture(
        manifest,
        assignment,
        "run",
        safety[assignment["id"]],
        origin_ns=origin,
        deadline_ns=deadline,
        client_origin_ns=origin + 1_250_000_000,
        service=service,
        client=client,
        kernel_boot_id=KERNEL,
    )
    event, _ = collect(tmp_path / "calls")
    probe = service_bridge.recorded_root_probe(
        root_receipt(event),
        event=event,
        kernel_boot_id=KERNEL,
        namespace_inode=456,
        source_identity=dict(SOURCE),
    )
    projection = r.replay_calls(
        r.read_calls(tmp_path / "calls"),
        policy=POLICY,
        boot=network.boot_reference(KERNEL),
        root_probe=probe,
    )
    record = service_bridge.measurement_record(
        manifest,
        assignment,
        capture=capture,
        projection=projection,
        event=event,
        kernel_boot_id=KERNEL,
        session_ref="controlled-test-session",
        clock=dict(
            edge_epoch_origin=98.75, controller_epoch_origin=98.75, uncertainty_ms=0
        ),
        confounders=[],
    )
    report = measure_experiment(
        manifest, dict(manifest_sha256=r.manifest_digest(manifest), records=[record])
    )
    assert report["integrity_rejections"] == 0
    actual = next(
        row for row in report["ledger"] if row["assignment_id"] == assignment["id"]
    )
    assert "release_absence_not_verified" in actual["reasons"]
    assert actual["status"] == "withheld"


def test_baseline_uses_recording_none_but_never_changes_native_dryrun_facts():
    from test_network_measure_driver import peer_audits, registration

    manifest, safety = registration()
    manifest["arms"][0]["role"] = "observe_only"
    assignment = manifest["assignments"][0]
    origin, deadline, service, client = peer_audits()
    client["objective_attempt_ns"] = origin + 1_650_000_000
    capture, _, _ = service_bridge.service_capture(
        manifest,
        assignment,
        "run",
        safety[assignment["id"]],
        origin_ns=origin,
        deadline_ns=deadline,
        client_origin_ns=origin + 1_250_000_000,
        service=service,
        client=client,
        kernel_boot_id=KERNEL,
    )
    native = {"enforcement": {"mode": "disabled", "result": "dry_run"}}
    record = service_bridge.measurement_record(
        manifest,
        assignment,
        capture=capture,
        projection=None,
        event=native,
        kernel_boot_id=KERNEL,
        session_ref="test-session",
        clock=dict(
            edge_epoch_origin=100, controller_epoch_origin=100, uncertainty_ms=0
        ),
        confounders=[],
    )
    assert (
        record["edge_recording"] is None
        and record["linkage"]["recording_sha256"] is None
    )
    assert native == {"enforcement": {"mode": "disabled", "result": "dry_run"}}


@pytest.mark.parametrize(
    "source",
    [
        {"source_revision": "a" * 40},
        dict(SOURCE, helper_sha256="B" * 64),
        dict(SOURCE, network_driver_sha256=False),
    ],
)
def test_expected_root_source_pins_must_be_full_exact_shape(source):
    from test_outcome_nft_flow_evidence import event

    e = event()
    receipt = root_receipt(e)
    receipt["source_identity"] = source
    with pytest.raises(BenefitInputError, match="source pin"):
        service_bridge.recorded_root_probe(
            receipt,
            event=e,
            kernel_boot_id=KERNEL,
            namespace_inode=456,
            source_identity=source,
        )


@pytest.mark.parametrize("raw", ["0" * 32, "9" * 32, "a" * 32, "f" * 32])
def test_native_session_mapping_preserves_exact_raw_identity(raw):
    mapped = service_bridge.native_session_reference(raw)
    assert mapped == "native-session-" + raw
    assert mapped.removeprefix("native-session-") == raw
    from azazel_edge.benchmark.measurement import _ref

    assert _ref(mapped) == mapped


@pytest.mark.parametrize(
    "raw", [True, None, 1, "", "A" * 32, "a" * 31, "a" * 33, "g" * 32, "a" * 31 + "\n"]
)
def test_native_session_mapping_refuses_malformed_original(raw):
    with pytest.raises(BenefitInputError, match="exact raw native session"):
        service_bridge.native_session_reference(raw)


def test_native_session_mapping_is_injective_without_changing_originals():
    originals = [f"{value:032x}" for value in range(256)]
    saved = list(originals)
    mapped = [service_bridge.native_session_reference(raw) for raw in originals]
    assert len(set(mapped)) == len(originals) and originals == saved
    assert [value.removeprefix("native-session-") for value in mapped] == originals
