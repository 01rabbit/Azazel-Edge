"""Test-only service coordinate bridge; original peer audits remain unchanged."""

import json
import math
from signed_network_recording import canonical, manifest_digest, need


def service_capture(
    manifest,
    assignment,
    run_id,
    safety,
    *,
    origin_ns,
    deadline_ns,
    client_origin_ns,
    service,
    client,
    kernel_boot_id,
):
    """Reuse the independent service contract with an explicitly recorded offset.

    The peer remains unchanged: its six request elapsed values use the actual
    later client origin. Only capture-input elapsed coordinates are translated;
    original audit bytes/digests and all duration/error/transaction fields remain.
    """
    import network_measure_driver as network

    need(
        all(type(v) is int for v in (origin_ns, deadline_ns, client_origin_ns))
        and deadline_ns - origin_ns == 5_000_000_000
        and client_origin_ns - origin_ns == 1_250_000_000,
        "frozen real service/client origins differ",
    )
    need(
        type(client) is dict
        and type(client.get("transactions")) is list
        and len(client["transactions"]) == 6,
        "exact client denominator required",
    )
    adjusted = json.loads(canonical(client))
    offset = (client_origin_ns - origin_ns) / 1e9
    for row in adjusted["transactions"]:
        need(
            type(row.get("elapsed_seconds")) in (int, float)
            and math.isfinite(row["elapsed_seconds"])
            and row["elapsed_seconds"] >= 0,
            "invalid original peer elapsed",
        )
        row["elapsed_seconds"] += offset
    capture, receipt = network.measured_capture(
        manifest,
        assignment,
        run_id,
        safety,
        origin_ns,
        deadline_ns,
        service,
        adjusted,
        kernel_boot_id=kernel_boot_id,
    )
    binding = dict(
        service_origin_ns=origin_ns,
        client_origin_ns=client_origin_ns,
        deadline_ns=deadline_ns,
        client_elapsed_offset_seconds=offset,
        original_service_audit_sha256=manifest_digest(service),
        original_client_audit_sha256=manifest_digest(client),
        capture_input_client_sha256=manifest_digest(adjusted),
        original_audits_mutated=False,
        scope="actual_recorded_monotonic_coordinate_translation_only",
    )
    return capture, receipt, binding


def record_clock_anchor():
    """Record the wall read inside an actual bounded host-monotonic bracket."""
    import time

    before = time.monotonic_ns()
    epoch = time.time_ns()
    after = time.monotonic_ns()
    return dict(monotonic_before_ns=before, epoch_ns=epoch, monotonic_after_ns=after)


def clock_origin(anchor, origin_ns):
    need(
        type(anchor) is dict
        and set(anchor) == {"monotonic_before_ns", "epoch_ns", "monotonic_after_ns"}
        and all(type(v) is int and v >= 0 for v in anchor.values())
        and type(origin_ns) is int,
        "actual bounded clock bracket required",
    )
    before, epoch, after = (
        anchor[k] for k in ("monotonic_before_ns", "epoch_ns", "monotonic_after_ns")
    )
    need(before <= after, "clock bracket reversed")
    return (epoch + origin_ns - (before + after) / 2) / 1e9, (after - before) / 2e6


def clock_binding(observer_anchor, controller_anchor, origin_ns):
    edge, edge_error = clock_origin(observer_anchor, origin_ns)
    controller, controller_error = clock_origin(controller_anchor, origin_ns)
    # No post-result alignment or threshold adjustment. The existing measurement
    # gate withholds >5ms discrepancies/uncertainty, including a slow clock read.
    return dict(
        edge_epoch_origin=edge,
        controller_epoch_origin=controller,
        uncertainty_ms=edge_error + controller_error,
    )


def recorded_root_probe(
    receipt, *, event, kernel_boot_id, namespace_inode, source_identity
):
    """Project an independently retained explicit ROOT-lab receipt into G5.

    This validates declared bindings only; source authenticity/operator authority
    still require the original launch receipt and independent review. Never a
    live observer probe, root proxy or authorization to execute the query.
    """
    from datetime import datetime
    from azazel_edge.outcome import from_rust_event
    from azazel_edge.outcome.nft_flow_evidence import QUERY

    need(
        type(receipt) is dict
        and receipt.get("argv") == list(QUERY)
        and type(receipt.get("returncode")) is int
        and receipt["returncode"] == 0,
        "exact successful root readonly query required",
    )
    need(
        receipt.get("root_uid") == 0
        and type(receipt.get("root_pid")) is int
        and receipt["root_pid"] > 0
        and receipt.get("kernel_boot_id") == kernel_boot_id
        and type(namespace_inode) is int
        and namespace_inode > 0
        and receipt.get("netns_inode") == namespace_inode
        and receipt.get("source_identity") == source_identity,
        "root query declared identity mismatch",
    )
    need(
        receipt.get("capture_boundary")
        == "actual_root_SubprocessReadOnlyRunner_inside_owned_netns"
        and receipt.get("source")
        == "live_root_query_recorded_once_for_pure_projection",
        "root query boundary missing",
    )
    for key in ("stdout", "stderr"):
        need(
            type(receipt.get(key)) is str and len(receipt[key].encode()) <= 1024 * 1024,
            "root query raw text unavailable",
        )
    start, end = (
        datetime.fromisoformat(receipt[key])
        for key in ("query_started_at", "query_ended_at")
    )
    need(
        start.tzinfo is not None
        and end.tzinfo is not None
        and 0 <= (end - start).total_seconds() <= 2.1,
        "root query actual timestamps invalid",
    )
    bundle = from_rust_event(event)
    return dict(
        op="probe",
        epoch=end.timestamp(),
        observed_at=receipt["query_ended_at"],
        decision_id=bundle.execution.decision_id,
        results=[{k: receipt[k] for k in ("argv", "returncode", "stdout", "stderr")}],
    )


def measurement_record(
    manifest,
    assignment,
    *,
    capture,
    projection,
    event,
    kernel_boot_id,
    session_ref,
    clock,
    confounders,
):
    """Use G5 + existing measurement gates; baseline signed facts stay separate."""
    import network_measure_driver as network
    from azazel_edge.outcome import from_rust_event
    from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy

    arms = {a["id"]: a for a in manifest["arms"]}
    need(
        assignment in manifest["assignments"]
        and capture["assignment_id"] == assignment["id"],
        "assignment/capture binding mismatch",
    )
    linkage = dict(
        capture_sha256=manifest_digest(capture),
        session_ref=session_ref,
        scope="controlled_session",
        clock=clock,
        confounders=confounders,
    )
    if assignment["arm"] == manifest["baseline"]:
        need(
            arms[assignment["arm"]]["role"] == "observe_only",
            "C0 must use existing observe-only baseline contract",
        )
        linkage["recording_sha256"] = None
        recording = None
    else:
        need(
            projection is not None and projection["root_augmented_replay"] is not None,
            "candidate independent root readback projection missing",
        )
        recording = projection["recording"]
        need(
            manifest["provenance"]["policy_sha256"]
            == manifest_digest(recording["policy"]),
            "frozen canonical policy mismatch",
        )
        bundle = from_rust_event(event)
        original_events = [
            step["event"]
            for boot in recording["boots"]
            for step in boot["steps"]
            if step["op"] == "event"
        ]
        need(
            original_events.count(event) == 1,
            "exact actual decision event coverage required",
        )
        objective = OutcomeTelemetryPolicy.from_mapping(
            recording["policy"], source_ref="golden-replay"
        ).objective_for(bundle.execution.action_kind, bundle.execution.decision_id)
        need(objective is not None, "actual policy objective missing")
        linkage.update(
            recording_sha256=manifest_digest(recording),
            edge_boot_id=network.boot_reference(kernel_boot_id),
            decision_id=bundle.execution.decision_id,
            execution_id=bundle.execution.execution_id,
            mechanism_id=bundle.mechanism.mechanism_id,
            objective_id=objective.objective_id,
        )
    return dict(
        assignment_id=assignment["id"],
        capture=capture,
        edge_recording=recording,
        linkage=linkage,
    )
