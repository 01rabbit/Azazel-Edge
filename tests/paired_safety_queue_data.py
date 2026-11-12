"""PUBLIC TEST signing only; main facts always SYNTHETIC, no runtime capture."""

from copy import deepcopy
import json
from pathlib import Path

from azazel_edge.outcome.journal import _json
from azazel_edge.benchmark.udp_queue import DOMAIN
from safety_observation_data import build, sign, wire, digest
from udp_queue_data import KEY, BOOT, PAYLOAD, TARGET, make_inputs


def pair_from_queue(contract_raw, plan_raw, report_raw, *, omit_main_protected=True):
    """Pair original queue bytes with explicitly SYNTHETIC four-category main facts.

    Default omits main protected channel observations: queue evidence does not fill
    delivery observations. Other main facts remain synthetic even for actual queue.
    """
    queue = json.loads(contract_raw)
    old_contract, old_observations, _ = build("violation-forged_evidence_accepted")
    main, observations = json.loads(old_contract), json.loads(old_observations)
    previous_owner = main["scope"]["owner"]
    main["scope"], main["keypins"] = (
        deepcopy(queue["scope"]),
        deepcopy(queue["keypins"]),
    )
    selected = deepcopy(queue["opportunities"]["protected_escape"][0])
    selected["id"] = "main-protected-opportunity"
    selected["reference_sha256"] = (
        "e" * 64
    )  # Frozen opaque main premise, NOT q reference.
    main["opportunities"]["protected_escape"] = [selected]
    start, end = selected["start_ns"], selected["end_ns"]
    owner = main["scope"]["owner"]
    uidmap = {
        previous_owner["producer_uid"]: owner["producer_uid"],
        previous_owner["observer_uid"]: owner["observer_uid"],
    }
    for category, descriptor in main["channels"].items():
        descriptor.update(
            channel_id="main-" + descriptor["channel_id"],
            capture_id="main-" + descriptor["capture_id"],
            collector_boot_id=main["scope"]["kernel_boot_id"],
            source_actor_uid=uidmap[descriptor["source_actor_uid"]],
        )
        for opportunity in main["opportunities"][category]:
            opportunity.update(start_ns=start, end_ns=end)
    raw = wire(main)
    observations.update(contract_sha256=digest(raw), scope=deepcopy(main["scope"]))
    heads = {}
    for category, channel in list(observations["channels"].items()):
        if category == "protected_escape" and omit_main_protected:
            observations["channels"].pop(category)
            heads[category] = None
            continue
        descriptor = main["channels"][category]
        opportunity = main["opportunities"][category][0]
        channel.update(
            channel_id=descriptor["channel_id"], capture_id=descriptor["capture_id"]
        )
        for row in channel["rows"]:
            row.update(
                contract_sha256=digest(raw),
                scope=deepcopy(main["scope"]),
                channel_id=descriptor["channel_id"],
                capture_id=descriptor["capture_id"],
            )
            kind = row["kind"]
            if row["opportunity_id"] is not None:
                row["opportunity_id"] = opportunity["id"]
            row["monotonic_ns"] = (
                main["scope"]["interval"]["start_ns"]
                if kind == "open"
                else main["scope"]["interval"]["end_ns"]
                if kind == "close"
                else start
                if kind == "challenge_begin"
                else end
                if kind == "challenge_end"
                else (start + end) // 2
            )
            if kind in ("open", "close"):
                row["data"]["boundary_ns"] = row["monotonic_ns"]
            if kind in ("challenge_begin", "challenge_end"):
                row["data"]["challenge_sha256"] = opportunity["challenge_sha256"]
            if category == "protected_escape" and kind == "delivery":
                row["data"]["tuple"] = deepcopy(
                    selected["predicate"]["protected_tuple"]
                )
        heads[category] = sign(channel["rows"])
    pair_plan = wire(
        dict(
            schema_version="edge-safety-queue-pair-plan/v1",
            main_contract_sha256=digest(raw),
            queue_contract_sha256=digest(contract_raw),
            queue_plan_sha256=digest(plan_raw),
            queue_report_sha256=digest(report_raw),
            main_opportunity_id=selected["id"],
            queue_opportunity_id=queue["opportunities"]["protected_escape"][0]["id"],
        )
    )
    return dict(
        main_contract_raw=raw,
        main_observations_raw=wire(observations),
        arguments=dict(
            main_arguments=dict(
                expected_contract_sha256=digest(raw),
                expected_stream_heads=heads,
                **main["keypins"],
            ),
            pair_plan_raw=pair_plan,
            expected_pair_plan_sha256=digest(pair_plan),
            queue_contract_raw=contract_raw,
            queue_plan_raw=plan_raw,
            queue_report_raw=report_raw,
        ),
    )


def make_pair_case(
    *, queue_positive=True, omit_main_protected=False, kernel_boot_id=BOOT
):
    """Signed report of DECLARED synthetic events, not provider/kernel execution."""
    contract, plan, _ = make_inputs(
        4,
        42,
        kernel_boot_id,
        40001,
        18080,
        2_000_000_000,
        4_000_000_000,
        PAYLOAD,
        TARGET,
        "synthetic-kernel-1",
        "b" * 64,
        "c" * 64,
    )
    q, p = json.loads(contract), json.loads(plan)
    event = dict(
        entered_ns=3_000_000_100,
        exited_ns=3_000_000_200,
        socket_inode=TARGET["socket_inode"],
        socket_cookie=TARGET["socket_cookie"],
        netns_cookie=TARGET["netns_cookie"],
        netns_inode=42,
        socket_uid=TARGET["uid"],
        src_ip="127.0.0.1",
        dst_ip="127.0.0.1",
        src_port=40001,
        dst_port=18080,
        payload_hex=PAYLOAD.hex(),
    )
    report = dict(
        schema_version="edge-udp-queue-report/v1",
        contract_sha256=digest(contract),
        plan_sha256=digest(plan),
        observation_layer="udp_socket_queue_admission",
        kernel_release=p["kernel_release"],
        btf_sha256=p["btf_sha256"],
        object_sha256=p["object_sha256"],
        kernel_boot_id=kernel_boot_id,
        namespace=dict(device=4, inode=42),
        capture_id=q["channels"]["protected_escape"]["capture_id"],
        started_ns=3_000_000_000,
        finished_ns=4_000_000_000,
        events=[event] if queue_positive else [],
        counters=dict(
            entry_matches=int(queue_positive),
            accepted=int(queue_positive),
            rejected=0,
            correlation_loss=0,
            overflow=0,
        ),
        partial_reasons=["timeout"],
    )
    report["signature"] = KEY.sign(DOMAIN + _json(report)).hex()
    return pair_from_queue(
        contract, plan, wire(report), omit_main_protected=omit_main_protected
    )


def make_pair_bundle(directory, inputs=None):
    """Public Root-enrollment bytes only; caller owns real staging/UID boundaries."""
    value = make_pair_case(omit_main_protected=True) if inputs is None else inputs
    args = value["arguments"]
    files = dict(
        main_contract=value["main_contract_raw"],
        main_observations=value["main_observations_raw"],
        pair_plan=args["pair_plan_raw"],
        queue_contract=args["queue_contract_raw"],
        queue_plan=args["queue_plan_raw"],
        queue_report=args["queue_report_raw"],
    )
    paths = {
        name: Path(directory) / (name + ".json")
        for name in (*files, "main_enrollment", "main_checkpoint", "pairing_enrollment")
    }
    main = json.loads(files["main_contract"])
    files["main_enrollment"] = wire(
        dict(
            schema_version="edge-safety-enrollment/v1",
            contract_sha256=digest(files["main_contract"]),
            scope=main["scope"],
            observer_uid=main["scope"]["owner"]["observer_uid"],
            paths=dict(
                contract=str(paths["main_contract"]),
                observations=str(paths["main_observations"]),
                checkpoint=str(paths["main_checkpoint"]),
            ),
        )
    )
    files["main_checkpoint"] = wire(
        dict(
            schema_version="edge-safety-checkpoint/v1",
            contract_sha256=digest(files["main_contract"]),
            scope=main["scope"],
            capture_ids={
                category: d["capture_id"] for category, d in main["channels"].items()
            },
            stream_heads=args["main_arguments"]["expected_stream_heads"],
        )
    )
    keys = ("pair_plan", "queue_contract", "queue_plan", "queue_report")
    files["pairing_enrollment"] = wire(
        dict(
            schema_version="edge-paired-safety-queue-enrollment/v1",
            main_enrollment_sha256=digest(files["main_enrollment"]),
            main_checkpoint_sha256=digest(files["main_checkpoint"]),
            paths={
                name: str(paths[name]) if files[name] is not None else None
                for name in keys
            },
            sha256={
                name: digest(files[name]) if files[name] is not None else None
                for name in keys
            },
        )
    )
    return dict(
        paths=paths,
        files=files,
        inputs=value,
        expected_main_enrollment_sha256=digest(files["main_enrollment"]),
        expected_main_checkpoint_sha256=digest(files["main_checkpoint"]),
        expected_pairing_enrollment_sha256=digest(files["pairing_enrollment"]),
    )
