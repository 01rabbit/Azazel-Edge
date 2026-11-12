"""PUBLIC synthetic safety payloads; optional actual Source/anchor byte inputs.

Returns bytes only. Supplied actual Source provenance never makes the separately
synthetic safety facts into measurements. No files, services or keys are created.
"""

from copy import deepcopy
import json
from pathlib import Path
from uuid import UUID

from azazel_edge.outcome.input_auth import TrustPolicy
from safety_observation_data import digest, wire, sign
from source_recovery_data import make_proof_bundle, bind_contract_to_source
from source_witness_data import ZERO, sign_anchors, anchor_checkpoint as checkpoint_of


def anchors_for_source(source):
    """Real TEST-key signatures over explicitly synthetic journal assertions."""
    tip = source["arguments"]["expected_prefix_checkpoint"]
    policy = TrustPolicy(json.loads(source["trust_raw"]))
    rows = []
    empty = dict(seq=0, head=ZERO, size=0, sha256=digest(b""))
    for counter, source_tip in enumerate((empty, tip), 1):
        state = {f"source_{key}": value for key, value in source_tip.items()}
        state.update(
            journal_seq=counter - 1,
            journal_head=ZERO if counter == 1 else "a" * 64,
            journal_size=0 if counter == 1 else 100,
            journal_sha256=digest(b"") if counter == 1 else "b" * 64,
            journal_device=0 if counter == 1 else 2,
            journal_inode=0 if counter == 1 else 3,
        )
        rows.append(
            dict(
                schema_version="outcome-input-anchor/v1",
                counter=counter,
                prev=ZERO,
                trust_sha256=policy.digest,
                state=state,
            )
        )
    raw = sign_anchors(rows)
    return raw, checkpoint_of(raw)


def make_witness_bundle(
    directory, *, source_override=None, anchors_raw=None, anchor_checkpoint=None
):
    """Return paths/files, pure evaluator arguments and external intake pins.

    source_override has trust_raw/source_raw/arguments, with the unchanged Source
    expected_* argument fields. Actual keys require actual supplied anchor bytes;
    no fallback signer is inferred from a public key. Pins are retained after all
    fixture scenario rebinding, before callers introduce negative mutations.
    """
    bundle = make_proof_bundle(directory, "source_bad_suffix")
    files, paths = bundle["files"], bundle["paths"]
    source = bundle["inputs"]["source"]
    if source_override is not None:
        source = {
            name: deepcopy(source_override[name])
            for name in ("trust_raw", "source_raw", "arguments")
        }
        context = source["arguments"]["expected_context"]
        source["kernel_boot_id"] = str(UUID(hex=context["boot_ref"]))
        size = source["arguments"]["expected_prefix_checkpoint"]["size"]
        source["valid_prefix"] = source["source_raw"][:size]
        contract = json.loads(files["contract"])
        old_owner = contract["scope"]["owner"]
        contract = bind_contract_to_source(contract, source)
        remap = {
            old_owner["producer_uid"]: context["producer_uid"],
            old_owner["observer_uid"]: context["observer_uid"],
        }
        for descriptor in contract["channels"].values():
            descriptor["source_actor_uid"] = remap[descriptor["source_actor_uid"]]
        files["contract"] = wire(contract)
        observations = json.loads(files["observations"])
        observations.update(
            contract_sha256=digest(files["contract"]), scope=deepcopy(contract["scope"])
        )
        heads = {}
        for category, channel in observations["channels"].items():
            for row in channel["rows"]:
                row.update(
                    contract_sha256=digest(files["contract"]),
                    scope=deepcopy(contract["scope"]),
                )
            heads[category] = sign(channel["rows"])
        files["observations"] = wire(observations)
        enrollment, checkpoint = (
            json.loads(files["enrollment"]),
            json.loads(files["checkpoint"]),
        )
        enrollment.update(
            contract_sha256=digest(files["contract"]),
            scope=contract["scope"],
            observer_uid=context["observer_uid"],
        )
        checkpoint.update(
            contract_sha256=digest(files["contract"]),
            scope=contract["scope"],
            stream_heads=heads,
        )
        files["enrollment"], files["checkpoint"] = wire(enrollment), wire(checkpoint)
        plan = json.loads(files["source_plan"])
        plan.update(
            contract_sha256=digest(files["contract"]),
            trust_sha256=digest(source["trust_raw"]),
            context=context,
            prefix_checkpoint=source["arguments"]["expected_prefix_checkpoint"],
            final_checkpoint=source["arguments"]["expected_final_checkpoint"],
        )
        files.update(
            source_plan=wire(plan),
            trust=source["trust_raw"],
            source=source["source_raw"],
        )
        supplement = json.loads(files["supplement"])
        supplement.update(
            enrollment_sha256=digest(files["enrollment"]),
            checkpoint_sha256=digest(files["checkpoint"]),
        )
        for name in supplement["sha256"]:
            supplement["sha256"][name] = digest(files[name]) if name in files else None
        files["supplement"] = wire(supplement)
    if anchors_raw is None and source_override is None:
        anchors_raw, generated = anchors_for_source(source)
        if anchor_checkpoint is None:
            anchor_checkpoint = generated
    paths.update(
        {
            name: Path(directory) / (name + ".json")
            for name in ("witness_plan", "anchors", "witness_supplement")
        }
    )
    files["witness_plan"] = wire(
        dict(
            schema_version="edge-source-witness-plan/v1",
            contract_sha256=digest(files["contract"]),
            source_plan_sha256=digest(files["source_plan"]),
            anchor_checkpoint=anchor_checkpoint,
        )
    )
    if anchors_raw is not None:
        files["anchors"] = anchors_raw
    files["witness_supplement"] = wire(
        dict(
            schema_version="edge-source-witness-enrollment/v1",
            enrollment_sha256=digest(files["enrollment"]),
            supplement_sha256=digest(files["supplement"]),
            plan_path=str(paths["witness_plan"]),
            plan_sha256=digest(files["witness_plan"]),
            anchors_path=str(paths["anchors"]) if anchors_raw is not None else None,
            anchors_sha256=digest(anchors_raw) if anchors_raw is not None else None,
        )
    )
    contract, checkpoint = (
        json.loads(files["contract"]),
        json.loads(files["checkpoint"]),
    )
    arguments = dict(
        proof_arguments=dict(
            safety_pins=dict(
                expected_contract_sha256=digest(files["contract"]),
                expected_stream_heads=checkpoint["stream_heads"],
                **contract["keypins"],
            ),
            source_plan_raw=files["source_plan"],
            expected_source_plan_sha256=digest(files["source_plan"]),
            trust_raw=files["trust"],
            source_raw=files.get("source"),
        ),
        witness_plan_raw=files["witness_plan"],
        expected_witness_plan_sha256=digest(files["witness_plan"]),
        anchors_raw=anchors_raw,
    )
    pins = {
        f"expected_{name}_sha256": digest(files[name])
        for name in ("enrollment", "checkpoint", "supplement", "witness_supplement")
    }
    inputs = dict(
        contract_raw=files["contract"],
        observations_raw=files["observations"],
        arguments=arguments["proof_arguments"],
        source=source,
    )
    return dict(
        paths=paths,
        files=files,
        arguments=arguments,
        pins=pins,
        scope=contract["scope"],
        inputs=inputs,
        **pins,
    )
