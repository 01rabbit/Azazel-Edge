"""PUBLIC synthetic Source fixtures: existing wire/signers, no runtime/key files."""

from copy import deepcopy
import json
from pathlib import Path

from auth_input_helpers import make_policy
from test_outcome_input_auth import signed
from test_outcome_live_origin import frame, signed_frame
from safety_observation_data import KEYS, wire, digest
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier, public_hex
from azazel_edge.outcome.journal import _json

BOOT = "00000000-0000-4000-8000-000000000001"
SESSION = "0123456789abcdef0123456789abcdef"


def make_source_case(
    directory,
    case="source_closed",
    *,
    scope_ref="synthetic-source-scope",
    session_ref=SESSION,
    kernel_boot_id=BOOT,
):
    """Return canonical trust/Source bytes, externally retained checkpoints/context."""
    base, *_ = make_policy(Path(directory), producer=61001, observer=61002, witness=0)
    policy = TrustPolicy(
        dict(
            base.data,
            schema_version="outcome-input-trust/v3",
            scope_ref=scope_ref,
            producer_public_key=public_hex(KEYS[1]),
            witness_public_key=public_hex(KEYS[2]),
            origin_registration_sha256="f" * 64,
        )
    )
    key = KEYS[1]
    context = {
        name: policy.data[name]
        for name in (
            "scope_ref",
            "producer_ref",
            "stream_ref",
            "producer_public_key",
            "witness_public_key",
            "producer_uid",
            "observer_uid",
        )
    }
    context.update(
        registration_sha256=policy.data["origin_registration_sha256"],
        session_ref=session_ref,
        boot_ref=kernel_boot_id.replace("-", ""),
    )
    native = [
        frame("session_prepare", 0, session_ref),
        frame("session_start", 1, session_ref),
    ]
    if case == "source_finite_float":
        native.append(frame("decision_execution", 2, session_ref))
    if case != "source_open":
        native.append(frame("session_end", len(native), session_ref))
    verifier = SourceVerifier(policy)
    rows = []
    raw = b""
    prefix_tip = None
    for index, item in enumerate(native, 1):
        event = json.loads(signed_frame(policy, key, item, index, verifier.head))[
            "event"
        ]
        line = signed(
            policy,
            key,
            seq=index,
            prev=verifier.head,
            event=event,
            boot_ref=context["boot_ref"],
        )
        raw += line
        tip = verifier.verify(raw)
        rows.append(json.loads(line))
        if index == 1:
            prefix_tip = deepcopy(tip)
    valid_source = raw
    valid_prefix = _json(rows[0]) + b"\n"
    final_tip = deepcopy(tip)
    source = raw
    if case in ("source_bad_suffix", "source_bad_suffix_positive"):
        source += b'{"truncated":'
    elif case == "source_bad_signature":
        row = rows[-1]
        row["signature"] = ("0" if row["signature"][0] != "0" else "1") + row[
            "signature"
        ][1:]
        source = b"".join(wire(row) for row in rows)
    elif case == "source_rewind":
        source = valid_prefix
    elif case in (
        "source_wrong_boot",
        "source_wrong_session",
        "source_wrong_registration",
    ):
        previous = digest(_json(rows[0]))
        rewritten = [wire(rows[0])]
        for row in rows[1:]:
            event = deepcopy(row["event"])
            if case == "source_wrong_session":
                event["capture_origin"]["session_ref"] = "a" * 32
            if case == "source_wrong_registration":
                event["capture_origin"]["registration_sha256"] = "e" * 64
            line = signed(
                policy,
                key,
                seq=row["seq"],
                prev=previous,
                event=event,
                boot_ref="a" * 32
                if case == "source_wrong_boot"
                else context["boot_ref"],
            )
            previous = digest(_json(json.loads(line)))
            rewritten.append(line)
        source = b"".join(rewritten)
    elif case == "source_empty":
        source = b""
        prefix_tip = None
        final_tip = None
    elif case == "source_missing":
        source = None
    elif case == "source_checkpoint_mismatch":
        final_tip["head"] = "e" * 64
    trust_raw = wire(dict(policy.data))
    arguments = dict(
        expected_trust_sha256="e" * 64
        if case == "source_wrong_trust_pin"
        else digest(trust_raw),
        expected_context=context,
        expected_prefix_checkpoint=prefix_tip,
        expected_final_checkpoint=final_tip,
    )
    return dict(
        trust_raw=trust_raw,
        source_raw=source,
        arguments=arguments,
        valid_prefix=valid_prefix,
        valid_source=valid_source,
        trust=policy,
        kernel_boot_id=kernel_boot_id,
    )


def bind_contract_to_source(contract, source):
    """Test fixture binding only; no imported Source receipt becomes authority."""
    value = deepcopy(contract)
    context = source["arguments"]["expected_context"]
    value["keypins"].update(
        source_producer_public_key=context["producer_public_key"],
        source_witness_public_key=context["witness_public_key"],
    )
    value["scope"].update(
        source_sha256=digest(source["valid_prefix"]),
        policy_sha256=digest(source["trust_raw"]),
        scope_ref=context["scope_ref"],
        session_ref=context["session_ref"],
        registration_sha256=context["registration_sha256"],
        kernel_boot_id=source["kernel_boot_id"],
        owner=dict(
            producer_uid=context["producer_uid"], observer_uid=context["observer_uid"]
        ),
    )
    for category, descriptor in value["channels"].items():
        descriptor["collector_boot_id"] = source["kernel_boot_id"]
        for opportunity in value["opportunities"][category]:
            opportunity["reference_sha256"] = digest(source["valid_prefix"])
    return value


def make_safety_proof_inputs(directory, case="source_closed", *, kernel_boot_id=BOOT):
    """Synthetic independent observation + Source proof; all rebindings before heads."""
    from safety_observation_data import build, sign

    source = make_source_case(directory, case, kernel_boot_id=kernel_boot_id)
    old_contract, old_observations, _ = build("violation-forged_evidence_accepted")
    contract = bind_contract_to_source(json.loads(old_contract), source)
    contract_raw = wire(contract)
    contract_sha = digest(contract_raw)
    observations = json.loads(old_observations)
    observations.update(contract_sha256=contract_sha, scope=deepcopy(contract["scope"]))
    heads = {}
    for category, channel in observations["channels"].items():
        for row in channel["rows"]:
            row.update(contract_sha256=contract_sha, scope=deepcopy(contract["scope"]))
        heads[category] = sign(channel["rows"])
    source_plan = dict(
        schema_version="edge-source-proof-plan/v1",
        contract_sha256=contract_sha,
        trust_sha256=digest(source["trust_raw"]),
        context=deepcopy(source["arguments"]["expected_context"]),
        prefix_checkpoint=deepcopy(source["arguments"]["expected_prefix_checkpoint"]),
        final_checkpoint=deepcopy(source["arguments"]["expected_final_checkpoint"]),
    )
    source_plan_raw = wire(source_plan)
    arguments = dict(
        safety_pins=dict(
            expected_contract_sha256=contract_sha,
            expected_stream_heads=heads,
            **contract["keypins"],
        ),
        source_plan_raw=source_plan_raw,
        expected_source_plan_sha256=digest(source_plan_raw),
        trust_raw=source["trust_raw"],
        source_raw=source["source_raw"],
    )
    return dict(
        contract_raw=contract_raw,
        observations_raw=wire(observations),
        arguments=arguments,
        source=source,
    )


def make_proof_bundle(directory, case="source_closed", *, kernel_boot_id=BOOT):
    """Public SEALED-intake fixture bytes only; caller owns actual staging/UIDs."""
    from azazel_edge.benchmark.safety_proofs import FILES

    directory = Path(directory)
    inputs = make_safety_proof_inputs(directory, case, kernel_boot_id=kernel_boot_id)
    contract = json.loads(inputs["contract_raw"])
    paths = {
        name: directory / (name + ".json")
        for name in (
            "enrollment",
            "contract",
            "observations",
            "checkpoint",
            "supplement",
            *FILES,
        )
    }
    base = dict(
        schema_version="edge-safety-enrollment/v1",
        contract_sha256=digest(inputs["contract_raw"]),
        scope=contract["scope"],
        observer_uid=contract["scope"]["owner"]["observer_uid"],
        paths={
            name: str(paths[name])
            for name in ("contract", "observations", "checkpoint")
        },
    )
    checkpoint = dict(
        schema_version="edge-safety-checkpoint/v1",
        contract_sha256=base["contract_sha256"],
        scope=contract["scope"],
        capture_ids={
            category: descriptor["capture_id"]
            for category, descriptor in contract["channels"].items()
        },
        stream_heads=inputs["arguments"]["safety_pins"]["expected_stream_heads"],
    )
    files = dict(
        enrollment=wire(base),
        contract=inputs["contract_raw"],
        observations=inputs["observations_raw"],
        checkpoint=wire(checkpoint),
        source_plan=inputs["arguments"]["source_plan_raw"],
        trust=inputs["arguments"]["trust_raw"],
    )
    if inputs["arguments"]["source_raw"] is not None:
        files["source"] = inputs["arguments"]["source_raw"]
    supplement = dict(
        schema_version="edge-safety-proof-enrollment/v1",
        enrollment_sha256=digest(files["enrollment"]),
        checkpoint_sha256=digest(files["checkpoint"]),
        paths={name: str(paths[name]) if name in files else None for name in FILES},
        sha256={name: digest(files[name]) if name in files else None for name in FILES},
    )
    files["supplement"] = wire(supplement)
    return dict(
        paths=paths,
        files=files,
        scope=contract["scope"],
        inputs=inputs,
        expected_enrollment_sha256=digest(files["enrollment"]),
        expected_checkpoint_sha256=digest(files["checkpoint"]),
        expected_supplement_sha256=digest(files["supplement"]),
    )
