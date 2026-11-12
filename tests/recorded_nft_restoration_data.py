"""SYNTHETIC recorded NFT snapshots and producer assertions, real TEST signatures."""

from copy import deepcopy
from pathlib import Path
import json

from azazel_edge.outcome import from_rust_event
from azazel_edge.outcome.input_auth import SourceVerifier
from azazel_edge.outcome.nft_flow_evidence import QUERY
from safety_observation_data import build, digest, wire, KEYS
from source_recovery_data import BOOT, make_source_case, bind_contract_to_source
from test_outcome_input_auth import signed
from test_outcome_live_origin import frame, signed_frame
from test_outcome_nft_flow_evidence import event, payload

PHASES = ("baseline", "applied", "released")


def make_restoration_case(directory, *, native_mutator=None, kernel_boot_id=BOOT):
    """Canonical enrolled plan, unchanged original receipts and fully signed Source.

    native_mutator changes the SYNTHETIC producer event before signing/pin retention.
    This is not a command runner, actual Root query, or kernel execution receipt.
    """
    source = make_source_case(directory, kernel_boot_id=kernel_boot_id)
    policy, context = source["trust"], source["arguments"]["expected_context"]
    native = event()
    native["enforcement_status"] = dict(
        enforce_enabled=True, dry_run=False, high_impact_auto=False
    )
    if native_mutator is not None:
        native_mutator(native)
    state = SourceVerifier(policy)
    raw, selected = b"", None
    lifecycle = [
        frame("session_prepare", 0, context["session_ref"]),
        frame("session_start", 1, context["session_ref"]),
        frame("decision_execution", 2, context["session_ref"], native),
        frame("session_end", 3, context["session_ref"]),
    ]
    for seq, native_frame in enumerate(lifecycle, 1):
        ev = json.loads(signed_frame(policy, KEYS[1], native_frame, seq, state.head))[
            "event"
        ]
        line = signed(
            policy,
            KEYS[1],
            seq=seq,
            prev=state.head,
            event=ev,
            boot_ref=context["boot_ref"],
        )
        raw += line
        tip = state.verify(raw)
        if seq == 1:
            prefix = deepcopy(tip)
            source["valid_prefix"] = line
        if seq == 3:
            selected = line
    source.update(source_raw=raw, valid_source=raw)
    source["arguments"].update(
        expected_prefix_checkpoint=prefix, expected_final_checkpoint=deepcopy(tip)
    )
    old, _, _ = build("violation-forged_evidence_accepted")
    contract_raw = wire(bind_contract_to_source(json.loads(old), source))
    source_plan_raw = wire(
        dict(
            schema_version="edge-source-proof-plan/v1",
            contract_sha256=digest(contract_raw),
            trust_sha256=digest(source["trust_raw"]),
            context=context,
            prefix_checkpoint=prefix,
            final_checkpoint=tip,
        )
    )
    # Use the original valid event to describe readback even in assertion-negative cases.
    scope = from_rust_event(event()).mechanism.scope
    applied = payload(scope)
    owned = applied["nftables"].pop()
    foreign = deepcopy(owned)
    foreign["rule"].update(
        handle=7,
        comment="foreign-canary-one",
        expr=[{"counter": {"packets": 1, "bytes": 64}}, {"accept": None}],
    )
    other = deepcopy(foreign)
    other["rule"].update(handle=8, comment="foreign-canary-two")
    baseline = deepcopy(applied)
    baseline["nftables"].extend([foreign, other])
    applied = deepcopy(baseline)
    applied["nftables"].append(owned)
    snapshots = dict(baseline=baseline, applied=applied, released=deepcopy(baseline))
    source_identity = dict(
        source_revision="a" * 40, helper_sha256="b" * 64, network_driver_sha256="c" * 64
    )
    plan = dict(
        schema_version="edge-recorded-nft-restoration-plan/v1",
        contract_sha256=digest(contract_raw),
        source_plan_sha256=digest(source_plan_raw),
        source_event_seq=3,
        source_event_sha256=digest(selected),
        kernel_boot_id=source["kernel_boot_id"],
        netns_inode=12345,
        query_window=dict(
            start="2026-11-13T00:00:00+00:00", end="2026-11-13T00:01:00+00:00"
        ),
        source_identity=source_identity,
        nft_binary_sha256="d" * 64,
        receipts={},
    )
    receipts = {}
    for index, phase in enumerate(PHASES):
        argv = ["/synthetic/python", "-I", "/synthetic/root-query.py", phase]
        receipt = dict(
            argv=list(QUERY),
            returncode=0,
            stdout=json.dumps(snapshots[phase]),
            stderr="",
            query_started_at=f"2026-11-13T00:00:{index * 10 + 1:02d}+00:00",
            query_ended_at=f"2026-11-13T00:00:{index * 10 + 2:02d}+00:00",
            root_pid=100 + index,
            root_uid=0,
            kernel_boot_id=source["kernel_boot_id"],
            source_identity=source_identity,
            netns_inode=12345,
            nft_binary_sha256="d" * 64,
            capture_boundary="actual_root_SubprocessReadOnlyRunner_inside_owned_netns",
            actual_child_argv=argv,
            source="live_root_query_recorded_once_for_pure_projection",
        )
        receipts[phase] = json.dumps(receipt, indent=2).encode()
        plan["receipts"][phase] = dict(
            sha256=digest(receipts[phase]), root_pid=100 + index, actual_child_argv=argv
        )
    return dict(
        plan_raw=wire(plan),
        expected_plan_sha256=digest(wire(plan)),
        source_inputs=dict(
            contract_raw=contract_raw,
            source_plan_raw=source_plan_raw,
            trust_raw=source["trust_raw"],
            source_raw=raw,
        ),
        receipts=receipts,
        plan=plan,
        snapshots=snapshots,
        source=source,
        signed_event_wire=selected,
        scope=scope,
    )


def retain_plan(value):
    """Test enrollment after scenario construction, BEFORE corruption tests."""
    value["plan_raw"] = wire(value["plan"])
    value["expected_plan_sha256"] = digest(value["plan_raw"])


def change_receipt(value, phase, mutate=None, *, snapshot_mutator=None):
    """Construct/re-enroll a SYNTHETIC receipt scenario; never a runtime repair."""
    receipt = json.loads(value["receipts"][phase])
    if snapshot_mutator is not None:
        snapshot = json.loads(receipt["stdout"])
        snapshot_mutator(snapshot)
        receipt["stdout"] = json.dumps(snapshot)
    if mutate is not None:
        mutate(receipt)
    value["receipts"][phase] = json.dumps(receipt, indent=2).encode()
    value["plan"]["receipts"][phase]["sha256"] = digest(value["receipts"][phase])
    retain_plan(value)


def make_restoration_bundle(directory, *, kernel_boot_id=BOOT):
    """Byte-only Root registration for filesystem tests; NFT facts stay SYNTHETIC."""
    case = make_restoration_case(directory, kernel_boot_id=kernel_boot_id)
    inputs = case["source_inputs"]
    files = dict(
        plan=case["plan_raw"],
        contract=inputs["contract_raw"],
        source_plan=inputs["source_plan_raw"],
        trust=inputs["trust_raw"],
        source=inputs["source_raw"],
        **case["receipts"],
    )
    paths = {
        name: Path(directory) / (name + ".json") for name in (*files, "enrollment")
    }
    contract = json.loads(files["contract"])
    files["enrollment"] = wire(
        dict(
            schema_version="edge-recorded-nft-enrollment/v1",
            observer_uid=contract["scope"]["owner"]["observer_uid"],
            kernel_boot_id=kernel_boot_id,
            paths={name: str(paths[name]) for name in files},
            sha256={name: digest(raw) for name, raw in files.items()},
        )
    )
    return dict(
        paths=paths,
        files=files,
        expected_enrollment_sha256=digest(files["enrollment"]),
        case=case,
    )
