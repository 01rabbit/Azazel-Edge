"""Pure comparison of enrolled, discrete fixed NFT chain snapshots.

Root query metadata is an enrolled assertion, never kernel attestation. Source
signatures authenticate producer statements, never actual execution or efficacy.
"""

import hashlib
import re
import uuid
from datetime import datetime, timezone

from azazel_edge.outcome import nft_flow_evidence as flow
from azazel_edge.outcome.journal import _json
from . import safety_observations as safety
from .safety_proofs import _source

PHASES = ("baseline", "applied", "released")


class RecordedNFTRestorationInputError(ValueError):
    """Malformed global enrollment, pin, or input slot."""


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _same(a, b):
    return _json(a) == _json(b)


def _tree(value, depth=0):
    safety._need(depth <= 12, "JSON depth bound")
    if type(value) is list:
        safety._need(len(value) <= 4096, "JSON array bound")
        for item in value:
            _tree(item, depth + 1)
    elif type(value) is dict:
        for item in value.values():
            _tree(item, depth + 1)


def _time(value):
    safety._need(type(value) is str and len(value) <= 40, "UTC timestamp")
    result = datetime.fromisoformat(value)
    safety._need(
        result.tzinfo is not None
        and result.utcoffset().total_seconds() == 0
        and result.astimezone(timezone.utc).isoformat() == value,
        "canonical aware UTC timestamp",
    )
    return result


def _identity(value):
    safety._fields(value, "source_revision helper_sha256 network_driver_sha256")
    safety._need(
        type(value["source_revision"]) is str
        and re.fullmatch("[0-9a-f]{40}", value["source_revision"]),
        "source revision",
    )
    for key in ("helper_sha256", "network_driver_sha256"):
        safety._hex(value[key])


def _argv(value):
    safety._need(type(value) is list and 0 < len(value) <= 64, "argv bound")
    safety._need(
        all(type(v) is str and 0 < len(v) <= 4096 and "\0" not in v for v in value),
        "literal argv",
    )


def _plan(raw, expected, source_inputs, receipts):
    safety._hex(expected)
    safety._need(type(raw) is bytes and _sha(raw) == expected, "plan pin differs")
    p = safety._wire(raw, 32768)
    safety._fields(
        p,
        "schema_version contract_sha256 source_plan_sha256 source_event_seq source_event_sha256 kernel_boot_id netns_inode query_window source_identity nft_binary_sha256 receipts",
    )
    safety._need(
        p["schema_version"] == "edge-recorded-nft-restoration-plan/v1", "plan schema"
    )
    for key in (
        "contract_sha256",
        "source_plan_sha256",
        "source_event_sha256",
        "nft_binary_sha256",
    ):
        safety._hex(p[key])
    safety._int(p["source_event_seq"], 1, 32768)
    safety._int(p["netns_inode"], 1)
    safety._need(
        type(p["kernel_boot_id"]) is str
        and str(uuid.UUID(p["kernel_boot_id"])) == p["kernel_boot_id"],
        "boot",
    )
    _identity(p["source_identity"])
    safety._fields(p["query_window"], "start end")
    start, end = (_time(p["query_window"][k]) for k in ("start", "end"))
    safety._need(0 < (end - start).total_seconds() <= 120, "query window")
    safety._fields(source_inputs, "contract_raw source_plan_raw trust_raw source_raw")
    for key in source_inputs:
        safety._need(
            type(source_inputs[key]) is bytes or source_inputs[key] is None,
            "Source byte slot",
        )
    safety._fields(receipts, " ".join(PHASES))
    safety._fields(p["receipts"], " ".join(PHASES))
    for phase in PHASES:
        safety._need(
            receipts[phase] is None or type(receipts[phase]) is bytes,
            "receipt byte slot",
        )
        descriptor = p["receipts"][phase]
        if descriptor is not None:
            safety._fields(descriptor, "sha256 root_pid actual_child_argv")
            safety._hex(descriptor["sha256"])
            safety._int(descriptor["root_pid"], 1, 2**31 - 1)
            _argv(descriptor["actual_child_argv"])
    return p, start, end


def _source_scope(p, inputs):
    contract = safety._wire(inputs["contract_raw"], 128 * 1024)
    pins = contract["keypins"]
    safety._fields(
        pins, "observer_public_key source_producer_public_key source_witness_public_key"
    )
    for value in pins.values():
        safety._hex(value)
    safety._need(len(set(pins.values())) == 3, "key roles overlap")
    safety._contract(contract, pins)
    safety._need(
        _sha(inputs["contract_raw"]) == p["contract_sha256"], "contract pin differs"
    )
    result = _source(
        inputs["contract_raw"],
        inputs["source_plan_raw"],
        p["source_plan_sha256"],
        inputs["trust_raw"],
        inputs["source_raw"],
    )
    safety._need(
        result["authenticated_full_source"] is True,
        "full Source authentication unavailable",
    )
    safety._need(
        contract["scope"]["kernel_boot_id"] == p["kernel_boot_id"],
        "Source boot differs",
    )
    lines = inputs["source_raw"].splitlines(keepends=True)
    safety._need(len(lines) >= p["source_event_seq"], "selected Source row missing")
    raw = lines[p["source_event_seq"] - 1]
    safety._need(
        _sha(raw) == p["source_event_sha256"], "selected Source row pin differs"
    )
    wire = flow.parse_readback(raw)
    event = wire["event"]
    safety._need(
        wire["seq"] == p["source_event_seq"]
        and event["capture_origin"]["kind"] == "decision_execution",
        "selected Source event kind",
    )
    native = {k: v for k, v in event.items() if k != "capture_origin"}
    enforcement = native["enforcement"]
    safety._need(
        enforcement["mode"] == "enforced"
        and enforcement["result"] == "applied"
        and type(enforcement["executed_count"]) is int
        and enforcement["executed_count"] > 0
        and type(enforcement["failed_count"]) is int
        and enforcement["failed_count"] == 0,
        "producer applied assertion unavailable",
    )
    safety._need(
        native["enforcement_status"]["enforce_enabled"] is True
        and native["enforcement_status"]["dry_run"] is False,
        "enforcement disabled/dry run",
    )
    scope = flow.flow_scope(
        enforcement["command_plan"],
        enforcement["rollback_plan"],
        enforcement["metadata"],
        enforcement["trace_id"],
        normalized=native["normalized"],
    )
    return result, scope


def _receipt(raw, descriptor, p, start, end, scope):
    safety._need(
        type(raw) is bytes and 0 < len(raw) <= 8 * 1024 * 1024, "receipt byte bound"
    )
    safety._need(_sha(raw) == descriptor["sha256"], "receipt pin differs")
    r = flow.parse_readback(raw)
    _tree(r)
    safety._fields(
        r,
        "argv returncode stdout stderr query_started_at query_ended_at root_pid root_uid kernel_boot_id source_identity netns_inode nft_binary_sha256 capture_boundary actual_child_argv source",
    )
    safety._need(
        _same(r["argv"], list(flow.QUERY))
        and type(r["returncode"]) is int
        and r["returncode"] == 0
        and type(r["root_uid"]) is int
        and r["root_uid"] == 0,
        "query command/role/result",
    )
    safety._need(
        type(r["stdout"]) is str
        and len(r["stdout"].encode()) <= 8 * 1024 * 1024
        and r["stderr"] == "",
        "query output",
    )
    for key in ("root_pid", "actual_child_argv"):
        safety._need(_same(r[key], descriptor[key]), "query child differs")
    for key in (
        "kernel_boot_id",
        "netns_inode",
        "source_identity",
        "nft_binary_sha256",
    ):
        safety._need(_same(r[key], p[key]), "query context differs")
    safety._need(
        r["capture_boundary"]
        == "actual_root_SubprocessReadOnlyRunner_inside_owned_netns"
        and r["source"] == "live_root_query_recorded_once_for_pure_projection",
        "query provenance label",
    )
    a, b = _time(r["query_started_at"]), _time(r["query_ended_at"])
    safety._need(start <= a <= b <= end, "query outside window")
    payload = flow.parse_readback(r["stdout"])
    _tree(payload)
    owned = flow.validated_owner_rows(payload, scope["owner_token"])
    return payload, owned, (a, b)


def evaluate_recorded_nft_restoration(
    plan_raw, *, expected_plan_sha256, source_inputs, receipts
):
    """No I/O: enrolled original snapshots, not fresh acquisition or execution truth."""
    try:
        p, start, end = _plan(plan_raw, expected_plan_sha256, source_inputs, receipts)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        raise RecordedNFTRestorationInputError(str(exc)) from exc
    reasons, source, scope = [], None, None
    try:
        source, scope = _source_scope(p, source_inputs)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        reasons.append("source_owner_binding_unavailable")
    phases, snapshots, rows, times = {}, {}, {}, {}
    for phase in PHASES:
        raw, descriptor = receipts[phase], p["receipts"][phase]
        item = dict(
            disposition="unavailable",
            owner_rule_count=None,
            raw_sha256=_sha(raw)
            if type(raw) is bytes and len(raw) <= 8 * 1024 * 1024
            else None,
            reasons=[],
        )
        phases[phase] = item
        if raw is None or descriptor is None:
            item["reasons"].append("receipt_unavailable")
        elif scope is None:
            item["reasons"].append("source_owner_binding_unavailable")
        else:
            try:
                payload, owned, bracket = _receipt(
                    raw, descriptor, p, start, end, scope
                )
                snapshots[phase], rows[phase], times[phase] = payload, owned, bracket
                item.update(
                    disposition="valid_recorded_snapshot", owner_rule_count=len(owned)
                )
            except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
                item.update(disposition="invalid", reasons=["invalid_recorded_receipt"])
    foreign, restored, applied = None, None, False
    if "baseline" in snapshots and "applied" in snapshots:
        base, active = snapshots["baseline"], snapshots["applied"]
        if not rows["baseline"] and len(rows["applied"]) == 1:
            stripped = {
                "nftables": [
                    e
                    for e in active["nftables"]
                    if not ("rule" in e and e["rule"] is rows["applied"][0])
                ]
            }
            foreign = _same(base, stripped)
            try:
                applied = flow.readback_matches(active, scope)
            except (ValueError, TypeError, KeyError):
                pass
    if "baseline" in snapshots and "released" in snapshots:
        restored = (
            not rows["baseline"]
            and not rows["released"]
            and _same(snapshots["baseline"], snapshots["released"])
        )
    ordered = (
        len(times) == 3
        and times["baseline"][1]
        <= times["applied"][0]
        <= times["applied"][1]
        <= times["released"][0]
    )
    residue = (
        ("released" in rows and bool(rows["released"]))
        or foreign is False
        or restored is False
    )
    complete = ordered and applied and foreign is True and restored is True
    if not ordered:
        reasons.append("query_order_unavailable_or_invalid")
    if not complete:
        reasons.append("recorded_comparison_incomplete_or_changed")
    return dict(
        schema_version="edge-recorded-nft-restoration-diagnostic/v1",
        status="sampled_fixed_chain_returned_to_baseline"
        if complete
        else "recorded_residue_or_change"
        if residue
        else "unknown",
        source_authentication=source,
        source_owner_bound=scope is not None,
        phases=phases,
        applied_foreign_matches_baseline=foreign,
        released_matches_baseline=restored,
        reasons=reasons,
        network_mechanism_restored=None,
        qualified_safety_count=None,
        execution_fact_verified=False,
        independently_measured=False,
        **safety.FLAGS,
    )
