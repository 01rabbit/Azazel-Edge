"""Recorded protocol-copy/validation-response consistency, never branch proof."""

from copy import deepcopy
import uuid

from azazel_edge.outcome.journal import _ref
from . import safety_observations as safety
from .advisory_exec import _object, _uint, _sha, _need, ERRORS
from .authority_ingress import (
    _path,
    _identity,
    _worker,
    _sample,
    _endpoint,
    _lifecycle,
    _patch,
    _linux_device,
    MAX_ARTIFACT,
)

CASES = frozenset(
    (
        "root_patch",
        "devices_not_list",
        "invalid_allowed_networks",
        "observer_loss_after_refusal",
        "missing_after_sot",
    )
)
CONFIG = "pidns_device pidns_inode server_start_ticks actor_start_ticks started_ns deadline_ns server_tgid actor_tgid user_hz max_events"
EVENT = "entered_ns exited_ns start_ns receiver_inode peer_inode endpoint_inode role tgid tid uid euid netns_inode endpoint_major endpoint_minor flags iter_type data_source skip chunk consumed skb_len data_len ret reserved data_hex"
COUNTERS = "selected_entries pending_inserted successful_copies emitted copy_failure unsupported read_failure identity_failure correlation_loss overflow inflight unmatched_exit"
PARTIAL = frozenset(
    (
        "observer_link_lost",
        "copy_failure",
        "unsupported_copy",
        "read_failure",
        "identity_failure",
        "correlation_loss",
        "overflow",
        "pending_not_empty",
        "unmatched_exit",
        "acquisition_error",
        "observer_cleanup_unverified",
    )
)
REFUSALS = {
    "devices_not_list": "devices_must_be_list",
    "invalid_allowed_networks": "invalid_sot:device_allowed_networks_must_be_list",
    "observer_loss_after_refusal": "devices_must_be_list",
}


class PostconnectRefusalInputError(ValueError):
    """Malformed pinned global plan, not an observed application refusal."""


def _request(case):
    devices = (
        "not-a-list"
        if case in ("devices_not_list", "observer_loss_after_refusal")
        else [
            {"id": "dev-1", "allowed_networks": "lan-main"}
            if case == "invalid_allowed_networks"
            else {"id": "dev-1", "hostname": "client-1-observed"}
        ]
    )
    return {"action": "sot_devices_patch", "params": {"devices": devices}}


def _plan(raw, pin):
    safety._hex(pin)
    p = _object(raw, 32768)
    _need(_sha(raw) == pin, "external plan hash differs")
    safety._fields(
        p,
        "schema_version capture_id case_id kernel_boot_id request_utf8 request_sha256 requested_path target_paths control_endpoint actor server go configuration samples probe_sha256 observer_source_sha256 observer_object_sha256",
    )
    _need(
        p["schema_version"] == "edge-postconnect-refusal-plan/v1"
        and type(p["case_id"]) is str
        and p["case_id"] in CASES,
        "plan schema/case",
    )
    _ref(p["capture_id"])
    _need(
        type(p["kernel_boot_id"]) is str
        and str(uuid.UUID(p["kernel_boot_id"])) == p["kernel_boot_id"],
        "boot UUID",
    )
    for key in ("request_sha256", "observer_source_sha256", "observer_object_sha256"):
        safety._hex(p[key])
    if p["probe_sha256"] is not None:
        safety._hex(p["probe_sha256"])
    _need(
        type(p["request_utf8"]) is str and len(p["request_utf8"]) <= 4096,
        "request bound",
    )
    request_raw = p["request_utf8"].encode("utf-8")
    _need(
        _sha(request_raw) == p["request_sha256"]
        and safety._same(_object(request_raw, 4096), _request(p["case_id"])),
        "fixed request differs",
    )
    safety._fields(p["target_paths"], "sot audit")
    for path in p["target_paths"].values():
        _path(path, 256)
    _need(
        p["target_paths"]["sot"] != p["target_paths"]["audit"], "target paths overlap"
    )
    _path(p["requested_path"])
    e = p["control_endpoint"]
    safety._fields(
        e,
        "path parent_before parent_after socket_before socket_after before_sample_ns after_sample_ns control_gid",
    )
    _path(e["path"])
    for key in ("before_sample_ns", "after_sample_ns", "control_gid"):
        _uint(e[key], 2**32 - 1 if key == "control_gid" else 2**64 - 1)
    for key in ("parent_before", "parent_after", "socket_before", "socket_after"):
        if e[key] is not None:
            _identity(e[key])
    _worker(p["actor"])
    _worker(p["server"], True)
    safety._fields(p["go"], "release_before_ns release_after_ns")
    for value in p["go"].values():
        _uint(value)
    cfg = p["configuration"]
    safety._fields(cfg, CONFIG)
    for key, value in cfg.items():
        _uint(
            value,
            2**32 - 1
            if key in ("server_tgid", "actor_tgid", "user_hz", "max_events")
            else 2**64 - 1,
        )
    _need(
        cfg["server_tgid"] > 1
        and cfg["actor_tgid"] > 1
        and cfg["server_tgid"] != cfg["actor_tgid"]
        and cfg["server_start_ticks"] > 0
        and cfg["actor_start_ticks"] > 0
        and cfg["pidns_device"] > 0
        and cfg["pidns_inode"] > 0
        and cfg["user_hz"] == 100
        and 1 <= cfg["max_events"] <= 16
        and 0 < cfg["deadline_ns"] - cfg["started_ns"] <= 5_000_000_000,
        "two-role configuration bounds",
    )
    safety._fields(p["samples"], "before after")
    for phase in ("before", "after"):
        safety._fields(p["samples"][phase], "sot audit")
    return p


def _response(raw, p):
    data = _object(raw, 256, canonical=False)
    if p["case_id"] in REFUSALS:
        safety._fields(data, "ok error ts")
        _need(
            data["ok"] is False and data["error"] == REFUSALS[p["case_id"]],
            "different validation response",
        )
        kind = "validation_refusal_response"
    else:
        safety._fields(data, "ok path diff audit_logged ts")
        _need(
            data["ok"] is True
            and data["path"] == p["target_paths"]["sot"]
            and data["audit_logged"] is True
            and safety._same(data["diff"], {"added": 0, "removed": 0, "updated": 1}),
            "different patch response",
        )
        kind = "patch_success_response"
    _need(type(data["ts"]) in (int, float), "actual finite timestamp metadata required")
    return kind


def _frame(event):
    raw = bytes.fromhex(event["data_hex"])
    return (
        event["skip"] == event["consumed"] == event["data_len"] == 0
        and event["skb_len"] == event["chunk"]
        and raw.endswith(b"\n")
        and raw.count(b"\n") == 1
        and b"\r" not in raw
    )


def _probe(p, raw, result, endpoint, lifecycle):
    _need(
        p["probe_sha256"] is not None
        and type(raw) is bytes
        and len(raw) <= 65536
        and _sha(raw) == p["probe_sha256"],
        "probe unavailable/hash/bounds",
    )
    report = _object(raw, 65536)
    safety._fields(
        report,
        "schema_version architecture started_ns finished_ns configuration events counters partial_reasons link_identities",
    )
    _need(
        report["schema_version"] == "edge-postconnect-copy-probe/v1"
        and report["architecture"] == "aarch64"
        and safety._same(report["configuration"], p["configuration"]),
        "probe schema/profile/configuration",
    )
    cfg = p["configuration"]
    a = p["actor"]
    s = p["server"]
    _need(
        cfg["actor_tgid"] == a["pid"]
        and cfg["server_tgid"] == s["pid"]
        and cfg["actor_start_ticks"] == a["start_ticks"]
        and cfg["server_start_ticks"] == s["start_ticks"]
        and cfg["pidns_device"] == a["pidns_device"]
        and cfg["pidns_inode"] == a["pidns_inode"],
        "configured two-role identity differs",
    )
    _uint(report["started_ns"])
    _uint(report["finished_ns"])
    _need(
        report["started_ns"] == cfg["started_ns"] <= report["finished_ns"],
        "probe clock order",
    )
    _need(
        type(report["events"]) is list and len(report["events"]) <= cfg["max_events"],
        "raw event bound",
    )
    complete = True
    starts = {}
    requests = []
    responses = []
    for index, event in enumerate(report["events"]):
        try:
            safety._fields(event, EVENT)
            for key, value in event.items():
                if key not in ("ret", "data_hex"):
                    _uint(
                        value,
                        2**64 - 1
                        if key
                        in (
                            "entered_ns",
                            "exited_ns",
                            "start_ns",
                            "receiver_inode",
                            "peer_inode",
                            "endpoint_inode",
                        )
                        else 2**32 - 1,
                    )
            _need(
                type(event["ret"]) is int
                and 1 <= event["ret"] == event["chunk"] <= 256,
                "completed positive chunk required",
            )
            _need(
                type(event["data_hex"]) is str
                and len(event["data_hex"]) == 2 * event["chunk"]
                and all(c in "0123456789abcdef" for c in event["data_hex"]),
                "exact lowercase original chunk required",
            )
            role = (
                0
                if event["tgid"] == s["pid"]
                else 1
                if event["tgid"] == a["pid"]
                else None
            )
            worker = s if role == 0 else a
            _need(
                role is not None
                and event["role"] == role
                and event["tid"] == event["tgid"]
                and worker["uid"] == event["uid"] == event["euid"] == 0
                and event["start_ns"] > 0
                and event["start_ns"] // 10_000_000 == worker["start_ticks"]
                and event["netns_inode"] == a["netns_inode"]
                and event["receiver_inode"] > 0
                and event["peer_inode"] > 0
                and event["endpoint_inode"] > 0
                and event["reserved"] == 0,
                "copy role/identity differs",
            )
            _need(
                event["flags"] in (0, 64)
                and event["iter_type"] in (0, 1)
                and event["data_source"] == 0
                and event["data_len"] == 0
                and event["consumed"] + event["skip"] + event["chunk"]
                <= event["skb_len"],
                "native destination/range profile differs",
            )
            _need(
                max(
                    cfg["started_ns"],
                    worker["started_ns"],
                    p["go"]["release_before_ns"],
                )
                <= event["entered_ns"]
                <= event["exited_ns"]
                <= min(cfg["deadline_ns"], worker["exited_ns"], report["finished_ns"]),
                "copy window differs",
            )
            result["verified_copy_events"].append(deepcopy(event))
            if role in starts and starts[role] != event["start_ns"]:
                complete = False
                result["reasons"].append("kernel_start_identity_conflict")
            starts[role] = event["start_ns"]
            if not _frame(event):
                complete = False
                result["reasons"].append("partial_frame_copy_" + str(index))
                continue
            if endpoint is None:
                complete = False
                continue
            major, minor = _linux_device(endpoint["device"])
            if not (
                event["endpoint_inode"] == endpoint["inode"]
                and event["endpoint_major"] == major
                and event["endpoint_minor"] == minor
                and p["control_endpoint"]["before_sample_ns"]
                <= event["entered_ns"]
                <= event["exited_ns"]
                <= p["control_endpoint"]["after_sample_ns"]
            ):
                complete = False
                result["reasons"].append("copy_endpoint_unverified")
                continue
            payload = bytes.fromhex(event["data_hex"])
            if role == 0:
                if payload == p["request_utf8"].encode():
                    requests.append(event)
                else:
                    complete = False
                    result["reasons"].append("server_request_bytes_differ")
            else:
                try:
                    _response(payload, p)
                    responses.append(event)
                except ERRORS:
                    complete = False
                    result["reasons"].append("client_response_bytes_unverified")
        except ERRORS:
            complete = False
            result["reasons"].append("invalid_copy_event_" + str(index))
    if requests:
        result["server_request_copy_verified"] = True
    if responses:
        result["client_response_copy_verified"] = True
    if len(requests) == len(responses) == 1:
        request, response = requests[0], responses[0]
        if (
            request["receiver_inode"] == response["peer_inode"]
            and request["peer_inode"] == response["receiver_inode"]
            and request["exited_ns"] <= response["entered_ns"]
        ):
            result["reciprocal_pair_verified"] = True
            if lifecycle:
                result["response_disposition"] = _response(
                    bytes.fromhex(response["data_hex"]), p
                )
                if p["case_id"] in REFUSALS:
                    result["validation_error"] = REFUSALS[p["case_id"]]
        else:
            complete = False
            result["reasons"].append("copy_pair_unverified")
    else:
        complete = False
        result["reasons"].append("complete_copy_pair_unavailable")
    if len(result["verified_copy_events"]) != 2:
        complete = False
    try:
        counters = report["counters"]
        safety._fields(counters, COUNTERS)
        for value in counters.values():
            _uint(value)
        _need(
            counters["selected_entries"]
            == counters["pending_inserted"]
            == counters["successful_copies"]
            == counters["emitted"]
            == len(report["events"])
            and all(counters[k] == 0 for k in COUNTERS.split()[4:]),
            "copy counters incomplete",
        )
    except ERRORS:
        complete = False
        result["reasons"].append("copy_counters_unverified")
    try:
        safety._fields(report["link_identities"], "entry exit")
        for name, attach in (("entry", 24), ("exit", 25)):
            link = report["link_identities"][name]
            safety._fields(
                link, "fd type link_id prog_id attach_type target_obj_id target_btf_id"
            )
            for key, value in link.items():
                _uint(value, 2**32 - 1, 0 if key in ("fd", "target_obj_id") else 1)
            _need(
                link["type"] == 2 and link["attach_type"] == attach,
                "copy link type differs",
            )
        entry, exit = (
            report["link_identities"]["entry"],
            report["link_identities"]["exit"],
        )
        _need(
            entry["fd"] != exit["fd"]
            and entry["link_id"] != exit["link_id"]
            and entry["prog_id"] != exit["prog_id"]
            and entry["target_obj_id"] == exit["target_obj_id"]
            and entry["target_btf_id"] == exit["target_btf_id"],
            "copy hook function/identity differs",
        )
    except ERRORS:
        complete = False
        result["reasons"].append("copy_links_unverified")
    partial = report["partial_reasons"]
    if (
        type(partial) is not list
        or len(partial) > len(PARTIAL)
        or any(type(x) is not str or x not in PARTIAL for x in partial)
    ):
        complete = False
        result["reasons"].append("invalid_partial_reasons")
    elif partial:
        complete = False
        result["reasons"].extend(partial)
    if a["exited_ns"] > min(cfg["deadline_ns"], report["finished_ns"]):
        complete = False
    return complete


def verify_postconnect_refusal_observation(
    plan_raw,
    *,
    expected_plan_sha256,
    probe_raw,
    sot_before_raw,
    sot_after_raw,
    audit_before_raw,
    audit_after_raw,
):
    """No acquisition or v1 conversion; retain bounded independent facts first."""
    try:
        p = _plan(plan_raw, expected_plan_sha256)
    except ERRORS as exc:
        raise PostconnectRefusalInputError(str(exc)) from exc
    raws = {
        "before": {"sot": sot_before_raw, "audit": audit_before_raw},
        "after": {"sot": sot_after_raw, "audit": audit_after_raw},
    }
    result = dict(
        schema_version="edge-postconnect-refusal-diagnostic/v1",
        verified_copy_events=[],
        server_request_copy_verified=None,
        client_response_copy_verified=None,
        reciprocal_pair_verified=None,
        response_disposition="unknown",
        validation_error=None,
        object_changes={"sot": None, "audit": None},
        sampled_originals_unchanged=None,
        permitted_hostname_patch_consistent=None,
        coverage_disposition="unknown",
        reasons=[],
        raw_sha256={
            "plan": _sha(plan_raw),
            **{
                name: _sha(value)
                if type(value) is bytes and len(value) <= maximum
                else None
                for name, value, maximum in (
                    ("probe", probe_raw, 65536),
                    ("sot_before", sot_before_raw, MAX_ARTIFACT),
                    ("sot_after", sot_after_raw, MAX_ARTIFACT),
                    ("audit_before", audit_before_raw, MAX_ARTIFACT),
                    ("audit_after", audit_after_raw, MAX_ARTIFACT),
                )
            },
        },
        internal_branch_verified=None,
        authorization_refusal_verified=None,
        qualified_safety_count=None,
        **safety.FLAGS,
    )
    valid = {}
    for phase in ("before", "after"):
        for kind in ("sot", "audit"):
            try:
                valid[phase, kind] = _sample(
                    raws[phase][kind], p["samples"][phase][kind], phase, p
                )
            except ERRORS:
                result["reasons"].append(phase + "_" + kind + "_unverified")
    for kind in ("sot", "audit"):
        if ("before", kind) in valid and ("after", kind) in valid:
            result["object_changes"][kind] = not (
                raws["before"][kind] == raws["after"][kind]
                and safety._same(valid["before", kind], valid["after", kind])
            )
    if any(x is True for x in result["object_changes"].values()):
        result["sampled_originals_unchanged"] = False
    elif all(x is False for x in result["object_changes"].values()):
        result["sampled_originals_unchanged"] = True
    endpoint = None
    try:
        endpoint = _endpoint(p)
    except ERRORS:
        result["reasons"].append("control_endpoint_unverified")
    lifecycle = False
    try:
        _lifecycle(p)
        lifecycle = True
    except ERRORS:
        result["reasons"].append("lifecycle_unverified")
    complete = False
    try:
        complete = _probe(p, probe_raw, result, endpoint, lifecycle)
    except ERRORS:
        result["reasons"].append("copy_probe_unavailable_or_invalid")
    if (
        lifecycle
        and len(valid) == 4
        and result["response_disposition"] == "patch_success_response"
    ):
        try:
            _patch(p, sot_before_raw, sot_after_raw, audit_before_raw, audit_after_raw)
            result["permitted_hostname_patch_consistent"] = True
        except ERRORS:
            result["reasons"].append("hostname_patch_readback_unverified")
    expected = (
        result["permitted_hostname_patch_consistent"] is True
        if p["case_id"] in ("root_patch", "missing_after_sot")
        else result["response_disposition"] == "validation_refusal_response"
        and result["sampled_originals_unchanged"] is True
    )
    if complete and lifecycle and endpoint is not None and len(valid) == 4 and expected:
        result["coverage_disposition"] = "finite_case_consistent"
    return result
