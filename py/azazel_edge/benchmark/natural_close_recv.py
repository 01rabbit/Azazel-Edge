"""Bounded recorded natural-close protocol copies and individual recv returns.

No cached peer identity, byte reconstruction, internal branch or safety claim.
"""

from copy import deepcopy
import uuid
from azazel_edge.outcome.journal import _ref
from . import safety_observations as safety
from .advisory_exec import _object, _uint, _sha, _need, ERRORS
from .authority_ingress import _path, _identity, _worker, MAX_ARTIFACT
from .postconnect_authorization import (
    _identity_profile,
    _sample,
    _endpoint,
    _patch,
    _frame,
    CONFIG,
    ROLE_UID,
)

CASES = frozenset(
    (
        "own_uid_patch",
        "root_only_refused",
        "spoofed_root_refused",
        "partial_read_close",
        "actor_death",
        "observer_stop_after_copy",
        "missing_after_sot",
    )
)
POSITIVES = frozenset(("own_uid_patch", "missing_after_sot"))
NORMAL = frozenset(("own_uid_patch", "root_only_refused", "spoofed_root_refused"))
EVENT = "token entered_ns exited_ns start_ns receiver_inode peer_inode endpoint_inode requested_len ret kind role tgid tid uid euid netns_inode fd flags iter_type data_source skip chunk consumed skb_len data_len endpoint_major endpoint_minor peer_status endpoint_status reserved reserved2 data_hex"
COUNTERS = "selected_entries pending_inserted successful_copies emitted copy_failure unsupported read_failure identity_failure correlation_loss overflow inflight unmatched_exit recv_selected recv_completed recv_inflight unmatched_recv_exit"
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
        "unmatched_recv_exit",
    )
)
LINKS = (("recv_entry", 24), ("recv_exit", 25), ("copy_entry", 24), ("copy_exit", 25))


class NaturalCloseRecvInputError(ValueError):
    """Malformed externally pinned global plan; not a measured target failure."""


def _request(case):
    if case in POSITIVES:
        return {
            "action": "sot_devices_patch",
            "params": {"devices": [{"id": "dev-1", "hostname": "client-1-observed"}]},
        }
    result = {
        "action": "migrate_path_schema",
        "params": {"dry_run": True, "target_schema": "v2"},
    }
    if case == "spoofed_root_refused":
        result["peer_uid"] = 0
    return result


def _plan(raw, pin):
    safety._hex(pin)
    p = _object(raw, 32768)
    _need(_sha(raw) == pin, "external plan hash differs")
    safety._fields(
        p,
        "schema_version capture_id case_id kernel_boot_id request_utf8 request_sha256 requested_path target_paths control_endpoint actor server go configuration samples probe_sha256 observer_source_sha256 observer_object_sha256 identity_profile",
    )
    _need(
        p["schema_version"] == "edge-natural-close-plan/v1"
        and type(p["case_id"]) is str
        and p["case_id"] in CASES,
        "plan schema/case",
    )
    _identity_profile(p["identity_profile"])
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
            if key
            in (
                "server_tgid",
                "actor_tgid",
                "user_hz",
                "max_events",
                "server_uid",
                "actor_uid",
            )
            else 2**64 - 1,
        )
    _need(
        cfg["server_uid"] == cfg["actor_uid"] == ROLE_UID
        and cfg["server_tgid"] > 1
        and cfg["actor_tgid"] > 1
        and cfg["server_tgid"] != cfg["actor_tgid"]
        and cfg["server_start_ticks"] > 0
        and cfg["actor_start_ticks"] > 0
        and cfg["pidns_device"] > 0
        and cfg["pidns_inode"] > 0
        and cfg["user_hz"] == 100
        and 1 <= cfg["max_events"] <= 32
        and 0 < cfg["deadline_ns"] - cfg["started_ns"] <= 5_000_000_000,
        "two-role configuration bounds",
    )
    safety._fields(p["samples"], "before after")
    for phase in ("before", "after"):
        safety._fields(p["samples"][phase], "sot audit")
    return p


def _clean_lifecycle(p):
    a, s, g = p["actor"], p["server"], p["go"]
    _need(
        a["uid"] == s["uid"] == a["gid"] == ROLE_UID and a["groups"] == [],
        "development roles differ",
    )
    _need(
        s["started_ns"] <= g["release_before_ns"]
        and a["started_ns"]
        <= g["release_before_ns"]
        <= g["release_after_ns"]
        <= a["exited_ns"]
        <= s["handlers_joined_ns"]
        <= s["exited_ns"],
        "lifecycle order differs",
    )
    _need(
        p["requested_path"] == p["control_endpoint"]["path"],
        "requested endpoint differs",
    )
    for w in (a, s):
        _need(
            w["returncode"] == 0 and w["forced"] is False and w["error"] is None,
            "unclean lifecycle",
        )


def _response(raw, p):
    body = _object(raw, 256, canonical=False)
    if p["case_id"] in POSITIVES:
        safety._fields(body, "ok path diff audit_logged ts")
        _need(
            body["ok"] is True
            and body["path"] == p["target_paths"]["sot"]
            and body["audit_logged"] is True
            and safety._same(body["diff"], {"added": 0, "removed": 0, "updated": 1}),
            "different patch response",
        )
        kind = "patch_success_response"
    else:
        safety._fields(body, "ok error reason action ts")
        _need(
            body["ok"] is False
            and body["error"] == "forbidden"
            and body["reason"] == "root_only"
            and body["action"] == "migrate_path_schema",
            "different root-only refusal response",
        )
        kind = "root_only_refusal_response"
    _need(type(body["ts"]) in (int, float), "finite actual timestamp required")
    return kind


def _event(row, p, finished):
    safety._fields(row, EVENT)
    optional = {"peer_inode", "endpoint_inode", "endpoint_major", "endpoint_minor"}
    wide = {
        "token",
        "entered_ns",
        "exited_ns",
        "start_ns",
        "receiver_inode",
        "peer_inode",
        "endpoint_inode",
        "requested_len",
    }
    for key, value in row.items():
        if key in ("ret", "data_hex") or key in optional:
            continue
        _uint(value, 2**64 - 1 if key in wide else 2**32 - 1)
    _need(
        type(row["ret"]) is int and -4095 <= row["ret"] <= 65536,
        "signed syscall/copy return differs",
    )
    _need(row["kind"] in (0, 1, 2) and row["role"] in (0, 1), "event kind/role")
    worker = p["server"] if row["role"] == 0 else p["actor"]
    cfg = p["configuration"]
    _need(
        row["tgid"] == row["tid"] == worker["pid"]
        and row["uid"] == row["euid"] == worker["uid"] == ROLE_UID
        and row["start_ns"] > 0
        and row["start_ns"] // 10_000_000 == worker["start_ticks"]
        and row["netns_inode"] == p["actor"]["netns_inode"]
        and row["receiver_inode"] > 0
        and row["reserved"] == row["reserved2"] == 0
        and row["fd"] <= 4095
        and 1 <= row["requested_len"] <= 65536,
        "own invocation identity differs",
    )
    _need(
        max(cfg["started_ns"], worker["started_ns"], p["go"]["release_before_ns"])
        <= row["token"]
        <= row["entered_ns"]
        <= min(cfg["deadline_ns"], worker["exited_ns"], finished),
        "event window differs",
    )
    for status, fields in (
        ("peer_status", ("peer_inode",)),
        ("endpoint_status", ("endpoint_inode", "endpoint_major", "endpoint_minor")),
    ):
        _need(
            row[status] in ((0,) if row["kind"] == 2 else (1, 2, 3)),
            "unknown optional availability",
        )
        for field in fields:
            if row[status] == 1:
                _uint(
                    row[field],
                    2**64 - 1 if field.endswith("inode") else 2**32 - 1,
                    1 if field.endswith("inode") else 0,
                )
            else:
                _need(row[field] is None, "unavailable identity must remain null")
    if row["kind"] == 1:
        _need(
            row["entered_ns"]
            <= row["exited_ns"]
            <= min(cfg["deadline_ns"], worker["exited_ns"], finished),
            "copy exit window",
        )
        _need(
            1 <= row["chunk"] == row["ret"] <= 256
            and row["flags"] in (0, 64)
            and row["iter_type"] in (0, 1)
            and row["data_source"] == row["data_len"] == 0
            and row["consumed"] + row["skip"] + row["chunk"] <= row["skb_len"],
            "bounded completed copy required",
        )
        _need(
            type(row["data_hex"]) is str
            and len(row["data_hex"]) == 2 * row["chunk"]
            and all(c in "0123456789abcdef" for c in row["data_hex"]),
            "exact original bytes required",
        )
    else:
        _need(
            row["entered_ns"] == row["token"]
            and row["flags"] == 0
            and row["data_hex"] == ""
            and all(
                row[k] == 0
                for k in (
                    "iter_type",
                    "data_source",
                    "skip",
                    "chunk",
                    "consumed",
                    "skb_len",
                    "data_len",
                )
            ),
            "syscall metadata differs",
        )
        if row["kind"] == 0:
            _need(row["exited_ns"] == row["ret"] == 0, "entry is not a return")
        else:
            _need(
                row["token"]
                <= row["exited_ns"]
                <= min(cfg["deadline_ns"], worker["exited_ns"], finished)
                and row["ret"] <= row["requested_len"],
                "return window/size differs",
            )
    return row


def _probe(p, raw, result):
    _need(
        p["probe_sha256"] is not None
        and type(raw) is bytes
        and len(raw) <= 65536
        and _sha(raw) == p["probe_sha256"],
        "probe unavailable/hash/bound",
    )
    report = _object(raw, 65536)
    safety._fields(
        report,
        "schema_version architecture started_ns finished_ns configuration events counters partial_reasons link_identities",
    )
    _need(
        report["schema_version"] == "edge-natural-close-probe/v1"
        and report["architecture"] == "aarch64"
        and safety._same(report["configuration"], p["configuration"]),
        "probe schema/configuration differs",
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
        "configured identities differ",
    )
    _uint(report["started_ns"])
    _uint(report["finished_ns"])
    _need(
        report["started_ns"] == cfg["started_ns"] <= report["finished_ns"],
        "probe clock order",
    )
    _need(
        type(report["events"]) is list and len(report["events"]) <= cfg["max_events"],
        "event bound",
    )
    complete = True
    groups = {}
    births = {}
    tainted_invocations = set()
    tainted_roles = set()
    unscopable_invalid = False
    classified = {0: [], 1: []}
    for index, row in enumerate(report["events"]):
        try:
            _event(row, p, report["finished_ns"])
            result["verified_events"].append(deepcopy(row))
            if row["kind"] == 1:
                result["raw_protocol_copy_events"].append(deepcopy(row))
            if row["role"] in births and births[row["role"]] != row["start_ns"]:
                complete = False
                result["reasons"].append("kernel_start_identity_conflict")
                tainted_roles.add(row["role"])
            births[row["role"]] = row["start_ns"]
            groups.setdefault((row["role"], row["token"]), []).append(row)
            if row["peer_status"] == 3 or row["endpoint_status"] == 3:
                complete = False
                result["reasons"].append("optional_identity_read_failure_" + str(index))
        except ERRORS:
            complete = False
            result["reasons"].append("invalid_event_" + str(index))
            if (
                type(row) is dict
                and type(row.get("role")) is int
                and row["role"] in (0, 1)
                and type(row.get("token")) is int
                and 0 < row["token"] <= 2**64 - 1
            ):
                tainted_invocations.add((row["role"], row["token"]))
            else:
                unscopable_invalid = True
    matching = (
        "role",
        "token",
        "start_ns",
        "receiver_inode",
        "requested_len",
        "tgid",
        "tid",
        "uid",
        "euid",
        "netns_inode",
        "fd",
    )
    for (role, token), rows in groups.items():
        if (
            unscopable_invalid
            or role in tainted_roles
            or (role, token) in tainted_invocations
        ):
            complete = False
            result["reasons"].append("recv_invocation_tainted")
            continue
        entry = [r for r in rows if r["kind"] == 0]
        copies = [r for r in rows if r["kind"] == 1]
        exit = [r for r in rows if r["kind"] == 2]
        if len(entry) != 1 or len(exit) != 1:
            complete = False
            result["reasons"].append("incomplete_recv_invocation")
            continue
        en, ex = entry[0], exit[0]
        if not all(safety._same(en[k], ex[k]) for k in matching):
            complete = False
            result["reasons"].append("recv_entry_exit_identity_differs")
            continue
        if not copies and ex["ret"] <= 0:
            continue  # A measured EOF/error return is no byte-delivery assertion.
        if len(copies) != 1:
            complete = False
            result["reasons"].append("single_copy_unavailable")
            continue
        copy = copies[0]
        if not (
            all(safety._same(en[k], copy[k]) for k in matching)
            and en["entered_ns"]
            <= copy["entered_ns"]
            <= copy["exited_ns"]
            <= ex["exited_ns"]
            and ex["ret"] == copy["ret"] == copy["chunk"] > 0
        ):
            complete = False
            result["reasons"].append("recv_copy_completion_unverified")
            continue
        full = _frame(copy)
        kind = "unknown"
        if full:
            payload = bytes.fromhex(copy["data_hex"])
            try:
                if role == 0:
                    _need(payload == p["request_utf8"].encode(), "request differs")
                    kind = "request_frame"
                else:
                    kind = _response(payload, p)
                classified[role].append(copy)
            except ERRORS:
                complete = False
                result["reasons"].append("full_frame_content_unverified")
        else:
            complete = False
            result["reasons"].append("partial_frame")
        result["receiver_completions"].append(
            dict(
                role=role,
                token=token,
                bytes=ex["ret"],
                full_frame=True if full else None,
                classification=kind,
            )
        )
        result[
            "server_request_completion_verified"
            if role == 0
            else "client_response_completion_verified"
        ] = True
    if len(classified[0]) == 1:
        result["server_request_frame_verified"] = True
    if len(classified[1]) == 1:
        result["client_response_frame_verified"] = True
        result["response_disposition"] = _response(
            bytes.fromhex(classified[1][0]["data_hex"]), p
        )
    # Optional peer/file traversal is a lockless best-effort snapshot. Even
    # readable reciprocal numbers cannot prove a coherent peer incarnation
    # through natural close; preserve the raw metadata, never qualify a pair.
    result["reasons"].append("peer_pairing_unqualified_lockless_optional_metadata")

    try:
        counters = report["counters"]
        safety._fields(counters, COUNTERS)
        for value in counters.values():
            _uint(value)
        _need(
            counters["recv_selected"]
            == len([r for r in report["events"] if r["kind"] == 0])
            and counters["recv_completed"]
            == len([r for r in report["events"] if r["kind"] == 2])
            and counters["successful_copies"]
            == len([r for r in report["events"] if r["kind"] == 1])
            and counters["emitted"] == len(report["events"])
            and counters["selected_entries"]
            == counters["pending_inserted"]
            == counters["successful_copies"]
            and all(
                counters[k] == 0
                for k in COUNTERS.split()
                if k
                not in (
                    "recv_selected",
                    "recv_completed",
                    "successful_copies",
                    "emitted",
                    "selected_entries",
                    "pending_inserted",
                )
            ),
            "incomplete counters",
        )
    except ERRORS:
        complete = False
        result["reasons"].append("counters_unverified")
    try:
        links = report["link_identities"]
        safety._fields(links, " ".join(k for k, _ in LINKS))
        fds = []
        ids = []
        programs = []
        for name, attach in LINKS:
            link = links[name]
            safety._fields(
                link, "fd type link_id prog_id attach_type target_obj_id target_btf_id"
            )
            for key, value in link.items():
                _uint(value, 2**32 - 1, 0 if key in ("fd", "target_obj_id") else 1)
            _need(
                link["type"] == 2 and link["attach_type"] == attach, "hook type differs"
            )
            fds.append(link["fd"])
            ids.append(link["link_id"])
            programs.append(link["prog_id"])
        _need(
            len(set(fds)) == len(set(ids)) == len(set(programs)) == 4,
            "hook identities reused",
        )
        for prefix in ("recv", "copy"):
            first, last = links[prefix + "_entry"], links[prefix + "_exit"]
            _need(
                first["target_obj_id"] == last["target_obj_id"]
                and first["target_btf_id"] == last["target_btf_id"],
                "hook target mismatch",
            )
        _need(
            links["recv_entry"]["target_btf_id"]
            != links["copy_entry"]["target_btf_id"],
            "distinct hook functions required",
        )
    except ERRORS:
        complete = False
        result["reasons"].append("links_unverified")
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


def verify_natural_close_recv_observation(
    plan_raw,
    *,
    expected_plan_sha256,
    probe_raw,
    sot_before_raw,
    sot_after_raw,
    audit_before_raw,
    audit_after_raw,
):
    """Evaluate only pinned originals; no I/O, acquisition, conversion or backfill."""
    try:
        p = _plan(plan_raw, expected_plan_sha256)
    except ERRORS as exc:
        raise NaturalCloseRecvInputError(str(exc)) from exc
    result = dict(
        schema_version="edge-natural-close-diagnostic/v1",
        verified_events=[],
        raw_protocol_copy_events=[],
        receiver_completions=[],
        server_request_completion_verified=None,
        client_response_completion_verified=None,
        server_request_frame_verified=None,
        client_response_frame_verified=None,
        reciprocal_pair_verified=None,
        root_only_refusal_response_consistent=None,
        response_disposition="unknown",
        clean_lifecycle_verified=None,
        object_changes={"sot": None, "audit": None},
        sampled_originals_unchanged=None,
        permitted_hostname_patch_consistent=None,
        coverage_disposition="unknown",
        reasons=[],
        internal_branch_verified=None,
        authorization_refusal_verified=None,
        qualified_safety_count=None,
        **safety.FLAGS,
    )
    raws = {
        "before": {"sot": sot_before_raw, "audit": audit_before_raw},
        "after": {"sot": sot_after_raw, "audit": audit_after_raw},
    }
    result["raw_sha256"] = {
        "plan": _sha(plan_raw),
        **{
            name: _sha(raw) if type(raw) is bytes and len(raw) <= limit else None
            for name, raw, limit in (
                ("probe", probe_raw, 65536),
                ("sot_before", sot_before_raw, MAX_ARTIFACT),
                ("sot_after", sot_after_raw, MAX_ARTIFACT),
                ("audit_before", audit_before_raw, MAX_ARTIFACT),
                ("audit_after", audit_after_raw, MAX_ARTIFACT),
            )
        },
    }
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
    if any(v is True for v in result["object_changes"].values()):
        result["sampled_originals_unchanged"] = False
    elif all(v is False for v in result["object_changes"].values()):
        result["sampled_originals_unchanged"] = True
    try:
        _clean_lifecycle(p)
        result["clean_lifecycle_verified"] = True
    except ERRORS:
        result["reasons"].append("lifecycle_unclean_or_unverified")
    endpoint = None
    try:
        endpoint = _endpoint(p)
    except ERRORS:
        result["reasons"].append("endpoint_unverified")
    complete = False
    try:
        complete = _probe(p, probe_raw, result)
    except ERRORS:
        result["reasons"].append("probe_unavailable_or_invalid")
    if (
        result["clean_lifecycle_verified"] is True
        and len(valid) == 4
        and result["response_disposition"] == "patch_success_response"
    ):
        try:
            _patch(p, sot_before_raw, sot_after_raw, audit_before_raw, audit_after_raw)
            result["permitted_hostname_patch_consistent"] = True
        except ERRORS:
            result["reasons"].append("patch_readback_unverified")
    expected = (
        result["permitted_hostname_patch_consistent"] is True
        if p["case_id"] in POSITIVES
        else result["sampled_originals_unchanged"] is True
        and result["response_disposition"] == "root_only_refusal_response"
    )
    if (
        p["case_id"] in NORMAL
        and complete
        and result["clean_lifecycle_verified"] is True
        and endpoint is not None
        and len(valid) == 4
        and result["server_request_frame_verified"] is True
        and result["client_response_frame_verified"] is True
        and expected
    ):
        result["coverage_disposition"] = "bounded_individual_observation"
    return result
