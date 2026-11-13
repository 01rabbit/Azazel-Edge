"""Finite recorded control-ingress connections and owned SoT readbacks.

Root pins/identity receipts are external premises, never cryptographic execution,
causation, application refusal or general authority-channel absence evidence.
"""

from copy import deepcopy
import uuid

from azazel_edge.sot import SoTConfig
from azazel_edge.outcome.journal import _ref
from . import safety_observations as safety
from .advisory_exec import _object, _uint, _sha, _need, ERRORS

CASES = frozenset(
    (
        "root_patch",
        "advisory_dac_denied",
        "spoofed_root_dac_denied",
        "unrelated_path",
        "observer_loss",
        "missing_readback",
    )
)
CONFIG = "pidns_device pidns_inode actor_start_ticks started_ns deadline_ns actor_tgid actor_uid user_hz max_events"
EVENT = "at_ns start_ns client_inode peer_inode tgid tid uid peer_major peer_minor netns_inode ret addr_len path reserved"
COUNTERS = "observed emitted overflow identity_failure read_failure"
PARTIAL = frozenset(
    (
        "observer_link_lost",
        "identity_failure",
        "read_failure",
        "overflow",
        "acquisition_error",
        "observer_cleanup_unverified",
    )
)
IDENTITY = "device inode uid gid mode nlink"
MAX_ARTIFACT = 1024 * 1024


class AuthorityIngressInputError(ValueError):
    """Invalid externally pinned global plan, not a missing measurement."""


def _path(value, maximum=107):
    _need(
        type(value) is str
        and value.isascii()
        and 0 < len(value) <= maximum
        and value.startswith("/")
        and "\x00" not in value
        and all(part not in ("", ".", "..") for part in value.split("/")[1:]),
        "physical bounded pathname required",
    )


def _identity(value, sample=False):
    safety._fields(value, IDENTITY + (" size mtime_ns ctime_ns" if sample else ""))
    for key, item in value.items():
        _uint(item, 2**64 - 1, 1 if key in ("device", "inode", "nlink") else 0)
    if sample:
        _need(value["nlink"] == 1, "single link required")


def _worker(value, server=False):
    fields = (
        "pid uid start_ticks code_sha256 started_ns exited_ns returncode forced error"
    )
    if server:
        fields += " handlers_joined_ns"
    else:
        fields += " gid groups pidns_device pidns_inode netns_inode"
    safety._fields(value, fields)
    for key in ("pid", "uid", "start_ticks", "started_ns", "exited_ns"):
        _uint(
            value[key],
            2**32 - 1 if key in ("pid", "uid") else 2**64 - 1,
            1 if key in ("pid", "start_ticks") else 0,
        )
    safety._hex(value["code_sha256"])
    _need(
        type(value["returncode"]) is int
        and -255 <= value["returncode"] <= 255
        and type(value["forced"]) is bool
        and (
            value["error"] is None
            or type(value["error"]) is str
            and len(value["error"]) <= 128
        ),
        "worker facts",
    )
    if server:
        _uint(value["handlers_joined_ns"])
    else:
        for key in ("gid", "pidns_device", "pidns_inode", "netns_inode"):
            _uint(value[key], 2**32 - 1 if key in ("gid", "netns_inode") else 2**64 - 1)
        _need(
            type(value["groups"]) is list and len(value["groups"]) <= 64,
            "group list bound",
        )
        for group in value["groups"]:
            _uint(group, 2**32 - 1)


def _plan(raw, pin):
    safety._hex(pin)
    p = _object(raw, 32768)
    _need(_sha(raw) == pin, "external plan hash differs")
    safety._fields(
        p,
        "schema_version capture_id case_id kernel_boot_id request_utf8 request_sha256 requested_path target_paths control_endpoint actor server go configuration samples probe_sha256 observer_source_sha256 observer_object_sha256",
    )
    _need(
        p["schema_version"] == "edge-authority-ingress-plan/v1"
        and type(p["case_id"]) is str
        and p["case_id"] in CASES,
        "plan version/case",
    )
    _ref(p["capture_id"])
    _need(
        type(p["kernel_boot_id"]) is str
        and str(uuid.UUID(p["kernel_boot_id"])) == p["kernel_boot_id"],
        "boot UUID",
    )
    for field in ("request_sha256", "observer_source_sha256", "observer_object_sha256"):
        safety._hex(p[field])
    if p["probe_sha256"] is not None:
        safety._hex(p["probe_sha256"])
    _need(
        type(p["request_utf8"]) is str and len(p["request_utf8"]) <= 4096,
        "request bound",
    )
    request_raw = p["request_utf8"].encode("utf-8")
    _need(_sha(request_raw) == p["request_sha256"], "request hash differs")
    request = _object(request_raw, 4096)
    expected = {
        "action": "sot_devices_patch",
        "params": {"devices": [{"id": "dev-1", "hostname": "client-1-observed"}]},
    }
    if p["case_id"] == "spoofed_root_dac_denied":
        expected["params"]["requested_by"] = {"actor": "root"}
    _need(safety._same(request, expected), "fixed request differs")
    safety._fields(p["target_paths"], "sot audit")
    for path in p["target_paths"].values():
        _path(path, 256)
    _need(
        p["target_paths"]["sot"] != p["target_paths"]["audit"], "target paths overlap"
    )
    _path(p["requested_path"])
    endpoint = p["control_endpoint"]
    safety._fields(
        endpoint,
        "path parent_before parent_after socket_before socket_after before_sample_ns after_sample_ns control_gid",
    )
    _path(endpoint["path"])
    for key in ("before_sample_ns", "after_sample_ns", "control_gid"):
        _uint(endpoint[key], 2**32 - 1 if key == "control_gid" else 2**64 - 1)
    for key in ("parent_before", "parent_after", "socket_before", "socket_after"):
        if endpoint[key] is not None:
            _identity(endpoint[key])
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
            if key in ("actor_tgid", "actor_uid", "user_hz", "max_events")
            else 2**64 - 1,
        )
    _need(
        cfg["actor_tgid"] > 1
        and cfg["actor_start_ticks"] > 0
        and cfg["pidns_device"] > 0
        and cfg["pidns_inode"] > 0
        and cfg["user_hz"] == 100
        and 1 <= cfg["max_events"] <= 16
        and 0 < cfg["deadline_ns"] - cfg["started_ns"] <= 5_000_000_000,
        "configuration bounds",
    )
    safety._fields(p["samples"], "before after")
    for phase in ("before", "after"):
        safety._fields(p["samples"][phase], "sot audit")
    return p


def _sample(raw, descriptor, phase, p):
    _need(raw is not None and descriptor is not None, "sample unavailable")
    safety._fields(descriptor, "sha256 read_started_ns read_finished_ns identity")
    safety._hex(descriptor["sha256"])
    _need(type(raw) is bytes and len(raw) <= MAX_ARTIFACT, "sample bound")
    identity = descriptor["identity"]
    _identity(identity, True)
    _need(
        identity["uid"] == 0
        and identity["mode"] == 0o644
        and identity["size"] == len(raw)
        and _sha(raw) == descriptor["sha256"],
        "original sample hash/identity differs",
    )
    start, end = descriptor["read_started_ns"], descriptor["read_finished_ns"]
    _uint(start)
    _uint(end)
    _need(start <= end, "sample clock order")
    if phase == "before":
        _need(end <= p["go"]["release_before_ns"], "before read overlaps attempt")
    else:
        _need(
            start
            >= max(
                p["actor"]["exited_ns"],
                p["server"]["handlers_joined_ns"],
                p["server"]["exited_ns"],
            ),
            "after read precedes close",
        )
    return identity


def _endpoint(p):
    e = p["control_endpoint"]
    for kind, mode in (("parent", 0o750), ("socket", 0o660)):
        first, last = e[kind + "_before"], e[kind + "_after"]
        _need(
            first is not None
            and last is not None
            and safety._same(first, last)
            and first["uid"] == 0
            and first["gid"] == e["control_gid"] > 0
            and first["mode"] == mode,
            "endpoint identity/permissions differ",
        )
    _need(
        e["before_sample_ns"] <= p["go"]["release_before_ns"]
        and e["after_sample_ns"] >= p["server"]["exited_ns"],
        "endpoint sample window differs",
    )
    return e["socket_before"]


def _lifecycle(p):
    a, s, g = p["actor"], p["server"], p["go"]
    _need(
        s["uid"] == 0
        and s["pid"] != a["pid"]
        and s["started_ns"] <= g["release_before_ns"]
        and a["started_ns"]
        <= g["release_before_ns"]
        <= g["release_after_ns"]
        <= a["exited_ns"]
        <= s["handlers_joined_ns"]
        <= s["exited_ns"],
        "lifecycle order/roles differ",
    )
    for worker in (a, s):
        _need(
            worker["returncode"] == 0
            and worker["forced"] is False
            and worker["error"] is None,
            "lifecycle unclean",
        )
    if p["case_id"] in ("advisory_dac_denied", "spoofed_root_dac_denied"):
        _need(
            a["uid"] > 0
            and a["gid"] != p["control_endpoint"]["control_gid"]
            and p["control_endpoint"]["control_gid"] not in a["groups"],
            "advisory DAC role differs",
        )
    else:
        _need(a["uid"] == 0, "Root control required")
    expected = p["control_endpoint"]["path"]
    _need(
        (p["requested_path"] != expected) == (p["case_id"] == "unrelated_path"),
        "fixed endpoint selector differs",
    )


def _linux_device(value):
    return ((value >> 8) & 0xFFF) | ((value >> 32) & 0xFFFFF000), (value & 0xFF) | (
        (value >> 12) & 0xFFFFFF00
    )


def _probe(p, raw, result, endpoint):
    _need(
        p["probe_sha256"] is not None
        and type(raw) is bytes
        and len(raw) <= 65536
        and _sha(raw) == p["probe_sha256"],
        "probe unavailable/hash/bounds",
    )
    r = _object(raw, 65536)
    safety._fields(
        r,
        "schema_version architecture started_ns finished_ns configuration events counters partial_reasons link_identity",
    )
    _need(
        r["schema_version"] == "edge-authority-ingress-probe/v1"
        and r["architecture"] == "aarch64"
        and safety._same(r["configuration"], p["configuration"]),
        "probe profile/configuration",
    )
    cfg = p["configuration"]
    actor = p["actor"]
    for key, target in (
        ("actor_tgid", "pid"),
        ("actor_uid", "uid"),
        ("actor_start_ticks", "start_ticks"),
        ("pidns_device", "pidns_device"),
        ("pidns_inode", "pidns_inode"),
    ):
        _need(cfg[key] == actor[target], "probe actor configuration differs")
    _uint(r["started_ns"])
    _uint(r["finished_ns"])
    _need(r["started_ns"] == cfg["started_ns"] <= r["finished_ns"], "probe clock order")
    _need(
        type(r["events"]) is list and len(r["events"]) <= cfg["max_events"],
        "event bounds",
    )
    complete = True
    positive = False
    denied = False
    unrelated = False
    previous = -1
    kernel_start_ns = None
    for index, event in enumerate(r["events"]):
        try:
            safety._fields(event, EVENT)
            for key, value in event.items():
                if key not in ("ret", "addr_len", "path"):
                    _uint(
                        value,
                        2**64 - 1
                        if key in ("at_ns", "start_ns", "client_inode", "peer_inode")
                        else 2**32 - 1,
                    )
            _need(
                type(event["ret"]) is int and -4095 <= event["ret"] <= 0,
                "kernel return type/bound",
            )
            _path(event["path"])
            _need(
                type(event["addr_len"]) is int
                and event["addr_len"] == len(event["path"]) + 3 <= 110,
                "fixed Python address length",
            )
            _need(
                event["tgid"] == actor["pid"]
                and event["tid"] == actor["pid"]
                and event["uid"] == actor["uid"]
                and event["start_ns"] > 0
                and event["start_ns"] // 10_000_000 == actor["start_ticks"]
                and event["netns_inode"] == actor["netns_inode"]
                and event["client_inode"] > 0
                and event["reserved"] == 0
                and max(
                    cfg["started_ns"], actor["started_ns"], p["go"]["release_before_ns"]
                )
                <= event["at_ns"]
                <= min(cfg["deadline_ns"], actor["exited_ns"], r["finished_ns"]),
                "event identity/window differs",
            )
            result["verified_connection_events"].append(deepcopy(event))
            if kernel_start_ns is None:
                kernel_start_ns = event["start_ns"]
            elif kernel_start_ns != event["start_ns"]:
                complete = False
                if "kernel_start_identity_conflict" not in result["reasons"]:
                    result["reasons"].append("kernel_start_identity_conflict")
            if event["at_ns"] < previous:
                complete = False
            previous = event["at_ns"]
            if event["path"] != p["requested_path"]:
                complete = False
            control = (
                event["path"] == p["control_endpoint"]["path"] == p["requested_path"]
            )
            if control and event["ret"] == -13:
                denied = True
            elif event["path"] != p["control_endpoint"]["path"]:
                unrelated = True
            if control and event["ret"] == 0 and endpoint is not None:
                major, minor = _linux_device(endpoint["device"])
                if (
                    event["peer_inode"] == endpoint["inode"]
                    and event["peer_major"] == major
                    and event["peer_minor"] == minor
                    and p["control_endpoint"]["before_sample_ns"]
                    <= event["at_ns"]
                    <= p["control_endpoint"]["after_sample_ns"]
                ):
                    positive = True
                else:
                    complete = False
                    result["reasons"].append("peer_endpoint_mismatch")
        except ERRORS:
            complete = False
            result["reasons"].append("invalid_connection_event_" + str(index))
    if positive:
        result["connection_disposition"] = "control_connected"
    elif denied:
        result["connection_disposition"] = "control_eacces"
    elif unrelated:
        result["connection_disposition"] = "unrelated_path_observed"
    if len(result["verified_connection_events"]) != 1:
        complete = False
    try:
        safety._fields(r["counters"], COUNTERS)
        for value in r["counters"].values():
            _uint(value)
        _need(
            r["counters"]["observed"] == r["counters"]["emitted"] == len(r["events"])
            and all(
                r["counters"][key] == 0
                for key in ("overflow", "identity_failure", "read_failure")
            ),
            "counter uncertainty",
        )
    except ERRORS:
        complete = False
        result["reasons"].append("probe_counters_unverified")
    try:
        link = r["link_identity"]
        safety._fields(
            link, "fd type link_id prog_id attach_type target_obj_id target_btf_id"
        )
        for key, value in link.items():
            _uint(value, 2**32 - 1, 0 if key in ("fd", "target_obj_id") else 1)
        _need(
            link["type"] == 2 and link["attach_type"] == 25,
            "tracing link identity differs",
        )
    except ERRORS:
        complete = False
        result["reasons"].append("probe_link_unverified")
    partial = r["partial_reasons"]
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
    if not (p["actor"]["exited_ns"] <= min(cfg["deadline_ns"], r["finished_ns"])):
        complete = False
    return complete


def _patch(p, sot_before, sot_after, audit_before, audit_after):
    _need(p["actor"]["uid"] == 0, "Root patch role required")
    before = _object(sot_before, MAX_ARTIFACT, canonical=False)
    after = _object(sot_after, MAX_ARTIFACT, canonical=False)
    candidate = deepcopy(before)
    devices = candidate.get("devices")
    _need(
        type(devices) is list
        and len([x for x in devices if type(x) is dict and x.get("id") == "dev-1"])
        == 1,
        "fixed unique device required",
    )
    device = next(x for x in devices if type(x) is dict and x.get("id") == "dev-1")
    _need(device.get("hostname") == "client-1", "fixed baseline hostname differs")
    device["hostname"] = "client-1-observed"
    expected = SoTConfig.from_dict(candidate).to_dict()
    _need(safety._same(expected, after), "normalized hostname patch differs")
    _need(
        audit_before == b""
        and type(audit_after) is bytes
        and 0 < len(audit_after) <= MAX_ARTIFACT
        and audit_after.endswith(b"\n")
        and audit_after.count(b"\n") == 1
        and b"\r" not in audit_after,
        "actual empty baseline and single audit append required",
    )
    audit = _object(audit_after, MAX_ARTIFACT, canonical=False)
    safety._fields(
        audit, "kind ts source peer_uid path device_count diff patched_count"
    )
    _need(
        audit["kind"] == "sot_devices_patched"
        and audit["source"] == "control_daemon"
        and type(audit["peer_uid"]) is int
        and audit["peer_uid"] == 0
        and type(audit["device_count"]) is int
        and audit["device_count"] == len(expected["devices"])
        and type(audit["patched_count"]) is int
        and audit["patched_count"] == 1
        and safety._same(audit["diff"], {"added": 0, "removed": 0, "updated": 1})
        and type(audit["ts"]) in (int, float),
        "audit append context differs",
    )
    _path(audit["path"], 256)
    _need(audit["path"] == p["target_paths"]["sot"], "audit target path differs")


def verify_authority_ingress_observation(
    plan_raw,
    *,
    expected_plan_sha256,
    probe_raw,
    sot_before_raw,
    sot_after_raw,
    audit_before_raw,
    audit_after_raw,
):
    """Original samples and valid connection rows survive later independent failures."""
    try:
        p = _plan(plan_raw, expected_plan_sha256)
    except ERRORS as exc:
        raise AuthorityIngressInputError(str(exc)) from exc
    raw_by_phase = {
        "before": {"sot": sot_before_raw, "audit": audit_before_raw},
        "after": {"sot": sot_after_raw, "audit": audit_after_raw},
    }
    result = dict(
        schema_version="edge-authority-ingress-diagnostic/v1",
        object_changes={"sot": None, "audit": None},
        sampled_originals_unchanged=None,
        connection_disposition="unknown",
        verified_connection_events=[],
        permitted_hostname_patch_consistent=None,
        coverage_disposition="unknown",
        reasons=[],
        raw_sha256={
            "plan": _sha(plan_raw),
            **{
                key: _sha(value)
                if type(value) is bytes and len(value) <= maximum
                else None
                for key, value, maximum in (
                    ("probe", probe_raw, 65536),
                    ("sot_before", sot_before_raw, MAX_ARTIFACT),
                    ("sot_after", sot_after_raw, MAX_ARTIFACT),
                    ("audit_before", audit_before_raw, MAX_ARTIFACT),
                    ("audit_after", audit_after_raw, MAX_ARTIFACT),
                )
            },
        },
        application_peer_refusal_verified=False,
        qualified_safety_count=None,
        **safety.FLAGS,
    )
    valid = {}
    for phase in ("before", "after"):
        for kind in ("sot", "audit"):
            try:
                valid[phase, kind] = _sample(
                    raw_by_phase[phase][kind], p["samples"][phase][kind], phase, p
                )
            except ERRORS:
                result["reasons"].append(phase + "_" + kind + "_unverified")
    for kind in ("sot", "audit"):
        if ("before", kind) in valid and ("after", kind) in valid:
            result["object_changes"][kind] = not (
                raw_by_phase["before"][kind] == raw_by_phase["after"][kind]
                and safety._same(valid["before", kind], valid["after", kind])
            )
    values = result["object_changes"].values()
    if any(value is True for value in values):
        result["sampled_originals_unchanged"] = False
    elif all(value is False for value in values):
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
        result["reasons"].append("lifecycle_or_role_unverified")
    probe_complete = False
    try:
        probe_complete = _probe(p, probe_raw, result, endpoint)
    except ERRORS:
        result["reasons"].append("probe_unavailable_or_invalid")
    if (
        lifecycle
        and len(valid) == 4
        and result["connection_disposition"] == "control_connected"
    ):
        try:
            _patch(p, sot_before_raw, sot_after_raw, audit_before_raw, audit_after_raw)
            result["permitted_hostname_patch_consistent"] = True
        except ERRORS:
            result["reasons"].append("hostname_patch_readback_unverified")
    case_good = (
        result["permitted_hostname_patch_consistent"] is True
        if p["case_id"] in ("root_patch", "observer_loss", "missing_readback")
        else result["sampled_originals_unchanged"] is True
        and result["connection_disposition"]
        == (
            "unrelated_path_observed"
            if p["case_id"] == "unrelated_path"
            else "control_eacces"
        )
    )
    if (
        lifecycle
        and endpoint is not None
        and len(valid) == 4
        and probe_complete
        and case_good
    ):
        result["coverage_disposition"] = "finite_case_consistent"
    return result
