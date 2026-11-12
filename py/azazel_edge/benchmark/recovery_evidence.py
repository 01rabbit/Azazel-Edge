"""Independent sampled observer-object queries; never a cleanup executor.

Linux6.8 ID lookups require SYS_ADMIN, unavailable to the existing sensor.
Permission denial is recorded, not worked around. No privileges are granted here.
"""

import ctypes as C
import errno
import hashlib
import os
import platform
import struct
import sys
import time

from azazel_edge.outcome.input_auth import public_hex, sign, verify_signature
from azazel_edge.outcome.journal import _json
from . import safety_observations as safety
from .safety_collection import _kernel_boot_id
from .protected_ingress import _proc_bytes

DOMAIN = b"azazel-edge:independent-observer-recovery:v1\x00"
COUNTS = {"link": 2, "program": 2, "map": 4}
STATES = {"absent", "present", "identity_reused", "unknown"}


class RecoveryEvidenceError(ValueError):
    """Invalid recovery enrollment or independently pinned evidence."""


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _plan(raw, expected):
    safety._hex(expected)
    safety._need(_digest(raw) == expected, "recovery plan pin differs")
    p = safety._wire(raw, 32768)
    safety._fields(
        p,
        "schema_version contract_sha256 queue_plan_sha256 queue_report_sha256 kernel_boot_id kernel_release observer_public_key not_before_ns deadline_ns resources",
    )
    safety._need(
        p["schema_version"] == "edge-observer-recovery-plan/v1", "recovery plan schema"
    )
    for k in ("contract_sha256", "queue_plan_sha256", "queue_report_sha256"):
        safety._hex(p[k])
    safety._hex(p["observer_public_key"])
    import uuid

    safety._need(
        str(uuid.UUID(p["kernel_boot_id"])) == p["kernel_boot_id"], "recovery boot"
    )
    safety._need(
        type(p["kernel_release"]) is str and 0 < len(p["kernel_release"]) <= 256,
        "recovery kernel",
    )
    safety._int(p["not_before_ns"])
    safety._int(p["deadline_ns"])
    safety._need(
        0 < p["deadline_ns"] - p["not_before_ns"] <= 60_000_000_000,
        "recovery sample window",
    )
    resources = p["resources"]
    safety._need(
        type(resources) is list and len(resources) == 8,
        "eight enrolled resources required",
    )
    seen, counts = set(), dict.fromkeys(COUNTS, 0)
    for r in resources:
        safety._fields(r, "kind id identity_sha256")
        safety._need(type(r["kind"]) is str and r["kind"] in COUNTS, "resource kind")
        safety._int(r["id"], 1, 2**32 - 1)
        safety._hex(r["identity_sha256"])
        key = (r["kind"], r["id"])
        safety._need(key not in seen, "duplicate enrolled resource")
        seen.add(key)
        counts[r["kind"]] += 1
    safety._need(counts == COUNTS, "resource kinds differ")
    return p


def _info(lib, fd, kind):
    # Fixed kernel UAPI prefixes only. No pointers/variable arrays are requested.
    raw = C.create_string_buffer(256)
    length = C.c_uint32(256)
    if lib.bpf_obj_get_info_by_fd(fd, raw, C.byref(length)) != 0:
        raise OSError(C.get_errno(), "independent object metadata unavailable")
    minimum = {"link": 28, "program": 48, "map": 40}[kind]
    safety._need(length.value >= minimum, "object metadata truncated")
    b = raw.raw
    typ, ident = struct.unpack_from("=2I", b)
    result = dict(kind=kind, id=ident, type=typ)
    if kind == "link":
        prog, _, attach, target, btf = struct.unpack_from("=5I", b, 8)
        safety._need(
            typ == 2 and attach in (24, 25) and prog > 0 and btf > 0,
            "not fixed tracing link",
        )
        result.update(
            program_id=prog,
            attach_type=attach,
            target_object_id=target,
            target_btf_id=btf,
        )
    elif kind == "program":
        safety._need(typ == 26, "not fixed tracing program")
        # bpf_prog_info: tag[8] offset8, load_time offset40.
        result.update(
            tag=b[8:16].hex(), load_time_ns=struct.unpack_from("=Q", b, 40)[0]
        )
    else:
        fields = struct.unpack_from("=4I", b, 8)
        safety._need(typ in (1, 2), "not fixed observer map")
        result.update(
            zip(("key_size", "value_size", "max_entries", "map_flags"), fields)
        )
        # map name is a fixed16-byte field at24; include full raw bytes.
        result["name_hex"] = b[24:40].hex()
    safety._need(ident > 0, "missing kernel object ID")
    return result


def _backend():
    lib = C.CDLL("libbpf.so.1", use_errno=True)
    for kind, name in (("link", "link"), ("program", "prog"), ("map", "map")):
        f = getattr(lib, "bpf_" + name + "_get_fd_by_id")
        f.argtypes, f.restype = [C.c_uint32], C.c_int
    lib.bpf_obj_get_info_by_fd.argtypes = [C.c_int, C.c_void_p, C.c_void_p]
    lib.bpf_obj_get_info_by_fd.restype = C.c_int
    return lib


def _lookup(lib, resource):
    """Do exactly one ID query; never keep a link FD through teardown."""
    kind = resource["kind"]
    name = {"link": "link", "program": "prog", "map": "map"}[kind]
    C.set_errno(0)
    fd = getattr(lib, "bpf_" + name + "_get_fd_by_id")(resource["id"])
    if fd < 0:
        error = C.get_errno()
        # Linux6.8 checks query capability before ID absence. EPERM/EACCES,
        # unsupported syscalls and every other failure are NEVER absence.
        return dict(
            state="absent" if error == errno.ENOENT else "unknown",
            identity_sha256=None,
            reason="not_found" if error == errno.ENOENT else "query_denied_or_failed",
        )
    result = dict(state="unknown", identity_sha256=None, reason="metadata_failed")
    try:
        actual = _info(lib, fd, kind)
        digest = _digest(_json(actual))
        same = actual["id"] == resource["id"] and digest == resource["identity_sha256"]
        result = dict(
            state="present" if same else "identity_reused",
            identity_sha256=digest,
            reason="matching_residue" if same else "identity_differs",
        )
    except (ValueError, OSError, TypeError):
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            result = dict(
                state="unknown", identity_sha256=None, reason="query_fd_close_failed"
            )
    return result


def _checker_role():
    """This version never admits a broader role than the existing sensor."""
    safety._need(
        sys.platform == "linux" and sys.byteorder == "little" and os.geteuid() == 0,
        "Linux Root checker required",
    )
    wanted = {"Uid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}
    fields = {}
    for line in _proc_bytes("/proc/self/status", 65536).decode("ascii").splitlines():
        key, sep, value = line.partition(":")
        if sep and key in wanted:
            safety._need(key not in fields, "duplicate checker role field")
            fields[key] = value.strip()
    safety._need(
        set(fields) == wanted
        and fields["Uid"].split() == ["0"] * 4
        and fields["NoNewPrivs"] == "1",
        "checker Root/NNP differs",
    )
    allowed = {0, (1 << 38) | (1 << 39)}
    masks = [int(fields[k], 16) for k in ("CapEff", "CapPrm", "CapBnd")]
    safety._need(
        masks[0] in allowed and len(set(masks)) == 1,
        "checker capability boundary differs",
    )
    safety._need(
        int(fields["CapInh"], 16) == int(fields["CapAmb"], 16) == 0,
        "checker inherited capability",
    )


def capture_recovery_evidence(plan_raw, *, expected_plan_sha256, observer_private_key):
    """Read-only independent checker; unavailable privilege yields signed unknown."""
    try:
        p = _plan(plan_raw, expected_plan_sha256)
        _checker_role()
        safety._need(
            public_hex(observer_private_key) == p["observer_public_key"],
            "recovery signer not enrolled",
        )
        boot, kernel = _kernel_boot_id(), platform.release()
        safety._need(
            boot == p["kernel_boot_id"] and kernel == p["kernel_release"],
            "checker boot/kernel differs",
        )
        started = time.monotonic_ns()
        safety._need(
            p["not_before_ns"] <= started <= p["deadline_ns"],
            "not post-run sample window",
        )
        lib = _backend()
        rows = []
        for resource in p["resources"]:
            begin = time.monotonic_ns()
            outcome = _lookup(lib, resource)
            end = time.monotonic_ns()
            rows.append(
                dict(
                    kind=resource["kind"],
                    id=resource["id"],
                    started_ns=begin,
                    finished_ns=end,
                    **outcome,
                )
            )
        finished = time.monotonic_ns()
        stable = (
            _kernel_boot_id() == boot
            and platform.release() == kernel
            and os.geteuid() == 0
        )
        _checker_role()
        core = dict(
            schema_version="edge-observer-recovery-report/v1",
            plan_sha256=expected_plan_sha256,
            kernel_boot_id=boot,
            kernel_release=kernel,
            observation_layer="observer_object_id_lookup",
            started_ns=started,
            finished_ns=finished,
            context_stable=stable,
            resources=rows,
        )
        return (
            _json(dict(**core, signature=sign(observer_private_key, DOMAIN, core)))
            + b"\n"
        )
    except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
        raise RecoveryEvidenceError(str(exc)) from exc


def unknown_recovery(reason="not_measured"):
    return dict(
        schema_version="edge-observer-recovery-diagnostic/v1",
        status="unknown",
        observer_objects_absent=None,
        matching_residue_count=None,
        resources=[],
        reasons=[reason],
        network_mechanism_restored=None,
        qualified_safety_count=None,
        authority_flags=dict(safety.FLAGS),
        **safety.FLAGS,
    )


def evaluate_recovery_evidence(
    plan_raw, report_raw, *, expected_plan_sha256, expected_report_sha256
):
    """Verify externally retained bytes; no query or cleanup in the evaluator."""
    try:
        p = _plan(plan_raw, expected_plan_sha256)
        if report_raw is None or expected_report_sha256 is None:
            return unknown_recovery()
        safety._hex(expected_report_sha256)
        safety._need(
            _digest(report_raw) == expected_report_sha256, "recovery report pin differs"
        )
        r = safety._wire(report_raw, 32768)
        safety._fields(
            r,
            "schema_version plan_sha256 kernel_boot_id kernel_release observation_layer started_ns finished_ns context_stable resources signature",
        )
        safety._need(
            r["schema_version"] == "edge-observer-recovery-report/v1"
            and r["observation_layer"] == "observer_object_id_lookup",
            "recovery report schema/layer",
        )
        safety._need(
            r["plan_sha256"] == expected_plan_sha256
            and r["kernel_boot_id"] == p["kernel_boot_id"]
            and r["kernel_release"] == p["kernel_release"],
            "recovery report context",
        )
        verify_signature(
            p["observer_public_key"],
            r["signature"],
            DOMAIN,
            {k: v for k, v in r.items() if k != "signature"},
        )
        for k in ("started_ns", "finished_ns"):
            safety._int(r[k])
        safety._need(type(r["context_stable"]) is bool, "context stability type")
        stable = (
            r["context_stable"]
            and p["not_before_ns"]
            <= r["started_ns"]
            <= r["finished_ns"]
            <= p["deadline_ns"]
        )
        safety._need(
            type(r["resources"]) is list and len(r["resources"]) <= 8,
            "resource report bound",
        )
        expected = {(x["kind"], x["id"]): x for x in p["resources"]}
        rows, seen, reasons = [], set(), []
        for item in r["resources"]:
            # Invalid siblings never erase an earlier verified residue.
            try:
                safety._fields(
                    item, "kind id started_ns finished_ns state identity_sha256 reason"
                )
                key = item["kind"], item["id"]
                safety._need(
                    type(item["id"]) is int and key in expected and key not in seen,
                    "wrong/duplicate resource",
                )
                seen.add(key)
                for k in ("started_ns", "finished_ns"):
                    safety._int(item[k])
                safety._need(
                    stable
                    and r["started_ns"]
                    <= item["started_ns"]
                    <= item["finished_ns"]
                    <= r["finished_ns"],
                    "resource sample outside window",
                )
                safety._need(
                    item["state"] in STATES and type(item["reason"]) is str,
                    "resource state",
                )
                state, digest = item["state"], item["identity_sha256"]
                allowed_reasons = {
                    "absent": {"not_found"},
                    "present": {"matching_residue"},
                    "identity_reused": {"identity_differs"},
                    "unknown": {
                        "metadata_failed",
                        "query_denied_or_failed",
                        "query_fd_close_failed",
                    },
                }
                safety._need(
                    item["reason"] in allowed_reasons[state],
                    "resource state/reason contradiction",
                )
                if state in ("present", "identity_reused"):
                    safety._hex(digest)
                    safety._need(
                        (state == "present")
                        == (digest == expected[key]["identity_sha256"]),
                        "residue identity differs",
                    )
                else:
                    safety._need(digest is None, "unexpected resource identity")
                rows.append(dict(item))
            except (ValueError, TypeError, KeyError):
                reasons.append("invalid_resource_sample")
        count = sum(x["state"] == "present" for x in rows)
        complete = stable and not reasons and len(rows) == 8 and len(seen) == 8
        absent = complete and all(x["state"] == "absent" for x in rows)
        out = unknown_recovery("incomplete_or_unavailable")
        out.update(
            status="residue_observed"
            if count
            else "sampled_absence"
            if absent
            else "unknown",
            observer_objects_absent=False if count else True if absent else None,
            matching_residue_count=count if count else 0 if absent else None,
            resources=rows,
            reasons=reasons
            or ([] if absent or count else ["incomplete_or_unavailable"]),
            raw_sha256=dict(plan=expected_plan_sha256, report=expected_report_sha256),
        )
        return out
    except (
        ValueError,
        OSError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise RecoveryEvidenceError(str(exc)) from exc
