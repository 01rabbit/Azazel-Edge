"""Pure validation of retained fixed-worker frames, never transport authentication.

Later Root code must bind original pipe/source/unit/kernel/mount/liveness evidence.
No caller-authored JSON or this structural validator creates isolation authority.
"""

import ctypes
from datetime import datetime, timezone
import errno
import json
import math
import re
import uuid

from azazel_edge.outcome.journal import _parse
import telemetry_isolation_contract as c
from telemetry_isolation_preflight import canary_spec

SOURCE = "/opt/edge400-src/tests/real_systemd/telemetry_isolation_worker.py"
CONTEXT = {"identity", "kernel_boot_id", "source_sha256", "source"}
COVERAGE = {"proc_net_dev", "proc_loadavg", "proc_meminfo", "proc_uptime"}


def _need(value, reason):
    if not value:
        raise ValueError(reason)


def _frame(raw):
    _need(
        type(raw) is bytes
        and 0 < len(raw) <= 65536
        and raw.endswith(b"\n")
        and raw.count(b"\n") == 1,
        "one bounded original worker frame required",
    )
    value = _parse(raw)
    _need(type(value) is dict, "worker object required")
    return value


def parse_ready(raw, mode, *, boot, worker_sha256):
    c.role_spec(mode)
    value = _frame(raw)
    _need(
        set(value) == CONTEXT | {"kind", "mode", "public_address", "public_size"}
        and value["kind"] == "ready"
        and value["mode"] == mode
        and value["source"] == SOURCE
        and type(boot) is str
        and str(uuid.UUID(boot)) == boot
        and value["kernel_boot_id"] == boot
        and type(worker_sha256) is str
        and re.fullmatch("[0-9a-f]{64}", worker_sha256)
        and value["source_sha256"] == worker_sha256,
        "actual source/role/boot marker differs",
    )
    c.validate_role_identity(value["identity"])
    if mode == "peer":
        _need(
            type(value["public_address"]) is int
            and 0 < value["public_address"] < 2 ** (ctypes.sizeof(ctypes.c_void_p) * 8)
            and type(value["public_size"]) is int
            and value["public_size"] == 1,
            "valid public peer byte required",
        )
    else:
        _need(
            value["public_address"] is value["public_size"] is None,
            "probe cannot supply peer data",
        )
    return value


def _sample(sample):
    _need(
        type(sample) is dict
        and set(sample)
        == {
            "epoch",
            "observed_at",
            "interface",
            "network",
            "system",
            "coverage",
            "evidence_ref",
        }
        and type(sample["epoch"]) in (int, float)
        and math.isfinite(sample["epoch"])
        and sample["epoch"] >= 0
        and sample["observed_at"]
        == datetime.fromtimestamp(sample["epoch"], timezone.utc).isoformat()
        and sample["interface"] == "es"
        and type(sample["coverage"]) is dict
        and set(sample["coverage"]) == COVERAGE
        and all(v is True for v in sample["coverage"].values()),
        "complete actual self sample required",
    )
    keys = {
        "rx_bytes",
        "rx_packets",
        "rx_errors",
        "rx_dropped",
        "tx_bytes",
        "tx_packets",
        "tx_errors",
        "tx_dropped",
    }
    _need(
        type(sample["network"]) is dict
        and set(sample["network"]) == keys
        and all(type(v) is int and v >= 0 for v in sample["network"].values()),
        "actual complete interface counters required",
    )
    integers = {
        "memory_total_kib",
        "memory_available_kib",
        "swap_total_kib",
        "swap_free_kib",
    }
    floats = {"load1", "load5", "load15", "uptime_seconds"}
    _need(
        type(sample["system"]) is dict
        and set(sample["system"]) == integers | floats
        and all(
            type(sample["system"][key]) is int and sample["system"][key] >= 0
            for key in integers
        )
        and all(
            type(sample["system"][key]) is float
            and math.isfinite(sample["system"][key])
            and sample["system"][key] >= 0
            for key in floats
        )
        and type(sample["evidence_ref"]) is str
        and re.fullmatch("procfs-sample:[0-9a-f]{24}", sample["evidence_ref"]),
        "actual global sample metrics/ref required",
    )


def expected_operations(peer_pid):
    _need(type(peer_pid) is int and 1 < peer_pid < 2**31, "actual peer PID required")
    denied = (errno.EACCES, errno.EPERM)
    expected = {
        name: None
        for name in (
            "self_process_vm_readv_sanity",
            "actual_self_sample",
            "proc_enumeration",
        )
    }
    for name in ("status", "register"):
        expected["binfmt_denied_open:" + c.BINFMT + "/" + name] = denied
    for pid in (peer_pid, 1):
        for suffix in (
            "net/dev",
            f"task/{pid}/net/dev",
            "root/proc/net/dev",
            "root/proc/self/net/dev",
            f"root/proc/{pid}/net/dev",
        ):
            expected[f"foreign_read_open:/proc/{pid}/" + suffix] = (
                *denied,
                errno.ENOENT,
            )
    expected["peer_process_vm_readv_valid_public_byte"] = (errno.EPERM,)
    for pid in (peer_pid, 1):
        expected[f"ptrace_seize:{pid}"] = (errno.EPERM,)
    for row in canary_spec()[:-1]:
        expected["public_nonkey_read_open:" + row["path"]] = denied
    for path in (
        canary_spec()[-1]["path"],
        "/proc/net/dev",
        "/proc/loadavg",
        "/proc/uptime",
    ):
        expected["nontruncating_write_open:" + path] = denied
    for path in (
        "/usr/bin/true",
        "/usr/sbin/nft",
        "/opt/edge400-runtime/bin/edge-capture",
    ):
        expected["unintended_exec:" + path] = denied
    for name in ("setuid_zero", "capset_raise_sysadmin"):
        expected[name] = (errno.EPERM,)
    expected["aa_change_profile_unconfined"] = denied
    expected["unshare_newuser"] = denied
    expected["unshare_newnet"] = (errno.EPERM,)
    expected["namespace_fd_open"] = denied
    expected["setns"] = None
    for family in (2, 10):
        expected[f"network_family:{family}"] = (*denied, errno.EAFNOSUPPORT)
    for pid in (peer_pid, 1):
        expected[f"signal_zero:{pid}"] = denied
    return expected


def validate_result(raw, ready, *, peer_pid=None):
    """Return the unchanged decoded observation only after ALL fixed rows match."""
    value = _frame(raw)
    c.validate_role_identity(value.get("identity"))
    _need(
        set(value) == CONTEXT | {"mode", "kind", "scope", "operations"}
        and value["mode"] == ready["mode"]
        and value["scope"] == "self_process_threadgroup_observations_not_qualification"
        and json.dumps({k: value[k] for k in CONTEXT}, sort_keys=True, allow_nan=False)
        == json.dumps({k: ready[k] for k in CONTEXT}, sort_keys=True, allow_nan=False),
        "final source/identity marker differs",
    )
    if ready["mode"] == "peer":
        _need(
            value["kind"] == "peer_wait_finished" and value["operations"] == [],
            "peer cannot report probe facts",
        )
        return value
    _need(
        value["kind"] == "probe_observations_complete"
        and type(value["operations"]) is list
        and all(type(row) is dict for row in value["operations"])
        and peer_pid != ready["identity"]["tgid"],
        "incomplete probe cannot qualify structurally",
    )
    expected = expected_operations(peer_pid)
    _need(
        [row.get("operation") for row in value["operations"]] == list(expected),
        "complete exact ordered 38-operation coverage required",
    )
    for row in value["operations"]:
        name = row["operation"]
        if expected[name] is not None:
            _need(
                set(row) == {"operation", "outcome", "errno"}
                and row["outcome"] == "denied"
                and type(row["errno"]) is int
                and row["errno"] in expected[name],
                "actual permission errno required",
            )
        elif name == "actual_self_sample":
            _need(set(row) == {"operation", "sample"}, "exact sample row required")
            _sample(row["sample"])
        elif name == "proc_enumeration":
            _need(
                set(row) == {"operation", "outcome", "numeric"}
                and row["outcome"] == "self_threadgroup_only_numeric_entries"
                and type(row["numeric"]) is list
                and row["numeric"] == [ready["identity"]["tgid"]]
                and all(type(v) is int for v in row["numeric"]),
                "actual self-only enumeration required",
            )
        else:
            outcome = (
                "one_public_byte_read"
                if name == "self_process_vm_readv_sanity"
                else "unexercised_no_namespace_fd"
            )
            _need(
                set(row) == {"operation", "outcome"} and row["outcome"] == outcome,
                "actual sanity/setns disposition required",
            )
    return value
