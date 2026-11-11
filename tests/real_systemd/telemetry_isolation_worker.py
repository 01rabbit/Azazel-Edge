"""Fixed unprivileged candidate roles. No Root controller or acceptance authority.

Never run outside the reviewed hardened unit. Self is process/thread-group scope;
worker output alone cannot establish hidepid, target liveness or LSM attribution.
"""

# ruff: noqa: E402
import argparse
import ctypes as ct
from dataclasses import asdict
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(SRC / "py"), str(SRC / "tests"), str(Path(__file__).parent)]
import telemetry_isolation_contract as contract
from telemetry_isolation_preflight import canary_spec
from azazel_edge.outcome.confinement import enforce_capture
from azazel_edge.outcome.input_auth import read_regular
from azazel_edge.outcome.telemetry import LinuxProcTelemetrySource

from telemetry_isolation_operations import (
    _need,
    _libc,
    _checked,
    _read_byte,
    _denied,
    _raise_capability,
    _change_profile,
    read_fence,
    target,
    DENIED,
)

SOURCE = Path("/opt/edge400-src/tests/real_systemd/telemetry_isolation_worker.py")


def guard():
    enforce_capture(contract.PROFILE)
    _need(
        sys.platform == "linux" and Path(__file__).resolve() == SOURCE,
        "fixed Linux source required",
    )
    raw = Path("/proc/self/status").read_bytes()
    _need(len(raw) <= 65536, "status bound")
    fields = dict(row.split(":", 1) for row in raw.decode().splitlines())
    _need(
        fields["Uid"].split() == fields["Gid"].split() == ["61002"] * 4,
        "real credentials differ",
    )
    libc = _libc()
    identity = dict(
        pid=int(fields["Pid"]),
        tgid=int(fields["Tgid"]),
        uid=os.getuid(),
        gid=os.getgid(),
        groups=os.getgroups(),
        apparmor=contract.PROFILE + " (enforce)",
        no_new_privs=fields["NoNewPrivs"].strip() == "1",
        dumpable=_checked(libc.prctl(3, 0, 0, 0, 0)),
        **{
            key: int(fields[field], 16)
            for key, field in (
                ("cap_eff", "CapEff"),
                ("cap_prm", "CapPrm"),
                ("cap_amb", "CapAmb"),
                ("cap_bnd", "CapBnd"),
            )
        },
    )
    contract.validate_role_identity(identity)
    _need(identity["pid"] == os.getpid(), "actual PID differs from kernel self view")
    source, _ = read_regular(SOURCE, owner=0, max_bytes=1024 * 1024)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    _need(str(uuid.UUID(boot)) == boot, "canonical actual boot required")
    return libc, dict(
        identity=identity,
        kernel_boot_id=boot,
        source_sha256=hashlib.sha256(source).hexdigest(),
        source=str(SOURCE),
    )


def emit(value):
    raw = (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )
    _need(len(raw) <= 65536, "worker reply bound")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def probe(libc, context, peer, records):
    own = ct.create_string_buffer(b"P")
    _need(
        _read_byte(libc, os.getpid(), ct.addressof(own)) == (1, b"P"),
        "self memory-read sanity failed",
    )
    records.append(
        dict(operation="self_process_vm_readv_sanity", outcome="one_public_byte_read")
    )
    sample = asdict(
        LinuxProcTelemetrySource().sample(interface="es", epoch=time.time())
    )
    records.append(dict(operation="actual_self_sample", sample=sample))
    _need(
        set(sample["coverage"])
        == {"proc_net_dev", "proc_loadavg", "proc_meminfo", "proc_uptime"}
        and all(v is True for v in sample["coverage"].values()),
        "self coverage incomplete",
    )
    numeric = []
    enumeration = dict(
        operation="proc_enumeration", outcome="inflight", numeric=numeric
    )
    records.append(enumeration)
    with os.scandir("/proc") as entries:
        for index, entry in enumerate(entries):
            _need(index < 4096, "proc enumeration bound")
            if entry.name.isascii() and entry.name.isdecimal():
                numeric.append(int(entry.name))
                _need(
                    int(entry.name) == context["identity"]["tgid"],
                    "foreign process enumerated",
                )
    enumeration["outcome"] = "self_threadgroup_only_numeric_entries"
    _need(
        set(numeric) == {context["identity"]["tgid"]},
        "self process missing from enumeration",
    )
    for pid in (peer["pid"], 1):
        for suffix in (
            "net/dev",
            f"task/{pid}/net/dev",
            "root/proc/net/dev",
            "root/proc/self/net/dev",
            f"root/proc/{pid}/net/dev",
        ):
            path = f"/proc/{pid}/" + suffix
            _denied(
                records,
                "foreign_read_open:" + path,
                lambda path=path: os.open(path, os.O_RDONLY | os.O_NOFOLLOW),
                DENIED + (errno.ENOENT,),
                "fd",
            )
    _denied(
        records,
        "peer_process_vm_readv_valid_public_byte",
        lambda: _read_byte(libc, peer["pid"], peer["address"]),
        (errno.EPERM,),
    )
    for pid in (peer["pid"], 1):
        _denied(
            records,
            f"ptrace_seize:{pid}",
            lambda pid=pid: _checked(libc.ptrace(0x4206, pid, None, None)),
            (errno.EPERM,),
        )
    for item in canary_spec()[:-1]:
        _denied(
            records,
            "public_nonkey_read_open:" + item["path"],
            lambda path=item["path"]: os.open(path, os.O_RDONLY | os.O_NOFOLLOW),
            resource="fd",
        )
    for path in (
        canary_spec()[-1]["path"],
        "/proc/net/dev",
        "/proc/loadavg",
        "/proc/uptime",
    ):
        _denied(
            records,
            "nontruncating_write_open:" + path,
            lambda path=path: os.open(path, os.O_WRONLY),
            resource="fd",
        )
    for argv in (
        ("/usr/bin/true", "--version"),
        ("/usr/sbin/nft", "--version"),
        ("/opt/edge400-runtime/bin/edge-capture", "--version"),
    ):
        _denied(
            records,
            "unintended_exec:" + argv[0],
            lambda argv=argv: subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ),
            resource="child",
        )
    _denied(records, "setuid_zero", lambda: os.setuid(0), (errno.EPERM,))
    _denied(
        records,
        "capset_raise_sysadmin",
        lambda: _raise_capability(libc),
        (errno.EPERM,),
    )
    _denied(records, "aa_change_profile_unconfined", _change_profile, DENIED)
    for flag, name in ((0x10000000, "newuser"), (0x40000000, "newnet")):
        _denied(
            records,
            "unshare_" + name,
            lambda flag=flag: _checked(libc.unshare(flag)),
            (errno.EPERM,),
        )
    _denied(
        records,
        "namespace_fd_open",
        lambda: os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC),
        resource="fd",
    )
    records.append(dict(operation="setns", outcome="unexercised_no_namespace_fd"))
    for family in (socket.AF_INET, socket.AF_INET6):
        _denied(
            records,
            "network_family:" + str(family),
            lambda family=family: socket.socket(family, socket.SOCK_STREAM),
            (errno.EACCES, errno.EPERM, errno.EAFNOSUPPORT),
            resource="socket",
        )
    for pid in (peer["pid"], 1):
        _denied(
            records,
            f"signal_zero:{pid}",
            lambda pid=pid: os.kill(pid, 0),
            (errno.EPERM,),
        )


def worker(mode):
    records = []
    result = dict(
        mode=mode,
        scope="self_process_threadgroup_observations_not_qualification",
        operations=records,
    )
    try:
        contract.role_spec(mode)
        libc, context = guard()
        result.update(context)
        public = ct.create_string_buffer(b"PUBLIC-NONKEY-CANARY")
        ready = dict(
            kind="ready",
            mode=mode,
            **context,
            public_address=ct.addressof(public) if mode == "peer" else None,
            public_size=1 if mode == "peer" else None,
        )
        emit(ready)
        raw = read_fence(1024 if mode == "probe" else 16)
        if mode == "peer":
            _need(raw == b"stop\n", "fixed peer stop required")
        else:
            probe(libc, context, target(raw, context), records)
        result["kind"] = (
            "peer_wait_finished" if mode == "peer" else "probe_observations_complete"
        )
        emit(result)
    except BaseException as exc:
        result.update(kind="blocked", error=type(exc).__name__)
        emit(result)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=("peer", "probe"), required=True)
    worker(parser.parse_args().worker)
