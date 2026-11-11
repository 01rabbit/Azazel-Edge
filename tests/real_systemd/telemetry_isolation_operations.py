"""Private fixed-worker primitives, not actual permission or isolation evidence.

No role main/Root controller, install/load, sampling, path/operation selector CLI.
Only later reviewed fixed worker code may compose these private primitives.
"""

import ctypes as ct
import errno
import os
import select
import subprocess
import sys
import time
from azazel_edge.outcome.journal import _parse

FENCE_SECONDS = 10
DENIED = (errno.EACCES, errno.EPERM)


class IOVec(ct.Structure):
    _fields_ = [("base", ct.c_void_p), ("length", ct.c_size_t)]


class CapHeader(ct.Structure):
    _fields_ = [("version", ct.c_uint32), ("pid", ct.c_int)]


class CapData(ct.Structure):
    _fields_ = [
        ("effective", ct.c_uint32),
        ("permitted", ct.c_uint32),
        ("inheritable", ct.c_uint32),
    ]


def _need(value, reason):
    if not value:
        raise RuntimeError(reason)


def _libc():
    libc = ct.CDLL("libc.so.6", use_errno=True)
    for name, args, result in (
        ("prctl", [ct.c_int, *([ct.c_ulong] * 4)], ct.c_int),
        (
            "process_vm_readv",
            [
                ct.c_int,
                ct.POINTER(IOVec),
                ct.c_ulong,
                ct.POINTER(IOVec),
                ct.c_ulong,
                ct.c_ulong,
            ],
            ct.c_ssize_t,
        ),
        ("ptrace", [ct.c_ulong, ct.c_int, ct.c_void_p, ct.c_void_p], ct.c_long),
        ("unshare", [ct.c_int], ct.c_int),
        ("capset", [ct.POINTER(CapHeader), ct.POINTER(CapData)], ct.c_int),
    ):
        function = getattr(libc, name)
        function.argtypes = args
        function.restype = result
    return libc


def _checked(result):
    if result == -1:
        code = ct.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def read_fence(limit):
    _need(type(limit) is int and limit in (16, 1024), "fixed fence bound required")
    deadline = time.monotonic() + FENCE_SECONDS
    raw = bytearray()
    while not raw.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        _need(
            remaining > 0 and select.select([sys.stdin.buffer], [], [], remaining)[0],
            "Root fence deadline",
        )
        chunk = os.read(sys.stdin.buffer.fileno(), limit + 1 - len(raw))
        _need(chunk, "Root fence EOF")
        raw.extend(chunk)
        _need(len(raw) <= limit, "Root fence size")
    _need(raw.count(b"\n") == 1, "Root fence has trailing frames")
    return bytes(raw)


def target(raw, context):
    value = _parse(raw)
    _need(
        type(value) is dict
        and set(value) == {"pid", "tgid", "address", "size", "kernel_boot_id"},
        "fixed peer fields required",
    )
    _need(
        all(type(value[k]) is int for k in ("pid", "tgid", "address", "size"))
        and 1 < value["pid"] == value["tgid"] < 2**31
        and value["pid"] != context["identity"]["tgid"]
        and 0 < value["address"] < 2 ** (ct.sizeof(ct.c_void_p) * 8)
        and value["size"] == 1
        and value["kernel_boot_id"] == context["kernel_boot_id"],
        "peer identity/valid public address differs",
    )
    return value


def _read_byte(libc, pid, address):
    local = ct.create_string_buffer(1)
    a, b = IOVec(ct.addressof(local), 1), IOVec(address, 1)
    ct.set_errno(0)
    count = _checked(libc.process_vm_readv(pid, ct.byref(a), 1, ct.byref(b), 1, 0))
    return count, local.raw


def _denied(records, name, call, accepted=DENIED, resource=None):
    row = dict(operation=name, outcome="inflight")
    records.append(row)
    try:
        result = call()
    except OSError as exc:
        row.update(
            outcome="denied" if exc.errno in accepted else "unsupported_error",
            errno=exc.errno,
        )
        _need(exc.errno in accepted, "unsupported errno is not permission evidence")
        return
    row.update(outcome="unexpected_success")
    if resource == "fd":
        os.close(result)
    elif resource == "socket":
        result.close()
    elif resource == "child":
        row["child_pid"] = result.pid
        try:
            result.wait(timeout=0.25)
            row["child_reaped"] = True
        except subprocess.TimeoutExpired:
            try:
                result.kill()
                result.wait(timeout=0.25)
                row["child_reaped"] = True
            except BaseException as exc:
                row["reap_error"] = type(exc).__name__
    raise RuntimeError("unexpected operation success; abort remaining probes")


def _raise_capability(libc):
    data = (CapData * 2)()
    data[0].effective = data[0].permitted = 1 << 21
    header = CapHeader(0x20080522, 0)
    ct.set_errno(0)
    return _checked(libc.capset(ct.byref(header), data))


def _change_profile():
    library = ct.CDLL("libapparmor.so.1", use_errno=True)
    library.aa_change_profile.argtypes = [ct.c_char_p]
    library.aa_change_profile.restype = ct.c_int
    ct.set_errno(0)
    return _checked(library.aa_change_profile(b"unconfined"))
