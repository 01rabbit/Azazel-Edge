"""Synthetic syscall-return fixtures ONLY; no actual permission/LSM evidence."""

import ctypes as ct
import errno
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import telemetry_isolation_operations as o

BOOT = "7be45004-1731-4b7c-8e62-59a5ddf129a4"


def peer(**kw):
    value = dict(pid=123, tgid=123, address=4096, size=1, kernel_boot_id=BOOT)
    value.update(kw)
    return json.dumps(value).encode() + b"\n"


def test_fixed_peer_fields_are_data_not_arbitrary_path_or_operation_selectors():
    context = dict(identity=dict(tgid=456), kernel_boot_id=BOOT)
    assert o.target(peer(), context) == dict(
        pid=123, tgid=123, address=4096, size=1, kernel_boot_id=BOOT
    )
    with pytest.raises(RuntimeError):
        o.target(peer(path="/proc/1/net/dev"), context)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", True),
        ("tgid", False),
        ("pid", 1),
        ("pid", 456),
        ("tgid", 124),
        ("address", True),
        ("address", 0),
        ("address", -1),
        ("address", 2 ** (ct.sizeof(ct.c_void_p) * 8)),
        ("size", True),
        ("size", 2),
        ("kernel_boot_id", "other"),
    ],
)
def test_malformed_peer_data_refuses_before_any_operation(field, value):
    with pytest.raises(RuntimeError):
        o.target(
            peer(**{field: value}), dict(identity=dict(tgid=456), kernel_boot_id=BOOT)
        )


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES])
def test_real_oserror_value_recorded_only_for_allowed_permission_errno(code):
    records = []

    def synthetic():
        raise OSError(code, "synthetic fixture")

    o._denied(records, "fixed_fixture_op", synthetic)
    assert records == [dict(operation="fixed_fixture_op", outcome="denied", errno=code)]


@pytest.mark.parametrize(
    "code", [errno.ESRCH, errno.EFAULT, errno.ENOSYS, errno.ENOENT, errno.EINVAL, 0]
)
def test_unsupported_errno_cannot_become_read_trace_permission_proof(code):
    records = []

    def synthetic():
        raise OSError(code, "synthetic fixture")

    with pytest.raises(RuntimeError, match="unsupported errno"):
        o._denied(
            records, "valid_peer_read_or_trace_fixture", synthetic, (errno.EPERM,)
        )
    assert (
        records[-1]["outcome"] == "unsupported_error" and records[-1]["errno"] == code
    )


def test_unexpected_privilege_success_aborts_before_next_operation():
    records = []
    progress = []
    with pytest.raises(RuntimeError, match="unexpected operation success"):
        o._denied(records, "synthetic_privilege_change", lambda: 0, (errno.EPERM,))
        progress.append("must never execute")
    assert not progress and records[-1]["outcome"] == "unexpected_success"


@pytest.mark.parametrize("kind", ["fd", "socket"])
def test_unexpected_owned_resource_is_closed_before_fatal_abort(monkeypatch, kind):
    closed = []
    resource = (
        99 if kind == "fd" else SimpleNamespace(close=lambda: closed.append("socket"))
    )
    monkeypatch.setattr(o.os, "close", lambda fd: closed.append(fd))
    with pytest.raises(RuntimeError):
        o._denied([], "synthetic_resource", lambda: resource, resource=kind)
    assert closed == ([99] if kind == "fd" else ["socket"])


@pytest.mark.parametrize(
    "slow,killfails", [(False, False), (True, False), (True, True)]
)
def test_unexpected_exec_is_never_called_denied_and_reap_attempts_are_bounded(
    slow, killfails
):
    events = []

    class Child:
        pid = 123

        def wait(self, timeout):
            events.append(("wait", timeout))
            if slow and len(events) == 1:
                raise subprocess.TimeoutExpired("fixed version command", timeout)
            return 0

        def kill(self):
            events.append(("kill",))
            if killfails:
                raise PermissionError(errno.EPERM, "synthetic deny signal")

    records = []
    with pytest.raises(RuntimeError):
        o._denied(records, "synthetic_exec_started", Child, resource="child")
    assert (
        records[-1]["outcome"] == "unexpected_success"
        and records[-1]["child_pid"] == 123
    )
    assert all(event[1] <= 0.25 for event in events if event[0] == "wait")
    if killfails:
        assert records[-1]["reap_error"] == "PermissionError"
    else:
        assert records[-1]["child_reaped"] is True


def test_public_memory_ffi_uses_valid_one_byte_iovecs_without_any_real_syscall():
    seen = []

    def synthetic(pid, local, count1, remote, count2, flags):
        a = ct.cast(local, ct.POINTER(o.IOVec)).contents
        b = ct.cast(remote, ct.POINTER(o.IOVec)).contents
        seen.append((pid, a.length, b.base, b.length, count1, count2, flags))
        ct.memmove(a.base, b"P", 1)
        return 1

    assert o._read_byte(SimpleNamespace(process_vm_readv=synthetic), 123, 4096) == (
        1,
        b"P",
    )
    assert seen == [(123, 1, 4096, 1, 1, 1, 0)]


def test_public_memory_ffi_forwards_actual_errno_without_invalid_address_fake_success():
    def synthetic(*args):
        ct.set_errno(errno.EPERM)
        return -1

    with pytest.raises(OSError) as error:
        o._read_byte(SimpleNamespace(process_vm_readv=synthetic), 123, 4096)
    assert error.value.errno == errno.EPERM


def test_capset_fixture_requests_real_effective_and_permitted_sysadmin_with_v3_header():
    seen = []

    def synthetic(header, data):
        h = ct.cast(header, ct.POINTER(o.CapHeader)).contents
        seen.append(
            (
                h.version,
                h.pid,
                data[0].effective,
                data[0].permitted,
                data[0].inheritable,
                data[1].effective,
                data[1].permitted,
            )
        )
        ct.set_errno(errno.EPERM)
        return -1

    with pytest.raises(OSError):
        o._raise_capability(SimpleNamespace(capset=synthetic))
    assert seen == [(0x20080522, 0, 1 << 21, 1 << 21, 0, 0, 0)]


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES])
def test_profile_change_fixture_accepts_only_legitimate_denials(monkeypatch, code):
    class Function:
        def __call__(self, label):
            assert label == b"unconfined"
            ct.set_errno(code)
            return -1

    function = Function()
    monkeypatch.setattr(
        o.ct, "CDLL", lambda *a, **k: SimpleNamespace(aa_change_profile=function)
    )
    records = []
    o._denied(records, "profile_change_fixture", o._change_profile)
    assert records[-1]["errno"] == code and function.argtypes == [ct.c_char_p]


def test_typed_libc_symbols_bound_without_invoking_any_operation(monkeypatch):
    functions = {
        name: SimpleNamespace()
        for name in ("prctl", "process_vm_readv", "ptrace", "unshare", "capset")
    }
    monkeypatch.setattr(o.ct, "CDLL", lambda *a, **kw: SimpleNamespace(**functions))
    o._libc()
    assert functions["process_vm_readv"].restype is ct.c_ssize_t
    assert functions["ptrace"].restype is ct.c_long
    assert len(functions["process_vm_readv"].argtypes) == 6


@pytest.mark.parametrize(
    "chunks,ready",
    [
        ([b'{"pid":', b"123}\n"], True),
        ([b"partial"], False),
        ([b""], True),
        ([b"x" * 1025], True),
        ([b"a\nb\n"], True),
    ],
)
def test_bounded_root_fence_retains_exact_frame_or_refuses(monkeypatch, chunks, ready):
    values = iter(chunks)
    monkeypatch.setattr(
        o.sys, "stdin", SimpleNamespace(buffer=SimpleNamespace(fileno=lambda: 42))
    )
    monkeypatch.setattr(
        o.select, "select", lambda *a: ([42], [], []) if ready else ([], [], [])
    )
    monkeypatch.setattr(o.os, "read", lambda *a: next(values))
    monkeypatch.setattr(o.time, "monotonic", lambda: 0)
    if chunks == [b'{"pid":', b"123}\n"]:
        assert o.read_fence(1024) == b'{"pid":123}\n'
    else:
        with pytest.raises(RuntimeError):
            o.read_fence(1024)
