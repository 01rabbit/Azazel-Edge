"""Synthetic source/kernel/syscall fixtures ONLY, never actual role/LSM evidence."""

from copy import deepcopy
from dataclasses import dataclass
import ctypes as ct
import errno
import hashlib
import json
from pathlib import Path
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import telemetry_isolation_worker as w
import telemetry_isolation_operations as ops
import telemetry_isolation_preflight as root

BOOT = "7be45004-1731-4b7c-8e62-59a5ddf129a4"


def context():
    return dict(
        identity=dict(
            pid=456,
            tgid=456,
            uid=61002,
            gid=61002,
            groups=[61002],
            apparmor=w.contract.PROFILE + " (enforce)",
            no_new_privs=True,
            cap_eff=0,
            cap_prm=0,
            cap_amb=0,
            cap_bnd=0,
            dumpable=1,
        ),
        kernel_boot_id=BOOT,
        source_sha256="a" * 64,
        source=str(w.SOURCE),
    )


def peer_frame(**kw):
    value = dict(pid=123, tgid=123, address=4096, size=1, kernel_boot_id=BOOT)
    value.update(kw)
    return json.dumps(value).encode() + b"\n"


def guard_fixture(monkeypatch, fault=None):
    fields = dict(
        Pid="456",
        Tgid="456",
        Uid="61002 61002 61002 61002",
        Gid="61002 61002 61002 61002",
        Groups="61002",
        NoNewPrivs="1",
        CapEff="0",
        CapPrm="0",
        CapAmb="0",
        CapBnd="0",
    )
    if fault == "uid":
        fields["Uid"] = "0 0 0 0"
    if fault == "caps":
        fields["CapBnd"] = "1"
    if fault == "nnp":
        fields["NoNewPrivs"] = "0"
    if fault == "tgid":
        fields["Tgid"] = "455"
    monkeypatch.setattr(
        w,
        "SOURCE",
        Path(w.__file__).resolve() if fault != "source" else Path("/wrong/source"),
    )
    monkeypatch.setattr(w.sys, "platform", "linux")
    seen = []

    def label(profile):
        seen.append("label")
        assert profile == w.contract.PROFILE
        if fault == "label":
            raise OSError("synthetic wrong label")

    monkeypatch.setattr(w, "enforce_capture", label)
    monkeypatch.setattr(
        w.Path,
        "read_bytes",
        lambda path: (
            "\n".join(k + ":" + v for k, v in fields.items()) + "\n"
        ).encode(),
    )
    monkeypatch.setattr(w.Path, "read_text", lambda path: BOOT)
    monkeypatch.setattr(
        w,
        "os",
        SimpleNamespace(
            getuid=lambda: 61002,
            getgid=lambda: 61002,
            getgroups=lambda: [61002],
            getpid=lambda: 456,
        ),
    )

    def source(*args, **kw):
        seen.append("protected_source")
        assert kw["owner"] == 0 and kw["max_bytes"] == 1024 * 1024
        return b"PUBLIC SYNTHETIC SOURCE", None

    monkeypatch.setattr(w, "read_regular", source)
    monkeypatch.setattr(
        w,
        "_libc",
        lambda: SimpleNamespace(prctl=lambda *args: 0 if fault == "dumpable" else 1),
    )
    return seen


def test_guard_reads_protected_source_and_actual_role_metadata_before_ready(
    monkeypatch,
):
    seen = guard_fixture(monkeypatch)
    _, value = w.guard()
    assert seen == ["label", "protected_source"]
    assert value["identity"]["pid"] == value["identity"]["tgid"] == 456
    assert (
        value["source_sha256"] == hashlib.sha256(b"PUBLIC SYNTHETIC SOURCE").hexdigest()
    )
    assert value["kernel_boot_id"] == BOOT


@pytest.mark.parametrize(
    "fault", ["source", "label", "uid", "caps", "nnp", "tgid", "dumpable"]
)
def test_guard_failure_cannot_reach_any_probe_or_emit_ready(monkeypatch, fault):
    guard_fixture(monkeypatch, fault)
    emitted = []
    monkeypatch.setattr(w, "emit", lambda value: emitted.append(deepcopy(value)))
    monkeypatch.setattr(
        w,
        "read_fence",
        lambda limit: pytest.fail("fence reached before successful source/role guard"),
    )
    with pytest.raises((RuntimeError, ValueError, OSError)):
        w.worker("probe")
    assert [value["kind"] for value in emitted] == ["blocked"]
    assert emitted[0]["operations"] == []


@pytest.mark.parametrize("mode", ["probe", "peer"])
def test_ready_and_root_fence_precede_all_operations(monkeypatch, mode):
    progress = []
    emitted = []
    monkeypatch.setattr(w, "guard", lambda: (None, context()))

    def emit(value):
        emitted.append(deepcopy(value))
        progress.append("emit:" + value["kind"])

    monkeypatch.setattr(w, "emit", emit)

    def fence(limit):
        assert progress == ["emit:ready"]
        progress.append("Root_fence")
        if mode == "peer":
            assert limit == 16 and emitted[0]["public_size"] == 1
            assert (
                ct.string_at(emitted[0]["public_address"], len(b"PUBLIC-NONKEY-CANARY"))
                == b"PUBLIC-NONKEY-CANARY"
            )
            return b"stop\n"
        assert limit == 1024
        return peer_frame()

    monkeypatch.setattr(w, "read_fence", fence)
    monkeypatch.setattr(w, "probe", lambda *args: progress.append("probe"))
    w.worker(mode)
    assert progress[:2] == ["emit:ready", "Root_fence"]
    assert ("probe" in progress) == (mode == "probe")
    assert (
        emitted[-1]["scope"]
        == "self_process_threadgroup_observations_not_qualification"
    )
    assert "qualified" not in emitted[-1] and "resume_authorized" not in emitted[-1]


def test_bad_root_frame_after_ready_cannot_start_a_probe(monkeypatch):
    emitted = []
    monkeypatch.setattr(w, "guard", lambda: (None, context()))
    monkeypatch.setattr(w, "emit", lambda value: emitted.append(deepcopy(value)))
    monkeypatch.setattr(w, "read_fence", lambda limit: peer_frame(pid=True))
    monkeypatch.setattr(
        w, "probe", lambda *args: pytest.fail("invalid peer frame reached probe")
    )
    with pytest.raises(RuntimeError):
        w.worker("probe")
    assert [v["kind"] for v in emitted] == ["ready", "blocked"]
    assert emitted[-1]["operations"] == []


def probe_fixture(monkeypatch, fault=None):
    calls = []
    closed = []

    def denied():
        raise PermissionError(errno.EPERM, "synthetic syscall denial")

    def syscall(name, *args):
        calls.append((name, args))
        if fault == name + "_success":
            return 0
        ct.set_errno(errno.EPERM)
        return -1

    libc = SimpleNamespace(
        ptrace=lambda *a: syscall("ptrace", *a),
        unshare=lambda flag: syscall("unshare", flag),
        capset=lambda *a: syscall("capset", *a),
    )

    def memory(lib, pid, address):
        calls.append(("memory", (pid, address)))
        if pid == 456:
            return (0, b"") if fault == "selfread" else (1, b"P")
        if fault == "peer_esrch":
            raise OSError(errno.ESRCH, "synthetic vanished peer")
        return denied()

    monkeypatch.setattr(w, "_read_byte", memory)

    @dataclass
    class Sample:
        coverage: dict

    monkeypatch.setattr(
        w,
        "LinuxProcTelemetrySource",
        lambda: SimpleNamespace(
            sample=lambda **k: Sample(
                dict.fromkeys(
                    ("proc_net_dev", "proc_loadavg", "proc_meminfo", "proc_uptime"),
                    fault != "coverage",
                )
            )
        ),
    )

    class Entries:
        def __enter__(self):
            return iter(
                SimpleNamespace(name=n)
                for n in (
                    ["self", "1"] if fault == "enumeration" else ["self", "456", "net"]
                )
            )

        def __exit__(self, *args):
            pass

    def opening(path, flags):
        calls.append(("open", (path, flags)))
        assert not flags & os.O_TRUNC and not flags & os.O_CREAT
        if "/binfmt_misc/" in path:
            assert flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC
            assert flags & os.O_ACCMODE == (
                os.O_WRONLY if path.endswith("register") else os.O_RDONLY
            )
            if fault == "binfmt_success":
                return 99
            if fault == "binfmt_missing":
                raise FileNotFoundError(errno.ENOENT, "synthetic missing API")
        if path == "/proc/self/ns/net" and fault == "nsfd_success":
            return 99
        if path.startswith("/proc/123/") or path.startswith("/proc/1/"):
            raise FileNotFoundError(errno.ENOENT, "synthetic hidden foreign process")
        return denied()

    def setuid(uid):
        calls.append(("setuid", (uid,)))
        return 0 if fault == "setuid_success" else denied()

    def signal(pid, sig):
        calls.append(("signal", (pid, sig)))
        return denied()

    constants = {
        key: getattr(os, key)
        for key in ("O_RDONLY", "O_WRONLY", "O_NOFOLLOW", "O_CLOEXEC")
    }
    monkeypatch.setattr(
        w,
        "os",
        SimpleNamespace(
            getpid=lambda: 456,
            scandir=lambda path: Entries(),
            open=opening,
            setuid=setuid,
            kill=signal,
            **constants,
        ),
    )
    monkeypatch.setattr(
        ops,
        "os",
        SimpleNamespace(close=lambda fd: closed.append(fd), strerror=os.strerror),
    )

    def profile():
        calls.append(("change_profile", ()))
        return 0 if fault == "profile_success" else denied()

    monkeypatch.setattr(w, "_change_profile", profile)

    def execute(argv, **kw):
        calls.append(("exec", argv))
        if fault == "exec_success":
            return SimpleNamespace(pid=999, wait=lambda timeout: 7)
        return denied()

    monkeypatch.setattr(w, "subprocess", SimpleNamespace(Popen=execute, DEVNULL=-3))

    def network(family, kind):
        calls.append(("network", (family, kind)))
        if fault == "socket_success":
            return SimpleNamespace(close=lambda: closed.append("socket"))
        raise OSError(errno.EAFNOSUPPORT, "synthetic systemd AF gate")

    monkeypatch.setattr(
        w,
        "socket",
        SimpleNamespace(AF_INET=2, AF_INET6=10, SOCK_STREAM=1, socket=network),
    )
    return libc, calls, closed


def test_fixed_probe_covers_all_required_real_operation_shapes_under_synthetic_returns(
    monkeypatch,
):
    libc, calls, _ = probe_fixture(monkeypatch)
    records = []
    w.probe(
        libc,
        context(),
        dict(pid=123, tgid=123, address=4096, size=1, kernel_boot_id=BOOT),
        records,
    )
    names = [r["operation"] for r in records]
    for prefix, count in (
        ("binfmt_denied_open:", 2),
        ("foreign_read_open:", 10),
        ("ptrace_seize:", 2),
        ("public_nonkey_read_open:", 4),
        ("nontruncating_write_open:", 4),
        ("unintended_exec:", 3),
        ("network_family:", 2),
        ("signal_zero:", 2),
    ):
        assert sum(name.startswith(prefix) for name in names) == count
    for name in (
        "self_process_vm_readv_sanity",
        "actual_self_sample",
        "proc_enumeration",
        "peer_process_vm_readv_valid_public_byte",
        "setuid_zero",
        "capset_raise_sysadmin",
        "aa_change_profile_unconfined",
        "unshare_newuser",
        "unshare_newnet",
        "namespace_fd_open",
        "setns",
    ):
        assert names.count(name) == 1
    assert (
        next(r for r in records if r["operation"] == "setns")["outcome"]
        == "unexercised_no_namespace_fd"
    )
    assert [(op, args) for op, args in calls if op == "unshare"] == [
        ("unshare", (0x10000000,)),
        ("unshare", (0x40000000,)),
    ]
    assert all(
        "azazel-edge-core" not in str(args) for op, args in calls if op == "exec"
    )
    assert len(records) == 40
    assert calls[0][0] == "memory" and calls[0][1][0] == 456 and calls[0][1][1] > 0
    assert ("memory", (123, 4096)) in calls


@pytest.mark.parametrize(
    "fault,last",
    [
        ("capset_success", "capset_raise_sysadmin"),
        ("profile_success", "aa_change_profile_unconfined"),
        ("unshare_success", "unshare_newuser"),
        ("setuid_success", "setuid_zero"),
        ("exec_success", "unintended_exec:/usr/bin/true"),
        ("nsfd_success", "namespace_fd_open"),
        ("socket_success", "network_family:2"),
        ("peer_esrch", "peer_process_vm_readv_valid_public_byte"),
        ("enumeration", "proc_enumeration"),
        ("coverage", "actual_self_sample"),
        ("binfmt_success", "binfmt_denied_open:/proc/sys/fs/binfmt_misc/status"),
        ("binfmt_missing", "binfmt_denied_open:/proc/sys/fs/binfmt_misc/status"),
    ],
)
def test_fatal_partial_record_aborts_without_any_later_probe(monkeypatch, fault, last):
    libc, calls, closed = probe_fixture(monkeypatch, fault)
    emitted = []
    monkeypatch.setattr(w, "guard", lambda: (libc, context()))
    monkeypatch.setattr(w, "read_fence", lambda limit: peer_frame())
    monkeypatch.setattr(w, "emit", lambda value: emitted.append(deepcopy(value)))
    with pytest.raises(RuntimeError):
        w.worker("probe")
    assert emitted[-1]["kind"] == "blocked"
    assert emitted[-1]["operations"][-1]["operation"] == last
    if fault == "binfmt_success":
        assert closed == [99]
    if fault == "peer_esrch":
        assert emitted[-1]["operations"][-1]["outcome"] == "unsupported_error"
    if fault == "exec_success":
        assert emitted[-1]["operations"][-1]["child_reaped"] is True
        assert emitted[-1]["operations"][-1]["outcome"] == "unexpected_success"
    if fault == "nsfd_success":
        assert closed == [99]
    if fault == "socket_success":
        assert closed == ["socket"]
    if fault == "capset_success":
        assert not any(op == "change_profile" for op, args in calls)
    if fault == "profile_success":
        assert not any(op == "unshare" for op, args in calls)
    if fault == "unshare_success":
        assert not any(op == "network" for op, args in calls)


def test_failed_self_read_sanity_never_reaches_sampling_or_foreign_read(monkeypatch):
    libc, calls, _ = probe_fixture(monkeypatch, "selfread")
    records = []
    with pytest.raises(RuntimeError, match="self memory-read sanity failed"):
        w.probe(libc, context(), dict(pid=123, address=4096), records)
    assert records == [] and len(calls) == 1


def test_reserved_root_argv_now_points_to_committed_worker_source_only():
    assert Path(root.worker_argv("probe")[3]).name == "telemetry_isolation_worker.py"
    assert root.worker_argv("peer")[-2:] == ["--worker", "peer"]


@pytest.mark.parametrize(
    "code",
    [errno.EPERM, errno.EACCES, errno.ENOENT, errno.EINVAL, errno.ENOSYS, errno.ESRCH],
)
def test_valid_newuser_permission_errnos_only_and_newnet_remains_strict(
    monkeypatch, code
):
    libc, calls, _ = probe_fixture(monkeypatch)
    flags_seen = []

    def unshare(flag):
        flags_seen.append(flag)
        ct.set_errno(code if flag == 0x10000000 else errno.EPERM)
        return -1

    libc.unshare = unshare
    records = []
    if code in (errno.EPERM, errno.EACCES):
        w.probe(libc, context(), dict(pid=123, address=4096), records)
        row = next(r for r in records if r["operation"] == "unshare_newuser")
        assert row["outcome"] == "denied" and row["errno"] == code
        assert len(records) == 40 and flags_seen == [0x10000000, 0x40000000]
    else:
        with pytest.raises(RuntimeError):
            w.probe(libc, context(), dict(pid=123, address=4096), records)
        assert records[-1]["operation"] == "unshare_newuser"
        assert records[-1]["outcome"] == "unsupported_error"
        assert flags_seen == [0x10000000]


def test_newnet_eacces_is_not_relaxed_by_newuser_errno_support(monkeypatch):
    libc, _, _ = probe_fixture(monkeypatch)

    def unshare(flag):
        ct.set_errno(errno.EACCES)
        return -1

    libc.unshare = unshare
    records = []
    with pytest.raises(RuntimeError):
        w.probe(libc, context(), dict(pid=123, address=4096), records)
    assert records[-1]["operation"] == "unshare_newnet"
    assert records[-1]["outcome"] == "unsupported_error"


@pytest.mark.parametrize("pid", [123, 1])
@pytest.mark.parametrize(
    "code",
    [errno.EPERM, errno.EACCES, errno.ENOENT, errno.EINVAL, errno.ENOSYS, errno.ESRCH],
)
def test_fixed_signal_zero_permission_denials_only_never_send_signal(
    monkeypatch, pid, code
):
    libc, _, _ = probe_fixture(monkeypatch)
    seen = []

    def killing(target, signal):
        seen.append((target, signal))
        raise OSError(
            code if target == pid else errno.EPERM, "synthetic kill-zero denial"
        )

    monkeypatch.setattr(w.os, "kill", killing)
    records = []
    if code in (errno.EPERM, errno.EACCES):
        w.probe(libc, context(), dict(pid=123, address=4096), records)
        assert len(records) == 40 and seen == [(123, 0), (1, 0)]
        row = next(r for r in records if r["operation"] == f"signal_zero:{pid}")
        assert row["outcome"] == "denied" and row["errno"] == code
    else:
        with pytest.raises(RuntimeError):
            w.probe(libc, context(), dict(pid=123, address=4096), records)
        assert records[-1]["operation"] == f"signal_zero:{pid}"
        assert records[-1]["outcome"] == "unsupported_error"
        assert seen == ([(123, 0)] if pid == 123 else [(123, 0), (1, 0)])


def test_unexpected_signal_zero_success_remains_fatal_before_pid1(monkeypatch):
    libc, _, _ = probe_fixture(monkeypatch)
    seen = []
    monkeypatch.setattr(w.os, "kill", lambda pid, signal: seen.append((pid, signal)))
    records = []
    with pytest.raises(RuntimeError):
        w.probe(libc, context(), dict(pid=123, address=4096), records)
    assert seen == [(123, 0)]
    assert records[-1]["operation"] == "signal_zero:123"
    assert records[-1]["outcome"] == "unexpected_success"
