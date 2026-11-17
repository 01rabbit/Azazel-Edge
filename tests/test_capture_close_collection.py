"""Synthetic syscall adapters; no capture pilot or privilege operation."""

import hashlib
import os
import stat
from types import SimpleNamespace

import pytest

from azazel_edge.benchmark import capture_close_collection as c

DOMAIN = dict(
    time_namespace_device=1,
    time_namespace_inode=2,
    timens_offsets=[
        dict(clock=clock, seconds=0, nanoseconds=0)
        for clock in ("monotonic", "boottime")
    ],
    established=True,
)
IDENTITY = dict(
    pid=303,
    uid=1000,
    process_start_ticks=33,
    boot_id="00000000-0000-4000-8000-000000000001",
    clock_domain=DOMAIN,
)
OBJECT = dict(device=11, inode=22, owner_uid=1000)


class Proxy:
    def __init__(self, original, **overrides):
        self.original, self.overrides = original, overrides

    def __getattr__(self, name):
        return (
            self.overrides[name]
            if name in self.overrides
            else getattr(self.original, name)
        )


def backend(monkeypatch, data=b"abcdef"):
    calls = []
    state = dict(
        mode=stat.S_IFREG | 0o600,
        nlink=0,
        size=len(data),
        device=11,
        inode=22,
        uid=1000,
        access=0,
        seals=15,
        fstat_calls=0,
    )

    def fstat(fd):
        assert fd == 7
        calls.append(("fstat", fd))
        state["fstat_calls"] += 1
        return SimpleNamespace(
            st_dev=state["device"],
            st_ino=state["inode"],
            st_uid=state["uid"],
            st_mode=state["mode"],
            st_nlink=state["nlink"],
            st_size=state["size"],
        )

    def fcntl(fd, command):
        assert fd == 7
        calls.append(("fcntl", command))
        assert command in (c.fcntl.F_GETFL, 999)
        return state["access"] if command == c.fcntl.F_GETFL else state["seals"]

    def pread(fd, size, offset):
        assert fd == 7
        calls.append(("pread", size, offset))
        return data[offset : offset + size]

    def forbidden(*args, **kwargs):
        raise AssertionError("target mutation, close or seek")

    monkeypatch.setattr(c, "process_identity", lambda: dict(IDENTITY))
    monkeypatch.setattr(
        c,
        "os",
        Proxy(
            os,
            fstat=fstat,
            pread=pread,
            write=forbidden,
            close=forbidden,
            lseek=forbidden,
            chmod=forbidden,
            fchmod=forbidden,
            open=forbidden,
        ),
    )
    monkeypatch.setattr(c, "fcntl", Proxy(c.fcntl, fcntl=fcntl, F_GET_SEALS=999))
    return state, calls


def test_readonly_full_object_is_recounted_without_seek_close_or_mutation(monkeypatch):
    state, calls = backend(monkeypatch)
    result = c.collect_sealed_fd(7, expected_identity=OBJECT)
    assert result["raw"] == b"abcdef" and result["receipt"]["complete"] is True
    assert (
        result["receipt"]["bytes_read"] == 6
        and result["receipt"]["sha256"] == hashlib.sha256(b"abcdef").hexdigest()
    )
    assert (
        result["receipt"]["access_mode"] == 0
        and result["receipt"]["seals_before"] == result["receipt"]["seals_after"] == 15
    )
    assert result["receipt"]["object_before"] == result["receipt"]["object_after"]
    assert ("pread", 1, 6) in calls


@pytest.mark.parametrize(
    "fault",
    ["identity", "writable", "unsealed", "type", "nlink", "size", "unsupported"],
)
def test_initial_invalid_object_never_reads_unrelated_or_unsealed_bytes(
    monkeypatch, fault
):
    state, calls = backend(monkeypatch)
    if fault == "identity":
        state["inode"] = 99
    elif fault == "writable":
        state["access"] = os.O_RDWR
    elif fault == "unsealed":
        state["seals"] = 7
    elif fault == "type":
        state["mode"] = stat.S_IFIFO | 0o600
    elif fault == "nlink":
        state["nlink"] = 1
    elif fault == "size":
        state["size"] = c.MAXIMUM + 1
    else:
        monkeypatch.setattr(c, "fcntl", Proxy(c.fcntl, F_GET_SEALS=None))
    result = c.collect_sealed_fd(7, expected_identity=OBJECT)
    assert (
        result["raw"] == b""
        and result["receipt"]["complete"] is False
        and result["receipt"]["errors"]
    )
    assert not any(call[0] == "pread" for call in calls)


def test_read_fault_retains_actual_bounded_prefix(monkeypatch):
    state, calls = backend(monkeypatch)

    def partial(fd, size, offset):
        if offset == 0:
            return b"abc"
        raise OSError("SYNTHETIC later read failure")

    monkeypatch.setattr(c, "os", Proxy(c.os, pread=partial))
    result = c.collect_sealed_fd(7, expected_identity=OBJECT)
    assert result["raw"] == b"abc" and result["receipt"]["bytes_read"] == 3
    assert result["receipt"]["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert (
        result["receipt"]["complete"] is False
        and "capture_read_incomplete" in result["receipt"]["errors"]
    )


def test_postread_replaced_object_retains_bytes_but_never_complete(monkeypatch):
    state, calls = backend(monkeypatch)
    initial = c.os.fstat

    def replaced(fd):
        if state["fstat_calls"]:
            state["inode"] = 99
        return initial(fd)

    monkeypatch.setattr(c, "os", Proxy(c.os, fstat=replaced))
    result = c.collect_sealed_fd(7, expected_identity=OBJECT)
    assert result["raw"] == b"abcdef" and result["receipt"]["complete"] is False
    assert "capture_object_changed" in result["receipt"]["errors"]


@pytest.mark.parametrize("fault", ["identity", "start_clock", "end_clock"])
def test_probe_unknown_is_not_replaced_by_success_bit(monkeypatch, fault):
    state, calls = backend(monkeypatch)
    if fault == "identity":
        monkeypatch.setattr(
            c, "process_identity", lambda: (_ for _ in ()).throw(OSError("identity"))
        )
    else:
        count = [0]
        real = c.time.monotonic_ns

        def clock():
            count[0] += 1
            if count[0] == (1 if fault == "start_clock" else 2):
                raise OSError("clock")
            return real()

        monkeypatch.setattr(c, "time", Proxy(c.time, monotonic_ns=clock))
    result = c.collect_sealed_fd(7, expected_identity=OBJECT)
    assert result["raw"] == b"abcdef" and result["receipt"]["complete"] is False
    assert result["receipt"]["errors"]
    if fault == "identity":
        assert result["receipt"]["collector_identity"] is None
    else:
        assert (
            result["receipt"][
                "read_started_ns" if fault == "start_clock" else "read_finished_ns"
            ]
            is None
        )


@pytest.mark.parametrize(
    "fd,expected,maximum",
    [
        (True, OBJECT, 100),
        (7, dict(OBJECT, inode=True), 100),
        (7, OBJECT, False),
        (7, OBJECT, c.MAXIMUM + 1),
        (7, dict(OBJECT, path="/unrelated"), 100),
    ],
)
def test_global_invalid_args_fail_before_any_observation(
    monkeypatch, fd, expected, maximum
):
    state, calls = backend(monkeypatch)
    with pytest.raises(ValueError):
        c.collect_sealed_fd(fd, expected_identity=expected, maximum=maximum)
    assert calls == []
