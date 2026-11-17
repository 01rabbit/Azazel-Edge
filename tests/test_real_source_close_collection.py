"""Synthetic FD/proc adapters, no real Source capture trial."""

import hashlib
import os
import stat
from types import SimpleNamespace

import pytest

from azazel_edge.benchmark import real_source_close_collection as c
from test_capture_close_collection import Proxy, DOMAIN

IDENTITY = dict(
    pid=303,
    uid=61002,
    process_start_ticks=33,
    boot_id="00000000-0000-4000-8000-000000000001",
    clock_domain=DOMAIN,
)
SOURCE = dict(device=11, inode=22, owner_uid=1000)


def backend(monkeypatch, data=b"actual-signed-test-bytes"):
    state = dict(
        inode=22,
        owner=1000,
        mode=stat.S_IFREG | 0o600,
        nlink=1,
        size=len(data),
        mtime=5,
        ctime=6,
    )
    calls = []

    def fstat(fd):
        assert fd == 7
        calls.append(("fstat", fd))
        return SimpleNamespace(
            st_dev=11,
            st_ino=state["inode"],
            st_uid=state["owner"],
            st_mode=state["mode"],
            st_nlink=state["nlink"],
            st_size=state["size"],
            st_mtime_ns=state["mtime"],
            st_ctime_ns=state["ctime"],
        )

    def pread(fd, size, offset):
        assert fd == 7
        calls.append(("pread", size, offset))
        return data[offset : offset + size]

    def fcntl(fd, command):
        assert fd == 7 and command == c.fcntl.F_GETFL
        calls.append(("F_GETFL", fd))
        return 0

    def forbidden(*a, **k):
        raise AssertionError("target write/close/seek/seal/path")

    monkeypatch.setattr(
        c,
        "os",
        Proxy(
            os,
            fstat=fstat,
            pread=pread,
            close=forbidden,
            write=forbidden,
            chmod=forbidden,
            fchmod=forbidden,
            lseek=forbidden,
            open=forbidden,
        ),
    )
    monkeypatch.setattr(c, "fcntl", Proxy(c.fcntl, fcntl=fcntl))
    monkeypatch.setattr(c, "process_identity", lambda: dict(IDENTITY))
    return state, calls


def test_source_RO_stable_fd_read_has_no_mutation_or_immutability_claim(monkeypatch):
    state, calls = backend(monkeypatch)
    value = c.collect_regular_source_fd(7, expected_identity=SOURCE)
    assert (
        value["raw"] == b"actual-signed-test-bytes"
        and value["receipt"]["complete"] is True
    )
    assert value["receipt"]["source_before"] == value["receipt"]["source_after"]
    assert (
        value["receipt"]["source_before"]["nlink"] == 1
        and value["receipt"]["source_before"]["mtime_ns"] == 5
    )
    assert value["receipt"]["sha256"] == hashlib.sha256(value["raw"]).hexdigest()
    assert ("pread", 1, len(value["raw"])) in calls


@pytest.mark.parametrize(
    "fault", ["inode", "owner", "mode", "writable_fd", "nlink", "size", "type"]
)
def test_bad_initial_source_refuses_unrelated_bytes(monkeypatch, fault):
    state, calls = backend(monkeypatch)
    if fault == "inode":
        state["inode"] = 99
    elif fault == "owner":
        state["owner"] = 99
    elif fault == "mode":
        state["mode"] = stat.S_IFREG | 0o666
    elif fault == "writable_fd":
        monkeypatch.setattr(c, "fcntl", Proxy(c.fcntl, fcntl=lambda *a: os.O_RDWR))
    elif fault == "nlink":
        state["nlink"] = 2
    elif fault == "size":
        state["size"] = c.MAXIMUM + 1
    else:
        state["mode"] = stat.S_IFIFO | 0o600
    value = c.collect_regular_source_fd(7, expected_identity=SOURCE)
    assert (
        value["raw"] == b""
        and value["receipt"]["complete"] is False
        and value["receipt"]["errors"]
    )
    assert not any(call[0] == "pread" for call in calls)


@pytest.mark.parametrize("fault", ["mtime", "ctime", "inode", "size", "partial"])
def test_postread_fault_preserves_bytes_without_complete_result(monkeypatch, fault):
    state, calls = backend(monkeypatch)
    original = c.os.pread

    def changed(fd, size, offset):
        if fault == "partial":
            if offset == 0:
                return b"actual"
            raise OSError("SYNTHETIC interrupted read")
        value = original(fd, size, offset)
        if fault in ("mtime", "ctime", "inode"):
            state[fault] += 1
        else:
            state["size"] += 1
        return value

    monkeypatch.setattr(c, "os", Proxy(c.os, pread=changed))
    value = c.collect_regular_source_fd(7, expected_identity=SOURCE)
    assert value["raw"] and value["receipt"]["complete"] is False
    assert value["receipt"]["sha256"] == hashlib.sha256(value["raw"]).hexdigest()


@pytest.mark.parametrize("fault", ["domain", "reverse", "start_fail", "end_fail"])
def test_bad_clock_evidence_never_emits_complete(monkeypatch, fault):
    state, calls = backend(monkeypatch)
    if fault == "domain":
        import copy

        actor = copy.deepcopy(IDENTITY)
        actor["clock_domain"]["established"] = False
        monkeypatch.setattr(c, "process_identity", lambda: actor)
    else:
        count = [0]

        def clock():
            count[0] += 1
            if (
                fault == "start_fail"
                and count[0] == 1
                or fault == "end_fail"
                and count[0] == 2
            ):
                raise OSError("clock")
            return (20 if count[0] == 1 else 10) if fault == "reverse" else count[0]

        monkeypatch.setattr(c, "time", Proxy(c.time, monotonic_ns=clock))
    value = c.collect_regular_source_fd(7, expected_identity=SOURCE)
    assert (
        value["raw"]
        and value["receipt"]["complete"] is False
        and value["receipt"]["errors"]
    )
    if fault == "start_fail":
        assert value["receipt"]["read_started_ns"] is None
    if fault == "end_fail":
        assert value["receipt"]["read_finished_ns"] is None


@pytest.mark.parametrize(
    "fd,identity,maximum",
    [
        (True, SOURCE, 100),
        (7, dict(SOURCE, path="/unrelated"), 100),
        (7, dict(SOURCE, inode=False), 100),
        (7, SOURCE, False),
        (7, SOURCE, c.MAXIMUM + 1),
    ],
)
def test_invalid_global_inputs_fail_before_IO(monkeypatch, fd, identity, maximum):
    state, calls = backend(monkeypatch)
    with pytest.raises(ValueError):
        c.collect_regular_source_fd(fd, expected_identity=identity, maximum=maximum)
    assert calls == []
