"""Synthetic Root metadata fixtures only; no worker/runtime qualification."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_proof as s
from test_telemetry_isolation_preflight import effective

BOOT = "095d28ff-ca7d-4b08-9e4b-e36a62db4810"
SOURCE = b"SYNTHETIC reserved worker source"
SHA = hashlib.sha256(SOURCE).hexdigest()


def identity():
    return dict(
        pid=123,
        tgid=123,
        uid=61002,
        gid=61002,
        groups=[61002],
        apparmor=s.contract.PROFILE + " (enforce)",
        no_new_privs=True,
        cap_eff=0,
        cap_prm=0,
        cap_amb=0,
        cap_bnd=0,
        dumpable=1,
    )


def frame(mode="initialize"):
    return dict(
        kind=s.contract.READY_KIND,
        role=s.contract.ROLE,
        mode=mode,
        identity=identity(),
        kernel_boot_id=BOOT,
        source=s.contract.SOURCE,
        source_sha256=SHA,
    )


def raw(value):
    return json.dumps(value).encode() + b"\n"


def actual_effective(mode):
    value = effective()
    spec = s.contract.observer_spec(mode)
    value.update(spec["properties"])
    value.pop("RuntimeMaxSec")
    value.pop("TimeoutStopSec")
    value.update(
        RuntimeMaxUSec="40s",
        TimeoutStopUSec="5s",
        FragmentPath="/run/systemd/transient/" + spec["unit"],
        ExecStart="{ path="
        + s.contract.ALIAS
        + " ; argv[]="
        + " ".join(s.reserved_argv(mode))
        + " ; ignore_errors=no }",
    )
    return value


@pytest.mark.parametrize("mode", ["initialize", "live"])
def test_closed_reserved_contract(mode):
    assert s.parse_ready(raw(frame(mode)), mode, kernel_boot_id=BOOT, source_sha256=SHA)
    s.p._validate_effective(
        actual_effective(mode), s.contract.observer_spec(mode), s.reserved_argv(mode)
    )
    assert not hasattr(s, "run") and not hasattr(s, "launch")


@pytest.mark.parametrize(
    "field,value",
    [
        ("mode", "probe"),
        ("role", "old"),
        ("source", "/other"),
        ("source_sha256", "0" * 64),
        ("kernel_boot_id", "other"),
        ("kind", "input_ready"),
    ],
)
def test_untrusted_ready_context_refused(field, value):
    item = frame()
    item[field] = value
    with pytest.raises(AssertionError):
        s.parse_ready(raw(item), "initialize", kernel_boot_id=BOOT, source_sha256=SHA)


def test_duplicate_and_extra_ready_refused():
    for item in (
        raw(frame())[:-2] + b',"mode":"initialize"}\n',
        raw(dict(frame(), extra=True)),
    ):
        with pytest.raises(AssertionError):
            s.parse_ready(item, "initialize", kernel_boot_id=BOOT, source_sha256=SHA)
    with pytest.raises(ValueError):
        s.reserved_argv("../../other")


def mountinfo():
    return "30 1 0:4 / /proc rw - proc proc rw,hidepid=ptraceable\n" + "".join(
        f"{40 + i} 1 0:5 net:[{20 + i}] {path} rw - nsfs nsfs rw\n"
        for i, path in enumerate(s.contract.NSFS_TARGETS)
    )


def test_nsfs_contexts_stay_separate():
    base = "30 1 0:4 / /proc rw - proc proc rw,hidepid=ptraceable\n"
    rows = "".join(
        f"{40 + i} 1 0:5 net:[{20 + i}] {path} rw - nsfs nsfs rw\n"
        for i, path in enumerate(s.contract.NSFS_TARGETS)
    )
    kwargs = dict(own_mount_ns=[5, 10], pid1_mount_ns=[5, 11], proc_device=[0, 4])
    s._proc_view(base + rows, **kwargs)
    with pytest.raises(ValueError):
        s.legacy.validate_proc_view(base + rows, **kwargs)
    handles = {path: [5, 20 + i] for i, path in enumerate(s.contract.NSFS_TARGETS)}
    s._bind_nsfs(base + rows, handles)
    with pytest.raises(AssertionError):
        s._bind_nsfs((base + rows).replace("net:[20]", "net:[99]"), handles)


def fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("EDGE_SIGNED_NETWORK_TELEMETRY", "1")
    monkeypatch.setattr(s.p.old.g, "guard", lambda: None)
    monkeypatch.setattr(s.p, "_output", lambda output: None)
    monkeypatch.setattr(s.p.old.g, "boot", lambda: BOOT)
    monkeypatch.setattr(s.p, "read_regular", lambda *a, **k: (SOURCE, None))
    monkeypatch.setattr(
        s.p, "stdio_identity", lambda proc: {i: [16, 100 + i] for i in range(3)}
    )
    handles = {path: [5, 20 + i] for i, path in enumerate(s.contract.NSFS_TARGETS)}
    monkeypatch.setattr(s, "_namespaces", lambda: deepcopy(handles))
    monkeypatch.setattr(s, "_receive_ready", lambda proc, path: raw(frame()))
    monkeypatch.setattr(
        s.p, "_collect_effective", lambda *a: actual_effective("initialize")
    )
    monkeypatch.setattr(
        s.p,
        "_collect_actor",
        lambda *a, **k: dict(
            identity=identity(), evidence=dict(raw=dict(mountinfo=mountinfo()))
        ),
    )
    return SimpleNamespace(stdin=SimpleNamespace(closed=False), poll=lambda: None)


def test_composed_metadata_never_releases_fence(tmp_path, monkeypatch):
    process = fixture(tmp_path, monkeypatch)
    result = s.collect_pre_api(
        "initialize",
        process,
        expected_namespace=[5, 20],
        kernel_boot_id=BOOT,
        source_sha256=SHA,
        output=tmp_path,
    )
    assert result["metadata"]["scope"] == "root_pre_api_metadata_only"
    assert not process.stdin.closed
    assert (tmp_path / "initialize-pre-api-root-proof.json").exists()


@pytest.mark.parametrize(
    "fault", ["boot", "source", "edge", "identity", "exited", "optin"]
)
def test_composed_binding_failure_is_sticky_and_retained(tmp_path, monkeypatch, fault):
    process = fixture(tmp_path, monkeypatch)
    if fault == "boot":
        monkeypatch.setattr(s.p.old.g, "boot", lambda: "different")
    if fault == "source":
        monkeypatch.setattr(s.p, "read_regular", lambda *a, **k: (b"other", None))
    if fault == "identity":
        monkeypatch.setattr(
            s.p, "_collect_actor", lambda *a, **k: dict(identity={}, evidence={})
        )
    if fault == "exited":
        process.poll = lambda: 0
    if fault == "optin":
        monkeypatch.delenv("EDGE_SIGNED_NETWORK_TELEMETRY")
    with pytest.raises(AssertionError):
        s.collect_pre_api(
            "initialize",
            process,
            expected_namespace=[5, 99 if fault == "edge" else 20],
            kernel_boot_id=BOOT,
            source_sha256=SHA,
            output=tmp_path,
        )
    if fault != "optin":
        assert (tmp_path / "initialize-pre-api-root-proof.json").exists()


def test_literal_namespace_stat_is_nofollow(monkeypatch):
    calls = []

    def metadata(path, **kwargs):
        calls.append((path, kwargs))
        return SimpleNamespace(st_dev=5, st_ino=20, st_mode=stat.S_IFREG)

    monkeypatch.setattr(s.os, "stat", metadata)
    assert len(s._namespaces()) == 3
    assert calls == [
        (path, dict(follow_symlinks=False)) for path in s.contract.NSFS_TARGETS
    ]


@pytest.mark.parametrize("fault", [None, "extrafd", "binfmtdrift", "nsdrift"])
def test_fixed_signed_actor_uses_shared_actual_metadata_checks(
    tmp_path, monkeypatch, fault
):
    from test_telemetry_isolation_preflight import actor_fixture

    args, texts = actor_fixture(tmp_path, monkeypatch, fault)
    oldunit = s.legacy.ROLES["probe"][0]
    unit = s.contract.INITIALIZER_UNIT
    snapshot = s.p.lab.unit_snapshot

    def mapped_snapshot(actual_unit):
        assert actual_unit == unit
        value = snapshot(actual_unit)
        value["ControlGroup"] = value["ControlGroup"].replace(oldunit, unit)
        return value

    monkeypatch.setattr(s.p.lab, "unit_snapshot", mapped_snapshot)
    texts["/proc/123/cgroup"] = texts["/proc/123/cgroup"].replace(oldunit, unit)
    args.pop("mode")

    def call():
        return s.p._collect_actor(
            unit, "initialize", proc_validator=s._proc_view, **args
        )

    if fault:
        with pytest.raises((ValueError, AssertionError)):
            call()
    else:
        assert call()["identity"] == identity()
    assert (tmp_path / "initialize-actor-proof.json").exists()


@pytest.mark.parametrize("payload", [b"x" * 16385, b'{"incomplete":'])
def test_original_consumed_ready_failure_prefix_retained(tmp_path, payload):
    import os
    import threading

    readfd, writefd = os.pipe()

    def writer():
        try:
            os.write(writefd, payload)
        finally:
            os.close(writefd)

    thread = threading.Thread(target=writer)
    with os.fdopen(readfd, "rb", buffering=0) as stdout:
        thread.start()
        process = SimpleNamespace(stdout=stdout, stdin=SimpleNamespace(closed=False))
        try:
            with pytest.raises(AssertionError):
                s._receive_ready(process, tmp_path / "ready.raw")
            assert (tmp_path / "ready.raw").read_bytes() == payload
            assert not process.stdin.closed
        finally:
            thread.join(timeout=2)
            assert not thread.is_alive()


def test_root_guard_refuses_before_any_query_or_artifact(tmp_path, monkeypatch):
    def refuse():
        raise AssertionError("unmarked host")

    monkeypatch.setattr(s.p.old.g, "guard", refuse)
    with pytest.raises(AssertionError, match="unmarked"):
        s.collect_pre_api(
            "initialize",
            None,
            expected_namespace=[5, 20],
            kernel_boot_id=BOOT,
            source_sha256=SHA,
            output=tmp_path,
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("fault", ["empty", "missing", "device", "inode"])
def test_namespace_object_requires_full_actor_nsfs_binding(fault):
    handles = {path: [5, 20 + i] for i, path in enumerate(s.contract.NSFS_TARGETS)}
    text = mountinfo()
    if fault == "empty":
        text = ""
    if fault == "missing":
        text = "\n".join(text.splitlines()[:-1]) + "\n"
    if fault == "device":
        text = text.replace("0:5", "0:6", 1)
    if fault == "inode":
        text = text.replace("net:[20]", "net:[99]", 1)
    with pytest.raises(AssertionError):
        s._bind_nsfs(text, handles)


def test_identical_repeated_systemd_nsfs_rows_are_allowed():
    handles = {path: [5, 20 + i] for i, path in enumerate(s.contract.NSFS_TARGETS)}
    text = mountinfo()
    duplicate = text.splitlines()[1].split()
    duplicate[0] = "90"
    s._bind_nsfs(text + " ".join(duplicate) + "\n", handles)
    duplicate[2] = "0:6"
    with pytest.raises(AssertionError):
        s._bind_nsfs(text + " ".join(duplicate) + "\n", handles)


@pytest.mark.parametrize("mode", [stat.S_IFDIR, stat.S_IFLNK])
def test_named_namespace_directory_or_alias_refused(monkeypatch, mode):
    monkeypatch.setattr(
        s.os, "stat", lambda *a, **k: SimpleNamespace(st_dev=5, st_ino=20, st_mode=mode)
    )
    with pytest.raises(AssertionError):
        s._namespaces()


def test_actual_ordinary_file_metadata_cannot_supply_namespace_proof(
    tmp_path, monkeypatch
):
    ordinary = tmp_path / "ordinary"
    ordinary.write_bytes(b"not a namespace")
    info = ordinary.stat()
    monkeypatch.setattr(s.os, "stat", lambda *a, **k: info)
    handles = s._namespaces()
    assert set(handles) == set(s.contract.NSFS_TARGETS)
    with pytest.raises(AssertionError, match="all three"):
        s._bind_nsfs("30 1 0:4 / /proc rw - proc proc rw,hidepid=ptraceable\n", handles)


def test_composed_empty_actor_mounts_cannot_pass(tmp_path, monkeypatch):
    process = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        s.p,
        "_collect_actor",
        lambda *a, **k: dict(
            identity=identity(), evidence=dict(raw=dict(mountinfo=""))
        ),
    )
    with pytest.raises(AssertionError, match="all three"):
        s.collect_pre_api(
            "initialize",
            process,
            expected_namespace=[5, 20],
            kernel_boot_id=BOOT,
            source_sha256=SHA,
            output=tmp_path,
        )
    assert (tmp_path / "initialize-pre-api-root-proof.json").exists()
