"""Synthetic scope/cleanup fault controls; no live namespace or systemd calls."""

import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark.benefit import BenefitInputError

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_scope as s


def fixture(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    handles = {}
    identities = {}
    for i, name in enumerate(s.names().values(), 1):
        path = tmp_path / name
        path.write_text("namespace fixture")
        info = path.stat()
        identity = dict(device=info.st_dev, inode=info.st_ino)
        handles[name] = path
        identities[name] = identity
        s.n.write_new(
            work / f"namespace-intent-{i}.json",
            dict(name=name, state="creation_intent"),
        )
        s.n.write_new(
            work / f"namespace-confirmed-{i}.json",
            dict(name=name, state="confirmed_created", identity=identity),
        )
    proof = dict(
        kernel_boot_id="new-boot",
        names=s.names(),
        root_before={"routes": "unchanged"},
        foreign="foreign-1234abcd",
    )
    s.n.write_new(work / "namespace-boot.json", proof)
    monkeypatch.setattr(s.g, "boot", lambda: "new-boot")
    monkeypatch.setattr(s.n, "root_snapshot", lambda: {"routes": "unchanged"})
    monkeypatch.setattr(
        s, "_open_namespace", lambda name: os.open(handles[name], os.O_RDONLY)
    )
    monkeypatch.setattr(
        s,
        "_named_identity",
        lambda name: (handles[name].stat().st_dev, handles[name].stat().st_ino),
    )
    return work, proof, handles


def close_fds(assets):
    for fd, _, _ in assets.created.values():
        os.close(fd)


def test_reopens_only_all_confirmed_current_boot_scope(tmp_path, monkeypatch):
    work, proof, _ = fixture(tmp_path, monkeypatch)
    assets, actual = s.reopen_assets(work)
    try:
        assert actual == proof and assets.foreign == proof["foreign"]
        assert set(assets.created) == set(s.names().values())
        assert isinstance(assets, s.FencedAssets)
    finally:
        close_fds(assets)


@pytest.mark.parametrize(
    "fault",
    [
        "boot",
        "intent",
        "missing",
        "duplicate",
        "identity",
        "unknown",
        "parent",
        "mode",
        "symlink",
    ],
)
def test_refuses_scope_conflict_before_namespace_use_or_cleanup(
    tmp_path, monkeypatch, fault
):
    work, proof, handles = fixture(tmp_path, monkeypatch)
    path = work / "namespace-confirmed-1.json"
    record = json.loads(path.read_text())
    if fault == "boot":
        proof["kernel_boot_id"] = "old"
        (work / "namespace-boot.json").write_text(json.dumps(proof))
    elif fault == "intent":
        (work / "namespace-intent-1.json").write_text(
            json.dumps(dict(name="other", state="creation_intent"))
        )
    elif fault == "missing":
        path.unlink()
    elif fault == "duplicate":
        other = json.loads((work / "namespace-confirmed-2.json").read_text())
        other["name"] = record["name"]
        (work / "namespace-confirmed-2.json").write_text(json.dumps(other))
    elif fault == "identity":
        record["identity"]["inode"] += 1
        path.write_text(json.dumps(record))
    elif fault == "unknown":
        record["extra"] = "unknown"
        path.write_text(json.dumps(record))
    elif fault == "parent":
        monkeypatch.setattr(s.n, "root_snapshot", lambda: {"routes": "changed"})
    elif fault == "mode":
        work.chmod(0o755)
    else:
        saved = tmp_path / "saved"
        path.rename(saved)
        path.symlink_to(saved)
    calls = []
    monkeypatch.setattr(
        s.n,
        "command",
        lambda *a, **k: (calls.append(a) or SimpleNamespace(returncode=0)),
    )
    with pytest.raises((BenefitInputError, OSError, ValueError)):
        s.reopen_assets(work)
    assert calls == [] and all(p.exists() for p in handles.values())


def test_replaced_named_handle_refuses_before_each_operation(tmp_path, monkeypatch):
    work, _, handles = fixture(tmp_path, monkeypatch)
    assets, _ = s.reopen_assets(work)
    calls = []
    monkeypatch.setattr(
        s.n,
        "command",
        lambda *a, **k: (calls.append(a) or SimpleNamespace(returncode=0)),
    )
    try:
        name = s.names()["edge"]
        path = handles[name]
        replacement = tmp_path / "replacement"
        replacement.write_text("different")
        os.replace(replacement, path)
        with pytest.raises(BenefitInputError, match="identity drift"):
            assets.ns("edge", "nft", "--version")
        with pytest.raises(BenefitInputError, match="identity drift"):
            assets.spawn("edge", ["program"])
        assert calls == []
    finally:
        close_fds(assets)


def state(group=""):
    return dict(
        LoadState="loaded",
        ActiveState="inactive",
        MainPID="0",
        ControlPID="0",
        ControlGroup=group,
    )


def test_stops_all_fixed_actors_before_allowing_namespace_cleanup(monkeypatch):
    monkeypatch.setattr(s.g, "guard", lambda: None)
    calls = []
    monkeypatch.setattr(s, "_state", lambda unit: state("/system.slice/" + unit))
    monkeypatch.setattr(s, "_group_empty", lambda group: True)
    monkeypatch.setattr(
        s.n,
        "command",
        lambda *a, **k: (calls.append((a, k)) or SimpleNamespace(returncode=0)),
    )
    receipt = s.stop_systemd_actors()
    assert receipt["status"] == "verified_stopped"
    assert [a[2] for a, _ in calls] == list(s.ACTOR_UNITS)
    assert all(k["timeout"] == 3 for _, k in calls)


@pytest.mark.parametrize(
    "fault", ["stop", "before", "live_pid", "child_cgroup", "verify"]
)
def test_actor_step_failure_still_attempts_every_unit_and_withholds(monkeypatch, fault):
    monkeypatch.setattr(s.g, "guard", lambda: None)
    target = s.ACTOR_UNITS[0]
    calls = []
    seen = {}

    def read(unit):
        seen[unit] = seen.get(unit, 0) + 1
        if unit == target:
            if fault == "before" and seen[unit] == 1:
                raise OSError()
            if fault == "verify" and seen[unit] == 2:
                raise OSError()
            if fault == "live_pid" and seen[unit] == 2:
                return dict(state(), MainPID="321")
        return state("/system.slice/" + unit)

    def command(*argv, **kwargs):
        calls.append(argv)
        if fault == "stop" and argv == ("systemctl", "stop", target):
            raise subprocess.TimeoutExpired(argv, 3)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(s, "_state", read)
    monkeypatch.setattr(s.n, "command", command)
    monkeypatch.setattr(
        s,
        "_group_empty",
        lambda group: not (fault == "child_cgroup" and group.endswith(target)),
    )
    receipt = s.stop_systemd_actors()
    assert receipt["status"] == "failed" and receipt["failures"]
    assert all(("systemctl", "stop", unit) in calls for unit in s.ACTOR_UNITS)
    if fault == "stop":
        assert (
            "systemctl",
            "kill",
            "--kill-whom=all",
            "--signal=KILL",
            target,
        ) in calls


def test_live_descendant_cgroup_not_hidden_by_empty_parent_procs(tmp_path, monkeypatch):
    path = tmp_path / ("system.slice/" + s.ACTOR_UNITS[0])
    path.mkdir(parents=True)
    (path / "cgroup.procs").write_text("")
    (path / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    monkeypatch.setattr(
        s, "_cgroup_view", lambda: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    )
    assert s._group_empty("/system.slice/" + s.ACTOR_UNITS[0]) is False
    (path / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    assert s._group_empty("/system.slice/" + s.ACTOR_UNITS[0]) is True
    (path / "cgroup.events").write_text("populated 0\npopulated 1\n")
    with pytest.raises(BenefitInputError):
        s._group_empty("/system.slice/" + s.ACTOR_UNITS[0])


def test_cleanup_never_deletes_namespaces_on_systemd_gap(tmp_path, monkeypatch):
    calls = []
    assets = SimpleNamespace(
        work=tmp_path, close=lambda: calls.append("namespace-cleanup")
    )
    monkeypatch.setattr(
        s, "stop_systemd_actors", lambda: dict(status="failed", failures=["actor"])
    )
    with pytest.raises(BenefitInputError, match="actor gap"):
        s.close_namespaces_after_actors(assets, dict(root_before={}))
    assert calls == []
    assert (
        json.loads((tmp_path / "systemd-stop-receipt.json").read_text())["status"]
        == "failed"
    )


def test_bad_show_shape_refuses(monkeypatch):
    monkeypatch.setattr(
        s.n,
        "command",
        lambda *a, **k: SimpleNamespace(stdout="LoadState=loaded\nLoadState=loaded\n"),
    )
    with pytest.raises(BenefitInputError):
        s._state(s.ACTOR_UNITS[0])


def mount_line(
    *, filesystem="cgroup2", root="/", target="/sys/fs/cgroup", device="0:28"
):
    return f"38 27 {device} {root} {target} rw,nosuid,nodev,noexec,relatime - {filesystem} cgroup rw\n"


@pytest.mark.parametrize(
    "fault", ["absent", "v1", "hybrid", "subtree", "nested", "alias", "duplicate"]
)
def test_unknown_or_partial_cgroup_mount_hierarchy_refuses(fault):
    raw = mount_line()
    if fault == "absent":
        raw = "27 1 0:20 / /sys rw - sysfs sysfs rw\n"
    elif fault == "v1":
        raw = mount_line(filesystem="cgroup")
    elif fault == "hybrid":
        raw += mount_line(filesystem="cgroup", target="/legacy")
    elif fault == "subtree":
        raw = mount_line(root="/system.slice/hidden")
    elif fault == "nested":
        raw += mount_line(filesystem="tmpfs", target="/sys/fs/cgroup/system.slice")
    elif fault == "alias":
        raw = mount_line(target="/different")
    else:
        raw += mount_line()
    with pytest.raises(BenefitInputError):
        s._unified_mount(raw)


def view_fixture(tmp_path, monkeypatch):
    actual = tmp_path.stat()
    device = f"{os.major(actual.st_dev)}:{os.minor(actual.st_dev)}"
    mount = mount_line(device=device)
    monkeypatch.setattr(s, "_kernel_text", lambda path, maximum=1024 * 1024: mount)
    monkeypatch.setattr(
        s,
        "_physical_cgroup_root",
        lambda: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    real_stat = os.stat

    def stat(path, *args, **kwargs):
        if str(path) in ("/proc/self/ns/cgroup", "/proc/1/ns/cgroup"):
            return SimpleNamespace(st_dev=4, st_ino=123)
        if str(path) == "/proc/1/root/sys/fs/cgroup":
            return actual
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(s.os, "stat", stat)
    return mount, stat


def test_verified_complete_unified_view_allows_genuinely_absent_group(
    tmp_path, monkeypatch
):
    view_fixture(tmp_path, monkeypatch)
    assert s._group_empty("/system.slice/" + s.ACTOR_UNITS[0]) is True
    assert s._group_empty("") is True


@pytest.mark.parametrize(
    "fault",
    ["namespace", "manager_mount", "manager_root", "device", "subtree", "absent_mount"],
)
def test_group_absence_is_not_empty_under_unknown_view(tmp_path, monkeypatch, fault):
    mount, stat = view_fixture(tmp_path, monkeypatch)
    if fault == "namespace":
        monkeypatch.setattr(
            s.os,
            "stat",
            lambda path, *a, **k: SimpleNamespace(st_dev=4, st_ino=456)
            if str(path) == "/proc/1/ns/cgroup"
            else stat(path, *a, **k),
        )
    elif fault == "manager_root":
        monkeypatch.setattr(
            s.os,
            "stat",
            lambda path, *a, **k: SimpleNamespace(st_dev=4, st_ino=456)
            if str(path) == "/proc/1/root/sys/fs/cgroup"
            else stat(path, *a, **k),
        )
    elif fault == "manager_mount":
        monkeypatch.setattr(
            s,
            "_kernel_text",
            lambda path, maximum=1024 * 1024: mount_line(device="0:999")
            if path == "/proc/1/mountinfo"
            else mount,
        )
    elif fault == "device":
        monkeypatch.setattr(
            s,
            "_kernel_text",
            lambda path, maximum=1024 * 1024: mount_line(device="0:999"),
        )
    elif fault == "subtree":
        monkeypatch.setattr(
            s,
            "_kernel_text",
            lambda path, maximum=1024 * 1024: mount_line(root="/partial"),
        )
    else:
        monkeypatch.setattr(s, "_kernel_text", lambda path, maximum=1024 * 1024: "")
    for group in ("", "/system.slice/" + s.ACTOR_UNITS[0]):
        with pytest.raises(BenefitInputError):
            s._group_empty(group)


@pytest.mark.parametrize(
    "raw",
    [
        "1:name=systemd:/system.slice/unit.service\n",
        "0::/other.service\n",
        "0::/system.slice/unit.service\n0::/\n",
    ],
)
def test_live_unit_pid_membership_must_equal_manager_controlgroup(monkeypatch, raw):
    monkeypatch.setattr(s, "_kernel_text", lambda path, maximum: raw)
    with pytest.raises(BenefitInputError):
        s._membership("123", "/system.slice/unit.service")


def test_correct_live_unit_pid_unified_membership(monkeypatch):
    monkeypatch.setattr(
        s, "_kernel_text", lambda path, maximum: "0::/system.slice/unit.service\n"
    )
    s._membership("123", "/system.slice/unit.service")


def test_unknown_cgroup_view_still_stops_every_actor_and_forbids_cleanup(monkeypatch):
    monkeypatch.setattr(s.g, "guard", lambda: None)
    monkeypatch.setattr(s, "_state", lambda unit: state(""))

    def refuse_view():
        raise BenefitInputError("unknown layout")

    monkeypatch.setattr(s, "_cgroup_view", refuse_view)
    calls = []
    monkeypatch.setattr(
        s.n,
        "command",
        lambda *a, **k: (calls.append(a) or SimpleNamespace(returncode=0)),
    )
    receipt = s.stop_systemd_actors()
    assert receipt["status"] == "failed"
    assert [a for a in calls] == [("systemctl", "stop", unit) for unit in s.ACTOR_UNITS]
    assert len(receipt["failures"]) == len(s.ACTOR_UNITS)


def test_kernel_mount_evidence_reads_to_eof_in_bounded_chunks(tmp_path, monkeypatch):
    path = tmp_path / "mountinfo"
    path.write_bytes(b"abcdef")
    real_read = os.read
    monkeypatch.setattr(s.os, "read", lambda fd, count: real_read(fd, min(count, 2)))
    assert s._kernel_text(path, 6) == "abcdef"
    with pytest.raises(BenefitInputError, match="exceeds bound"):
        s._kernel_text(path, 5)


def test_fixed_initializer_and_observer_are_both_in_stop_and_cgroup_whitelist():
    assert s.INITIALIZER_UNIT in s.ACTOR_UNITS and s.OBSERVER_UNIT in s.ACTOR_UNITS
    assert len(s.ACTOR_UNITS) == 5


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "pre_read",
        "post_read",
        "pre_loaded",
        "post_loaded",
        "unknown_view",
        "canonical_populated",
        "timeout",
    ],
)
def test_collected_nonzero_stop_only_with_independent_full_before_after_absence(
    monkeypatch, fault
):
    monkeypatch.setattr(s.g, "guard", lambda: None)
    unit = s.OBSERVER_UNIT
    calls = []
    reads = {}
    groups = []
    absent = dict(
        LoadState="not-found",
        ActiveState="inactive",
        MainPID="0",
        ControlPID="0",
        ControlGroup="",
    )

    def read(name):
        reads[name] = reads.get(name, 0) + 1
        if name == unit:
            if fault == "pre_read" and reads[name] == 1:
                raise OSError()
            if fault == "post_read" and reads[name] == 2:
                raise OSError()
            if (fault == "pre_loaded" and reads[name] == 1) or (
                fault == "post_loaded" and reads[name] == 2
            ):
                return state()
        return dict(absent)

    def command(*argv, **kwargs):
        calls.append(argv)
        if fault == "timeout" and argv == ("systemctl", "stop", unit):
            raise subprocess.TimeoutExpired(argv, 3)
        return SimpleNamespace(
            returncode=5 if argv == ("systemctl", "stop", unit) else 0
        )

    def empty(group):
        groups.append(group)
        if fault == "unknown_view":
            raise BenefitInputError("unknown view")
        return not (fault == "canonical_populated" and group == "/system.slice/" + unit)

    monkeypatch.setattr(s, "_state", read)
    monkeypatch.setattr(s.n, "command", command)
    monkeypatch.setattr(s, "_group_empty", empty)
    result = s.stop_systemd_actors()
    assert result["status"] == ("verified_stopped" if fault is None else "failed")
    assert all(("systemctl", "stop", name) in calls for name in s.ACTOR_UNITS)
    if fault is None:
        assert "/system.slice/" + unit in groups
