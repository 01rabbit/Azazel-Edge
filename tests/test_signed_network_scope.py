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
    monkeypatch.setattr(s.n, "command", lambda *a, **k: calls.append(a))
    with pytest.raises((BenefitInputError, OSError, ValueError)):
        s.reopen_assets(work)
    assert calls == [] and all(p.exists() for p in handles.values())


def test_replaced_named_handle_refuses_before_each_operation(tmp_path, monkeypatch):
    work, _, handles = fixture(tmp_path, monkeypatch)
    assets, _ = s.reopen_assets(work)
    calls = []
    monkeypatch.setattr(s.n, "command", lambda *a, **k: calls.append(a))
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
    monkeypatch.setattr(s.n, "command", lambda *a, **k: calls.append((a, k)))
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
    path = tmp_path / "system.slice/unit.service"
    path.mkdir(parents=True)
    (path / "cgroup.procs").write_text("")
    (path / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    monkeypatch.setattr(s, "Path", lambda _: tmp_path)
    assert s._group_empty("/system.slice/unit.service") is False
    (path / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    assert s._group_empty("/system.slice/unit.service") is True
    (path / "cgroup.events").write_text("populated 0\npopulated 1\n")
    with pytest.raises(BenefitInputError):
        s._group_empty("/system.slice/unit.service")


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
