"""Synthetic Root staging/metadata fixtures; no actual policy/tool/VM execution."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import telemetry_isolation_setup as s

OLD = (
    "\n".join(
        name + " (enforce)"
        for name in (
            "edge400-capture",
            "edge400-witness",
            "edge400-observer",
            "edge400-native",
        )
    )
    + "\n"
)


def test_new_optin_failure_precedes_any_output_or_baseline_mutation(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(s.G, "guard", lambda: None)
    monkeypatch.delenv(s.FLAG, raising=False)
    monkeypatch.setattr(
        s, "old_assets", lambda: pytest.fail("baseline reached before explicit opt-in")
    )
    with pytest.raises(AssertionError, match="explicit NEW"):
        s.stage(tmp_path / "unused")
    assert list(tmp_path.iterdir()) == []


def test_external_old_alias_mismatch_refuses_without_repair(monkeypatch):
    def read(path, limit=0, mode=None):
        content = (
            b"old policy"
            if str(path).endswith(("edge400.apparmor", "edge400-lab"))
            else b"python"
        )
        if Path(path).name == "edge-observe":
            content = b"foreign interpreter"
        return content, dict(sha256=hashlib.sha256(content).hexdigest())

    monkeypatch.setattr(s, "_read", read)
    monkeypatch.setattr(s.G, "PYTHON", Path(sys.executable))
    with pytest.raises(AssertionError, match="external old alias"):
        s.old_assets()


def stage_fixture(tmp_path, monkeypatch, fault=None):
    output = tmp_path / "out"
    baseline = dict(
        pins=dict(ABI_SHA256="a" * 64),
        old_assets={"old": "unchanged"},
        loaded_before=OLD,
    )
    calls = []
    installed = {}
    monkeypatch.setattr(s, "guard", lambda path: dict(baseline))
    monkeypatch.setattr(s.p.old, "private_output", lambda path: path.mkdir(mode=0o700))
    monkeypatch.setattr(s.network, "root_snapshot", lambda: {"routes": "original"})
    monkeypatch.setattr(
        s.p, "collect_features", lambda *a, **k: calls.append("features")
    )
    monkeypatch.setattr(s.G, "PYTHON", Path(sys.executable))

    def read(path, limit=0, mode=None):
        path = Path(path)
        data = installed.get(
            str(path),
            b"public candidate profile"
            if path == s.SOURCE_POLICY
            else b"public interpreter",
        )
        if path.name.endswith(".stderr"):
            data = (
                b"warning"
                if fault == "compilewarning"
                and path.name == "candidate-compile.stderr"
                or fault == "loadwarning"
                and path.name == "candidate-load.stderr"
                else b""
            )
        return data, dict(
            sha256=hashlib.sha256(data).hexdigest(), device=1, inode=2, mode=0o100644
        )

    monkeypatch.setattr(s, "_read", read)

    def query(argv, prefix, out):
        assert (out / "root-before.json").exists() and (out / "baseline.json").exists()
        assert (
            argv[0] == "apparmor_parser"
            and "--warn=all" in argv
            and "--Werror" in argv
            and "--skip-cache" in argv
        )
        calls.append(prefix)
        return 0, b"public compiled bytes"

    monkeypatch.setattr(s.p.old, "_retained_query", query)

    def write(path, data, mode, *, on_create=None):
        assert (output / "root-before.json").exists() and (
            output / "install-intent.json"
        ).exists()
        assert str(path) not in installed
        calls.append("new:" + str(path))
        installed[str(path)] = data
        info = SimpleNamespace(
            st_dev=1,
            st_ino=100 + len(installed),
            st_uid=0,
            st_mode=stat.S_IFREG | mode,
            st_nlink=1,
            st_size=len(data),
        )
        if on_create:
            on_create("created", info)
            on_create("complete", info)

    monkeypatch.setattr(s, "_new_file", write)

    def mkdir(path, *, on_create=None):
        calls.append("mkdir:" + str(path))
        info = SimpleNamespace(
            st_dev=1,
            st_ino=200 + len(calls),
            st_uid=0,
            st_mode=stat.S_IFDIR | 0o755,
            st_nlink=2,
            st_size=0,
        )
        if on_create:
            on_create("created", info)
            on_create("complete", info)

    monkeypatch.setattr(s, "_mkdir", mkdir)

    def kernel(path, limit):
        return OLD + s.C.PROFILE + " (enforce)\n" if path == s.PROFILES else "1\n"

    monkeypatch.setattr(s.p.cg, "_kernel_text", kernel)
    monkeypatch.setattr(
        s, "invariants", lambda *a, **k: calls.append("independent_invariants")
    )

    def inventory(baseline):
        values = {}
        for path, spec in baseline["intended_assets"].items():
            confirmation = baseline["asset_confirmations"][path]
            facts = dict(confirmation["complete"])
            facts["uid"] = 0
            values[path] = dict(
                state="present", metadata=facts, confirmation=confirmation
            )
            if spec["kind"] == "file":
                values[path]["sha256"] = spec["sha256"]
        return values

    monkeypatch.setattr(s, "inventory_assets", inventory)
    return output, calls, installed


def test_staging_order_keeps_snapshot_upfront_and_old_baseline_external(
    tmp_path, monkeypatch
):
    output, calls, installed = stage_fixture(tmp_path, monkeypatch)
    result = s.stage(output)
    assert calls[0:2] == ["features", "candidate-compile"]
    assert calls.index("candidate-load") > calls.index("new:" + str(s.NEW_POLICY))
    assert str(s.OLD_POLICY) not in installed
    assert str(s.G.PYTHON.with_name("edge-observe")) not in installed
    assert str(s.G.PYTHON.with_name("edge-capture")) not in installed
    assert all(
        "PUBLIC-NONKEY" in installed[row["path"]].decode() for row in s.p.canary_spec()
    )
    assert result["root_before"] == json.loads(
        (output / "root-before.json").read_bytes()
    )
    assert "qualification" not in result and (output / "staged.json").exists()


@pytest.mark.parametrize("fault", ["compilewarning", "loadwarning"])
def test_compile_or_load_warning_retains_evidence_and_runs_independent_invariants(
    tmp_path, monkeypatch, fault
):
    output, calls, installed = stage_fixture(tmp_path, monkeypatch, fault)
    with pytest.raises(AssertionError, match="failed/warned"):
        s.stage(output)
    assert (
        calls[-1] == "independent_invariants" and (output / "root-before.json").exists()
    )
    if fault == "compilewarning":
        assert not installed and "candidate-load" not in calls
    else:
        assert installed and (output / "install-intent.json").exists()


def test_all_invariant_checks_continue_even_after_parent_save_or_comparison_failure(
    tmp_path, monkeypatch
):
    visited = []
    monkeypatch.setattr(
        s.network,
        "root_snapshot",
        lambda: visited.append("parent") or {"changed": True},
    )
    monkeypatch.setattr(
        s, "old_assets", lambda: visited.append("old") or {"old": "same"}
    )
    monkeypatch.setattr(
        s.p.cg, "_kernel_text", lambda *a: visited.append("profiles") or OLD
    )
    save = s.LAB.save_json

    def saving(path, value):
        if path.name == "parent-after.json":
            raise OSError("synthetic disk failure")
        save(path, value)

    monkeypatch.setattr(s.LAB, "save_json", saving)
    with pytest.raises(AssertionError, match="Root invariants failed"):
        s.invariants(
            tmp_path,
            dict(
                root_before={"original": True},
                old_assets={"old": "same"},
                loaded_before=OLD,
            ),
        )
    assert visited == ["parent", "old", "profiles"]
    assert (tmp_path / "old_assets-after.json").exists() and (
        tmp_path / "loaded_profiles-after.json"
    ).exists()


def virtual_root_files(monkeypatch, tmp_path, race=False):
    def parent(path, trusted_owner):
        return os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY), Path(path).name

    monkeypatch.setattr(s, "open_parent", parent)
    real = os.stat
    count = {}

    def info(value):
        return SimpleNamespace(
            st_dev=value.st_dev,
            st_ino=value.st_ino,
            st_uid=0,
            st_mode=value.st_mode,
            st_nlink=value.st_nlink,
            st_size=value.st_size,
        )

    def named(path, **kwargs):
        value = info(real(path, **kwargs))
        count[path] = count.get(path, 0) + 1
        if race and count[path] > 1:
            value.st_ino += 1
        return value

    original = os
    proxy = SimpleNamespace(
        **{
            name: getattr(original, name)
            for name in dir(original)
            if not name.startswith("__")
        }
    )
    proxy.stat = named
    proxy.fstat = lambda fd: info(original.fstat(fd))
    monkeypatch.setattr(s, "os", proxy)


def test_exclusive_new_file_uses_exact_fd_mode_and_never_overwrites_existing(
    tmp_path, monkeypatch
):
    virtual_root_files(monkeypatch, tmp_path)
    path = tmp_path / "public"
    s._new_file(path, b"PUBLIC-NONKEY", 0o755)
    assert (
        path.read_bytes() == b"PUBLIC-NONKEY"
        and stat.S_IMODE(path.stat().st_mode) == 0o755
    )
    with pytest.raises(FileExistsError):
        s._new_file(path, b"other", 0o644)
    assert path.read_bytes() == b"PUBLIC-NONKEY"


def test_existing_symlink_refuses_without_changing_foreign_file(tmp_path, monkeypatch):
    virtual_root_files(monkeypatch, tmp_path)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"unchanged")
    (tmp_path / "target").symlink_to(foreign)
    with pytest.raises(FileExistsError):
        s._new_file(tmp_path / "target", b"bad", 0o755)
    assert foreign.read_bytes() == b"unchanged"


@pytest.mark.parametrize("race", [False, True])
def test_new_directory_fd_normalization_checks_named_identity(
    tmp_path, monkeypatch, race
):
    virtual_root_files(monkeypatch, tmp_path, race)
    path = tmp_path / "new"
    if race:
        with pytest.raises(AssertionError, match="replaced"):
            s._mkdir(path)
    else:
        s._mkdir(path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o755
    with pytest.raises(FileExistsError):
        s._mkdir(path)


@pytest.mark.parametrize("kind", ["directory", "file", "dangling"])
def test_deep_systemd_prefix_refuses_lexists_without_mutation(tmp_path, kind):
    path = tmp_path / "edge400-telemetry-isolation-.service.d"
    if kind == "directory":
        path.mkdir()
    elif kind == "file":
        path.write_bytes(b"foreign")
    else:
        path.symlink_to(tmp_path / "missing")
    with pytest.raises(AssertionError, match="deep candidate prefix"):
        s.reject_unit_material([str(tmp_path)])
    assert os.path.lexists(path) and len(list(tmp_path.iterdir())) == 1


def real_inventory_stage(tmp_path, monkeypatch, fault):
    """Real exclusive FD writes/inventory/invariants, virtual Root UID metadata.

    Every path is a private test temporary. Kernel/Root guard/parser observations
    remain synthetic; no AppArmor installation/loading command is executed.
    """
    from azazel_edge.outcome.input_auth import (
        open_parent as parent_reader,
        read_regular as regular_reader,
    )

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    python = runtime / "python"
    python.write_bytes(b"PUBLIC INTERPRETER IMAGE")
    python.chmod(0o755)
    aa = tmp_path / "aa"
    aa.mkdir()
    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"PUBLIC CANDIDATE PROFILE")
    base = tmp_path / "lab"
    monkeypatch.setattr(s.G, "BASE", base)
    monkeypatch.setattr(s.G, "BUNDLE", base / "bundle")
    monkeypatch.setattr(s.G, "PYTHON", python)
    monkeypatch.setattr(s.C, "ALIAS", str(runtime / "new-alias"))
    monkeypatch.setattr(s, "NEW_POLICY", aa / "new-policy")
    monkeypatch.setattr(s, "SOURCE_POLICY", candidate)
    baseline = dict(
        pins=dict(ABI_SHA256="a" * 64),
        old_assets={"old": "unchanged"},
        loaded_before=OLD,
    )
    monkeypatch.setattr(s, "guard", lambda output: baseline)
    monkeypatch.setattr(s.p.old, "private_output", lambda path: path.mkdir(mode=0o700))
    monkeypatch.setattr(s.p, "collect_features", lambda *a, **k: None)
    monkeypatch.setattr(s.network, "root_snapshot", lambda: {"root": "unchanged"})
    monkeypatch.setattr(s, "old_assets", lambda: {"old": "unchanged"})
    virtual_root_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        s,
        "open_parent",
        lambda path, trusted_owner: parent_reader(path, trusted_owner=os.geteuid()),
    )
    monkeypatch.setattr(
        s,
        "read_regular",
        lambda path, **kw: regular_reader(path, **{**kw, "owner": os.geteuid()}),
    )
    loaded = []
    monkeypatch.setattr(
        s.p.cg,
        "_kernel_text",
        lambda path, limit: OLD + (s.C.PROFILE + " (enforce)\n" if loaded else "")
        if path == s.PROFILES
        else "1\n",
    )

    def query(argv, prefix, out):
        if prefix == "candidate-load":
            loaded.append(True)
        s.LAB.save(
            out / (prefix + ".stderr"),
            b"warning" if fault == "loadwarning" and loaded else b"",
        )
        return 0, b"PUBLIC compiled fixture"

    monkeypatch.setattr(s.p.old, "_retained_query", query)
    original = s._new_file

    def writing(path, data, mode, **kw):
        if fault == "partial" and str(path) == s.C.ALIAS:
            actual_write = os.write
            monkeypatch.setattr(
                s.os, "write", lambda fd, raw: actual_write(fd, raw[:3])
            )
        original(path, data, mode, **kw)
        if fault == "alias" and str(path) == s.C.ALIAS:
            raise RuntimeError("synthetic after first alias")

    monkeypatch.setattr(s, "_new_file", writing)
    return tmp_path / "output", baseline


@pytest.mark.parametrize("fault", ["alias", "partial", "loadwarning"])
def test_real_failure_inventory_covers_every_intended_path_and_partial_creation(
    tmp_path, monkeypatch, fault
):
    output, baseline = real_inventory_stage(tmp_path, monkeypatch, fault)
    with pytest.raises((RuntimeError, AssertionError)):
        s.stage(output)
    inventory = json.loads((output / "new_assets-after.json").read_bytes())
    assert len(inventory) == 12 and set(inventory) == set(baseline["intended_assets"])
    assert all(
        row["state"] in ("present", "absent", "unknown") for row in inventory.values()
    )
    alias = inventory[s.C.ALIAS]
    assert alias["state"] == "present" and "created" in alias["confirmation"]
    assert alias["metadata"]["inode"] == alias["confirmation"]["created"]["inode"]
    if fault == "partial":
        assert (
            alias["metadata"]["size"] == 3 and "complete" not in alias["confirmation"]
        )
        assert alias["sha256"] != baseline["intended_assets"][s.C.ALIAS]["sha256"]
    if fault in ("alias", "partial"):
        assert any(row["state"] == "absent" for row in inventory.values())
        with pytest.raises(AssertionError):
            s.validate_inventory(inventory, baseline)
    else:
        assert all(row["state"] == "present" for row in inventory.values())
        for path in s.p.canary_spec():
            assert (
                inventory[path["path"]]["sha256"]
                == baseline["intended_assets"][path["path"]]["sha256"]
            )
    assert (output / "install-intent.json").exists() and not (
        output / "staged.json"
    ).exists()
    assert (output / "parent-after.json").exists() and (
        output / "old_assets-after.json"
    ).exists()
    assert (output / "loaded_profiles-after.json").exists()
    assert list(output.glob("asset-*-created.json"))


def test_empty_or_unconfirmed_inventory_cannot_report_unchanged(tmp_path, monkeypatch):
    with pytest.raises(AssertionError):
        s.validate_inventory({}, dict(intended_assets={}))
    path = tmp_path / "unconfirmed"
    path.write_bytes(b"public")
    from azazel_edge.outcome.input_auth import open_parent as parent_reader

    virtual_root_files(monkeypatch, tmp_path)
    monkeypatch.setattr(
        s,
        "open_parent",
        lambda path, trusted_owner: parent_reader(path, trusted_owner=os.geteuid()),
    )
    baseline = dict(
        intended_assets={
            str(path): dict(
                kind="file",
                mode=0o644,
                size=6,
                sha256=hashlib.sha256(b"public").hexdigest(),
            )
        },
        asset_confirmations={},
    )
    inventory = s.inventory_assets(baseline)
    assert (
        inventory[str(path)]["state"] == "present"
        and "sha256" not in inventory[str(path)]
    )
    with pytest.raises(AssertionError):
        s.validate_inventory(inventory, baseline)
