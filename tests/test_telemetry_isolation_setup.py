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
            and "--Werror" in argv
            and "--skip-cache" in argv
        )
        calls.append(prefix)
        return 0, b"public compiled bytes"

    monkeypatch.setattr(s.p.old, "_retained_query", query)

    def write(path, data, mode):
        assert (output / "root-before.json").exists() and (
            output / "install-intent.json"
        ).exists()
        assert str(path) not in installed
        calls.append("new:" + str(path))
        installed[str(path)] = data

    monkeypatch.setattr(s, "_new_file", write)
    monkeypatch.setattr(s, "_mkdir", lambda path: calls.append("mkdir:" + str(path)))

    def kernel(path, limit):
        return OLD + s.C.PROFILE + " (enforce)\n" if path == s.PROFILES else "1\n"

    monkeypatch.setattr(s.p.cg, "_kernel_text", kernel)
    monkeypatch.setattr(
        s, "invariants", lambda *a, **k: calls.append("independent_invariants")
    )
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
