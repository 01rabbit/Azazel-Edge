"""SYNTHETIC closed99-leaf publication tests; no actual matrix or native action."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

import window_cost_publication as publication


@pytest.fixture
def retained(tmp_path):
    root = tmp_path.resolve() / "retained"
    root.mkdir(mode=0o700)
    arms = {arm: dict(arm_id=arm) for arm in publication.ARMS}
    cases = {case: dict(id=case, artifacts={}) for case in publication.CASES}
    for relative, selector in publication.inventory():
        if selector is None:
            continue
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        raw = ("SYNTHETIC public evidence " + relative + "\n").encode()
        path.write_bytes(raw)
        descriptor = dict(
            sha256=publication.sha(raw),
            bytes=len(raw),
            path="/NEVER/READ/DESCRIPTOR/PATH",
        )
        if len(selector) == 3:
            arm, group, name = selector
            if group == "control_artifacts":
                arms[arm].setdefault("normal_stop", {}).setdefault("artifacts", {})[
                    name
                ] = descriptor
            else:
                arms[arm].setdefault(group, {})[name] = descriptor
        else:
            case, slot = selector
            cases[case]["artifacts"][slot] = descriptor
    normal = dict(
        original_load_evaluation=dict(original_arm_inputs=list(arms.values()))
    )
    (root / "original-normal-clock/report.json").write_bytes(publication.wire(normal))
    (root / "window-cost-completion.json").write_bytes(
        publication.wire(dict(original_normal_clock_evaluation=normal))
    )
    (root / "synthetic-window-cases/manifest.json").write_bytes(
        publication.wire(dict(cases=list(cases.values())))
    )
    for case in publication.CASES:
        directory = root / "synthetic-window-cases" / case
        directory.chmod(0o700)
        for name in ("input", "private-key"):
            path = directory / name
            path.write_bytes(b"PRIVATE SETUP: NEVER PUBLISH")
            path.chmod(0o600)
    return root


def test_complete_copy_readable_by_ordinary_reader_and_originals_unchanged(retained):
    planned = [path for path, _ in publication.inventory()]
    originals = {
        path: (
            (retained / path).read_bytes(),
            stat.S_IMODE((retained / path).stat().st_mode),
        )
        for path in planned
    }
    before_dirs = {
        str(path): stat.S_IMODE(path.stat().st_mode)
        for path in retained.rglob("*")
        if path.is_dir()
    }
    index = publication.publish_publication(retained)
    target = retained / "publication"
    assert index["status"] == "complete" and index["errors"] == []
    assert index["copied_files"] == index["planned_files"] == 99
    assert {entry["path"] for entry in index["entries"]} == set(planned)
    assert len([p for p in target.rglob("*") if p.is_file()]) == 100
    for path, (raw, mode) in originals.items():
        assert (retained / path).read_bytes() == raw
        assert stat.S_IMODE((retained / path).stat().st_mode) == mode
        assert (target / path).read_bytes() == raw
    assert all(
        stat.S_IMODE(Path(path).stat().st_mode) == mode
        for path, mode in before_dirs.items()
    )
    assert all(
        stat.S_IMODE(p.stat().st_mode) == (0o755 if p.is_dir() else 0o444)
        for p in [target, *target.rglob("*")]
    )
    assert not any(p.name in {"private-key", "input"} for p in target.rglob("*"))
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        script = "import os,sys,json,hashlib;os.fchdir(int(sys.argv[1]));print(json.dumps({p:hashlib.sha256(open(p,'rb').read()).hexdigest() for p in json.loads(sys.argv[2])}))"
        options = (
            dict(user=65533, group=65533, extra_groups=[])
            if sys.platform == "linux" and os.geteuid() == 0
            else {}
        )
        child = subprocess.run(
            [sys.executable, "-c", script, str(fd), json.dumps(planned)],
            pass_fds=(fd,),
            capture_output=True,
            text=True,
            timeout=10,
            **options,
        )
    finally:
        os.close(fd)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == {
        path: publication.sha(raw) for path, (raw, _) in originals.items()
    }


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "symlink_leaf",
        "symlink_parent",
        "nondirectory_parent",
        "digest",
        "oversize",
    ],
)
def test_failed_leaf_retains_valid_siblings_and_all_planned_errors(retained, fault):
    relative = "synthetic-window-cases/expiry_commit/event.json"
    path = retained / relative
    if fault == "missing":
        path.unlink()
    elif fault == "symlink_leaf":
        path.unlink()
        path.symlink_to(path.parent / "private-key")
    elif fault in ("symlink_parent", "nondirectory_parent"):
        parent = path.parent
        backup = parent.with_name("private-backup")
        parent.rename(backup)
        if fault == "symlink_parent":
            parent.symlink_to(backup, target_is_directory=True)
        else:
            parent.write_bytes(b"not a directory")
    elif fault == "digest":
        path.write_bytes(b"changed")
    else:
        with path.open("wb") as stream:
            stream.truncate(publication.MAX_SYNTHETIC + 1)
    index = publication.publish_publication(retained)
    assert index["status"] == "incomplete" and index["planned_files"] == 99
    assert index["copied_files"] >= 94
    entry = next(item for item in index["entries"] if item["path"] == relative)
    assert entry["error"] and entry["sha256"] is entry["bytes"] is None
    assert not (retained / "publication" / relative).exists()
    assert (retained / "publication/window-cost-completion.json").read_bytes() == (
        retained / "window-cost-completion.json"
    ).read_bytes()
    assert (
        retained / "publication/synthetic-window-cases/stop_pending_loss/event.json"
    ).is_file()
    assert (
        json.loads((retained / "publication/publication-index.json").read_bytes())
        == index
    )


def test_changed_inode_version_during_read_is_not_copied(retained, monkeypatch):
    relative = "synthetic-window-cases/expiry_commit/event.json"
    path = retained / relative
    inode = path.stat().st_ino
    actual_os = publication.os
    changed = []

    class ObservedOS:
        def __getattr__(self, name):
            return getattr(actual_os, name)

        def read(self, fd, maximum):
            if not changed and actual_os.fstat(fd).st_ino == inode:
                changed.append(True)
                path.write_bytes(b"mutated during bounded read")
            return actual_os.read(fd, maximum)

    monkeypatch.setattr(publication, "os", ObservedOS())
    index = publication.publish_publication(retained)
    entry = next(item for item in index["entries"] if item["path"] == relative)
    assert changed == [True]
    assert "changed during read" in entry["error"]
    assert index["copied_files"] == 98


def test_fresh_publication_exclusive_and_root_ancestor_symlink_rejected(retained):
    alias = retained.parent / "alias"
    alias.symlink_to(retained, target_is_directory=True)
    with pytest.raises(OSError):
        publication.publish_publication(alias)
    assert not (retained / "publication").exists()
    publication.publish_publication(retained)
    saved = (retained / "publication/publication-index.json").read_bytes()
    with pytest.raises(FileExistsError):
        publication.publish_publication(retained)
    assert (retained / "publication/publication-index.json").read_bytes() == saved


def test_existing_target_symlink_is_never_followed(retained, tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    (external / "keep").write_bytes(b"unchanged")
    (retained / "publication").symlink_to(external, target_is_directory=True)
    with pytest.raises(FileExistsError):
        publication.publish_publication(retained)
    assert [p.name for p in external.iterdir()] == ["keep"]


def test_total_bound_records_partial_copy_without_zero_substitution(
    retained, monkeypatch
):
    monkeypatch.setattr(publication, "MAX_TOTAL", 1)
    index = publication.publish_publication(retained)
    assert index["status"] == "incomplete" and index["copied_files"] == 0
    assert len(index["errors"]) == 99
    assert all(row["sha256"] is row["bytes"] is None for row in index["entries"])


@pytest.mark.parametrize(
    "empty", ["window-cost-completion.json", "original-normal-clock/report.json"]
)
def test_empty_required_report_never_completes_from_other_descriptors(retained, empty):
    (retained / empty).write_bytes(b"{}\n")
    planned = [path for path, _ in publication.inventory()]
    originals = {
        path: ((retained / path).read_bytes(), (retained / path).stat().st_mode)
        for path in planned
    }
    index = publication.publish_publication(retained)
    assert index["status"] == "incomplete"
    assert index["planned_files"] == 99 and index["copied_files"] < 99
    rejected = next(row for row in index["entries"] if row["path"] == empty)
    assert rejected["error"] and rejected["sha256"] is rejected["bytes"] is None
    assert not (retained / "publication" / empty).exists()
    assert (
        retained / "publication/synthetic-window-cases/expiry_commit/event.json"
    ).is_file()
    assert (
        retained
        / "publication/original-normal-clock/original_off-raw_artifacts-source.raw"
    ).is_file()
    for path, (raw, mode) in originals.items():
        assert (retained / path).read_bytes() == raw
        assert (retained / path).stat().st_mode == mode
