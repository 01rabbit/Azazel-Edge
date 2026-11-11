"""Real root-owned directory/mode tests; no service activation or host chown."""

import os
import stat
import subprocess
import sys
from unittest.mock import patch

import pytest

from azazel_edge.outcome import service_switch as switch
from azazel_edge.outcome.journal import OutcomeJournalError

ROOT_ONLY = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="actual root-owned protected directories required; no host chown",
)


@pytest.mark.parametrize("path", ["relative/dropin", "/tmp/../dropin"])
def test_unprotected_nonphysical_path_refuses_before_creation(path):
    with (
        patch.object(switch.os, "mkdir", side_effect=AssertionError("must not create")),
        patch.object(switch.os, "fchmod", side_effect=AssertionError("must not chmod")),
    ):
        with pytest.raises(OutcomeJournalError, match="physical absolute"):
            switch._ensure_dropin_directory(path)


@ROOT_ONLY
def test_new_directory_exact0755_under_umask077_in_isolated_child(tmp_path):
    path = tmp_path / "azazel-edge-core.service.d"
    script = """import os,sys,stat
from pathlib import Path
from azazel_edge.outcome.service_switch import _ensure_dropin_directory
os.umask(0o077)
p=Path(sys.argv[1]);_ensure_dropin_directory(p)
assert stat.S_IMODE(p.stat().st_mode)==0o755
# The helper must not alter the process umask.
f=p.parent/'umask-control';f.touch(mode=0o666)
assert stat.S_IMODE(f.stat().st_mode)==0o600
"""
    subprocess.run([sys.executable, "-c", script, str(path)], check=True, timeout=10)
    assert stat.S_IMODE(path.stat().st_mode) == 0o755


@ROOT_ONLY
@pytest.mark.parametrize("mode", [0o700, 0o777, 0o750])
def test_existing_wrong_mode_directory_refused_unchanged(tmp_path, mode):
    path = tmp_path / "dropin"
    path.mkdir()
    path.chmod(mode)
    original = path.stat()
    with patch.object(
        switch.os, "fchmod", side_effect=AssertionError("existing directory modified")
    ):
        with pytest.raises(OutcomeJournalError):
            switch._ensure_dropin_directory(path)
    assert (
        path.stat().st_ino == original.st_ino
        and stat.S_IMODE(path.stat().st_mode) == mode
    )


@ROOT_ONLY
def test_existing_exact_directory_is_never_chmodded(tmp_path):
    path = tmp_path / "dropin"
    path.mkdir()
    path.chmod(0o755)
    with patch.object(
        switch.os, "fchmod", side_effect=AssertionError("existing directory modified")
    ):
        switch._ensure_dropin_directory(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o755


@ROOT_ONLY
@pytest.mark.parametrize("kind", ["symlink", "file", "unsafe_parent", "wrong_owner"])
def test_foreign_or_unsafe_object_is_not_changed(tmp_path, kind):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o755)
    path = parent / "dropin"
    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o700)
    if kind == "symlink":
        path.symlink_to(foreign, target_is_directory=True)
    elif kind == "file":
        path.write_bytes(b"foreign settings")
    elif kind == "unsafe_parent":
        parent.chmod(0o777)
    else:
        path.mkdir(mode=0o755)
        os.chown(path, 65534, 65534)
    before = foreign.stat()
    with patch.object(
        switch.os, "fchmod", side_effect=AssertionError("foreign directory modified")
    ):
        with pytest.raises((OutcomeJournalError, OSError)):
            switch._ensure_dropin_directory(path)
    assert (
        foreign.stat().st_ino == before.st_ino
        and stat.S_IMODE(foreign.stat().st_mode) == 0o700
    )
    if kind == "file":
        assert path.read_bytes() == b"foreign settings"
    if kind == "unsafe_parent":
        assert not path.exists()
    if kind == "wrong_owner":
        assert path.stat().st_uid == 65534


@ROOT_ONLY
@pytest.mark.parametrize("when", ["before_open", "before_chmod", "after_chmod"])
def test_replacement_refuses_and_never_chmods_foreign_node(tmp_path, when):
    path = tmp_path / "dropin"
    original = tmp_path / "created-original"
    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o700)
    real_open = os.open
    real_stat = os.stat
    real_chmod = os.fchmod
    replaced = False

    def replace():
        nonlocal replaced
        if not replaced:
            path.rename(original)
            foreign.rename(path)
            replaced = True

    def opened(name, flags, *args, **kwargs):
        if (
            name == "dropin"
            and kwargs.get("dir_fd") is not None
            and when == "before_open"
        ):
            replace()
        return real_open(name, flags, *args, **kwargs)

    def stated(name, *args, **kwargs):
        info = real_stat(name, *args, **kwargs)
        # First stat captures the created identity; second is pre-chmod name.
        if name == "dropin" and kwargs.get("dir_fd") is not None:
            stated.calls += 1
            if stated.calls == 2 and when == "before_chmod":
                replace()
                return real_stat(name, *args, **kwargs)
        return info

    stated.calls = 0

    def chmod(fd, mode):
        real_chmod(fd, mode)
        if when == "after_chmod":
            replace()

    with (
        patch.object(switch.os, "open", opened),
        patch.object(switch.os, "stat", stated),
        patch.object(switch.os, "fchmod", chmod),
    ):
        with pytest.raises(OutcomeJournalError, match="changed"):
            switch._ensure_dropin_directory(path)
    assert replaced and stat.S_IMODE(path.stat().st_mode) == 0o700
    assert original.exists()  # preserve own abandoned directory, no predelete/repair


@ROOT_ONLY
def test_new_directory_and_parent_synced_after_owned_fd_chmod(tmp_path):
    path = tmp_path / "dropin"
    events = []
    real_chmod = os.fchmod
    real_sync = os.fsync

    def chmod(fd, mode):
        events.append(("chmod", os.fstat(fd).st_ino, mode))
        real_chmod(fd, mode)

    def sync(fd):
        events.append(("sync", os.fstat(fd).st_ino))
        real_sync(fd)

    with (
        patch.object(switch.os, "fchmod", chmod),
        patch.object(switch.os, "fsync", sync),
    ):
        switch._ensure_dropin_directory(path)
    assert events == [
        ("chmod", path.stat().st_ino, 0o755),
        ("sync", path.stat().st_ino),
        ("sync", tmp_path.stat().st_ino),
    ]


@ROOT_ONLY
@pytest.mark.parametrize("failure", ["fchmod", "fsync"])
def test_new_directory_io_failure_preserves_original_for_review(tmp_path, failure):
    path = tmp_path / "dropin"
    with patch.object(switch.os, failure, side_effect=OSError("disk unavailable")):
        with pytest.raises(OSError):
            switch._ensure_dropin_directory(path)
    assert path.is_dir()
    assert stat.S_IMODE(path.stat().st_mode) == (
        0o700 if failure == "fchmod" else 0o755
    )
