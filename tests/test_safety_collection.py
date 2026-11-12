"""SYNTHETIC Root metadata/reader/boot only; real FD IO, signatures and evaluator.

Actual Linux ownership and UID-denial tests live in test_safety_collection_linux.
"""

from copy import deepcopy
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from azazel_edge.benchmark import safety_collection as c
from safety_collection_data import BOOT, CASES, build_bundle

OS_BOUNDARY = {"producer-write-denied", "observer-write-denied"}
UNIT_CASES = [row for row in CASES if row["id"] not in OS_BOUNDARY]


class SyntheticRootOS:
    """Real opened FDs/races; explicitly synthetic root ownership/protected ancestry."""

    def __init__(self, bundle, case):
        self.bundle, self.case = bundle, case
        self.opened, self.closed, self.paths = [], [], {}
        self.mutated = False

    def __getattr__(self, name):
        return getattr(os, name)

    def geteuid(self):
        owner = self.bundle["scope"]["owner"]
        return (
            owner["producer_uid"]
            if self.case == "producer-as-reader"
            else owner["observer_uid"] + 1
            if self.case == "wrong-reader"
            else owner["observer_uid"]
        )

    def open(self, path, flags, *args, dir_fd=None):
        assert flags & os.O_ACCMODE == os.O_RDONLY
        assert flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC and flags & os.O_NONBLOCK
        physical = Path(path) if dir_fd is None else self.paths[dir_fd] / path
        fd = os.open(path, flags, *args, dir_fd=dir_fd)
        self.paths[fd] = physical
        self.opened.append(fd)
        return fd

    def metadata(self, info, path):
        fields = {
            name: getattr(info, name) for name in dir(info) if name.startswith("st_")
        }
        fields["st_uid"], fields["st_gid"] = 0, 0
        if stat.S_ISDIR(info.st_mode):
            fields["st_mode"] &= ~0o022
            if (
                self.case == "unsafe-ancestor"
                and path == self.bundle["paths"]["enrollment"].parent
            ):
                fields["st_mode"] |= 0o022
        if self.case == "unsafe-owner" and path == self.bundle["paths"]["observations"]:
            fields["st_uid"] = self.bundle["scope"]["owner"]["producer_uid"]
        return SimpleNamespace(**fields)

    def fstat(self, fd):
        return self.metadata(os.fstat(fd), self.paths[fd])

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        physical = Path(path) if dir_fd is None else self.paths[dir_fd] / path
        return self.metadata(
            os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks), physical
        )

    def read(self, fd, maximum):
        raw = os.read(fd, maximum)
        if (
            raw
            and not self.mutated
            and self.paths[fd] == self.bundle["paths"]["observations"]
            and self.case
            in ("replacement", "growth", "truncation", "ancestor-replacement")
        ):
            self.mutated = True
            path = self.bundle["paths"]["observations"]
            if self.case == "replacement":
                old = path.read_bytes()
                path.unlink()
                path.write_bytes(old)
                path.chmod(0o444)
            elif self.case == "growth":
                path.chmod(0o644)
                with path.open("ab") as stream:
                    stream.write(b" ")
                path.chmod(0o444)
            elif self.case == "truncation":
                path.chmod(0o644)
                path.write_bytes(raw[:8])
                path.chmod(0o444)
            else:
                parent = path.parent
                parent.rename(parent.with_name(parent.name + "-retained"))
                parent.mkdir()
        return raw

    def close(self, fd):
        self.closed.append(fd)
        os.close(fd)
        if self.case == "close-failure" and len(self.closed) == 1:
            raise OSError("synthetic close failure AFTER actual close")


def staged(tmp_path, monkeypatch, case):
    directory = tmp_path / "sealed"
    directory.mkdir(mode=0o755)
    bundle = build_bundle(directory, case)
    for name, raw in bundle["files"].items():
        bundle["paths"][name].write_bytes(raw)
        bundle["paths"][name].chmod(0o444)
    path = bundle["paths"]["observations"]
    if case == "unsafe-mode":
        path.chmod(0o644)
    elif case == "symlink":
        path.unlink()
        path.symlink_to(bundle["paths"]["contract"])
    elif case == "hardlink":
        path.unlink()
        os.link(bundle["paths"]["contract"], path)
    elif case == "special-file":
        path.unlink()
        os.mkfifo(path, 0o444)
    proxy = SyntheticRootOS(bundle, case)
    monkeypatch.setattr(c, "os", proxy)
    boots = []

    def boot():
        boots.append(1)
        return (
            "00000000-0000-4000-8000-000000000002"
            if case == "boot-drift" and len(boots) > 1
            else BOOT
        )

    monkeypatch.setattr(c, "_kernel_boot_id", boot)
    original = c.evaluator.evaluate_safety_observations
    evaluations = []

    def evaluate(*args, **kwargs):
        evaluations.append(1)
        result = original(*args, **kwargs)
        if case == "inplace-change":
            raw = path.read_bytes()
            path.chmod(0o644)
            path.write_bytes(raw.replace(b"synthetic", b"Synthetic", 1))
            path.chmod(0o444)
        return result

    monkeypatch.setattr(c.evaluator, "evaluate_safety_observations", evaluate)
    return bundle, proxy, evaluations


def invoke(bundle):
    return c.collect_registered_safety(
        bundle["paths"]["enrollment"],
        expected_enrollment_sha256=bundle["expected_enrollment_sha256"],
        expected_checkpoint_sha256=bundle["expected_checkpoint_sha256"],
    )


@pytest.mark.parametrize("expected", UNIT_CASES, ids=lambda row: row["id"])
def test_frozen_cases_with_real_crypto_and_fd_intake_synthetic_owner_and_reader(
    tmp_path, monkeypatch, expected
):
    bundle, proxy, evaluations = staged(tmp_path, monkeypatch, expected["id"])
    if expected["expected"] == "rejected":
        with pytest.raises(c.SafetyCollectionError):
            invoke(bundle)
    else:
        result = invoke(bundle)
        assert result["status"] == "unqualified_collection"
        assert (
            result["independently_measured"] is False
            and result["qualified_safety_count"] is None
        )
        category = result["evaluation"]["categories"]["protected_escape"]
        assert (
            category["observed_violation_count"] == expected["protected_escape_count"]
        )
        assert all(
            flag is False for flag in result["evaluation"]["authority_flags"].values()
        )
        assert (
            result["provenance"]["observer_uid"]
            == bundle["scope"]["owner"]["observer_uid"]
        )
        assert len(evaluations) == 1
    assert sorted(proxy.closed) == sorted(proxy.opened)


def test_every_frozen_id_has_unit_or_explicit_linux_owner():
    assert {row["id"] for row in UNIT_CASES} | OS_BOUNDARY == {
        row["id"] for row in CASES
    }
    assert not ({row["id"] for row in UNIT_CASES} & OS_BOUNDARY)


def test_actual_scope_substitution_is_before_signature_and_checkpoint(tmp_path):
    bundle = build_bundle(
        tmp_path,
        "violation",
        boot_id="00000000-0000-4000-8000-000000000009",
        observer_uid=62002,
        producer_uid=62001,
    )
    enrollment = json.loads(bundle["files"]["enrollment"])
    contract = json.loads(bundle["files"]["contract"])
    observation = json.loads(bundle["files"]["observations"])
    checkpoint = json.loads(bundle["files"]["checkpoint"])
    result = c.evaluator.evaluate_safety_observations(
        bundle["files"]["contract"],
        bundle["files"]["observations"],
        expected_contract_sha256=enrollment["contract_sha256"],
        expected_stream_heads=checkpoint["stream_heads"],
        **contract["keypins"],
    )
    assert all(
        row["scope"] == contract["scope"]
        for channel in observation["channels"].values()
        for row in channel["rows"]
    )
    assert result["categories"]["protected_escape"]["observed_violation_count"] == 1


def test_no_writes_execution_or_retries_and_input_bytes_unchanged(
    tmp_path, monkeypatch
):
    bundle, proxy, _ = staged(tmp_path, monkeypatch, "complete")
    original = deepcopy(bundle["files"])
    with (
        patch(
            "builtins.open", side_effect=AssertionError("file writes/high-level read")
        ),
        patch("socket.socket", side_effect=AssertionError("network")),
        patch("subprocess.Popen", side_effect=AssertionError("execution")),
        patch("os.system", side_effect=AssertionError("execution")),
    ):
        result = invoke(bundle)
    assert result["status"] == "unqualified_collection"
    assert bundle["files"] == original
    assert all(
        path.read_bytes() == original[name] for name, path in bundle["paths"].items()
    )
    assert len(proxy.opened) == len(proxy.closed)
