"""Mocked compiler provenance and bounded prerequisite failure diagnostics."""

import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

REAL_RUN = subprocess.run


SPEC = importlib.util.spec_from_file_location(
    "arm_clang_probe_under_test",
    Path(__file__).with_name("test_advisory_exec_linux.py"),
)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def compiler_fixture(tmp_path, monkeypatch, *, machine=183, timeout=False):
    image = tmp_path / "clang-native"
    raw = bytearray(64)
    raw[:6] = b"\x7fELF\x02\x01"
    raw[18:20] = machine.to_bytes(2, "little")
    image.write_bytes(raw)
    output = tmp_path / "public"
    monkeypatch.setenv("EDGE_ADVISORY_EXEC_PUBLIC_DIR", str(output))
    output.mkdir(mode=0o755)
    monkeypatch.setattr(probe.shutil, "which", lambda name: "/path/shadow/clang")
    original_resolve = Path.resolve

    def resolve(path, *args, **kwargs):
        if str(path) == probe.CLANG:
            return image
        if str(path) == "/path/shadow/clang":
            return tmp_path / "shadow-native"
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    original_stat = Path.stat

    def stat(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        if path == image:
            return SimpleNamespace(st_uid=0, st_mode=0o100755, st_size=info.st_size)
        return info

    monkeypatch.setattr(Path, "stat", stat)
    monkeypatch.setattr(probe.os, "access", lambda path, mode: True)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if len(argv) > 2 and argv[1] == "-c" and argv[2] == probe.PUBLIC_READER:
            assert kwargs["user"] == kwargs["group"] == 1000
            assert kwargs["extra_groups"] == [] and kwargs["timeout"] == 12
            return run_reader(argv[3], argv[4], argv[5])
        if "-E" in argv:
            if timeout:
                raise subprocess.TimeoutExpired(
                    argv,
                    10,
                    output=b"original partial output",
                    stderr=b"original partial stderr",
                )
            return subprocess.CompletedProcess(argv, 0, b"172 221 281 220 435\n", b"")
        return subprocess.CompletedProcess(argv, 0, b"Ubuntu clang native test\n", b"")

    monkeypatch.setattr(probe.subprocess, "run", run)
    return image, output, calls


def test_selected_absolute_native_compiler_and_exact_original_macro_probe(
    tmp_path, monkeypatch
):
    image, output, calls = compiler_fixture(tmp_path, monkeypatch)
    assert probe.approved_clang(output) == "/usr/bin/clang"
    record = json.loads((output / "toolchain-probe.json").read_bytes())
    assert record["path_lookup"] == "/path/shadow/clang" and record[
        "resolved_path"
    ] == str(image)
    assert (
        record["elf_machine"] == 183
        and record["sha256"] == probe.sha(image.read_bytes())
        and record["error"] is None
    )
    assert len(calls) == 2 and all(
        argv[0] == "/usr/bin/clang" and options["timeout"] == 10
        for argv, options in calls
    )
    assert calls[1][0] == ["/usr/bin/clang", "-E", "-P", "-x", "c", "-"]
    assert calls[1][1]["input"] == probe.NATIVE_MACRO_INPUT


def test_same_ten_second_timeout_preserves_partial_original_stdout_stderr(
    tmp_path, monkeypatch
):
    image, output, calls = compiler_fixture(tmp_path, monkeypatch, timeout=True)
    with pytest.raises(AssertionError, match="preprocessing failed"):
        probe.approved_clang(output)
    record = json.loads((output / "toolchain-probe.json").read_bytes())
    assert (
        record["macro_probe"]["timed_out"] is True
        and record["macro_probe"]["timeout_seconds"] == 10
    )
    assert (
        base64.b64decode(record["macro_probe"]["stdout_base64"])
        == b"original partial output"
    )
    assert (
        base64.b64decode(record["macro_probe"]["stderr_base64"])
        == b"original partial stderr"
    )
    assert (
        record["macro_probe"]["error"]["type"] == "TimeoutExpired"
        and record["error"] is not None
    )
    assert len(calls) == 2


def test_wrong_native_elf_fails_before_any_compiler_command_but_keeps_provenance(
    tmp_path, monkeypatch
):
    image, output, calls = compiler_fixture(tmp_path, monkeypatch, machine=62)
    with pytest.raises(AssertionError, match="AArch64"):
        probe.approved_clang(output)
    record = json.loads((output / "toolchain-probe.json").read_bytes())
    assert (
        record["elf_machine"] == 62
        and record["version"] is None
        and record["macro_probe"] is None
    )
    assert calls == [] and record["error"]["type"] == "AssertionError"


def test_public_fixture_sole_root_owner_then_probe_and_index(tmp_path, monkeypatch):
    image, output, calls = compiler_fixture(tmp_path, monkeypatch)
    output.rmdir()  # No fixture-owned files exist yet.
    fixture = probe.public_export.__wrapped__()
    publication = next(fixture)
    root, inventory = publication
    assert root == output and inventory
    assert probe.approved_clang(root, publication=publication) == probe.CLANG
    original = (root / "toolchain-probe.json").read_bytes()
    assert len(calls) == 2
    with pytest.raises(FileExistsError):
        next(probe.public_export.__wrapped__())
    with pytest.raises(StopIteration):
        next(fixture)
    assert (root / "toolchain-probe.json").read_bytes() == original
    assert json.loads((root / "case-index.json").read_bytes()) == inventory
    assert calls[-1][1]["timeout"] == 12


def run_reader(root, index_pin, probe_pin):
    # Synthetic UID assertion only: execute the entire original reader body,
    # filesystem opens, hashes, allowlists and parser without changing its logic.
    return REAL_RUN(
        [
            sys.executable,
            "-c",
            "import os;os.geteuid=lambda:1000\n" + probe.PUBLIC_READER,
            str(root),
            index_pin,
            probe_pin,
        ],
        capture_output=True,
        text=True,
        timeout=12,
    )


def test_actual_public_reader_accepts_absent_diagnostic_before_probe(
    tmp_path, monkeypatch
):
    output = tmp_path / "public"
    monkeypatch.setenv("EDGE_ADVISORY_EXEC_PUBLIC_DIR", str(output))
    fixture = probe.public_export.__wrapped__()
    publication = next(fixture)
    root, _ = publication
    calls = []

    def readback(argv, **kwargs):
        calls.append(argv)
        return run_reader(argv[3], argv[4], argv[5])

    monkeypatch.setattr(probe.subprocess, "run", readback)
    with pytest.raises(StopIteration):
        next(fixture)
    assert calls[0][5] == "-" and not (root / "toolchain-probe.json").exists()


@pytest.mark.parametrize(
    "fault", ["wrong_pin", "unpinned", "extra", "symlink", "schema", "bound"]
)
def test_actual_public_reader_strict_diagnostic_contract(tmp_path, monkeypatch, fault):
    _, output, _ = compiler_fixture(tmp_path, monkeypatch)
    output.rmdir()
    fixture = probe.public_export.__wrapped__()
    publication = next(fixture)
    root, _ = publication
    probe.approved_clang(root, publication=publication)
    with pytest.raises(StopIteration):
        next(fixture)
    diagnostic = root / "toolchain-probe.json"
    expected = publication.probe_sha256
    index_pin = probe.sha((root / "case-index.json").read_bytes())
    if fault == "wrong_pin":
        expected = "0" * 64
    elif fault == "unpinned":
        expected = "-"
    elif fault == "extra":
        (root / "unrecognized.json").write_bytes(b"{}")
    elif fault == "symlink":
        target = root.parent / "diagnostic-copy"
        target.write_bytes(diagnostic.read_bytes())
        target.chmod(0o444)
        diagnostic.unlink()
        diagnostic.symlink_to(target)
    else:
        value = json.loads(diagnostic.read_bytes())
        if fault == "schema":
            value["schema_version"] = "unrecognized/v1"
        else:
            value["version"]["stdout_base64"] = "A" * 87385
        raw = probe._json(value) + b"\n"
        diagnostic.chmod(0o644)
        diagnostic.write_bytes(raw)
        diagnostic.chmod(0o444)
        expected = probe.sha(raw)
    checked = run_reader(root, index_pin, expected)
    assert checked.returncode != 0
