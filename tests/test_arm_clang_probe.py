"""Mocked compiler provenance and bounded prerequisite failure diagnostics."""

import base64
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

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
    assert probe.approved_clang() == "/usr/bin/clang"
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
        probe.approved_clang()
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
        probe.approved_clang()
    record = json.loads((output / "toolchain-probe.json").read_bytes())
    assert (
        record["elf_machine"] == 62
        and record["version"] is None
        and record["macro_probe"] is None
    )
    assert calls == [] and record["error"]["type"] == "AssertionError"
