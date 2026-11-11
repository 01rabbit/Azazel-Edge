"""Synthetic worker-source/clock/role fixtures; no UID/LSM/runtime qualification."""

import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_observer as o
import signed_network_telemetry_contract as c
from test_signed_network_telemetry_proof import frame, identity, BOOT
from test_signed_network_observer import role_fixture


def streams(monkeypatch, payload, *, timeout=False):
    readfd, writefd = os.pipe()
    os.write(writefd, payload)
    os.close(writefd)
    stdin = os.fdopen(readfd, "rb", buffering=0)
    stdout, stderr = io.BytesIO(), io.StringIO()
    monkeypatch.setattr(
        o,
        "sys",
        SimpleNamespace(
            stdin=SimpleNamespace(buffer=stdin),
            stdout=SimpleNamespace(buffer=stdout),
            stderr=stderr,
        ),
    )
    if timeout:
        monkeypatch.setattr(o.select, "select", lambda *a: [])
    return stdin, stdout, stderr


@pytest.mark.parametrize("mode", ["initialize", "live"])
def test_fixed_new_selector_matches_frozen_root_comparator(mode):
    import signed_network_telemetry_proof as proof

    value = o.role_argv(mode, telemetry_lab_v2=True)
    spec = c.observer_spec(mode)
    assert "--unit=" + spec["unit"] in value
    assert value[-7:] == proof.reserved_argv(mode)
    for key, item in spec["properties"].items():
        assert key + "=" + item in value
    assert c.CLI_FLAG not in o.role_argv(mode)
    with pytest.raises(Exception):
        o.role_argv(mode, telemetry_lab_v2="yes")


@pytest.mark.parametrize("mode", ["initialize", "live"])
@pytest.mark.parametrize(
    "payload,timeout",
    [
        (b"", False),
        (b"wrong\n", False),
        (c.GO[:-1], False),
        (c.GO + b"x", False),
        (b"x" * 100, False),
        (b"", True),
    ],
)
def test_failed_fence_retains_prefix_and_opens_zero_api(
    monkeypatch, mode, payload, timeout
):
    monkeypatch.setattr(o, "_telemetry_guard", lambda selected: frame(selected))
    opened = []
    monkeypatch.setattr(
        o.TrustPolicy, "from_file", lambda *a, **k: opened.append("trust")
    )
    monkeypatch.setattr(o, "policy_material", lambda: opened.append("policy"))
    monkeypatch.setattr(o, "LinuxProcTelemetrySource", lambda: opened.append("sample"))
    stdin, stdout, stderr = streams(monkeypatch, payload, timeout=timeout)
    try:
        with pytest.raises(Exception):
            o.worker(mode, telemetry_lab_v2=True)
        assert opened == []
        ready = json.loads(stdout.getvalue())
        assert ready["kind"] == c.READY_KIND and ready["mode"] == mode
        diagnostic = json.loads(stderr.getvalue())
        assert diagnostic["kind"] == "pre_api_go_refused"
        consumed = bytes.fromhex(diagnostic["consumed_hex"])
        assert consumed == payload[: len(c.GO) + 1] if not timeout else consumed == b""
    finally:
        stdin.close()


def guard_fixture(monkeypatch, mode="initialize"):
    from azazel_edge.outcome import confinement

    monkeypatch.setattr(o, "__file__", c.SOURCE)
    monkeypatch.setattr(
        o,
        "sys",
        SimpleNamespace(
            platform="linux",
            executable=c.ALIAS,
            argv=[c.SOURCE, "--worker", mode, c.CLI_FLAG],
        ),
    )
    labels = []
    monkeypatch.setattr(
        confinement, "enforce_capture", lambda label: labels.append(label)
    )
    fields = dict(
        Pid="123",
        Tgid="123",
        Uid="61002 " * 4,
        Gid="61002 " * 4,
        Groups="61002",
        NoNewPrivs="1",
        CapEff="0",
        CapPrm="0",
        CapAmb="0",
        CapBnd="0",
    )
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda path: (
            "\n".join(k + ":" + v for k, v in fields.items()) + "\n"
        ).encode(),
    )
    monkeypatch.setattr(o.os, "getuid", lambda: 61002)
    monkeypatch.setattr(o.os, "getgid", lambda: 61002)
    monkeypatch.setattr(o.os, "getgroups", lambda: [61002])
    monkeypatch.setattr(o.os, "getpid", lambda: 123)
    monkeypatch.setattr(
        ctypes, "CDLL", lambda *a, **k: SimpleNamespace(prctl=lambda *a: 1)
    )
    monkeypatch.setattr(
        o, "read_regular", lambda *a, **k: (b"synthetic reviewed source", None)
    )
    monkeypatch.setattr(o.g, "boot", lambda: BOOT)
    return fields, labels


def test_guard_ready_exact_schema_matches_root_parser(monkeypatch):
    import signed_network_telemetry_proof as proof

    _, labels = guard_fixture(monkeypatch)
    ready = o._telemetry_guard("initialize")
    digest = hashlib.sha256(b"synthetic reviewed source").hexdigest()
    assert (
        proof.parse_ready(
            json.dumps(ready).encode() + b"\n",
            "initialize",
            kernel_boot_id=BOOT,
            source_sha256=digest,
        )["identity"]
        == identity()
    )
    assert labels == [c.PROFILE]


@pytest.mark.parametrize("mode", ["initialize", "live"])
@pytest.mark.parametrize(
    "fault",
    [
        "alias",
        "source",
        "argv",
        "boot",
        "uid",
        "cap",
        "bnd",
        "nnp",
        "tgid",
        "dumpable",
        "profile",
    ],
)
def test_guard_mismatch_prevents_ready_and_api(monkeypatch, fault, mode):
    from azazel_edge.outcome import confinement

    fields, _ = guard_fixture(monkeypatch, mode)
    if fault == "alias":
        o.sys.executable = "/other"
    if fault == "source":
        monkeypatch.setattr(o, "__file__", "/other.py")
    if fault == "argv":
        o.sys.argv.append("extra")
    if fault == "boot":
        monkeypatch.setattr(o.g, "boot", lambda: "not-boot")
    if fault == "uid":
        fields["Uid"] = "0 0 0 0"
    if fault == "cap":
        fields["CapEff"] = "1"
    if fault == "bnd":
        fields["CapBnd"] = "1"
    if fault == "nnp":
        fields["NoNewPrivs"] = "0"
    if fault == "tgid":
        fields["Tgid"] = "124"
    if fault == "dumpable":
        monkeypatch.setattr(
            ctypes, "CDLL", lambda *a, **k: SimpleNamespace(prctl=lambda *a: 0)
        )
    if fault == "profile":

        def deny(label):
            raise AssertionError("actual label differs")

        monkeypatch.setattr(confinement, "enforce_capture", deny)
    monkeypatch.setattr(
        o.TrustPolicy, "from_file", lambda *a, **k: pytest.fail("API before fence")
    )
    with pytest.raises((AssertionError, ValueError)):
        o.worker(mode, telemetry_lab_v2=True)


def test_exact_go_enters_real_authenticated_empty_journal_api(tmp_path, monkeypatch):
    """Real journal/input/auth; explicitly synthetic role, ownership and witness I/O."""
    from azazel_edge.outcome import input_cursor, input_witness

    p, _, directory, _ = role_fixture(tmp_path, monkeypatch)
    Path(p.data["source_path"]).touch(mode=0o600)
    # Local fixture file belongs to test runner, not an actual capture UID.
    original_safe = input_cursor.BoundedInput._safe

    def synthetic_owner(self, info):
        actual = self.authentication
        try:
            self.authentication = SimpleNamespace(
                policy=SimpleNamespace(data={"producer_uid": os.geteuid()})
            )
            return original_safe(self, info)
        finally:
            self.authentication = actual

    monkeypatch.setattr(input_cursor.BoundedInput, "_safe", synthetic_owner)
    witnessed = []

    class SyntheticWitness:
        state = None

        def __init__(self, trust):
            assert trust is p

        def preflight(self, *args):
            witnessed.append(("preflight", args))

        def advance(self, *args):
            witnessed.append(("advance", args))

    monkeypatch.setattr(input_witness, "WitnessClient", SyntheticWitness)
    monkeypatch.setattr(o, "_telemetry_guard", lambda mode: frame(mode))
    stdin, stdout, stderr = streams(monkeypatch, c.GO)
    # Final existing print uses text stdout, whereas READY uses its byte buffer.
    o.sys.stdout = io.TextIOWrapper(stdout, encoding="utf-8", write_through=True)
    try:
        result = o.worker("initialize", telemetry_lab_v2=True)
        assert result["initialized_empty"] is True
        frames = o.lab.journal_frames((directory / o.NAME).read_bytes())
        assert frames[-1]["kind"] == "session_close"
        assert frames[-1]["data"] == {"boot_id": result["boot_ref"]}
        assert witnessed[0][0] == "preflight" and witnessed[-1][0] == "advance"
        assert stderr.getvalue() == ""
    finally:
        stdin.close()


def test_exact_go_live_preserves_signed_terminal_callback_flow(tmp_path, monkeypatch):
    """Existing ephemeral signed terminal fixture; live/witness callbacks synthetic."""
    from test_signed_network_observer import (
        test_actual_end_anchor_follows_natural_api_and_durable_recorder_close,
    )

    original = o.worker
    monkeypatch.setattr(o, "worker", lambda mode: original(mode, telemetry_lab_v2=True))
    monkeypatch.setattr(o, "_telemetry_guard", lambda mode: frame(mode))
    stdin, stdout, _ = streams(monkeypatch, c.GO)
    o.sys.stdout = io.TextIOWrapper(stdout, encoding="utf-8", write_through=True)
    try:
        test_actual_end_anchor_follows_natural_api_and_durable_recorder_close(
            tmp_path, monkeypatch
        )
    finally:
        stdin.close()
