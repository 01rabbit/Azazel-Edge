"""SYNTHETIC signed samples/ctypes responses, NOT actual observer teardown."""

import copy
import ctypes as C
import errno
import itertools
import os
import struct
from types import SimpleNamespace

import pytest

from azazel_edge.benchmark import recovery_evidence as recovery
from azazel_edge.outcome.journal import _json
from recovery_evidence_data import (
    BOOT,
    KEYS,
    digest,
    make_recovery,
    materialize,
    wire,
)


def evaluate(plan, report, **signing):
    a, b, pins = materialize(plan, report, **signing)
    return recovery.evaluate_recovery_evidence(a, b, **pins)


def assert_unqualified(result):
    assert (
        result["network_mechanism_restored"] is result["qualified_safety_count"] is None
    )
    assert not any(result["authority_flags"].values())
    for flag in result["authority_flags"]:
        assert result[flag] is False


def test_synthetic_all_absent_is_finite_sample_only_and_inputs_unchanged():
    plan, report = make_recovery()
    before = copy.deepcopy((plan, report))
    result = evaluate(plan, report)
    assert result["status"] == "sampled_absence"
    assert result["observer_objects_absent"] is True
    assert result["matching_residue_count"] == 0 and len(result["resources"]) == 8
    assert (plan, report) == before
    assert_unqualified(result)


@pytest.mark.parametrize("bad_sibling", [False, True])
def test_matching_signed_residue_survives_invalid_sibling(bad_sibling):
    plan, report = make_recovery()
    first = report["resources"][0]
    first.update(
        state="present",
        identity_sha256=plan["resources"][0]["identity_sha256"],
        reason="matching_residue",
    )
    if bad_sibling:
        report["resources"][1]["extra"] = True
    result = evaluate(plan, report)
    assert (
        result["status"] == "residue_observed" and result["matching_residue_count"] == 1
    )
    assert result["observer_objects_absent"] is False
    assert len(result["resources"]) == (7 if bad_sibling else 8)
    assert_unqualified(result)


@pytest.mark.parametrize(
    "fault",
    [
        "reused",
        "denied",
        "missing",
        "duplicate",
        "bool",
        "row_late",
        "context_unstable",
        "capture_late",
        "contradictory_denial",
    ],
)
def test_synthetic_unknown_never_becomes_absence(fault):
    plan, report = make_recovery()
    row = report["resources"][0]
    if fault == "reused":
        row.update(
            state="identity_reused", identity_sha256="0" * 64, reason="identity_differs"
        )
    elif fault == "denied":
        row.update(state="unknown", reason="query_denied_or_failed")
    elif fault == "missing":
        report["resources"].pop()
    elif fault == "duplicate":
        report["resources"][-1] = copy.deepcopy(row)
    elif fault == "bool":
        row["id"] = True
    elif fault == "row_late":
        row["finished_ns"] = plan["deadline_ns"] + 1
    elif fault == "context_unstable":
        report["context_stable"] = False
    elif fault == "capture_late":
        report["finished_ns"] = plan["deadline_ns"] + 1
    else:
        for item in report["resources"]:
            item["reason"] = "query_denied_or_failed"
    result = evaluate(plan, report)
    assert result["status"] == "unknown" and result["observer_objects_absent"] is None
    assert result["matching_residue_count"] is None
    assert_unqualified(result)


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_key",
        "wrong_domain",
        "bad_signature",
        "boot",
        "kernel",
        "plan_binding",
        "layer",
        "schema",
        "extra",
    ],
)
def test_signed_global_proof_mismatch_refuses(fault):
    plan, report = make_recovery()
    signing = {}
    if fault == "wrong_key":
        signing["key"] = KEYS[1]
    elif fault == "wrong_domain":
        signing["domain"] = b"synthetic-wrong-domain\x00"
    elif fault == "boot":
        report["kernel_boot_id"] = "00000000-0000-4000-8000-000000000002"
    elif fault == "kernel":
        report["kernel_release"] = "other-kernel"
    elif fault == "plan_binding":
        report["plan_sha256"] = "0" * 64
    elif fault == "layer":
        report["observation_layer"] = "network_restored"
    elif fault == "schema":
        report["schema_version"] = "unknown/v1"
    elif fault == "extra":
        report["verified"] = True
    a, b, pins = materialize(plan, report, **signing)
    if fault == "bad_signature":
        import json

        value = json.loads(b)
        value["signature"] = "00" * 64
        b = wire(value)
        pins["expected_report_sha256"] = digest(b)
    with pytest.raises(recovery.RecoveryEvidenceError):
        recovery.evaluate_recovery_evidence(a, b, **pins)


@pytest.mark.parametrize(
    "fault", ["pin", "noncanonical", "duplicate_key", "nan", "oversize"]
)
def test_wire_and_external_hash_guards(fault):
    plan, report = make_recovery()
    a, b, pins = materialize(plan, report)
    if fault == "pin":
        pins["expected_report_sha256"] = "0" * 64
    elif fault == "noncanonical":
        b = b + b"\n"
        pins["expected_report_sha256"] = digest(b)
    elif fault == "duplicate_key":
        b = b'{"schema_version":"x","schema_version":"x"}\n'
        pins["expected_report_sha256"] = digest(b)
    elif fault == "nan":
        b = b'{"x":NaN}\n'
        pins["expected_report_sha256"] = digest(b)
    else:
        b = b" " * 32769
        pins["expected_report_sha256"] = digest(b)
    with pytest.raises(recovery.RecoveryEvidenceError):
        recovery.evaluate_recovery_evidence(a, b, **pins)


@pytest.mark.parametrize(
    "fault",
    ["bool_id", "duplicate", "missing", "wrong_kinds", "bad_window", "bad_hash"],
)
def test_malformed_global_enrollment_refuses(fault):
    plan, report = make_recovery()
    if fault == "bool_id":
        plan["resources"][0]["id"] = True
    elif fault == "duplicate":
        plan["resources"][1] = copy.deepcopy(plan["resources"][0])
    elif fault == "missing":
        plan["resources"].pop()
    elif fault == "wrong_kinds":
        plan["resources"][0]["kind"] = "map"
    elif fault == "bad_window":
        plan["deadline_ns"] = plan["not_before_ns"]
    else:
        plan["resources"][0]["identity_sha256"] = "not-a-hash"
    with pytest.raises(recovery.RecoveryEvidenceError):
        evaluate(plan, report)


@pytest.mark.parametrize("missing", ["report", "pin", "both"])
def test_missing_postrun_evidence_is_unknown(missing):
    plan, report = make_recovery()
    a, b, pins = materialize(plan, report)
    if missing in ("report", "both"):
        b = None
    if missing in ("pin", "both"):
        pins["expected_report_sha256"] = None
    result = recovery.evaluate_recovery_evidence(a, b, **pins)
    assert result["status"] == "unknown" and result["observer_objects_absent"] is None
    assert_unqualified(result)


class FakeInfo:
    """Synthetic kernel UAPI bytes. No actual bpf syscall or privilege claim."""

    def __init__(self, raw):
        self.raw = raw
        self.calls = []

    def bpf_obj_get_info_by_fd(self, fd, destination, length):
        self.calls.append(fd)
        C.memmove(destination, self.raw, len(self.raw))
        C.cast(length, C.POINTER(C.c_uint32))[0] = len(self.raw)
        return 0


def kernel_bytes(kind, identifier=31):
    raw = bytearray({"link": 28, "program": 48, "map": 40}[kind])
    typ = {"link": 2, "program": 26, "map": 1}[kind]
    struct.pack_into("=2I", raw, 0, typ, identifier)
    if kind == "link":
        struct.pack_into("=5I", raw, 8, 21, 0, 24, 1, 29236)
    elif kind == "program":
        raw[8:16] = bytes.fromhex("0102030405060708")
        struct.pack_into("=Q", raw, 40, 700_000_000)
    else:
        struct.pack_into("=4I", raw, 8, 32, 128, 64, 0)
        raw[24:40] = b"pending".ljust(16, b"\0")
    return bytes(raw)


@pytest.mark.parametrize("kind", ["link", "program", "map"])
def test_exact_selected_kernel_uapi_offsets(kind):
    actual = recovery._info(FakeInfo(kernel_bytes(kind)), 91, kind)
    assert actual["id"] == 31
    if kind == "link":
        assert actual == dict(
            kind="link",
            id=31,
            type=2,
            program_id=21,
            attach_type=24,
            target_object_id=1,
            target_btf_id=29236,
        )
    elif kind == "program":
        assert actual == dict(
            kind="program",
            id=31,
            type=26,
            tag="0102030405060708",
            load_time_ns=700_000_000,
        )
    else:
        assert actual == dict(
            kind="map",
            id=31,
            type=1,
            key_size=32,
            value_size=128,
            max_entries=64,
            map_flags=0,
            name_hex=b"pending".ljust(16, b"\0").hex(),
        )


@pytest.mark.parametrize("fault", ["present", "reused", "metadata", "close_failed"])
def test_one_id_lookup_and_independent_exactly_once_temporary_fd_close(
    tmp_path, monkeypatch, fault
):
    path = tmp_path / "PUBLIC-SYNTHETIC"
    path.write_bytes(b"public")
    fd = os.open(path, os.O_RDONLY)
    lib = FakeInfo(kernel_bytes("map"))
    query = []
    closes = []

    def lookup(identifier):
        query.append(identifier)
        return fd

    lib.bpf_map_get_fd_by_id = lookup
    identity = dict(
        kind="map",
        id=31,
        type=1,
        key_size=32,
        value_size=128,
        max_entries=64,
        map_flags=0,
        name_hex=b"pending".ljust(16, b"\0").hex(),
    )
    resource = dict(kind="map", id=31, identity_sha256=digest(_json(identity)))
    if fault == "reused":
        resource["identity_sha256"] = "0" * 64
    if fault == "metadata":
        lib.raw = b"\0" * 8
    close = os.close

    def tracked(number):
        closes.append(number)
        close(number)
        if fault == "close_failed":
            raise OSError(errno.EIO, "synthetic close failure AFTER actual close")

    monkeypatch.setattr(recovery.os, "close", tracked)
    result = recovery._lookup(lib, resource)
    assert query == [31] and closes == [fd] and lib.calls == [fd]
    assert (
        result["state"]
        == {
            "present": "present",
            "reused": "identity_reused",
            "metadata": "unknown",
            "close_failed": "unknown",
        }[fault]
    )
    if fault == "close_failed":
        assert result["reason"] == "query_fd_close_failed"
    with pytest.raises(OSError):
        os.fstat(fd)


@pytest.mark.parametrize(
    "error", [errno.ENOENT, errno.EPERM, errno.EACCES, errno.ENOSYS]
)
def test_denied_or_missing_single_lookup_never_retries_or_closes(error, monkeypatch):
    calls = []

    def lookup(identifier):
        calls.append(identifier)
        C.set_errno(error)
        return -1

    lib = SimpleNamespace(bpf_link_get_fd_by_id=lookup)
    monkeypatch.setattr(
        recovery.os, "close", lambda fd: pytest.fail("no temporary descriptor exists")
    )
    result = recovery._lookup(lib, dict(kind="link", id=11, identity_sha256="0" * 64))
    assert calls == [11]
    assert result["state"] == ("absent" if error == errno.ENOENT else "unknown")


def role_status(mask=0, **changes):
    values = dict(
        Uid="0 0 0 0",
        CapInh="0",
        CapPrm=f"{mask:x}",
        CapEff=f"{mask:x}",
        CapBnd=f"{mask:x}",
        CapAmb="0",
        NoNewPrivs="1",
    )
    values.update(changes)
    return "".join(f"{key}:\t{value}\n" for key, value in values.items()).encode()


@pytest.mark.parametrize("mask", [0, (1 << 38) | (1 << 39)])
def test_synthetic_checker_role_accepts_only_documented_masks(monkeypatch, mask):
    monkeypatch.setattr(
        recovery, "sys", SimpleNamespace(platform="linux", byteorder="little")
    )
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 0)
    monkeypatch.setattr(recovery, "_proc_bytes", lambda *args: role_status(mask))
    recovery._checker_role()


@pytest.mark.parametrize(
    "change",
    [
        dict(NoNewPrivs="0"),
        dict(CapEff="200000"),
        dict(CapPrm="200000"),
        dict(CapBnd="200000"),
        dict(CapInh="1"),
        dict(CapAmb="1"),
        dict(Uid="0 1 0 0"),
    ],
)
def test_synthetic_checker_rejects_broader_mixed_or_inherited_role(monkeypatch, change):
    monkeypatch.setattr(
        recovery, "sys", SimpleNamespace(platform="linux", byteorder="little")
    )
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 0)
    monkeypatch.setattr(recovery, "_proc_bytes", lambda *args: role_status(**change))
    with pytest.raises(ValueError):
        recovery._checker_role()


def test_capture_signs_real_crypto_but_synthetic_denied_queries_are_unknown(
    monkeypatch,
):
    plan, _ = make_recovery()
    calls = []
    roles = []
    times = itertools.count(plan["not_before_ns"] + 100)

    def denied(identifier):
        calls.append(identifier)
        C.set_errno(errno.EPERM)
        return -1

    lib = SimpleNamespace(
        bpf_link_get_fd_by_id=denied,
        bpf_prog_get_fd_by_id=denied,
        bpf_map_get_fd_by_id=denied,
    )
    monkeypatch.setattr(recovery, "_checker_role", lambda: roles.append("checked"))
    monkeypatch.setattr(recovery, "_kernel_boot_id", lambda: BOOT)
    monkeypatch.setattr(recovery.platform, "release", lambda: "synthetic-kernel")
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 0)
    monkeypatch.setattr(recovery, "_backend", lambda: lib)
    monkeypatch.setattr(recovery.time, "monotonic_ns", lambda: next(times))
    raw = recovery.capture_recovery_evidence(
        wire(plan),
        expected_plan_sha256=digest(wire(plan)),
        observer_private_key=KEYS[0],
    )
    result = recovery.evaluate_recovery_evidence(
        wire(plan),
        raw,
        expected_plan_sha256=digest(wire(plan)),
        expected_report_sha256=digest(raw),
    )
    assert len(calls) == 8 and roles == ["checked", "checked"]
    assert result["status"] == "unknown" and all(
        row["state"] == "unknown" for row in result["resources"]
    )
    assert_unqualified(result)
