"""Pure synthetic frames and real parser on synthetic proc text; no role proof."""

from copy import deepcopy
from dataclasses import asdict
import errno
import json
from pathlib import Path
import sys

import pytest
from azazel_edge.outcome.telemetry import LinuxProcTelemetrySource

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import telemetry_isolation_result as r

BOOT = "7be45004-1731-4b7c-8e62-59a5ddf129a4"
SHA = "a" * 64


def raw(value):
    return json.dumps(value, sort_keys=True, allow_nan=False).encode() + b"\n"


def ready(mode="probe"):
    identity = dict(
        pid=456 if mode == "probe" else 123,
        tgid=456 if mode == "probe" else 123,
        uid=61002,
        gid=61002,
        groups=[61002],
        apparmor=r.c.PROFILE + " (enforce)",
        no_new_privs=True,
        cap_eff=0,
        cap_prm=0,
        cap_amb=0,
        cap_bnd=0,
        dumpable=1,
    )
    return dict(
        kind="ready",
        mode=mode,
        identity=identity,
        kernel_boot_id=BOOT,
        source_sha256=SHA,
        source=r.SOURCE,
        public_address=4096 if mode == "peer" else None,
        public_size=1 if mode == "peer" else None,
    )


def sample(tmp_path):
    (tmp_path / "net").mkdir()
    (tmp_path / "net/dev").write_text(
        "es: " + " ".join(str(n) for n in range(16)) + "\n"
    )
    (tmp_path / "loadavg").write_text("0.1 0.2 0.3 1/1 456\n")
    (tmp_path / "meminfo").write_text(
        "MemTotal: 1000 kB\nMemAvailable: 500 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
    )
    (tmp_path / "uptime").write_text("1000.0 2000.0\n")
    return asdict(
        LinuxProcTelemetrySource(tmp_path).sample(interface="es", epoch=1000.0)
    )


def final(tmp_path, mode="probe"):
    start = ready(mode)
    value = deepcopy({k: start[k] for k in r.CONTEXT})
    value.update(
        mode=mode,
        kind="probe_observations_complete" if mode == "probe" else "peer_wait_finished",
        scope="self_process_threadgroup_observations_not_qualification",
        operations=[],
    )
    if mode == "peer":
        return start, value
    data = sample(tmp_path)
    for name, allowed in r.expected_operations(123).items():
        if allowed:
            value["operations"].append(
                dict(operation=name, outcome="denied", errno=allowed[0])
            )
        elif name == "actual_self_sample":
            value["operations"].append(dict(operation=name, sample=data))
        elif name == "proc_enumeration":
            value["operations"].append(
                dict(
                    operation=name,
                    outcome="self_threadgroup_only_numeric_entries",
                    numeric=[456],
                )
            )
        else:
            value["operations"].append(
                dict(
                    operation=name,
                    outcome="one_public_byte_read"
                    if name == "self_process_vm_readv_sanity"
                    else "unexercised_no_namespace_fd",
                )
            )
    return start, value


@pytest.mark.parametrize("mode", ["peer", "probe"])
def test_ready_requires_exact_actual_role_and_public_buffer_shape(mode):
    value = ready(mode)
    original = deepcopy(value)
    assert r.parse_ready(raw(value), mode, boot=BOOT, worker_sha256=SHA) == value
    assert value == original


@pytest.mark.parametrize(
    "fault",
    [
        "wrongsource",
        "wrongboot",
        "wrongsha",
        "wrongmode",
        "uid",
        "caps",
        "nnp",
        "extrafield",
        "booladdress",
        "boolsize",
    ],
)
def test_false_or_malformed_ready_cannot_be_local_source_proof(fault):
    value = ready("peer")
    if fault == "wrongsource":
        value["source"] = "/other"
    elif fault == "wrongboot":
        value["kernel_boot_id"] = "other"
    elif fault == "wrongsha":
        value["source_sha256"] = "b" * 64
    elif fault == "wrongmode":
        value["mode"] = "probe"
    elif fault == "uid":
        value["identity"]["uid"] = 0
    elif fault == "caps":
        value["identity"]["cap_bnd"] = 1
    elif fault == "nnp":
        value["identity"]["no_new_privs"] = 1
    elif fault == "extrafield":
        value["verified"] = True
    elif fault == "booladdress":
        value["public_address"] = True
    elif fault == "boolsize":
        value["public_size"] = True
    with pytest.raises(ValueError):
        r.parse_ready(raw(value), "peer", boot=BOOT, worker_sha256=SHA)


@pytest.mark.parametrize("mode", ["peer", "probe"])
def test_complete_result_preserves_originals_and_returns_no_acceptance_flags(
    tmp_path, mode
):
    start, value = final(tmp_path, mode)
    before = deepcopy((start, value))
    decoded = r.validate_result(
        raw(value), start, peer_pid=123 if mode == "probe" else None
    )
    assert decoded == value and (start, value) == before
    assert not {
        "qualified",
        "authorizes_transition",
        "production_admission",
        "resume_authorized",
    } & set(decoded)
    if mode == "probe":
        assert len(decoded["operations"]) == 40


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "duplicate",
        "reorder",
        "unsupported",
        "inflight",
        "success",
        "boolerrno",
        "extraopfield",
        "numericfloat",
        "numericforeign",
        "coverage",
        "emptynetwork",
        "missingmemory",
        "interface",
        "noopread",
        "fakesetns",
        "identitytype",
        "blocked",
        "extrarow",
        "extrafield",
        "badrow",
    ],
)
def test_complete_probe_gate_refuses_partial_typed_or_unsupported_facts(
    tmp_path, fault
):
    start, value = final(tmp_path)
    rows = value["operations"]
    if fault == "missing":
        rows.pop()
    elif fault == "duplicate":
        rows[-1] = deepcopy(rows[-2])
    elif fault == "reorder":
        rows[-1], rows[-2] = rows[-2], rows[-1]
    elif fault == "unsupported":
        rows[13]["errno"] = errno.ESRCH
    elif fault == "inflight":
        rows[13]["outcome"] = "inflight"
    elif fault == "success":
        rows[13]["outcome"] = "unexpected_success"
    elif fault == "boolerrno":
        rows[13]["errno"] = True
    elif fault == "extraopfield":
        rows[13]["verified"] = True
    elif fault == "numericfloat":
        rows[2]["numeric"] = [456.0]
    elif fault == "numericforeign":
        rows[2]["numeric"] = [456, 123]
    elif fault == "coverage":
        rows[1]["sample"]["coverage"]["proc_net_dev"] = False
    elif fault == "emptynetwork":
        rows[1]["sample"]["network"] = {}
    elif fault == "missingmemory":
        rows[1]["sample"]["system"].pop("memory_available_kib")
    elif fault == "interface":
        rows[1]["sample"]["interface"] = "lo"
    elif fault == "noopread":
        rows[0]["outcome"] = "not_attempted"
    elif fault == "fakesetns":
        next(row for row in rows if row["operation"] == "setns")["outcome"] = "denied"
    elif fault == "identitytype":
        value["identity"]["dumpable"] = 1.0
    elif fault == "blocked":
        value["kind"] = "blocked"
    elif fault == "extrarow":
        rows.append(dict(operation="operator_says_ok"))
    elif fault == "extrafield":
        value["verified"] = True
    elif fault == "badrow":
        rows[-1] = True
    before = deepcopy((start, value))
    with pytest.raises(ValueError):
        r.validate_result(raw(value), start, peer_pid=123)
    assert (start, value) == before


@pytest.mark.parametrize(
    "wire",
    [
        b'{"kind":1,"kind":2}\n',
        b'{"value":NaN}\n',
        b"{}\n{}\n",
        b"{}",
        b"x" * 65537 + b"\n",
    ],
)
def test_duplicate_nonfinite_trailing_or_oversized_raw_frame_refuses(wire):
    with pytest.raises((ValueError, OSError)):
        r.parse_ready(wire, "probe", boot=BOOT, worker_sha256=SHA)


@pytest.mark.parametrize(
    "key,value",
    [
        ("memory_total_kib", 1000.5),
        ("memory_total_kib", 1000.0),
        ("memory_available_kib", 500.0),
        ("swap_total_kib", 0.0),
        ("swap_free_kib", 0.0),
        ("load1", 1),
        ("load5", 0),
        ("load15", 0),
        ("uptime_seconds", 1000),
    ],
)
def test_parser_metric_type_substitution_refuses_without_rewriting(
    tmp_path, key, value
):
    start, observed = final(tmp_path)
    original = observed["operations"][1]["sample"]["system"][key]
    assert type(original) is (int if "_kib" in key else float)
    observed["operations"][1]["sample"]["system"][key] = value
    wire = raw(observed)
    with pytest.raises(ValueError, match="actual global sample metrics"):
        r.validate_result(wire, start, peer_pid=123)
    assert raw(observed) == wire


@pytest.mark.parametrize("fault", ["missing", "reorder", "enoent", "einval", "success"])
def test_binfmt_api_requires_both_actual_ordered_permission_denials(tmp_path, fault):
    start, value = final(tmp_path)
    rows = value["operations"]
    assert rows[3]["operation"].endswith("binfmt_misc/status")
    assert rows[4]["operation"].endswith("binfmt_misc/register")
    if fault == "missing":
        rows.pop(4)
    elif fault == "reorder":
        rows[3], rows[4] = rows[4], rows[3]
    elif fault == "success":
        rows[3]["outcome"] = "unexpected_success"
    else:
        rows[3]["errno"] = errno.ENOENT if fault == "enoent" else errno.EINVAL
    before = deepcopy(value)
    with pytest.raises(ValueError):
        r.validate_result(raw(value), start, peer_pid=123)
    assert value == before


@pytest.mark.parametrize(
    "code",
    [errno.EPERM, errno.EACCES, errno.ENOENT, errno.EINVAL, errno.ENOSYS, errno.ESRCH],
)
def test_only_newuser_accepts_two_permission_denial_errnos(tmp_path, code):
    start, value = final(tmp_path)
    row = next(r for r in value["operations"] if r["operation"] == "unshare_newuser")
    row["errno"] = code
    before = deepcopy(value)
    if code in (errno.EPERM, errno.EACCES):
        assert r.validate_result(raw(value), start, peer_pid=123) == value
    else:
        with pytest.raises(ValueError):
            r.validate_result(raw(value), start, peer_pid=123)
    assert value == before


@pytest.mark.parametrize(
    "fault", ["partial", "blocked", "unsupported", "newnet_eacces"]
)
def test_newuser_permission_denial_never_promotes_incomplete_or_other_namespace_facts(
    tmp_path, fault
):
    start, value = final(tmp_path)
    rows = value["operations"]
    user = next(r for r in rows if r["operation"] == "unshare_newuser")
    user["errno"] = errno.EACCES
    if fault == "partial":
        value["operations"] = rows[: rows.index(user) + 1]
        assert len(value["operations"]) == 33
    elif fault == "blocked":
        value["kind"] = "blocked"
    elif fault == "unsupported":
        user["outcome"] = "unsupported_error"
    else:
        next(r for r in rows if r["operation"] == "unshare_newnet")["errno"] = (
            errno.EACCES
        )
    before = deepcopy(value)
    with pytest.raises(ValueError):
        r.validate_result(raw(value), start, peer_pid=123)
    assert value == before
