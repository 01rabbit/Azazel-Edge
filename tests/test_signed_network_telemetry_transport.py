"""Synthetic Root/unit observations; no socket, role or namespace is created."""

from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
import os
import json
import sys
from types import SimpleNamespace

import pytest
from azazel_edge.outcome.input_transport import transport
from azazel_edge.outcome.input_auth import read_regular

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_transport as t


BOOT = "095d28ff-ca7d-4b08-9e4b-e36a62db4810"
COOKIE = dict(cookie=71, kernel_boot_id=BOOT)


HEADER = "Num       RefCount Protocol Flags    Type St Inode Path\n"


def socket_row(name, inode="12345", flags="00010000", kind="0001", state="01"):
    return (
        f"0000000000000000: 00000002 00000000 {flags} {kind} {state} {inode} @{name}\n"
    )


def table(name):
    return HEADER + socket_row(name)


def fixture(tmp_path, monkeypatch, fault):
    monkeypatch.setattr(t.g, "boot", lambda: BOOT)
    monkeypatch.setattr(t.g, "UNITS", tmp_path)
    monkeypatch.setattr(t.g, "guard", lambda: None)
    monkeypatch.setattr(t.p, "_output", lambda path: None)
    monkeypatch.setenv(t.material.FLAG, "1")
    unit = tmp_path / t.g.WITNESS
    unit.write_text(
        "[Service]\nType=exec\nNotifyAccess=none\nExecStart="
        + t.witness_command()
        + "\nNetworkNamespacePath="
        + t.role.NSFS_TARGETS[0]
        + "\n"
    )
    before = dict(
        LoadState="loaded",
        ActiveState="active",
        MainPID="4321",
        ControlPID="0",
        ControlGroup="/system.slice/" + t.g.WITNESS,
        pid_stat="4321 (witness) " + " ".join(["S"] + ["0"] * 18 + ["123"]),
    )
    count = []

    def state(_):
        count.append(1)
        value = deepcopy(before)
        if fault == "pid" and len(count) == 2:
            value["MainPID"] = "4322"
        return value

    monkeypatch.setattr(t.lab, "unit_snapshot", state)
    reads = []

    def read(path, **kw):
        assert path == unit and kw == dict(owner=0, max_bytes=16384)
        reads.append(1)
        info = unit.stat()
        if fault == "file" and len(reads) == 2:
            return b"changed", info
        return unit.read_bytes(), info

    monkeypatch.setattr(t.p, "read_regular", read)
    # Root ownership is synthetic; keep actual protected-parent/type/bounds checks
    # for the private retained query files under the test runner's real UID.
    monkeypatch.setattr(
        t.material,
        "_read",
        lambda path, limit=1024 * 1024, mode=None: read_regular(
            path, owner=os.getuid(), max_bytes=limit, mode=mode
        )[0],
    )
    label = "other (enforce)\n" if fault == "label" else "edge400-witness (enforce)\n"
    name = transport("synthetic-scope", COOKIE)["name"]
    monkeypatch.setattr(
        t.p.cg,
        "_kernel_text",
        lambda path, limit: table(name) if path.endswith("/net/unix") else label,
    )
    monkeypatch.setattr(
        t,
        "os",
        SimpleNamespace(
            environ=t.os.environ,
            scandir=lambda path: nullcontext(iter([SimpleNamespace(name="3")])),
            readlink=lambda path: "socket:[12345]",
            stat=lambda path: SimpleNamespace(
                st_dev=5, st_ino=99 if fault == "namespace" else 20
            ),
        ),
    )
    expected = dict(
        Type="exec",
        NotifyAccess="none",
        User="root",
        Group="root",
        AppArmorProfile="edge400-witness",
        NetworkNamespacePath=t.role.NSFS_TARGETS[0],
        NoNewPrivileges="yes",
        CapabilityBoundingSet="cap_dac_read_search",
        AmbientCapabilities="",
        RestrictAddressFamilies="AF_UNIX",
        Restart="no",
        DropInPaths="",
        FragmentPath=str(unit),
        ExecStart="{ path="
        + str(t.g.PYTHON)
        + " ; argv[]="
        + t.witness_command()
        + " ; ignore_errors=no }",
    )
    if fault in ("command", "fragment", "caps", "dropins", "type", "notify"):
        expected[
            {
                "type": "Type",
                "notify": "NotifyAccess",
                "command": "ExecStart",
                "fragment": "FragmentPath",
                "caps": "CapabilityBoundingSet",
                "dropins": "DropInPaths",
            }[fault]
        ] = "unexpected"

    def query(argv, prefix, output):
        raw = "".join(k + "=" + v + "\n" for k, v in expected.items()).encode()
        if fault == "duplicate":
            raw += b"User=root\n"
        t.lab.save(output / (prefix + ".stdout"), raw)
        t.lab.save(
            output / (prefix + ".stderr"), b"warning" if fault == "stderr" else b""
        )
        return 1 if fault == "rc" else 0, raw

    monkeypatch.setattr(t.p.old, "_retained_query", query)
    return dict(
        scope_ref="synthetic-scope",
        trust_schema="outcome-input-trust/v4",
        witness_transport=transport("synthetic-scope", COOKIE),
    )


def test_stable_witness_context_excludes_mutable_protocol_counters(
    tmp_path, monkeypatch
):
    auth = fixture(tmp_path, monkeypatch, None)
    first = t.witness_binding(auth, [5, 20], tmp_path, "initialize-initial", COOKIE)
    second = t.witness_binding(auth, [5, 20], tmp_path, "live-initial", COOKIE)
    assert first == second and first["pid"] == 4321 and first["start_ticks"] == "123"
    assert first["witness_transport"] == auth["witness_transport"]
    assert not {"counter", "source_seq", "journal_seq"} & set(first)
    assert (tmp_path / "witness-live-initial.json").exists()


@pytest.mark.parametrize(
    "fault",
    [
        "pid",
        "file",
        "label",
        "namespace",
        "command",
        "type",
        "notify",
        "fragment",
        "caps",
        "dropins",
        "duplicate",
        "stderr",
        "rc",
    ],
)
def test_actual_context_gap_refuses_with_retained_root_facts(
    tmp_path, monkeypatch, fault
):
    auth = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises(AssertionError):
        t.witness_binding(auth, [5, 20], tmp_path, "initialize-before-go", COOKIE)
    assert (tmp_path / "witness-initialize-before-go-sample-0.json").exists()


@pytest.mark.parametrize("fault", ["old", "different-edge", "unknown-phase"])
def test_no_legacy_or_namespace_or_path_selector_fallback(tmp_path, monkeypatch, fault):
    auth = fixture(tmp_path, monkeypatch, None)
    if fault == "old":
        auth["trust_schema"] = "outcome-input-trust/v3"
    with pytest.raises(AssertionError):
        t.witness_binding(
            auth,
            [5, 21] if fault == "different-edge" else [5, 20],
            tmp_path,
            "../other" if fault == "unknown-phase" else "initialize-initial",
            COOKIE,
        )


def test_initial_absence_only_wait_has_unique_raw_samples_before_success(
    tmp_path, monkeypatch
):
    auth = fixture(tmp_path, monkeypatch, None)
    name = auth["witness_transport"]["name"]
    calls = []
    original = t.p.cg._kernel_text

    def kernel(path, limit):
        if path.endswith("/net/unix"):
            calls.append(path)
            return HEADER if len(calls) <= 2 else table(name)
        return original(path, limit)

    monkeypatch.setattr(t.p.cg, "_kernel_text", kernel)
    value = t.witness_binding(auth, [5, 20], tmp_path, "initialize-initial", COOKIE)
    assert value["listener"] == dict(inode="12345", fd="3", abstract_name=name)
    assert len(calls) == 4
    assert (
        tmp_path / "witness-initialize-initial-sample-0-unix-before.raw"
    ).read_text() == HEADER
    assert (
        tmp_path / "witness-initialize-initial-sample-1-unix-before.raw"
    ).read_text() == table(name)
    receipt = json.loads((tmp_path / "witness-initialize-initial.json").read_bytes())
    assert [row["listener"] for row in receipt["samples"]] == [None, value["listener"]]


@pytest.mark.parametrize(
    "phase",
    [
        "initialize-before-go",
        "initialize-after-init",
        "live-initial",
        "live-before-go",
        "live-after-terminal",
    ],
)
def test_later_absence_never_waits_or_retries(tmp_path, monkeypatch, phase):
    auth = fixture(tmp_path, monkeypatch, None)
    original = t.p.cg._kernel_text
    monkeypatch.setattr(
        t.p.cg,
        "_kernel_text",
        lambda path, limit: HEADER
        if path.endswith("/net/unix")
        else original(path, limit),
    )
    monkeypatch.setattr(
        t.time, "sleep", lambda seconds: pytest.fail("later phase must not poll")
    )
    with pytest.raises(AssertionError, match="listener absent"):
        t.witness_binding(auth, [5, 20], tmp_path, phase, COOKIE)
    assert not (tmp_path / ("witness-" + phase + "-sample-1.json")).exists()


def test_initial_absence_timeout_stays_blocked_without_extra_sample(
    tmp_path, monkeypatch
):
    auth = fixture(tmp_path, monkeypatch, None)
    original = t.p.cg._kernel_text
    monkeypatch.setattr(
        t.p.cg,
        "_kernel_text",
        lambda path, limit: HEADER
        if path.endswith("/net/unix")
        else original(path, limit),
    )
    ticks = iter([0, 0, 3])  # Deadline, post-sample, absence decision.
    monkeypatch.setattr(t.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(t.time, "sleep", lambda seconds: pytest.fail("expired wait"))
    with pytest.raises(AssertionError, match="listener absent"):
        t.witness_binding(auth, [5, 20], tmp_path, "initialize-initial", COOKIE)
    assert not (tmp_path / "witness-initialize-initial-sample-1.json").exists()


@pytest.mark.parametrize("fault", ["pid", "label", "namespace", "cookie"])
def test_absent_wait_does_not_tolerate_identity_drift(tmp_path, monkeypatch, fault):
    auth = fixture(tmp_path, monkeypatch, None)
    original_kernel = t.p.cg._kernel_text
    original_state = t.lab.unit_snapshot
    state_count = []
    net_count = []

    def state(unit):
        state_count.append(unit)
        result = original_state(unit)
        if fault == "pid" and len(state_count) > 2:
            result["MainPID"] = "4322"
            result["pid_stat"] = result["pid_stat"].replace("4321", "4322")
        return result

    def kernel(path, limit):
        if path.endswith("/net/unix"):
            net_count.append(path)
            return HEADER
        if fault == "label" and len(state_count) > 2:
            return "other (enforce)\n"
        return original_kernel(path, limit)

    monkeypatch.setattr(t.lab, "unit_snapshot", state)
    monkeypatch.setattr(t.p.cg, "_kernel_text", kernel)
    original_stat = t.os.stat
    monkeypatch.setattr(
        t.os,
        "stat",
        lambda path: SimpleNamespace(st_dev=5, st_ino=21)
        if fault == "namespace" and len(state_count) > 2
        else original_stat(path),
    )
    # Each new sample checks current boot against the independently sampled descriptor.
    monkeypatch.setattr(
        t.g,
        "boot",
        lambda: "195d28ff-ca7d-4b08-9e4b-e36a62db4810"
        if fault == "cookie" and len(state_count) >= 2
        else BOOT,
    )
    with pytest.raises(AssertionError):
        t.witness_binding(auth, [5, 20], tmp_path, "initialize-initial", COOKIE)
    assert len(net_count) <= 4


@pytest.mark.parametrize(
    "raw",
    [
        "",
        HEADER.rstrip("\n"),
        "unexpected\n",
        HEADER + "broken\n",
        HEADER + socket_row("expected", kind="0002"),
        HEADER + socket_row("expected", flags="00010001"),
        HEADER + socket_row("expected", state="03"),
        HEADER + socket_row("expected", inode="0"),
        HEADER + socket_row("expected", inode="0123"),
        HEADER + socket_row("expected", inode=str(2**64)),
        HEADER + socket_row("expected") + socket_row("expected", inode="12346"),
        HEADER + socket_row("expected") + socket_row("other"),
    ],
)
def test_socket_table_rejects_unknown_ambiguous_or_invalid_listener(raw):
    with pytest.raises(AssertionError):
        t._listener_row(raw, "expected")


def test_connected_accepted_stream_row_does_not_impersonate_listener():
    raw = table("expected") + socket_row(
        "expected", inode="12346", flags="00000000", state="03"
    )
    assert t._listener_row(raw, "expected") == "12345"
    assert (
        t._listener_row(
            HEADER + socket_row("expected", flags="00000000", state="01"), "expected"
        )
        is None
    )


@pytest.mark.parametrize(
    "fault", ["missing", "duplicate", "changed", "readerror", "injected", "oversized"]
)
def test_listener_requires_unique_stable_same_pid_fd_and_retains_partial(
    tmp_path, monkeypatch, fault
):
    auth = fixture(tmp_path, monkeypatch, None)
    names = ["3", "4"] if fault == "duplicate" else ["3"]
    if fault == "injected":
        names = ["../../outside"]
    if fault == "oversized":
        names = [str(number) for number in range(257)]
    monkeypatch.setattr(
        t.os,
        "scandir",
        lambda path: nullcontext(iter(SimpleNamespace(name=name) for name in names)),
    )
    calls = []

    def link(path):
        assert path.startswith("/proc/4321/fd/")
        calls.append(path)
        if fault == "readerror":
            raise PermissionError("synthetic FD metadata refusal")
        return (
            "socket:[999]"
            if fault == "missing" or fault == "changed" and len(calls) > 1
            else "socket:[12345]"
        )

    monkeypatch.setattr(t.os, "readlink", link)
    with pytest.raises((AssertionError, PermissionError)):
        t.witness_binding(auth, [5, 20], tmp_path, "initialize-before-go", COOKIE)
    prefix = "witness-initialize-before-go-sample-0"
    assert (tmp_path / (prefix + "-unix-before.raw")).exists()
    retained = json.loads((tmp_path / (prefix + "-listener.json")).read_bytes())
    assert retained["error"] in ("AssertionError", "PermissionError")
    if fault == "injected":
        assert retained["names"] == names and calls == []


def transition_tables(name, fault=None):
    before = socket_row(name, flags="00000000").rsplit(" @", 1)[0] + "\n"
    if fault == "replaced-inode":
        before = before.replace("12345", "99999")
    if fault == "type":
        before = before.replace("0001 01", "0002 01")
    if fault == "connected":
        before = before.replace("0001 01", "0001 03")
    if fault == "refcount":
        before = before.replace("00000002", "00000003", 1)
    if fault == "already-named":
        before = socket_row("other", flags="00000000")
    after = table(name)
    if fault == "malformed":
        after += "malformed\n"
    return HEADER + before, after


def install_transition(tmp_path, monkeypatch, fault=None, repeat=False):
    auth = fixture(tmp_path, monkeypatch, "pid" if fault == "pid" else None)
    before, after = transition_tables(auth["witness_transport"]["name"], fault)
    original = t.p.cg._kernel_text
    calls = []

    def kernel(path, limit):
        if path.endswith("/net/unix"):
            calls.append(path)
            return (
                before if (len(calls) == 1 or repeat and len(calls) % 2 == 1) else after
            )
        return original(path, limit)

    monkeypatch.setattr(t.p.cg, "_kernel_text", kernel)
    if fault == "fd":
        monkeypatch.setattr(t.os, "readlink", lambda path: "socket:[99999]")
    return auth, before, after, calls


def test_exact_startup_forward_transition_requires_fresh_complete_stable_sample(
    tmp_path, monkeypatch
):
    auth, before, after, calls = install_transition(tmp_path, monkeypatch)
    value = t.witness_binding(auth, [5, 20], tmp_path, "initialize-initial", COOKIE)
    assert len(calls) == 4
    assert value["listener"] == dict(
        inode="12345", fd="3", abstract_name=auth["witness_transport"]["name"]
    )
    prefix = "witness-initialize-initial-sample-0"
    assert (tmp_path / (prefix + "-unix-before.raw")).read_text() == before
    assert (tmp_path / (prefix + "-unix-after.raw")).read_text() == after
    pending = json.loads((tmp_path / (prefix + "-listener.json")).read_bytes())
    assert pending["startup_transition_pending"] == dict(inode="12345", fd="3")
    first = json.loads((tmp_path / (prefix + ".json")).read_bytes())
    assert (
        first["after"] == first["before"]
    )  # Final PID/start/unit fence WAS completed.
    receipt = json.loads((tmp_path / "witness-initialize-initial.json").read_bytes())
    assert [sample["listener"] for sample in receipt["samples"]] == [
        None,
        value["listener"],
    ]


@pytest.mark.parametrize(
    "fault",
    [
        "replaced-inode",
        "refcount",
        "type",
        "connected",
        "already-named",
        "malformed",
        "fd",
        "pid",
    ],
)
def test_startup_transition_cannot_hide_bad_socket_or_final_identity_fence(
    tmp_path, monkeypatch, fault
):
    auth, _, _, calls = install_transition(tmp_path, monkeypatch, fault)
    with pytest.raises(AssertionError):
        t.witness_binding(auth, [5, 20], tmp_path, "initialize-initial", COOKIE)
    assert len(calls) <= 2
    assert not (tmp_path / "witness-initialize-initial-sample-1.json").exists()
    if fault == "pid":
        pending = json.loads(
            (
                tmp_path / "witness-initialize-initial-sample-0-listener.json"
            ).read_bytes()
        )
        assert "startup_transition_pending" in pending
        final = json.loads(
            (tmp_path / "witness-initialize-initial-sample-0.json").read_bytes()
        )
        assert final["before"]["MainPID"] != final["after"]["MainPID"]


@pytest.mark.parametrize(
    "phase", ["initialize-before-go", "live-initial", "live-after-terminal"]
)
def test_later_phase_exact_forward_transition_remains_fatal(
    tmp_path, monkeypatch, phase
):
    auth, _, _, calls = install_transition(tmp_path, monkeypatch)
    with pytest.raises(AssertionError, match="listener changed"):
        t.witness_binding(auth, [5, 20], tmp_path, phase, COOKIE)
    assert len(calls) == 2
    assert not (tmp_path / ("witness-" + phase + "-sample-1.json")).exists()


def test_transition_pending_does_not_extend_original_two_second_deadline(
    tmp_path, monkeypatch
):
    auth, _, _, calls = install_transition(tmp_path, monkeypatch)
    ticks = iter(
        [0, 3]
    )  # Original deadline, AFTER full transition sample/final fences.
    monkeypatch.setattr(t.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(t.time, "sleep", lambda seconds: pytest.fail("expired wait"))
    with pytest.raises(AssertionError, match="exceeded two seconds"):
        t.witness_binding(auth, [5, 20], tmp_path, "initialize-initial", COOKIE)
    assert len(calls) == 2


def test_initial_absence_still_hits_existing_101_sample_cap(tmp_path, monkeypatch):
    auth = fixture(tmp_path, monkeypatch, None)
    calls = []
    original = t.p.cg._kernel_text

    def absent(path, limit):
        if path.endswith("/net/unix"):
            calls.append(path)
            return HEADER
        return original(path, limit)

    monkeypatch.setattr(t.p.cg, "_kernel_text", absent)
    monkeypatch.setattr(t.time, "monotonic", lambda: 0)
    monkeypatch.setattr(t.time, "sleep", lambda seconds: None)
    with pytest.raises(AssertionError, match="listener absent"):
        t.witness_binding(auth, [5, 20], tmp_path, "initialize-initial", COOKIE)
    receipt = json.loads((tmp_path / "witness-initialize-initial.json").read_bytes())
    assert len(receipt["samples"]) == 101 and len(calls) == 202
    assert all(sample["listener"] is None for sample in receipt["samples"])


@pytest.mark.parametrize(
    "fault", ["replacement", "disappearance", "not-stable", "fd-change"]
)
def test_next_complete_sample_must_hold_same_pending_listener_candidate(
    tmp_path, monkeypatch, fault
):
    auth = fixture(tmp_path, monkeypatch, None)
    name = auth["witness_transport"]["name"]
    before, after = transition_tables(name)
    original = t.p.cg._kernel_text
    calls = []

    def kernel(path, limit):
        if not path.endswith("/net/unix"):
            return original(path, limit)
        calls.append(path)
        if len(calls) == 1:
            return before
        if len(calls) == 2:
            return after
        if fault == "replacement":
            return after.replace("12345", "99999")
        if fault == "disappearance":
            return HEADER
        if fault == "not-stable":
            return before if len(calls) % 2 else after
        return after

    monkeypatch.setattr(t.p.cg, "_kernel_text", kernel)
    monkeypatch.setattr(
        t.os,
        "readlink",
        lambda path: "socket:[99999]"
        if fault == "replacement" and len(calls) >= 3
        else "socket:[12345]",
    )
    monkeypatch.setattr(
        t.os,
        "scandir",
        lambda path: nullcontext(
            iter(
                [
                    SimpleNamespace(
                        name="4" if fault == "fd-change" and len(calls) >= 3 else "3"
                    )
                ]
            )
        ),
    )
    with pytest.raises(AssertionError, match="pending startup listener"):
        t.witness_binding(auth, [5, 20], tmp_path, "initialize-initial", COOKIE)
    assert len(calls) == 4
    assert not (tmp_path / "witness-initialize-initial-sample-2.json").exists()
    receipt = json.loads((tmp_path / "witness-initialize-initial.json").read_bytes())
    assert len(receipt["samples"]) == 2
