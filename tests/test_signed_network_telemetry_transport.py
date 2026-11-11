"""Synthetic Root/unit observations; no socket, role or namespace is created."""

from copy import deepcopy
from pathlib import Path
import os
import sys
from types import SimpleNamespace

import pytest
from azazel_edge.outcome.input_transport import transport
from azazel_edge.outcome.input_auth import read_regular

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_transport as t


BOOT = "095d28ff-ca7d-4b08-9e4b-e36a62db4810"
COOKIE = dict(cookie=71, kernel_boot_id=BOOT)


def fixture(tmp_path, monkeypatch, fault):
    monkeypatch.setattr(t.g, "boot", lambda: BOOT)
    monkeypatch.setattr(t.g, "UNITS", tmp_path)
    monkeypatch.setattr(t.g, "guard", lambda: None)
    monkeypatch.setattr(t.p, "_output", lambda path: None)
    monkeypatch.setenv(t.material.FLAG, "1")
    unit = tmp_path / t.g.WITNESS
    unit.write_text(
        "[Service]\nExecStart="
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
    monkeypatch.setattr(t.p.cg, "_kernel_text", lambda path, limit: label)
    monkeypatch.setattr(
        t,
        "os",
        SimpleNamespace(
            environ=t.os.environ,
            stat=lambda path: SimpleNamespace(
                st_dev=5, st_ino=99 if fault == "namespace" else 20
            ),
        ),
    )
    expected = dict(
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
    if fault in ("command", "fragment", "caps", "dropins"):
        expected[
            {
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
    assert (tmp_path / "witness-initialize-before-go.json").exists()


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
