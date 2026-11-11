"""Synthetic public signatures/read-only imports; no VM/measurement acceptance."""

import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from auth_input_helpers import make_policy
from test_outcome_input_auth import signed
from test_signed_network_run import signed_source_fixture, decision, release, KERNEL
from azazel_edge.outcome.input_auth import SourceVerifier, sign
from azazel_edge.outcome.input_witness import ANCHOR_DOMAIN
from azazel_edge.outcome.journal import _json, ZERO_HASH
from azazel_edge.outcome.input_terminal import TerminalControlStop

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_read as reader


def journal(rows):
    raw, frames, head = b"", [], ZERO_HASH
    for seq, (kind, data) in enumerate(rows, 1):
        body = dict(seq=seq, prev=head, kind=kind, data=data)
        head = reader.sha(_json(body))
        frames.append(dict(**body, sha256=head))
        raw += _json(frames[-1]) + b"\n"
    return raw, frames


def anchor_material(tmp_path):
    trust, pk, wk, *_ = make_policy(tmp_path)
    source = signed(trust, pk)
    raw, frames = journal([("header", {}), ("session_close", {})])
    info = SimpleNamespace(st_dev=2, st_ino=3)
    previous, anchors = ZERO_HASH, []
    for seq in range(3):
        prefix = b"" if seq == 0 else b"".join(raw.splitlines(keepends=True)[:seq])
        data = b"" if seq == 0 else source
        tip = SourceVerifier(trust).verify(data)
        state = dict(
            journal_seq=seq,
            journal_head=frames[seq - 1]["sha256"] if seq else ZERO_HASH,
            journal_size=len(prefix),
            journal_sha256=reader.sha(prefix),
            journal_device=2 if seq else 0,
            journal_inode=3 if seq else 0,
            **{"source_" + k: v for k, v in tip.items()},
        )
        core = dict(
            schema_version="outcome-input-anchor/v1",
            counter=seq + 1,
            prev=previous,
            trust_sha256=trust.digest,
            state=state,
        )
        wire = dict(**core, signature=sign(wk, ANCHOR_DOMAIN, core))
        anchors.append(wire)
        previous = reader.digest(wire)
    return trust, wk, source, raw, frames, anchors, info


def encode(anchors):
    return b"".join(_json(a) + b"\n" for a in anchors)


def test_actual_public_anchor_signatures_bind_every_prefix(tmp_path):
    trust, _, source, raw, frames, anchors, info = anchor_material(tmp_path)
    original = (source, raw, encode(anchors))
    parsed, verified, state = reader.witnessed_prefixes(trust, *original, info)
    assert parsed == frames and verified.raw == source and state == anchors[-1]["state"]
    assert original == (source, raw, encode(anchors))


@pytest.mark.parametrize(
    "fault",
    [
        "signature",
        "domain",
        "trust",
        "counter",
        "prev",
        "sourcehash",
        "journalhash",
        "inode",
        "nonboundary",
        "missingfinal",
        "partial",
        "genesis",
    ],
)
def test_signed_anchor_or_prefix_mismatch_refuses(tmp_path, fault):
    trust, wk, source, raw, _, anchors, info = anchor_material(tmp_path)
    if fault == "missingfinal":
        anchors.pop()
    elif fault == "partial":
        with pytest.raises(Exception):
            reader.witnessed_prefixes(trust, source, raw, encode(anchors)[:-1], info)
        return
    else:
        a = anchors[-1]
        if fault == "signature":
            a["signature"] = "00" * 64
        elif fault == "trust":
            a["trust_sha256"] = "00" * 32
        elif fault == "counter":
            a["counter"] = True
        elif fault == "prev":
            a["prev"] = "00" * 32
        elif fault == "sourcehash":
            a["state"]["source_sha256"] = "00" * 32
        elif fault == "journalhash":
            a["state"]["journal_sha256"] = "00" * 32
        elif fault == "inode":
            a["state"]["journal_inode"] += 1
        elif fault == "nonboundary":
            a["state"]["source_size"] -= 1
        elif fault == "genesis":
            anchors[0]["state"]["source_seq"] = 1
        # Re-sign altered metadata: even a valid signature cannot excuse bad binding.
        if fault != "signature":
            for a in anchors:
                core = {k: v for k, v in a.items() if k != "signature"}
                a["signature"] = sign(
                    wk, b"wrong-domain" if fault == "domain" else ANCHOR_DOMAIN, core
                )
    with pytest.raises(Exception):
        reader.witnessed_prefixes(trust, source, raw, encode(anchors), info)


def terminal_material(tmp_path, monkeypatch):
    source_reader, state, append = signed_source_fixture(tmp_path, monkeypatch)
    event = decision()
    append("decision_execution", 2, event)
    append("release", 3, release(event))
    append("session_end", 4)
    source_reader.poll(terminal=True)
    source = state["raw"]
    wires = source.splitlines(keepends=True)
    positions, offset = [], 0
    for line in wires:
        offset += len(line)
        positions.append(dict(offset=offset, sha256=reader.sha(source[:offset])))
    context = dict(
        kernel_boot_id=KERNEL,
        boot_ref=reader.n.boot_reference(KERNEL),
        signed_boot_ref=KERNEL.replace("-", ""),
        scope_ref=source_reader.trust.data["scope_ref"],
        registration_sha256=source_reader.trust.data["origin_registration_sha256"],
        source_start_position=positions[1],
    )
    decoded = SourceVerifier.unwrap(wires[-1])
    terminal = TerminalControlStop(
        context["registration_sha256"],
        source_reader.verifier.live_state.session,
        source_reader.verifier.live_state.seq,
        positions[-2],
        positions[-1],
        wires[-1],
        decoded,
        0,
    ).to_dict()
    rows = [
        ("header", {}),
        ("session_open", dict(boot_id=context["boot_ref"])),
        ("input_ready", dict(offset=0, sha256=reader.sha(b""))),
        ("session_close", {}),
        ("session_open", dict(boot_id=context["boot_ref"])),
    ]
    for index, pos in enumerate(positions):
        rows.append(("cursor", dict(position=pos, missed=index in (0, 1, 4))))
        if index == 1:
            rows.append(("input_ready", pos))
    rows.append(("session_close", {}))
    _, frames = journal(rows)
    return (
        source_reader,
        source,
        frames,
        dict(context=context, terminal=terminal),
        wires[-1],
        decoded,
    )


def test_authentic_complete_signed_terminal_and_c0_chain_is_required(
    tmp_path, monkeypatch
):
    r, source, frames, result, wire, decoded = terminal_material(tmp_path, monkeypatch)
    assert (
        len(
            reader.terminal_chain(
                r.trust, source, frames, r.verifier, result, wire, decoded
            )
        )
        == 5
    )


@pytest.mark.parametrize(
    "fault",
    [
        "wire",
        "decoded",
        "boot",
        "cursor",
        "missedactivity",
        "closeremoved",
        "missingready",
        "lost",
        "missingcursor",
        "terminalclaim",
        "recovery",
    ],
)
def test_terminal_or_c0_chain_gap_never_waived(tmp_path, monkeypatch, fault):
    r, source, frames, result, wire, decoded = terminal_material(tmp_path, monkeypatch)
    if fault == "wire":
        wire += b" "
    elif fault == "decoded":
        decoded += b" "
    elif fault == "boot":
        result["context"]["kernel_boot_id"] = "1" * 32
    elif fault == "cursor":
        frames[-2]["data"]["position"]["sha256"] = "0" * 64
    elif fault == "missedactivity":
        frames[8]["data"]["missed"] = True
    elif fault == "closeremoved":
        frames.pop()
    elif fault == "missingready":
        frames[:] = [f for f in frames if f["kind"] != "input_ready"]
    elif fault == "lost":
        frames.insert(-1, dict(kind="lost", data={}))
    elif fault == "missingcursor":
        frames.pop(-3)
    elif fault == "terminalclaim":
        result["terminal"]["resume_authorized"] = True
    elif fault == "recovery":
        frames.insert(-1, dict(kind="session_recovered", data={}))
    with pytest.raises(Exception):
        reader.terminal_chain(
            r.trust, source, frames, r.verifier, result, wire, decoded
        )


def test_partial_import_retains_independent_service_facts_without_writes(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(reader.phase, "WORK", tmp_path)
    original_read = reader.read_regular
    monkeypatch.setattr(
        reader,
        "read_regular",
        lambda path, **kw: original_read(
            path, owner=os.geteuid(), max_bytes=kw["max_bytes"]
        ),
    )
    service = {"unchanged": [1, 2], "independent": True}
    path = tmp_path / "service-audit.json"
    path.write_bytes(_json(service) + b"\n")
    path.chmod(0o600)
    monkeypatch.setattr(
        reader.phase,
        "validated_inputs",
        lambda *a: (_ for _ in ()).throw(ValueError("missing run")),
    )
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    result = reader.read_assignment_artifacts("a" * 64, "b" * 64)
    assert result["status"] == "withheld" and result["measurement_record"] is None
    assert result["independent_service_facts"] == dict(service=service)
    assert result["raw_sha256"][str(path)]["sha256"] == reader.sha(before[path.name])
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert result["measurement_completed"] is result["production_admission"] is False


def test_snapshot_replacement_cannot_return_calculation(tmp_path):
    path = tmp_path / "owned"
    path.write_bytes(b"first")
    path.chmod(0o600)
    snap = reader._Snapshot(dict(raw_sha256={}))
    snap.raw(path, os.geteuid())
    path.unlink()
    path.write_bytes(b"second")
    path.chmod(0o600)
    with pytest.raises(Exception):
        snap.unchanged()


def test_failed_run_retains_unverified_live_facts_and_raw_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(reader.phase, "WORK", tmp_path)
    monkeypatch.setattr(reader.g, "BUNDLE", tmp_path / "bundle")
    directory = reader.g.BUNDLE / "observer"
    directory.mkdir(parents=True)
    live = dict(original="retained without qualification")
    raw, _ = journal([("header", {}), ("commit", dict(outcome=live))])
    (directory / "observations.journal").write_bytes(raw)
    calls = b'{"partial":'
    (directory / "actual-collector-calls.jsonl").write_bytes(calls)
    original = reader.read_regular
    monkeypatch.setattr(
        reader,
        "read_regular",
        lambda path, **kw: original(
            path, owner=os.geteuid(), max_bytes=kw["max_bytes"]
        ),
    )
    monkeypatch.setattr(
        reader.phase,
        "validated_inputs",
        lambda *a: (_ for _ in ()).throw(ValueError("failed run")),
    )
    result = reader.read_assignment_artifacts("a" * 64, "b" * 64)
    assert result["status"] == "withheld" and result["measurement_record"] is None
    assert result["live_outcomes"] == [live]
    assert result["live_outcomes_authentication"] == "unverified_retained_facts"
    assert result["raw_sha256"][str(directory / "actual-collector-calls.jsonl")][
        "sha256"
    ] == reader.sha(calls)
    assert (directory / "observations.journal").read_bytes() == raw
    assert (directory / "actual-collector-calls.jsonl").read_bytes() == calls


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "writable"])
def test_import_snapshot_refuses_unsafe_file(tmp_path, fault):
    path = tmp_path / "evidence"
    actual = tmp_path / "actual"
    actual.write_bytes(b"unchanged")
    actual.chmod(0o600)
    if fault == "symlink":
        path.symlink_to(actual)
    elif fault == "hardlink":
        os.link(actual, path)
    else:
        path.write_bytes(b"unchanged")
        path.chmod(0o666)
    with pytest.raises(Exception):
        reader._Snapshot(dict(raw_sha256={})).raw(path, os.geteuid())
    assert actual.read_bytes() == b"unchanged"
