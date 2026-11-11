"""Real recorder/pipe bytes; declared synthetic Root/namespace identities, no VM."""

import hashlib
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark.benefit import BenefitInputError
from test_signed_network_recording import collect

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_run as run


@pytest.fixture
def recorder(tmp_path, monkeypatch):
    path = tmp_path / "collector"
    event, _ = collect(path)
    closed = path.read_bytes()
    opened = b"".join(closed.splitlines(keepends=True)[:-1])
    monkeypatch.setattr(run.phase, "WORK", tmp_path)
    monkeypatch.setattr(
        run,
        "read_regular",
        lambda *a, **k: (
            path.read_bytes(),
            SimpleNamespace(st_dev=4, st_ino=5, st_uid=61002),
        ),
    )
    return path, event, closed, opened


@pytest.mark.parametrize("tail", [b"", b'{"partial'])
def test_actual_callback_retains_original_bytes_and_original_complete_row(
    recorder, tail
):
    path, event, _, opened = recorder
    path.write_bytes(opened + tail)
    receipt = run._callback(
        event,
        "active",
        session=SimpleNamespace(poll=lambda: None),
        deadline_ns=time.monotonic_ns() + 1_000_000_000,
    )
    root = path.parent
    assert (root / "active-callback-observation-0.raw").read_bytes() == opened + tail
    assert (root / "active-callback-prefix.raw").read_bytes() == opened + tail
    assert (root / "active-callback-complete.raw").read_bytes() == opened
    assert receipt["row"]["data"]["event"] == event
    assert receipt["raw_sha256"] == hashlib.sha256(opened + tail).hexdigest()
    assert receipt["partial_tail_bytes"] == len(tail)
    assert receipt["recording_identity"] == dict(device=4, inode=5, uid=61002)
    assert receipt["observed_before_ns"] <= receipt["observed_after_ns"]
    # Later real sample/finalize calls follow the event; it need not be last.
    assert run.recording.decode_calls_prefix(opened)["calls"][-1] != receipt["row"]


@pytest.mark.parametrize(
    "fault", ["closed", "bad-complete", "future-clock", "duplicate"]
)
def test_callback_refusal_retains_failure_bytes_without_ready_authority(
    recorder, fault
):
    path, event, closed, opened = recorder
    raw = closed if fault == "closed" else opened
    if fault == "bad-complete":
        raw += b'{"invalid"}\n{'
    if fault in {"future-clock", "duplicate"}:
        rows = [json.loads(line) for line in opened.splitlines()]
        row = next(row for row in rows if row["kind"] == "event")
        if fault == "future-clock":
            row["data"]["clock_after"]["monotonic_after_ns"] = (
                time.monotonic_ns() + 10**12
            )
        else:
            rows.insert(rows.index(row) + 1, json.loads(json.dumps(row)))
        previous = "0" * 64
        for index, row in enumerate(rows):
            row["seq"], row["prev"] = index, previous
            row["sha256"] = run.recording.manifest_digest(
                {k: row[k] for k in ("seq", "prev", "kind", "data")}
            )
            previous = row["sha256"]
        raw = b"".join(run.recording.canonical(row) + b"\n" for row in rows)
    path.write_bytes(raw)
    with pytest.raises((BenefitInputError, ValueError)):
        run._callback(
            event,
            "active",
            session=SimpleNamespace(poll=lambda: None),
            deadline_ns=time.monotonic_ns() + 10**9,
        )
    assert (path.parent / "active-callback-observation-0.raw").read_bytes() == raw
    assert not (path.parent / "active-callback-ready.json").exists()


@pytest.mark.parametrize("fault", ["dead", "deadline", "kind", "missing"])
def test_no_callback_or_budget_never_produces_ready(recorder, monkeypatch, fault):
    path, event, _, opened = recorder
    path.write_bytes(opened.splitlines(keepends=True)[0])
    if fault == "missing":
        monkeypatch.setattr(run.time, "sleep", lambda _: None)
    with pytest.raises(BenefitInputError):
        run._callback(
            event,
            "other" if fault == "kind" else "active",
            session=SimpleNamespace(poll=lambda: 1 if fault == "dead" else None),
            deadline_ns=time.monotonic_ns() + (-1 if fault == "deadline" else 10**9),
        )
    assert not (path.parent / "active-callback-ready.json").exists()


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "bool-root",
        "pid",
        "partial",
        "nonzero",
        "late-wall",
        "early-mono",
        "horizon",
    ],
)
def test_root_query_binds_raw_original_child_and_callback_cutoffs(
    tmp_path, monkeypatch, fault
):
    monkeypatch.setattr(run.phase, "WORK", tmp_path)
    identity = dict(
        source_revision="a" * 40, helper_sha256="b" * 64, network_driver_sha256="c" * 64
    )
    monkeypatch.setattr(run, "_source_identity", lambda: identity)
    monkeypatch.setattr(run.g, "boot", lambda: "boot-actual-fixture")
    now = time.monotonic_ns()
    receipt = dict(
        root_pid=123,
        root_uid=0,
        argv=list(run.flow.QUERY),
        returncode=0,
        source_identity=identity,
        kernel_boot_id="boot-actual-fixture",
        netns_inode=2,
        stdout='{"nftables":[]}',
        stderr="",
        query_started_at="2026-11-12T00:00:01+00:00",
        query_ended_at="2026-11-12T00:00:01.100000+00:00",
        query_start_clock_anchor=dict(monotonic_before_ns=now),
        query_end_clock_anchor=dict(monotonic_after_ns=now),
    )
    callback = dict(observed_after_ns=now - 1, row=dict(data=dict(epoch=1794441600.0)))
    if fault == "bool-root":
        receipt["root_uid"] = False
    if fault == "pid":
        receipt["root_pid"] = 999
    if fault == "late-wall":
        callback["row"]["data"]["epoch"] -= 3
    if fault == "early-mono":
        receipt["query_start_clock_anchor"]["monotonic_before_ns"] = now - 2
    raw = json.dumps(receipt).encode() + (b"" if fault == "partial" else b"\n")
    read, write = os.pipe()
    os.write(write, raw)
    os.close(write)
    with os.fdopen(read, "rb") as stream:
        child = SimpleNamespace(
            pid=123,
            args=["original-child"],
            stdout=stream,
            returncode=1 if fault == "nonzero" else 0,
            wait=lambda **kw: 0,
        )
        assets = SimpleNamespace(
            created={run.p.EDGE: (None, 1, 2)}, spawn=lambda *a, **kw: child
        )
        kwargs = dict(
            deadline_ns=time.monotonic_ns() + 10**9,
            callback=callback,
            horizon_ns=now - 1 if fault == "horizon" else now + 10**9,
        )
        if fault:
            with pytest.raises(BenefitInputError):
                run.root_query(assets, "active", {}, **kwargs)
        else:
            assert run.root_query(assets, "active", {}, **kwargs)[0] == receipt
    assert (tmp_path / "active-query.raw").read_bytes() == raw
    launch = json.loads((tmp_path / "active-query-launch.json").read_bytes())
    assert launch["pid"] == 123 and launch["actual_child_argv"] == ["original-child"]
    assert launch["launch_before_ns"] <= launch["launch_after_ns"]
    assert (tmp_path / "active-query.json").exists() == (fault is None)


@pytest.mark.parametrize("fault", ["source", "intent", "cleanup-too"])
def test_direct_preparation_context_cleanup_survives_early_runner_failure(
    tmp_path, monkeypatch, fault
):
    """Synthetic ownership context; no actor creation or authentication claim."""
    import types

    events = []
    original = RuntimeError("original-source-failure")

    def source():
        if fault != "intent":
            raise original
        return {}

    def close():
        events.append("context-close")
        if fault == "cleanup-too":
            raise ValueError("independent cleanup failed")

    ctx = SimpleNamespace(inputs={}, close=close)
    prep = types.ModuleType("signed_network_telemetry_phase")
    prep.prepare_telemetry_assignment = lambda *a, **k: ctx
    monkeypatch.setitem(sys.modules, prep.__name__, prep)
    monkeypatch.setattr(run.phase, "WORK", tmp_path)
    monkeypatch.setattr(run.g, "boot", lambda: "fixture-boot")
    monkeypatch.setattr(run, "_source_identity", source)
    if fault == "intent":
        save = run.n.write_new

        def fail_intent(path, value):
            if path.name == "run-intent.json":
                raise original
            return save(path, value)

        monkeypatch.setattr(run.n, "write_new", fail_intent)
    with pytest.raises(RuntimeError) as caught:
        run.run_telemetry_assignment(
            tmp_path,
            **{
                k: "a" * 64
                for k in (
                    "manifest_sha256",
                    "start_head",
                    "source_commit",
                    "archive_sha256",
                    "core_sha256",
                    "abi_sha256",
                    "interpreter_sha256",
                )
            },
        )
    assert caught.value is original and events == ["context-close"]
    assert not (tmp_path / "run-facts.json").exists()
    failure = json.loads((tmp_path / "run-failure.json").read_bytes())
    assert failure["status"] == "withheld" and failure["error"] == "RuntimeError"
    if fault == "cleanup-too":
        assert any(
            "Owned context cleanup: ValueError" in note
            for note in caught.value.__notes__
        )


@pytest.mark.parametrize("fault", ["label", "callback-not-yet-retained"])
def test_query_cannot_spawn_before_closed_kind_and_retained_callback(
    tmp_path, monkeypatch, fault
):
    monkeypatch.setattr(run.phase, "WORK", tmp_path)
    spawned = []
    assets = SimpleNamespace(spawn=lambda *a, **kw: spawned.append(a))
    with pytest.raises(BenefitInputError):
        run.root_query(
            assets,
            "unknown" if fault == "label" else "active",
            {},
            deadline_ns=time.monotonic_ns() + 10**9,
            callback=dict(observed_after_ns=time.monotonic_ns() + 10**9),
        )
    assert spawned == [] and list(tmp_path.iterdir()) == []
