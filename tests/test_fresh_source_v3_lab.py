"""Synthetic four-stream lab barriers; no native capture or operational claims."""

import importlib.util
from pathlib import Path
import sys

import pytest

REAL = Path(__file__).parent / "real_systemd"
sys.path.insert(0, str(REAL))
import fresh_source_observe as lab  # noqa: E402


def chain(rows, schema):
    previous = "0" * 64
    result = b""
    for seq, (kind, data) in enumerate(rows, 1):
        raw = lab.accounting.canonical(
            dict(schema_version=schema, seq=seq, prev=previous, kind=kind, data=data)
        )
        result += raw
        previous = lab.accounting.sha256(raw)
    return result


def barrier_fixture(monkeypatch, *, kind="sample", fault=None):
    metadata, identity = dict(run_id="synthetic"), dict(native_tid=81)
    paths = {k: "/synthetic/" + k for k in ("calls", "phase", "context", "publication")}
    context = dict(
        files={
            "observer-config.json": lab.accounting.canonical(
                dict(paths=paths, metadata=metadata)
            )
        },
        load=dict(observer=dict(identity=identity)),
    )
    intent = dict(
        span_id=1,
        parent_id=None,
        phase="observation_" + kind,
        event_kind=None,
        event_seq=None,
        operation=kind,
    )
    span = dict(intent, native_tid=81, start_ns=11, end_ns=19, outcome="returned")
    if fault == "outside":
        span["end_ns"] = 21
    if fault == "wrong_kind":
        span["phase"] = "observation_finalize"
    if fault == "wrong_thread":
        span["native_tid"] = 82
    phase = [("header", dict(metadata, **identity)), ("intent", intent)]
    if fault != "unfinished":
        phase.append(("span", span))
    begin = dict(metadata=metadata, identity=identity)
    if fault == "context_identity":
        begin["identity"] = dict(native_tid=82)
    raws = dict(
        phase=chain(phase, "edge-fresh-phase-timing-record/v3"),
        context=chain([("begin", begin)], "edge-fresh-clock-context/v3"),
        calls=b"synthetic original call",
    )
    monkeypatch.setattr(
        lab,
        "decode_calls_prefix",
        lambda raw: dict(
            calls=[dict(seq=4, kind=kind, data=dict(start_ns=10, end_ns=20))]
        ),
    )
    monkeypatch.setattr(lab, "stable_read", lambda path, limit: (raws[path.name], {}))
    return context, raws


@pytest.mark.parametrize("kind", ["sample", "event"])
def test_four_stream_barrier_requires_exact_original_completed_phase(monkeypatch, kind):
    context, _ = barrier_fixture(monkeypatch, kind=kind)
    assert lab.four_stream_barrier_needs(context, 4) == dict(
        calls=4, phase=3, context=1
    )


@pytest.mark.parametrize(
    "fault", ["outside", "wrong_kind", "wrong_thread", "unfinished", "context_identity"]
)
def test_four_stream_barrier_rejects_mismatched_or_unfinished_rows(monkeypatch, fault):
    context, _ = barrier_fixture(monkeypatch, fault=fault)
    with pytest.raises((AssertionError, StopIteration)):
        lab.four_stream_barrier_needs(context, 4)


def test_explicit_v3_dispatch_collector_and_legacy_defaults():
    assert lab.FreshSourceObserveLab.version == 1
    assert lab.FreshSourceObserveV2Lab.version == 2
    assert lab.FreshSourceObserveV3Lab.version == 3
    assert lab.FreshSourceObserveV3Lab.core_module.endswith("fresh_source_observe_v3")
    assert lab.FreshObserverProcessV3.role_mode == "fresh-source-v3"
    spec = importlib.util.spec_from_file_location(
        "fresh_v3_collector",
        REAL.parents[1] / ".github/scripts/collect_fresh_source_observe.py",
    )
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    assert len(collector.NAMES | {"observer-publication.raw"}) == 49
    assert collector.file_limit("observer-publication.raw") == 1024 * 1024
    workflow = (REAL.parents[1] / ".github/workflows/ci.yml").read_text()
    assert "--native-core --fresh-source-observe-v3" in workflow
    assert "collect_fresh_source_observe.py --v3" in workflow


@pytest.mark.parametrize("stream", ["phase", "context"])
@pytest.mark.parametrize("committed", [False, True])
def test_v3_barrier_rejects_visible_uncommitted_phase_context(
    monkeypatch, stream, committed
):
    context, raws = barrier_fixture(monkeypatch)
    # A visible suffix is never selected as the durable prefix.
    prefix = raws[stream]
    visible = prefix + b"uncommitted suffix"
    obj = dict(device=9, inode=99, owner_uid=61002, mode=0o100600, nlink=1)
    clock = dict(start_ns=10, end_ns=20)
    commit = dict(
        stream=stream,
        first_seq=1,
        last_seq=3,
        rows=3,
        bytes=len(prefix),
        sha256=lab.accounting.sha256(prefix),
        object=dict(device=9, inode=99, owner_uid=61002, mode=0o100600, link_count=1),
        worker_native_tid=82,
        write=clock,
        fsync=dict(start_ns=20, end_ns=30),
    )
    entries = [
        (
            "header",
            dict(
                metadata=dict(run_id="synthetic"),
                identity=dict(native_tid=81),
                limits={},
            ),
        )
    ]
    if committed:
        entries.append(("commit", commit))
    publication = chain(entries, "edge-observer-publication/v2")
    monkeypatch.setattr(
        lab,
        "stable_read",
        lambda path, limit: (publication, {})
        if path.name == "publication"
        else (visible, dict(object=obj)),
    )
    result = lab.publication_commits(context, {stream: 3}, version=3)
    if committed:
        assert result[0][stream] == dict(
            size=len(prefix), sha256=lab.accounting.sha256(prefix)
        )
    else:
        assert result is None


@pytest.mark.parametrize("case", ["fresh-controls", "fresh-interrupted"])
def test_composed_v3_originals_and_publication(case):
    from fresh_source_data_v3 import make_fresh_case, pins
    from azazel_edge.benchmark import fresh_source_observe_v3 as core

    artifacts = make_fresh_case(case)
    expected = pins(artifacts)
    result = lab.evaluate_fresh_observer_originals(artifacts, expected, version=3)
    assert result["error"] is None
    assert (
        core.evaluate_publication(artifacts, expected=expected)["status"] == "qualified"
    )
    if case == "fresh-controls":
        assert result["normal_completion"] is True
        assert result["clock"]["status"] == "qualified"
    else:
        assert result["fault_verified"] is True and result["clock"] is None


def test_v3_rejects_phase_previous_write_cost_profile():
    import json
    from fresh_source_data_v3 import make_fresh_case, pins

    artifacts = make_fresh_case()
    rows = []
    for raw in artifacts["observer-phase.raw"].splitlines():
        row = json.loads(raw)
        row["data"]["previous_write_cost"] = row["data"].pop("previous_enqueue_cost")
        rows.append((row["kind"], row["data"]))
    artifacts["observer-phase.raw"] = chain(rows, "edge-fresh-phase-timing-record/v3")
    result = lab.evaluate_fresh_observer_originals(
        artifacts, pins(artifacts), version=3
    )
    assert result["status"] == "withheld" and result["error"] is not None
