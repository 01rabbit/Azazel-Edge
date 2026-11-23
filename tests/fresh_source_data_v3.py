"""SYNTHETIC TEST-key v3 originals; never rewrites acquired v1/v2 trial bytes."""

from copy import deepcopy
import json
from pathlib import Path

from fresh_source_data_v2 import make_fresh_case as synthetic_v2
from fresh_source_data import chain, pins
from safety_observation_data import digest
from test_native_close_receipts import wire, rewrite

REAL = Path(__file__).parent / "real_systemd"
PROTOCOL_SHA256 = "01f653e970f4313aaa6066219ded163e21c0753ee97d5ded5cbfedd2872a938a"
CASES = ("fresh-controls", "fresh-interrupted")


def clock(ns):
    return dict(
        start_ns=ns,
        end_ns=ns + 1,
        process_cpu_start_ns=ns // 10,
        process_cpu_end_ns=ns // 10 + 1,
        thread_cpu_start_ns=ns // 20,
        thread_cpu_end_ns=ns // 20 + 1,
    )


def make_fresh_case(case="fresh-controls"):
    from fresh_publication import V3_LIMITS

    a = synthetic_v2(case)
    a["protocol.json"] = (REAL / "fresh-source-observe-protocol-v3.json").read_bytes()
    names = [
        "fresh-timestamp-receipts.json",
        "corpus-manifest.json",
        "observer-config.json",
        "fresh-controller.json",
        "load-controller.json",
    ]
    v = {n: json.loads(a[n]) for n in names}
    for data in v.values():
        data["schema_version"] = data["schema_version"].removesuffix("/v2") + "/v3"
        data["protocol_sha256"] = PROTOCOL_SHA256
    config = v["observer-config.json"]
    load = v["load-controller.json"]
    control = v["fresh-controller.json"]
    observer = load["observer"]
    metadata = config["metadata"]
    identity = observer["identity"]
    observer["bootstrap"]["schema_version"] = "edge-fresh-source-observer-bootstrap/v3"
    for name, schema in [
        ("observer-context.raw", "edge-fresh-clock-context/v3"),
        ("observer-input-calls.raw", "edge-fresh-input-record/v3"),
    ]:
        old = [json.loads(x) for x in a[name].splitlines()]
        a[name] = chain([(r["kind"], r["data"]) for r in old], schema, 1, True)
    # Real-shape synthetic phase bodies are nested strictly inside actual recorded
    # original wrapper intervals, not merely joined by SID or event name.
    header = json.loads(a["observer-phase.raw"].splitlines()[0])["data"]
    header.pop("previous_write_cost", None)
    header["previous_enqueue_cost"] = None
    phase = [("header", header)]
    enqueue = [300_000_000]
    calls = [json.loads(x) for x in a["observer-calls.raw"].splitlines()]
    span = 0
    for call in calls:
        if call["kind"] not in ("sample", "event"):
            continue
        span += 1
        data = call["data"]
        ns = data["start_ns"]
        ctx = dict(
            span_id=span,
            parent_id=None,
            phase="observation_sample"
            if call["kind"] == "sample"
            else "observation_event",
            event_kind=None,
            event_seq=None,
            operation=None,
        )
        phase.append(
            (
                "intent",
                dict(
                    ctx,
                    previous_enqueue_cost=dict(seq=len(phase), **clock(enqueue[-1])),
                ),
            )
        )
        enqueue.append(ns - 5)
        timing = clock(ns + 1)
        timing["end_ns"] = data["end_ns"] - 1
        phase.append(
            (
                "span",
                dict(
                    ctx,
                    **timing,
                    outcome="returned",
                    native_tid=identity["native_tid"],
                    previous_enqueue_cost=dict(seq=len(phase), **clock(enqueue[-1])),
                ),
            )
        )
        enqueue.append(data["end_ns"] + 1)
    if case == "fresh-controls":
        phase.append(
            (
                "end",
                dict(
                    normal_return=True,
                    incomplete=False,
                    previous_enqueue_cost=dict(seq=len(phase), **clock(enqueue[-1])),
                ),
            )
        )
    a["observer-phase.raw"] = chain(phase, "edge-fresh-phase-timing-record/v3", 1, True)
    v["corpus-manifest.json"]["timestamp_receipts_sha256"] = digest(
        wire(v["fresh-timestamp-receipts.json"])
    )
    control.update(
        timestamp_receipts_sha256=digest(wire(v["fresh-timestamp-receipts.json"])),
        input_manifest_sha256=digest(wire(v["corpus-manifest.json"])),
        input_calls_sha256=digest(a["observer-input-calls.raw"]),
    )
    streams = dict(
        calls="observer-calls.raw",
        input_calls="observer-input-calls.raw",
        phase="observer-phase.raw",
        context="observer-context.raw",
    )
    for stream, name in streams.items():
        meta = observer["sidecars"][stream]
        for when in ("before", "after"):
            meta[when]["size"] = len(a[name])
        meta.update(size=len(a[name]), sha256=digest(a[name]))
    items = [
        (
            "header",
            dict(
                metadata=deepcopy(metadata),
                identity=deepcopy(identity),
                limits=deepcopy(V3_LIMITS),
            ),
        )
    ]
    last = dict.fromkeys(streams, 0)

    def commit(stream, count, ns):
        body = b"".join(a[streams[stream]].splitlines(keepends=True)[:count])
        meta = observer["sidecars"][stream]["before"]
        d = dict(
            stream=stream,
            first_seq=last[stream] + (0 if stream == "calls" else 1),
            last_seq=count - (1 if stream == "calls" else 0),
            rows=count,
            bytes=len(body),
            sha256=digest(body),
            object=dict(
                device=meta["device"],
                inode=meta["inode"],
                owner_uid=meta["owner_uid"],
                mode=meta["mode"],
                link_count=meta["nlink"],
            ),
            worker_native_tid=31,
            write=clock(ns),
            fsync=clock(ns + 10),
        )
        items.append(("commit", d))
        last[stream] = count

    commit("calls", 2, 600_000_000)
    commit("phase", 3, 600_000_100)
    commit("context", 1, 600_000_200)

    def checkpoint(body):
        return dict(size=len(body), sha256=digest(body))

    phase_ready = b"".join(a["observer-phase.raw"].splitlines(keepends=True)[:3])
    ctxbegin = a["observer-context.raw"].splitlines(keepends=True)[0]
    control["readiness"].update(
        publication_checkpoint=checkpoint(
            chain(items, "edge-observer-publication/v2", 1, True)
        ),
        phase_checkpoint=checkpoint(phase_ready),
        context_checkpoint=checkpoint(ctxbegin),
    )
    commit("calls", 3, 4_020_000_000)
    commit("input_calls", 3, 4_020_000_100)
    commit("phase", 5, 4_020_000_200)
    if case == "fresh-controls":
        for i, stream in enumerate(streams):
            commit(
                stream, len(a[streams[stream]].splitlines()), 11_050_000_000 + i * 100
            )
        marks = {}
        for stream, name in streams.items():
            raw = a[name]
            count = len(raw.splitlines())
            mark = dict(
                rows=count,
                last_seq=count - (1 if stream == "calls" else 0),
                bytes=len(raw),
                sha256=digest(raw),
            )
            marks[stream] = {
                k: deepcopy(mark) for k in ("enqueued", "written", "fsynced")
            }
        items.append(
            (
                "end",
                dict(
                    normal_return=True,
                    complete=True,
                    incomplete=False,
                    error=None,
                    streams=marks,
                    close=clock(11_060_000_000),
                ),
            )
        )
    a["observer-publication.raw"] = chain(
        items, "edge-observer-publication/v2", 1, True
    )
    if case == "fresh-interrupted":
        control["interrupt_boundary"].update(
            input_calls_checkpoint=checkpoint(a["observer-input-calls.raw"]),
            publication_checkpoint=checkpoint(a["observer-publication.raw"]),
            phase_checkpoint=checkpoint(
                b"".join(a["observer-phase.raw"].splitlines(keepends=True)[:5])
            ),
            context_checkpoint=checkpoint(ctxbegin),
        )
    pubmeta = observer["sidecars"]["publication"]
    for when in ("before", "after"):
        pubmeta[when]["size"] = len(a["observer-publication.raw"])
    pubmeta.update(
        size=len(a["observer-publication.raw"]),
        sha256=digest(a["observer-publication.raw"]),
    )
    if case == "fresh-controls":
        c = json.loads(a["observer-completion.json"])
        c["schema_version"] = "edge-fresh-observer-completion/v3"
        for stream, name in dict(
            streams, publication="observer-publication.raw"
        ).items():
            c["sidecars"][stream] = dict(bytes=len(a[name]), sha256=digest(a[name]))
        a["observer-completion.json"] = wire(c)
        meta = observer["sidecars"]["completion"]
        for when in ("before", "after"):
            meta[when]["size"] = len(a["observer-completion.json"])
        meta.update(
            size=len(a["observer-completion.json"]),
            sha256=digest(a["observer-completion.json"]),
        )
    for name, data in v.items():
        a[name] = wire(data)
    for name in ("ingress-controller.json", "code-pins.json"):
        data = json.loads(a[name])
        data["protocol_sha256"] = PROTOCOL_SHA256
        a[name] = wire(data)
    c = json.loads(a["close-controller.json"])
    c["protocol_sha256"] = PROTOCOL_SHA256
    root = json.loads(a["root-custody.raw"].splitlines()[-1])
    rewrite(a, c, root)
    return a


def make_fresh_run():
    from azazel_edge.benchmark import fresh_source_observe_v3 as core

    cases = {case: make_fresh_case(case) for case in CASES}
    for case, a in cases.items():
        a["evaluation.json"] = wire(
            core.evaluate_fresh_source_case(a, expected=pins(a))
        )
    revision = json.loads(cases[CASES[0]]["code-pins.json"])["source_revision"]
    run = "a" * 32
    snapshots = {
        case: wire(
            dict(
                schema_version="edge-fresh-snapshot/v1",
                case_id=case,
                run_ref=run,
                protocol_sha256=PROTOCOL_SHA256,
                source_revision=revision,
                files=pins(a),
            )
        )
        for case, a in cases.items()
    }
    disposition = wire(
        dict(
            schema_version="edge-fresh-run-disposition/v1",
            protocol_sha256=PROTOCOL_SHA256,
            source_revision=revision,
            run_ref=run,
            started_ns=10,
            finished_ns=30_000_000_000,
            cases=[
                dict(
                    case_id=case,
                    state="accepted",
                    snapshot_manifest_sha256=digest(snapshots[case]),
                    evaluation_sha256=digest(cases[case]["evaluation.json"]),
                    error=None,
                    cleanup_errors=[],
                )
                for case in CASES
            ],
            errors=[],
        )
    )
    return dict(
        cases=cases,
        snapshots=snapshots,
        disposition=disposition,
        expected=dict(
            cases={case: pins(a) for case, a in cases.items()},
            snapshots={case: digest(raw) for case, raw in snapshots.items()},
            disposition=digest(disposition),
        ),
    )
