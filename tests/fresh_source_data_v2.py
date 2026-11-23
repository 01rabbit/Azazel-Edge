"""Prospective v2 SYNTHETIC TEST-key fixture; never converts acquired v1 evidence.

Old fixture is a test-data constructor only. No original trial bytes are read or
rewritten. All actors/publication/timing assertions below are synthetic.
"""

from copy import deepcopy
import json
from pathlib import Path

from azazel_edge.benchmark import fresh_source_observe_v2 as core
from fresh_source_data import make_fresh_case as make_synthetic_v1, chain, pins, anchor
from test_native_close_receipts import obj, wire, rewrite
from safety_observation_data import digest

REAL = Path(__file__).parent / "real_systemd"


def make_fresh_case(case="fresh-controls"):
    a = make_synthetic_v1(case)
    a["observer-publication.raw"] = None
    a["protocol.json"] = (REAL / "fresh-source-observe-protocol-v2.json").read_bytes()
    names = [
        "fresh-timestamp-receipts.json",
        "corpus-manifest.json",
        "observer-config.json",
        "fresh-controller.json",
        "load-controller.json",
    ]
    values = {name: json.loads(a[name]) for name in names}
    for name, v in values.items():
        v["schema_version"] = v["schema_version"].removesuffix("/v1") + "/v2"
        v["protocol_sha256"] = core.PROTOCOL_SHA256
    config = values["observer-config.json"]
    load = values["load-controller.json"]
    control = values["fresh-controller.json"]
    config["paths"]["publication"] = str(
        Path(config["paths"]["input_calls"]).with_name("publication.raw")
    )
    top = (REAL / "fresh_source_observer.py").read_bytes()
    dep = (REAL / "fresh_source_recording.py").read_bytes()
    publication = (REAL / "fresh_publication.py").read_bytes()
    config["helper_sha256"] = digest(top)
    config["metadata"]["code_sha256"] = digest(top + b"\0" + dep + b"\0" + publication)
    metadata = config["metadata"]
    observer = load["observer"]
    identity = observer["identity"]
    observer["bootstrap"]["schema_version"] = "edge-fresh-source-observer-bootstrap/v2"
    # Reconstruct newly declared synthetic v2 rows directly from test assertions.
    for name, schema in [
        ("observer-phase.raw", "edge-fresh-phase-timing-record/v2"),
        ("observer-context.raw", "edge-fresh-clock-context/v2"),
        ("observer-input-calls.raw", "edge-fresh-input-record/v2"),
    ]:
        items = []
        for line in a[name].splitlines():
            row = json.loads(line)
            data = row["data"]
            if row["kind"] == "header":
                data.update(metadata)
            if row["kind"] == "begin":
                data["metadata"] = deepcopy(metadata)
            items.append((row["kind"], data))
        a[name] = chain(items, schema, 1, True)
    values["corpus-manifest.json"]["timestamp_receipts_sha256"] = digest(
        wire(values["fresh-timestamp-receipts.json"])
    )
    control.update(
        timestamp_receipts_sha256=digest(wire(values["fresh-timestamp-receipts.json"])),
        input_manifest_sha256=digest(wire(values["corpus-manifest.json"])),
        input_calls_sha256=digest(a["observer-input-calls.raw"]),
    )
    if case == "fresh-interrupted":
        control["interrupt_boundary"]["input_calls_checkpoint"] = dict(
            size=len(a["observer-input-calls.raw"]),
            sha256=digest(a["observer-input-calls.raw"]),
        )
    # Correct original sidecar object snapshots bind final reconstructed bytes.
    sidefiles = dict(
        phase="observer-phase.raw",
        context="observer-context.raw",
        input_calls="observer-input-calls.raw",
    )
    for key, name in sidefiles.items():
        meta = observer["sidecars"][key]
        for when in ("before", "after"):
            meta[when]["size"] = len(a[name])
        meta.update(size=len(a[name]), sha256=digest(a[name]))
    pubitems = [
        (
            "header",
            dict(
                metadata=deepcopy(metadata),
                identity=deepcopy(identity),
                limits=deepcopy(core.LIMITS),
            ),
        )
    ]
    bystream = {
        k: a[name].splitlines(keepends=True) for k, name in core.STREAMS.items()
    }
    last = {k: 0 for k in core.STREAMS}

    def clock(ns):
        return dict(
            start_ns=ns,
            end_ns=ns + 10,
            process_cpu_start_ns=ns // 10,
            process_cpu_end_ns=ns // 10 + 1,
            thread_cpu_start_ns=ns // 20,
            thread_cpu_end_ns=ns // 20 + 1,
        )

    def commit(stream, count, ns):
        lines = bystream[stream]
        body = b"".join(lines[:count])
        first = last[stream] + (0 if stream == "calls" else 1)
        lastseq = count - (1 if stream == "calls" else 0)
        meta = observer["sidecars"][stream]["before"]
        pubitems.append(
            (
                "commit",
                dict(
                    stream=stream,
                    first_seq=first,
                    last_seq=lastseq,
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
                    fsync=clock(ns + 20),
                ),
            )
        )
        last[stream] = count

    commit("calls", 2, 600_000_000)
    readyraw = chain(pubitems, "edge-observer-publication/v1", 1, True)
    control["readiness"]["publication_checkpoint"] = dict(
        size=len(readyraw), sha256=digest(readyraw)
    )
    commit("calls", 3, 4_020_000_000)
    commit("input_calls", 3, 4_020_000_100)
    if case == "fresh-controls":
        commit("calls", len(bystream["calls"]), 11_050_000_000)
        commit("input_calls", len(bystream["input_calls"]), 11_050_000_100)
        streams = {}
        for s, lines in bystream.items():
            body = b"".join(lines)
            mark = dict(
                rows=len(lines),
                last_seq=len(lines) - (1 if s == "calls" else 0),
                bytes=len(body),
                sha256=digest(body),
            )
            streams[s] = {k: deepcopy(mark) for k in ("enqueued", "written", "fsynced")}
        pubitems.append(
            (
                "end",
                dict(
                    normal_return=True,
                    complete=True,
                    incomplete=False,
                    error=None,
                    streams=streams,
                    close=clock(11_060_000_000),
                ),
            )
        )
    a["observer-publication.raw"] = chain(
        pubitems, "edge-observer-publication/v1", 1, True
    )
    pubmeta = obj(950, 61002, a["observer-publication.raw"])
    observer["sidecars"]["publication"] = dict(
        before=deepcopy(pubmeta),
        after=deepcopy(pubmeta),
        size=len(a["observer-publication.raw"]),
        sha256=digest(a["observer-publication.raw"]),
    )
    if case == "fresh-interrupted":
        control["interrupt_boundary"]["publication_checkpoint"] = dict(
            size=len(a["observer-publication.raw"]),
            sha256=digest(a["observer-publication.raw"]),
        )
    else:
        completion = json.loads(a["observer-completion.json"])
        completion.update(
            schema_version="edge-fresh-observer-completion/v2",
            metadata=deepcopy(metadata),
            publication=dict(
                joined=True,
                complete=True,
                incomplete=False,
                error=None,
                owner_close=clock(11_070_000_000),
            ),
            api_return_anchor=anchor(11_000_000_000),
        )
        # Main close must enclose worker stream-close + final publication stages.
        completion["publication"]["owner_close"]["start_ns"] = 11_040_000_000
        completion["publication"]["owner_close"]["process_cpu_start_ns"] = 1_104_000_000
        completion["publication"]["owner_close"]["thread_cpu_start_ns"] = 552_000_000
        for key, name in dict(
            sidefiles,
            calls="observer-calls.raw",
            publication="observer-publication.raw",
        ).items():
            completion["sidecars"][key] = dict(
                bytes=len(a[name]), sha256=digest(a[name])
            )
        a["observer-completion.json"] = wire(completion)
        meta = observer["sidecars"]["completion"]
        for when in ("before", "after"):
            meta[when]["size"] = len(a["observer-completion.json"])
        meta.update(
            size=len(a["observer-completion.json"]),
            sha256=digest(a["observer-completion.json"]),
        )
    for name, v in values.items():
        a[name] = wire(v)
    ingress = json.loads(a["ingress-controller.json"])
    ingress["protocol_sha256"] = core.PROTOCOL_SHA256
    a["ingress-controller.json"] = wire(ingress)
    c = json.loads(a["close-controller.json"])
    c["protocol_sha256"] = core.PROTOCOL_SHA256
    code = json.loads(a["code-pins.json"])
    code["protocol_sha256"] = core.PROTOCOL_SHA256
    a["code-pins.json"] = wire(code)
    root = json.loads(a["root-custody.raw"].splitlines()[-1])
    rewrite(a, c, root)
    return a


def make_fresh_run():
    cases = {case: make_fresh_case(case) for case in core.CASES}
    # Persist leaf evaluation first; snapshot/external inventory pins it independently.
    for case, a in cases.items():
        a["evaluation.json"] = wire(
            core.evaluate_fresh_source_case(a, expected=pins(a))
        )
    revision = json.loads(cases[core.CASES[0]]["code-pins.json"])["source_revision"]
    run = "a" * 32
    snapshots = {
        case: wire(
            dict(
                schema_version="edge-fresh-snapshot/v1",
                case_id=case,
                run_ref=run,
                protocol_sha256=core.PROTOCOL_SHA256,
                source_revision=revision,
                files=pins(a),
            )
        )
        for case, a in cases.items()
    }
    disposition = wire(
        dict(
            schema_version="edge-fresh-run-disposition/v1",
            protocol_sha256=core.PROTOCOL_SHA256,
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
                for case in core.CASES
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
            snapshots={case: digest(b) for case, b in snapshots.items()},
            disposition=digest(disposition),
        ),
    )
