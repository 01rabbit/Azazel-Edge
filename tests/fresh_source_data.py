"""Crypto-valid SYNTHETIC TEST-key originals, never actual Linux evidence.

make_fresh_case returns the exact 48 public original slots. All actors, clock
samples, callback returns and custody assertions here are synthetic test inputs.
"""

from copy import deepcopy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))

from azazel_edge.benchmark import fresh_source_observe as fresh
from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
from azazel_edge.outcome.journal import _json
from safety_observation_data import digest
from test_finite_load_cost import fixture as old_fixture
from test_finite_ingress import change_source
from test_native_close_receipts import obj, rewrite, stream, wire
from source_witness_data import sign_anchors, anchor_checkpoint

REAL = Path(__file__).parent / "real_systemd"
EPOCH = 1_800_000_000_000_000_000


def pins(a):
    return {k: digest(v) if type(v) is bytes else None for k, v in a.items()}


def chain(items, schema=None, start=0, full=False):
    raw = b""
    previous = "0" * 64
    for seq, (kind, data) in enumerate(items, start):
        row = dict(seq=seq, prev=previous, kind=kind, data=data)
        if schema:
            row["schema_version"] = schema
        if not full:
            row["sha256"] = digest(_json(row))
            previous = row["sha256"]
        line = wire(row)
        if full:
            previous = digest(line)
        raw += line
    return raw


def anchor(ns):
    return dict(
        monotonic_before_ns=ns, epoch_ns=EPOCH + ns + 5, monotonic_after_ns=ns + 10
    )


def make_fresh_case(case="fresh-controls"):
    if case not in fresh.CASES:
        raise ValueError(case)
    a, c, root, ic = old_fixture()
    a.update({k: None for k in fresh.FILES - a.keys()})
    a["protocol.json"] = (REAL / "fresh-source-observe-protocol-v1.json").read_bytes()
    c.update(case_id=case, protocol_sha256=fresh.PROTOCOL_SHA256)
    c["root_custody"]["relative_name"] = (
        "close-custody/" + case + "-" + "a" * 32 + ".raw"
    )
    a["code-pins.json"] = wire(
        {k: c[k] for k in ("source_revision", "protocol_sha256", "core_image_sha256")}
    )
    specs = fresh.event_specs(case)
    # Deterministic prospective write schedule; no timestamp retiming to callbacks.
    rows = []
    markers = []
    pieces = []
    offset = 0
    by_ref = {}
    nonalerts = fresh.nonalert_lines()
    for count, line in enumerate(nonalerts, 1):
        pieces.append(line)
        offset += len(line)
        for spec in [s for s in specs if s["after_nonalert"] == count]:
            ns = (
                1_000_000_000
                + count * 1_000_000_000 // 3000
                + (spec["occurrence"] - 1) * 100
            )
            if spec["duplicate_of"]:
                original = by_ref[spec["duplicate_of"]]
                alert = original["line"]
                generation = None
            else:
                generation = anchor(ns)
                alert = fresh.materialize_alert(spec, generation["epoch_ns"])
            decoded = json.loads(alert)
            from datetime import datetime

            ts = (
                int(
                    datetime.fromisoformat(
                        decoded["timestamp"].replace("Z", "+00:00")
                    ).timestamp()
                    * 1e6
                )
                * 1000
            )
            stamp = dict(
                **spec,
                generation_anchor=generation,
                timestamp_epoch_ns=ts,
                timestamp=decoded["timestamp"],
                start_offset=offset,
                end_offset=offset + len(alert),
                raw_sha256=digest(alert),
                materialization_before_ns=ns - 10,
                materialization_after_ns=ns + 20,
                write_before_ns=ns + 30,
                write_after_ns=ns + 40,
                error=None,
            )
            rows.append(stamp)
            by_ref[spec["event_ref"]] = dict(stamp=stamp, line=alert)
            markers.append(
                {
                    k: stamp[k]
                    for k in (
                        "event_ref",
                        "kind",
                        "sid",
                        "occurrence",
                        "after_nonalert",
                        "start_offset",
                        "end_offset",
                        "raw_sha256",
                        "timestamp",
                    )
                }
            )
            pieces.append(alert)
            offset += len(alert)
    raw = b"".join(pieces)
    timestamps = dict(
        schema_version="edge-fresh-timestamp-receipts/v1",
        case_id=case,
        protocol_sha256=fresh.PROTOCOL_SHA256,
        input_recipe_sha256=fresh.RECIPE_SHA256,
        rows=rows,
        errors=[],
    )
    a["fresh-timestamp-receipts.json"] = wire(timestamps)
    manifest = dict(
        schema_version="edge-fresh-input-manifest/v1",
        case_id=case,
        protocol_sha256=fresh.PROTOCOL_SHA256,
        input_recipe_sha256=fresh.RECIPE_SHA256,
        sha256=digest(raw),
        bytes=len(raw),
        lf_records=27004 + len(specs),
        nonalert_records=27004,
        per_class=dict.fromkeys(("flow", "dns", "stats", "http"), 6751),
        markers=markers,
        timestamp_receipts_sha256=digest(a["fresh-timestamp-receipts.json"]),
    )
    a["corpus-manifest.json"] = wire(manifest)
    n = json.loads(a["native-close.raw"])
    n["ingress"].update(
        committed_end_offset=len(raw),
        last_observed_length=len(raw),
        committed_bytes=len(raw),
        committed_sha256=digest(raw),
    )
    n["ingress"]["counts"].update(
        examined=27004 + len(specs),
        admitted=27004 + len(specs),
        alerts_admitted=len(specs),
        normalized_decisions=len(specs),
    )
    a["native-close.raw"] = wire(n)
    root["native_stream"] = stream(a["native-close.raw"])

    def replace(events):
        template = deepcopy(
            next(
                e for e in events if e["capture_origin"]["kind"] == "decision_execution"
            )
        )
        before = [
            e
            for e in events
            if e["capture_origin"]["kind"] not in ("decision_execution", "session_end")
        ]
        end = next(e for e in events if e["capture_origin"]["kind"] == "session_end")
        decisions = []
        for spec, marker in zip(specs, markers):
            e = deepcopy(template)
            e["normalized"].update(sid=spec["sid"], ts=marker["timestamp"])
            e["enforcement"]["trace_id"] = "fresh-" + (
                spec["duplicate_of"] or spec["event_ref"]
            )
            e["ingress_origin"] = dict(
                schema_version="azazel-edge/ingress-origin/v1",
                range_ref=c["session_ref"],
                device=8,
                inode=777,
                **{k: marker[k] for k in ("start_offset", "end_offset", "raw_sha256")},
            )
            decisions.append(e)
        events[:] = before + decisions + [end]
        for i, e in enumerate(events):
            e["capture_origin"]["seq"] = i
        for k in ("produced", "admitted", "enqueued", "written"):
            end["capture_lifecycle"]["counts"][k] = len(specs)

    change_source(a, c, root, replace)
    initial, final = obj(777, 0, b"", 0o644), obj(777, 0, raw, 0o644)
    for name in (
        "eve-start.raw",
        "eve-after-writer.raw",
        "eve-held-final.raw",
        "eve-path-final.raw",
    ):
        body = b"" if name == "eve-start.raw" else raw
        meta = initial if not body else final
        a[name] = body
        ic["snapshots"][name] = dict(
            before=deepcopy(meta),
            after=deepcopy(meta),
            sha256=digest(body),
            size=len(body),
            fd=5,
            flags=0,
        )
    finish = 12_000_000_000
    ic.update(case_id=case, protocol_sha256=fresh.PROTOCOL_SHA256, finished_ns=finish)
    ic["writer"][0].update(
        before=initial,
        after=final,
        offset_after=len(raw),
        requested_bytes=len(raw),
        written_bytes=len(raw),
        write_calls=27004 + len(specs),
        started_ns=1_000_000_000,
        finished_ns=10_001_333_443,
        joined_ns=10_001_333_444,
    )
    ic["held_fd"]["closed_ns"] = finish + 1
    tip = SourceVerifier(TrustPolicy(json.loads(a["trust.json"]))).verify(
        a["source-before.raw"]
    )
    ic["markers"][0].update(
        sid=specs[-1]["sid"],
        observed_ns=10_100_000_000,
        source_checkpoint=tip,
        ingress_origin=dict(
            schema_version="azazel-edge/ingress-origin/v1",
            range_ref=c["session_ref"],
            device=8,
            inode=777,
            **{k: markers[-1][k] for k in ("start_offset", "end_offset", "raw_sha256")},
        ),
    )
    a["ingress-controller.json"] = wire(ic)
    c["finished_ns"] = finish
    load = json.loads(a["load-controller.json"])
    load.update(
        schema_version="edge-fresh-load-controller/v1",
        case_id=case,
        protocol_sha256=fresh.PROTOCOL_SHA256,
        input_recipe_sha256=fresh.RECIPE_SHA256,
        corpus_sha256=digest(raw),
        finished_ns=finish,
    )
    load["writer"].update(
        started_ns=1_000_000_000,
        first_write_before_ns=1_000_000_000,
        marker_one_before_ns=rows[0]["write_before_ns"],
        final_nonalert_after_ns=10_001_333_443,
        finished_ns=10_001_333_443,
        joined_ns=10_001_333_444,
        before=initial,
        after=final,
        written_bytes=len(raw),
        write_calls=27004 + len(specs),
        sha256=digest(raw),
    )
    load["controller_identity"]["clock_domain"]["timens_offsets"] = [
        dict(clock=k, seconds=0, nanoseconds=0) for k in ("monotonic", "boottime")
    ]
    load["controller_identity"]["clock_resolutions"] = dict.fromkeys(
        ("monotonic", "process_time", "thread_time"), 1e-9
    )
    load["controller_anchors"] = dict(before=anchor(90), after=anchor(finish + 10))
    _observer(a, c, root, load, rows, case)
    a["load-controller.json"] = wire(load)
    rewrite(a, c, root)
    return a


def _observer(a, c, root, load, stamps, case):
    """Synthetic actor assertions and original-format records; no process run."""
    from azazel_edge.outcome.telemetry import (
        OutcomeTelemetryPolicy,
        persistence_context,
    )
    from azazel_edge.outcome.input_control_stop import ObserverControlStop
    from azazel_edge.benchmark.source_witness import _source_tips

    policy = TrustPolicy(json.loads(a["trust.json"]))
    source = a["source-after.raw"]
    tips = _source_tips(source)
    domain = deepcopy(load["controller_identity"]["clock_domain"])
    identity = dict(
        pid=30,
        start_ticks=130,
        native_tid=30,
        boot_id=c["boot_id"],
        clock_ticks_per_second=100,
        clock_domain=domain,
        clock_resolutions=dict.fromkeys(
            ("monotonic", "process_time", "thread_time"), 1e-9
        ),
    )
    actor = deepcopy(c["reader"]["actor"])
    actor.update(pid=30, start_ticks=130)
    run = "a" * 32
    bundle = "/var/lib/azazel-edge/outcome/edge400-" + run
    paths = {
        k: bundle + "/observer/" + v
        for k, v in dict(
            phase="phase.raw",
            calls="calls.raw",
            context="context.raw",
            completion="completion.json",
            journal="journal.raw",
            outcomes="outcomes.raw",
            input_calls="input-calls.raw",
        ).items()
    }
    paths.update(
        registration=bundle + "/origin.json",
        trust=bundle + "/trust.json",
        policy="/opt/edge400-src/tests/fixtures/signed_network_observer_policy.json",
    )
    top = (REAL / "fresh_source_observer.py").read_bytes()
    dep = (REAL / "fresh_source_recording.py").read_bytes()
    metadata = dict(
        run_id=run,
        arm=case,
        role="observer",
        input_recipe_sha256=fresh.RECIPE_SHA256,
        code_sha256=digest(top + b"\0" + dep),
        core_sha256=c["core_image_sha256"],
        interpreter_sha256="c" * 64,
    )
    config = dict(
        schema_version="edge-fresh-source-observer-config/v1",
        case_id=case,
        protocol_sha256=fresh.PROTOCOL_SHA256,
        input_recipe_sha256=fresh.RECIPE_SHA256,
        registration_sha256=c["registration_sha256"],
        trust_sha256=c["trust_sha256"],
        helper_sha256=digest(top),
        paths=paths,
        metadata=metadata,
    )
    a["observer-config.json"] = wire(config)
    pv = json.loads(
        (
            Path(__file__).parent / "fixtures/signed_network_observer_policy.json"
        ).read_bytes()
    )
    a["observer-policy.json"] = wire(pv)
    telemetry = OutcomeTelemetryPolicy.from_mapping(pv, source_ref=paths["policy"])
    pc = dict(
        policy_sha256=digest(_json(pv)),
        policy_source_ref=paths["policy"],
        policy_ref=telemetry.policy_ref,
    )
    selected = []
    offset = 0
    for line in source.splitlines(keepends=True):
        before = offset
        offset += len(line)
        event = json.loads(line)["event"]
        if event["capture_origin"]["kind"] == "decision_execution":
            selected.append(
                dict(
                    event=event,
                    position=dict(offset=offset, sha256=digest(source[:offset])),
                    before=dict(offset=before, sha256=digest(source[:before])),
                    tip=tips[offset],
                )
            )
    ready = selected[0]["before"]
    sourceobj = c["stores"]["source"]["after"]["object"]
    journalitems = [
        (
            "header",
            dict(
                scope_ref=policy.data["scope_ref"],
                input_config=dict(
                    device=sourceobj["device"],
                    inode=sourceobj["inode"],
                    uid=sourceobj["owner_uid"],
                    path_sha256=digest(policy.data["source_path"].encode()),
                    authentication=policy.binding(),
                ),
            ),
        ),
        ("input_ready", ready),
    ]
    callitems = [("begin", pc)]

    def call(kind, ns, **extra):
        callitems.append(
            (
                kind,
                dict(
                    epoch=(EPOCH + ns) / 1e9,
                    start_ns=ns + 20,
                    end_ns=ns + 30,
                    clock_before=anchor(ns),
                    clock_after=anchor(ns + 40),
                    **extra,
                ),
            )
        )
        return len(callitems) - 1

    call("sample", 500_000_000, sample=None)
    callsready = chain(callitems)
    binding = dict(
        case_id=case,
        run_id=run,
        registration_sha256=c["registration_sha256"],
        trust_sha256=c["trust_sha256"],
        input_recipe_sha256=fresh.RECIPE_SHA256,
    )
    inputs = [
        (
            "begin",
            dict(
                metadata=metadata,
                identity=identity,
                binding=binding,
                limits=dict(max_rows=256, max_bytes=4 * 1024 * 1024),
            ),
        )
    ]
    observations = []
    completed = 0
    callbacks = 0
    for index, (record, stamp) in enumerate(zip(selected, stamps), 1):
        ns = stamp["write_after_ns"] + 1_000_000 + index * 100_000
        eligible = stamp["kind"] not in ("stale", "future")
        observations.append(
            dict(
                event_ref=stamp["event_ref"],
                observed_ns=ns - 1,
                session_ref=c["session_ref"],
                source_position=record["position"],
                source_checkpoint=record["tip"],
                ingress_origin=record["event"]["ingress_origin"],
            )
        )
        if case == "fresh-interrupted" and index > 1:
            continue
        supplied = (EPOCH + ns) / 1e9
        inputs.append(
            (
                "input_intent",
                dict(
                    input_id=index,
                    decoded_event_sha256=digest(wire(record["event"])),
                    position=record["position"],
                    cursor_before=record["before"],
                    live_floor=(EPOCH + 500_000_000) / 1e9,
                    supplied_now=supplied,
                    start_ns=ns - 20,
                ),
            )
        )
        callback = []
        if eligible:
            seq = call("event", ns, event=record["event"], accepted=False)
            callbacks += 1
            n = record["event"]["normalized"]
            from datetime import datetime

            epoch = datetime.fromisoformat(n["ts"].replace("Z", "+00:00")).timestamp()
            activity = dict(
                epoch=epoch,
                src_ip=n["src_ip"],
                dst_ip=n["dst_ip"],
                target_port=n["target_port"],
                sid=n["sid"],
                evidence_ref="rust-activity:"
                + record["event"]["enforcement"]["trace_id"],
            )
            callback = [
                dict(
                    call_seq=seq,
                    event_sha256=digest(wire(record["event"])),
                    return_value=False,
                    observed_epoch=supplied,
                    activity=activity,
                )
            ]
        inputs.append(
            (
                "input_return",
                dict(
                    input_id=index,
                    end_ns=ns + 70,
                    handler_result=None,
                    cursor_after=record["position"],
                    callbacks=callback,
                ),
            )
        )
        journalitems.append(
            ("cursor", dict(position=record["position"], missed=not eligible))
        )
        completed += 1
    finalpos = selected[completed - 1]["position"]
    if case == "fresh-controls":
        inputs.append(
            (
                "end",
                dict(
                    completed_inputs=completed,
                    completed_callbacks=callbacks,
                    final_cursor=finalpos,
                    normal_return=True,
                    incomplete=False,
                ),
            )
        )
        callitems.append(("end", {}))
        journalitems.append(("session_close", {}))
    a["observer-calls.raw"] = chain(callitems)
    a["observer-input-calls.raw"] = chain(inputs, "edge-fresh-input-record/v1", 1, True)
    a["observer-journal.raw"] = chain(journalitems, start=1)
    a["observer-outcomes.raw"] = b""
    context = [
        (
            "begin",
            dict(metadata=metadata, identity=identity, anchor=anchor(300_000_000)),
        )
    ]
    phase = [("header", dict(**metadata, **identity))]
    if case == "fresh-controls":
        context.append(("end", dict(normal_return=True, anchor=anchor(11_000_000_000))))
        phase.append(("end", dict(normal_return=True, incomplete=False)))
    a["observer-context.raw"] = chain(context, "edge-fresh-clock-context/v1", 1, True)
    a["observer-phase.raw"] = chain(phase, "edge-fresh-phase-timing-record/v1", 1, True)
    a["observer-stdout.raw"] = b""
    a["observer-stderr.raw"] = b""
    observer = dict(
        identity=identity,
        actor=actor,
        error=None,
        command_verified=True,
        bootstrap=dict(
            schema_version="edge-fresh-source-observer-bootstrap/v1",
            pid=30,
            challenge=run,
            invocation_id="b" * 32,
        ),
        challenge=run,
        unit_properties=dict(MainPID="30", InvocationID="b" * 32),
        sidecars={},
        stdout_truncated=False,
        stderr_truncated=False,
        stdout_eof=True,
        stderr_eof=True,
        drain_errors=[],
        stdout_bytes=0,
        stderr_bytes=0,
        signal_target=actor,
        started_ns=200_000_000,
        ready_ns=800_000_000,
        stop_requested_ns=11_000_000_000 if case == "fresh-controls" else 4_100_000_000,
        finished_ns=11_100_000_000,
        exit=dict(
            ExecMainPID="30",
            ExecMainCode="1" if case == "fresh-controls" else "2",
            ExecMainStatus="0" if case == "fresh-controls" else "9",
        ),
        signal=15 if case == "fresh-controls" else 9,
        runner_returncode=0,
    )
    from fresh_source_observe import SIDE_FILES

    if case == "fresh-controls":
        jr = json.loads(a["observer-journal.raw"].splitlines()[-1])
        stop = ObserverControlStop(
            scope_ref=policy.data["scope_ref"],
            trust_sha256=c["trust_sha256"],
            journal_policy_sha256=digest(
                persistence_context(telemetry, "lo", 0.1).encode()
            ),
            journal_boot_id=c["boot_id"],
            input_offset=finalpos["offset"],
            input_sha256=finalpos["sha256"],
            journal_sequence_before=jr["seq"] - 1,
            journal_sequence_after=jr["seq"],
            journal_head_after=jr["sha256"],
            journal_bytes_after=len(a["observer-journal.raw"]),
            pending_windows_before=0,
            pending_windows_lost=0,
            committed_outcomes=0,
            lost_before=0,
            lost_after=0,
        ).to_dict()
        a["observer-completion.json"] = wire(
            dict(
                schema_version="edge-fresh-observer-completion/v1",
                identity=identity,
                metadata=metadata,
                control_stop=stop,
                policy_context=pc,
                sidecars={
                    k: dict(
                        bytes=len(a[SIDE_FILES[k]]), sha256=digest(a[SIDE_FILES[k]])
                    )
                    for k in ("phase", "calls", "context", "input_calls")
                },
            )
        )
    for i, (key, name) in enumerate(SIDE_FILES.items(), 800):
        body = a[name]
        if body is None:
            observer["sidecars"][key] = None
            continue
        meta = obj(i, 61002, body)
        observer["sidecars"][key] = dict(
            before=deepcopy(meta),
            after=deepcopy(meta),
            size=len(body),
            sha256=digest(body),
        )
    load["observer"] = observer
    _anchors(
        a, c, policy, source, journalitems, observer["sidecars"]["journal"]["before"]
    )
    rdjournal = chain(journalitems[:2], start=1)
    readyanchors = b"".join(a["anchors-after.raw"].splitlines(keepends=True)[:3])
    readywb = dict(
        source_checkpoint=tips[ready["offset"]],
        anchor_checkpoint=anchor_checkpoint(readyanchors),
    )
    ctrl = dict(
        schema_version="edge-fresh-source-controller/v1",
        case_id=case,
        protocol_sha256=fresh.PROTOCOL_SHA256,
        input_recipe_sha256=fresh.RECIPE_SHA256,
        session_ref=c["session_ref"],
        started_ns=100,
        finished_ns=12_000_000_000,
        timestamp_receipts_sha256=digest(a["fresh-timestamp-receipts.json"]),
        input_manifest_sha256=digest(a["corpus-manifest.json"]),
        input_calls_sha256=digest(a["observer-input-calls.raw"]),
        observations=observations,
        interrupt_boundary=None,
        errors=[],
        readiness=dict(
            observed_ns=800_000_000,
            first_sample_seq=1,
            clock_calls_checkpoint=dict(
                size=len(callsready), sha256=digest(callsready)
            ),
            input_ready_position=ready,
            journal_checkpoint=dict(size=len(rdjournal), sha256=digest(rdjournal)),
            witness_boundary=readywb,
        ),
    )
    if case == "fresh-interrupted":
        boundary = dict(
            observed_ns=4_050_000_000,
            event_ref="interrupt-one",
            input_calls_checkpoint=dict(
                size=len(a["observer-input-calls.raw"]),
                sha256=digest(a["observer-input-calls.raw"]),
            ),
            handler_id=1,
            event_call_id=2,
            source_position=finalpos,
        )
        ctrl["interrupt_boundary"] = boundary
        faultanchors = b"".join(a["anchors-after.raw"].splitlines(keepends=True)[:4])
        a["observer-fault-anchors.raw"] = faultanchors
        observer["fault_boundary"] = dict(
            observed_ns=boundary["observed_ns"],
            source_checkpoint=selected[0]["tip"],
            cursor_position=finalpos,
            journal_checkpoint=dict(
                size=len(a["observer-journal.raw"]),
                sha256=digest(a["observer-journal.raw"]),
            ),
            witness_sha256=digest(faultanchors),
            witness_boundary=dict(
                source_checkpoint=selected[0]["tip"],
                anchor_checkpoint=anchor_checkpoint(faultanchors),
            ),
        )
    a["fresh-controller.json"] = wire(ctrl)


def _anchors(a, c, policy, source, journalitems, jobj):
    from azazel_edge.benchmark.source_witness import _source_tips

    tips = _source_tips(source)
    empty = dict(seq=0, head="0" * 64, size=0, sha256=digest(b""))

    def state(tip, seq, body):
        return dict(
            **{"source_" + k: v for k, v in tip.items()},
            journal_seq=seq,
            journal_head="0" * 64
            if not body
            else json.loads(body.splitlines()[-1])["sha256"],
            journal_size=len(body),
            journal_sha256=digest(body),
            journal_device=0 if not body else jobj["device"],
            journal_inode=0 if not body else jobj["inode"],
        )

    states = [state(empty, 0, b"")]
    prefix = b""
    sourceoffset = 0
    for seq, item in enumerate(journalitems, 1):
        prefix = chain(journalitems[:seq], start=1)
        if item[0] == "input_ready":
            sourceoffset = item[1]["offset"]
        if item[0] == "cursor":
            sourceoffset = item[1]["position"]["offset"]
        states.append(state(tips[sourceoffset] if sourceoffset else empty, seq, prefix))
    # Independent Root post-stop audits append coherent journal/witness states;
    # before/after stores are genuine prefixes of one synthetic signed history.
    beforetip = SourceVerifier(policy).verify(a["source-before.raw"])
    preaudit = chain(journalitems + [("audit_before_terminal", {})], start=1)
    states.append(state(beforetip, len(journalitems) + 1, preaudit))
    audit = chain(
        journalitems + [("audit_before_terminal", {}), ("audit_after_terminal", {})],
        start=1,
    )
    states.append(state(tips[len(source)], len(journalitems) + 2, audit))
    rows = [
        dict(
            schema_version="outcome-input-anchor/v1",
            counter=i,
            prev="0" * 64,
            trust_sha256=policy.digest,
            state=s,
        )
        for i, s in enumerate(states, 1)
    ]
    aa = sign_anchors(rows)
    ab = b"".join(aa.splitlines(keepends=True)[:-1])
    for name, br, ar in (("anchors", ab, aa), ("journal", preaudit, audit)):
        a[name + "-before.raw"] = br
        a[name + "-after.raw"] = ar
        for when, body in (("before", br), ("after", ar)):
            entry = c["stores"][name][when]
            entry.update(bytes=len(body), sha256=digest(body))
            entry["object"]["size"] = len(body)
        if name == "anchors":
            c["stores"][name].update(
                before_checkpoint=anchor_checkpoint(ab),
                after_checkpoint=anchor_checkpoint(aa),
            )
    tip = SourceVerifier(policy).verify(source)
    a["witness-boundary.json"] = wire(
        dict(source_checkpoint=tip, anchor_checkpoint=anchor_checkpoint(aa))
    )
