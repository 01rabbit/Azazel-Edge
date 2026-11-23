"""Explicit v2 measurement publication and immutable outer trial evidence."""

from copy import deepcopy
import stat

from . import fresh_source_observe as legacy
from .native_source_accounting import ERRORS, _fields, _hash, _need, _uint

PROTOCOL_SHA256 = "107595f5c7d85d410d65517a7f50bdb6e3dd3b31bdb4cffcd3936be98b65ea59"
RECIPE_SHA256 = legacy.RECIPE_SHA256
CASES = legacy.CASES
FILES = legacy.FILES | {"observer-publication.raw"}
wire = legacy.wire
nonalert_lines = legacy.nonalert_lines
event_specs = legacy.event_specs
materialize_alert = legacy.materialize_alert
LIMITS = dict(
    queue_rows=1156,
    queue_bytes=8388608,
    stream_rows=dict(calls=900, input_calls=256),
    stream_bytes=dict(calls=4194304, input_calls=4194304),
    publication_rows=4096,
    publication_bytes=1048576,
    batch_bytes=65536,
    batch_ns=100000000,
    close_ns=5000000000,
)
STREAMS = {"calls": "observer-calls.raw", "input_calls": "observer-input-calls.raw"}
OBJECT = {"device", "inode", "owner_uid", "mode", "link_count"}
CLOCK = set(
    "start_ns end_ns process_cpu_start_ns process_cpu_end_ns thread_cpu_start_ns thread_cpu_end_ns".split()
)
WATERMARK = {"rows", "last_seq", "bytes", "sha256"}


def file_limit(name):
    return 1048576 if name == "observer-publication.raw" else legacy.file_limit(name)


def _clock(value):
    _fields(value, CLOCK)
    _need(all(_uint(v, 2**64) for v in value.values()), "actual_publication_clocks")
    for before, after in (
        ("start_ns", "end_ns"),
        ("process_cpu_start_ns", "process_cpu_end_ns"),
        ("thread_cpu_start_ns", "thread_cpu_end_ns"),
    ):
        _need(value[before] <= value[after], "ordered_publication_clock")


def _raw_reader(artifacts, expected):
    def raw(name):
        b = artifacts.get(name)
        _need(
            type(b) is bytes
            and len(b) <= file_limit(name)
            and type(expected.get(name)) is str
            and legacy._sha(b) == expected[name],
            "original_pin:" + name,
        )
        return b

    def data(name):
        b = raw(name)
        v = legacy._parse(b)
        _need(wire(v) == b, "canonical_original:" + name)
        return v

    return raw, data


def _records(stream, raw, *, version=2):
    if stream == "calls":
        return legacy._records(raw, maximum=900)
    names = {
        "input_calls": ("input-record", 256),
        "phase": ("phase-timing-record", 4096),
        "context": ("clock-context", 2),
    }
    name, maximum = names[stream]
    return legacy._records(
        raw, schema=f"edge-fresh-{name}/v{version}", convention="full", maximum=maximum
    )


def _root_object(meta):
    _need(
        type(meta) is dict
        and all(
            _uint(meta[k], 2**64)
            for k in ("device", "inode", "owner_uid", "mode", "nlink")
        ),
        "typed_Root_stream_object",
    )
    return dict(
        device=meta["device"],
        inode=meta["inode"],
        owner_uid=meta["owner_uid"],
        mode=meta["mode"],
        link_count=meta["nlink"],
    )


def _ordered_phase_prefix(rows):
    """A partial stack is known unfinished; a return needs a unique earlier intent."""
    _need(rows and rows[0]["kind"] == "header", "phase_prefix_header")
    active, seen, stack = {}, set(), []
    for index, row in enumerate(rows[1:], 1):
        body, kind = row["data"], row["kind"]
        if kind == "intent":
            sid, parent = body["span_id"], body["parent_id"]
            _need(
                _uint(sid, 2**64) and sid > 0 and sid not in seen,
                "unique_ordered_phase_intent",
            )
            _need(
                parent is None
                if not stack
                else type(parent) is int and parent == stack[-1],
                "actual_phase_parent_stack",
            )
            active[sid] = body
            seen.add(sid)
            stack.append(sid)
        elif kind == "span":
            sid = body["span_id"]
            _need(
                _uint(sid, 2**64) and sid in active and stack and stack[-1] == sid,
                "phase_return_requires_prior_active_intent",
            )
            intent = active.pop(sid)
            stack.pop()
            _need(
                all(
                    body[k] == intent[k]
                    for k in (
                        "span_id",
                        "parent_id",
                        "phase",
                        "event_kind",
                        "event_seq",
                        "operation",
                    )
                ),
                "ordered_phase_return_context",
            )
            _need(body["outcome"] in ("returned", "raised"), "actual_phase_disposition")
        elif kind == "end":
            _need(
                index == len(rows) - 1
                and not active
                and not stack
                and body["normal_return"] is True
                and body["incomplete"] is False,
                "genuine_quiescent_phase_footer",
            )
        else:
            raise ValueError("unknown_ordered_phase_record")


def evaluate_publication(artifacts, *, expected):
    return _evaluate_publication_profile(artifacts, expected=expected)


def _evaluate_publication_profile(
    artifacts,
    *,
    expected,
    version=2,
    protocol_sha256=PROTOCOL_SHA256,
    publication_version=1,
    streams=STREAMS,
    limits=LIMITS,
):
    result = dict(
        schema_version=f"edge-observer-publication-analysis/v{publication_version}",
        status="withheld",
        streams=dict.fromkeys(streams),
        normal_complete=False,
        readiness_verified=False,
        interrupt_verified=False,
        reasons=[],
    )
    raw, data = _raw_reader(artifacts, expected)

    def decode_stream(stream, value):
        return _records(stream, value, version=version)

    def check(name, fn):
        try:
            return fn()
        except ERRORS as exc:
            result["reasons"].append(name + ":" + str(exc))
            return None

    def originals():
        config, load, control = (
            data("observer-config.json"),
            data("load-controller.json"),
            data("fresh-controller.json"),
        )
        _need(
            config["schema_version"] == f"edge-fresh-source-observer-config/v{version}"
            and load["schema_version"] == f"edge-fresh-load-controller/v{version}"
            and control["schema_version"] == f"edge-fresh-source-controller/v{version}"
            and all(
                v["protocol_sha256"] == protocol_sha256 for v in (config, load, control)
            )
            and all(v["case_id"] == control["case_id"] for v in (config, load)),
            "explicit_v2_publication_context",
        )
        observer = load["observer"]
        _need(
            all(_uint(observer[k], 2**64) for k in ("started_ns", "finished_ns"))
            and observer["started_ns"] <= observer["finished_ns"],
            "actual_observer_lifetime",
        )
        b = raw("observer-publication.raw")
        rows, tail, issue = legacy._records(
            b,
            schema=f"edge-observer-publication/v{publication_version}",
            convention="full",
            maximum=4096,
        )
        _need(rows and rows[0]["kind"] == "header", "publication_header")
        header = rows[0]["data"]
        _fields(header, {"metadata", "identity", "limits"})
        _need(
            header["metadata"] == config["metadata"]
            and header["identity"] == load["observer"]["identity"]
            and header["limits"] == limits,
            "pinned_publication_header",
        )
        return config, load, control, rows, tail, issue, b

    context = check("context", originals)
    if context is None:
        return result
    config, load, control, rows, tail, issue, publication = context
    if issue is not None:
        result["reasons"].append("publication_prefix:" + issue)
    commits, footer, worker_tid, previous_end = [], None, None, 0
    failed = False
    life = load["observer"]
    offset = len(wire(rows[0]))
    for row in rows[1:]:
        offset += len(wire(row))
        try:
            d = row["data"]
            if row["kind"] == "commit":
                _fields(
                    d,
                    set(
                        "stream first_seq last_seq rows bytes sha256 object worker_native_tid write fsync".split()
                    ),
                )
                stream = d["stream"]
                _need(
                    type(stream) is str and stream in streams,
                    "known_measurement_stream",
                )
                _need(
                    all(
                        _uint(d[k], 2**64)
                        for k in (
                            "first_seq",
                            "last_seq",
                            "rows",
                            "bytes",
                            "worker_native_tid",
                        )
                    )
                    and d["worker_native_tid"] > 0,
                    "actual_commit_counts",
                )
                worker_tid = (
                    d["worker_native_tid"] if worker_tid is None else worker_tid
                )
                _need(
                    d["worker_native_tid"] == worker_tid
                    and worker_tid != load["observer"]["identity"]["native_tid"],
                    "one_separate_worker_thread",
                )
                _clock(d["write"])
                _clock(d["fsync"])
                _need(
                    previous_end
                    <= d["write"]["start_ns"]
                    <= d["write"]["end_ns"]
                    <= d["fsync"]["start_ns"]
                    <= d["fsync"]["end_ns"],
                    "write_then_fsync",
                )
                _need(
                    life["started_ns"] <= d["write"]["start_ns"]
                    and d["fsync"]["end_ns"] <= life["finished_ns"],
                    "publication_inside_actual_observer_lifetime",
                )
                prior = result["streams"][stream]
                first = (
                    (prior["last_seq"] + 1)
                    if prior
                    else (0 if stream == "calls" else 1)
                )
                _need(
                    d["first_seq"] == first and d["first_seq"] <= d["last_seq"],
                    "contiguous_committed_rows",
                )
                b = raw(streams[stream])
                _need(
                    0 < d["bytes"] <= len(b)
                    and b[d["bytes"] - 1 : d["bytes"]] == b"\n"
                    and legacy._sha(b[: d["bytes"]]) == d["sha256"],
                    "actual_committed_prefix_hash",
                )
                decoded, rest, error = decode_stream(stream, b[: d["bytes"]])
                _need(
                    decoded
                    and not rest
                    and error is None
                    and d["rows"] == len(decoded)
                    and decoded[-1]["seq"] == d["last_seq"]
                    and (prior is None or d["bytes"] > prior["bytes"]),
                    "exact_committed_stream_prefix",
                )
                if version == 3 and stream == "phase":
                    _ordered_phase_prefix(decoded)
                if version == 3 and stream == "context":
                    _need(
                        decoded[0]["kind"] == "begin"
                        and (len(decoded) == 1 or decoded[1]["kind"] == "end"),
                        "ordered_context_begin_end",
                    )
                if version == 3 and control["case_id"] == CASES[1]:
                    _need(
                        all(row["kind"] != "end" for row in decoded),
                        "interrupted_stream_cannot_have_normal_footer",
                    )
                known_returns = []
                for original in decoded:
                    body = original["data"]
                    if stream == "calls" and original["kind"] in (
                        "sample",
                        "event",
                        "finalize",
                    ):
                        stamp = body["clock_after"]["monotonic_after_ns"]
                    elif stream == "input_calls" and original["kind"] in (
                        "input_return",
                        "input_raise",
                    ):
                        stamp = body["end_ns"]
                    elif stream == "input_calls" and original["kind"] == "input_intent":
                        stamp = body["start_ns"]
                    elif version == 3 and stream == "phase":
                        _need(
                            "previous_write_cost" not in body
                            and "previous_enqueue_cost" in body,
                            "explicit_phase_enqueue_cost_semantics",
                        )
                        enqueued = body["previous_enqueue_cost"]
                        _need(
                            (original["seq"] == 1 and enqueued is None)
                            or (original["seq"] > 1 and enqueued is not None),
                            "measured_previous_enqueue_not_missing",
                        )
                        if enqueued is not None:
                            _fields(enqueued, CLOCK | {"seq"})
                            _need(
                                _uint(enqueued["seq"], 2**64)
                                and enqueued["seq"] == original["seq"] - 1,
                                "actual_previous_enqueue_row",
                            )
                            _clock({k: enqueued[k] for k in CLOCK})
                            _need(
                                life["started_ns"]
                                <= enqueued["start_ns"]
                                <= enqueued["end_ns"]
                                <= life["finished_ns"],
                                "enqueue_inside_actual_observer_lifetime",
                            )
                            known_returns.append(enqueued["end_ns"])
                        if original["kind"] != "span":
                            continue
                        _clock({k: body[k] for k in CLOCK})
                        _need(
                            life["started_ns"]
                            <= body["start_ns"]
                            <= body["end_ns"]
                            <= life["finished_ns"],
                            "phase_inside_actual_observer_lifetime",
                        )
                        stamp = body["end_ns"]
                    elif version == 3 and stream == "context":
                        legacy._anchor(body["anchor"])
                        _need(
                            life["started_ns"]
                            <= body["anchor"]["monotonic_before_ns"]
                            <= body["anchor"]["monotonic_after_ns"]
                            <= life["finished_ns"],
                            "context_inside_actual_observer_lifetime",
                        )
                        stamp = body["anchor"]["monotonic_after_ns"]
                    else:
                        continue
                    _need(_uint(stamp, 2**64), "original_queued_row_time")
                    known_returns.append(stamp)
                _need(
                    not known_returns or max(known_returns) <= d["write"]["start_ns"],
                    "publication_after_original_row_creation",
                )
                _fields(d["object"], OBJECT)
                obj = d["object"]
                _need(
                    all(_uint(v, 2**64) for v in obj.values())
                    and obj["device"] > 0
                    and obj["inode"] > 0
                    and obj["owner_uid"] == 61002
                    and obj["link_count"] == 1
                    and stat.S_ISREG(obj["mode"])
                    and not obj["mode"] & 0o022,
                    "measurement_descriptor_object",
                )
                meta = load["observer"]["sidecars"][stream]
                _need(
                    obj == _root_object(meta["before"]) == _root_object(meta["after"])
                    and meta["size"] == len(b)
                    and meta["sha256"] == legacy._sha(b),
                    "Root_observed_stream_object_and_bytes",
                )
                fact = {k: d[k] for k in ("rows", "last_seq", "bytes", "sha256")}
                fact.update(
                    object=obj,
                    worker_native_tid=worker_tid,
                    fsync_end_ns=d["fsync"]["end_ns"],
                )
                result["streams"][stream] = fact
                commits.append((offset, stream, fact))
                previous_end = d["fsync"]["end_ns"]
            elif row["kind"] == "end":
                _need(footer is None and row is rows[-1], "publication_terminal_footer")
                footer = d
            else:
                raise ValueError("unknown_publication_row")
        except ERRORS as exc:
            result["reasons"].append("commit_prefix:" + str(exc))
            failed = True
            break

    def barrier(value, *, before_ns, need_input):
        _need(
            _uint(value["observed_ns"], 2**64)
            and _uint(before_ns, 2**64)
            and life["started_ns"] <= value["observed_ns"] <= life["finished_ns"],
            "actual_barrier_observation_time",
        )
        checkpoint = value["publication_checkpoint"]
        _fields(checkpoint, {"size", "sha256"})
        n = checkpoint["size"]
        _need(
            _uint(n, 2**64)
            and 0 < n <= len(publication)
            and legacy._sha(publication[:n]) == checkpoint["sha256"]
            and publication[n - 1 : n] == b"\n",
            "Root_publication_prefix_checkpoint",
        )
        verified, partial, err = legacy._records(
            publication[:n],
            schema=f"edge-observer-publication/v{publication_version}",
            convention="full",
            maximum=4096,
        )
        _need(
            verified and not partial and err is None, "barrier_actual_publication_chain"
        )
        available = {}
        for end, stream, fact in commits:
            if end <= n and fact["fsync_end_ns"] <= value["observed_ns"] <= before_ns:
                available[stream] = fact

        def covers(stream, checkpoint, row_kind, seq):
            _fields(checkpoint, {"size", "sha256"})
            prefix = raw(streams[stream])[: checkpoint["size"]]
            _need(
                _uint(checkpoint["size"], 2**64)
                and checkpoint["size"] > 0
                and len(prefix) == checkpoint["size"]
                and prefix.endswith(b"\n")
                and legacy._sha(prefix) == checkpoint["sha256"]
                and stream in available
                and available[stream]["bytes"] >= len(prefix),
                "barrier_fsynced_measurement_prefix",
            )
            rr, t, e = decode_stream(stream, prefix)
            _need(
                rr
                and not t
                and e is None
                and any(r["kind"] == row_kind and r["seq"] == seq for r in rr),
                "barrier_original_returned_call",
            )
            return rr

        selected_call = None
        if not need_input:
            selected_calls = covers(
                "calls",
                value["clock_calls_checkpoint"],
                "sample",
                value["first_sample_seq"],
            )
            selected_call = next(
                (
                    r
                    for r in selected_calls
                    if r["kind"] == "sample" and r["seq"] == value["first_sample_seq"]
                ),
                None,
            )
        else:
            rr = covers(
                "input_calls",
                value["input_calls_checkpoint"],
                "input_return",
                value["handler_id"] * 2 + 1,
            )
            returned = next(
                (
                    r
                    for r in rr
                    if r["kind"] == "input_return"
                    and r["data"]["input_id"] == value["handler_id"]
                ),
                None,
            )
            _need(returned is not None, "barrier_exact_handler_return")
            _need(
                any(
                    c["call_seq"] == value["event_call_id"]
                    for c in returned["data"]["callbacks"]
                ),
                "barrier_paired_original_callback",
            )
            _need("calls" in available, "barrier_calls_committed")
            cc, _, _ = _records(
                "calls", raw("observer-calls.raw")[: available["calls"]["bytes"]]
            )
            _need(
                any(
                    r["kind"] == "event" and r["seq"] == value["event_call_id"]
                    for r in cc
                ),
                "barrier_exact_event_committed",
            )
            selected_call = next(
                (
                    r
                    for r in cc
                    if r["kind"] == "event" and r["seq"] == value["event_call_id"]
                ),
                None,
            )
        if version == 3:
            _need(selected_call is not None, "barrier_selected_original_call")
            phase_rows = covers("phase", value["phase_checkpoint"], "header", 1)
            context_rows = covers("context", value["context_checkpoint"], "begin", 1)
            header = phase_rows[0]["data"]
            _need(
                all(header[k] == v for k, v in config["metadata"].items())
                and all(
                    header[k] == v for k, v in load["observer"]["identity"].items()
                ),
                "barrier_phase_original_identity",
            )
            context_begin = context_rows[0]["data"]
            _need(
                context_rows[0]["kind"] == "begin"
                and context_begin["metadata"] == config["metadata"]
                and context_begin["identity"] == load["observer"]["identity"],
                "barrier_original_context_begin",
            )
            legacy._anchor(context_begin["anchor"])
            original_call = selected_call["data"]
            _need(
                context_begin["anchor"]["monotonic_after_ns"]
                <= original_call["clock_before"]["monotonic_before_ns"],
                "context_before_original_selected_call",
            )
            phase_name = "observation_event" if need_input else "observation_sample"
            intents = {
                r["data"]["span_id"]: r["data"]
                for r in phase_rows
                if r["kind"] == "intent"
            }
            matched = []
            for phase_row in phase_rows:
                if phase_row["kind"] != "span":
                    continue
                span = phase_row["data"]
                if span["phase"] != phase_name:
                    continue
                _clock({k: span[k] for k in CLOCK})
                if (
                    original_call["start_ns"]
                    <= span["start_ns"]
                    <= span["end_ns"]
                    <= original_call["end_ns"]
                ):
                    _need(
                        span["outcome"] == "returned"
                        and _uint(span["span_id"], 2**64)
                        and span["span_id"] > 0
                        and (
                            span["parent_id"] is None
                            or (
                                _uint(span["parent_id"], 2**64)
                                and 0 < span["parent_id"] < span["span_id"]
                            )
                        )
                        and type(span["native_tid"]) is int
                        and span["native_tid"]
                        == load["observer"]["identity"]["native_tid"]
                        and span["span_id"] in intents
                        and all(
                            span[k] == intents[span["span_id"]][k]
                            for k in (
                                "span_id",
                                "parent_id",
                                "phase",
                                "event_kind",
                                "event_seq",
                                "operation",
                            )
                        ),
                        "barrier_paired_original_phase_return",
                    )
                    matched.append(span)
            _need(len(matched) == 1, "barrier_exact_completed_phase_span")
        return True

    result["readiness_verified"] = (
        check(
            "readiness",
            lambda: barrier(
                control["readiness"],
                before_ns=load["writer"]["first_write_before_ns"],
                need_input=False,
            ),
        )
        is True
    )
    case = control["case_id"]
    if case == CASES[1]:
        if version == 3:

            def interrupted_streams():
                for stream, name in streams.items():
                    visible_rows, _, _ = decode_stream(stream, raw(name))
                    _need(
                        all(row["kind"] != "end" for row in visible_rows),
                        "interrupted_visible_stream_has_normal_footer",
                    )
                return True

            if check("interrupted_streams", interrupted_streams) is not True:
                failed = True
        result["interrupt_verified"] = (
            check(
                "interrupt",
                lambda: barrier(
                    control["interrupt_boundary"],
                    before_ns=load["observer"]["stop_requested_ns"],
                    need_input=True,
                ),
            )
            is True
        )

    def normal():
        _need(
            case == CASES[0]
            and footer is not None
            and not failed
            and issue is None
            and not tail,
            "complete_publication_recording",
        )
        _fields(
            footer,
            {"normal_return", "complete", "incomplete", "error", "streams", "close"},
        )
        _need(
            footer["normal_return"] is True
            and footer["complete"] is True
            and footer["incomplete"] is False
            and footer["error"] is None,
            "genuine_publication_completion",
        )
        _clock(footer["close"])
        _need(
            footer["close"]["end_ns"] - footer["close"]["start_ns"] <= 5000000000
            and previous_end <= footer["close"]["end_ns"],
            "fixed_close_deadline",
        )
        _fields(footer["streams"], set(streams))
        for stream, name in streams.items():
            marks = footer["streams"][stream]
            _fields(marks, {"enqueued", "written", "fsynced"})
            expected_mark = {k: result["streams"][stream][k] for k in WATERMARK}
            for mark in marks.values():
                _fields(mark, WATERMARK)
                _need(mark == expected_mark, "all_enqueued_rows_fsynced")
            _need(expected_mark["bytes"] == len(raw(name)), "no_uncommitted_final_tail")
            if version == 3:
                final_rows, partial, record_issue = decode_stream(stream, raw(name))
                _need(
                    final_rows
                    and not partial
                    and record_issue is None
                    and final_rows[-1]["kind"] == "end",
                    "genuine_four_stream_footer",
                )
                if stream in ("phase", "context"):
                    _need(
                        final_rows[-1]["data"]["normal_return"] is True,
                        "original_phase_context_normal_return",
                    )
                if stream == "phase":
                    _need(
                        final_rows[-1]["data"]["incomplete"] is False,
                        "original_phase_complete_not_invented",
                    )
        completion = data("observer-completion.json")
        owner = completion["publication"]
        _fields(owner, {"joined", "complete", "incomplete", "error", "owner_close"})
        _need(
            owner["joined"] is True
            and owner["complete"] is True
            and owner["incomplete"] is False
            and owner["error"] is None,
            "genuine_main_join_result",
        )
        _clock(owner["owner_close"])
        _need(
            life["started_ns"] <= owner["owner_close"]["start_ns"]
            and owner["owner_close"]["end_ns"] <= life["finished_ns"],
            "whole_close_inside_observer_lifetime",
        )
        _need(
            owner["owner_close"]["end_ns"] - owner["owner_close"]["start_ns"]
            <= 5000000000
            and owner["owner_close"]["start_ns"]
            <= footer["close"]["start_ns"]
            <= footer["close"]["end_ns"]
            <= owner["owner_close"]["end_ns"],
            "main_whole_close_deadline_and_worker_containment",
        )
        _need(
            completion["sidecars"]["publication"]
            == dict(bytes=len(publication), sha256=legacy._sha(publication)),
            "normal_publication_original_pin",
        )
        return True

    if case == CASES[0]:
        result["normal_complete"] = check("normal", normal) is True
    else:
        _need_no_normal = (
            footer is None and artifacts.get("observer-completion.json") is None
        )
        if not _need_no_normal:
            result["reasons"].append("interrupted_case_has_normal_footer_or_completion")
    qualified = (
        result["readiness_verified"]
        and not failed
        and issue is None
        and (
            result["normal_complete"]
            if case == CASES[0]
            else result["interrupt_verified"]
            and footer is None
            and artifacts.get("observer-completion.json") is None
        )
    )
    if qualified:
        result["status"] = "qualified"
    return result


def evaluate_fresh_source_case(artifacts, *, expected):
    return _evaluate_fresh_source_profile(artifacts, expected=expected)


def _evaluate_fresh_source_profile(
    artifacts,
    *,
    expected,
    version=2,
    protocol_sha256=PROTOCOL_SHA256,
    publication_verifier=evaluate_publication,
):
    result = legacy._evaluate_fresh_profile(
        artifacts,
        expected=expected,
        protocol_sha256=protocol_sha256,
        version=version,
        files=FILES,
    )
    result["publication"] = publication_verifier(artifacts, expected=expected)
    if result["publication"]["status"] != "qualified":
        result["status"] = "withheld"
        result["reasons"].append("publication_not_qualified")
    return result


def _typed_error(value):
    if value is None:
        return
    _fields(value, {"type", "message"})
    _need(
        all(type(v) is str and len(v) <= 4096 for v in value.values())
        and bool(value["type"]),
        "bounded_typed_disposition_error",
    )


def evaluate_fresh_run_evidence(cases, snapshots, disposition, *, expected):
    return _evaluate_run_profile(cases, snapshots, disposition, expected=expected)


def _evaluate_run_profile(
    cases,
    snapshots,
    disposition,
    *,
    expected,
    version=2,
    protocol_sha256=PROTOCOL_SHA256,
    leaf_evaluator=evaluate_fresh_source_case,
):
    """Explicit new-profile dispatch; stored metadata never chooses its verifier."""
    result = dict(
        schema_version="edge-fresh-run-analysis/v1",
        status="withheld",
        cases=dict.fromkeys(CASES),
        disposition=None,
        reasons=[],
        authority_flags=deepcopy(legacy.finite.close.AUTHORITY),
    )
    if type(expected) is not dict or set(expected) != {
        "cases",
        "snapshots",
        "disposition",
    }:
        result["reasons"].append("external_run_pin_envelope")
        return result
    if (
        type(cases) is not dict
        or set(cases) != set(CASES)
        or type(snapshots) is not dict
        or set(snapshots) != set(CASES)
        or type(expected["cases"]) is not dict
        or set(expected["cases"]) != set(CASES)
        or type(expected["snapshots"]) is not dict
        or set(expected["snapshots"]) != set(CASES)
    ):
        result["reasons"].append("fixed_two_case_assignment")
        return result
    for case in CASES:
        result["cases"][case] = leaf_evaluator(
            cases[case], expected=expected["cases"][case]
        )

    def pinned_json(raw, pin, limit=131072):
        _need(
            type(raw) is bytes
            and len(raw) <= limit
            and type(pin) is str
            and legacy._sha(raw) == pin,
            "external_original_pin",
        )
        value = legacy._parse(raw)
        _need(wire(value) == raw, "canonical_run_original")
        return value

    try:
        d = pinned_json(disposition, expected["disposition"])
        _fields(
            d,
            set(
                "schema_version protocol_sha256 source_revision run_ref started_ns finished_ns cases errors".split()
            ),
        )
        _need(
            d["schema_version"] == "edge-fresh-run-disposition/v1"
            and d["protocol_sha256"] == protocol_sha256
            and _hash(d["source_revision"], 40)
            and _hash(d["run_ref"], 32)
            and _uint(d["started_ns"], 2**64)
            and _uint(d["finished_ns"], 2**64)
            and d["started_ns"] <= d["finished_ns"],
            "fixed_v2_run_context",
        )
        _need(
            type(d["errors"]) is list and len(d["errors"]) <= 32, "bounded_run_errors"
        )
        for error in d["errors"]:
            _fields(error, {"stage", "type", "message"})
            _need(
                type(error["stage"]) is str
                and error["stage"] in ("run", "final-replay"),
                "actual_outer_error_stage",
            )
            _typed_error({k: error[k] for k in ("type", "message")})
        result["disposition"] = d
        _need(
            type(d["cases"]) is list and len(d["cases"]) == len(CASES),
            "complete_case_vector",
        )
        accepted = not d["errors"]
        for case, item in zip(CASES, d["cases"]):
            _fields(
                item,
                set(
                    "case_id state snapshot_manifest_sha256 evaluation_sha256 error cleanup_errors".split()
                ),
            )
            _need(
                item["case_id"] == case
                and item["state"]
                in (
                    "not_run",
                    "accepted",
                    "rejected",
                    "collection_failed",
                    "cleanup_failed",
                ),
                "ordered_case_disposition",
            )
            _typed_error(item["error"])
            _need(
                type(item["cleanup_errors"]) is list
                and len(item["cleanup_errors"]) <= 32,
                "bounded_cleanup_errors",
            )
            for error in item["cleanup_errors"]:
                _fields(error, {"stage", "type", "message"})
                _need(
                    type(error["stage"]) is str and 0 < len(error["stage"]) <= 128,
                    "actual_cleanup_stage",
                )
                _typed_error({k: error[k] for k in ("type", "message")})
            a, pins = cases[case], expected["cases"][case]
            _need(
                type(a) is dict
                and set(a) == FILES
                and type(pins) is dict
                and set(pins) == FILES,
                "exact49_immutable_case_slots",
            )
            if item["state"] == "not_run":
                _need(
                    item["snapshot_manifest_sha256"]
                    is item["evaluation_sha256"]
                    is None
                    and snapshots[case] is expected["snapshots"][case] is None
                    and all(v is None for v in a.values())
                    and all(v is None for v in pins.values())
                    and item["error"] is None
                    and item["cleanup_errors"] == [],
                    "not_run_is_absent_not_zero",
                )
                accepted = False
                continue
            snapshot_raw = snapshots[case]
            if snapshot_raw is None:
                _need(
                    item["state"] in ("collection_failed", "cleanup_failed")
                    and item["snapshot_manifest_sha256"] is None
                    and expected["snapshots"][case] is None
                    and (item["error"] is not None or bool(item["cleanup_errors"])),
                    "unsealed_failure_never_accepted",
                )
                accepted = False
                continue
            snapshot = pinned_json(snapshot_raw, expected["snapshots"][case])
            _fields(
                snapshot,
                {
                    "schema_version",
                    "case_id",
                    "run_ref",
                    "protocol_sha256",
                    "source_revision",
                    "files",
                },
            )
            _need(
                snapshot["schema_version"] == "edge-fresh-snapshot/v1"
                and snapshot["case_id"] == case
                and snapshot["run_ref"] == d["run_ref"]
                and snapshot["protocol_sha256"] == protocol_sha256
                and snapshot["source_revision"] == d["source_revision"]
                and item["snapshot_manifest_sha256"] == legacy._sha(snapshot_raw)
                and snapshot["files"] == pins,
                "exact_sealed_snapshot_binding",
            )
            for name in FILES:
                if pins[name] is None:
                    _need(a[name] is None, "immutable_null_slot_appeared:" + name)
                else:
                    _need(
                        type(a[name]) is bytes
                        and len(a[name]) <= file_limit(name)
                        and legacy._sha(a[name]) == pins[name],
                        "sealed_original_changed:" + name,
                    )
            _need(
                type(a["evaluation.json"]) is bytes
                and _hash(pins["evaluation.json"])
                and item["evaluation_sha256"] == pins["evaluation.json"],
                "external_positive_evaluation_pin",
            )
            original_evaluation = legacy._parse(a["evaluation.json"])
            _need(
                original_evaluation["schema_version"]
                == f"edge-fresh-source-analysis/v{version}"
                and original_evaluation["case_id"] == case,
                "sealed_evaluation_identity",
            )
            case_control = legacy._parse(a["close-controller.json"])
            _need(
                all(
                    _uint(case_control[k], 2**64) for k in ("started_ns", "finished_ns")
                )
                and d["started_ns"]
                <= case_control["started_ns"]
                <= case_control["finished_ns"]
                <= d["finished_ns"],
                "case_inside_actual_run_interval",
            )
            code = legacy._parse(a["code-pins.json"])
            _need(
                code["source_revision"] == d["source_revision"],
                "exact_run_source_revision",
            )
            leaf = result["cases"][case]
            if item["state"] == "accepted":
                _need(
                    item["error"] is None
                    and item["cleanup_errors"] == []
                    and leaf["status"]
                    == (
                        "bound_fresh_controls"
                        if case == CASES[0]
                        else "bound_interrupted_prefix"
                    ),
                    "accepted_case_requires_verified_leaf",
                )
            else:
                _need(
                    item["error"] is not None or bool(item["cleanup_errors"]),
                    "failed_disposition_keeps_actual_error",
                )
                accepted = False
        if accepted:
            result["status"] = "qualified"
        else:
            result["reasons"].append("run_has_failed_or_unmeasured_assignment")
    except ERRORS as exc:
        result["reasons"].append("run_envelope:" + str(exc))
    return result
