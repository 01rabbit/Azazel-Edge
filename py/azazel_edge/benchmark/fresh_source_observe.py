"""Bounded read-only fresh-input facts; no callback/window or authority invention."""

from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import math

from ..outcome.input_auth import SourceVerifier, TrustPolicy
from ..outcome.input_cursor import BoundedInput
from ..outcome.input_resume import _event_epoch
from ..outcome.journal import _json, _parse
from . import finite_ingress as finite
from . import finite_load_cost as cost
from .native_source_accounting import ERRORS, _fields, _need, _uint
from .source_witness import _source_tips, _verify_anchors

PROTOCOL_SHA256 = "f12b5d79b277856251ee674994e5a3527cb07c7ae2c161ebf9241a73c3488bf2"
RECIPE_SHA256 = "46d83e1ea8551a5010f37a45a76044d81ce15d3e8a8e1196ed4d3114fa7da1ea"
CASES = ("fresh-controls", "fresh-interrupted")
EXTRA_FILES = frozenset(
    (
        "fresh-controller.json",
        "fresh-timestamp-receipts.json",
        "observer-input-calls.raw",
    )
)
FILES = cost.FILES | EXTRA_FILES
CONTROL = set(
    "schema_version case_id protocol_sha256 input_recipe_sha256 session_ref started_ns finished_ns timestamp_receipts_sha256 input_manifest_sha256 input_calls_sha256 observations interrupt_boundary errors readiness".split()
)
STAMP = set(
    "event_ref kind sid occurrence after_nonalert duplicate_of generation_anchor timestamp_epoch_ns timestamp start_offset end_offset raw_sha256 materialization_before_ns materialization_after_ns write_before_ns write_after_ns error".split()
)
MANIFEST = set(
    "schema_version case_id protocol_sha256 input_recipe_sha256 sha256 bytes lf_records nonalert_records per_class markers timestamp_receipts_sha256".split()
)
MARKER = set(
    "event_ref kind sid occurrence after_nonalert start_offset end_offset raw_sha256 timestamp".split()
)
ACTIVITY = set("epoch src_ip dst_ip target_port sid evidence_ref".split())


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return _json(value) + b"\n"


@lru_cache(maxsize=1)
def nonalert_lines():
    result = []
    for index in range(27004):
        value = dict(event_type=cost.CLASSES[index % 4], load_index=index, padding="")
        value["padding"] = "x" * (600 - len(wire(value)))
        result.append(wire(value))
    return tuple(result)


def event_specs(case_id):
    _need(case_id in CASES, "fixed_fresh_case")
    if case_id == CASES[0]:
        items = (
            ("fresh-one", "fresh", 9000, 90233001),
            ("stale", "stale", 12000, 90233002),
            ("future", "future", 15000, 90233003),
            ("fresh-two", "fresh", 18000, 90233004),
            ("duplicate-one", "fresh", 21000, 90233005),
            ("duplicate-two", "duplicate", 21000, 90233005),
            ("fresh-three", "fresh", 27004, 90233006),
        )
    else:
        items = tuple(
            (f"interrupt-{word}", "fresh", n, sid)
            for word, n, sid in (
                ("one", 9000, 90233101),
                ("two", 18000, 90233102),
                ("three", 27004, 90233103),
            )
        )
    occurrences, result = {}, []
    for ref, kind, after, sid in items:
        occurrences[sid] = occurrences.get(sid, 0) + 1
        result.append(
            dict(
                event_ref=ref,
                kind=kind,
                after_nonalert=after,
                sid=sid,
                occurrence=occurrences[sid],
                duplicate_of="duplicate-one" if kind == "duplicate" else None,
            )
        )
    return result


def materialize_alert(spec, epoch_ns):
    _need(
        _uint(epoch_ns, 2**63) and spec["kind"] in ("fresh", "stale", "future"),
        "actual_generation_epoch",
    )
    delta = -600 if spec["kind"] == "stale" else 600 if spec["kind"] == "future" else 0
    seconds, nano = divmod(epoch_ns, 1_000_000_000)
    stamp = (
        datetime.fromtimestamp(seconds + delta, timezone.utc)
        .replace(microsecond=nano // 1000)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    return wire(
        dict(
            timestamp=stamp,
            event_type="alert",
            src_ip="192.0.2.1",
            dest_ip="192.0.2.2",
            dest_port=22,
            proto="TCP",
            alert=dict(
                signature_id=spec["sid"],
                signature="fresh Source fixture",
                category="test",
                severity=2,
            ),
        )
    )


def file_limit(name):
    if name == "fresh-controller.json":
        return 131072
    if name == "fresh-timestamp-receipts.json":
        return 65536
    if name == "observer-input-calls.raw":
        return 4 * 1024 * 1024
    return cost._limit(name)


def _anchor(value):
    _fields(value, {"monotonic_before_ns", "epoch_ns", "monotonic_after_ns"})
    _need(
        all(_uint(x, 2**63) for x in value.values())
        and value["monotonic_before_ns"] <= value["monotonic_after_ns"],
        "actual_anchor",
    )


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value < 2**63


def _identity(value, boot):
    _fields(value, cost.IDENTITY)
    _need(
        value["boot_id"] == boot
        and all(
            _uint(value[k], 2**63) and value[k] > 0
            for k in ("pid", "start_ticks", "native_tid", "clock_ticks_per_second")
        ),
        "actual_Root_identity",
    )
    domain = value["clock_domain"]
    _fields(
        domain,
        set(
            "time_namespace_device time_namespace_inode timens_offsets established".split()
        ),
    )
    _need(type(domain["established"]) is bool, "explicit_clock_domain_status")
    for key in ("time_namespace_device", "time_namespace_inode"):
        _need(
            domain[key] is None or _uint(domain[key], 2**63),
            "observed_namespace_identity",
        )
    offsets = domain["timens_offsets"]
    _need(
        offsets is None or type(offsets) is list and len(offsets) <= 2,
        "bounded_time_offsets",
    )
    if offsets is not None:
        for row in offsets:
            _fields(row, {"clock", "seconds", "nanoseconds"})
            _need(
                row["clock"] in ("monotonic", "boottime")
                and type(row["seconds"]) is int
                and type(row["nanoseconds"]) is int,
                "actual_time_offset_shape",
            )
    if domain["established"]:
        _need(
            all(
                domain[k] is not None
                for k in ("time_namespace_device", "time_namespace_inode")
            )
            and offsets is not None
            and {o["clock"] for o in offsets} == {"monotonic", "boottime"}
            and all(o["seconds"] == o["nanoseconds"] == 0 for o in offsets),
            "established_original_domain",
        )
    _fields(value["clock_resolutions"], {"monotonic", "process_time", "thread_time"})
    _need(
        all(_number(x) and x > 0 for x in value["clock_resolutions"].values()),
        "actual_clock_resolutions",
    )


def _records(
    raw, *, schema=None, convention="core", maximum=900, complete=False, start_seq=None
):
    """Retain a validated complete-row prefix; never repair a terminal fragment."""
    _need(type(raw) is bytes and len(raw) <= 8 * 1024 * 1024, "recording_bound")
    stop = raw.rfind(b"\n") + 1
    prefix, tail = raw[:stop], raw[stop:]
    rows, previous, issue = [], "0" * 64, None
    for line in prefix.splitlines(keepends=True):
        try:
            _need(len(rows) < maximum, "recording_row_bound")
            row = _parse(line)
            fields = (
                {"schema_version", "seq", "prev", "kind", "data"}
                if convention == "full"
                else {"seq", "prev", "kind", "data", "sha256"}
            )
            _fields(row, fields)
            _need(
                wire(row) == line
                and type(row["seq"]) is int
                and row["seq"]
                == len(rows)
                + (
                    start_seq
                    if start_seq is not None
                    else 1
                    if convention == "full"
                    else 0
                )
                and row["prev"] == previous
                and type(row["kind"]) is str
                and type(row["data"]) is dict,
                "canonical_record_chain",
            )
            if convention == "full":
                _need(row["schema_version"] == schema, "new_input_record_schema")
                previous = _sha(line)
            else:
                digest = _sha(_json({k: v for k, v in row.items() if k != "sha256"}))
                _need(row["sha256"] == digest, "unsigned_record_hash")
                previous = digest
            rows.append(row)
        except ERRORS as error:
            issue = str(error)
            break
    if complete:
        _need(not tail and issue is None, "recording_not_complete")
    return rows, tail, issue


def _actual_population(raw, receipts, case_id):
    """Validate every actual timestamp/span and all immutable EVE bytes."""
    _fields(
        receipts,
        set(
            "schema_version case_id protocol_sha256 input_recipe_sha256 rows errors".split()
        ),
    )
    _need(
        receipts["schema_version"] == "edge-fresh-timestamp-receipts/v1"
        and receipts["case_id"] == case_id
        and receipts["protocol_sha256"] == PROTOCOL_SHA256
        and receipts["input_recipe_sha256"] == RECIPE_SHA256
        and receipts["errors"] == [],
        "timestamp_receipt_context",
    )
    specs = event_specs(case_id)
    _need(
        type(receipts["rows"]) is list and len(receipts["rows"]) == len(specs),
        "all_actual_write_receipts",
    )
    chunks, markers, by_ref, offset, index = [], [], {}, 0, 0
    for spec, receipt in zip(specs, receipts["rows"]):
        _fields(receipt, STAMP)
        _need(
            all(receipt[k] == v for k, v in spec.items()) and receipt["error"] is None,
            "fixed_timestamp_recipe",
        )
        for line in nonalert_lines()[index : spec["after_nonalert"]]:
            chunks.append(line)
            offset += len(line)
        index = spec["after_nonalert"]
        timekeys = (
            "materialization_before_ns",
            "materialization_after_ns",
            "write_before_ns",
            "write_after_ns",
        )
        _need(
            all(
                _uint(receipt[k], 2**63)
                for k in (*timekeys, "timestamp_epoch_ns", "start_offset", "end_offset")
            )
            and all(receipt[a] <= receipt[b] for a, b in zip(timekeys, timekeys[1:])),
            "actual_materialization_write_order",
        )
        if spec["kind"] == "duplicate":
            _need(receipt["generation_anchor"] is None, "duplicate_not_redated")
            first = by_ref["duplicate-one"]
            line = first["line"]
            _need(
                receipt["timestamp_epoch_ns"] == first["receipt"]["timestamp_epoch_ns"],
                "duplicate_original_epoch",
            )
        else:
            anchor = receipt["generation_anchor"]
            _anchor(anchor)
            _need(
                receipt[timekeys[0]]
                <= anchor["monotonic_before_ns"]
                <= anchor["monotonic_after_ns"]
                <= receipt[timekeys[1]],
                "actual_generation_bracket",
            )
            line = materialize_alert(spec, anchor["epoch_ns"])
            delta = (
                -600
                if spec["kind"] == "stale"
                else 600
                if spec["kind"] == "future"
                else 0
            )
            _need(
                receipt["timestamp_epoch_ns"]
                == anchor["epoch_ns"] // 1000 * 1000 + delta * 1_000_000_000,
                "timestamp_exact_actual_utc_rule",
            )
        event = _parse(line)
        _need(
            receipt["timestamp"] == event["timestamp"]
            and receipt["start_offset"] == offset
            and receipt["end_offset"] == offset + len(line)
            and receipt["raw_sha256"] == _sha(line),
            "actual_original_alert_span",
        )
        chunks.append(line)
        offset += len(line)
        marker = {k: receipt[k] for k in MARKER}
        markers.append(marker)
        by_ref[spec["event_ref"]] = dict(receipt=receipt, marker=marker, line=line)
    chunks.extend(nonalert_lines()[index:])
    _need(b"".join(chunks) == raw, "actual_eve_bytes_reconstruct_exactly")
    return markers, by_ref


def _journal_facts(raw, source, policy, anchors, identity):
    rows, tail, issue = _records(raw, maximum=4096, start_seq=1)
    _need(rows and issue is None and not tail, "original_journal_chain")
    header = rows[0]
    _need(
        header["kind"] == "header"
        and header["data"]["scope_ref"] == policy.data["scope_ref"]
        and header["data"]["input_config"]["authentication"] == policy.binding(),
        "journal_authenticated_scope",
    )
    cursor_rows, ready, prefixes, offset, hasher = [], [], {}, 0, hashlib.sha256()
    for row, line in zip(rows, raw.splitlines(keepends=True)):
        offset += len(line)
        hasher.update(line)
        prefixes[offset] = (row["seq"], row["sha256"], hasher.hexdigest())
        if row["kind"] == "cursor":
            _fields(row["data"], {"position", "missed"})
            position = BoundedInput.position(row["data"]["position"])
            _need(
                type(row["data"]["missed"]) is bool
                and position["offset"] <= len(source)
                and position["sha256"] == _sha(source[: position["offset"]]),
                "actual_journal_cursor",
            )
            cursor_rows.append(row)
        if row["kind"] == "input_ready":
            ready.append(BoundedInput.position(row["data"]))
    tips = _source_tips(source)
    _verify_anchors(policy, anchors, tips, tips[len(source)])
    states = []
    for line in anchors.splitlines():
        state = _parse(line)["state"]
        if (
            prefixes.get(state["journal_size"])
            == (state["journal_seq"], state["journal_head"], state["journal_sha256"])
            and state["journal_device"] == identity["device"]
            and state["journal_inode"] == identity["inode"]
        ):
            states.append(state)

    def protected(cursor_row):
        return any(
            s["journal_seq"] >= cursor_row["seq"]
            and s["source_size"] >= cursor_row["data"]["position"]["offset"]
            for s in states
        )

    return cursor_rows, ready, protected


def evaluate_fresh_source_case(artifacts, *, expected):
    r = dict(
        schema_version="edge-fresh-source-analysis/v1",
        case_id=None,
        status="withheld",
        raw_sha256={},
        pins={},
        reasons=[],
        finite=None,
        input_manifest=None,
        load=None,
        intake=None,
        handler_facts=None,
        callback_facts=None,
        scope_facts=None,
        observer=None,
        authority_flags=deepcopy(finite.close.AUTHORITY),
    )
    if (
        type(artifacts) is not dict
        or type(expected) is not dict
        or set(artifacts) != FILES
        or set(expected) != FILES
    ):
        r["reasons"].append("exact48_original_pin_envelope")
        return r
    for name in sorted(FILES):
        b, pin = artifacts[name], expected[name]
        digest = _sha(b) if type(b) is bytes and len(b) <= file_limit(name) else None
        r["raw_sha256"][name] = digest
        r["pins"][name] = type(pin) is str and digest == pin
        if name == "evaluation.json":
            r["raw_sha256"][name] = r["pins"][name] = None
        elif not r["pins"][name] and not (b is None and pin is None):
            r["reasons"].append(name + ":invalid_pin_or_bound")

    def raw(name):
        _need(r["pins"][name], name + ":missing_or_invalid_original")
        return artifacts[name]

    def data(name):
        b = raw(name)
        value = _parse(b)
        _need(wire(value) == b, name + ":canonical_JSON_LF")
        return value

    def check(name, call):
        try:
            return call()
        except ERRORS as error:
            r["reasons"].append(name + ":" + str(error))
            return None

    case_id = check("case", lambda: data("close-controller.json")["case_id"])
    r["case_id"] = case_id
    if case_id not in CASES:
        r["reasons"].append("fixed_fresh_case")
        return r
    manifest, receipts, markers, by_ref = None, None, [], {}

    def population():
        protocol = data("protocol.json")
        _need(
            _sha(raw("protocol.json")) == PROTOCOL_SHA256
            and protocol["schema_version"] == "edge-fresh-source-observe-protocol/v1"
            and _sha(wire(protocol["input_recipe"])) == RECIPE_SHA256,
            "fixed_protocol_recipe",
        )
        manifest = data("corpus-manifest.json")
        _fields(manifest, MANIFEST)
        receipts = data("fresh-timestamp-receipts.json")
        observed = raw("eve-after-writer.raw")
        markers, refs = _actual_population(observed, receipts, case_id)
        _need(
            manifest["schema_version"] == "edge-fresh-input-manifest/v1"
            and manifest["case_id"] == case_id
            and manifest["protocol_sha256"] == PROTOCOL_SHA256
            and manifest["input_recipe_sha256"] == RECIPE_SHA256
            and manifest["sha256"] == _sha(observed)
            and type(manifest["bytes"]) is int
            and manifest["bytes"] == len(observed)
            and manifest["lf_records"] == observed.count(b"\n") == 27004 + len(markers)
            and manifest["nonalert_records"] == 27004
            and manifest["per_class"] == dict.fromkeys(cost.CLASSES, 6751)
            and manifest["markers"] == markers
            and manifest["timestamp_receipts_sha256"]
            == _sha(raw("fresh-timestamp-receipts.json")),
            "actual_dynamic_manifest",
        )
        return manifest, receipts, markers, refs

    pop = check("population", population)
    if pop is not None:
        manifest, receipts, markers, by_ref = pop
        r["input_manifest"] = manifest
    raw_input = artifacts["eve-after-writer.raw"]
    actual_pin = (
        dict(bytes=len(raw_input), sha256=_sha(raw_input))
        if type(raw_input) is bytes and len(raw_input) <= finite.EVE_LIMIT
        else dict(bytes=0, sha256="0" * 64)
    )
    specs = event_specs(case_id)
    profile = dict(
        protocol_sha256=PROTOCOL_SHA256,
        cases={name: ("normal_stop", None) for name in CASES},
        case_specs={
            name: dict(
                recipe_intended_pin=actual_pin,
                signed_barrier=dict(sid=event_specs(name)[-1]["sid"], occurrence=1),
            )
            for name in CASES
        },
        close_profile=dict(
            load_cost=True, protocol_schema="edge-fresh-source-observe-protocol/v1"
        ),
    )
    bound = finite._evaluate_finite_profile(
        {k: artifacts[k] for k in finite.FILES},
        expected={k: expected[k] for k in finite.FILES},
        profile=profile,
    )
    r["finite"] = bound
    if pop is None:
        # Authentication and original span facts remain available above.
        r["reasons"].append("experiment_population_not_established")

    def load():
        _need(
            manifest is not None and bound["legs"].get("context") is True,
            "bound_actual_input_context",
        )
        ctrl, ic, cc = (
            data("load-controller.json"),
            data("ingress-controller.json"),
            data("close-controller.json"),
        )
        _fields(ctrl, cost.CONTROL | {"input_recipe_sha256"})
        _need(
            ctrl["schema_version"] == "edge-fresh-load-controller/v1"
            and ctrl["case_id"] == case_id
            and ctrl["protocol_sha256"] == PROTOCOL_SHA256
            and ctrl["input_recipe_sha256"] == RECIPE_SHA256
            and ctrl["corpus_sha256"] == manifest["sha256"]
            and ctrl["session_ref"] == ic["session_ref"] == cc["session_ref"],
            "fresh_load_context",
        )
        _identity(ctrl["controller_identity"], cc["boot_id"])
        _need(
            all(_uint(ctrl[k], 2**63) for k in ("started_ns", "finished_ns"))
            and ctrl["started_ns"] <= ctrl["finished_ns"],
            "actual_load_controller_interval",
        )
        _fields(ctrl["controller_anchors"], {"before", "after"})
        writer = ctrl["writer"]
        _fields(writer, cost.WRITER)
        _need(len(ic["writer"]) == 1 and ic["mutation"] is None, "one_actual_writer")
        shared = set(
            "pid tid fd flags before after started_ns finished_ns joined_ns written_bytes write_calls fsync_completed joined error".split()
        )
        _need(
            all(writer[k] == ic["writer"][0][k] for k in shared)
            and writer["pid"] == ctrl["controller_identity"]["pid"]
            and writer["joined"] is True
            and writer["fsync_completed"] is True
            and writer["error"] is None,
            "same_actual_shared_writer",
        )
        _need(
            all(
                bound["legs"].get(k) is True
                for k in (
                    "eve-start.raw",
                    "eve-after-writer.raw",
                    "eve-held-final.raw",
                    "eve-path-final.raw",
                )
            ),
            "independent_original_RO_snapshots",
        )
        _need(
            raw("eve-start.raw") == b""
            and raw("eve-held-final.raw")
            == raw("eve-path-final.raw")
            == raw("eve-after-writer.raw")
            and writer["before"] == ic["held_fd"]["object"]
            and writer["after"] == ic["snapshots"]["eve-after-writer.raw"]["before"]
            and finite.close._same_object(writer["before"], writer["after"])
            and writer["before"]["size"] == ic["writer"][0]["offset_before"] == 0
            and writer["after"]["size"]
            == writer["written_bytes"]
            == len(raw("eve-after-writer.raw"))
            and writer["sha256"] == manifest["sha256"]
            and writer["nonalert_records"] == 27004
            and writer["per_class"] == manifest["per_class"],
            "actual_writer_generation_population",
        )
        keys = (
            "started_ns",
            "first_write_before_ns",
            "marker_one_before_ns",
            "final_nonalert_after_ns",
            "finished_ns",
            "joined_ns",
        )
        _need(
            all(_uint(writer[k], 2**63) for k in keys)
            and all(writer[a] <= writer[b] for a, b in zip(keys, keys[1:])),
            "actual_load_brackets",
        )
        _need(
            all(
                _uint(writer[k], 2**63)
                for k in ("pid", "tid", "fd", "flags", "write_calls")
            )
            and writer["pid"] > 0
            and writer["tid"] > 0,
            "actual_writer_identity_fields",
        )
        previous_end = writer["started_ns"]
        for row in receipts["rows"]:
            _need(
                previous_end
                <= row["materialization_before_ns"]
                <= row["materialization_after_ns"]
                <= row["write_before_ns"]
                <= row["write_after_ns"]
                <= writer["finished_ns"],
                "actual_receipt_within_writer_order",
            )
            previous_end = row["write_after_ns"]
        _need(
            receipts["rows"][0]["write_before_ns"] == writer["marker_one_before_ns"],
            "actual_first_marker_writer_boundary",
        )
        _need(
            ctrl["started_ns"]
            <= writer["started_ns"]
            <= writer["joined_ns"]
            <= ctrl["finished_ns"]
            and ic["started_ns"]
            <= writer["started_ns"]
            <= writer["joined_ns"]
            <= ic["finished_ns"],
            "writer_within_original_controllers",
        )
        _anchor(ctrl["controller_anchors"]["before"])
        _anchor(ctrl["controller_anchors"]["after"])
        _need(
            ctrl["controller_anchors"]["before"]["monotonic_after_ns"]
            <= ctrl["started_ns"]
            and ctrl["finished_ns"]
            <= ctrl["controller_anchors"]["after"]["monotonic_before_ns"],
            "load_clock_containment",
        )
        start, middle, end = (writer[k] for k in keys[1:4])
        full, warmup, measurement = end - start, middle - start, end - middle
        _need(full > 0 and measurement > 0, "nonempty_actual_duration")
        qualified = (
            full >= 9_000_000_000
            and warmup >= 3_000_000_000
            and measurement >= 6_000_000_000
            and 2940 * full <= 27004 * 1_000_000_000 <= 3060 * full
            and 2940 * measurement <= 18004 * 1_000_000_000 <= 3060 * measurement
        )
        return dict(
            status="qualified" if qualified else "failed",
            full_ns=full,
            warmup_ns=warmup,
            measurement_ns=measurement,
            full_nonalert_per_second=27004 * 1e9 / full,
            measurement_nonalert_per_second=18004 * 1e9 / measurement,
            reasons=[] if qualified else ["fixed_load_condition_not_met"],
        )

    r["load"] = check("load", load)

    def intake():
        _need(
            manifest is not None
            and bound["committed_range_verified"] is True
            and bound["legs"].get("spans") is True,
            "verified_input_prefix",
        )
        ingress = bound["ingress"]
        c = ingress["counts"]
        _need(
            c is not None and ingress["measurement_valid"] is True,
            "actual_final_native_counts",
        )
        prefix = raw("eve-held-final.raw")[: ingress["committed_end_offset"]]
        alerts = sum(
            _parse(line).get("event_type") == "alert" for line in prefix.splitlines()
        )
        _need(
            alerts == c["alerts_admitted"] == bound["source_decisions"]
            and bound["unconfirmed_decision_outputs"] == 0,
            "authenticated_marker_denominator",
        )
        examined = c["examined"] - alerts
        _need(0 <= examined <= 27004, "examined_nonalert_population")
        return dict(
            status="qualified" if examined * 100 >= 27004 * 98 else "failed",
            examined_nonalert=examined,
            written_nonalert=27004,
            percent=examined * 100 / 27004,
        )

    r["intake"] = check("intake", intake)
    _evaluate_callbacks(r, raw, data, check, by_ref, specs)
    return r


def _evaluate_callbacks(r, raw, data, check, by_ref, specs):
    """Independent Source-position oracle, retaining validated returned prefixes."""
    case_id = r["case_id"]

    def originals():
        ctrl, load, cc = (
            data("fresh-controller.json"),
            data("load-controller.json"),
            data("close-controller.json"),
        )
        _fields(ctrl, CONTROL)
        _need(
            ctrl["schema_version"] == "edge-fresh-source-controller/v1"
            and ctrl["case_id"] == case_id
            and ctrl["protocol_sha256"] == PROTOCOL_SHA256
            and ctrl["input_recipe_sha256"] == RECIPE_SHA256
            and ctrl["session_ref"] == cc["session_ref"] == load["session_ref"],
            "fresh_provenance_context",
        )
        _need(
            all(_uint(ctrl[k], 2**63) for k in ("started_ns", "finished_ns"))
            and ctrl["started_ns"] <= ctrl["finished_ns"],
            "fresh_root_interval",
        )
        for field, name in (
            ("timestamp_receipts_sha256", "fresh-timestamp-receipts.json"),
            ("input_manifest_sha256", "corpus-manifest.json"),
            ("input_calls_sha256", "observer-input-calls.raw"),
        ):
            _need(ctrl[field] == _sha(raw(name)), "fresh_original_file_pin:" + name)
        policy = TrustPolicy(_parse(raw("trust.json")))
        source = raw("source-after.raw")
        SourceVerifier(policy).verify(source)
        _need(
            r["finite"]["close"]["legs"].get("context") is True,
            "authenticated_selected_native_context",
        )
        tips, selected, offset = _source_tips(source), {}, 0
        for line in source.splitlines(keepends=True):
            start, offset = offset, offset + len(line)
            signed = _parse(line)
            event = signed["event"]
            origin = event["capture_origin"]
            if (
                origin["session_ref"] != cc["session_ref"]
                or origin["kind"] != "decision_execution"
            ):
                continue
            _need(
                origin["registration_sha256"] == cc["registration_sha256"],
                "same_source_registration",
            )
            span = event["ingress_origin"]
            _fields(span, finite.ORIGIN)
            eve = raw("eve-held-final.raw")
            begin, end = span["start_offset"], span["end_offset"]
            _need(
                all(
                    _uint(span[k], 2**63)
                    for k in ("start_offset", "end_offset", "device", "inode")
                )
                and 0 <= begin < end <= len(eve)
                and _sha(eve[begin:end]) == span["raw_sha256"]
                and span["range_ref"] == cc["session_ref"]
                and span["schema_version"] == "azazel-edge/ingress-origin/v1",
                "actual_signed_eve_span",
            )
            src = _parse(eve[begin:end])
            _need(
                src["alert"]["signature_id"] == event["normalized"]["sid"]
                and src["timestamp"] == event["normalized"]["ts"],
                "signed_normalization_actual_input",
            )
            refs = [
                name
                for name, v in by_ref.items()
                if v["marker"]["start_offset"] == begin
                and v["marker"]["end_offset"] == end
            ]
            selected[offset] = dict(
                event=event,
                position=dict(offset=offset, sha256=tips[offset]["sha256"]),
                before=dict(offset=start, sha256=_sha(source[:start])),
                checkpoint=tips[offset],
                event_ref=refs[0] if len(refs) == 1 else None,
                decoded_sha256=_sha(SourceVerifier.unwrap(line)),
                source_seq=signed["seq"],
            )
        _need(
            type(ctrl["observations"]) is list and len(ctrl["observations"]) <= 16,
            "bounded_actual_Source_observations",
        )
        observed_refs = set()
        for item in ctrl["observations"]:
            _fields(
                item,
                set(
                    "event_ref observed_ns session_ref source_position source_checkpoint ingress_origin".split()
                ),
            )
            pos = BoundedInput.position(item["source_position"])
            record = selected[pos["offset"]]
            _need(
                _uint(item["observed_ns"], 2**63)
                and pos == record["position"]
                and item["source_checkpoint"] == record["checkpoint"]
                and item["session_ref"] == cc["session_ref"]
                and item["ingress_origin"] == record["event"]["ingress_origin"]
                and item["event_ref"] == record["event_ref"]
                and item["event_ref"] not in observed_refs
                and ctrl["started_ns"] <= item["observed_ns"] <= ctrl["finished_ns"],
                "exact_original_Source_observation",
            )
            observed_refs.add(item["event_ref"])
        config = data("observer-config.json")
        _need(
            config["schema_version"] == "edge-fresh-source-observer-config/v1"
            and config["case_id"] == case_id
            and config["protocol_sha256"] == PROTOCOL_SHA256
            and config["input_recipe_sha256"] == RECIPE_SHA256
            and config["registration_sha256"] == cc["registration_sha256"]
            and config["trust_sha256"] == cc["trust_sha256"],
            "fresh_original_config",
        )
        journal = raw("observer-journal.raw")
        jobj = load["observer"]["sidecars"]["journal"]["before"]
        header = _parse(journal.splitlines()[0])["data"]["input_config"]
        source_obj = cc["stores"]["source"]["after"]["object"]
        _need(
            header["device"] == source_obj["device"]
            and header["inode"] == source_obj["inode"]
            and header["uid"] == source_obj["owner_uid"]
            and header["path_sha256"] == _sha(policy.data["source_path"].encode()),
            "journal_actual_source_object",
        )
        cursor_rows, ready, protected = _journal_facts(
            journal, source, policy, raw("anchors-after.raw"), jobj
        )
        clock_rows, clock_tail, clock_error = _records(raw("observer-calls.raw"))
        _need(clock_rows, "original_clock_callback_prefix")
        if clock_error is not None:
            r["reasons"].append("clock_record_prefix:" + clock_error)
        rd = ctrl["readiness"]
        _fields(
            rd,
            set(
                "observed_ns first_sample_seq clock_calls_checkpoint input_ready_position journal_checkpoint witness_boundary".split()
            ),
        )
        samples = [row for row in clock_rows if row["kind"] == "sample"]
        _need(
            samples
            and _uint(rd["first_sample_seq"], 2**63)
            and _uint(rd["observed_ns"], 2**63)
            and rd["first_sample_seq"] == samples[0]["seq"]
            and rd["input_ready_position"] in ready
            and rd["observed_ns"] <= load["writer"]["first_write_before_ns"],
            "actual_original_recovery_and_sample_before_writer",
        )
        for name, checkpoint in (
            ("observer-calls.raw", rd["clock_calls_checkpoint"]),
            ("observer-journal.raw", rd["journal_checkpoint"]),
        ):
            _fields(checkpoint, {"size", "sha256"})
            b = raw(name)
            _need(
                _uint(checkpoint["size"], 2**63)
                and 0 < checkpoint["size"] <= len(b)
                and b[checkpoint["size"] - 1 : checkpoint["size"]] == b"\n"
                and _sha(b[: checkpoint["size"]]) == checkpoint["sha256"],
                "actual_prewrite_readiness_prefix",
            )
        ready_prefix_rows = _records(
            journal[: rd["journal_checkpoint"]["size"]], start_seq=1, maximum=4096
        )[0]
        sample_prefix_rows = _records(
            raw("observer-calls.raw")[: rd["clock_calls_checkpoint"]["size"]]
        )[0]
        _need(
            any(row == samples[0] for row in sample_prefix_rows),
            "original_sample_within_prewrite_prefix",
        )
        wb = rd["witness_boundary"]
        _fields(wb, {"source_checkpoint", "anchor_checkpoint"})
        ac = wb["anchor_checkpoint"]
        _fields(ac, {"counter", "head", "size", "sha256"})
        anchor_raw = raw("anchors-after.raw")
        _need(
            _uint(ac["size"], 2**63) and 0 < ac["size"] <= len(anchor_raw),
            "readiness_witness_prefix_size",
        )
        anchor_prefix = anchor_raw[: ac["size"]]
        _need(
            anchor_prefix.endswith(b"\n")
            and _sha(anchor_prefix) == ac["sha256"]
            and _verify_anchors(policy, anchor_prefix, tips, wb["source_checkpoint"])
            == ac,
            "readiness_signed_witness_boundary",
        )
        witness_state = _parse(anchor_prefix.splitlines()[-1])["state"]
        _need(
            witness_state["journal_device"] == jobj["device"]
            and witness_state["journal_inode"] == jobj["inode"]
            and witness_state["journal_size"] <= rd["journal_checkpoint"]["size"]
            and any(
                row["kind"] == "input_ready"
                and row["data"] == rd["input_ready_position"]
                and row["seq"] <= witness_state["journal_seq"]
                for row in ready_prefix_rows
            )
            and _sha(journal[: witness_state["journal_size"]])
            == witness_state["journal_sha256"],
            "original_ready_journal_protected_before_writer",
        )
        _need(
            any(
                row["kind"] == "input_ready"
                and row["data"] == rd["input_ready_position"]
                for row in _records(
                    journal[: rd["journal_checkpoint"]["size"]],
                    start_seq=1,
                    maximum=4096,
                )[0]
            ),
            "original_input_ready_before_publication",
        )
        return (
            ctrl,
            load,
            config,
            selected,
            cursor_rows,
            protected,
            clock_rows,
            clock_tail,
            clock_error,
        )

    context = check("callback_context", originals)
    if context is None:
        return
    (
        ctrl,
        load,
        config,
        selected,
        cursor_rows,
        protected,
        clock_rows,
        clock_tail,
        clock_error,
    ) = context
    rows, tail, error = _records(
        raw("observer-input-calls.raw"),
        schema="edge-fresh-input-record/v1",
        convention="full",
        maximum=256,
    )
    if error:
        r["reasons"].append("input_record_prefix:" + error)
    if not rows:
        r["reasons"].append("input_record_begin_missing")
        return
    begin = rows[0]

    def begin_context():
        _need(begin["kind"] == "begin", "fresh_record_begin")
        _fields(begin["data"], {"metadata", "identity", "binding", "limits"})
        _need(
            begin["data"]["metadata"] == config["metadata"]
            and begin["data"]["identity"] == load["observer"]["identity"]
            and begin["data"]["binding"]
            == dict(
                case_id=case_id,
                run_id=config["metadata"]["run_id"],
                registration_sha256=config["registration_sha256"],
                trust_sha256=config["trust_sha256"],
                input_recipe_sha256=RECIPE_SHA256,
            )
            and begin["data"]["limits"]
            == dict(max_rows=256, max_bytes=4 * 1024 * 1024),
            "fresh_recorder_identity_binding",
        )
        return True

    if check("input_begin", begin_context) is not True:
        return
    r["handler_facts"], r["callback_facts"] = [], []
    calls = {row["seq"]: row for row in clock_rows if row["kind"] == "event"}
    intents, returns, used_calls, positions = {}, set(), set(), set()
    footer = None
    prefix_failed = False
    last_offset = 0
    floor = None
    for row in rows[1:]:
        try:
            d = row["data"]
            if row["kind"] == "input_intent":
                _fields(
                    d,
                    set(
                        "input_id decoded_event_sha256 position cursor_before live_floor supplied_now start_ns".split()
                    ),
                )
                _need(
                    type(d["input_id"]) is int
                    and d["input_id"] == len(intents) + 1
                    and _uint(d["start_ns"], 2**63)
                    and _number(d["live_floor"])
                    and _number(d["supplied_now"])
                    and d["live_floor"] <= d["supplied_now"],
                    "original_handler_arguments",
                )
                pos = BoundedInput.position(d["position"])
                record = selected[pos["offset"]]
                _need(
                    pos == record["position"]
                    and d["cursor_before"] == record["before"]
                    and d["decoded_event_sha256"] == record["decoded_sha256"]
                    and pos["offset"] > last_offset
                    and pos["offset"] not in positions,
                    "exact_handler_Source_position",
                )
                _need(
                    floor is None or floor == d["live_floor"], "one_original_live_floor"
                )
                floor = d["live_floor"]
                last_offset = pos["offset"]
                positions.add(pos["offset"])
                stamp = _event_epoch(record["event"])
                _need(stamp is not None, "actual_decoded_input_timestamp")
                eligible = (
                    d["live_floor"] <= stamp <= d["supplied_now"]
                    and d["supplied_now"] - stamp <= 0.1
                )
                intents[d["input_id"]] = (d, record, eligible, stamp)
            elif row["kind"] in ("input_return", "input_raise"):
                required = set("input_id end_ns cursor_after callbacks".split()) | (
                    {"handler_result"}
                    if row["kind"] == "input_return"
                    else {"exception_type"}
                )
                _fields(d, required)
                _need(
                    type(d["input_id"]) is int
                    and d["input_id"] in intents
                    and d["input_id"] not in returns,
                    "one_handler_completion",
                )
                intent, record, eligible, stamp = intents[d["input_id"]]
                _need(
                    _uint(d["end_ns"], 2**63)
                    and intent["start_ns"] <= d["end_ns"]
                    and type(d["callbacks"]) is list
                    and len(d["callbacks"]) <= 1,
                    "original_handler_return_interval",
                )
                fact = dict(
                    input_id=d["input_id"],
                    event_ref=record["event_ref"],
                    source_position=record["position"],
                    live_floor=intent["live_floor"],
                    supplied_now=intent["supplied_now"],
                    timestamp=stamp,
                    timestamp_age_seconds=intent["supplied_now"] - stamp,
                    eligible=eligible,
                    returned=row["kind"] == "input_return",
                    callbacks_completed=None,
                    cursor_protected=False,
                    missed=None,
                )
                for callback in d["callbacks"]:
                    _fields(
                        callback,
                        set(
                            "call_seq event_sha256 return_value observed_epoch activity".split()
                        ),
                    )
                    seq = callback["call_seq"]
                    _need(
                        type(seq) is int and seq not in used_calls and seq in calls,
                        "actual_original_callback_sequence",
                    )
                    actual = calls[seq]["data"]
                    _need(
                        actual["event"] == record["event"]
                        and callback["event_sha256"] == _sha(wire(record["event"]))
                        and actual["epoch"]
                        == callback["observed_epoch"]
                        == intent["supplied_now"]
                        and actual["accepted"] is callback["return_value"] is False
                        and intent["start_ns"]
                        <= actual["clock_before"]["monotonic_before_ns"]
                        <= actual["clock_after"]["monotonic_after_ns"]
                        <= d["end_ns"],
                        "actual_callback_event_return_and_epoch",
                    )
                    activity = callback["activity"]
                    _fields(activity, ACTIVITY)
                    n = record["event"]["normalized"]
                    _need(
                        activity
                        == dict(
                            epoch=stamp,
                            src_ip=n["src_ip"],
                            dst_ip=n["dst_ip"],
                            target_port=n["target_port"],
                            sid=n["sid"],
                            evidence_ref="rust-activity:"
                            + record["event"]["enforcement"]["trace_id"],
                        ),
                        "actual_nonwindow_activity",
                    )
                    r["callback_facts"].append(
                        dict(
                            input_id=d["input_id"],
                            event_ref=record["event_ref"],
                            source_position=record["position"],
                            call_seq=seq,
                            returned=False,
                            activity=activity,
                        )
                    )
                    used_calls.add(seq)
                if row["kind"] == "input_return":
                    _need(
                        d["handler_result"] is None
                        and d["cursor_after"] == record["position"],
                        "original_handler_cursor_return",
                    )
                    cursors = [
                        c
                        for c in cursor_rows
                        if c["data"]["position"] == record["position"]
                    ]
                    _need(
                        len(cursors) == 1
                        and cursors[0]["data"]["missed"] is (not eligible)
                        and protected(cursors[0]),
                        "actual_durable_missed_cursor_and_witness",
                    )
                    _need(
                        len(d["callbacks"]) == int(eligible),
                        "actual_guard_callback_disposition",
                    )
                    fact.update(
                        callbacks_completed=len(d["callbacks"]),
                        cursor_protected=True,
                        missed=not eligible,
                    )
                    returns.add(d["input_id"])
                r["handler_facts"].append(fact)
            elif row["kind"] == "end":
                _need(footer is None and row is rows[-1], "terminal_input_footer")
                footer = d
            else:
                raise ValueError("unknown_fresh_input_row")
        except ERRORS as exc:
            r["reasons"].append("handler_prefix:" + str(exc))
            prefix_failed = True
            break
    complete = bool(footer is not None and not tail and error is None)
    r["scope_facts"] = dict(
        observation_complete=False,
        completed_handlers_lower_bound=len(returns),
        completed_callbacks_lower_bound=len(r["callback_facts"]),
        later_callbacks=None,
        partial_tail_bytes=len(tail),
        intent_count=len(intents),
        unmatched_original_callbacks=len(set(calls) - used_calls),
    )

    def qualification():
        _need(
            not prefix_failed and error is None and clock_error is None,
            "valid_input_record_prefix",
        )
        _need(ctrl["errors"] == [], "fresh_controller_without_collection_errors")
        _need(
            r["input_manifest"] is not None
            and r["finite"]["whole_input_complete"] is True
            and (r["load"] or {}).get("status") == "qualified"
            and (r["intake"] or {}).get("status") == "qualified",
            "finite_input_load_prerequisites",
        )
        _need(
            not r["scope_facts"]["unmatched_original_callbacks"]
            and len(r["handler_facts"]) == len(returns),
            "no_unbound_or_raised_handler",
        )
        _need(
            set(item["event_ref"] for item in ctrl["observations"])
            == set(item["event_ref"] for item in specs),
            "all_original_Source_observations",
        )
        _need(
            floor is not None
            and floor
            <= next(x for x in clock_rows if x["kind"] == "sample")["data"]["epoch"],
            "original_loop_floor_before_first_sample",
        )
        if case_id == CASES[0]:
            _need(
                complete
                and len(returns) == 7
                and len(r["callback_facts"]) == 5
                and sum(f["missed"] is True for f in r["handler_facts"]) == 2,
                "fixed_fresh_controls",
            )
            _fields(
                footer,
                set(
                    "completed_inputs completed_callbacks final_cursor normal_return incomplete".split()
                ),
            )
            _need(
                footer["normal_return"] is True
                and footer["incomplete"] is False
                and footer
                == dict(
                    completed_inputs=7,
                    completed_callbacks=5,
                    final_cursor=r["handler_facts"][-1]["source_position"],
                    normal_return=True,
                    incomplete=False,
                ),
                "genuine_recorder_footer",
            )
            _need(
                [f["event_ref"] for f in r["handler_facts"]]
                == [s["event_ref"] for s in specs],
                "ordered_exact_recipe_handlers",
            )
            r["scope_facts"].update(observation_complete=True, later_callbacks=0)
            r["status"] = "bound_fresh_controls"
        else:
            _need(
                not complete
                and footer is None
                and len(returns) == 1
                and len(r["callback_facts"]) == 1
                and r["handler_facts"][0]["event_ref"] == "interrupt-one",
                "interrupted_callback_prefix_only",
            )
            boundary = ctrl["interrupt_boundary"]
            _fields(
                boundary,
                set(
                    "observed_ns event_ref input_calls_checkpoint handler_id event_call_id source_position".split()
                ),
            )
            cb = r["callback_facts"][0]
            _need(
                all(
                    _uint(boundary[k], 2**63)
                    for k in ("handler_id", "event_call_id", "observed_ns")
                )
                and boundary["handler_id"] == cb["input_id"]
                and boundary["event_call_id"] == cb["call_seq"]
                and boundary["source_position"] == cb["source_position"]
                and boundary["event_ref"] == "interrupt-one",
                "exact_completed_callback_kill_boundary",
            )
            checkpoint = boundary["input_calls_checkpoint"]
            b = raw("observer-input-calls.raw")
            _fields(checkpoint, {"size", "sha256"})
            size = checkpoint["size"]
            _need(
                _uint(size, 2**63)
                and 0 < size <= len(b)
                and _sha(b[:size]) == checkpoint["sha256"]
                and b[size - 1 : size] == b"\n"
                and _records(
                    b[:size],
                    schema="edge-fresh-input-record/v1",
                    convention="full",
                    maximum=256,
                )[0][-1]["kind"]
                == "input_return",
                "actual_pre_signal_completed_input_prefix",
            )
            _need(
                boundary["observed_ns"]
                <= load["observer"]["stop_requested_ns"]
                < load["writer"]["first_write_before_ns"] + 6_000_000_000
                and load["observer"]["signal"] == 9,
                "fixed_interrupt_deadline",
            )
            r["status"] = "bound_interrupted_prefix"
        return True

    check("fresh_qualification", qualification)
