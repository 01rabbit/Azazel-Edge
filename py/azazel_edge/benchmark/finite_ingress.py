"""Additional finite ingress facts; never an authority or missing-data repair."""

import json
import stat

from ..outcome.input_auth import SourceVerifier, TrustPolicy
from . import native_close_receipts as close
from .native_source_accounting import ERRORS, _decode, _fields, _hash, _need, _sha, _uint

PROTOCOL_SHA256 = "09c49c3e6a9d997c64de8e2d607109a90b7c5d3f7a4afe94fd9aa8ce506045d7"
RAW_FILES = frozenset("eve-start.raw eve-after-writer.raw eve-before-mutation.raw eve-held-final.raw eve-path-final.raw normalized-log-before.raw normalized-log-final.raw".split())
FILES = close.FILES | RAW_FILES | {"ingress-controller.json"}
EVE_LIMIT = 16 * 1024 * 1024
CASES = {
    "ingress-mixed": ("normal_stop", [90231001, 90231002, 90231003, 90231004]),
    "ingress-partial-tail": ("normal_stop", [90231101, 90231102]),
    "ingress-oversize": ("normal_stop", [90231201, 90231202]),
    "ingress-duplicate-sid": ("normal_stop", [90231301, 90231301]),
    "ingress-backlog-shed": ("normal_stop", [90231401, 90231402]),
    "ingress-rename": ("normal_stop", None),
    "ingress-truncate": ("normal_stop", None),
    "ingress-same-inode-overwrite": ("normal_stop", [90231701]),
    "ingress-native-killed": ("native_sigkill", [90231801]),
    "ingress-receiver-killed": ("receiver_sigkill_then_normal_stop", [90231901]),
}
CONTROL = set("schema_version case_id protocol_sha256 session_ref range_ref started_ns finished_ns held_fd snapshots writer mutation markers errors".split())
SNAPSHOT = {"before", "after", "sha256", "size", "fd", "flags"}
INGRESS = set("schema_version range_ref measurement_valid invalid_reason input_identity start_offset committed_end_offset last_observed_length committed_bytes committed_sha256 last_stop unfinished_tail oversized_in_progress counts".split())
COUNTS = set("polls examined admitted alerts_admitted shed_by_type shed_rate shed_backlog oversized_started oversized_possible_alerts file_replacements truncation_resets unread_bytes_lost_observed normalized_decisions blank admitted_without_source".split())
ORIGIN = set("schema_version range_ref device inode start_offset end_offset raw_sha256".split())
INVALID = {"initial_metadata_unavailable", "identity_changed", "truncation_observed", "io_error", "hash_overflow", "counter_overflow", "invariant_failure"}
WRITER = set("stage pid tid fd flags before after started_ns finished_ns offset_before offset_after requested_bytes written_bytes write_calls fsync_completed joined joined_ns pause resume error".split())
MUTATION = set("kind pid tid started_ns finished_ns path_before path_after held_before held_after renamed_relative_name operation_completed fsync_completed pause resume error".split())
MARKER = set("kind sid occurrence observed_ns session_ref range_ref source_checkpoint ingress_origin normalized_log_checkpoint".split())


def _numbers(value, keys):
    _need(all(_uint(value[k], 2**63) for k in keys), "unsigned_integer_fields")


def _identity(value):
    _fields(value, {"device", "inode"})
    _numbers(value, value)


def _error(value):
    if value is not None:
        _fields(value, {"type", "message"})
        _need(all(type(v) is str and len(v) <= 4096 for v in value.values()), "typed_error")


def _signal(value, number):
    if value is not None:
        _fields(value, set("pid start_ticks signal requested_ns observed_ns observed_state error".split()))
        _numbers(value, ("pid", "start_ticks", "signal", "requested_ns"))
        _need(value["signal"] == number, "fixed_signal")
        if value["observed_ns"] is not None:
            _numbers(value, ("observed_ns",))
            _need(value["observed_ns"] >= value["requested_ns"], "signal_observation_order")
        _need(value["observed_state"] is None or type(value["observed_state"]) is str, "observed_process_state")
        _error(value["error"])


def _controls(c):
    """Check reported controls without substituting them for input evidence."""
    for w in c["writer"]:
        _fields(w, WRITER)
        _need(w["stage"] in ("initial", "post_receiver_failure"), "fixed_writer_stage")
        _numbers(w, set("pid tid fd flags started_ns finished_ns offset_before offset_after requested_bytes written_bytes write_calls joined_ns".split()))
        _need(w["flags"] & 3 == 1 and w["flags"] & 0o2000
              and w["started_ns"] <= w["finished_ns"] <= w["joined_ns"]
              and w["written_bytes"] <= w["requested_bytes"]
              and w["offset_after"] - w["offset_before"] == w["written_bytes"], "actual_append_receipt")
        for k in ("before", "after"):
            close._object_shape(w[k])
        _need(close._same_object(w["before"], w["after"]), "same_writer_object")
        _need(type(w["fsync_completed"]) is bool and type(w["joined"]) is bool, "writer_boolean_fields")
        _signal(w["pause"], 19)
        _signal(w["resume"], 18)
        _error(w["error"])
    m = c["mutation"]
    if m is not None:
        _fields(m, MUTATION)
        _need(m["kind"] in ("rename_replace", "same_inode_truncate_shorter", "same_inode_same_length_overwrite"), "fixed_mutation")
        _numbers(m, ("pid", "tid", "started_ns", "finished_ns"))
        _need(m["started_ns"] <= m["finished_ns"], "mutation_order")
        for k in ("path_before", "path_after", "held_before", "held_after"):
            close._object_shape(m[k])
        _need(m["renamed_relative_name"] is None or m["renamed_relative_name"] == "eve-finite-held.json", "fixed_renamed_fixture")
        _need(type(m["operation_completed"]) is bool and type(m["fsync_completed"]) is bool, "mutation_boolean_fields")
        _signal(m["pause"], 19)
        _signal(m["resume"], 18)
        _error(m["error"])
    for m in c["markers"]:
        _fields(m, MARKER)
        _numbers(m, ("sid", "occurrence", "observed_ns"))
        _need(m["kind"] in ("source", "normalized_log") and m["session_ref"] == m["range_ref"] == c["range_ref"], "marker_context")
        if m["kind"] == "source":
            close._tip(m["source_checkpoint"])
            _need(m["normalized_log_checkpoint"] is None and type(m["ingress_origin"]) is dict, "Source_marker")
        else:
            _need(m["source_checkpoint"] is m["ingress_origin"] is None, "log_not_Source")
            _fields(m["normalized_log_checkpoint"], {"object", "bytes", "sha256"})
            close._object_shape(m["normalized_log_checkpoint"]["object"])
            _numbers(m["normalized_log_checkpoint"], ("bytes",))
            _need(_hash(m["normalized_log_checkpoint"]["sha256"]), "log_checkpoint_hash")


def validate_ingress(value, session):
    """Exact original native snapshot shape and internal arithmetic only."""
    _fields(value, INGRESS)
    _need(value["schema_version"] == "azazel-edge/finite-ingress/v1"
          and value["range_ref"] == session and _hash(session, 32), "ingress_session")
    _numbers(value, ("start_offset", "committed_end_offset", "last_observed_length", "committed_bytes"))
    _need(type(value["measurement_valid"]) is bool and type(value["oversized_in_progress"]) is bool,
          "ingress_boolean_fields")
    _need(value["invalid_reason"] is None or value["invalid_reason"] in INVALID, "invalid_reason")
    _need(value["measurement_valid"] == (value["invalid_reason"] is None), "invalid_reason_consistency")
    if value["input_identity"] is not None:
        _identity(value["input_identity"])
    if value["measurement_valid"]:
        _need(value["input_identity"] is not None and _hash(value["committed_sha256"])
              and value["committed_end_offset"] >= value["start_offset"]
              and value["committed_bytes"] == value["committed_end_offset"] - value["start_offset"], "contiguous_frontier_arithmetic")
    else:
        _need(value["committed_sha256"] is None, "no_discontinuous_hash")
    _need(value["last_stop"] is None or value["last_stop"] in
          ("NoFile", "CaughtUp", "PartialLine", "AlertBudget", "ExamineBudget", "WorkTime"), "poll_stop")
    tail = value["unfinished_tail"]
    if tail is not None:
        _fields(tail, {"start_offset", "observed_bytes", "raw_sha256"})
        _numbers(tail, ("start_offset", "observed_bytes"))
        _need(tail["observed_bytes"] > 0 and _hash(tail["raw_sha256"]), "actual_observed_tail")
    c = value["counts"]
    if c is None:
        _need(not value["measurement_valid"], "unknown_counts_reason")
        return value
    _fields(c, COUNTS)
    _numbers(c, COUNTS - {"shed_by_type"})
    _fields(c["shed_by_type"], {"flow", "dns", "stats", "other", "unparseable"})
    _numbers(c["shed_by_type"], c["shed_by_type"])
    shed = sum(c["shed_by_type"].values())
    _need(c["examined"] == c["admitted"] + shed + c["oversized_started"] + c["blank"]
          and shed == c["shed_rate"] + c["shed_backlog"]
          and c["admitted"] == c["normalized_decisions"] + c["admitted_without_source"]
          and c["normalized_decisions"] <= c["alerts_admitted"] <= c["admitted"]
          and c["oversized_possible_alerts"] <= c["oversized_started"], "counter_conservation")
    if value["measurement_valid"]:
        _need(c["file_replacements"] == c["truncation_resets"] == c["unread_bytes_lost_observed"] == 0,
              "stable_range_no_resets")
    return value


def _raw_classes(raw):
    """Independent complete-record population, never callback measurements."""
    counts = dict(examined=0, blank=0, oversized_started=0, raw_parseable_records=0,
                  alerts=0, flow=0, dns=0, stats=0, other=0, unparseable=0)
    for piece in raw.split(b"\n")[:-1]:
        line = piece + b"\n"
        counts["examined"] += 1
        if len(line) > 1024 * 1024 + 1:
            counts["oversized_started"] += 1
            continue
        if not line.strip():
            counts["blank"] += 1
            continue
        try:
            value = json.loads(line.decode("utf-8", errors="replace"))
            counts["raw_parseable_records"] += 1
        except (ValueError, UnicodeError):
            counts["unparseable"] += 1
            continue
        kind = value.get("event_type") if type(value) is dict else None
        if kind == "alert":
            counts["alerts"] += 1
        else:
            counts[{"flow": "flow", "netflow": "flow", "dns": "dns", "stats": "stats"}.get(kind, "other")] += 1
    return counts


def evaluate_finite_ingress(artifacts, *, expected):
    return _evaluate_finite_profile(artifacts, expected=expected)


def _evaluate_finite_profile(artifacts, *, expected, profile=None):
    """Read fixed original artifacts, retaining independently valid partial facts."""
    protocol_sha = PROTOCOL_SHA256 if profile is None else profile["protocol_sha256"]
    cases = CASES if profile is None else profile["cases"]
    r = dict(schema_version="edge-finite-ingress-analysis/v1" if profile is None else "edge-finite-load-ingress-analysis/v1", case_id=None,
             status="unknown", raw_sha256={}, pins={}, legs={}, reasons=[], close=None,
             ingress=None, source_decisions=None, source_releases=None,
             matched_decision_spans=None, committed_range_verified=None,
             raw_population=None, unconfirmed_decision_outputs=None,
             whole_input_complete=None, authority_flags=close.AUTHORITY.copy())
    if type(artifacts) is not dict or set(artifacts) != FILES or type(expected) is not dict or set(expected) != FILES:
        r["reasons"].append("exact_artifact_pin_envelope")
        return r
    all_pins = True
    for name in sorted(FILES):
        raw, pin = artifacts[name], expected[name]
        limit = EVE_LIMIT if name.startswith("eve-") else close.BIG if name.startswith("normalized-log-") else 4096 if name == "native-close.raw" else close._limit(name)
        digest = _sha(raw) if type(raw) is bytes and len(raw) <= limit else None
        r["raw_sha256"][name] = digest
        r["pins"][name] = bool(_hash(pin) and digest == pin)
        if not (raw is None and pin is None) and not r["pins"][name]:
            all_pins = False
            r["reasons"].append(name + ":invalid_supplied_pin")
        if name == "evaluation.json":
            r["raw_sha256"][name] = r["pins"][name] = None

    def check(name, call):
        try:
            value = call()
            r["legs"][name] = True
            return value
        except ERRORS as error:
            r["legs"][name] = False
            r["reasons"].append(name + ":" + str(error))
            return None

    def raw(name):
        _need(r["pins"][name], name + ":missing_or_invalid_pin")
        return artifacts[name]

    def data(name):
        return _decode(raw(name), 128 * 1024, lf=True)

    original_close = {k: artifacts[k] for k in close.FILES}
    r["close"] = close._evaluate_close_profile(
        original_close, expected={k: expected[k] for k in close.FILES},
        profile=dict(protocol_sha256=protocol_sha, cases=cases, **({} if profile is None else profile.get("close_profile", {}))))
    bound = r["close"]
    r["case_id"] = bound["case_id"]

    def context():
        _need(bound["legs"].get("context") is True and bound["legs"].get("registration") is True,
              "authenticated_context_registration")
        c, old = data("ingress-controller.json"), data("close-controller.json")
        _fields(c, CONTROL)
        _need(c["schema_version"] == "edge-finite-ingress-controller/v1"
              and c["case_id"] == old["case_id"] and c["protocol_sha256"] == protocol_sha
              and c["session_ref"] == c["range_ref"] == old["session_ref"], "same_range_session_case")
        _numbers(c, ("started_ns", "finished_ns"))
        _need(c["started_ns"] <= c["finished_ns"], "controller_order")
        h = c["held_fd"]
        _fields(h, {"fd", "object", "opened_ns", "closed_ns"})
        _numbers(h, ("fd", "opened_ns", "closed_ns"))
        close._object_shape(h["object"])
        _need(stat.S_ISREG(h["object"]["mode"]) and h["object"]["nlink"] == 1
              and c["started_ns"] <= h["opened_ns"] <= old["invocation"]["exec_main_start_monotonic_us"] * 1000
              and c["finished_ns"] <= h["closed_ns"], "actual_held_FD_lifetime")
        _fields(c["snapshots"], RAW_FILES)
        _need(type(c["errors"]) is list and len(c["errors"]) <= 64, "bounded_controller_errors")
        for e in c["errors"]:
            _fields(e, {"stage", "type", "message"})
            _need(all(type(v) is str and len(v) <= 4096 for v in e.values()), "typed_controller_errors")
        _need(type(c["writer"]) is list and len(c["writer"]) <= 2
              and type(c["markers"]) is list and len(c["markers"]) <= 8, "bounded_actual_controls")
        _controls(c)
        return c

    control = check("context", context)
    snapshots = {}
    if control is not None:
        for name in sorted(RAW_FILES):
            def snapshot(name=name):
                value = control["snapshots"][name]
                _need(value is not None, "snapshot_unavailable")
                _fields(value, SNAPSHOT)
                _numbers(value, ("size", "fd", "flags"))
                close._object_shape(value["before"])
                close._object_shape(value["after"])
                b = raw(name)
                _need(value["before"] == value["after"] and value["flags"] & 3 == 0
                      and stat.S_ISREG(value["before"]["mode"]) and value["before"]["nlink"] == 1
                      and value["size"] == value["before"]["size"] == len(b)
                      and value["sha256"] == _sha(b), "stable_original_RO_snapshot")
                if name == "eve-held-final.raw":
                    _need(value["fd"] == control["held_fd"]["fd"]
                          and close._same_object(value["before"], control["held_fd"]["object"]), "original_held_FD")
                return (b, value["before"])
            item = check(name, snapshot)
            if item is not None:
                snapshots[name] = item
        if sum(len(v) for k, v in artifacts.items() if k.startswith("eve-") and type(v) is bytes) > 64 * 1024 * 1024:
            r["legs"]["eve_total_bound"] = False
            r["reasons"].append("eve_total_bound")
            snapshots.clear()

    if "eve-path-final.raw" in snapshots:
        final = snapshots["eve-path-final.raw"][0]
        r["raw_population"] = dict(bytes=len(final), complete_lf_records=final.count(b"\n"),
            tail_bytes=len(final) - final.rfind(b"\n") - 1 if final else 0,
            committed_lf_records=None, unread_bytes=None)

    def native():
        _need(control is not None and all(bound["legs"].get(k) is True for k in
              ("context", "registration", "manager", "root_output", "live_custody", "native_report", "child_waits")),
              "original_native_custody")
        return validate_ingress(bound["native_ingress"], control["range_ref"])
    ingress = check("native", native)
    r["ingress"] = ingress

    def source():
        policy = TrustPolicy(_decode(raw("trust.json"), 32768, lf=False))
        b = raw("source-after.raw")
        _need(b.count(b"\n") <= 4096, "Source_row_bound")
        SourceVerifier(policy).verify(b)
        _need(bound["legs"].get("context") is True, "selected_session_context")
        session = data("close-controller.json")["session_ref"]
        rows = [json.loads(line)["event"] for line in b.splitlines()]
        rows = [e for e in rows if e["capture_origin"]["session_ref"] == session]
        decisions = [e for e in rows if e["capture_origin"]["kind"] == "decision_execution"]
        r["source_decisions"] = len(decisions)
        r["source_releases"] = sum(e["capture_origin"]["kind"] == "release" for e in rows)
        return decisions
    decisions = check("source", source)

    def case_controls():
        _need(control is not None and decisions is not None, "case_originals")
        protocol = data("protocol.json")
        case = (next(v for v in protocol["cases"] if v["case_id"] == control["case_id"])
                if profile is None else profile["case_specs"][control["case_id"]])
        _need("eve-after-writer.raw" in snapshots, "actual_writer_snapshot")
        written = snapshots["eve-after-writer.raw"][0]
        pin = case["recipe_intended_pin"]
        if control["case_id"] == "ingress-receiver-killed":
            first, second = written[:pin["bytes"]], written[pin["bytes"]:]
            _need(_sha(first) == pin["sha256"] and _sha(second) == case["second_append_recipe_intended_pin"]["sha256"], "fixed_fault_input_control")
        else:
            _need(len(written) == pin["bytes"] and _sha(written) == pin["sha256"], "fixed_input_control")
        stages = [w["stage"] for w in control["writer"]]
        _need(stages == (["initial", "post_receiver_failure"] if control["case_id"] == "ingress-receiver-killed" else ["initial"]), "fixed_append_stages")
        _need(all(w["joined"] is True and w["fsync_completed"] is True and w["written_bytes"] == w["requested_bytes"] and w["error"] is None
                  and w["joined_ns"] <= control["finished_ns"] for w in control["writer"]), "finished_actual_writers")
        frontier = 0
        for w in control["writer"]:
            _need(close._same_object(w["before"], control["held_fd"]["object"])
                  and close._same_object(w["after"], snapshots["eve-after-writer.raw"][1])
                  and w["offset_before"] == w["before"]["size"] == frontier
                  and w["offset_after"] == w["after"]["size"] <= len(written)
                  and control["started_ns"] <= w["started_ns"], "same_actual_writer_generation_frontier")
            frontier = w["offset_after"]
        _need(frontier == len(written), "writer_final_frontier")
        mutation = control["mutation"]
        if "mutation" in case:
            _need(mutation is not None and mutation["kind"] == case["mutation"]["kind"]
                  and mutation["operation_completed"] is True and mutation["fsync_completed"] is True
                  and mutation["error"] is None, "actual_fixed_mutation")
            _need("eve-before-mutation.raw" in snapshots and "eve-path-final.raw" in snapshots
                  and _sha(snapshots["eve-before-mutation.raw"][0]) == pin["sha256"]
                  and _sha(snapshots["eve-path-final.raw"][0]) == case["mutation"]["replacement_intended_pin"]["sha256"], "actual_mutation_preimage_and_replacement")
            _need(mutation["path_before"] == mutation["held_before"] == snapshots["eve-before-mutation.raw"][1]
                  and mutation["path_after"] == snapshots["eve-path-final.raw"][1]
                  and mutation["held_after"] == snapshots["eve-held-final.raw"][1]
                  and close._same_object(mutation["held_before"], mutation["held_after"]), "actual_mutation_objects")
            same_path = close._same_object(mutation["path_before"], mutation["path_after"])
            _need(same_path == (mutation["kind"] != "rename_replace"), "mutation_identity_kind")
            if mutation["kind"] == "same_inode_truncate_shorter":
                _need(mutation["path_after"]["size"] < mutation["path_before"]["size"], "actual_truncation")
            if mutation["kind"] == "same_inode_same_length_overwrite":
                _need(mutation["path_after"]["size"] == mutation["path_before"]["size"], "actual_equal_length")
        else:
            _need(mutation is None, "no_undeclared_mutation")
        for signals in ([mutation] if mutation else []) + ([control["writer"][0]] if control["case_id"] == "ingress-backlog-shed" else []):
            for key, number in (("pause", 19), ("resume", 18)):
                sig = signals[key]
                actor = data("close-controller.json")["actors"]["native"]
                _need(sig is not None and sig["pid"] == actor["pid"] and sig["start_ticks"] == actor["start_ticks"]
                      and sig["signal"] == number and sig["observed_ns"] is not None and sig["error"] is None
                      and (number != 19 or sig["observed_state"] in ("T", "t")), "controlled_native_incarnation")
            finished = signals.get("joined_ns", signals["finished_ns"])
            _need(signals["pause"]["observed_ns"] <= signals["started_ns"] <= signals["finished_ns"] <= finished
                  <= signals["resume"]["requested_ns"], "controlled_operation_order")
        source_raw = raw("source-after.raw")
        policy = TrustPolicy(_decode(raw("trust.json"), 32768, lf=False))
        source_markers = []
        for m in control["markers"]:
            if m["kind"] != "source":
                continue
            tip = m["source_checkpoint"]
            _need(tip["size"] <= len(source_raw) and SourceVerifier(policy).verify(source_raw[:tip["size"]]) == tip,
                  "original_marker_checkpoint")
            rows = [json.loads(v)["event"] for v in source_raw[:tip["size"]].splitlines()]
            hits = [e for e in rows if e["capture_origin"]["session_ref"] == control["session_ref"]
                    and e["capture_origin"]["kind"] == "decision_execution" and e["normalized"]["sid"] == m["sid"]]
            _need(len(hits) == m["occurrence"] and hits[-1]["ingress_origin"] == m["ingress_origin"]
                  and control["started_ns"] <= m["observed_ns"] <= control["finished_ns"], "actual_signed_marker_record")
            source_markers.append(m)
        for spec in (case["signed_barrier"], case.get("post_mutation_signed_barrier")):
            if spec is not None:
                _need(any(m["sid"] == spec["sid"] and m["occurrence"] == spec["occurrence"] for m in source_markers), "required_signed_barrier")
        if ingress is not None and ingress["measurement_valid"] and ingress["counts"] is not None and "expected_counts" in case:
            c = ingress["counts"]
            population = _raw_classes(written)
            for key, expected_value in case["expected_counts"].items():
                aliases = {"normalized_outputs": "normalized_decisions", "blank_records": "blank", "oversized_records": "oversized_started", "non_alert_rate_shed": "shed_rate"}
                if key in ("complete_lf_records", "invalid_json_records", "raw_parseable_records"):
                    observed = written.count(b"\n") if key == "complete_lf_records" else population["unparseable" if key == "invalid_json_records" else key]
                elif key == "source_decisions":
                    observed = len(decisions)
                elif key == "policy_shed":
                    observed = sum(c["shed_by_type"].values())
                elif key == "backlog_flow_shed_min":
                    _need(c["shed_backlog"] >= expected_value and c["shed_by_type"]["flow"] >= expected_value, "actual_backlog_shedding")
                    continue
                elif key == "flow_admitted_plus_backlog_shed":
                    observed = c["admitted"] - c["alerts_admitted"] + c["shed_backlog"]
                else:
                    observed = c[aliases.get(key, key)]
                _need(observed == expected_value, "fixed_case_count:" + key)
        return True
    case_valid = check("case_controls", case_controls)

    def spans():
        _need(decisions is not None and control is not None, "authenticated_decisions_and_input_context")
        previous, matched = None, 0
        for event in decisions:
            origin = event.get("ingress_origin")
            _fields(origin, ORIGIN)
            _numbers(origin, ("device", "inode", "start_offset", "end_offset"))
            _need(origin["schema_version"] == "azazel-edge/ingress-origin/v1"
                  and origin["range_ref"] == control["range_ref"] and _hash(origin["raw_sha256"])
                  and origin["start_offset"] < origin["end_offset"], "signed_origin_shape")
            candidates = [(b, obj) for name, (b, obj) in snapshots.items() if name.startswith("eve-")
                          and all(obj[k] == origin[k] for k in ("device", "inode"))
                          and origin["end_offset"] <= len(b)]
            matching = []
            for b, _ in candidates:
                start, end = origin["start_offset"], origin["end_offset"]
                line = b[start:end]
                if (start == 0 or b[start - 1:start] == b"\n") and line.endswith(b"\n") and line.count(b"\n") == 1 and _sha(line) == origin["raw_sha256"]:
                    value = json.loads(line)
                    if (type(value) is dict and value.get("event_type") == "alert"
                            and type(value.get("alert")) is dict
                            and type(value["alert"].get("signature_id")) is int
                            and value["alert"]["signature_id"] == event["normalized"]["sid"]):
                        matching.append(line)
            _need(bool(matching), "signed_span_actual_alert_record_preimage")
            position = (origin["device"], origin["inode"], origin["start_offset"], origin["end_offset"])
            _need(previous is None or position[:2] != previous[:2] or position[2] >= previous[3], "ordered_nonoverlapping_spans")
            previous = position
            matched += 1
        r["matched_decision_spans"] = matched
        return True
    matched = check("spans", spans)
    if ingress is not None and ingress["counts"] is not None and matched is True and bound["legs"].get("selected_session") is True:
        n, d = ingress["counts"]["normalized_decisions"], r["source_decisions"]
        if n >= d:
            r["unconfirmed_decision_outputs"] = n - d
        else:
            r["reasons"].append("Source_decisions_exceed_native_normalizations")

    def committed():
        _need(ingress is not None and ingress["measurement_valid"] is True, "contiguous_native_measurement")
        _need("eve-start.raw" in snapshots and "eve-held-final.raw" in snapshots
              and "eve-path-final.raw" in snapshots, "actual_start_and_final_raw")
        initial, initial_obj = snapshots["eve-start.raw"]
        final, obj = snapshots["eve-held-final.raw"]
        current, current_obj = snapshots["eve-path-final.raw"]
        _need(initial == b"" and ingress["start_offset"] == 0 and initial_obj == control["held_fd"]["object"]
              and close._same_object(initial_obj, obj) and close._same_object(obj, current_obj)
              and current == final and all(obj[k] == ingress["input_identity"][k] for k in ("device", "inode")), "same_input_generation")
        start, end = ingress["start_offset"], ingress["committed_end_offset"]
        _need(end <= len(final) and _sha(final[start:end]) == ingress["committed_sha256"], "exact_consumed_raw_hash")
        _need(matched is True and all(e["ingress_origin"]["end_offset"] <= end
              and e["ingress_origin"]["start_offset"] >= start
              and all(e["ingress_origin"][k] == obj[k] for k in ("device", "inode")) for e in decisions), "same_consumed_signed_cohort")
        c = ingress["counts"]
        _need(c is not None and (ingress["oversized_in_progress"] or c["examined"] == final[start:end].count(b"\n")), "raw_examined_agreement")
        classes = _raw_classes(final[start:end])
        _need(c["blank"] == classes["blank"] and (ingress["oversized_in_progress"] or c["oversized_started"] == classes["oversized_started"])
              and c["alerts_admitted"] <= classes["alerts"]
              and all(v <= classes[k] for k, v in c["shed_by_type"].items()), "independent_raw_class_bounds")
        r["raw_population"] = dict(bytes=len(final), complete_lf_records=final.count(b"\n"),
            tail_bytes=len(final) - final.rfind(b"\n") - 1 if final else 0,
            committed_lf_records=final[start:end].count(b"\n"), unread_bytes=len(final) - end)
        r["committed_range_verified"] = True
        return True
    verified = check("committed", committed)
    if control is not None and (bound["source_authenticated"] is True or snapshots):
        r["status"] = "bound_partial_evidence"
    if verified is True and all_pins:
        r["status"] = "bound_consumed_prefix"
        pop = r["raw_population"]
        c = ingress["counts"]
        complete = (case_valid is True and not pop["unread_bytes"] and not pop["tail_bytes"] and not ingress["oversized_in_progress"]
                    and r["unconfirmed_decision_outputs"] == 0 and c["normalized_decisions"] == r["source_decisions"]
                    and bool(control["writer"]) and all(w["joined"] is True and w["fsync_completed"] is True
                        and w["written_bytes"] == w["requested_bytes"] and w["error"] is None for w in control["writer"])
                    and control["mutation"] is None
                    and bound["status"] == "bound_finite_close")
        observed_incomplete = bool(pop["unread_bytes"] or pop["tail_bytes"] or ingress["oversized_in_progress"]
                                   or bound["native_returncode"] == -9 or bound["receiver_returncode"] == -9
                                   or (r["unconfirmed_decision_outputs"] is not None and r["unconfirmed_decision_outputs"] > 0))
        r["whole_input_complete"] = True if complete else False if observed_incomplete else None
        if complete:
            r["status"] = "bound_complete_input"
        else:
            r["reasons"].append("whole_input_closure_not_established")
    else:
        r["reasons"].append("finite_input_range_not_established")
        if control is not None and ((control["mutation"] is not None and control["mutation"]["operation_completed"] is True) or bound["native_returncode"] == -9
                                    or bound["receiver_returncode"] == -9):
            r["whole_input_complete"] = False
    return r
