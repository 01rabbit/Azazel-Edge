"""Read-only finite load facts. Missing evidence is never a measured zero."""

import hashlib
import json

from . import finite_ingress as finite
from .native_source_accounting import ERRORS, _decode, _fields, _need, _uint

PROTOCOL_SHA256 = "9764ea4b3d907f63d53f3526cfeef9f91895af6d8a0de44cc10236f636f8beec"
ARMS = ("load-off", "load-on", "load-faulted")
EXTRA_FILES = frozenset(
    "load-controller.json corpus-manifest.json observer-config.json observer-policy.json observer-phase.raw observer-calls.raw observer-context.raw observer-completion.json observer-stdout.raw observer-stderr.raw observer-journal.raw observer-outcomes.raw".split()
)
FILES = finite.FILES | EXTRA_FILES
CLASSES = ("flow", "dns", "stats", "http")
MARKERS = ((9000, 90232001), (18000, 90232002), (27004, 90232003))
CONTROL = set(
    "schema_version case_id protocol_sha256 corpus_sha256 session_ref started_ns finished_ns controller_identity controller_anchors writer observer resources errors audits".split()
)
WRITER = set(
    "pid tid fd flags before after started_ns first_write_before_ns marker_one_before_ns final_nonalert_after_ns finished_ns joined_ns written_bytes nonalert_records per_class write_calls fsync_completed joined sha256 error".split()
)
IDENTITY = set(
    "pid start_ticks native_tid boot_id clock_domain clock_ticks_per_second clock_resolutions".split()
)


def _limit(name):
    if name not in EXTRA_FILES:
        return (
            finite.EVE_LIMIT
            if name.startswith("eve-")
            else finite.close.BIG
            if name.startswith("normalized-log-")
            else 4096
            if name == "native-close.raw"
            else finite.close._limit(name)
        )
    if name in ("observer-stdout.raw", "observer-stderr.raw"):
        return 65536
    if name == "observer-context.raw":
        return 16384
    if name in ("observer-phase.raw", "observer-calls.raw"):
        return 4 * 1024 * 1024
    if name in ("observer-journal.raw", "observer-outcomes.raw"):
        return 8 * 1024 * 1024
    if name == "observer-completion.json":
        return 65536
    return 128 * 1024


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _wire(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def materialize_corpus():
    """Frozen intended corpus; independently retained raw bytes remain evidence."""
    blocks, markers, offset = [], [], 0
    lookup = dict(MARKERS)
    for index in range(27004):
        value = dict(event_type=CLASSES[index % 4], load_index=index, padding="")
        value["padding"] = "x" * (600 - len(_wire(value)))
        line = _wire(value)
        assert len(line) == 600
        blocks.append(line)
        offset += len(line)
        if index + 1 in lookup:
            sid = lookup[index + 1]
            alert = dict(
                timestamp="2026-01-01T00:00:00Z",
                event_type="alert",
                src_ip="192.0.2.1",
                dest_ip="192.0.2.2",
                dest_port=22,
                proto="TCP",
                alert=dict(
                    signature_id=sid,
                    signature="finite load fixture",
                    category="test",
                    severity=2,
                ),
            )
            raw = _wire(alert)
            markers.append(
                dict(
                    sid=sid,
                    after_nonalert=index + 1,
                    start_offset=offset,
                    end_offset=offset + len(raw),
                    raw_sha256=_sha(raw),
                )
            )
            blocks.append(raw)
            offset += len(raw)
    raw = b"".join(blocks)
    manifest = dict(
        schema_version="edge-finite-load-corpus/v1",
        protocol_sha256=PROTOCOL_SHA256,
        sha256=_sha(raw),
        bytes=len(raw),
        lf_records=27007,
        nonalert_records=27004,
        per_class=dict.fromkeys(CLASSES, 6751),
        markers=markers,
    )
    return raw, manifest


def _profile():
    raw, manifest = materialize_corpus()
    case = dict(
        recipe_intended_pin=dict(bytes=len(raw), sha256=manifest["sha256"]),
        signed_barrier=dict(sid=90232003, occurrence=1),
    )
    return dict(
        protocol_sha256=PROTOCOL_SHA256,
        cases={arm: ("normal_stop", [s for _, s in MARKERS]) for arm in ARMS},
        case_specs={arm: case for arm in ARMS},
        close_profile=dict(
            load_cost=True, protocol_schema="edge-finite-load-cost-protocol/v1"
        ),
    )


def evaluate_finite_load_cost_case(artifacts, *, expected):
    result = dict(
        schema_version="edge-finite-load-analysis/v1",
        case_id=None,
        status="withheld",
        pins={},
        raw_sha256={},
        reasons=[],
        finite=None,
        corpus=None,
        load=None,
        intake=None,
        native_cost=None,
        receiver_cost=None,
        observer=None,
        authority_flags=finite.close.AUTHORITY.copy(),
    )
    if (
        type(artifacts) is not dict
        or set(artifacts) != FILES
        or type(expected) is not dict
        or set(expected) != FILES
    ):
        result["reasons"].append("exact_artifact_pin_envelope")
        return result
    for name in FILES:
        raw, pin = artifacts[name], expected[name]
        limit = _limit(name)
        digest = _sha(raw) if type(raw) is bytes and len(raw) <= limit else None
        if (
            name in ("observer-phase.raw", "observer-calls.raw")
            and type(raw) is bytes
            and raw.count(b"\n") > 900
        ):
            digest = None
        valid = type(pin) is str and digest == pin
        result["raw_sha256"][name] = digest
        result["pins"][name] = valid
        if name == "evaluation.json":
            result["raw_sha256"][name] = result["pins"][name] = None
        elif not valid and not (raw is None and pin is None):
            result["reasons"].append(name + ":invalid_supplied_pin")

    def original(name):
        _need(result["pins"][name], name + ":missing_or_invalid_pin")
        return artifacts[name]

    def data(name):
        return _decode(original(name), 128 * 1024, lf=True)

    bound = finite._evaluate_finite_profile(
        {k: artifacts[k] for k in finite.FILES},
        expected={k: expected[k] for k in finite.FILES},
        profile=_profile(),
    )
    result["finite"] = bound
    result["case_id"] = bound["case_id"]
    result["native_cost"] = bound["close"].get("native_cost")
    result["receiver_cost"] = bound["close"].get("receiver_cost")

    try:
        _need(result["case_id"] in ARMS, "fixed_case")
        controller = data("load-controller.json")
        _fields(controller, CONTROL)
        ic = data("ingress-controller.json")
        cc = data("close-controller.json")
        _need(
            controller["schema_version"] == "edge-finite-load-controller/v1"
            and controller["case_id"] == result["case_id"]
            and controller["protocol_sha256"] == PROTOCOL_SHA256
            and controller["session_ref"] == ic["session_ref"],
            "bound_load_context",
        )
        identity = controller["controller_identity"]
        _fields(identity, IDENTITY)
        _need(
            identity["boot_id"] == cc["boot_id"]
            and all(
                _uint(identity[k], 2**63) and identity[k] > 0
                for k in ("pid", "start_ticks", "native_tid", "clock_ticks_per_second")
            ),
            "Root_controller_incarnation",
        )
        _fields(
            identity["clock_domain"],
            set(
                "time_namespace_device time_namespace_inode timens_offsets established".split()
            ),
        )
        _need(
            type(identity["clock_domain"]["established"]) is bool,
            "explicit_clock_domain_evidence",
        )
        _fields(controller["controller_anchors"], {"before", "after"})
        anchors = controller["controller_anchors"]
        for anchor in anchors.values():
            _fields(anchor, {"monotonic_before_ns", "epoch_ns", "monotonic_after_ns"})
            _need(
                all(_uint(v, 2**63) for v in anchor.values())
                and anchor["monotonic_before_ns"] <= anchor["monotonic_after_ns"],
                "real_controller_anchor_shape",
            )
        _need(
            all(_uint(controller[k], 2**63) for k in ("started_ns", "finished_ns"))
            and anchors["before"]["monotonic_after_ns"]
            <= controller["started_ns"]
            <= controller["finished_ns"]
            <= anchors["after"]["monotonic_before_ns"],
            "controller_anchor_containment",
        )
        intended, manifest = materialize_corpus()
        _need(data("corpus-manifest.json") == manifest, "fixed_corpus_manifest")
        _need(
            controller["corpus_sha256"] == manifest["sha256"], "controller_corpus_pin"
        )
        _need(
            bound["legs"].get("context") is True
            and bound["legs"].get("case_controls") is True,
            "independent_input_writer_custody",
        )
        observed = original("eve-after-writer.raw")
        _need(
            observed == intended and original("eve-path-final.raw") == intended,
            "actual_retained_corpus",
        )
        result["corpus"] = dict(
            status="verified",
            sha256=_sha(observed),
            bytes=len(observed),
            nonalert_records=27004,
            per_class=dict.fromkeys(CLASSES, 6751),
        )
        writer = controller["writer"]
        _fields(writer, WRITER)
        original_writer = ic["writer"][0]
        shared = set(
            "pid tid fd flags before after started_ns finished_ns joined_ns written_bytes write_calls fsync_completed joined error".split()
        )
        _need(
            all(writer[k] == original_writer[k] for k in shared)
            and writer["pid"] == identity["pid"]
            and all(
                _uint(writer[k], 2**63)
                for k in ("pid", "tid", "fd", "flags", "write_calls")
            )
            and writer["pid"] > 0
            and writer["tid"] > 0
            and controller["started_ns"]
            <= writer["started_ns"]
            <= writer["joined_ns"]
            <= controller["finished_ns"],
            "same_independently_bound_paced_writer",
        )
        _need(
            writer["error"] is None
            and writer["joined"] is True
            and writer["fsync_completed"] is True
            and writer["sha256"] == _sha(observed)
            and writer["written_bytes"] == len(observed)
            and writer["nonalert_records"] == 27004
            and writer["per_class"] == dict.fromkeys(CLASSES, 6751),
            "actual_completed_paced_writer",
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
            "actual_writer_brackets",
        )
        start, middle, end = (writer[k] for k in keys[1:4])
        full, warmup, measurement = end - start, middle - start, end - middle
        _need(full > 0 and measurement > 0, "nonempty_actual_load_intervals")
        full_rate = 27004 * 1e9 / full
        measurement_rate = 18004 * 1e9 / measurement
        qualified = (
            full >= 9_000_000_000
            and warmup >= 3_000_000_000
            and measurement >= 6_000_000_000
            and abs(full_rate / 3000 - 1) <= 0.02
            and abs(measurement_rate / 3000 - 1) <= 0.02
        )
        result["load"] = dict(
            status="qualified" if qualified else "failed",
            full_ns=full,
            warmup_ns=warmup,
            measurement_ns=measurement,
            full_nonalert_per_second=full_rate,
            measurement_nonalert_per_second=measurement_rate,
            full_per_class_per_second=full_rate / 4,
            measurement_per_class_per_second=measurement_rate / 4,
            reasons=[] if qualified else ["fixed_rate_or_duration_not_met"],
        )
    except ERRORS as error:
        result["reasons"].append("load:" + str(error))

    try:
        _need(
            result["corpus"] is not None
            and bound["committed_range_verified"] is True
            and bound["legs"].get("spans") is True,
            "verified_actual_native_prefix",
        )
        ingress = bound["ingress"]
        counts = ingress["counts"]
        _need(
            counts is not None and ingress["measurement_valid"] is True,
            "final_native_measurement",
        )
        prefix = original("eve-held-final.raw")[: ingress["committed_end_offset"]]
        alerts = [
            json.loads(line)
            for line in prefix.splitlines()
            if json.loads(line).get("event_type") == "alert"
        ]
        _need(
            len(alerts) == counts["alerts_admitted"] == bound["source_decisions"]
            and bound["unconfirmed_decision_outputs"] == 0,
            "bound_examined_marker_population",
        )
        examined = counts["examined"] - len(alerts)
        _need(0 <= examined <= 27004, "actual_examined_nonalert_population")
        qualified = examined * 100 >= 27004 * 98
        result["intake"] = dict(
            status="qualified" if qualified else "failed",
            examined_nonalert=examined,
            written_nonalert=27004,
            percent=examined * 100 / 27004,
            reasons=[] if qualified else ["below_98_percent"],
        )
    except ERRORS as error:
        result["reasons"].append("intake:" + str(error))
    result["reasons"].append(
        "observer_clock_requires_separate_original_recording_verification"
    )
    if bound["whole_input_complete"] is not True:
        result["reasons"].append("finite_input_completion_not_established")
    return result


def evaluate_finite_load_cost_comparison(cases):
    result = dict(
        schema_version="edge-finite-load-comparison/v1",
        status="withheld",
        reasons=[],
        cases=cases,
        differences=[],
        authority_flags=finite.close.AUTHORITY.copy(),
    )
    if (
        type(cases) is not list
        or len(cases) != 3
        or any(type(c) is not dict for c in cases)
        or [c.get("case_id") for c in cases] != list(ARMS)
    ):
        result["reasons"].append("fixed_order_all_three_original_arms_required")
        return result

    def fact(case, name):
        value = case.get(name)
        return value if type(value) is dict else {}

    hashes = [fact(c, "corpus").get("sha256") for c in cases]
    if None in hashes or len(set(hashes)) != 1:
        result["reasons"].append("same_actual_corpus_not_established")
    for case in cases:
        arm = case["case_id"]
        for gate in ("load", "intake"):
            if fact(case, gate).get("status") != "qualified":
                result["reasons"].append(arm + ":" + gate + "_not_qualified")
        if fact(case, "finite").get("whole_input_complete") is not True:
            result["reasons"].append(arm + ":finite_completion_not_established")
    baseline = cases[0]
    for case in cases[1:]:
        delta = dict(
            case_id=case["case_id"],
            status="withheld",
            reasons=[],
            native_cost=None,
            receiver_cost=None,
        )
        result["differences"].append(delta)
        gates = all(
            fact(c, g).get("status") == "qualified"
            for c in (baseline, case)
            for g in ("load", "intake")
        ) and all(
            fact(c, "finite").get("whole_input_complete") is True
            for c in (baseline, case)
        )
        if (
            not gates
            or hashes[0] is None
            or hashes[0] != fact(case, "corpus").get("sha256")
        ):
            delta["reasons"].append("same_complete_finite_population_and_load_required")
            continue
        for role in ("native_cost", "receiver_cost"):
            before, after = fact(baseline, role), fact(case, role)
            phases = (
                finite.close.NATIVE_COST_PHASES
                if role == "native_cost"
                else finite.close.RECEIVER_COST_PHASES
            )
            try:
                finite.close._cost(before, phases)
                finite.close._cost(after, phases)
            except ERRORS:
                delta["reasons"].append(role + ":invalid_phase_aggregate")
                continue
            if not (
                before.get("complete") is True
                and after.get("complete") is True
                and type(before.get("phases")) is dict
                and type(after.get("phases")) is dict
                and set(before["phases"]) == set(after["phases"])
            ):
                delta["reasons"].append(role + ":complete_valid_totals_required")
                continue
            values = {}
            for name, end in after["phases"].items():
                start = before["phases"][name]
                values[name] = (
                    None
                    if start is None or end is None
                    else {k: end[k] - start[k] for k in start}
                )
            delta[role] = values
        if not delta["reasons"]:
            delta["status"] = "descriptive_measured_difference"
    result["reasons"].append("OFF_and_FAULTED_do_not_establish_complete_observer_clock")
    result["reasons"].append(
        "sequential_stale_marker_pilot_is_not_full_performance_or_safety_acceptance"
    )
    return result
