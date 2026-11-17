"""Read-only regular Source test-origin annex; original verifiers stay unchanged."""

from copy import deepcopy
import io
import stat

from .capture_close import (
    _wire,
    _sha,
    _same,
    _need,
    _uint,
    _hash,
    _label,
    _fields,
    _parse,
    MAXIMUM,
)
from .notification_timing import _domain
from .source_authentication import verify_source_bytes
from .source_witness import verify_witnessed_source_prefix
from ..outcome.journal import _parse as _source_parse

PROTOCOL_SHA256 = "4b8c23e3adf2b3f082cad016c4270ba845b33aeb25cc36fc155813ae2e3dd3e0"
IDS = tuple(f"a{i:02d}" for i in range(8))
LATE_IDS = ("late0", "late1")
KINDS = (
    "session_prepare",
    "session_start",
    *("decision_execution",) * 5,
    "session_end",
)
IDENTITY = {"pid", "uid", "process_start_ticks", "boot_id", "clock_domain"}
SOURCE_ARGS = {
    "expected_trust_sha256",
    "expected_context",
    "expected_prefix_checkpoint",
    "expected_final_checkpoint",
}
WITNESS_ARGS = {
    "expected_trust_sha256",
    "expected_context",
    "expected_source_checkpoint",
    "expected_anchor_checkpoint",
}
PLAN = {
    "schema_version",
    "run_id",
    "capture_id",
    "case_id",
    "protocol_sha256",
    "source_inventory_sha256",
    "trust_sha256",
    "expected_context",
    "controller_identity",
    "producer_identity",
    "collector_identity",
    "source_identity",
    "gate_id",
    "gate_token",
    "attempts",
    "late_ids",
    "maximum_bytes",
}
CONTROLLER = {
    "schema_version",
    "run_id",
    "capture_id",
    "controller_identity",
    "producer_identity",
    "gate_id",
    "gate_token",
    "enrollment",
    "attempts",
    "C",
    "late_controls",
    "prefix_selection",
    "final_selection",
    "writer_close",
    "post_close_append",
    "W",
    "test_loss_ids",
}
READ = {
    "schema_version",
    "collector_identity",
    "source_before",
    "source_after",
    "access_mode",
    "read_started_ns",
    "read_finished_ns",
    "bytes_read",
    "sha256",
    "complete",
    "errors",
}
ERRORS = (
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    OverflowError,
    RecursionError,
    UnicodeError,
)


def _actor(value):
    _fields(value, IDENTITY)
    _need(
        _uint(value["pid"])
        and value["pid"] > 0
        and _uint(value["uid"])
        and _uint(value["process_start_ticks"])
        and value["process_start_ticks"] > 0,
        "actor_incarnation",
    )
    import re

    _need(
        type(value["boot_id"]) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]
        ),
        "actor_boot",
    )
    _domain(value["clock_domain"])


def _bracket(value, begin="started_ns", end="finished_ns"):
    _need(
        _uint(value[begin]) and _uint(value[end]) and value[begin] <= value[end],
        "actual_clock_bracket",
    )


def _source_object(value, expected):
    _fields(
        value,
        {
            "device",
            "inode",
            "owner_uid",
            "mode",
            "nlink",
            "size",
            "mtime_ns",
            "ctime_ns",
        },
    )
    _need(
        all(_uint(v) for v in value.values())
        and stat.S_ISREG(value["mode"])
        and value["nlink"] == 1
        and not value["mode"] & 0o022
        and all(_same(value[k], v) for k, v in expected.items()),
        "regular_Source_identity_or_mode",
    )


def _plan(value):
    _fields(value, PLAN)
    _need(
        value["schema_version"] == "edge-real-source-close-plan/v1"
        and value["case_id"] in ("clean", "explicit_loss", "abrupt_writer")
        and value["protocol_sha256"] == PROTOCOL_SHA256
        and _hash(value["source_inventory_sha256"])
        and _hash(value["trust_sha256"])
        and _label(value["run_id"])
        and _label(value["capture_id"])
        and _label(value["gate_id"])
        and _hash(value["gate_token"]),
        "test_plan_profile",
    )
    _need(
        type(value["maximum_bytes"]) is int and 1 <= value["maximum_bytes"] <= MAXIMUM,
        "source_byte_bound",
    )
    _fields(value["source_identity"], {"device", "inode", "owner_uid"})
    _need(
        all(_uint(v) for v in value["source_identity"].values()),
        "source_identity_types",
    )
    for key in ("controller_identity", "producer_identity", "collector_identity"):
        _actor(value[key])
    _need(
        value["controller_identity"]["uid"] == 0
        and value["producer_identity"]["uid"] == 1000
        and value["collector_identity"]["uid"] == 61002
        and value["source_identity"]["owner_uid"] == 1000
        and len(
            {
                value[k]["pid"]
                for k in (
                    "controller_identity",
                    "producer_identity",
                    "collector_identity",
                )
            }
        )
        == 3,
        "existing_test_role_binding",
    )
    _need(
        type(value["attempts"]) is list
        and len(value["attempts"]) == 8
        and value["late_ids"] == list(LATE_IDS),
        "fixed_test_population",
    )
    expected_native = (
        [0, 1, 2, 3, None, 4, 5, 6]
        if value["case_id"] == "explicit_loss"
        else list(range(8))
    )
    hashes = []
    for ordinal, attempt in enumerate(value["attempts"]):
        _fields(attempt, {"id", "kind", "event_sha256", "native_seq"})
        _need(
            attempt["id"] == IDS[ordinal]
            and attempt["kind"] == KINDS[ordinal]
            and _hash(attempt["event_sha256"])
            and _same(attempt["native_seq"], expected_native[ordinal]),
            "prospective_synthetic_recipe_ordinal",
        )
        hashes.append(attempt["event_sha256"])
    _need(len(set(hashes)) == 8, "ambiguous_test_event_hashes")


def _test_event(event):
    origin = event.get("capture_origin", {})
    if origin.get("kind") != "decision_execution":
        return
    enforcement, posture = event.get("enforcement"), event.get("enforcement_status")
    _need(
        type(enforcement) is dict
        and type(posture) is dict
        and event.get("defense", {}).get("action") == "observe"
        and enforcement.get("mode") == "disabled"
        and enforcement.get("result") == "not_executed"
        and type(enforcement.get("executed_count")) is int
        and enforcement["executed_count"] == 0
        and type(enforcement.get("failed_count")) is int
        and enforcement["failed_count"] == 0
        and enforcement.get("command_plan") == []
        and enforcement.get("rollback_plan") == []
        and enforcement.get("errors") == []
        and posture.get("enforce_enabled") is False
        and posture.get("dry_run") is True
        and posture.get("high_impact_auto") is False,
        "not_disabled_SYNTHETIC_test_decision",
    )


def _argument_guard(value, fields):
    # Selector dictionaries have a small closed grammar; inspect without encoding.
    _need(type(value) is dict and len(value) == len(fields), "argument_shape")
    _fields(value, fields)
    stack = [(value, 0)]
    visited = 0
    encoded_budget = 1  # Final canonical newline; no serialization during this walk.
    while stack:
        item, depth = stack.pop()
        visited += 1
        _need(depth <= 16, "argument_depth_bound")
        _need(visited <= 128, "argument_structure_bound")
        if type(item) is dict:
            _need(len(item) <= 32, "argument_dictionary_bound")
            _need(all(type(key) is str for key in item), "argument_key_type")
            encoded_budget += 2 + 2 * len(item)
            encoded_budget += sum(12 * len(key) + 2 for key in item)
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            _need(len(item) <= 32, "argument_list_bound")
            encoded_budget += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        else:
            _need(
                item is None or type(item) in (str, int, bool, float),
                "argument_value_type",
            )
            if type(item) is str:
                _need(len(item) <= MAXIMUM, "argument_string_bound")
                encoded_budget += 12 * len(item) + 2
            elif type(item) is int:
                _need(item.bit_length() <= 64, "argument_integer_bound")
                encoded_budget += 21
            else:
                encoded_budget += 32
        _need(encoded_budget <= MAXIMUM, "argument_aggregate_byte_bound")


def evaluate_real_source_close(
    trust_raw,
    source_raw,
    anchors_raw,
    *,
    source_arguments,
    witness_arguments,
    plan_raw=None,
    controller_raw=None,
    read_raw=None,
    expected,
):
    """Retain both original replays even when annex data/pins are unavailable."""
    result = dict(
        schema_version="edge-real-source-close-analysis/v1",
        status="unqualified",
        original_source_evaluation=None,
        original_witness_evaluation=None,
        original_errors={},
        known_signed_ids=[],
        unexpected_ids=[],
        unverified_source_diagnostics=[],
        unresolved_ids=list(IDS),
        finite_test_gate_accounting_complete=False,
        complete_assigned_test_capture=False,
        test_gate_missing_count=None,
        test_gate_missing_ids=None,
        independent_read_verified=False,
        witnessed_prefix_equals_final=None,
        authenticated_declared_test_terminal=False,
        raw_pin_verified={},
        raw_sha256={},
        originals={},
        reasons=[],
        legs={
            key: None
            for key in (
                "plan",
                "source_selectors",
                "source_authentication",
                "witness_prefix",
                "controller",
                "wait",
                "writer_close",
                "post_close_control",
                "read",
                "common_clock",
                "order",
            )
        },
        native_registry_authentication="not_exercised",
        actual_native_execution=False,
        actual_native_terminal_verified=None,
        source_immutability=False,
        native_atomic_close=None,
        upstream_produced=None,
        upstream_loss=None,
        runtime_inflight=None,
        whole_window_coverage=False,
        old_evaluation_modified=False,
        performance_acceptance=False,
        comparison_qualified=False,
        whole_measurement_qualified=False,
        production_admission=False,
        resume_authorized=False,
        safety_count=None,
        qualified_safety_count=None,
        old_category_counts={
            key: None
            for key in (
                "unauthorized_action",
                "advisory_authority_conversion",
                "forged_evidence_accepted",
                "protected_escape",
            )
        },
        authority_flags={
            key: False
            for key in (
                "authorizes_transition",
                "experiment",
                "measurement_completed",
                "production_admission",
                "resume_authorized",
            )
        },
        scope="actual_regular_Source_signing_storage_witness_mechanics_SYNTHETIC_declared_v3_origin_registration_payloads",
    )
    reasons, legs = result["reasons"], result["legs"]
    # These standalone APIs are neither modified nor fed substituted bytes.
    for name, function, args, kwargs in (
        ("source", verify_source_bytes, (trust_raw, source_raw), source_arguments),
        (
            "witness",
            verify_witnessed_source_prefix,
            (trust_raw, source_raw, anchors_raw),
            witness_arguments,
        ),
    ):
        try:
            for index, original in enumerate(args):
                limit = 32768 if index == 0 else MAXIMUM
                _need(
                    original is None
                    or type(original) is bytes
                    and len(original) <= limit,
                    "annex_original_byte_bound_before_delegation",
                )
            _argument_guard(kwargs, SOURCE_ARGS if name == "source" else WITNESS_ARGS)
            _need(
                len(_wire(kwargs)) <= MAXIMUM,
                "annex_argument_bound_before_delegation",
            )
            result["original_" + name + "_evaluation"] = function(*args, **kwargs)
        except ERRORS as exc:
            result["original_errors"][name] = dict(
                type=type(exc).__name__, reason=str(exc)
            )
    raw = dict(
        trust=trust_raw,
        source=source_raw,
        anchors=anchors_raw,
        plan=plan_raw,
        controller=controller_raw,
        read=read_raw,
    )
    names = set(raw) | {"source_arguments", "witness_arguments"}
    envelope_good = type(expected) is dict and set(expected) == {
        name + "_sha256" for name in names
    }
    if not envelope_good:
        reasons.append("external_pin_envelope_invalid")
    pins, values = {}, {}
    for name, data in raw.items():
        maximum = 32768 if name == "trust" else MAXIMUM
        digest = _sha(data) if type(data) is bytes and len(data) <= maximum else None
        pin = expected.get(name + "_sha256") if type(expected) is dict else None
        pins[name] = type(data) is bytes and _hash(pin) and pin == digest
        result["raw_sha256"][name] = digest
        if data is None:
            reasons.append(
                name + ":original_unavailable"
                if pin is None
                else name + ":pin_without_original"
            )
            continue
        if not pins[name]:
            reasons.append(name + ":raw_pin_or_bound_invalid")
        if name in ("plan", "controller", "read"):
            try:
                value = _parse(data)
                result["originals"][name] = deepcopy(value)
                _need(pins[name], "external_original_pin")
                values[name] = value
            except ERRORS as exc:
                reasons.append(name + ":" + str(exc))
    for name, args, fields in (
        ("source_arguments", source_arguments, SOURCE_ARGS),
        ("witness_arguments", witness_arguments, WITNESS_ARGS),
    ):
        pins[name] = False
        try:
            _argument_guard(args, fields)
            encoded = _wire(args)
            _need(len(encoded) <= MAXIMUM, "argument_byte_bound")
            # Strict JSON/depth/type validation even though original APIs remain independent.
            _parse(encoded)
            pin = expected.get(name + "_sha256") if type(expected) is dict else None
            _need(_hash(pin) and _sha(encoded) == pin, "external_argument_pin")
            pins[name] = True
        except ERRORS as exc:
            reasons.append(name + ":" + str(exc))
    result["raw_pin_verified"] = dict(pins)
    source_eval, witness_eval = (
        result["original_source_evaluation"],
        result["original_witness_evaluation"],
    )
    plan = values.get("plan")
    if plan is not None:
        try:
            _plan(plan)
            legs["plan"] = True
        except ERRORS as exc:
            legs["plan"] = False
            reasons.append("plan:" + str(exc))
            plan = None
    selectors = False
    if plan is not None:
        try:
            _need(
                all(
                    pins[key]
                    for key in (
                        "source_arguments",
                        "witness_arguments",
                        "trust",
                        "source",
                        "plan",
                    )
                ),
                "required_source_context_pins",
            )
            _need(
                _same(plan["expected_context"], source_arguments["expected_context"])
                and _same(
                    plan["expected_context"], witness_arguments["expected_context"]
                )
                and plan["trust_sha256"]
                == expected["trust_sha256"]
                == source_arguments["expected_trust_sha256"]
                == witness_arguments["expected_trust_sha256"]
                and _same(
                    source_arguments["expected_prefix_checkpoint"],
                    witness_arguments["expected_source_checkpoint"],
                ),
                "source_context_or_prefix_selectors",
            )
            context = plan["expected_context"]
            _need(
                all(
                    context["boot_ref"] == plan[role]["boot_id"].replace("-", "")
                    for role in (
                        "controller_identity",
                        "producer_identity",
                        "collector_identity",
                    )
                )
                and type(context["producer_uid"]) is int
                and context["producer_uid"]
                == plan["producer_identity"]["uid"]
                == plan["source_identity"]["owner_uid"]
                == 1000
                and type(context["observer_uid"]) is int
                and context["observer_uid"] == 65534,
                "source_context_actor_boot_or_UID",
            )
            selectors = legs["source_selectors"] = True
        except ERRORS as exc:
            legs["source_selectors"] = False
            reasons.append("source_selectors:" + str(exc))
    source_replay_bound = all(
        pins[key] for key in ("trust", "source", "source_arguments")
    )
    witness_replay_bound = all(
        pins[key] for key in ("trust", "source", "anchors", "witness_arguments")
    )
    result["original_replay_provenance"] = dict(
        source=dict(
            required_raw_and_argument_pins_verified=source_replay_bound,
            required_pins=["trust", "source", "source_arguments"],
        ),
        witness=dict(
            required_raw_and_argument_pins_verified=witness_replay_bound,
            required_pins=["trust", "source", "anchors", "witness_arguments"],
        ),
        meaning="unchanged_signature_diagnostics_not_native_enrollment_or_execution",
    )
    authenticated_size = 0
    if type(source_eval) is dict:
        if source_eval["authenticated_full_source"]:
            authenticated_size = source_eval["final_tip"]["size"]
        elif source_eval["authenticated_prefix"]:
            authenticated_size = source_eval["prefix_tip"]["size"]
        legs["source_authentication"] = bool(
            source_replay_bound
            and source_eval["authenticated_full_source"]
            and source_eval["normal_terminal_verified"]
        )
        result["authenticated_declared_test_terminal"] = (
            selectors and legs["source_authentication"] is True
        )
    if type(witness_eval) is dict:
        legs["witness_prefix"] = bool(
            witness_replay_bound and witness_eval["witness_prefix_authenticated"]
        )
        if (
            source_replay_bound
            and witness_replay_bound
            and type(source_eval) is dict
            and source_eval["final_tip"] is not None
            and witness_eval["source_checkpoint"] is not None
        ):
            result["witnessed_prefix_equals_final"] = _same(
                source_eval["final_tip"], witness_eval["source_checkpoint"]
            )
    known, unexpected = [], []
    source_rows_good = True
    if type(source_raw) is bytes and len(source_raw) <= MAXIMUM and authenticated_size:
        stream = io.BytesIO(source_raw[:authenticated_size])
        consumed = 0
        lookup = (
            {attempt["event_sha256"]: attempt for attempt in plan["attempts"]}
            if plan is not None
            else {}
        )
        for number in range(129):
            line = (
                stream.readline(MAXIMUM + 1 - consumed) if consumed <= MAXIMUM else b""
            )
            if not line:
                break
            try:
                _need(number < 128, "annex_Source_row_bound")
                row = _source_parse(line)
                event = row["event"]
                event_hash = _sha(_wire(event))
                attempt = lookup.get(event_hash)
                origin = event["capture_origin"]
                if selectors:
                    _test_event(event)
                    if (
                        attempt is not None
                        and attempt["native_seq"] is not None
                        and attempt["kind"] == origin["kind"]
                        and _same(attempt["native_seq"], origin["seq"])
                    ):
                        _need(
                            attempt["id"] not in known,
                            "duplicate_signed_test_assignment",
                        )
                        known.append(attempt["id"])
                    else:
                        unexpected.append("source-seq-" + str(row["seq"]))
                else:
                    result["unverified_source_diagnostics"].append(
                        dict(
                            source_seq=row["seq"],
                            event_sha256=event_hash,
                            provenance="original_signature_diagnostic_new_context_pins_unverified",
                        )
                    )
                consumed += len(line)
            except ERRORS as exc:
                source_rows_good = False
                reasons.append("signed_Source_diagnostic:" + str(exc))
                break
        if consumed != authenticated_size:
            source_rows_good = False
    result["known_signed_ids"], result["unexpected_ids"] = known, unexpected
    result["unresolved_ids"] = [
        identifier for identifier in IDS if identifier not in known
    ]
    if plan is None:
        return result
    if type(source_raw) is bytes and len(source_raw) > plan["maximum_bytes"]:
        source_rows_good = False
        reasons.append("plan_Source_byte_bound")
    actors = [
        plan[key]
        for key in ("controller_identity", "producer_identity", "collector_identity")
    ]
    common = all(
        actor["boot_id"] == actors[0]["boot_id"]
        and actor["clock_domain"]["established"] is True
        and _same(actor["clock_domain"], actors[0]["clock_domain"])
        for actor in actors
    )
    legs["common_clock"] = common
    if not common:
        reasons.append("common_actor_clock_unestablished")
    controller = values.get("controller")
    controller_bound = False
    if controller is not None:
        try:
            _fields(controller, CONTROLLER)
            _need(
                controller["schema_version"] == "edge-real-source-close-controller/v1"
                and controller["run_id"] == plan["run_id"]
                and controller["capture_id"] == plan["capture_id"]
                and controller["gate_id"] == plan["gate_id"]
                and controller["gate_token"] == plan["gate_token"]
                and _same(
                    controller["controller_identity"], plan["controller_identity"]
                )
                and _same(controller["producer_identity"], plan["producer_identity"]),
                "controller_identity_gate_binding",
            )
            controller_bound = True
        except ERRORS as exc:
            reasons.append("controller:" + str(exc))
            legs["controller"] = False
    if controller_bound:
        try:
            enrollment = controller["enrollment"]
            _fields(
                enrollment,
                {
                    "started_ns",
                    "finished_ns",
                    "plan_sha256",
                    "plan_bytes_read",
                    "source_inventory_sha256",
                    "source_inventory_bytes_read",
                    "source_identity",
                },
            )
            _bracket(enrollment)
            _need(
                enrollment["plan_sha256"] == _sha(plan_raw)
                and enrollment["source_inventory_sha256"]
                == plan["source_inventory_sha256"]
                and type(enrollment["plan_bytes_read"]) is int
                and enrollment["plan_bytes_read"] == len(plan_raw)
                and type(enrollment["source_inventory_bytes_read"]) is int
                and 0 < enrollment["source_inventory_bytes_read"] <= MAXIMUM
                and _same(enrollment["source_identity"], plan["source_identity"]),
                "prospective_enrollment_readback",
            )
            attempts = controller["attempts"]
            _need(
                type(attempts) is list and len(attempts) == 10, "test_gate_population"
            )
            for index, attempt in enumerate(attempts):
                _fields(attempt, {"id", "decision", "started_ns", "finished_ns"})
                _need(
                    attempt["id"] == (IDS + LATE_IDS)[index]
                    and attempt["decision"]
                    in ("admitted", "rejected_closed", "not_attempted"),
                    "test_gate_attempt",
                )
                if attempt["decision"] == "not_attempted":
                    _need(
                        attempt["started_ns"] is attempt["finished_ns"] is None,
                        "not_attempted_clocks",
                    )
                    raise ValueError("test_attempt_unresolved")
                _bracket(attempt)
                _need(
                    attempt["decision"]
                    == ("admitted" if index < 8 else "rejected_closed"),
                    "test_gate_decision",
                )
            _need(
                enrollment["finished_ns"] <= min(a["started_ns"] for a in attempts),
                "enrollment_not_prospective",
            )
            _need(
                all(
                    previous["finished_ns"] <= current["started_ns"]
                    for previous, current in zip(attempts, attempts[1:])
                ),
                "test_gate_attempts_not_serial",
            )
            close = controller["C"]
            _fields(
                close,
                {"started_ns", "finished_ns", "gate_id", "gate_token", "admitted_ids"},
            )
            _bracket(close)
            _need(
                close["gate_id"] == plan["gate_id"]
                and close["gate_token"] == plan["gate_token"]
                and _same(close["admitted_ids"], list(IDS))
                and max(a["finished_ns"] for a in attempts[:8]) <= close["started_ns"],
                "same_closed_test_gate",
            )
            prefix = controller["prefix_selection"]
            _fields(
                prefix,
                {"started_ns", "finished_ns", "source_checkpoint", "anchor_checkpoint"},
            )
            _bracket(prefix)
            _need(
                selectors
                and source_eval is not None
                and witness_eval is not None
                and _same(
                    prefix["source_checkpoint"],
                    source_arguments["expected_prefix_checkpoint"],
                )
                and _same(
                    prefix["anchor_checkpoint"],
                    witness_arguments["expected_anchor_checkpoint"],
                )
                and prefix["source_checkpoint"]["seq"] == 4
                and max(a["finished_ns"] for a in attempts[:8]) <= prefix["started_ns"]
                and prefix["finished_ns"] <= close["started_ns"],
                "prospective_prefix4_selection",
            )
            late = controller["late_controls"]
            _need(type(late) is list and len(late) == 2, "late_test_gate_population")
            for index, control in enumerate(late):
                _fields(
                    control,
                    {
                        "id",
                        "gate_id",
                        "gate_token",
                        "started_ns",
                        "finished_ns",
                        "poll_before_ns",
                        "poll_after_ns",
                        "poll_before_returncode",
                        "poll_after_returncode",
                    },
                )
                _bracket(control)
                _need(
                    control["id"] == LATE_IDS[index]
                    and control["gate_id"] == plan["gate_id"]
                    and control["gate_token"] == plan["gate_token"]
                    and _uint(control["poll_before_ns"])
                    and _uint(control["poll_after_ns"])
                    and close["finished_ns"]
                    <= control["poll_before_ns"]
                    <= control["started_ns"]
                    <= attempts[8 + index]["started_ns"]
                    <= attempts[8 + index]["finished_ns"]
                    <= control["finished_ns"]
                    <= control["poll_after_ns"]
                    and control["poll_before_returncode"] is None
                    and control["poll_after_returncode"] is None,
                    "same_late_invocation_live_poll",
                )
            legs["controller"] = True
        except ERRORS as exc:
            legs["controller"] = False
            reasons.append("controller:" + str(exc))
        try:
            wait = controller["W"]
            _fields(
                wait,
                {
                    "started_ns",
                    "finished_ns",
                    "pid",
                    "process_start_ticks",
                    "returncode",
                    "waited",
                },
            )
            _bracket(wait)
            _need(
                type(wait["pid"]) is int
                and wait["pid"] == plan["producer_identity"]["pid"]
                and type(wait["process_start_ticks"]) is int
                and wait["process_start_ticks"]
                == plan["producer_identity"]["process_start_ticks"]
                and wait["waited"] is True
                and type(wait["returncode"]) is int
                and wait["returncode"] == 0,
                "normal_actual_producer_wait",
            )
            legs["wait"] = True
        except ERRORS as exc:
            legs["wait"] = False
            reasons.append("wait:" + str(exc))
        try:
            close = controller["writer_close"]
            _fields(close, {"started_ns", "finished_ns", "returned"})
            _bracket(close)
            _need(close["returned"] is True, "original_writer_close_return_unavailable")
            legs["writer_close"] = True
        except ERRORS as exc:
            legs["writer_close"] = False
            reasons.append("writer_close:" + str(exc))
        try:
            post = controller["post_close_append"]
            _fields(
                post,
                {
                    "attempted",
                    "started_ns",
                    "finished_ns",
                    "outcome",
                    "exception_type",
                    "source_unchanged",
                },
            )
            _need(type(post["attempted"]) is bool, "post_close_attempt_type")
            if post["attempted"]:
                _bracket(post)
                _need(
                    legs["writer_close"] is True
                    and controller["writer_close"]["finished_ns"] <= post["started_ns"]
                    and post["outcome"] == "raised"
                    and post["exception_type"] == "OutcomeJournalError"
                    and post["source_unchanged"] is True,
                    "same_closed_writer_append_refusal",
                )
                legs["post_close_control"] = True
            else:
                _need(
                    all(post[k] is None for k in post if k != "attempted"),
                    "unattempted_post_close_fields",
                )
        except ERRORS as exc:
            legs["post_close_control"] = False
            reasons.append("post_close_control:" + str(exc))
    read = values.get("read")
    if read is not None:
        try:
            _fields(read, READ)
            _need(
                read["schema_version"] == "edge-real-source-close-read/v1"
                and _same(read["collector_identity"], plan["collector_identity"]),
                "Source_reader_identity",
            )
            _source_object(read["source_before"], plan["source_identity"])
            _source_object(read["source_after"], plan["source_identity"])
            _bracket(read, "read_started_ns", "read_finished_ns")
            _need(
                _same(read["source_before"], read["source_after"])
                and type(read["access_mode"]) is int
                and read["access_mode"] == 0
                and read["complete"] is True
                and type(read["errors"]) is list
                and read["errors"] == []
                and pins["source"]
                and type(read["bytes_read"]) is int
                and read["bytes_read"]
                == len(source_raw)
                == read["source_before"]["size"]
                and read["sha256"] == _sha(source_raw),
                "complete_stable_regular_Source_read_unavailable",
            )
            _need(
                plan["collector_identity"]["clock_domain"]["established"] is True,
                "reader_clock_domain_unestablished",
            )
            legs["read"] = result["independent_read_verified"] = True
        except ERRORS as exc:
            legs["read"] = False
            reasons.append("read:" + str(exc))
    if (
        controller_bound
        and legs["controller"]
        and legs["wait"]
        and legs["writer_close"]
        and legs["read"]
    ):
        try:
            final = controller["final_selection"]
            _fields(final, {"started_ns", "finished_ns", "source_checkpoint"})
            _bracket(final)
            _need(
                source_eval is not None
                and _same(
                    final["source_checkpoint"],
                    source_arguments["expected_final_checkpoint"],
                )
                and controller["W"]["finished_ns"]
                <= final["started_ns"]
                <= final["finished_ns"]
                <= read["read_started_ns"]
                and max(c["poll_after_ns"] for c in controller["late_controls"])
                <= controller["writer_close"]["started_ns"]
                <= controller["writer_close"]["finished_ns"]
                <= controller["W"]["started_ns"],
                "actual_close_wait_read_order",
            )
            if legs["post_close_control"]:
                _need(
                    controller["post_close_append"]["finished_ns"]
                    <= controller["W"]["started_ns"],
                    "post_close_control_after_wait",
                )
            legs["order"] = True
        except ERRORS as exc:
            legs["order"] = False
            reasons.append("order:" + str(exc))
    if not legs["source_authentication"]:
        reasons.append("authenticated_declared_terminal_or_full_Source_unavailable")
    if unexpected:
        reasons.append("unexpected_authenticated_Source_rows")
    mandatory = (
        "plan",
        "source_selectors",
        "source_authentication",
        "witness_prefix",
        "controller",
        "wait",
        "writer_close",
        "post_close_control",
        "read",
        "common_clock",
        "order",
    )
    complete = (
        envelope_good
        and all(legs[k] is True for k in mandatory)
        and source_rows_good
        and not unexpected
    )
    if complete:
        loss = controller["test_loss_ids"]
        expected_loss = ["a04"] if plan["case_id"] == "explicit_loss" else []
        if (
            type(loss) is list
            and _same(loss, expected_loss)
            and set(IDS) - set(known) == set(loss)
        ):
            result.update(
                finite_test_gate_accounting_complete=True,
                complete_assigned_test_capture=not loss,
                test_gate_missing_count=len(loss),
                test_gate_missing_ids=list(loss),
                unresolved_ids=[],
                status="complete_assigned_test_capture"
                if not loss
                else "accounted_explicit_test_omission",
            )
        else:
            reasons.append("trusted_test_omission_does_not_match_signed_ID_recount")
    return result
