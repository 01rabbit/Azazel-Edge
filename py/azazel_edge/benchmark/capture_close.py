"""Read-only annex for a finite controller-owned test object, never old coverage."""

from copy import deepcopy
import hashlib
import io
import json
import re
import stat

PROTOCOL_SHA256 = "d89e6e78266cbe6af7cc0f24a8b78ce7560d98da3eeadc6ab3c1acdd7931620b"
MAXIMUM, MAX_ROWS = 1048576, 128
CASES = (
    "clean",
    "explicit_loss",
    "abrupt_writer",
    "missing_loss_counter",
    "late_bypass",
    "seal_busy",
)
IDS = tuple(f"a{i:02d}" for i in range(16)) + ("late0", "late1")
IDENTITY = {"pid", "uid", "process_start_ticks", "boot_id", "clock_domain"}
OBJECT_ID = {"device", "inode", "owner_uid"}
OBJECT = OBJECT_ID | {"mode", "nlink", "size"}
FIELDS = {
    "plan": {
        "schema_version",
        "run_id",
        "capture_id",
        "case_id",
        "protocol_sha256",
        "source_inventory_sha256",
        "controller_identity",
        "writer_identity",
        "collector_identity",
        "object_identity",
        "gate_id",
        "gate_token",
        "attempts",
        "maximum_bytes",
    },
    "enrollment": {
        "schema_version",
        "plan_sha256",
        "source_inventory_sha256",
        "controller_identity",
        "writer_identity",
        "collector_identity",
        "object_identity",
        "started_ns",
        "finished_ns",
        "plan_bytes_read",
        "source_inventory_bytes_read",
    },
    "admission": {
        "schema_version",
        "run_id",
        "capture_id",
        "controller_identity",
        "gate_id",
        "gate_token",
        "attempts",
        "C",
        "late_controls",
    },
    "terminal": {
        "schema_version",
        "run_id",
        "capture_id",
        "controller_identity",
        "writer_identity",
        "D",
        "W",
        "S",
        "post_seal_write",
    },
    "collector": {
        "schema_version",
        "collector_identity",
        "object_before",
        "object_after",
        "access_mode",
        "seals_before",
        "seals_after",
        "read_started_ns",
        "read_finished_ns",
        "bytes_read",
        "sha256",
        "complete",
        "errors",
    },
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


def _wire(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _same(a, b):
    return _wire(a) == _wire(b)


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _uint(value):
    return type(value) is int and 0 <= value < 2**64


def _hash(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def _label(value):
    return (
        type(value) is str
        and re.fullmatch("[A-Za-z0-9_.:/-]{1,128}", value) is not None
    )


def _fields(value, fields):
    _need(type(value) is dict and set(value) == set(fields), "field_set")


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        _need(key not in value, "duplicate_JSON_key")
        value[key] = item
    return value


def _depth(value, level=0):
    _need(level <= 16, "JSON_depth_bound")
    if type(value) is dict:
        for child in value.values():
            _depth(child, level + 1)
    elif type(value) is list:
        for child in value:
            _depth(child, level + 1)


def _parse(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= MAXIMUM, "original_byte_bound")
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_JSON")),
    )
    _depth(value)
    _need(_wire(value) == raw, "canonical_JSON_LF")
    return value


def _bracket(value, start="started_ns", end="finished_ns"):
    _need(
        _uint(value[start]) and _uint(value[end]) and value[start] <= value[end],
        "actual_clock_bracket",
    )


def _identity(value):
    _fields(value, IDENTITY)
    _need(
        all(
            _uint(value[k]) and value[k] > 0
            for k in ("pid", "uid", "process_start_ticks")
        ),
        "actor_incarnation",
    )
    _need(
        type(value["boot_id"]) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]
        ),
        "actor_boot",
    )
    domain = value["clock_domain"]
    _fields(
        domain,
        {
            "time_namespace_device",
            "time_namespace_inode",
            "timens_offsets",
            "established",
        },
    )
    _need(type(domain["established"]) is bool, "clock_domain_type")
    for key in ("time_namespace_device", "time_namespace_inode"):
        _need(domain[key] is None or _uint(domain[key]), "clock_namespace_type")
    offsets = domain["timens_offsets"]
    _need(
        offsets is None or type(offsets) is list and len(offsets) <= 2, "clock_offsets"
    )
    if offsets is not None:
        for row in offsets:
            _fields(row, {"clock", "seconds", "nanoseconds"})
            _need(
                row["clock"] in ("monotonic", "boottime")
                and type(row["seconds"]) is int
                and type(row["nanoseconds"]) is int,
                "clock_offset_types",
            )
    if domain["established"]:
        _need(
            all(
                domain[k] is not None
                for k in ("time_namespace_device", "time_namespace_inode")
            )
            and offsets is not None
            and {r["clock"] for r in offsets} == {"monotonic", "boottime"}
            and all(r["seconds"] == r["nanoseconds"] == 0 for r in offsets),
            "clock_domain_unestablished",
        )


def _object_id(value):
    _fields(value, OBJECT_ID)
    _need(all(_uint(v) for v in value.values()), "object_identity_types")


def _object(value, enrolled):
    _fields(value, OBJECT)
    _need(
        all(_uint(v) for v in value.values())
        and stat.S_ISREG(value["mode"])
        and value["nlink"] == 0,
        "memfd_object_shape",
    )
    _need(
        all(_same(value[k], v) for k, v in enrolled.items()), "object_identity_mismatch"
    )


def _binding(value, plan, actor=True):
    _need(
        value["run_id"] == plan["run_id"] and value["capture_id"] == plan["capture_id"],
        "run_capture_binding",
    )
    if actor:
        _need(
            _same(value["controller_identity"], plan["controller_identity"]),
            "controller_incarnation_binding",
        )


def _plan(value):
    _need(
        value["case_id"] in CASES
        and _label(value["run_id"])
        and _label(value["capture_id"])
        and _label(value["gate_id"])
        and _hash(value["gate_token"])
        and value["protocol_sha256"] == PROTOCOL_SHA256
        and _hash(value["source_inventory_sha256"]),
        "plan_profile_pins",
    )
    _need(
        type(value["maximum_bytes"]) is int and 1 <= value["maximum_bytes"] <= MAXIMUM,
        "plan_capture_bound",
    )
    for key in ("controller_identity", "writer_identity", "collector_identity"):
        _identity(value[key])
    actors = [
        value[k]
        for k in ("controller_identity", "writer_identity", "collector_identity")
    ]
    _need(
        len({a["pid"] for a in actors}) == 3
        and len({a["uid"] for a in actors}) == 1
        and len({a["boot_id"] for a in actors}) == 1,
        "distinct_process_same_UID_boot",
    )
    _object_id(value["object_identity"])
    _need(value["object_identity"]["owner_uid"] == actors[0]["uid"], "capture_owner")
    _need(
        type(value["attempts"]) is list and len(value["attempts"]) == 18,
        "fixed_attempt_population",
    )
    for ordinal, attempt in enumerate(value["attempts"]):
        _fields(attempt, {"id", "seq", "payload_sha256", "payload_bytes", "phase"})
        _need(
            attempt["id"] == IDS[ordinal]
            and type(attempt["seq"]) is int
            and attempt["seq"] == ordinal
            and _hash(attempt["payload_sha256"])
            and type(attempt["payload_bytes"]) is int
            and 0 <= attempt["payload_bytes"] <= value["maximum_bytes"]
            and attempt["phase"] == ("pre_C" if ordinal < 16 else "late"),
            "fixed_attempt_identity_or_payload",
        )


def _capture(raw, plan, pinned, report):
    """Bounded lazy parsing; a later broken row never erases earlier facts."""
    rows, matching, occurrences, unexpected, conflicts = [], set(), {}, set(), set()
    footer = footer_hash = None
    full, previous, last_seq, consumed = True, "0" * 64, -1, 0
    if type(raw) is not bytes:
        return dict(
            rows=rows,
            matching=matching,
            occurrences=occurrences,
            unexpected=unexpected,
            conflicts=conflicts,
            footer=None,
            footer_hash=None,
            full=False,
        )
    if len(raw) > MAXIMUM:
        report["reasons"].append("capture_byte_bound")
        full = False
    stream = io.BytesIO(raw[: MAXIMUM + 1])
    expected_attempts = (
        {a["id"]: a for a in plan["attempts"]} if plan is not None else {}
    )
    for number in range(MAX_ROWS + 1):
        line = stream.readline(MAXIMUM + 1 - consumed) if consumed <= MAXIMUM else b""
        if not line:
            break
        try:
            _need(
                number < MAX_ROWS and consumed + len(line) <= MAXIMUM,
                "capture_row_or_byte_bound",
            )
            row = _parse(line)
            _need(
                type(row) is dict
                and row.get("schema_version") == "edge-capture-close-frame/v1"
                and row.get("prev_sha256") == previous
                and footer is None,
                "frame_chain_or_after_footer",
            )
            if plan is not None:
                _binding(row, plan, actor=False)
            if row.get("kind") == "data":
                _fields(
                    row,
                    {
                        "schema_version",
                        "kind",
                        "run_id",
                        "capture_id",
                        "attempt_id",
                        "seq",
                        "payload_hex",
                        "prev_sha256",
                    },
                )
                _need(
                    _label(row["attempt_id"])
                    and type(row["seq"]) is int
                    and 0 <= row["seq"] <= 17
                    and type(row["payload_hex"]) is str
                    and len(row["payload_hex"]) % 2 == 0
                    and re.fullmatch("[0-9a-f]*", row["payload_hex"]) is not None,
                    "data_frame_types",
                )
                identifier = row["attempt_id"]
                occurrences[identifier] = occurrences.get(identifier, 0) + 1
                if row["seq"] <= last_seq:
                    report["reasons"].append(
                        "duplicate_or_reordered_DATA:" + identifier
                    )
                    conflicts.add(identifier)
                last_seq = row["seq"]
                expected = expected_attempts.get(identifier)
                if plan is not None and (
                    expected is None or expected["phase"] == "late"
                ):
                    unexpected.add(identifier)
                payload = bytes.fromhex(row["payload_hex"])
                if (
                    expected is not None
                    and row["seq"] == expected["seq"]
                    and len(payload) == expected["payload_bytes"]
                    and _sha(payload) == expected["payload_sha256"]
                ):
                    if pinned and plan is not None and expected["phase"] == "pre_C":
                        matching.add(identifier)
                elif plan is not None:
                    conflicts.add(identifier)
                    report["reasons"].append(
                        "unexpected_or_conflicting_DATA:" + identifier
                    )
                rows.append(dict(sha256=_sha(line), row=deepcopy(row)))
            elif row.get("kind") == "terminal":
                footer, footer_hash = row, _sha(line)
                # Preserve even a missing mandatory counter as an invalid D leg.
            else:
                raise ValueError("unknown_frame_kind")
            consumed += len(line)
            previous = _sha(line)
        except ERRORS as exc:
            report["reasons"].append("capture_prefix_invalid:" + str(exc))
            full = False
            break
    if consumed != len(raw):
        full = False
    return dict(
        rows=rows,
        matching=matching,
        occurrences=occurrences,
        unexpected=unexpected,
        conflicts=conflicts,
        footer=footer,
        footer_hash=footer_hash,
        last_seq=last_seq,
        full=full,
    )


def evaluate_capture_close(
    plan_raw,
    admission_raw,
    terminal_raw,
    collector_raw,
    capture_raw,
    *,
    expected,
    enrollment_raw=None,
):
    """Verify finite test accounting only; no I/O, old coverage conversion or authority."""
    report = dict(
        schema_version="edge-capture-close-analysis/v1",
        status="unqualified",
        case_id=None,
        finite_accounting_complete=False,
        complete_finite_capture=False,
        known_matching_ids=[],
        exact_matching_ids=[],
        unexpected_ids=[],
        conflicting_ids=[],
        admitted_ids=[],
        denied_ids=[],
        unresolved_attempt_ids=[],
        unresolved_admitted_ids=[],
        terminal_missing_ids=None,
        terminal_missing_count=None,
        unresolved_count=None,
        upstream_produced=None,
        upstream_dropped=None,
        runtime_inflight=None,
        independent_read_verified=False,
        valid_capture_rows=[],
        originals={},
        raw_sha256={},
        legs={
            k: None
            for k in (
                "plan",
                "enrollment",
                "admission",
                "terminal_data",
                "wait",
                "seal",
                "collector",
                "post_seal_control",
                "common_clock",
                "boundary_order",
            )
        },
        reasons=[],
        old_category_counts={
            k: None
            for k in (
                "unauthorized_action",
                "advisory_authority_conversion",
                "forged_evidence_accepted",
                "protected_escape",
            )
        },
        old_evaluation_modified=False,
        performance_acceptance=False,
        safety_count=None,
        whole_window_coverage=False,
        comparison_qualified=False,
        whole_measurement_qualified=False,
        production_admission=False,
        resume_authorized=False,
        qualified_safety_count=None,
        authority_flags={
            k: False
            for k in (
                "authorizes_transition",
                "experiment",
                "measurement_completed",
                "production_admission",
                "resume_authorized",
            )
        },
        known_data_provenance="pinned_raw_capture_prefix_independent_read_verified_separately",
        trust_scope="finite_controller_owned_test_capture_same_UID_kernel_controller_premises_not_independent_production_custody",
    )
    reasons, legs = report["reasons"], report["legs"]
    raw = dict(
        plan=plan_raw,
        admission=admission_raw,
        terminal=terminal_raw,
        collector=collector_raw,
        capture=capture_raw,
        enrollment=enrollment_raw,
    )
    values, pins = {}, {}
    envelope_good = type(expected) is dict and set(expected) == {
        k + "_sha256" for k in raw
    }
    if not envelope_good:
        reasons.append("expected_pin_envelope_invalid")
    for name, data in raw.items():
        pin = expected.get(name + "_sha256") if type(expected) is dict else None
        digest = _sha(data) if type(data) is bytes and len(data) <= MAXIMUM else None
        report["raw_sha256"][name] = digest
        pins[name] = type(data) is bytes and _hash(pin) and pin == digest
        if data is None:
            if pin is not None:
                reasons.append(name + ":pin_without_original")
            reasons.append(name + ":original_unavailable")
            continue
        if not pins[name]:
            reasons.append(name + ":original_pin_missing_mismatched_or_overbound")
        if name == "capture":
            continue
        try:
            value = _parse(data)
            report["originals"][name] = deepcopy(value)
            _fields(value, FIELDS[name])
            _need(
                value["schema_version"] == "edge-capture-close-" + name + "/v1",
                "schema_version",
            )
            _need(pins[name], "external_original_pin")
            values[name] = value
        except ERRORS as exc:
            reasons.append(name + ":" + str(exc))
    plan = values.get("plan")
    if plan is not None:
        try:
            _plan(plan)
            report["case_id"] = plan["case_id"]
            legs["plan"] = True
        except ERRORS as exc:
            reasons.append("plan:" + str(exc))
            legs["plan"] = False
            plan = None
    capture = _capture(capture_raw, plan, pins["capture"], report)
    report["valid_capture_rows"] = capture["rows"]
    report["terminal_footer"] = deepcopy(capture["footer"])
    report["terminal_footer_sha256"] = capture["footer_hash"]
    report["known_matching_ids"] = sorted(capture["matching"])
    report["exact_matching_ids"] = sorted(
        k
        for k in capture["matching"]
        if capture["occurrences"][k] == 1 and k not in capture["conflicts"]
    )
    report["unexpected_ids"] = sorted(capture["unexpected"])
    report["conflicting_ids"] = sorted(
        capture["conflicts"] | {k for k, v in capture["occurrences"].items() if v > 1}
    )
    if plan is None:
        return report
    if (
        len(capture_raw) > plan["maximum_bytes"]
        if type(capture_raw) is bytes
        else False
    ):
        reasons.append("capture_plan_byte_bound")
        capture["full"] = False
    actors = [
        plan[k]
        for k in ("controller_identity", "writer_identity", "collector_identity")
    ]
    common = all(
        a["clock_domain"]["established"] is True
        and _same(a["clock_domain"], actors[0]["clock_domain"])
        for a in actors
    )
    legs["common_clock"] = common
    if not common:
        reasons.append("actor_common_clock_unestablished")
    admission = values.get("admission")
    admitted, denied, unresolved = set(), set(), set()
    admission_shape = False
    if admission is not None:
        try:
            _binding(admission, plan)
            _need(
                admission["gate_id"] == plan["gate_id"]
                and admission["gate_token"] == plan["gate_token"],
                "same_gate_token",
            )
            _need(
                type(admission["attempts"]) is list
                and len(admission["attempts"]) == 18,
                "attempt_ledger_population",
            )
            for index, attempt in enumerate(admission["attempts"]):
                _fields(
                    attempt,
                    {"id", "decision", "attempt_started_ns", "attempt_finished_ns"},
                )
                _need(
                    attempt["id"] == IDS[index]
                    and attempt["decision"]
                    in ("admitted", "rejected_closed", "not_attempted"),
                    "attempt_ledger_identity",
                )
                decision = attempt["decision"]
                if decision == "not_attempted":
                    _need(
                        attempt["attempt_started_ns"]
                        is attempt["attempt_finished_ns"]
                        is None,
                        "not_attempted_clocks",
                    )
                    unresolved.add(attempt["id"])
                else:
                    _bracket(attempt, "attempt_started_ns", "attempt_finished_ns")
                    (admitted if decision == "admitted" else denied).add(attempt["id"])
            admission_shape = True
            report.update(
                admitted_ids=sorted(admitted),
                denied_ids=sorted(denied),
                unresolved_attempt_ids=sorted(unresolved),
            )
            close = admission["C"]
            _fields(
                close,
                {"started_ns", "finished_ns", "gate_id", "gate_token", "admitted_ids"},
            )
            _bracket(close)
            _need(
                close["gate_id"] == plan["gate_id"]
                and close["gate_token"] == plan["gate_token"],
                "closed_same_gate",
            )
            _need(
                _same(close["admitted_ids"], [x for x in IDS if x in admitted]),
                "admitted_frontier",
            )
            for attempt in admission["attempts"]:
                if attempt["decision"] == "admitted":
                    _need(
                        attempt["attempt_finished_ns"] <= close["started_ns"],
                        "admission_after_C",
                    )
                elif attempt["decision"] == "rejected_closed":
                    _need(
                        close["finished_ns"] <= attempt["attempt_started_ns"],
                        "denial_before_C",
                    )
            _need(
                admitted == set(IDS[:16])
                and denied == set(IDS[16:])
                and not unresolved,
                "frozen_admission_not_fully_exercised",
            )
            late = admission["late_controls"]
            _need(type(late) is list and len(late) == 2, "late_control_population")
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
                _need(
                    control["id"] == IDS[16 + index]
                    and control["gate_id"] == plan["gate_id"]
                    and control["gate_token"] == plan["gate_token"],
                    "late_same_gate_binding",
                )
                _bracket(control)
                _need(
                    _uint(control["poll_before_ns"])
                    and _uint(control["poll_after_ns"])
                    and close["finished_ns"]
                    <= control["poll_before_ns"]
                    <= control["started_ns"]
                    <= control["finished_ns"]
                    <= control["poll_after_ns"]
                    and control["poll_before_returncode"] is None
                    and control["poll_after_returncode"] is None,
                    "late_control_actual_live_polls",
                )
                attempt = admission["attempts"][16 + index]
                _need(
                    control["started_ns"]
                    <= attempt["attempt_started_ns"]
                    <= attempt["attempt_finished_ns"]
                    <= control["finished_ns"],
                    "late_invocation_bracket",
                )
            legs["admission"] = True
        except ERRORS as exc:
            legs["admission"] = False
            reasons.append("admission:" + str(exc))
    enrollment = values.get("enrollment")
    if enrollment is not None:
        try:
            _bracket(enrollment)
            _need(
                enrollment["plan_sha256"] == _sha(plan_raw)
                and enrollment["source_inventory_sha256"]
                == plan["source_inventory_sha256"],
                "enrollment_plan_source",
            )
            for key in (
                "controller_identity",
                "writer_identity",
                "collector_identity",
                "object_identity",
            ):
                _need(_same(enrollment[key], plan[key]), "enrollment_actor_object")
            _need(
                type(enrollment["plan_bytes_read"]) is int
                and enrollment["plan_bytes_read"] == len(plan_raw)
                and type(enrollment["source_inventory_bytes_read"]) is int
                and 0 < enrollment["source_inventory_bytes_read"] <= MAXIMUM,
                "enrollment_actual_read_sizes",
            )
            _need(
                admission_shape
                and enrollment["finished_ns"]
                <= min(
                    a["attempt_started_ns"]
                    for a in admission["attempts"]
                    if a["decision"] != "not_attempted"
                ),
                "enrollment_not_prospective",
            )
            legs["enrollment"] = True
        except ERRORS as exc:
            legs["enrollment"] = False
            reasons.append("enrollment:" + str(exc))
    terminal = values.get("terminal")
    terminal_bound = False
    if terminal is not None:
        try:
            _binding(terminal, plan)
            _need(
                _same(terminal["writer_identity"], plan["writer_identity"]),
                "writer_incarnation_binding",
            )
            terminal_bound = True
        except ERRORS as exc:
            reasons.append("terminal:" + str(exc))
    if terminal_bound:
        try:
            wait = terminal["W"]
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
                and wait["pid"] == plan["writer_identity"]["pid"]
                and type(wait["process_start_ticks"]) is int
                and wait["process_start_ticks"]
                == plan["writer_identity"]["process_start_ticks"]
                and wait["waited"] is True
                and type(wait["returncode"]) is int
                and wait["returncode"] == 0,
                "normal_supervised_writer_wait_unavailable",
            )
            legs["wait"] = True
        except ERRORS as exc:
            legs["wait"] = False
            reasons.append("wait:" + str(exc))
        try:
            seal = terminal["S"]
            _fields(
                seal,
                {
                    "started_ns",
                    "finished_ns",
                    "result",
                    "errno",
                    "seals_before",
                    "seals_after",
                    "object_identity",
                },
            )
            _bracket(seal)
            _need(
                _same(seal["object_identity"], plan["object_identity"]),
                "seal_object_binding",
            )
            _need(
                seal["result"] in ("sealed", "failed")
                and _uint(seal["seals_before"])
                and _uint(seal["seals_after"]),
                "seal_result_types",
            )
            _need(
                seal["result"] == "sealed"
                and seal["errno"] is None
                and seal["seals_after"] == 15,
                "kernel_seal_unestablished",
            )
            # W chronology is a separate leg; do not erase an observed S barrier.
            legs["seal"] = True
        except ERRORS as exc:
            legs["seal"] = False
            reasons.append("seal:" + str(exc))
        try:
            post = terminal["post_seal_write"]
            _fields(
                post,
                {"attempted", "started_ns", "finished_ns", "bytes_written", "errno"},
            )
            _need(type(post["attempted"]) is bool, "post_seal_attempt_type")
            if post["attempted"]:
                _bracket(post)
                _need(
                    legs["seal"] is True
                    and terminal["S"]["finished_ns"] <= post["started_ns"]
                    and post["bytes_written"] is None
                    and type(post["errno"]) is int
                    and post["errno"] == 1,
                    "post_seal_EPERM_not_observed",
                )
                legs["post_seal_control"] = True
            else:
                _need(
                    all(post[k] is None for k in post if k != "attempted"),
                    "unattempted_post_seal_fields",
                )
        except ERRORS as exc:
            legs["post_seal_control"] = False
            reasons.append("post_seal_control:" + str(exc))
    collector = values.get("collector")
    if collector is not None:
        try:
            _need(
                _same(collector["collector_identity"], plan["collector_identity"]),
                "collector_incarnation_binding",
            )
            _object(collector["object_before"], plan["object_identity"])
            _object(collector["object_after"], plan["object_identity"])
            _need(
                _same(collector["object_before"], collector["object_after"]),
                "collector_object_changed",
            )
            _bracket(collector, "read_started_ns", "read_finished_ns")
            _need(
                type(collector["access_mode"]) is int
                and collector["access_mode"] == 0
                and type(collector["seals_before"]) is int
                and collector["seals_before"] == 15
                and type(collector["seals_after"]) is int
                and collector["seals_after"] == 15,
                "readonly_sealed_descriptor_unestablished",
            )
            _need(
                type(collector["complete"]) is bool
                and collector["complete"] is True
                and collector["errors"] == []
                and type(collector["errors"]) is list
                and pins["capture"]
                and type(collector["bytes_read"]) is int
                and collector["bytes_read"]
                == len(capture_raw)
                == collector["object_before"]["size"]
                and collector["sha256"] == _sha(capture_raw),
                "full_independent_read_unestablished",
            )
            legs["collector"] = report["independent_read_verified"] = True
        except ERRORS as exc:
            legs["collector"] = False
            reasons.append("collector:" + str(exc))
    footer = capture["footer"]
    if terminal_bound and footer is not None:
        try:
            _need("declared_lost" in footer, "mandatory_loss_counter_missing")
            _fields(
                footer,
                {
                    "schema_version",
                    "kind",
                    "run_id",
                    "capture_id",
                    "last_seq",
                    "declared_records",
                    "declared_lost",
                    "lost_ids",
                    "prev_sha256",
                },
            )
            _need(
                capture["full"]
                and type(footer["last_seq"]) is int
                and footer["last_seq"] == capture["last_seq"],
                "terminal_frontier_incomplete",
            )
            _need(
                type(footer["declared_records"]) is int
                and footer["declared_records"] == len(capture["rows"])
                and type(footer["declared_lost"]) is int
                and 0 <= footer["declared_lost"] <= 18
                and type(footer["lost_ids"]) is list
                and all(type(k) is str for k in footer["lost_ids"])
                and len(set(footer["lost_ids"]))
                == len(footer["lost_ids"])
                == footer["declared_lost"],
                "mandatory_terminal_counter_or_loss_ids",
            )
            ack = terminal["D"]
            _need(ack is not None, "actual_footer_ACK_unavailable")
            _fields(ack, {"started_ns", "finished_ns", "footer_sha256"})
            _bracket(ack)
            _need(
                ack["footer_sha256"] == capture["footer_hash"], "actual_footer_ACK_hash"
            )
            _need(admission_shape, "terminal_admission_population_unavailable")
            exact = set(report["exact_matching_ids"]) & admitted
            _need(
                set(footer["lost_ids"]) == admitted - exact
                and not set(footer["lost_ids"]) & exact,
                "declared_loss_differs_from_recount",
            )
            legs["terminal_data"] = True
        except ERRORS as exc:
            legs["terminal_data"] = False
            reasons.append("terminal_data:" + str(exc))
    elif footer is None:
        reasons.append("terminal_data:footer_unavailable")
    report["unresolved_admitted_ids"] = sorted(
        admitted - set(report["exact_matching_ids"])
    )
    if report["unexpected_ids"]:
        reasons.append("unadmitted_DATA_retained")
    if report["conflicting_ids"]:
        reasons.append("conflicting_or_duplicate_DATA_retained")
    if all(
        legs[key] is True
        for key in (
            "admission",
            "terminal_data",
            "wait",
            "seal",
            "collector",
            "common_clock",
        )
    ):
        try:
            _need(
                max(item["poll_after_ns"] for item in admission["late_controls"])
                <= terminal["D"]["started_ns"]
                <= terminal["D"]["finished_ns"]
                <= terminal["W"]["started_ns"]
                <= terminal["W"]["finished_ns"]
                <= terminal["S"]["started_ns"]
                <= terminal["S"]["finished_ns"]
                <= collector["read_started_ns"],
                "C_D_W_S_R_actual_order_unestablished",
            )
            legs["boundary_order"] = True
        except ERRORS as exc:
            legs["boundary_order"] = False
            reasons.append("boundary_order:" + str(exc))
    mandatory = (
        "plan",
        "enrollment",
        "admission",
        "terminal_data",
        "wait",
        "seal",
        "collector",
        "common_clock",
        "boundary_order",
    )
    complete = (
        envelope_good
        and all(legs[k] is True for k in mandatory)
        and pins["capture"]
        and capture["full"]
    )
    complete = (
        complete
        and not report["unexpected_ids"]
        and not report["conflicting_ids"]
        and legs["post_seal_control"] is not False
    )
    if complete:
        missing = admitted - set(report["exact_matching_ids"])
        report.update(
            finite_accounting_complete=True,
            complete_finite_capture=not missing,
            terminal_missing_ids=sorted(missing),
            terminal_missing_count=len(missing),
            unresolved_count=0,
            unresolved_admitted_ids=[],
            status="verified_finite_capture"
            if not missing
            else "accounted_with_explicit_loss",
        )
    return report
