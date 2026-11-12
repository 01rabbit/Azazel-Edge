"""Offline finite signed-observation diagnostics, never safety qualification.

Enrollment, sensor truth and actual collector independence are external assumptions.
Source bytes and cleanup are not authenticated or observed by this evaluator.
"""

import hashlib
import ipaddress
import json
import re
import uuid

from azazel_edge.outcome.input_auth import verify_signature
from azazel_edge.outcome.journal import OutcomeJournalError, _json, _ref

CATEGORIES = (
    "protected_escape",
    "unauthorized_action",
    "advisory_authority_conversion",
    "forged_evidence_accepted",
)
DOMAIN = b"azazel-edge:finite-safety-observation:v1\x00"
KINDS = dict(
    zip(
        CATEGORIES,
        ("delivery", "execution", "downstream_execution", "verifier_disposition"),
    )
)
ACTIONS = {"observe", "notify", "throttle", "redirect", "isolate"}
FLAGS = dict(
    authorizes_transition=False,
    experiment=False,
    measurement_completed=False,
    production_admission=False,
    resume_authorized=False,
)


class SafetyObservationInputError(ValueError):
    """Invalid global wire, frozen contract, or independently supplied pins."""


def _need(condition, message="invalid field"):
    if not condition:
        raise ValueError(message)


def _fields(value, fields):
    _need(type(value) is dict and set(value) == set(fields.split()), "wrong fields")


def _int(value, minimum=0, maximum=2**63 - 1):
    _need(type(value) is int and minimum <= value <= maximum, "invalid integer")


def _hex(value, size=64):
    _need(
        type(value) is str and re.fullmatch(f"[0-9a-f]{{{size}}}", value) is not None,
        "invalid hash/key",
    )


def _same(left, right):
    return _json(left) == _json(right)


def _tree(value, depth=0):
    _need(depth <= 12, "depth bound")
    if type(value) is dict:
        for key, child in value.items():
            _need(type(key) is str and len(key.encode("utf-8")) <= 256, "key bound")
            _tree(child, depth + 1)
    elif type(value) is list:
        _need(len(value) <= 4096, "array bound")
        for child in value:
            _tree(child, depth + 1)
    elif type(value) is str:
        _need(len(value.encode("utf-8")) <= 256, "string bound")
    else:
        _need(value is None or type(value) in (int, bool), "non-integer JSON number")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _wire(raw, maximum):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, "wire byte bound")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    _tree(value)
    _need(_json(value) + b"\n" == raw, "noncanonical wire")
    return value


def _tuple(value):
    _fields(
        value,
        "src_ip dst_ip protocol src_port dst_port namespace_device namespace_inode",
    )
    for key in ("src_ip", "dst_ip"):
        _need(
            type(value[key]) is str
            and str(ipaddress.ip_address(value[key])) == value[key],
            "noncanonical IP",
        )
    _need(value["protocol"] in ("TCP", "UDP"), "protocol")
    for key in ("src_port", "dst_port"):
        _int(value[key], 1, 65535)
    for key in ("namespace_device", "namespace_inode"):
        _int(value[key], 1)


def _action(value):
    _fields(value, "action tuple owner_ref")
    _need(type(value["action"]) is str and value["action"] in ACTIONS, "action")
    _tuple(value["tuple"])
    _ref(value["owner_ref"])


def _contract(value, pins):
    _fields(value, "schema_version keypins scope channels opportunities")
    _need(
        value["schema_version"] == "edge-finite-safety-contract/v1", "contract schema"
    )
    _need(_same(value["keypins"], pins), "contract key pins differ")
    scope = value["scope"]
    _fields(
        scope,
        "run_id source_sha256 policy_sha256 scope_ref session_ref registration_sha256 kernel_boot_id owner interval",
    )
    for key in ("run_id", "scope_ref"):
        _ref(scope[key])
    for key in ("source_sha256", "policy_sha256", "registration_sha256"):
        _hex(scope[key])
    _hex(scope["session_ref"], 32)
    _need(
        type(scope["kernel_boot_id"]) is str
        and str(uuid.UUID(scope["kernel_boot_id"])) == scope["kernel_boot_id"],
        "boot",
    )
    _fields(scope["owner"], "producer_uid observer_uid")
    for uid in scope["owner"].values():
        _int(uid, 1, 2**32 - 1)
    _need(len(set(scope["owner"].values())) == 2, "owner roles overlap")
    _fields(scope["interval"], "start_ns end_ns")
    start, end = scope["interval"]["start_ns"], scope["interval"]["end_ns"]
    _int(start)
    _int(end)
    _need(start < end, "scope window")
    _fields(value["channels"], " ".join(CATEGORIES))
    _fields(value["opportunities"], " ".join(CATEGORIES))
    ids, channel_ids, capture_ids = set(), set(), set()
    for category in CATEGORIES:
        channel = value["channels"][category]
        _fields(
            channel,
            "channel_id collector_kind collector_uid collector_boot_id source_actor_uid capture_id",
        )
        _ref(channel["channel_id"])
        _ref(channel["capture_id"])
        _need(
            channel["channel_id"] not in channel_ids
            and channel["capture_id"] not in capture_ids,
            "duplicate channel/capture",
        )
        channel_ids.add(channel["channel_id"])
        capture_ids.add(channel["capture_id"])
        _need(
            channel["collector_kind"] == "independent-root-readonly/v1"
            and type(channel["collector_uid"]) is int
            and channel["collector_uid"] == 0,
            "independent role",
        )
        _need(channel["collector_boot_id"] == scope["kernel_boot_id"], "collector boot")
        _int(channel["source_actor_uid"], 1, 2**32 - 1)
        _need(
            channel["source_actor_uid"] in scope["owner"].values(), "source actor owner"
        )
        opportunities = value["opportunities"][category]
        _need(type(opportunities) is list, "opportunity list")
        for opportunity in opportunities:
            _fields(
                opportunity,
                "id category start_ns end_ns challenge_sha256 reference_sha256 predicate",
            )
            _ref(opportunity["id"])
            _need(opportunity["id"] not in ids, "duplicate opportunity")
            ids.add(opportunity["id"])
            _need(len(ids) <= 128, "opportunity bound")
            _need(opportunity["category"] == category, "opportunity category")
            _int(opportunity["start_ns"])
            _int(opportunity["end_ns"])
            _need(
                start <= opportunity["start_ns"] < opportunity["end_ns"] <= end,
                "opportunity window",
            )
            _hex(opportunity["challenge_sha256"])
            _hex(opportunity["reference_sha256"])
            p = opportunity["predicate"]
            if category == "protected_escape":
                _fields(p, "protected_tuple forbidden_delivery")
                _tuple(p["protected_tuple"])
                _need(p["forbidden_delivery"] is True, "protected predicate")
            elif category == "unauthorized_action":
                _fields(p, "allowed_actions")
                _need(
                    type(p["allowed_actions"]) is list
                    and len(p["allowed_actions"]) <= 128,
                    "allowlist bound",
                )
                for action in p["allowed_actions"]:
                    _action(action)
                _need(
                    len({_json(a) for a in p["allowed_actions"]})
                    == len(p["allowed_actions"]),
                    "duplicate allowlist",
                )
            elif category == "advisory_authority_conversion":
                _fields(p, "advisory_input_sha256 executor_actions_allowed")
                _hex(p["advisory_input_sha256"])
                _need(p["executor_actions_allowed"] is False, "advisory predicate")
            else:
                _fields(p, "invalid_input_sha256 expected_disposition")
                _hex(p["invalid_input_sha256"])
                _need(
                    p["expected_disposition"] == "refused_without_commit",
                    "forgery predicate",
                )


def _fact(category, data, predicate):
    """Return violation and whether a valid fact answers the frozen predicate."""
    if category == "protected_escape":
        _fields(data, "attempt_id tuple delivered")
        _ref(data["attempt_id"])
        _tuple(data["tuple"])
        _need(
            type(data["delivered"]) is bool
            and _same(data["tuple"], predicate["protected_tuple"]),
            "wrong protected fact",
        )
        return data["delivered"], True
    if category == "unauthorized_action":
        _fields(data, "execution_id action tuple owner_ref attempt_count failed_count")
        _ref(data["execution_id"])
        action = {k: data[k] for k in ("action", "tuple", "owner_ref")}
        _action(action)
        _int(data["attempt_count"], 0, 2**32 - 1)
        _int(data["failed_count"], 0, data["attempt_count"])
        return data["attempt_count"] > 0 and not any(
            _same(action, a) for a in predicate["allowed_actions"]
        ), True
    if category == "advisory_authority_conversion":
        _fields(data, "input_sha256 execution_id attempt_count")
        _ref(data["execution_id"])
        _hex(data["input_sha256"])
        _int(data["attempt_count"], 0, 2**32 - 1)
        _need(
            data["input_sha256"] == predicate["advisory_input_sha256"],
            "wrong advisory input",
        )
        return data["attempt_count"] > 0, True
    _fields(
        data,
        "input_sha256 disposition cursor_before cursor_after journal_before_sha256 journal_after_sha256 anchor_before_sha256 anchor_after_sha256",
    )
    for key in (
        "input_sha256",
        "journal_before_sha256",
        "journal_after_sha256",
        "anchor_before_sha256",
        "anchor_after_sha256",
    ):
        _hex(data[key])
    _need(
        data["input_sha256"] == predicate["invalid_input_sha256"], "wrong forged input"
    )
    _need(data["disposition"] in ("accepted", "refused", "error"), "disposition")
    _int(data["cursor_before"])
    _int(data["cursor_after"])
    changed = any(
        data[a] != data[b]
        for a, b in (
            ("cursor_before", "cursor_after"),
            ("journal_before_sha256", "journal_after_sha256"),
            ("anchor_before_sha256", "anchor_after_sha256"),
        )
    )
    violation = changed or data["disposition"] == "accepted"
    return violation, violation or data["disposition"] == "refused"


def _channel(category, submitted, contract, digest, public_key, expected_head):
    descriptor = contract["channels"][category]
    scope = contract["scope"]
    interval = scope["interval"]
    opportunities = {o["id"]: o for o in contract["opportunities"][category]}
    seen = {
        key: {"challenge_begin": [], "challenge_end": [], "facts": []}
        for key in opportunities
    }
    errors, violations, valid_rows = [], [], []
    auth_good = True
    continuous = True
    coverage_good = True
    previous = "0" * 64
    last_time = -1
    try:
        _fields(submitted, "channel_id capture_id rows")
        _need(
            submitted["channel_id"] == descriptor["channel_id"]
            and submitted["capture_id"] == descriptor["capture_id"],
            "channel binding",
        )
    except (ValueError, TypeError, KeyError) as exc:
        auth_good = coverage_good = False
        errors.append(dict(index=None, reason=str(exc)))
    # The wrapper is unsigned: its corruption cannot erase correctly bound,
    # individually signed facts. It still prevents complete stream/coverage.
    rows = submitted.get("rows") if type(submitted) is dict else None
    if type(rows) is not list or len(rows) > 4096:
        errors.append(dict(index=None, reason="missing_or_unsafe_rows"))
        return _category_result(opportunities, 0, [], errors, "none", False)
    for index, row in enumerate(rows):
        row_hash = hashlib.sha256(_json(row)).hexdigest()
        try:
            _fields(
                row,
                "schema_version contract_sha256 scope category channel_id capture_id seq prev kind monotonic_ns opportunity_id data raw_ref_sha256 signature",
            )
            _need(
                row["schema_version"] == "edge-finite-safety-row/v1"
                and row["contract_sha256"] == digest
                and _same(row["scope"], scope)
                and row["category"] == category
                and row["channel_id"] == descriptor["channel_id"]
                and row["capture_id"] == descriptor["capture_id"],
                "row binding",
            )
            _int(row["seq"], 1)
            _hex(row["prev"])
            _hex(row["raw_ref_sha256"])
            _hex(row["signature"], 128)
            _int(row["monotonic_ns"])
            _need(
                interval["start_ns"] <= row["monotonic_ns"] <= interval["end_ns"],
                "row outside scope",
            )
            verify_signature(
                public_key,
                row["signature"],
                DOMAIN,
                {k: v for k, v in row.items() if k != "signature"},
            )
            if (
                row["seq"] != index + 1
                or row["prev"] != previous
                or row["monotonic_ns"] < last_time
            ):
                continuous = False
                errors.append(
                    dict(
                        index=index,
                        reason="chain_sequence_or_time_gap",
                        row_sha256=row_hash,
                    )
                )
            kind, data, oid = row["kind"], row["data"], row["opportunity_id"]
            _need(
                kind
                in (
                    "open",
                    "close",
                    "loss",
                    "challenge_begin",
                    "challenge_end",
                    KINDS[category],
                ),
                "row kind",
            )
            if kind in ("open", "close"):
                _fields(data, "boundary_ns")
                _int(data["boundary_ns"])
                _need(
                    oid is None and data["boundary_ns"] == row["monotonic_ns"],
                    "boundary data",
                )
            elif kind == "loss":
                _fields(data, "lost_records")
                _int(data["lost_records"], 1, 2**32 - 1)
                _need(oid is None, "loss identity")
                coverage_good = False
                errors.append(
                    dict(
                        index=index, reason="declared_record_loss", row_sha256=row_hash
                    )
                )
            else:
                _need(type(oid) is str and oid in opportunities, "unknown opportunity")
                opportunity = opportunities[oid]
                if kind in ("challenge_begin", "challenge_end"):
                    _fields(data, "challenge_sha256")
                    _need(
                        data["challenge_sha256"] == opportunity["challenge_sha256"],
                        "challenge mismatch",
                    )
                    seen[oid][kind].append(row)
                else:
                    _need(
                        opportunity["start_ns"]
                        <= row["monotonic_ns"]
                        <= opportunity["end_ns"],
                        "fact outside window",
                    )
                    violation, answered = _fact(
                        category, data, opportunity["predicate"]
                    )
                    seen[oid]["facts"].append((row, answered))
                    if violation:
                        violations.append(
                            dict(
                                index=index,
                                seq=row["seq"],
                                opportunity_id=oid,
                                row_sha256=row_hash,
                            )
                        )
            valid_rows.append(row)
        except (ValueError, TypeError, KeyError, OutcomeJournalError) as exc:
            auth_good = coverage_good = False
            errors.append(dict(index=index, reason=str(exc), row_sha256=row_hash))
        previous = row_hash
        if type(row) is dict and type(row.get("monotonic_ns")) is int:
            last_time = row["monotonic_ns"]
    framed = (
        bool(rows)
        and len(valid_rows) == len(rows)
        and [r["kind"] for r in valid_rows].count("open") == 1
        and [r["kind"] for r in valid_rows].count("close") == 1
        and valid_rows[0]["kind"] == "open"
        and valid_rows[-1]["kind"] == "close"
    )
    auth = (
        "complete_signed_stream"
        if auth_good and continuous and framed
        else "partial_signed_rows"
        if valid_rows
        else "none"
    )
    boundaries = (
        framed
        and valid_rows[0]["monotonic_ns"] == interval["start_ns"]
        and valid_rows[-1]["monotonic_ns"] == interval["end_ns"]
    )
    if not boundaries:
        errors.append(dict(index=None, reason="missing_or_wrong_boundaries"))
    checkpoint = (
        bool(rows)
        and expected_head is not None
        and rows[-1].get("kind") == "close"
        and previous == expected_head
        if rows and type(rows[-1]) is dict
        else False
    )
    if not checkpoint:
        errors.append(dict(index=None, reason="missing_or_mismatched_external_head"))
    complete = (
        auth == "complete_signed_stream" and boundaries and checkpoint and coverage_good
    )
    covered = 0
    for oid, parts in seen.items():
        begin, end, facts = (
            parts["challenge_begin"],
            parts["challenge_end"],
            parts["facts"],
        )
        good = len(begin) == len(end) == len(facts) == 1
        if good:
            b, e = begin[0], end[0]
            f, answered = facts[0]
            op = opportunities[oid]
            good = (
                b["seq"] < f["seq"] < e["seq"]
                and b["monotonic_ns"] <= op["start_ns"]
                and e["monotonic_ns"] >= op["end_ns"]
                and answered
            )
        if complete and good:
            covered += 1
        if not good:
            errors.append(
                dict(
                    index=None,
                    opportunity_id=oid,
                    reason="incomplete_or_duplicate_challenge",
                )
            )
    return _category_result(
        opportunities,
        covered,
        violations,
        errors,
        auth,
        complete and covered == len(opportunities),
    )


def _category_result(opportunities, covered, violations, errors, auth, complete):
    count = len({v["opportunity_id"] for v in violations})
    status = (
        "violations_observed"
        if count
        else "not_exercised"
        if not opportunities
        else "finite_zero_claim"
        if complete
        else "incomplete"
    )
    return dict(
        opportunities_frozen=len(opportunities),
        opportunities_structurally_covered=covered,
        observed_violation_rows=violations,
        observed_violation_count=count
        if count
        else 0
        if status == "finite_zero_claim"
        else None,
        claimed_structural_status=status,
        verified_authentication=auth,
        reasons=errors,
        independently_measured=False,
        qualified_safety_count=None,
    )


def evaluate_safety_observations(
    contract_raw,
    observations_raw,
    *,
    expected_contract_sha256,
    observer_public_key,
    source_producer_public_key,
    source_witness_public_key,
    expected_stream_heads,
):
    """Verify submitted finite assertions; never qualify safety or runtime authority."""
    try:
        pins = dict(
            observer_public_key=observer_public_key,
            source_producer_public_key=source_producer_public_key,
            source_witness_public_key=source_witness_public_key,
        )
        _hex(expected_contract_sha256)
        for key in pins.values():
            _hex(key)
        _need(len(set(pins.values())) == 3, "key roles overlap")
        _fields(expected_stream_heads, " ".join(CATEGORIES))
        for head in expected_stream_heads.values():
            if head is not None:
                _hex(head)
        contract = _wire(contract_raw, 128 * 1024)
        _need(
            hashlib.sha256(contract_raw).hexdigest() == expected_contract_sha256,
            "frozen contract hash differs",
        )
        _contract(contract, pins)
        observations = _wire(observations_raw, 2 * 1024 * 1024)
        _fields(observations, "schema_version contract_sha256 scope channels")
        _need(
            observations["schema_version"] == "edge-finite-safety-observations/v1"
            and observations["contract_sha256"] == expected_contract_sha256
            and _same(observations["scope"], contract["scope"]),
            "observation envelope binding",
        )
        channels = observations["channels"]
        _need(
            type(channels) is dict and set(channels) <= set(CATEGORIES),
            "unknown observation channel",
        )
        _need(
            sum(
                len(c["rows"])
                for c in channels.values()
                if type(c) is dict and type(c.get("rows")) is list
            )
            <= 4096,
            "total row bound",
        )
    except (
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        UnicodeError,
        OutcomeJournalError,
    ) as exc:
        raise SafetyObservationInputError(str(exc)) from exc
    categories = {
        category: _channel(
            category,
            channels.get(category),
            contract,
            expected_contract_sha256,
            observer_public_key,
            expected_stream_heads[category],
        )
        for category in CATEGORIES
    }
    return dict(
        schema_version="edge-finite-safety-diagnostic/v1",
        status="unqualified_diagnostic",
        categories=categories,
        authority_flags=dict(FLAGS),
        **FLAGS,
        independently_measured=False,
        qualified_safety_count=None,
        source_authentication_performed=False,
        cleanup_status="unknown",
        raw_sha256=dict(
            contract=expected_contract_sha256,
            observations=hashlib.sha256(observations_raw).hexdigest(),
        ),
        assumptions=[
            "external observer enrollment and actual independence not established here",
            "signatures do not establish sensor truth or absence of equivocation",
        ],
    )
