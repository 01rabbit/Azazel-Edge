"""Enrolled finite original-byte association, never safety or event attestation."""

import hashlib

from azazel_edge.outcome.journal import _ref
from . import safety_observations as safety
from . import safety_evidence_composition as composition
from .forged_input_refusal import _object

REQUIRED_LAYERS = (
    "input_bytes",
    "reference_authentication",
    "baseline_witness",
    "journal_cursor_structure",
    "worker_refusal",
    "sampled_source",
    "sampled_journal",
    "sampled_anchors",
)
MAX_ENROLLMENT_BYTES = 128 * 1024
MAX_ENTRIES = 64
ERRORS = composition.ERRORS + (AttributeError, IndexError)
CATEGORY_BY_KIND = {
    **{kind: "forged_evidence_accepted" for kind in composition.KINDS[:2]},
    "advisory_exec": "advisory_authority_conversion",
    **{kind: "unauthorized_action" for kind in composition.KINDS[3:]},
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _enrollment(raw, pin, main_contract_sha256):
    """Exact optional manifest; external pins never establish capture chronology."""
    safety._hex(pin)
    safety._need(
        type(raw) is bytes
        and 0 < len(raw) <= MAX_ENROLLMENT_BYTES
        and _sha(raw) == pin,
        "enrollment pin or bound differs",
    )
    value = safety._wire(raw, MAX_ENROLLMENT_BYTES)
    safety._fields(
        value, "schema_version capture_group_id main_contract_sha256 entries"
    )
    safety._need(
        value["schema_version"] == "edge-common-event-enrollment/v1"
        and value["main_contract_sha256"] == main_contract_sha256,
        "enrollment main binding",
    )
    _ref(value["capture_group_id"])
    entries = value["entries"]
    safety._need(
        type(entries) is list and len(entries) <= MAX_ENTRIES, "enrollment entry bound"
    )
    ids, selectors = set(), set()
    for entry in entries:
        safety._fields(
            entry,
            "id kind category channel_id capture_id opportunity_id fact_seq required_layers",
        )
        for key in ("id", "channel_id", "capture_id", "opportunity_id"):
            _ref(entry[key])
        safety._need(
            type(entry["kind"]) is str and entry["kind"] in composition.KINDS,
            "unknown enrollment kind",
        )
        safety._need(
            entry["category"] == CATEGORY_BY_KIND[entry["kind"]], "enrollment category"
        )
        safety._need(
            type(entry["fact_seq"]) is int and 1 <= entry["fact_seq"] <= 4096,
            "fact sequence",
        )
        layers = entry["required_layers"]
        safety._need(
            type(layers) is list
            and all(type(layer) is str and layer in REQUIRED_LAYERS for layer in layers)
            and len(set(layers)) == len(layers),
            "unknown or duplicate required layer",
        )
        if entry["kind"] == "forged_refusal_v2":
            safety._need(
                layers == list(REQUIRED_LAYERS), "complete ordered layers required"
            )
        selector = tuple(
            entry[key]
            for key in (
                "category",
                "channel_id",
                "capture_id",
                "opportunity_id",
                "fact_seq",
            )
        )
        safety._need(
            entry["id"] not in ids and selector not in selectors,
            "duplicate enrollment selector",
        )
        ids.add(entry["id"])
        selectors.add(selector)
    return value


class _Conflict(ValueError):
    pass


class _Unavailable(ValueError):
    pass


def _equal(actual, expected, reason):
    if not safety._same(actual, expected):
        raise _Conflict(reason)


def _layers(original):
    result = {}
    keys = dict(
        input_bytes="challenge_verified",
        reference_authentication="reference_frame_authenticated",
        baseline_witness="baseline_witness_verified",
        journal_cursor_structure="journal_cursor_structurally_verified",
    )
    for layer in REQUIRED_LAYERS:
        if layer in keys:
            value = original.get(keys[layer])
            verified = True if value is True else None
        elif layer == "worker_refusal":
            value = original.get("status")
            verified = True if value == "recorded_refusal_consistent" else None
        else:
            value = original.get("changes", {}).get(layer.removeprefix("sampled_"))
            verified = True if type(value) is bool else None
        result[layer] = dict(
            verified=verified,
            original_value=value,
            reasons=[] if verified else [layer + "_original_evidence_unavailable"],
        )
    return result


def _original_raw(item, supplied, slot):
    raw = supplied.get(slot)
    expected = item["expected_sha256"].get(slot)
    if (
        type(raw) is not bytes
        or len(raw) > composition.BOUNDS[slot]
        or expected is None
        or _sha(raw) != expected
    ):
        raise _Unavailable(slot + "_original_unavailable_or_unpinned")
    return raw


def _timing(entry, opportunity, row, plan, layers):
    end = opportunity["end_ns"]
    start = opportunity["start_ns"]
    worker = plan["worker"]
    for phase in ("before", "after"):
        for name, descriptor in plan["samples"][phase].items():
            if descriptor is None or layers["sampled_" + name]["verified"] is not True:
                layers["sampled_" + name]["reasons"].append(
                    phase + "_sample_bracket_unavailable"
                )
                raise _Unavailable("sample_timing_bracket_unavailable")
            before, after = (
                descriptor["read_started_ns"],
                descriptor["read_finished_ns"],
            )
            if not start <= before <= after <= end:
                raise _Unavailable("sample_bracket_outside_enrolled_opportunity")
    if not start <= worker["started_ns"] <= worker["exited_ns"] <= end:
        raise _Unavailable("worker_bracket_outside_enrolled_opportunity")
    last_read = max(d["read_finished_ns"] for d in plan["samples"]["after"].values())
    if not last_read <= row["monotonic_ns"] <= end:
        raise _Unavailable("fact_not_after_original_sample_reads")


def _bind(entry, old_item, supplied, contract, observations, main):
    replay = (old_item or {}).get("replayed_evaluation") or {}
    report = dict(
        id=entry["id"],
        kind=entry["kind"],
        category=entry["category"],
        identity_binding="unknown",
        main_assertion_consistency="unknown",
        timing_binding="unknown",
        finite_layer_coverage=_layers(replay),
        status="unknown",
        reasons=[],
        original_raw_sha256=dict((old_item or {}).get("raw_sha256", {})),
        original_expected_sha256=dict((old_item or {}).get("expected_sha256", {})),
        original_evaluation=replay if replay else None,
        source_input_completeness=False,
        whole_window_coverage=False,
        enrollment_chronology="root_prelaunch_custody_premise_not_proven_by_hashes",
        qualified_safety_count=None,
        **safety.FLAGS,
    )
    if entry["kind"] != "forged_refusal_v2":
        report["finite_layer_coverage"] = _layers({})
        if old_item is None or old_item["kind"] != entry["kind"]:
            report["original_evaluation"] = None
        report["reasons"].append("binding_adapter_unsupported_for_original_family")
        return report
    try:
        if (
            old_item is None
            or old_item["kind"] != entry["kind"]
            or not replay
            or type(supplied) is not dict
        ):
            raise _Unavailable("original_supplemental_replay_unavailable")
        plan_raw = _original_raw(old_item, supplied, "plan")
        plan = _object(plan_raw, 32768)
        category = entry["category"]
        diagnostic = main["categories"][category]
        if (
            diagnostic["verified_authentication"] != "complete_signed_stream"
            or diagnostic["reasons"]
        ):
            raise _Unavailable(
                "main_complete_authenticated_channel_and_coverage_unavailable"
            )
        channel = contract["channels"][category]
        _equal(entry["channel_id"], channel["channel_id"], "channel_id_conflict")
        _equal(entry["capture_id"], channel["capture_id"], "main_capture_id_conflict")
        _equal(
            entry["capture_id"], plan["capture_id"], "supplemental_capture_id_conflict"
        )
        scope, context = contract["scope"], plan["expected_context"]
        for key in ("scope_ref", "session_ref", "registration_sha256"):
            _equal(scope[key], context[key], key + "_conflict")
        _equal(scope["kernel_boot_id"], plan["kernel_boot_id"], "boot_id_conflict")
        _equal(
            scope["kernel_boot_id"].replace("-", ""),
            context["boot_ref"],
            "source_boot_ref_conflict",
        )
        _equal(
            scope["policy_sha256"], plan["expected_trust_sha256"], "trust_hash_conflict"
        )
        _equal(
            scope["source_sha256"],
            plan["expected_source_checkpoint"]["sha256"],
            "baseline_source_hash_conflict",
        )
        for role in ("producer", "observer"):
            _equal(
                scope["owner"][role + "_uid"],
                context[role + "_uid"],
                role + "_uid_conflict",
            )
        _equal(
            channel["source_actor_uid"],
            context["producer_uid"],
            "channel_source_actor_conflict",
        )
        for role in ("producer", "witness"):
            _equal(
                contract["keypins"]["source_" + role + "_public_key"],
                context[role + "_public_key"],
                role + "_key_conflict",
            )
        opportunities = [
            o
            for o in contract["opportunities"][category]
            if o["id"] == entry["opportunity_id"]
        ]
        if len(opportunities) != 1:
            raise _Conflict("opportunity_id_conflict")
        opportunity = opportunities[0]
        rows = observations["channels"][category]["rows"]
        selected = [r for r in rows if r["seq"] == entry["fact_seq"]]
        if len(selected) != 1:
            raise _Conflict("fact_sequence_conflict")
        row = selected[0]
        _equal(row["kind"], "verifier_disposition", "selected_row_is_not_fact")
        _equal(
            row["opportunity_id"], entry["opportunity_id"], "fact_opportunity_conflict"
        )
        _equal(
            row["raw_ref_sha256"],
            _sha(plan_raw),
            "fact_original_plan_reference_conflict",
        )
        invalid_input = _original_raw(old_item, supplied, "before_source")
        reference = _original_raw(old_item, supplied, "reference_frame")
        for expected in (
            opportunity["challenge_sha256"],
            opportunity["predicate"]["invalid_input_sha256"],
            row["data"]["input_sha256"],
        ):
            _equal(expected, _sha(invalid_input), "invalid_input_hash_conflict")
        for expected in (
            opportunity["reference_sha256"],
            plan["challenge"]["reference_frame_sha256"],
        ):
            _equal(expected, _sha(reference), "reference_frame_hash_conflict")
        for name in ("journal", "anchors"):
            for phase in ("before", "after"):
                slot = phase + "_" + name
                fact_key = name.removesuffix("s") + "_" + phase + "_sha256"
                _equal(
                    row["data"][fact_key],
                    _sha(_original_raw(old_item, supplied, slot)),
                    slot + "_hash_conflict",
                )
        report["identity_binding"] = "matched"
        _timing(entry, opportunity, row, plan, report["finite_layer_coverage"])
        report["timing_binding"] = "controller_brackets_enclosed_not_scheduling_proof"
        if (
            replay.get("journal_cursor_structurally_verified") is True
            and replay.get("changes", {}).get("journal") is False
        ):
            cursor = plan["expected_source_checkpoint"]["size"]
            for key in ("cursor_before", "cursor_after"):
                _equal(row["data"][key], cursor, key + "_conflict")
        else:
            raise _Unavailable("original_unchanged_structural_cursor_unavailable")
        if replay.get("status") == "recorded_refusal_consistent":
            if row["data"]["disposition"] != "refused":
                report["main_assertion_consistency"] = "conflict"
                raise _Conflict("main_disposition_contradicts_original_refusal")
            report["main_assertion_consistency"] = "consistent"
        else:
            raise _Unavailable("original_worker_refusal_unavailable")
        if old_item["status"] != "historical_replay_consistent":
            raise _Unavailable("original_published_report_unavailable_or_mismatched")
        if not all(
            report["finite_layer_coverage"][layer]["verified"] is True
            for layer in REQUIRED_LAYERS
        ):
            raise _Unavailable("required_finite_artifact_consistency_unavailable")
        report["status"] = "verified_enrolled_finite_artifact_consistency"
    except _Conflict as exc:
        if report["identity_binding"] != "matched":
            report["identity_binding"] = "conflict"
        elif report["main_assertion_consistency"] == "unknown":
            report["main_assertion_consistency"] = "conflict"
        report["status"] = "conflict"
        report["reasons"].append(str(exc))
    except _Unavailable as exc:
        report["reasons"].append(str(exc))
    except ERRORS:
        report["reasons"].append("binding_originals_missing_invalid_or_incomplete")
    return report


def evaluate_common_event_binding(
    contract_raw,
    observations_raw,
    *,
    safety_pins,
    composition_plan_raw=None,
    expected_composition_plan_sha256=None,
    supplements=None,
    event_enrollment_raw=None,
    expected_event_enrollment_sha256=None,
):
    """Main/composition first; independent optional binding cannot rewrite them."""
    base = composition.evaluate_safety_evidence_composition(
        contract_raw,
        observations_raw,
        safety_pins=safety_pins,
        composition_plan_raw=composition_plan_raw,
        expected_composition_plan_sha256=expected_composition_plan_sha256,
        supplements=supplements,
    )
    bindings, reasons, group = [], [], None
    status = "unknown"
    if event_enrollment_raw is None:
        reasons.append("event_enrollment_unavailable")
    else:
        try:
            enrollment = _enrollment(
                event_enrollment_raw,
                expected_event_enrollment_sha256,
                _sha(contract_raw),
            )
            group = enrollment["capture_group_id"]
            contract = safety._wire(contract_raw, 128 * 1024)
            observations = safety._wire(observations_raw, 2 * 1024 * 1024)
            old = {item["id"]: item for item in base["supplemental_items"]}
            supplied = supplements if type(supplements) is dict else {}
            bindings = [
                _bind(
                    entry,
                    old.get(entry["id"]),
                    supplied.get(entry["id"]),
                    contract,
                    observations,
                    base["main_evaluation"],
                )
                for entry in enrollment["entries"]
            ]
            status = "not_exercised" if not bindings else "finite_binding_annex"
        except ERRORS:
            reasons.append("event_enrollment_invalid_or_unbound")
    return dict(
        schema_version="edge-common-event-binding/v1",
        status=status,
        composition_evaluation=base,
        capture_group_id=group,
        bindings=bindings,
        reasons=reasons,
        comparison_eligibility=False,
        comparison_status="WITHHELD",
        source_input_completeness=False,
        whole_window_coverage=False,
        independently_attested_capture=False,
        qualified_safety_count=None,
        authority_flags=dict(safety.FLAGS),
        **safety.FLAGS,
    )
