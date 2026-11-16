"""Offline historical references; original evaluations never qualify comparison."""

import hashlib

from azazel_edge.outcome.journal import _ref
from . import safety_observations as safety
from . import forged_input_refusal as forged
from .advisory_exec import _object, verify_advisory_exec_observation
from .authority_ingress import verify_authority_ingress_observation
from .postconnect_refusal import verify_postconnect_refusal_observation
from .postconnect_authorization import verify_postconnect_authorization_observation
from .natural_close_recv import verify_natural_close_recv_observation

KINDS = (
    "forged_refusal_v1", "forged_refusal_v2", "advisory_exec",
    "authority_ingress", "postconnect_refusal", "postconnect_authorization",
    "natural_close_recv",
)
_FORGED_SLOTS = (
    "plan", "trust", "before_source", "before_journal", "before_anchors",
    "after_source", "after_journal", "after_anchors", "stdout", "stderr", "evaluation",
)
_STATE_SLOTS = (
    "plan", "probe", "sot_before", "sot_after", "audit_before", "audit_after", "evaluation",
)
SLOTS = {
    "forged_refusal_v1": _FORGED_SLOTS,
    "forged_refusal_v2": _FORGED_SLOTS + ("reference_frame",),
    "advisory_exec": ("plan", "probe", "governance", "audit", "evaluation"),
    **{kind: _STATE_SLOTS for kind in KINDS[3:]},
}
BOUNDS = {slot: 1024 * 1024 for slots in SLOTS.values() for slot in slots}
BOUNDS.update(plan=32768, trust=32768, probe=65536, governance=65536,
              audit=65536, stdout=65536, stderr=65536, reference_frame=65536)
MAX_TOTAL_BYTES = 64 * 1024 * 1024
ERRORS = (ValueError, TypeError, KeyError, OverflowError, RecursionError, OSError, UnicodeError)
COMPARISON_BLOCKERS = (
    "independent_safety_qualification_unavailable",
    "supplemental_main_event_binding_unestablished",
    "full_window_coverage_unestablished",
    "source_collector_custody_not_proven_by_hashes",
    "comparative_timing_and_assignments_not_validated",
    "causal_benefit_not_established",
)
SCOPE_LIMITS = (
    "internal_branch_and_userspace_consumption_unestablished",
    "transient_and_all_persistent_state_unestablished",
    "production_root_web_advisory_and_keys_unvalidated",
    "pi_hil_physical_and_performance_unvalidated",
)
_LAYERS = {
    "forged_refusal_v1": ("finite_challenge", "sampled_original_state"),
    "forged_refusal_v2": ("finite_challenge", "sampled_original_state"),
    "advisory_exec": ("exec_attempt",),
    "authority_ingress": ("connection", "sampled_original_state"),
    "postconnect_refusal": ("protocol_copy", "refusal_response", "sampled_original_state"),
    "postconnect_authorization": ("protocol_copy", "refusal_response", "sampled_original_state"),
    "natural_close_recv": ("individual_recv_return", "protocol_copy", "refusal_response", "sampled_original_state"),
}
_CATEGORY_GAPS = {
    "protected_escape": ("independent_protected_network_delivery_unmeasured",),
    "unauthorized_action": (
        "authorization_branch_unmeasured", "alternate_dispatch_paths_unmeasured",
        "transient_and_all_persistent_state_unestablished",
    ),
    "advisory_authority_conversion": (
        "advisory_to_executor_bridge_unestablished", "exec_attempt_not_success_or_effect",
        "all_dispatch_paths_unmeasured",
    ),
    "forged_evidence_accepted": (
        "finite_challenge_not_full_window_verifier_coverage",
        "test_keys_not_independent_production_custody",
    ),
}
_VERIFIERS = dict(zip(KINDS[2:], (
    verify_advisory_exec_observation, verify_authority_ingress_observation,
    verify_postconnect_refusal_observation, verify_postconnect_authorization_observation,
    verify_natural_close_recv_observation,
)))


class SafetyEvidenceCompositionInputError(ValueError):
    """Invalid optional composition manifest; original main remains independent."""


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _plan(raw, pin, maincontractsha):
    """Validate the exact flat manifest; shared with the readonly intake."""
    try:
        safety._hex(pin)
        safety._need(type(raw) is bytes and _sha(raw) == pin, "composition plan pin differs")
        p = safety._wire(raw, 128 * 1024)
        safety._fields(p, "schema_version main_contract_sha256 entries")
        safety._need(p["schema_version"] == "edge-safety-evidence-composition-plan/v1"
                     and p["main_contract_sha256"] == maincontractsha, "composition main binding")
        safety._need(type(p["entries"]) is list and len(p["entries"]) <= 64, "entry bound")
        seen = set()
        for entry in p["entries"]:
            safety._fields(entry, "id kind sha256")
            _ref(entry["id"])
            safety._need(entry["id"] not in seen, "duplicate entry")
            seen.add(entry["id"])
            kind = entry["kind"]
            safety._need(type(kind) is str and kind in KINDS, "unknown kind")
            safety._fields(entry["sha256"], " ".join(SLOTS[kind]))
            for slot, digest in entry["sha256"].items():
                safety._need(slot not in ("plan", "evaluation") or digest is not None,
                             "required artifact pin absent")
                if digest is not None:
                    safety._hex(digest)
        return p
    except ERRORS as exc:
        raise SafetyEvidenceCompositionInputError(str(exc)) from exc


def _replay(kind, raw, pin):
    if kind.startswith("forged_refusal_"):
        arguments = dict(
            expected_plan_sha256=pin, trust_raw=raw["trust"],
            before={k: raw["before_" + k] for k in forged.KINDS},
            after={k: raw["after_" + k] for k in forged.KINDS},
            stdout_raw=raw["stdout"], stderr_raw=raw["stderr"],
        )
        verifier = forged.verify_forged_input_refusal
        if kind == "forged_refusal_v2":
            verifier = forged.verify_forged_input_refusal_v2
            arguments["reference_frame_raw"] = raw["reference_frame"]
    else:
        arguments = {slot + "_raw": value for slot, value in raw.items()
                     if slot not in ("plan", "evaluation")}
        arguments["expected_plan_sha256"] = pin
        verifier = _VERIFIERS[kind]
    return verifier(raw["plan"], **arguments)


def _item(entry, supplied):
    kind = entry["kind"]
    result = dict(
        id=entry["id"], kind=kind,
        evidence_relation="historical_reference_only",
        scope_binding="scope_binding_unestablished",
        raw_sha256={}, expected_sha256=dict(entry["sha256"]),
        replayed_evaluation=None, published_evaluation=None,
        published_evaluation_matches=None, reasons=[], status="unknown",
    )
    reasons = result["reasons"]
    if type(supplied) is not dict or set(supplied) != set(SLOTS[kind]):
        reasons.append("missing_or_invalid_artifact_slots")
        return result
    trusted = {}
    for slot in SLOTS[kind]:
        raw, pin = supplied[slot], entry["sha256"][slot]
        digest = _sha(raw) if type(raw) is bytes and len(raw) <= BOUNDS[slot] else None
        result["raw_sha256"][slot] = digest
        valid = (raw is None and pin is None) or (digest is not None and digest == pin)
        trusted[slot] = raw if valid else None
        if not valid:
            reasons.append(slot + ("_missing" if raw is None else "_invalid_or_pin_mismatch"))
    published_raw = trusted["evaluation"]
    if published_raw is not None:
        try:
            published = _object(published_raw, BOUNDS["evaluation"], canonical=True)
            result["published_evaluation"] = published
        except ERRORS:
            reasons.append("published_evaluation_invalid")
    if trusted["plan"] is not None:
        try:
            result["replayed_evaluation"] = _replay(kind, trusted, entry["sha256"]["plan"])
        except ERRORS:
            reasons.append("original_verifier_input_invalid")
    else:
        reasons.append("original_plan_unavailable")
    replayed, published = result["replayed_evaluation"], result["published_evaluation"]
    if replayed is not None and published is not None:
        result["published_evaluation_matches"] = safety._same(replayed, published)
        if not result["published_evaluation_matches"]:
            reasons.append("published_evaluation_mismatch")
    if not reasons and result["published_evaluation_matches"] is True:
        result["status"] = "historical_replay_consistent"
    return result


def evaluate_safety_evidence_composition(
    contract_raw, observations_raw, *, safety_pins, composition_plan_raw=None,
    expected_composition_plan_sha256=None, supplements=None,
):
    """Main first, independently pinned references second; no I/O or authority."""
    main = safety.evaluate_safety_observations(contract_raw, observations_raw, **safety_pins)
    reasons, items = [], []
    if composition_plan_raw is None:
        reasons.append("composition_plan_unavailable")
    else:
        try:
            plan = _plan(composition_plan_raw, expected_composition_plan_sha256, _sha(contract_raw))
            supplied = {} if supplements is None else supplements
            safety._need(type(supplied) is dict, "supplements map")
            declared = {e["id"] for e in plan["entries"]}
            safety._need(set(supplied) <= declared, "undeclared supplement")
            # Sum only bytes, before hashing or parsing any supplemental leaves.
            total = 0
            for bundle in supplied.values():
                if type(bundle) is dict:
                    total += sum(len(v) for v in bundle.values() if type(v) is bytes)
            safety._need(total <= MAX_TOTAL_BYTES, "supplement total byte bound")
            items = [_item(e, supplied.get(e["id"])) for e in plan["entries"]]
        except ERRORS:
            reasons.append("composition_plan_or_bundle_invalid")
    blockers = list(COMPARISON_BLOCKERS) + reasons
    for item in items:
        blockers.extend(item["id"] + ":" + reason for reason in item["reasons"])
        blockers.extend(item["id"] + ":" + reason for reason in
                        (item["replayed_evaluation"] or {}).get("reasons", []))
    categories = {}
    for category in safety.CATEGORIES:
        selected = [i for i in items if (
            "forged_evidence_accepted" if i["kind"].startswith("forged_refusal_") else
            "advisory_authority_conversion" if i["kind"] == "advisory_exec" else
            "unauthorized_action"
        ) == category]
        categories[category] = dict(
            main_category=main["categories"][category],
            supplement_ids=[i["id"] for i in selected],
            observation_layers=sorted({layer for i in selected for layer in _LAYERS[i["kind"]]}),
            observation_layers_status="family_capabilities_not_observed_coverage",
            unmeasured_reasons=["independent_safety_qualification_unavailable",
                                "full_window_coverage_unestablished"] + list(_CATEGORY_GAPS[category]) + [i["id"] + ":" + r for i in selected for r in i["reasons"]]
            + [i["id"] + ":" + r for i in selected
               for r in (i["replayed_evaluation"] or {}).get("reasons", [])],
            qualified_safety_count=None, independently_measured=False,
        )
    return dict(
        schema_version="edge-safety-evidence-composition/v1",
        main_evaluation=main, supplemental_items=items, category_diagnostics=categories,
        comparison_eligibility=False, comparison_status="WITHHELD",
        comparison_blockers=blockers, scope_acceptance_limits=list(SCOPE_LIMITS),
        reasons=reasons, qualified_safety_count=None, independently_measured=False,
        authority_flags=dict(safety.FLAGS), **safety.FLAGS,
    )
