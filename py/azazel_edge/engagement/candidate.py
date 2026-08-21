"""Deterministic EngagementCandidate builder + arbiter-authority evaluation.

Flow (Azazel-Edge#319):

    validated evidence (soc/noc) + ActionArbiter decision
      -> build_engagement_candidate()  ->  Fabric EngagementCandidate (a request)
      -> evaluate_engagement()          ->  reconcile against the arbiter's actual
                                            decision; the arbiter is the sole
                                            authority and can only downgrade
      -> engagement_event()             ->  EngagementEvent for audit / Knowledge

Invariants:
* The Action Arbiter remains the sole authority. This layer never selects,
  executes, or escalates — the accepted activity is derived from the arbiter's
  own ``decision['action']``; a candidate requesting a stronger activity is
  recorded as a downgrade, never applied.
* Feature-flagged and optional: with the feature disabled or the Fabric
  engagement contracts absent, every entry point is a safe no-op and baseline
  Edge behavior is byte-identical.
* Safety defaults are fixed: no attacker egress, no production access.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from azazel_fabric.engagement_contracts import (
        EngagementAdvisory,  # noqa: F401 (re-exported symbol availability probe)
        EngagementCandidate,
        EngagementConstraint,
        EngagementEvent,
        EngagementOutcome,
        EngagementTrigger,
        assert_candidate_not_executable,
    )
except ImportError:  # Fabric engagement contracts are an optional integration.
    EngagementCandidate = None  # type: ignore[assignment,misc]
    EngagementConstraint = None  # type: ignore[assignment,misc]
    EngagementEvent = None  # type: ignore[assignment,misc]
    EngagementOutcome = None  # type: ignore[assignment,misc]
    EngagementTrigger = None  # type: ignore[assignment,misc]
    assert_candidate_not_executable = None  # type: ignore[assignment]


class EngagementDisabled(RuntimeError):
    """Raised when an engagement build is requested but unavailable/disabled."""


# The bounded arbiter action -> Engage (objective, approach, activity). Every
# activity maps 1:1 back onto a bounded Azazel action the arbiter already gates.
ACTION_TO_ACTIVITY: Dict[str, Dict[str, str]] = {
    "observe": {"objective": "detect", "approach": "detect", "activity": "observe"},
    "notify": {"objective": "detect", "approach": "detect", "activity": "notify"},
    "throttle": {"objective": "disrupt", "approach": "disrupt", "activity": "throttle"},
    "redirect": {"objective": "collect", "approach": "channel", "activity": "redirect_to_decoy"},
    "isolate": {"objective": "prevent", "approach": "prevent", "activity": "isolate"},
}

# Monotonic strength ordering so a reconciliation can tell "the arbiter chose a
# weaker action than the candidate requested" = a downgrade.
_ACTIVITY_STRENGTH: Dict[str, int] = {
    "observe": 0,
    "notify": 1,
    "collect_credentials": 2,
    "expose_decoy_surface": 2,
    "throttle": 3,
    "redirect": 4,
    "redirect_to_decoy": 4,
    "isolate": 5,
}


def engagement_available() -> bool:
    """True iff the Fabric engagement contracts can be constructed."""

    return EngagementCandidate is not None and assert_candidate_not_executable is not None


def _techniques(soc: Dict[str, Any]) -> List[str]:
    """Best-effort ATT&CK ids from the SOC payload; empty when unsupported."""

    tl = soc.get("technique_likelihood")
    if isinstance(tl, dict):
        for key in ("techniques", "attack_techniques", "top_techniques"):
            v = tl.get(key)
            if isinstance(v, list):
                return [str(t) for t in v if t]
    v = soc.get("attack_techniques")
    if isinstance(v, list):
        return [str(t) for t in v if t]
    return []


def _evidence_refs(soc: Dict[str, Any], noc: Dict[str, Any], decision: Dict[str, Any]) -> List[str]:
    refs: List[str] = []
    for src in (decision.get("chosen_evidence_ids"), soc.get("evidence_ids"), noc.get("evidence_ids")):
        if isinstance(src, list):
            refs.extend(str(x) for x in src if x)
    # stable de-dup
    seen: set[str] = set()
    out: List[str] = []
    for r in refs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def build_engagement_candidate(
    soc: Dict[str, Any],
    noc: Dict[str, Any],
    decision: Dict[str, Any],
    *,
    enabled: bool = False,
    product: str = "AZ-01",
    policy: Optional[Dict[str, Any]] = None,
    candidate_id: Optional[str] = None,
):
    """Build a Fabric ``EngagementCandidate`` from evidence + the arbiter decision.

    Returns ``None`` when ``enabled`` is False or the engagement contracts are
    unavailable, so a caller can wire this in unconditionally without changing
    baseline behavior. Raises :class:`EngagementDisabled` only if called with
    ``enabled=True`` while the contracts are missing (an explicit misconfig).
    """

    if not enabled:
        return None
    if not engagement_available():
        raise EngagementDisabled("Fabric engagement contracts are unavailable")

    action = str(decision.get("action") or "observe")
    mapping = ACTION_TO_ACTIVITY.get(action, ACTION_TO_ACTIVITY["observe"])
    policy = policy or {}
    budget = policy.get("engagement_budget") if isinstance(policy.get("engagement_budget"), dict) else {}
    max_duration = int(budget.get("max_duration_seconds") or 300)

    techniques = _techniques(soc)
    confidence = float(int(soc.get("confidence", {}).get("score") or 0)) / 100.0
    confidence = min(max(confidence, 0.0), 1.0)

    constraints = EngagementConstraint(
        max_duration_seconds=max_duration,
        outbound_allowed=False,        # fixed safe posture
        production_access=False,       # fixed safe posture
        scope=str(policy.get("scope") or "decoy_segment"),
        termination_conditions=["noc_health_degraded", "max_duration_reached", "operator_terminate"],
        evidence_refs=_evidence_refs(soc, noc, decision),
    )
    trigger = EngagementTrigger(
        attack_technique=techniques[0] if techniques else None,
        confidence=confidence,
        evidence_refs=_evidence_refs(soc, noc, decision),
    )
    candidate = EngagementCandidate(
        candidate_id=candidate_id or f"{product}-eng-{action}",
        product=product,
        objective=mapping["objective"],
        approach=mapping["approach"],
        activity=mapping["activity"],
        attack_techniques=techniques,
        requested_actions=[mapping["activity"]],
        expected_observations=["decoy_engaged", "disengaged", "continued_scanning"],
        trigger=trigger,
        constraints=constraints,
        evidence_refs=_evidence_refs(soc, noc, decision),
    )
    # Structural authority guard: a candidate is a request, never a command.
    assert_candidate_not_executable(candidate)
    return candidate


def evaluate_engagement(candidate, decision: Dict[str, Any]) -> Dict[str, Any]:
    """Reconcile a candidate against the arbiter's decision (arbiter = authority).

    The accepted activity is derived from the arbiter's own ``decision['action']``.
    If the candidate requested a stronger activity than the arbiter selected, the
    result is a ``downgraded`` status and the requested activity is recorded as a
    rejected alternative — the engagement can only ever be reduced, never
    escalated, by this layer. Fails closed on a malformed candidate.
    """

    if candidate is None:
        return {"status": "disabled", "authority": "azazel-edge-arbiter"}
    if engagement_available():
        assert_candidate_not_executable(candidate)  # fail closed on a tampered candidate

    requested = getattr(candidate, "activity", None) or (
        candidate.get("activity") if isinstance(candidate, dict) else None
    )
    action = str(decision.get("action") or "observe")
    accepted = ACTION_TO_ACTIVITY.get(action, ACTION_TO_ACTIVITY["observe"])["activity"]

    req_strength = _ACTIVITY_STRENGTH.get(str(requested), 0)
    acc_strength = _ACTIVITY_STRENGTH.get(accepted, 0)
    if acc_strength >= req_strength:
        status = "accepted" if accepted == requested else "modified"
    else:
        status = "downgraded"

    rejected: List[Dict[str, str]] = list(decision.get("rejected_alternatives") or [])
    if status == "downgraded":
        rejected = [
            {"activity": str(requested), "reason": str(decision.get("reason") or "arbiter_selected_weaker_action")},
            *rejected,
        ]

    return {
        "status": status,
        "requested_activity": requested,
        "accepted_activity": accepted,
        "arbiter_action": action,
        "authority": "azazel-edge-arbiter",
        "rejected_alternatives": rejected,
        "evidence_refs": list(decision.get("chosen_evidence_ids") or []),
    }


def engagement_event(
    candidate,
    decision: Dict[str, Any],
    *,
    attacker_reaction: str = "unknown",
    event_id: Optional[str] = None,
):
    """Build a Fabric ``EngagementEvent`` for audit / Knowledge ingest.

    Records the *accepted* (arbiter-authoritative) activity and the observed
    reaction. Returns ``None`` when unavailable so callers stay unconditional.
    """

    if candidate is None or not engagement_available():
        return None
    result = evaluate_engagement(candidate, decision)
    accepted = result["accepted_activity"]
    mapping = next(
        (m for m in ACTION_TO_ACTIVITY.values() if m["activity"] == accepted),
        ACTION_TO_ACTIVITY["observe"],
    )
    return EngagementEvent(
        event_id=event_id or f"{getattr(candidate, 'product', 'AZ-01')}-engev-{result['arbiter_action']}",
        product=getattr(candidate, "product", "AZ-01"),
        objective=mapping["objective"],
        approach=mapping["approach"],
        activity=accepted,
        trigger=getattr(candidate, "trigger", None),
        constraints=candidate.constraints,
        outcome=EngagementOutcome(
            attacker_reaction=attacker_reaction,
            evidence_refs=list(result.get("evidence_refs") or []),
            termination_reason=None,
        ),
        evidence_refs=list(getattr(candidate, "evidence_refs", []) or []),
    )
