"""Explainable, deterministic evidence-gap scoring (#366 Part A / #386).

The model may *propose* evidence gaps. This module decides, without any model
input beyond the proposal itself, which gaps are eligible and in which order the
reasoning loop should ask the Capability Broker. Every score is an itemised
sum of named rule contributions so an operator can see why a gap ranked where
it did. The policy is versioned and its weights are digested so a scoring
change is visible in provenance.

Scoring never grants anything: an eligible gap still has to pass the playbook
allowlist, the broker registry, the broker's own per-capability and per-cycle
budgets, and its typed parameter schema.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .contracts import HypothesisStatus, MioEvidenceGap, MioHypothesis

SCORING_POLICY_ID = "mio-evidence-gap-score"
# Bump SCORING_POLICY_VERSION on ANY change to the scoring logic below, not only
# to the weights: the digest covers the version, the weights and RULE_LOGIC, but
# it cannot see code. RULE_LOGIC is a canonical prose description of the rules
# and must be edited together with the code.
SCORING_POLICY_VERSION = "1.1.0"
RULE_LOGIC: tuple[str, ...] = (
    "targets = gap hypothesis ids that name a current, non-terminal (not falsified/superseded) hypothesis",
    "ineligible if capability not in playbook allowlist, not in broker registry, no targets, or cycle broker budget exhausted",
    "discriminates_multiple_hypotheses if len(targets) >= 2",
    "targets_falsifiable_hypothesis if any target has a non-blank falsification condition",
    "model_priority_hint = clamp(priority, 0, 100) * model_priority_hint_max // 100; ordering only",
    "eligibility threshold applies to structural score = score - model_priority_hint",
    "greedy selection: after a gap is chosen its capability counts as already collected for the remaining gaps",
    "order: score desc, gap_id asc; ineligible gaps last by gap_id",
)

# Rule weights (integers keep the arithmetic exact and reproducible).
WEIGHTS: Mapping[str, int] = MappingProxyType(
    {
        "base": 50,
        "discriminates_multiple_hypotheses": 20,
        "targets_falsifiable_hypothesis": 10,
        "model_priority_hint_max": 10,  # model priority 0..100 maps to 0..10
        "already_collected_this_cycle": -30,
        "cost_low": 0,
        "cost_medium": -5,
        "cost_high": -15,
    }
)

# Static cost classes for the capabilities the v1 playbooks reference. Unknown
# capabilities default to "medium"; cost never makes an ineligible gap eligible.
CAPABILITY_COST_CLASS: Mapping[str, str] = MappingProxyType(
    {
        "query_recent_alerts": "low",
        "lookup_behavior_pattern": "low",
        "get_host_health": "low",
        "get_deception_state": "low",
        "query_flow_summary": "medium",
        "request_trace": "high",
    }
)

# Ineligibility reasons. An ineligible gap is never sent to the broker.
INELIGIBLE_NOT_IN_PLAYBOOK = "capability_not_allowed_by_playbook"
INELIGIBLE_NOT_REGISTERED = "capability_not_registered_in_broker"
INELIGIBLE_NO_HYPOTHESIS = "cannot_change_hypothesis_state"
INELIGIBLE_BUDGET = "cycle_broker_budget_exhausted"
INELIGIBLE_LOW_VALUE = "insufficient_expected_value"

# Gaps scoring below this are not worth a broker call this cycle.
MIN_ELIGIBLE_SCORE = 40


def scoring_policy_digest() -> str:
    data = json.dumps(
        {
            "policy_id": SCORING_POLICY_ID,
            "policy_version": SCORING_POLICY_VERSION,
            "weights": dict(WEIGHTS),
            "cost_classes": dict(CAPABILITY_COST_CLASS),
            "min_eligible_score": MIN_ELIGIBLE_SCORE,
            "rule_logic": list(RULE_LOGIC),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class GapScore:
    gap_id: str
    capability: str
    score: int
    eligible: bool
    reasons: tuple[tuple[str, int], ...]  # (rule, contribution) in evaluation order
    ineligible_reasons: tuple[str, ...] = ()
    rank: int = 0  # 1-based among eligible gaps; 0 when ineligible

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "capability": self.capability,
            "score": self.score,
            "eligible": self.eligible,
            "rank": self.rank,
            "reasons": [{"rule": rule, "delta": delta} for rule, delta in self.reasons],
            "ineligible_reasons": list(self.ineligible_reasons),
        }


_TERMINAL_STATUSES = frozenset({HypothesisStatus.FALSIFIED, HypothesisStatus.SUPERSEDED})


def _score_one(
    gap: MioEvidenceGap,
    *,
    by_id: Mapping[str, MioHypothesis],
    allowed: set[str],
    registered: set[str],
    collected: set[str],
    budget_left: int,
) -> GapScore:
    reasons: list[tuple[str, int]] = [("base", WEIGHTS["base"])]
    ineligible: list[str] = []
    if gap.capability not in allowed:
        ineligible.append(INELIGIBLE_NOT_IN_PLAYBOOK)
    if gap.capability not in registered:
        ineligible.append(INELIGIBLE_NOT_REGISTERED)
    targets = [
        by_id[h] for h in dict.fromkeys(gap.discriminates_hypothesis_ids)
        if h in by_id and by_id[h].status not in _TERMINAL_STATUSES
    ]
    if not targets:
        ineligible.append(INELIGIBLE_NO_HYPOTHESIS)
    if budget_left <= 0:
        ineligible.append(INELIGIBLE_BUDGET)

    if len(targets) >= 2:
        reasons.append(("discriminates_multiple_hypotheses", WEIGHTS["discriminates_multiple_hypotheses"]))
    if any(any(c.strip() for c in h.falsification_conditions) for h in targets):
        reasons.append(("targets_falsifiable_hypothesis", WEIGHTS["targets_falsifiable_hypothesis"]))
    hint = (max(0, min(int(gap.priority), 100)) * WEIGHTS["model_priority_hint_max"]) // 100
    reasons.append(("model_priority_hint", hint))
    if gap.capability in collected:
        reasons.append(("already_collected_this_cycle", WEIGHTS["already_collected_this_cycle"]))
    cost = CAPABILITY_COST_CLASS.get(gap.capability, "medium")
    reasons.append((f"cost_{cost}", WEIGHTS[f"cost_{cost}"]))

    score = sum(delta for _, delta in reasons)
    # The model's priority hint orders eligible gaps but can never lift a gap
    # over the threshold on its own.
    if not ineligible and score - hint < MIN_ELIGIBLE_SCORE:
        ineligible.append(INELIGIBLE_LOW_VALUE)
    return GapScore(gap.gap_id, gap.capability, score, not ineligible, tuple(reasons), tuple(ineligible))


def score_evidence_gaps(
    gaps: Sequence[MioEvidenceGap],
    *,
    hypotheses: Sequence[MioHypothesis],
    allowed_capabilities: Sequence[str],
    registered_capabilities: Sequence[str],
    remaining_broker_calls: int,
    collected_capabilities: Sequence[str] = (),
) -> tuple[GapScore, ...]:
    """Score every proposed gap. Output order: chosen eligible gaps best-first, then ineligible.

    Greedy and deterministic: once a gap is chosen, its capability counts as
    already collected for the remaining gaps (so duplicates are penalised), and
    each chosen gap consumes one unit of the remaining broker budget. Identical
    inputs always give identical output, independent of input order.
    """
    allowed = {str(x) for x in allowed_capabilities}
    registered = {str(x) for x in registered_capabilities}
    collected = {str(x) for x in collected_capabilities}
    by_id = {h.hypothesis_id: h for h in hypotheses}
    budget_left = max(0, int(remaining_broker_calls))

    pending = sorted(gaps, key=lambda g: g.gap_id)
    chosen: list[GapScore] = []
    while pending:
        current = [
            _score_one(g, by_id=by_id, allowed=allowed, registered=registered, collected=collected, budget_left=budget_left)
            for g in pending
        ]
        eligible = [s for s in current if s.eligible]
        if not eligible:
            rejected = sorted(current, key=lambda s: s.gap_id)
            break
        best = min(eligible, key=lambda s: (-s.score, s.gap_id))
        chosen.append(GapScore(best.gap_id, best.capability, best.score, True, best.reasons, (), rank=len(chosen) + 1))
        collected.add(best.capability)
        budget_left -= 1
        pending = [g for g in pending if g.gap_id != best.gap_id]
    else:
        rejected = []
    return tuple(chosen) + tuple(rejected)
