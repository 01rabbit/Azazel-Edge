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

from .contracts import MioEvidenceGap, MioHypothesis

SCORING_POLICY_ID = "mio-evidence-gap-score"
SCORING_POLICY_VERSION = "1.0.0"

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


def score_evidence_gaps(
    gaps: Sequence[MioEvidenceGap],
    *,
    hypotheses: Sequence[MioHypothesis],
    allowed_capabilities: Sequence[str],
    registered_capabilities: Sequence[str],
    remaining_broker_calls: int,
    collected_capabilities: Sequence[str] = (),
) -> tuple[GapScore, ...]:
    """Score every proposed gap. Output order: eligible by (score desc, gap_id asc), then ineligible.

    Pure function: identical inputs always give identical output.
    """
    allowed = {str(x) for x in allowed_capabilities}
    registered = {str(x) for x in registered_capabilities}
    collected = {str(x) for x in collected_capabilities}
    by_id = {h.hypothesis_id: h for h in hypotheses}
    budget_left = max(0, int(remaining_broker_calls))

    scored: list[GapScore] = []
    for gap in gaps:
        reasons: list[tuple[str, int]] = [("base", WEIGHTS["base"])]
        ineligible: list[str] = []
        if gap.capability not in allowed:
            ineligible.append(INELIGIBLE_NOT_IN_PLAYBOOK)
        if gap.capability not in registered:
            ineligible.append(INELIGIBLE_NOT_REGISTERED)
        targets = [by_id[h] for h in gap.discriminates_hypothesis_ids if h in by_id]
        if not targets:
            ineligible.append(INELIGIBLE_NO_HYPOTHESIS)
        if budget_left <= 0:
            ineligible.append(INELIGIBLE_BUDGET)

        if len(targets) >= 2:
            reasons.append(("discriminates_multiple_hypotheses", WEIGHTS["discriminates_multiple_hypotheses"]))
        if any(h.falsification_conditions for h in targets):
            reasons.append(("targets_falsifiable_hypothesis", WEIGHTS["targets_falsifiable_hypothesis"]))
        hint = (max(0, min(int(gap.priority), 100)) * WEIGHTS["model_priority_hint_max"]) // 100
        reasons.append(("model_priority_hint", hint))
        if gap.capability in collected:
            reasons.append(("already_collected_this_cycle", WEIGHTS["already_collected_this_cycle"]))
        cost = CAPABILITY_COST_CLASS.get(gap.capability, "medium")
        reasons.append((f"cost_{cost}", WEIGHTS[f"cost_{cost}"]))

        score = sum(delta for _, delta in reasons)
        if not ineligible and score < MIN_ELIGIBLE_SCORE:
            ineligible.append(INELIGIBLE_LOW_VALUE)
        scored.append(GapScore(gap.gap_id, gap.capability, score, not ineligible, tuple(reasons), tuple(ineligible)))

    eligible = sorted((s for s in scored if s.eligible), key=lambda s: (-s.score, s.gap_id))
    rejected = sorted((s for s in scored if not s.eligible), key=lambda s: s.gap_id)
    ranked = [
        GapScore(s.gap_id, s.capability, s.score, True, s.reasons, (), rank=i + 1)
        for i, s in enumerate(eligible)
    ]
    return tuple(ranked) + tuple(rejected)
