# M.I.O. Grounding and Evidence-Gap Scoring

Implementation: `py/azazel_edge/mio/evidence_gap_scoring.py`,
`py/azazel_edge/mio/claim_audit.py`, `py/azazel_edge/mio/grounding.py`, wired in
`py/azazel_edge/mio/reasoning.py`. Tests:
`tests/test_mio_grounding_playbook_acceptance.py`,
`tests/test_mio_cognitive_shadow_core.py`, `tests/test_mio_adversarial_schema.py`.
Design: #366. Acceptance: #386. Related: [mio-reasoning-playbooks.md](mio-reasoning-playbooks.md),
[mio-capability-broker.md](mio-capability-broker.md), [mio-situation-frame.md](mio-situation-frame.md).

> The model proposes. Deterministic code decides what is eligible, in what order,
> and whether a claim is supported. No LLM judges another LLM.

Everything here is advisory-only. Nothing in this path reaches the Action Arbiter,
enforcement handlers, the control-plane socket, or AZ-06 control. Grounding and
scoring can only *narrow* what the reasoning loop does: they never add a capability,
raise a budget, or approve anything. Playbooks are non-executable data.

## Cycle overview

```
SituationFrame ──► reasoning_provenance (playbook/template version + digest)
      │
      ▼
generate_hypotheses ──► GroundingValidator.validate_hypotheses   (refs must exist)
      │
      ▼
identify_evidence_gaps ──► GroundingValidator.validate_evidence_gaps (playbook allowlist, known hypothesis ids)
      │
      ▼
score_evidence_gaps ──► trace "evidence_gap_scores" (itemised reasons, policy digest)
      │                eligible gaps only, best first
      ▼
CapabilityBroker.execute (registry, typed params, per-capability + per-cycle budgets)
      │
      ▼
update_hypotheses ──► validate_raw + validate_hypotheses
      │
      ▼
recommend ──► validate_raw + validate_recommendation + audit_claims ──► trace "claim_audit"
```

## Evidence-gap scoring (`score_evidence_gaps`)

Policy `mio-evidence-gap-score` version `1.1.0`. `scoring_policy_digest()` covers the
version, the weights, the cost classes, the threshold and `RULE_LOGIC` (a canonical prose
description of the rules); the digest and version are written to the
`evidence_gap_scores` trace event. The digest cannot see code: **any change to the
scoring logic must bump `SCORING_POLICY_VERSION` and update `RULE_LOGIC` in the same
change.**

The function is pure and greedy: identical inputs give identical output regardless of
input order. At each step the best eligible gap (score descending, then `gap_id`
ascending) is chosen; its capability then counts as already collected for the remaining
gaps and it consumes one unit of the remaining cycle broker budget. Ineligible gaps
follow and are **never** sent to the broker.

### Which model-controlled fields can move a score

Only facts tied to the current, validated hypotheses count:

- `targets` = the gap's `discriminates_hypothesis_ids` that name a current hypothesis
  that is not `falsified`/`superseded` (duplicates and invented ids are ignored);
- `targets_falsifiable_hypothesis` needs a non-blank falsification condition on a target;
- the model's `priority` is a hint for **ordering only**: the eligibility threshold is
  applied to the structural score (score minus `model_priority_hint`), so priority can
  never lift a gap over the threshold on its own.

### Score rules (additive, integer)

| Rule | Delta | When |
|---|---|---|
| `base` | 50 | always |
| `discriminates_multiple_hypotheses` | 20 | the gap names ≥2 known hypotheses (it can separate them) |
| `targets_falsifiable_hypothesis` | 10 | a targeted hypothesis declares `falsification_conditions` |
| `model_priority_hint_max` | 10 | ceiling of `model_priority_hint` = model priority (0..100) × 10 // 100; the model's hint can never outweigh discrimination |
| `already_collected_this_cycle` | -30 | the capability was already collected this cycle |
| `cost_low` | 0 | capability cost class low |
| `cost_medium` | -5 | cost class medium (also the default for unknown capabilities) |
| `cost_high` | -15 | cost class high (e.g. `request_trace`) |

Each `GapScore` carries `reasons` as `(rule, delta)` pairs whose sum is the score, so an
operator can read exactly why a gap ranked where it did. This is what makes a cheap,
discriminating, falsifying query win over an expensive confirming one even when the
model gave the confirming one a higher priority.

### Ineligibility (explicit reason codes)

| Code | Meaning |
|---|---|
| `capability_not_allowed_by_playbook` | not in the selected playbook's `allowed_capabilities` |
| `capability_not_registered_in_broker` | not in the broker registry; naming a capability never causes a call |
| `cannot_change_hypothesis_state` | the gap targets no known hypothesis |
| `cycle_broker_budget_exhausted` | no broker calls left in the cycle budget |
| `insufficient_expected_value` | score below `MIN_ELIGIBLE_SCORE` (40): stop instead of querying |

The loop also records each as `gap_not_eligible:<gap_id>:<code>` in the outcome errors.
Eligibility is necessary, not sufficient: the broker still enforces its registry, typed
parameter schema, freshness, and its own per-capability and total budgets, whichever is
tighter.

## Claim-to-reference audit (`audit_claims`)

**Scope, stated plainly:** the audit checks that every cited ref *exists* in the current
context and records *where it came from*. It does **not** judge whether a ref is relevant
to, or actually supports, the claim text. Relevance remains a model/operator judgement,
bounded by the playbook claim boundaries.

Every cycle that reaches the recommendation step projects its output into claims and
records one audit entry per claim in the `claim_audit` trace event
(`schema: mio_claim_audit/v1`): claim id → cited refs (each with origin) → verdict.

| Claim class | Source | Material | Required refs |
|---|---|---|---|
| `inference` | hypothesis with status proposed/active/unresolved/superseded | no | none; if unreferenced the verdict is `inference_unreferenced` (explicitly marked, not presented as fact) |
| `evidence_assessment` | hypothesis `strengthened` | yes | ≥1 supporting ref |
| `evidence_assessment` | hypothesis `falsified` | yes | ≥1 contradicting ref |
| `evidence_assessment` | hypothesis `weakened` | yes | ≥1 contradicting ref, or an explicit `missing_evidence` entry (verdict `weakened_by_named_gap`); a supporting-only ref does not count |
| `evidence_assessment` | any hypothesis whose raw model `status` was not in the vocabulary | yes | always `unsupported_unparseable_status` |
| `recommendation` | the advisory | yes | ≥1 evidence ref |

These rules are the same as the #385 lifecycle rules (`lifecycle._evidence_errors`),
which usually reject such an update earlier; the claim audit is the per-claim record.
`MioHypothesis.from_mapping` silently coerces an unknown status to `proposed`; the loop
detects that from the raw model output (`unparseable_status_ids`) so the coercion is
audited instead of silent.

Ref origins: `frame_evidence`, `frame_knowledge`, `broker_imported` (returned by a broker
result with `ok=True` in this cycle; refs on failed/timeout/stale results are not
imported), or `not_in_frame`.

Verdicts: `supported`, `inference_unreferenced`, `weakened_by_named_gap`,
`unsupported_missing_refs`, `unsupported_unknown_ref` (any cited ref is `not_in_frame`),
`unsupported_unparseable_status`.

**Policy: `reject`.** If any material claim is unsupported, the cycle ends in
`VALIDATION_REJECTED` with `unsupported_claim:<claim_id>:<verdict>` errors. Claims are
never silently dropped while keeping the surrounding certainty, and never silently
accepted. Edge's deterministic outputs are unaffected either way.

## Deliberate behaviour changes in #386

- Broker calls follow the greedy score order, not the model's raw `priority`.
- Gaps that target no current hypothesis, name an unregistered capability, fall below
  the threshold or exceed the cycle budget are dropped before the broker and reported as
  `gap_not_eligible:<gap_id>:<code>` in the outcome errors (a cycle can still `COMPLETE`).
- Only refs from successful broker results extend the cycle's allowed refs.
- A generic-playbook cycle reports `generic_fallback:<reason>` in the outcome errors.

## Structural grounding (`GroundingValidator`)

Pre-existing checks, unchanged: unknown/fabricated evidence refs, duplicate hypothesis
ids, a ref used as both supporting and contradicting, gaps referencing unknown
hypotheses or capabilities outside the playbook, recommendation vocabulary
(`OBSERVE|NOTIFY|THROTTLE|REDIRECT|ISOLATE`, advisory only, `executable` always false),
and recursive rejection of directive keys (`execute`, `override`, `must_action`,
`command`, `shell`, `activate`, `enforce`, `executable`).

## Not yet covered (tracked)

Staleness of individual evidence refs, contradiction against arbiter results,
Knowledge-as-decision wording, AZ-06 belief wording, attribution and confidence-wording
checks from #366 Part B are not implemented as dedicated claim classes yet; they remain
covered only by the structural checks above and the playbook claim boundaries.
