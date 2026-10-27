# M.I.O. Grounding and Evidence-Gap Scoring

Canonical architecture, authority matrix and degradation ladder: [M.I.O. Cognitive Plane](mio-cognitive-plane.md).

Implementation: `py/azazel_edge/mio/evidence_gap_scoring.py`,
`py/azazel_edge/mio/claim_audit.py`, `py/azazel_edge/mio/grounding.py`, wired in
`py/azazel_edge/mio/reasoning.py`. Tests:
`tests/test_mio_grounding_playbook_acceptance.py`,
`tests/test_mio_grounding_provenance_386.py`, `tests/test_mio_cognitive_shadow_core.py`, `tests/test_mio_adversarial_schema.py`.
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
operator can read exactly why a gap ranked where it did.

Each component is also traceable to the named missing evidence it rests on. The gap
itself is the named missing evidence (`gap:<gap_id>`); every rule and every
ineligibility code carries a sorted `basis` of identifiers, never model prose (the gap
`question` is not copied into the trace). Every id in `gap_id`, `targets` and `basis` has
passed the model-id grammar below; anything else is shown as `invalid-model-id`. A
capability (`capability`, `capability:<name>`) is shown only when it is registered in the
broker, otherwise as `unregistered-capability`. The basis does not change the score, the
policy version or `scoring_policy_digest()`.

| Rule / code | `basis` |
|---|---|
| `base` | `gap:<gap_id>` |
| `discriminates_multiple_hypotheses` | `hypothesis:<id>` for each live target |
| `targets_falsifiable_hypothesis` | `hypothesis:<id>` for each target with a falsification condition |
| `model_priority_hint` | `gap:<gap_id>`, `model_priority:<0..100>` |
| `already_collected_this_cycle` | `capability:<name>` |
| `cost_<class>` | `capability:<name>`, `cost_class:<class>` |
| `capability_not_allowed_by_playbook`, `capability_not_registered_in_broker` | `capability:<name>` |
| `cannot_change_hypothesis_state` | `gap:<gap_id>` and the unknown or terminal `hypothesis:<id>` it named |
| `cycle_broker_budget_exhausted` | `budget:remaining_broker_calls=0` |
| `insufficient_expected_value` | `gap:<gap_id>`, `structural_score:<n>`, `min_eligible_score:<n>` |

In the `evidence_gap_scores` trace event each score has `targets` (the live hypotheses
the gap could move), `reasons[].basis`, `ineligible_reasons` (codes) and
`ineligible_basis` (`{code, basis}` in the same order). This is what makes a cheap,
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

Each verdict has exactly one fixed `reason` code (`VERDICT_REASON`, closed set
`REASON_CODES`); `ClaimAuditRecord` refuses any other reason, so the audit never carries
free text from the model or from evidence:

| Verdict | `reason` |
|---|---|
| `supported` | `all_cited_refs_in_context` |
| `inference_unreferenced` | `marked_inference` |
| `weakened_by_named_gap` | `weakened_with_named_missing_evidence` |
| `unsupported_missing_refs` | `material_claim_without_required_refs` |
| `unsupported_unknown_ref` | `cited_ref_not_in_context` |
| `unsupported_unparseable_status` | `model_status_not_in_vocabulary_coerced_to_proposed` |

Which refs are missing is visible in `refs` (origin `not_in_frame`). For
`weakened_by_named_gap` the record keeps only `named_missing_evidence_count`; the
`missing_evidence` entries themselves are not copied into the audit.

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
- If the generic playbook itself fails `verify_generic_fallback`, the cycle ends in
  `VALIDATION_REJECTED` before any model call (`generic_fallback_unverified`).
- Claim-audit `reason` is a fixed code per verdict; earlier builds put cited refs and
  `missing_evidence` text into it.

## Model-written identifiers (closed grammar)

Hypothesis ids, gap ids, the hypothesis ids a gap names, gap capabilities and every
evidence ref the model cites (supporting, contradicting, recommendation) are written by
the model, so they are attacker-reachable. Each field has an exact-match **allowlist**
(`contracts.MODEL_ID_GRAMMAR`, checked by `model_id_ok(value, kind)`), built from the
shapes the repo actually produces. It is not a denylist: a shape not listed is refused.
`MODEL_ID_GRAMMAR` only selects kinds; every kind is defined once in
`py/azazel_edge/mio/id_grammar.py` (`ID_KINDS`), shared with the no-model handoff and
the broker audit (see "One id grammar" below).

| Field (`kind`) | Accepted shapes | Producer |
|---|---|---|
| `evidence_ref` | `sha256:<64 lowercase hex>` | Evidence Plane event ids (`make_event_id`), carried into frames |
| | `ev:<kind>:<1-6 digits>`, kind one of `EVIDENCE_REF_KINDS` (`alert`, `auth`, `dns`, `flow`, `http`, `ssh`, `tls`) | structured refs |
| | `suricata_sid:<1-8 digits>` | Suricata adapter |
| | `kn:attack:T<4 digits>[.<3 digits>]` | ATT&CK knowledge refs |
| | `sha256:fixture-<word>[-<word>]-<1-3 digits>` | offline replay fixtures |
| `hypothesis_id` | `h<1-3 digits>` | the prompt schema (`h1`) and `TRUSTED_RULES` |
| `gap_id` | `g<1-3 digits>` | the prompt schema (`g1`) and `TRUSTED_RULES` |
| `capability` | broker name grammar `[a-z][a-z0-9_]{2,63}` | broker registry; registration is checked at scoring time |

As a second layer (`id_grammar.second_layer_ok`), a value must also pass the
SituationFrame opaque-ID address checks (`id_grammar.opaque_id`), contain no secret word
(`password`, `token`, `api_key`, `secret`, `bearer` …) and no M.I.O. redaction token
shape (API key prefixes, bearer, JWT, e-mail, long token). This applies to capability
names too. Integers and other non-string values are refused, never stringified. The prompt
template (version 1.1.0) tells the model the `h<n>` / `g<n>` format explicitly.

When the model output is parsed (`MioHypothesis.from_mapping`,
`MioEvidenceGap.from_mapping`, `MioRecommendation.from_mapping`) a refused value is
replaced by the fixed `invalid-model-id` and the raw value is dropped. A missing id
still gets its deterministic default (`h<n>`, `g<n>`). `GroundingValidator` then rejects
the output with a fixed code and the cycle ends in `VALIDATION_REJECTED`:

| Field | Code |
|---|---|
| hypothesis id | `invalid_model_id:hypothesis_id` |
| supporting / contradicting / recommendation ref | `invalid_model_id:evidence_ref` |
| gap id | `invalid_model_id:gap_id` |
| a hypothesis id named by a gap | `invalid_model_id:discriminates_hypothesis_id` |
| gap capability | `invalid_model_id:capability` |

The general form is `invalid_model_id:<field>`; the code never carries the value. As
defence in depth, the gap-score explanation and the claim audit run every id through
`safe_model_id` again, so a caller that builds contract objects directly still cannot
put raw text into them. A ref that fails the grammar is recorded as `invalid-model-id`
with origin `not_in_frame`, even if the frame happens to carry it. The grammar is
deliberately closed and fails closed: a harmless id in a shape not listed is rejected
rather than guessed at; add the shape to `id_grammar.ID_KINDS` (and select it in
`MODEL_ID_GRAMMAR`) when a new producer appears.
The frame's own refs come from deterministic evaluators and are not re-checked here.

A gap whose capability passes the name grammar but is not in the playbook's
`allowed_capabilities` is rejected with `capability_not_allowed_by_playbook:<name>` only
when `<name>` is in the broker registry; any other name is reported as
`capability_not_allowed_by_playbook:unregistered-capability`, so a model-chosen word (a
person's name, say) is not echoed into the errors. The gap score follows the same rule:
its `capability` and every `capability:<name>` in `basis` / `ineligible_basis` (and so the
trace's `evidence_gap_scores` event) show the name only when it is registered, otherwise
`unregistered-capability`.

### One id grammar

The model output parser (#386), the no-model handoff (#385) and the broker audit
projection (#384) share one grammar, `py/azazel_edge/mio/id_grammar.py`. Each kind is
defined there once (`ID_KINDS`: `event_id`, `structured_ref`, `suricata_ref`,
`knowledge_ref`, `fixture_ref`, `hypothesis_id`, `gap_id`, `trace_id`, `frame_id`,
`cycle_request_id`, `capability`), and so is the second layer. Each surface only selects
which kinds a field accepts and keeps its own policy for a value that does not match:

| Surface | Field kinds | Non-matching value |
|---|---|---|
| model output (`contracts.MODEL_ID_GRAMMAR`) | evidence ref: `event_id`, `structured_ref`, `suricata_ref`, `knowledge_ref`, `fixture_ref`; `hypothesis_id`; `gap_id`; `capability` | `invalid-model-id`, cycle rejected |
| no-model handoff (`handoff.HANDOFF_ID_KINDS`) | `trace_id`; `frame_id`; evidence ref: `event_id`, `structured_ref`, `suricata_ref`; `hypothesis_id` | fixed placeholder |
| broker audit (`id_grammar.AUDIT_ID_KINDS`) | `event_id`, `cycle_request_id` | keyed digest `h:<digest>` |

The surfaces still accept different sets: the handoff and the audit never accepted the
model-only `kn:attack:` / `sha256:fixture-` refs, and the audit's cycle / request id
grammar (vocabulary words and short ordinals) also covers refs such as `ev:noc:0001`.
Making them one set would widen the handoff or the audit, or drop refs the model parser
is tested to accept, so that is left to a later decision.

Merging the grammars narrowed what is accepted, never widened it
(`tests/test_mio_id_grammar_consolidation.py` compares the old and new functions over
the fixture ids and the review corpus):

- model output: `ev:` refs of kind `deception`, `host`, `noc`, `soc`, `sys` (the handoff
  never accepted them), so canonical fixtures that contain `ev:noc|soc|sys|host|deception:`
  refs are rejected when a model cites them (production refs are `sha256:` event ids and
  `suricata_sid:`); values with a redaction token shape; capability names with an
  address shape (`aa_bb_cc_dd_ee_ff`) or of 32 or more characters (long-token rule; the
  registered names are much shorter).
- no-model handoff: `ev:` refs of kind `anomaly`, `dhcp`, `drop`, `ftp`, `netflow`, `smb`,
  `smtp` (the model parser never accepted them) and `ev:<kind>` without an ordinal; and
  the second layer now applies, so for example a trace id of 32 or more characters
  without a `:` (long-token rule) becomes the placeholder.
- broker audit: ids containing a secret word.

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
