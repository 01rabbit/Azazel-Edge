# M.I.O. Reasoning Playbooks and Prompt Compiler

Canonical architecture, authority matrix and degradation ladder: [M.I.O. Cognitive Plane](mio-cognitive-plane.md).

Implementation: `py/azazel_edge/mio/playbook.py` (corpus, `PromptCompiler`,
`select_playbook`, `validate_playbook`, `verify_generic_fallback`, `playbook_digest`, `template_digest`,
`reasoning_provenance`). Tests: `tests/test_mio_grounding_playbook_acceptance.py`, `tests/test_mio_grounding_provenance_386.py`,
`tests/test_mio_adversarial_schema.py`, `tests/test_mio_situation_frame_contract.py`.
Design: #376. Acceptance: #386. Related:
[mio-grounding-and-evidence-gaps.md](mio-grounding-and-evidence-gaps.md),
[mio-capability-broker.md](mio-capability-broker.md).

> A playbook says *how to investigate*. It never says *what to do to the network*.

Playbooks are **non-executable**, reviewed, versioned data. They are code-review
changes, not runtime configuration. They hold no handlers, no callables, no commands.
A playbook cannot call a capability outside the Capability Broker, cannot raise a broker
or cycle budget, cannot widen the broker registry, and carries no Edge or AZ-06
authority. It is advisory method only.

## Corpus (v1)

| Playbook | Use |
|---|---|
| `auth-ambiguity-v1` | hostile auth vs benign/misconfigured automation |
| `scan-ambiguity-v1` | recon vs discovery/monitoring noise |
| `exploit-signal-ambiguity-v1` | exploit vs signature collision vs malformed client |
| `noc-soc-ambiguity-v1` | security symptom vs independent NOC failure |
| `friction-reaction-v1` | behaviour after bounded friction, without intent claims |
| `deception-observation-v1` | interpreting an already-approved bounded deception environment |
| `generic-evidence-first-v1` | **generic fallback** when nothing specific applies |

## Selection (`select_playbook`)

Deterministic, before any model call, no network retrieval, no model-supplied id:

1. A trusted caller id (fixture, operator config) wins if registered (`mode: explicit`).
   An unregistered id does not raise and does not invent a playbook: it falls back to the
   generic playbook (`mode: explicit_unknown_fallback`, `reason: requested_playbook_not_registered`).
2. Otherwise fixed keyword families (`SELECTION_RULES`) are matched as whole tokens over
   the frame's `mission`, `soc_summary` and `noc_summary` (`known_facts` are excluded
   because they can carry attacker strings verbatim);
   `deception-observation-v1` is a candidate when `deception_status == "available"`.
3. Exactly one candidate → that playbook (`mode: matched`).
   Zero → `generic-evidence-first-v1` (`reason: no_family_match`).
   More than one → `generic-evidence-first-v1` (`reason: ambiguous_family_match`, candidates listed).

**Selection input may be attacker-influenced.** The summaries are produced by
deterministic evaluators and the operator, but they can echo attacker-chosen labels
(signature names, usernames). Selection therefore only affects the *advisory prompt*: it
chooses among reviewed playbooks, so a wrong match changes the method, never the
capabilities, budgets or authority available. A future revision should select on
structured evaluator fields (category/reason codes) instead of free text.

Runtime gate (`guard_selection`): every cycle validates its playbook with
`validate_playbook` before compiling. An invalid playbook is never compiled; the cycle
runs the generic playbook with `selection_mode: invalid_playbook_fallback` and
`selection_reason: playbook_failed_validation:<code>`. Capability registration is
enforced at gap-scoring time against the live broker registry
(`capability_not_registered_in_broker`), so an allowlisted but unregistered capability
can never be called even though the content gate does not need the registry.

A caller-supplied `selection` must wrap the very playbook passed to the loop: the loop
compiles `selection.playbook`, so a selection that names a different object is treated
as invalid (`selection_reason: playbook_failed_validation:selection_playbook_mismatch`)
and the generic playbook runs instead.

The generic playbook is verified too (`verify_generic_fallback`): it must pass
`validate_playbook` (and, when a registry is given, broker registration) and may not allow
a capability whose cost class is `high` (`generic_capability_cost_high:<name>`), so the
fallback stays cheap. If the generic playbook itself fails, there is no further fallback:
the selection mode is `generic_fallback_unverified`
(`selection_reason: generic_playbook_failed_verification:<code>`), the cycle ends in
`VALIDATION_REJECTED` before any model call, nothing is compiled, and the no-model
handoff carries no playbook block.

What the generic checks cover, exactly: a playbook counts as "generic" only by
`playbook_id == "generic-evidence-first-v1"`. The extra checks (high-cost ban,
`generic_fallback_unverified`) apply to any playbook with that id, and to the module's
`GENERIC_PLAYBOOK` whenever the loop falls back to it. A playbook with another id gets
only `validate_playbook`, so it may allow a high-cost capability such as
`request_trace`. The high-cost ban uses the static `CAPABILITY_COST_CLASS` table; a
capability missing from that table counts as medium and is not banned. The ban is a
static content check, not a budget: call counts stay with the broker's total and
per-capability budgets and the loop's `ReasoningBudget`.

Under the generic playbook the usual limits still hold: a gap naming a capability outside
its allowlist rejects the gap set before the broker; the broker's total and
per-capability budgets bound calls even when the loop budget is higher; a directive key
or an unknown action in the recommendation rejects the cycle, and `executable` is always
false.

Every generic fallback is visible three ways: the `reasoning_provenance` event
(`generic_fallback: true`), the outcome errors (`generic_fallback:<reason>`), and a
`WARNING` log line. `replay.run_selected(loop, frame, cycle_id=..., requested_id=...)`
runs a cycle this way; `replay.run_replay()` keeps refusing unknown fixture ids so
evaluation fixtures stay pinned.

## Provenance (`reasoning_provenance`)

Every cycle records a `reasoning_provenance` trace event
(`schema: mio_reasoning_provenance/v1`):

- `playbook_id`, `playbook_version`, `playbook_digest`
- `generic_fallback` (true when the generic playbook ran), `selection_mode`,
  `selection_reason`, `selection_candidates`
- `template_id` (`mio-prompt-compiler`), `template_version`, `template_digest`
- `selection_rules_digest` (`selection_rules_digest()`: keyword families, order, token
  fields, tie policy)

`playbook_digest(p)` is `sha256:` over the canonical JSON (sorted keys, ASCII, no
whitespace) of exactly the playbook section the compiler renders into
`TRUSTED_CONTROL`. Any content change — wording, an added boundary, a removed
capability, a version bump — changes the digest. `template_digest()` covers
`TRUSTED_RULES`, the limits block, every task's output schema and the
`TRUSTED_CONTROL`/`UNTRUSTED_DATA` envelope markers, plus the template version. It does
**not** cover compiler code (`PromptCompiler`, reduction/truncation logic): a change there
must bump `PROMPT_TEMPLATE_VERSION`.

## Authoring a playbook

1. Add a `ReasoningPlaybook` to `DEFAULT_PLAYBOOKS` with a new id (`[a-z][a-z0-9-]{2,63}`)
   and semantic `version` (`X.Y.Z`). Editing an existing playbook **must** bump its
   version; the digest changes regardless, and evaluation fixtures (#372) pin it.
2. Fill every field with short plain-language items (≤8 items, ≤240 chars each):
   `purpose`, `hypothesis_prompts` (competing explanations, including benign ones),
   `discriminating_questions`, `falsification_patterns` (what would *weaken* each
   hypothesis), `allowed_capabilities`, `stop_conditions`, `claim_boundaries`.
3. `allowed_capabilities` may only name capabilities registered in the broker
   (check with `validate_playbook(p, registered_capabilities=broker.names())`). Do not add
   a playbook whose evidence does not exist; mark it planned instead.
4. If the family should be auto-selected, add a keyword set to `SELECTION_RULES`. Keep
   keyword sets disjoint from other families so ambiguity falls back to generic.
5. Run `validate_playbook` (the test suite does this for every shipped playbook) and the
   M.I.O. tests. Reviewers check: meaningful falsification workflow (not generic advice),
   capability reality, and absence of directive semantics.

### What a playbook may not contain

`validate_playbook` rejects, deterministically:

| Code | Example |
|---|---|
| `forbidden_content:url` | `http://…`, `www.` |
| `forbidden_content:filesystem_path` | `/etc/…`, `~/…`, `C:\…` |
| `forbidden_content:shell_syntax` | `$(`, backticks, `&&`, `;`, `sudo`, `curl`, `rm -` |
| `forbidden_content:secret_material` | `password=`, `api_key:`, `token=` |
| `directive_language` | enforcement/execution verbs (`isolate`, `throttle`, `redirect`, `block`, `quarantine`, `activate`, `execute`, `run`, `kill`, `shutdown`, `disable`, `drop`, `terminate`, `deny`, `delete`, `transition`, `override`, `approve`, `nuke`, `disconnect`, `sever`, `erase`, `wipe`, `reboot`, `cut`, `shut`, and phrasal `shut down`, `shut off`, `cut off`, `power off`, `power down`, …) scanned over the whole item. The list is closed: add a verb here and in `_DIRECTIVE_VERBS` / `_DIRECTIVE_PHRASES` when review finds a new one. The only exception is a claim boundary that is a single prohibition of the verbs themselves: `(do not|never) VERB (or VERB)* <object>` with no further verb and no clause punctuation. "Do not worry, isolate the host now" is refused |
| `non_text_item`, `field_not_non_empty_tuple`, `bad_item_length`, `control_character` | callables, dicts, empty or oversized fields |
| `invalid_capability_name`, `capability_not_registered` | capability names outside the broker grammar or registry |

A playbook may say "compare retry interval before/after friction". It may not say
"run command X", "activate deception profile Y" or "isolate the client".

## Runtime guarantees (tested)

- The model cannot select or invent a playbook id; unknown ids fall back to generic.
- A capability allowed by a playbook but absent from the broker registry is ineligible
  and never called (`capability_not_registered_in_broker`).
- The broker's total and per-capability budgets bound calls even when a playbook allows
  more capabilities and the loop budget is higher.
- Compiled context for identical inputs is byte-identical; untrusted data stays in
  `UNTRUSTED_DATA`.

## Not yet covered (tracked)

Per-playbook source/reviewer metadata fields, `excluded_conditions`,
`compatible_schema_versions`, configurable rollback to a prior playbook version, and
#372 playbook-on/off evaluation fixtures are not implemented in v1.
