# Auditable Edge SOC/NOC Gateway for Privacy-Sensitive and Constrained Operations

*Status note: this is a concept-profile document supporting a CFP draft for Black Hat Europe Arsenal. It is not a record of an accepted appearance and makes no claim of acceptance. Sibling concept profiles have been demonstrated as Asia 2026 and USA 2026 profiles; the profile described here is a concept profile.*

## Abstract

Edge, branch, and temporary networks are increasingly operated in privacy-sensitive
and regulated settings where exporting raw telemetry to a cloud SIEM is undesirable,
contractually constrained, or legally fraught. At the same time, operators are
expected to justify, after the fact, why any automated control acted. Black-box
machine-learning responders make this difficult: their decisions resist
post-incident review. Azazel-Edge is a small gateway design that addresses this
gap. It is not a black-box AI defender. Response decisions are made by a
deterministic decision loop that converts normalized telemetry into one of five
bounded, reviewable actions — observe, notify, throttle, redirect, isolate — each
carrying an explicit action profile (reversibility, approval requirement, audit
status). Local AI is restricted to triage hints, summarization, and explanation
assistance, and cannot select or alter actions. Raw logs are handled local-first
and are not sent to external APIs; they do not need to leave the site. Every
decision emits a structured explanation record and is recorded in a hash-chained,
tamper-evident audit log, so operators can reconstruct and explain decisions later.
Deception is limited to defensive observation via controlled decoys bounded by
policy. The system does not guarantee legal or regulatory compliance; it is a tool
that supports operator accountability in regulated environments. This paper
describes the design, the implemented decision and evidence machinery, and its
honest limitations.

## 1. Problem Statement

Small networks at the edge — branch offices, clinics, pop-up sites, temporary
event infrastructure, and other constrained deployments — are frequently operated
in contexts where data handling is sensitive or regulated. Two pressures
collide in these settings.

First, the default architecture of modern detection-and-response tooling assumes
that raw telemetry can be shipped to a centralized, often cloud-hosted, analytics
backend. In privacy-sensitive or regulated environments this assumption is often
undesirable or disallowed: raw logs may contain personal data, the destination may
be outside an acceptable jurisdiction, or the contractual posture simply forbids
bulk export. The operator needs detection and decision support without making
external raw-log export a precondition for the system to function.

Second, when an automated control does act — when it throttles, redirects, or
isolates traffic — the operator is accountable for that action. In a regulated
environment, "the model decided" is not an adequate account. Operators must be
able to explain *why* the control acted, on the basis of recorded evidence, often
weeks later and to a non-technical reviewer or auditor. Black-box ML responders
are poorly suited to this: the very property that makes them flexible, an opaque
learned decision surface, is what makes them resist after-the-fact review.

Azazel-Edge takes the position that, for these settings, the response decision
itself should be deterministic and explainable, the data should stay local by
default, and an audit trace should be preserved so the decision can be
reconstructed and justified later.

## 2. Design Goals

The design is organized around six goals, each of which maps onto a concrete
implemented mechanism described later in this paper.

- **Determinism.** The authoritative decision path is a deterministic evaluator
  and arbiter. Given the same normalized evidence and the same policy, it produces
  the same action. There is no learned model in the decision path.
- **Explainability.** Every decision produces a structured explanation that names
  the selected action, the reason, the rejected alternatives and why each was
  rejected, the evidence that was consulted, and a human-readable operator wording.
- **Auditability.** Decisions are recorded in a hash-chained, tamper-evident audit
  log keyed by a `trace_id`, so the record of a decision can be verified and
  reconstructed.
- **Local-first data handling.** Raw logs are handled locally. Default log sinks
  write to local files. Raw logs are not sent to external APIs and do not need to
  leave the site.
- **Bounded, reversible response.** The arbiter may select only from a small,
  fixed set of actions, each carrying an explicit profile describing whether it is
  reversible, whether it requires approval, and that it is audited.
- **Advisory-only AI.** Local AI assist is limited to triage hints, summarization,
  and explanation assistance. It is governed, secondary, and cannot select or alter
  actions.

## 3. Threat and Operational Model

The threat model is deliberately scoped to what a small edge gateway can credibly
address, rather than overstated.

**In scope.** The system targets opportunistic and commodity threats observed on
small networks: opportunistic scanning, brute-force attempts, and lateral probing
across a modest number of hosts. These are the activities a single, co-located
gateway can observe and respond to in a bounded way.

**Deployment.** The reference deployment is a single Raspberry Pi-class gateway
co-located with the network it observes. This constrains both the compute budget
(small local models, limited throughput) and the architectural assumptions (one
node, local storage, no mandatory backhaul).

**Non-goals.** The system is explicitly *not*:

- an EDR or host-based agent platform;
- a compliance product — it does not guarantee legal or regulatory compliance, and
  is instead a tool that *supports* operator accountability;
- a perimeter or detection platform for large enterprises with high traffic volumes
  and dedicated SOC staff.

Within this scope, the operational model assumes a human operator who reviews and
remains accountable for the gateway's actions, supported by the explanation and
audit machinery described below.

## 4. System Overview

Azazel-Edge separates a fast deterministic decision path from optional, governed,
advisory functions. Telemetry — for example Suricata EVE alerts and local
probes — is received and normalized into Evidence Plane records. Two deterministic
evaluators then score the current state independently: a NOC evaluator covering
network and service health dimensions (availability, path health, device health,
client health, capacity health, client inventory health, service health,
resolution health, and config-drift health), and a SOC evaluator scoring security
state (suspicion, confidence, technique likelihood, blast radius). Policy
thresholds are applied, and an `ActionArbiter` selects exactly one bounded action.
A `DecisionExplainer` then produces a structured explanation, and a hash-chained
audit logger records the trace. Notification and any AI assist run only *after* the
deterministic decision has been made.

A `trace_id` is intended to thread through the entire path. The field exists at
every stage from the Rust core through the Python pipeline; however, fully
automatic end-to-end propagation is **(Prototype)** — there is no integration test
confirming the identifier is threaded automatically across the language boundary.

The deterministic path is authoritative. AI is invoked only post-decision and is
constrained as described in Section 7. Default log handling is local-first: the
default Vector sinks write to local files only.

## 5. Deterministic Decision Loop

The decision loop is the heart of the design and is implemented, not aspirational.
It proceeds as follows: telemetry is normalized into Evidence Plane records; the
deterministic NOC and SOC evaluators score state; policy thresholds are applied;
the `ActionArbiter` selects one bounded action; the `DecisionExplainer` records the
rationale; and the audit logger records the full trace.

### 5.1 The five bounded actions and their profiles

The arbiter may select only from five actions. Each action carries a fixed
*action profile* recording its reversibility, whether it requires approval, that it
is audited, its effect, and its control mode. These profiles are defined in code
(`ActionArbiter.ACTION_PROFILES`):

| Action   | reversible | approval_required | audited | effect                 | mode               |
|----------|------------|-------------------|---------|------------------------|--------------------|
| observe  | true       | false             | true    | visibility_only        | passive            |
| notify   | true       | false             | true    | operator_notification  | human_loop         |
| throttle | true       | true              | true    | traffic_shaping        | bounded_control    |
| redirect | true       | true              | true    | controlled_redirect    | bounded_control    |
| isolate  | true       | true              | true    | segment_isolation      | high_risk_control  |

Two properties follow directly from this table. All five actions are marked
`audited`. The three impactful actions — throttle, redirect, isolate — are marked
`approval_required`, while observe and notify are not. This makes the boundedness
and reviewability of the action set a structural property of the system rather than
a convention.

### 5.2 Selection logic

The arbiter validates that the NOC and SOC inputs carry their required keys, then
derives a small number of decision predicates. Two are central: `noc_fragile`,
true when availability, path, or device health is labelled `poor` or `critical`;
and `strong_soc`, true when the suspicion label is `high` or `critical` *and*
confidence meets the policy's `strong_soc` minimum. The escalating actions
(isolate, redirect, throttle) are gated on `strong_soc and not noc_fragile` plus
action-specific suspicion, confidence, and blast-radius thresholds drawn from the
active policy's `action_mapping`. Notably, a strong SOC signal on a fragile network
de-escalates to `notify` (reason `soc_high_but_noc_fragile`) rather than applying a
control on an already-degraded path. A separate client-impact guard further
downgrades any control action to `notify` when the estimated client-impact score is
high or any critical clients are affected (reason
`client_impact_too_high_for_control`).

### 5.3 Rejected alternatives and release conditions

For every decision, the arbiter records *why other actions were not chosen*. It
emits a `rejected_alternatives` list, each entry pairing an `action` with a
`reason` (for example `{'action': 'redirect', 'reason': 'availability_risk_too_high'}`
or `{'action': 'isolate', 'reason': 'threat_signal_not_strong_enough'}`). This is
what allows a reviewer to confirm not only that the chosen action was justified, but
that the more aggressive options were correctly declined.

Each decision also carries a `release_condition` — a human-readable string stating
when the control may be released. The implemented conditions are:
`no_repeated_failures_for_300_seconds` (throttle, redirect),
`manual_review_and_no_high_risk_signals_for_600_seconds` (isolate),
`operator_acknowledged_or_signal_stabilized` (notify), and
`observe_only_no_control_applied` (observe). These are recorded strings reviewed by
operators; automated release-condition orchestration is **(Planned)** — there is no
automated rollback today.

Finally, the arbiter records `chosen_evidence_ids`, the deduplicated, sorted set of
evidence identifiers actually consulted for the selected action, so the explanation
points back at concrete evidence rather than at the entire input.

## 6. Evidence Model and Audit Trace

The evidence model distinguishes two layers. *Raw logs* preserve original upstream
detail and transport context and are handled local-first. *Compact evidence*
normalizes the key fields needed for reproducible deterministic evaluation and
operator review. The decision path consumes compact evidence; raw logs are never a
prerequisite for external review and are not exported to external APIs.

### 6.1 The v2 decision-explanation record

The `DecisionExplainer` writes `format_version` `v2` JSONL records to
`/var/log/azazel-edge/decision-explanations.jsonl` (falling back to a local `/tmp`
path if the canonical directory is not writable). The following is a representative
*trimmed* record. Every key shown is a real field emitted by the explainer; the
values are illustrative.

```json
{
  "ts": "2026-06-10T09:14:07+00:00",
  "trace_id": "trace-7f3a91",
  "format_version": "v2",
  "selected_action": "redirect",
  "reason": "soc_high_confidence_redirect_is_preferred",
  "rejected_actions": ["observe", "notify", "throttle", "isolate"],
  "release_condition": "no_repeated_failures_for_300_seconds",
  "policy_profile": "soc-policy-v1",
  "config_hash": "9b1c4a2e7d0f5a83",
  "why_chosen": {
    "format_version": "v2",
    "action": "redirect",
    "reason": "soc_high_confidence_redirect_is_preferred",
    "control_mode": "opencanary_redirect",
    "noc_status": "good",
    "soc_status": "high",
    "noc_dimensions": {
      "availability": "good",
      "path_health": "good",
      "device_health": "good"
    },
    "attack_candidates": ["T1110", "T1046"],
    "client_impact": {"score": 10, "critical_client_count": 0}
  },
  "why_not_others": [
    {"action": "isolate", "reason": "isolate_gate_not_satisfied"},
    {"action": "observe", "reason": "insufficient_response_for_detected_threat"}
  ],
  "evidence_ids": ["ev-1042", "ev-1051", "ev-1077"],
  "next_checks": ["verify_control_applied_and_reversible",
                  "review_soc_evidence_and_attack_candidates"],
  "operator_wording": "Selected action redirect for azazel-edge because soc_high_confidence_redirect_is_preferred. NOC status is good and SOC status is high. Control mode: opencanary_redirect.",
  "machine": {"noc_summary": {}, "soc_summary": {}, "arbiter": {}},
  "trust_capsule": {"hmac_sig": "…"}
}
```

The record carries both the machine-facing rationale (`why_chosen`,
`why_not_others`, `evidence_ids`) and an `operator_wording` string suitable for a
human reviewer, plus `next_checks` suggesting follow-up review steps. The
`trust_capsule` carries an HMAC over the explanation for integrity.

### 6.2 Hash-chained audit log

Decisions are recorded by `P0AuditLogger`, which writes JSONL records of typed
kinds (for example `event_receive`, `evaluation`, `action_decision`,
`notification`, `ai_assist`, and the triage-session kinds). Each record carries a
`chain_prev` field set to the prior record's `chain_hash`, and its own `chain_hash`
computed as a SHA-256 over the canonical (sorted-key) JSON of the record. A
`verify_chain` routine walks the file, checks that each `chain_prev` matches the
previous `chain_hash` and that each recomputed hash matches, and reports the first
mismatch. This makes the log tamper-evident: a modified or removed record breaks the
chain at a detectable position. This mechanism is implemented and tested.

### 6.3 Reproducibility metadata

A SHA-256 hash of the active policy is computed at load (the arbiter exposes it as
`policy_hash`), and the explanation record carries both `policy_profile` and
`config_hash`. The repository ships three policy profiles — balanced, conservative,
and demo — and the auditable profile recommends the conservative profile to reduce
unnecessary high-impact actions. Config-drift auditing is implemented. Full
config-hash and reproducibility *packaging across all outputs* is **(Planned)**, as
is a unified incident evidence-bundle export format. Runtime policy-profile
switching today is environment-variable-at-start only **(Prototype)**.

## 7. AI Assist Governance

Local AI is optional, secondary, and tightly governed by `AIGovernance`. It cannot
select or alter actions; the deterministic path has already decided before AI is
ever invoked.

**Invocation whitelist.** `should_invoke` permits AI only for an allowed set of
intents (`advice`, `summary`, `candidate`) and only for specific source/risk-band
combinations — for example `advice` is permitted only for `suricata_eve` events in
an `ambiguous` or `uncertain` risk band, and `summary`/`candidate` are permitted for
explicit operator-facing sources (operator, ops_comm, mattermost, dashboard).
Anything else is refused with a recorded reason.

**Payload sanitization.** Before any model call, `sanitize_payload` keeps only a
whitelist of compact keys and strips raw-log content. The forbidden keys removed are
`raw`, `raw_log`, `full_log`, `message`, `line`, `payload`, and `event`. Raw logs
therefore do not reach the model; this is the mechanism behind the local-first,
no-raw-export property.

**Output validation.** `validate_output` constrains the model's output to advisory
fields only — `advice`, `summary`, `candidate`, `runbook_candidates`, and
`attack_candidates` — rejecting any extra keys, enforcing types, and truncating
lengths. If validation fails, the system falls back to a minimal advisory result
rather than adopting unconstrained output.

**Local-only and fully audited.** The assist path uses a local Ollama runtime only;
there is no external API dependency for AI. Every invocation is audited: the
governance layer logs `ai_assist` records at input, decision, output, review, and
fallback stages, so the use of AI is itself reconstructable from the audit chain. AI
downtime does not block deterministic operation.

## 8. Deception and Reversible Response

Deception in Azazel-Edge is *not* an unrestricted offensive capability. It is
defensive observation via controlled decoys (OpenCanary), bounded by policy. When
the arbiter selects `redirect`, selected flows can be diverted toward
pre-positioned decoy surfaces to preserve visibility while reducing direct exposure
of real assets. Decoys are pre-positioned so a constrained edge node need not
provision them dynamically.

Two safety properties bound this. First, redirect (like throttle and isolate)
carries `approval_required: true` in its action profile, so impactful actions are
gated. Second, the response posture is reversible: every action profile is marked
`reversible`, and each control carries a `release_condition`.

**Enforcement is opt-in and dry-run by default.** This distinction is important and
must not be overstated. The Python redirect path *records and audits* redirect
decisions — it writes the decision to a state JSON file, to JSONL, and into the
audit chain. Actual network enforcement (nftables/tc) lives in the Rust core and is
gated behind `AZAZEL_DEFENSE_ENFORCE=true`. The default is **false**; in dry-run
(the default), rollback commands are *recorded but not executed*. Live network
redirection is therefore never the default behavior — it is an explicit opt-in.
Release conditions are recorded human-readable strings reviewed by operators;
automated release orchestration and rollback are **(Planned)**.

## 9. Demo Scenario

The reviewer-facing entry point is the deterministic replay demo. A demo runner
executes the pipeline with `execution.mode = 'deterministic_replay'` and
`ai_used = False`, so a reviewer sees the deterministic decision path produce
explanations and audit records without any AI in the loop and without live
enforcement.

The auditable concept pack (`demos/concepts/auditable-edge-socnoc.yaml`) currently
references two existing scenarios: `mixed_correlation_demo`, used to exercise the
explanation trace and rejected-alternatives review, and `disaster_phishing_demo`,
used for social-engineering triage with auditable operator handoff. A dedicated
Europe-framed scenario with the id `auditable_edge_socnoc` does **not exist yet** and
is **(Planned)**; the concept pack reuses the two existing scenarios above.

Reviewers can inspect the outputs along the same paths operators would use: the v2
decision-explanation JSONL at
`/var/log/azazel-edge/decision-explanations.jsonl`, the hash-chained audit log via
the `verify_chain` mechanism, and the Web/CLI/TUI review surfaces — including the
`/api/triage/audit` and `/api/demo/explanation/latest` endpoints and the SOC policy
dry-run CLI.

## 10. Limitations

This section is candid by design; the value of the system depends on not
overstating it.

- **Prototype trace_id threading.** The `trace_id` field exists at every stage, but
  automatic end-to-end propagation across the Rust core and Python pipeline is
  unverified and has no integration test (Prototype). Correlation across the
  language boundary cannot yet be guaranteed.
- **Enforcement off by default.** Actual nftables/tc enforcement is opt-in
  (`AZAZEL_DEFENSE_ENFORCE=true`) and dry-run by default. The Python path records
  and audits redirect decisions; it does not itself enforce them.
- **Release conditions are not auto-executed.** Release conditions are recorded,
  human-readable strings reviewed by operators. There is no automated rollback today
  (Planned).
- **No unified evidence bundle yet.** Decision explanations and audit logs exist as
  separate streams; a unified incident evidence-bundle export format is not yet
  implemented (Planned). Full config-hash/reproducibility packaging across all
  outputs is likewise Planned.
- **Single-file Rust core without tests.** The enforcement core is a single-file Rust
  component and does not currently carry its own test coverage, which limits
  confidence in enforcement behavior even when opted in.
- **Deterministic rules have inherent limits.** A deterministic, rule-based decision
  path is, by construction, blind to novel patterns it was not designed to score. It
  trades adaptive coverage for explainability; it will not catch what its rules do
  not encode.
- **Small-model AI assist quality.** AI assist runs on small local models suited to
  Raspberry Pi-class hardware. Its triage hints and summaries are advisory and of
  limited quality, and its availability depends on local runtime health. It must
  never be relied on as a decision authority.

## 11. Future Work

Several limitations above map directly onto planned work. The most impactful items
are: verifying and testing automatic `trace_id` propagation across the Rust/Python
boundary; a unified incident evidence-bundle export that packages explanation
records, consulted evidence, and the relevant audit-chain segment for a single
incident; full config-hash and reproducibility packaging across all outputs so that
a recorded decision can be replayed against its exact policy; automated
release-condition orchestration so that recorded release conditions can drive
reviewed, auditable rollback rather than purely manual review; runtime policy-profile
switching beyond environment-variable-at-start; and a dedicated Europe demo scenario
(`auditable_edge_socnoc`) framing the profile around privacy-sensitive, regulated,
local-first operation. Test coverage for the Rust enforcement core is a prerequisite
for treating opt-in enforcement as production-ready.

## References / Related Project Documents

- Concept: Auditable Edge SOC/NOC — [`../concepts/auditable-edge-socnoc.md`](../concepts/auditable-edge-socnoc.md)
- Decision Loop — [`../architecture/decision-loop.md`](../architecture/decision-loop.md)
- Evidence Model — [`../architecture/evidence-model.md`](../architecture/evidence-model.md)
- Local AI Triage — [`../architecture/local-ai-triage.md`](../architecture/local-ai-triage.md)
- Deception Routing — [`../architecture/deception-routing.md`](../architecture/deception-routing.md)
- Concept profile (YAML) — [`../../concept_profiles/auditable-edge-socnoc.yaml`](../../concept_profiles/auditable-edge-socnoc.yaml)
- Demo concept pack (YAML) — [`../../demos/concepts/auditable-edge-socnoc.yaml`](../../demos/concepts/auditable-edge-socnoc.yaml)
- Demo Guide — [`../DEMO_GUIDE.md`](../DEMO_GUIDE.md)
- Privacy and Legal — [`../PRIVACY_AND_LEGAL.md`](../PRIVACY_AND_LEGAL.md)
- SOC Policy Guide — [`../SOC_POLICY_GUIDE.md`](../SOC_POLICY_GUIDE.md)
- Evolution Map — [`../concepts/evolution-map.md`](../concepts/evolution-map.md)
