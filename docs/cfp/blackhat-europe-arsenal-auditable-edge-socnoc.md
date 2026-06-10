# Black Hat Europe Arsenal CFP Draft: Auditable Edge SOC/NOC Gateway

Status: CFP draft — not an accepted appearance. This document must not be moved to `docs/arsenal/` unless accepted.

This is a submission draft for a Black Hat Europe Arsenal proposal. Nothing here implies that the tool has been reviewed, selected, or scheduled. It describes one concept profile of the single Azazel-Edge core platform, framed for privacy-sensitive and regulated operations.

## Proposed Title

Primary title:

- **AZ-01 Azazel-Edge: Auditable Edge SOC/NOC Gateway**

Alternative titles (one-line rationale each):

| Candidate | Rationale |
|---|---|
| Azazel-Edge: Deterministic Edge Defense with Explainable Deception and Local AI Triage | Foregrounds the three pillars: deterministic decisions, bounded deception, advisory local AI. |
| AZ-01 Azazel-Edge: Privacy-Preserving Edge SOC/NOC with Auditable Decision Support | Leads with the privacy and accountability angle most relevant to European reviewers. |
| Azazel-Edge: Explainable Cyber Scapegoat Gateway for Local-First Incident Response | Keeps the project's "scapegoat" decoy metaphor while stressing local-first handling. |
| Azazel-Edge: Reviewable Decision Records for Edge SOC/NOC in Regulated Environments | Sober, regulation-facing framing centered on after-the-fact review. |
| AZ-01 Azazel-Edge: Hash-Chained, Explainable Edge Defense Decisions | Concise, emphasizes the tamper-evident audit chain as the differentiator. |

## Short Abstract

Azazel-Edge is a local-first edge SOC/NOC gateway built around a deterministic decision loop rather than an opaque AI defender. Telemetry is normalized into compact evidence, scored by separate NOC and SOC evaluators, and resolved by an Action Arbiter that selects exactly one of five bounded responses: observe, notify, throttle, redirect, isolate. Each decision produces a structured explanation record — the selected action, the rejected alternatives and why they were not chosen, a human-readable release condition, the active policy profile, a configuration hash, and a trace id — and is appended to a hash-chained, tamper-evident audit log. Local AI assist is strictly advisory: it can summarize, hint, and help phrase explanations, but it cannot select or modify an action. Raw logs stay on the device by default. The Arsenal demo runs as a deterministic replay on Raspberry Pi-class hardware, offline-capable, so reviewers can inspect the same explanation JSONL and audit chain an operator would use to justify a decision after the fact.

## Detailed Abstract

Many "AI for defense" tools ask operators to trust a black-box verdict. In privacy-sensitive and regulated environments this is a poor fit: reviewers, auditors, and incident handlers need to know why a control was applied, what else was considered, and how to reverse it. Azazel-Edge takes the opposite stance. The deterministic decision loop is authoritative; AI is advisory only and always runs after the decision is made.

The pipeline is small and inspectable. Edge telemetry (for example Suricata EVE events and local probes) is normalized into Evidence Plane records. Two separate deterministic evaluators score state: a NOC evaluator across nine health dimensions and a SOC evaluator whose policy is loaded from a YAML policy file whose SHA-256 hash is computed at load time. Policy thresholds are applied, and the Action Arbiter selects one bounded action from a fixed set — observe, notify, throttle, redirect, isolate — where each action declares whether it is reversible, whether it requires approval, and whether it is audited.

Every decision is explained in machine- and operator-readable form. The DecisionExplainer writes `format_version` "v2" JSONL records containing, among other fields: `selected_action`, `reason`, `rejected_actions` with `why_not_others`, `release_condition` (a human-readable string describing what must hold before the action is relaxed), `policy_profile`, `config_hash`, `trace_id`, `why_chosen`, `evidence_ids`, `next_checks`, and `operator_wording` for plain-language handoff. The record is sealed with an HMAC-signed trust capsule. In parallel, the P0 audit logger appends each event to a hash-chained JSONL log (`chain_prev` / `chain_hash` per record), making after-the-fact tampering detectable; the test suite includes tamper-detection cases.

Local-first handling is the default. The shipped Vector configuration writes only to local files, and no code path sends raw logs to external APIs. AI assist talks only to a local Ollama instance on `127.0.0.1`; an AI governance layer strips raw-log keys before any model call, restricts AI output to advice, summary, and candidate fields, and audits every invocation. The AI cannot pick or alter an arbiter action — this is enforced in code and in tests. Deception is defensive and bounded: a redirect decision can divert selected flows toward prepared OpenCanary decoys, but the Python path records and audits the redirect decision and a recorded enforcement plan; actual network enforcement lives in the Rust core, is opt-in, and is dry-run by default with rollback commands recorded.

Reproducibility is built into the workflow. Three SOC policy profiles (balanced, conservative, demo) are selectable, and a policy dry-run CLI replays normalized events against a candidate policy and reports the policy hash and would-be decisions before anything ships. A deterministic replay demo runner tags every run `execution.mode = deterministic_replay` and `ai_used = false`, so the demo is stable and explainable.

Azazel-Edge does not guarantee legal or regulatory compliance. It supports operator accountability and after-the-fact explanation in regulated contexts by making decisions reviewable, reversible, and traceable.

## Tool Description

Azazel-Edge is a single core platform presented through concept profiles; this submission is the "Auditable Edge SOC/NOC" profile. It runs on Raspberry Pi-class edge hardware and is offline-capable. Core components reviewers will see:

- **Deterministic evaluators** — separate NOC evaluator (nine health dimensions) and SOC evaluator, policy loaded from `config/soc_policy.yaml` with a SHA-256 hash computed at load.
- **Action Arbiter** — selects one of five bounded actions; each output includes the selected action, reason, rejected alternatives with reasons, release condition, chosen evidence ids, decision trace, and policy reference.
- **DecisionExplainer** — writes `format_version` "v2" explanation JSONL with the fields named above plus an HMAC-signed trust capsule.
- **P0 audit logger** — hash-chained, tamper-evident JSONL.
- **AI governance layer** — local Ollama only, advisory output only, every call audited; AI cannot decide actions.
- **OpenCanary redirect decision path** — evaluates arbiter plus SOC thresholds and records redirect decisions to state JSON, JSONL, and the audit chain.
- **Review surfaces** — Web API endpoints (`/api/triage/audit`, `/api/demo/explanation/latest`, dashboard APIs), a unified CLI, a TUI, and the read-only `bin/azazel-edge-audit-review` command (decision → explanation → audit-chain walk, no state modification).

## Why This Fits Black Hat Europe Arsenal

European SOC/NOC teams increasingly operate under privacy and accountability expectations that an opaque automated defender cannot satisfy. Arsenal attendees can sit at a Raspberry Pi-class device, trigger a deterministic decision, and immediately read the full explanation record and the hash-chained audit entry that justify it — no cloud, no raw-log egress, no trust-the-model leap. The tool demonstrates a concrete pattern for explainable, reviewable, local-first edge defense rather than a marketing claim, which suits Arsenal's hands-on, source-available format. It also shows a defensive use of deception (controlled decoy observation via OpenCanary, bounded by policy) without any offensive or attack-automation framing.

## Technical Differentiators

| Differentiator | What it means for reviewers |
|---|---|
| Rejected alternatives recorded | Each decision lists the actions not chosen and `why_not_others`, so the decision space is visible, not just the outcome. |
| Release condition per action | Every action carries a human-readable `release_condition` describing what must hold before it is relaxed. |
| Config hash + policy profile | Decisions carry `config_hash` and `policy_profile`, anchoring them to a known configuration for reproducibility (full cross-output packaging is still maturing). |
| Hash-chained audit trail | `chain_prev` / `chain_hash` per record makes tampering detectable; tamper-detection is covered by tests. |
| SOC policy dry-run | A CLI replays normalized events against a candidate policy and reports the policy hash and would-be decisions before rollout. |
| Deterministic replay demo | Replay runs are tagged `deterministic_replay` with `ai_used = false`, giving stable, explainable demo output. |
| Enforced AI governance boundary | AI is local-only and advisory; it cannot select or modify an arbiter action, enforced in code and tests. |
| Reversible, bounded actions | Five explicit actions only, each declaring reversible / approval-required / audited attributes. |

## Demo Plan

The demo is staged and replay-based, designed for a booth and for offline operation on Raspberry Pi-class hardware.

1. **Deterministic path (primary).** Run a replay scenario in `deterministic_replay` mode (`ai_used = false`). Show evidence normalization, separate NOC/SOC scoring, and the Action Arbiter selecting one bounded action.
2. **Explanation review (live).** Open the latest explanation record via CLI or the Web UI (`/api/demo/explanation/latest`) and walk the fields: `selected_action`, `rejected_actions` / `why_not_others`, `release_condition`, `policy_profile`, `config_hash`, `trace_id`, `operator_wording`.
3. **Audit chain review (live).** Inspect the hash-chained audit log (`/api/triage/audit`) and show how a modified record breaks the chain.
4. **Policy dry-run.** Replay the same events against a candidate SOC policy profile and compare reported policy hash and would-be decisions.
5. **Optional local AI assist (shown separately).** Demonstrate that local AI only summarizes and hints, and that its invocation is audited and cannot change the decision.

Demo scenarios: the deterministic showcase uses the **`auditable_edge_socnoc`** scenario (available in the demo pack). It drives a high-confidence SOC bounded reversible-control decision (action=throttle) with non-empty rejected alternatives, a release condition, and `config_hash`/`policy_profile` in the local decision record, reviewable read-only via `bin/azazel-edge-audit-review`.

If anything fails, the deterministic replay path is the final fallback, consistent with the Arsenal demo profile.

## Implemented Capabilities

| Capability | Status | Notes |
|---|---|---|
| Deterministic NOC evaluator (nine health dimensions) | Implemented | `py/azazel_edge/evaluators/noc.py`. |
| Deterministic SOC evaluator with hashed policy load | Implemented | `py/azazel_edge/evaluators/soc.py`; policy SHA-256 computed at load in `py/azazel_edge/policy.py`. |
| Action Arbiter, five bounded actions with profiles | Implemented | `py/azazel_edge/arbiter/action.py`; output includes selected action, reason, rejected alternatives, release condition, evidence ids, decision trace, policy reference. |
| DecisionExplainer v2 JSONL with trust capsule | Implemented | `py/azazel_edge/explanations/decision.py`; HMAC-signed trust capsule. |
| Hash-chained tamper-evident audit log | Implemented | `py/azazel_edge/audit/logger.py`; tamper detection covered by tests. |
| Three SOC policy profiles (balanced/conservative/demo) | Implemented | `config/soc_policy_profiles/`; selected via `AZAZEL_SOC_POLICY_PATH`. |
| Config drift auditing (per-file SHA-256 baselines) | Implemented | `py/azazel_edge/config_drift.py`. |
| SOC policy dry-run CLI | Implemented | `bin/azazel-soc-policy-dry-run`; reports policy hash and would-be decisions. |
| Deterministic replay demo runner (11 scenarios) | Implemented | `bin/azazel-edge-demo`, `py/azazel_edge/demo/scenarios.py`; tagged `deterministic_replay`, `ai_used = false`. |
| OpenCanary redirect decision path (decision + audit) | Implemented | `py/azazel_edge/opencanary_redirect.py`, `config/redirect_policy.yaml`; records decisions to state JSON, JSONL, audit chain. |
| Local AI assist with enforced governance | Implemented | `py/azazel_edge_ai/agent.py` (local Ollama only), `py/azazel_edge/ai_governance.py`; AI cannot select/modify actions. |
| Local-first raw-log handling (default) | Implemented | Default Vector config writes only to local files; no raw-log egress path. |
| Review surfaces (Web API, CLI, TUI) | Implemented | `/api/triage/audit`, `/api/demo/explanation/latest`, dashboard APIs. |
| Read-only audit review command | Implemented | `bin/azazel-edge-audit-review`; read-only, presents the decision → explanation → audit-chain walk without modifying any state. |
| Europe demo scenario `auditable_edge_socnoc` | Implemented | Available in the demo pack; drives action=throttle with non-empty rejected alternatives, release condition, and `config_hash`/`policy_profile` in the local decision record. |

## Planned / Prototype Capabilities

| Capability | Status | Notes |
|---|---|---|
| End-to-end `trace_id` threading (Rust core → Python pipeline) | Prototype | Every layer carries a `trace_id`, but automatic end-to-end threading is not guaranteed and lacks an integration test. |
| Runtime policy-profile switching | Prototype | Profiles load via environment variable at start; no runtime switcher. |
| Full config-hash / reproducibility packaging across all outputs | Planned | Partial support exists today. |
| Unified incident evidence bundle export | Planned | Partial export paths exist; unified package format is in progress. |
| Automated release-condition orchestration | Planned | Release conditions are recorded as reviewable strings; no automated rollback executes them. |
| Live network redirect/isolation enforcement | Prototype | Code path exists in the Rust core behind `AZAZEL_DEFENSE_ENFORCE=true`; defaults to false with dry-run mode, rollback commands recorded, no automated tests. Never the demo default. |

## Safety and Ethical Boundaries

- **AI is advisory, never authoritative.** The deterministic decision loop decides. AI assists only with triage hints, summarization, and explanation support, and cannot select or modify an arbiter action (enforced in code and tests).
- **Deception is defensive and bounded.** Redirect is controlled decoy observation via OpenCanary, gated by policy. There is no offensive or attack-automation capability.
- **Enforcement is opt-in and dry-run by default.** The Python path records and audits redirect decisions and a recorded enforcement plan. Live nftables/tc enforcement is in the Rust core, off by default, with rollback commands recorded. The demo never performs live network redirection by default.
- **Local-first by default.** Raw logs never need to leave the site; default configuration keeps them on the device.
- **No compliance guarantee.** Azazel-Edge does not guarantee legal or regulatory compliance. It supports operator accountability and after-the-fact explanation in regulated contexts.

## Reviewer Notes

- **Demo-default vs opt-in.** The demo default is deterministic replay with `ai_used = false` and no live enforcement. Live Suricata input and live network enforcement are opt-in and must preserve immediate fallback to replay-only mode.
- **Honest status.** Items marked Prototype (end-to-end `trace_id` threading, runtime profile switching) and Planned (full reproducibility packaging, unified evidence bundle export, automated release-condition orchestration) are not finished; please treat the tables above as authoritative.
- **Evidence for reviewers.** The behavior described is backed by the test suite at [`../../tests/`](../../tests/), including arbiter, audit-logger (with tamper detection), AI-governance, and config-drift tests.
- **Privacy posture.** Raw logs never need to leave the site; the only external forwarding is an optional, non-default opt-in (normalized alerts via Wazuh CEF).
- **No acceptance implied.** This is a draft submission, not a confirmed appearance.

## Claims & Safety Sign-off

Recorded 2026-06-11.

- **Hype scan result.** The three documents reviewed (`docs/cfp/blackhat-europe-arsenal-auditable-edge-socnoc.md`, `docs/papers/auditable-edge-socnoc-europe.md`, `docs/roadmaps/blackhat-europe-auditable-edge-socnoc-roadmap.md`) were scanned for the project's forbidden-hype phrase set (defined in `tools/claims_discipline.py` and the roadmap validation section); the only match was the checker's own definition list and a `grep` example, not a capability claim. No non-negated hype phrase was found in the draft, paper, or roadmap prose. Sign-off is **not blocked**.
- **Implemented/Prototype/Planned label review.** Capability status labels were reviewed against repository state. The `auditable_edge_socnoc` scenario and `bin/azazel-edge-audit-review` command are now reflected as Implemented. Per-stream `config_hash`/`policy_profile` and rejected-alternatives/release-condition traceability are reflected as Implemented. The remaining Prototype items (end-to-end `trace_id` threading, runtime profile switching) and Planned items (full reproducibility packaging, unified evidence bundle export, automated release-condition orchestration) remain accurately labelled.
- **AI-advisory boundary.** The AI-advisory-only and audited boundary is stated accurately: local AI assist cannot select or modify an arbiter action (enforced in code and tests); every AI invocation is audited. This is stated in the Safety and Ethical Boundaries section and the Tool Description.
- **Enforcement-off-by-default boundary.** The `AZAZEL_DEFENSE_ENFORCE` off-by-default and dry-run posture is stated accurately in the Safety and Ethical Boundaries section and in the Reviewer Notes.
- **Human proofread.** A final human proofread of the full draft against the submission form has not yet been completed. This remains an open item before submission.

## Abstract Variants

The two variants below restate only claims already present in this draft. No new claims are introduced.

### Short Abstract

Azazel-Edge is a local-first edge SOC/NOC gateway built around a deterministic decision loop rather than an opaque AI defender. Telemetry is normalized into compact evidence, scored by separate NOC and SOC evaluators, and resolved by an Action Arbiter that selects exactly one of five bounded responses: observe, notify, throttle, redirect, isolate. Each decision produces a structured explanation record — the selected action, the rejected alternatives and why they were not chosen, a human-readable release condition, the active policy profile, a configuration hash, and a trace id — and is appended to a hash-chained, tamper-evident audit log. Local AI assist is strictly advisory: it can summarize, hint, and help phrase explanations, but it cannot select or modify an action. Raw logs stay on the device by default. The Arsenal demo runs as a deterministic replay on Raspberry Pi-class hardware, offline-capable, so reviewers can inspect the same explanation JSONL and audit chain an operator would use to justify a decision after the fact.

(1045 characters)

### Detailed Abstract

Many "AI for defense" tools ask operators to trust a black-box verdict. In privacy-sensitive and regulated environments this is a poor fit: reviewers, auditors, and incident handlers need to know why a control was applied, what else was considered, and how to reverse it. Azazel-Edge takes the opposite stance. The deterministic decision loop is authoritative; AI is advisory only and always runs after the decision is made.

The pipeline is small and inspectable. Edge telemetry (for example Suricata EVE events and local probes) is normalized into Evidence Plane records. Two separate deterministic evaluators score state: a NOC evaluator across nine health dimensions and a SOC evaluator whose policy is loaded from a YAML policy file whose SHA-256 hash is computed at load time. Policy thresholds are applied, and the Action Arbiter selects one bounded action from a fixed set — observe, notify, throttle, redirect, isolate — where each action declares whether it is reversible, whether it requires approval, and whether it is audited.

Every decision is explained in machine- and operator-readable form. The DecisionExplainer writes `format_version` "v2" JSONL records containing, among other fields: `selected_action`, `reason`, `rejected_actions` with `why_not_others`, `release_condition` (a human-readable string describing what must hold before the action is relaxed), `policy_profile`, `config_hash`, `trace_id`, `why_chosen`, `evidence_ids`, `next_checks`, and `operator_wording` for plain-language handoff. The record is sealed with an HMAC-signed trust capsule. In parallel, the P0 audit logger appends each event to a hash-chained JSONL log (`chain_prev` / `chain_hash` per record), making after-the-fact tampering detectable; the test suite includes tamper-detection cases.

Local-first handling is the default. The shipped Vector configuration writes only to local files, and no code path sends raw logs to external APIs. AI assist talks only to a local Ollama instance on `127.0.0.1`; an AI governance layer strips raw-log keys before any model call, restricts AI output to advice, summary, and candidate fields, and audits every invocation. The AI cannot pick or alter an arbiter action — this is enforced in code and in tests. Deception is defensive and bounded: a redirect decision can divert selected flows toward prepared OpenCanary decoys, but the Python path records and audits the redirect decision and a recorded enforcement plan; actual network enforcement lives in the Rust core, is opt-in, and is dry-run by default with rollback commands recorded.

Reproducibility is built into the workflow. Three SOC policy profiles (balanced, conservative, demo) are selectable, and a policy dry-run CLI replays normalized events against a candidate policy and reports the policy hash and would-be decisions before anything ships. A deterministic replay demo runner tags every run `execution.mode = deterministic_replay` and `ai_used = false`, so the demo is stable and explainable.

Azazel-Edge does not guarantee legal or regulatory compliance. It supports operator accountability and after-the-fact explanation in regulated contexts by making decisions reviewable, reversible, and traceable.

(3176 characters)

---

*Confirm against the official Black Hat Europe Arsenal submission-form character limits before submission.*

## Links to Repository Documents

- [Concept: Auditable Edge SOC/NOC](../concepts/auditable-edge-socnoc.md)
- [Decision Loop](../architecture/decision-loop.md)
- [Evidence Model](../architecture/evidence-model.md)
- [Local AI Triage](../architecture/local-ai-triage.md)
- [Deception Routing](../architecture/deception-routing.md)
- [Concept profile YAML](../../concept_profiles/auditable-edge-socnoc.yaml)
- [Demo concept pack](../../demos/concepts/auditable-edge-socnoc.yaml)
- [Demo Guide](../DEMO_GUIDE.md)
- [Arsenal Demo Profile](../ARSENAL_DEMO_PROFILE.md)
- [Privacy and Legal](../PRIVACY_AND_LEGAL.md)
