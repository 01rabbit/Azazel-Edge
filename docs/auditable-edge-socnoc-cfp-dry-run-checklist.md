# Auditable Edge SOC/NOC — CFP Rehearsal Checklist

**Status: rehearsal tracking artifact.**
This document tracks preparation steps for a candidate CFP submission that has **not been accepted**. Nothing here implies acceptance, scheduling, or appearance. All on-Raspberry-Pi run checkboxes are left unchecked because the actual hardware run is a human step that cannot be pre-confirmed in this document.

---

## Offline Rehearsal Checklist

Steps adapted from the "Demo Readiness Checklist" in [`docs/archive/roadmaps/auditable-edge-socnoc-cfp-roadmap.md`](archive/roadmaps/auditable-edge-socnoc-cfp-roadmap.md).

### Environment Setup

- [ ] Raspberry Pi-class device powered on, storage verified, no mandatory network dependency.
- [ ] All scenario files and model weights pre-loaded on device (AI-assist aside requires local Ollama; demo runs fully without it in deterministic mode).
- [ ] Confirm `AZAZEL_DEFENSE_ENFORCE` is **not set** (default off). Live enforcement must not be active during any demo run.

### Step 1 — Deterministic Replay: `auditable_edge_socnoc` scenario

- [ ] Run `bin/azazel-edge-scenario-replay run auditable_edge_socnoc` offline on target hardware.
- [ ] Confirm output reports `execution.mode = deterministic_replay` and `ai_used = false`.
- [ ] Confirm the scenario drives a high-confidence SOC bounded reversible-control decision (`action=throttle`).
- [ ] Confirm `rejected_alternatives` list is non-empty (at minimum one alternative recorded with a reason).
- [ ] Confirm a `release_condition` string is present in the decision record.
- [ ] Confirm `config_hash` and `policy_profile` are present in the local decision record.

**Target time for Step 1: ~3 minutes.**

### Step 2 — v2 Explanation Field Walk-Through

- [ ] Open the latest explanation record (via `bin/azazel-edge-audit-review`).
- [ ] Walk through each auditable field with the audience:
  - `selected_action`
  - `rejected_actions` / `why_not_others` (show that alternatives were considered and recorded)
  - `release_condition` (read the human-readable string aloud)
  - `policy_profile` and `config_hash` (explain anchoring to known configuration)
  - `trace_id`
  - `evidence_ids`
  - `operator_wording` (plain-language handoff text)
- [ ] Demonstrate `bin/azazel-edge-audit-review` in read-only mode — confirm it presents the decision → explanation → audit-chain walk without modifying any state.

**Target time for Step 2: ~5 minutes.**

### Step 3 — Audit-Chain `verify_chain` Demonstration

- [ ] Run `verify_chain` against the hash-chained audit log. Confirm it reports no mismatch on the clean log.
- [ ] Tamper drill: manually alter one byte of a record in a copy of the audit log (do not touch the original). Run `verify_chain` against the copy. Confirm it detects and reports the mismatch at the correct position.
- [ ] Show audience that the tampered-record chain break is detectable at a specific position, illustrating the tamper-evident property.

**Target time for Step 3: ~4 minutes.**

### Step 4 — SOC Policy Dry-Run

- [ ] Run `bin/azazel-soc-policy-dry-run` against two policy profiles (e.g., `balanced` and `conservative`).
- [ ] Confirm the command reports the policy hash for each profile and the would-be decisions.
- [ ] Walk through how a different policy profile yields a different policy hash and potentially different action thresholds — demonstrating reproducibility metadata.

**Target time for Step 4: ~3 minutes.**

### Step 5 — Read-Only Review Command

- [ ] Run `bin/azazel-edge-audit-review` as the primary reviewer walk-through command.
- [ ] Confirm it is read-only (no writes, no state changes, no enforcement).
- [ ] Show the decision → explanation → audit-chain navigation.

**Target time for Step 5: ~2 minutes.**

### Step 6 — Optional Local AI Assist (shown separately, clearly labelled)

- [ ] If demonstrating AI assist: confirm it runs only against a local Ollama instance (`127.0.0.1`).
- [ ] Show that the AI assist step runs *after* the deterministic decision and cannot change it.
- [ ] Show an audited AI invocation record in the audit log (the governance layer logs every invocation).
- [ ] Clearly label this as optional and not part of the deterministic path.

**Target time for Step 6 (if shown): ~3 minutes.**

### Step 7 — Fallback Drill

- [ ] Simulate a failure condition (e.g., telemetry feed unavailable, AI assist unavailable).
- [ ] Confirm the deterministic replay path remains functional with no live telemetry and no live enforcement.
- [ ] Confirm `bin/azazel-edge-scenario-replay run auditable_edge_socnoc` completes successfully in fallback (replay-only) mode.
- [ ] Confirm no live network redirection or enforcement is triggered in fallback mode.

**Target time for fallback drill: ~3 minutes.**

### Overall Timing Estimate

| Step | Estimated Time |
|------|----------------|
| Step 1 — Deterministic replay | ~3 min |
| Step 2 — Explanation field walk | ~5 min |
| Step 3 — Audit-chain verify + tamper drill | ~4 min |
| Step 4 — Policy dry-run | ~3 min |
| Step 5 — Read-only review command | ~2 min |
| Step 6 — AI assist (optional) | ~3 min |
| Step 7 — Fallback drill | ~3 min |
| **Total (incl. optional AI step)** | **~23 min** |
| **Total (excl. optional AI step)** | **~20 min** |

Adjust per actual Arsenal slot length. Plan for an audience Q&A buffer.

---

## Reviewer Q&A — Honest Answers

These answers are prepared for the likely Prototype and Planned questions from reviewers. They are candid by design.

### On Prototype items

**Q: Does `trace_id` thread automatically end-to-end from the Rust core through the Python pipeline?**

A: No. The `trace_id` field exists at every stage from the Rust core through the Python pipeline, but automatic end-to-end propagation is **(Prototype)**: there is no integration test confirming the identifier is threaded automatically across the language boundary. Correlation across that boundary cannot currently be guaranteed. The demo correlates within the Python pipeline only and makes no claim of automatic Rust→Python threading.

**Q: Can policy profiles be switched at runtime?**

A: Not yet. Policy profiles are loaded via environment variable (`AZAZEL_SOC_POLICY_PATH`) at start time. Runtime switching without restart is **(Prototype)** — there is no runtime switcher. Three profiles (balanced, conservative, demo) are available and selectable at start.

**Q: Is live nftables/tc enforcement tested and production-ready?**

A: No. Live network enforcement (nftables/tc) lives in the Rust core behind `AZAZEL_DEFENSE_ENFORCE=true`. The default is **false**; the demo always runs with the default (dry-run). The Rust enforcement core does not carry its own automated test coverage, which limits confidence in enforcement behavior even when opted in. The Python redirect path records and audits redirect decisions without executing them. This is **(Prototype)** behavior at the enforcement layer.

### On Planned items

**Q: Can I get a reproducible replay by packaging the exact policy, config, and evidence together?**

A: Partially. Decisions carry `config_hash` and `policy_profile`, which anchor them to a known configuration. However, full config-hash and reproducibility *packaging across all outputs* — a single bundle you could ship to a reviewer and replay exactly — is **(Planned)** and not yet implemented. The infrastructure to support it (per-stream hashes, policy hash at load) is in place; the packaging layer is not.

**Q: Can I export a unified incident evidence bundle?**

A: Not yet as a unified package. Decision explanations and audit logs exist as separate streams. A unified incident evidence-bundle export format — one package containing the explanation record, the consulted evidence, and the relevant audit-chain segment for a single incident — is **(Planned)**.

**Q: Do release conditions trigger automated rollback?**

A: No. Release conditions are recorded as human-readable strings (e.g., `no_repeated_failures_for_300_seconds`) and are reviewed by operators. There is no automated rollback or release-condition orchestration today. Automated release-condition orchestration is **(Planned)**.

### On enforcement and AI boundaries

**Q: Is enforcement on by default?**

A: No. `AZAZEL_DEFENSE_ENFORCE` is **off by default**. The Python path records and audits redirect decisions without executing them. Live nftables/tc enforcement is an explicit opt-in. The demo never performs live network redirection by default. This is stated in the Safety and Ethical Boundaries section and enforced at the code level.

**Q: Can the AI change a decision?**

A: No. AI assist is advisory-only and fully audited. The deterministic path decides before AI is ever invoked. AI assist can summarize, hint, and help phrase explanations; it cannot select or modify an arbiter action. This boundary is enforced in code and covered by tests. Every AI invocation is recorded in the audit log.

**Q: Does the AI autonomously decide or take defensive action?**

A: No. Azazel-Edge is explicitly not an autonomous AI defender. The authoritative decision path is a deterministic evaluator and arbiter. AI is restricted to advisory functions that run *after* the decision is made and that cannot alter it.

---

*No event acceptance implied. This is a pre-submission rehearsal tracking artifact.*
