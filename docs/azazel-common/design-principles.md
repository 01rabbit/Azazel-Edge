# Azazel-Common: Design Principles

Status: **Design proposal only.**

## 1. First principle

> Azazel-Common holds contracts. It does not hold judgment.

Anything that decides — what action to take, whether to escalate, whether
an IOC is credible, whether a device is trusted — stays in the owning
product. Anything that merely *describes* — a state, a message, a log
line's shape, a directory path — is eligible for Common.

A useful test before adding anything to Common: **"If this code were
deleted, would a product lose its ability to decide, or only its ability
to describe that decision the same way as its siblings?"** If the former,
it does not belong in Common.

## 2. What goes in, and why

| Module | Contents | Why it's safe to share |
|---|---|---|
| `azazel_common.schema` | `StateSnapshot`, `ModeState`, `ActionIntent`, `EvidenceRef`, `DecisionExplanation`, `AuditEvent`, `TrustCapsule` | Pure data shape. Describing a decision that already happened is not the same as making it. |
| `azazel_common.cti_contracts` | `CtiEventBatch`, `CtiFlowBatch`, `CtiReactionBatch`, `CtiContextRequest`, `CtiContextResponse` | Wire format for an advisory exchange. Fixing the *shape* of advice does not grant CTI authority over Edge/Gadget. |
| `azazel_common.paths` | runtime/config/log dir schema, legacy-path compatibility, migration dry-run helper, active-schema discovery | Directory naming convention only; no product logic depends on where a log file happens to sit. |
| `azazel_common.audit` | JSONL writer, trace-id generator, config-hash helper, HMAC helper, (future) chain-of-custody helper | Standardizes the *envelope* audit events are written in. The content and triggering of an audit event stays product-owned. |
| `azazel_common.api` | token-auth helper, role helper (viewer/operator/responder/admin), fail-closed default response, standard JSON error model | Security posture conventions, not endpoint logic. Framework-neutral; Flask/FastAPI adapters are separate optional modules. |
| `azazel_common.notify` | notification event schema, thin ntfy/Mattermost send helpers, SSE bridge model | Payload shape and transport plumbing only. No product-specific copy, tone, or UI. |
| `azazel_common.testing` | shared fixtures and contract test cases | Lets each product's CI assert it still satisfies the shared contract, without depending on another product's test suite. |

Everything in this list is chosen because it is safe to be wrong about in
the same way across all products — a naming/format detail, not a security
or arbitration decision.

## 3. What must never go in, and why

| Excluded | Reason |
|---|---|
| Azazel-Edge's Action Arbiter | AZ-01's final decision authority must stay singular and local. Moving it to Common would let a shared library's release cycle gate Edge's core safety behavior, and would blur which repository "owns" the decision that matters most. |
| Azazel-Edge's NOC/SOC Evaluator | Edge-specific judgment logic tuned to Edge's evidence model; not reusable without dragging Edge's threat model into Common. |
| Azazel-CTI's Correlation Engine | Knowledge-Plane-specific processing; CTI's analytic method is not a cross-product concern. |
| Behavioral CTI Generator | Same reasoning — CTI-specific generation logic, not a shared shape. |
| Azazel-Gadget's Wi-Fi connection control | Tightly coupled to `wlan0` / captive-portal / USB gadget specifics that do not generalize to Edge or CTI. |
| Azazel-Gadget's USB gadget control | Gadget-hardware-specific; Edge has no USB gadget role. |
| nft / tc / OpenCanary execution | Execution adapters differ by network topology and deployment target; a shared executor would either be too generic to be useful or would silently encode one product's assumptions into the others. |
| AI Assist (as a decision subject) | Each product's safety boundary around AI-assisted suggestions differs; Common must never let AI Assist output be treated as authoritative across products. |
| Web UI | UI is inherently product-specific (Edge dashboard vs. Gadget portable UX vs. CTI console). |
| E-Paper rendering | Device/screen-specific; not a contract concern. |

## 4. Safety boundaries that must hold across every phase

1. **Edge's Deterministic Arbiter is never relocated to Common.** Not in
   v0.1.0, not in v1.0.0, not ever, unless a future, separately-approved
   design explicitly revisits this — which this document does not
   authorize.
2. **CTI is advisory-only.** `CtiContextResponse` may include
   `recommended_action` / `suggested_posture`-shaped fields, but the schema
   must never include a field that reads as a command (no `directive`,
   no `must_execute`, no `override`). Consuming products treat every CTI
   field as optional input to their own arbiter.
3. **A missing, malformed, or timed-out CTI response must never block a
   decision.** Contract schemas define `CtiContextResponse` fields as
   optional/omittable (notably `behavioral_cti`, which is *absent*, not
   `null`, when there is nothing to report) precisely so that "CTI said
   nothing" and "CTI is down" both degrade to "Edge/Gadget decide alone,"
   never to "Edge/Gadget wait."
4. **Gadget is a sibling of Edge, not a subset of it.** Common schemas must
   be generic enough to fit both without silently modeling Gadget as
   "Edge minus features." Where a schema needs product-specific extension
   (e.g. Gadget-only mode values), extend via enums/optional fields, not
   by assuming Edge's field set is the baseline.
5. **Common ships schema-only in its first release.** No execution logic,
   no nft/tc/OpenCanary bindings, no AI Assist decision logic, ships in
   `v0.1.0`. This is a hard gate, not a preference — see
   `migration-plan.md` Phase 1.
6. **No name implies more than it is.** The repository is `Azazel-Common`,
   not `Azazel-Core`, specifically so nobody mistakes "shared schema
   library" for "shared decision core."

## 5. Dependency-weight principle

Because Common's primary runtime targets include a Raspberry Pi (both
AZ-01 and AZ-02), dependencies are kept minimal:

- Pydantic is the preferred base for schema modules (validated, fast
  enough, already familiar to the series), but pinned to a version range
  that avoids heavyweight optional extras.
- `azazel_common.api` stays framework-neutral in its core; Flask/FastAPI
  adapters are optional extras (`azazel-common[flask]`,
  `azazel-common[fastapi]`) so a consumer only pays for what it uses.
- No transitive dependency on any product's runtime stack (no importing
  from Edge, Gadget, or CTI source — dependency direction is strictly
  Common → nothing, products → Common).

## 6. Change-safety principle

Common is a dependency of products that have their own release cadence and
their own demo/field commitments (including BHUSA 2026 preparation for
Edge). Therefore:

- Consuming repositories pin Common to a **tag**, not a branch or
  `main`, and not a git submodule (submodules are avoided — they are prone
  to CI/local-dev/dependency-update mismatches).
- Common follows SemVer; breaking schema changes require a major version
  bump and an explicit migration note (see `migration-plan.md`).
- Introducing Common into a product is additive-only at first (new
  optional call sites), never a rewrite of an existing working path, until
  a contract test suite proves equivalence.
