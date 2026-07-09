# Azazel-Common: Architecture and Series Positioning

Status: **Design proposal only. No implementation started. No changes to
existing repositories.**

## 1. What Azazel-Common is

`Azazel-Common` (recommended repository name: `01rabbit/Azazel-Common`) is a
thin, shared **contract package** for the Azazel series — Doctrine Hub
(`Azazel`), Edge (`Azazel-Edge`, AZ-01), Gadget (`Azazel-Gadget`, AZ-02), and
CTI (`Azazel-CTI`) — plus future tools such as `Azazel-Boot`.

It is not a runtime, not a decision engine, and not a shared execution core.
It exists so that every Azazel product can describe state, actions,
decisions, audit events, and CTI exchanges the same way, without forcing
those products to share a brain.

> Azazel-Common is not the heart of the series. It is the series' common
> language.

This is why the name `Azazel-Core` was rejected: "Core" implies a shared
decision core, which would blur AZ-01's Deterministic Arbiter boundary.
"Common" correctly signals a shared vocabulary, not a shared judgment.

## 2. Why this is needed

Today, Edge, Gadget, and CTI each independently invent:

- their own state/mode representations,
- their own audit log JSON shapes,
- their own token-auth and role conventions,
- their own notification payloads,
- their own path conventions (and their own legacy-path migration logic),
- and — most urgently — an *implicit*, not formally shared, contract for
  what Edge sends to CTI and what CTI is allowed to answer with.

That divergence is fine while each product is built independently. It
becomes a liability once:

- CTI needs to serve more than one Edge-like client (Edge and, later,
  Gadget),
- new tools (`Azazel-Boot`, future AZ-0x devices) need to speak to Edge/CTI
  without re-deriving these formats from scratch,
- audits, demos (e.g. BHUSA), or partner integrations need one documented
  format to point at instead of three slightly different ones.

Azazel-Common addresses this by extracting only the parts that are safe to
extract: shapes, contracts, and thin helpers — never judgment.

## 3. Series responsibility map

```
                      ┌─────────────────────┐
                      │   Azazel (Doctrine)  │   naming, principles, series design
                      └──────────┬───────────┘
                                 │ informs
                                 ▼
                      ┌─────────────────────┐
                      │    Azazel-Common     │   shared schema / contracts /
                      │  (this repository)   │   audit format / path helpers /
                      │                      │   notify payloads / api helpers
                      └───┬─────────┬────────┘
              depends on  │         │  depends on
                          ▼         ▼
      ┌───────────────────┐   ┌───────────────────┐        ┌──────────────────┐
      │   Azazel-Edge      │   │  Azazel-Gadget     │        │   Azazel-CTI      │
      │   AZ-01            │   │  AZ-02             │        │  Knowledge Plane  │
      │   Decision Plane    │   │  Personal Tactical │        │                  │
      │                    │   │  Defense Gateway    │        │                  │
      └─────────┬──────────┘   └─────────┬──────────┘        └────────┬─────────┘
                │                        │                            │
                │   advisory context (never a command)                │
                └───────────────►  CTI contract (Azazel-Common)  ◄────┘
```

Key invariant: **arrows into "Decision Plane" never carry command
authority.** Common and CTI can hand Edge/Gadget information; only
Edge's/Gadget's own arbiter decides what happens next.

### Azazel-Edge — Decision Plane

Owns Evidence Plane, NOC Evaluator, SOC Evaluator, Action Arbiter, Decision
Explanation, and Audit Logger. Holds final decision authority. Common,
CTI, and AI Assist may inform this decision; none of them may override it.

### Azazel-Gadget — Personal Tactical Defense Gateway

Owns `usb0`-protected / `wlan0`-upstream topology, portal / shield /
scapegoat modes, portable UX. Gadget is a sibling of Edge, not a "lite
Edge" — it is not layered underneath Edge, and Common must not encode any
assumption that Gadget is a subset of Edge.

### Azazel-CTI — Knowledge Plane

Owns IOC management, correlation, campaign analysis, Behavioral CTI
generation, feed import, offline bundle import. CTI is **advisory-only**:
it may return `recommended_action` / `suggested_posture` fields, but these
are recommendations, never commands. CTI never has authority to act on
Edge or Gadget, and a CTI response being missing, malformed, or timed out
must never block an Edge/Gadget decision.

## 4. What "Common" is allowed to hold

Common holds representation, not behavior:

- shared Pydantic **schemas** for state, mode, action intent, evidence
  reference, decision explanation, audit event, trust capsule, and the CTI
  request/response contracts,
- shared **path helpers** (runtime/config/log directory conventions,
  legacy-path compatibility, migration dry-run helpers),
- shared **audit helpers** (JSONL writer, trace-id generation, config-hash
  helper, HMAC tamper-evidence helper — not the Decision Logger itself),
- shared **API helpers** (token/role model, fail-closed error shape,
  framework-neutral by default),
- shared **notification payload models** and thin send helpers (ntfy,
  Mattermost, SSE bridge shape) — not product-specific message copy or UI,
- the **CTI advisory contract** (Edge/Gadget → CTI ingestion shapes, CTI →
  Edge/Gadget advisory response shape).

See `design-principles.md` for the full in/out list and rationale, and
`contracts.md` for the schema definitions themselves.

## 5. What Common explicitly is not

Common is not where Edge's Action Arbiter, NOC/SOC Evaluators, CTI's
Correlation Engine or Behavioral CTI Generator, Gadget's Wi-Fi/USB control,
nft/tc/OpenCanary execution, AI Assist, or any product's UI/E-Paper
rendering live. These stay in their owning repository. See
`design-principles.md` §2 for the full exclusion list and the reasoning
behind each entry.

## 6. Relationship to this task

This document, together with `design-principles.md`, `contracts.md`,
`migration-plan.md`, `repository-layout.md`, and `issue-breakdown.md`, is
the complete deliverable for this design task. No code has been written,
no existing repository has been modified, and no `Azazel-Common`
repository has been created yet. Repository creation and implementation
are follow-up actions gated on review of this design.
