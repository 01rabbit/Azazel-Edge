# AZ-06 activation and termination decisions (Edge producer)

Status: implemented library; production integration remains open
(Azazel-Deception#55).
The activation and termination decision builders are present and tested, but no
normal Edge service calls them. There are no API or configuration changes and
no runtime behaviour changes.

## Purpose

Azazel-Deception acts only on a signed `EnvironmentActivationDecision` from
Edge, and accepts a signed `EnvironmentTerminationDecision` for early
withdrawal. Edge has pure builders in
`py/azazel_edge/deception_activation.py`, alongside the
transition builder in `py/azazel_edge/deception_transition.py`. The drill tools
(`tools/detection_to_decoy_drill.py`, `tools/edge_integration_functional_test.py`)
also construct decisions for isolated tests. These are producer libraries and
test paths; Edge has not yet connected them to a normal service, a production
signing-key source, a caller that wires them into the shadow/replay client or a
live transport, or a withdrawal watcher.

## Authority boundary

The builders **decide nothing**.

- Inputs are values Edge has already fixed: package id and digest, target node,
  tier, budget, `as_of`, `ttl_seconds`, status, reason. Whether to activate or
  terminate is decided by the caller through Edge's own path (Action Arbiter,
  operator approval). Neither function accepts a M.I.O. objective, hypothesis,
  recommendation or any other advisory object as input.
- Only executable statuses (`accepted`, `modified`) can be issued for
  activation. Fabric's model validates required fields, the sha256 digest, the
  bounded `ResourceBudget`, the fixed all-false `SafetyPolicy`, and
  `expires_at > effective_at`; extra fields are refused. A budget without a
  finite `bandwidth_kbps` is refused here, matching the consumer.
- Time comes only from `as_of`. The `decision_id` is a SHA-256 of every field
  that makes two decisions distinct (`edge-activation-...`,
  `edge-termination-...`), so the same inputs reproduce the same id and
  signature, and different inputs never share an AZ-06 anti-replay slot.
- With `key`, the dict is signed with Fabric's `sign_decision` (field
  `decision_signature`), exactly as `deception_transition.py` does.

## `objective_refs` (optional)

Azazel-Deception PR #59 binds a M.I.O. objective to a decision only when the signed
decision's `evidence_refs` list the objective's `advisory:` refs. Passing
`objective_refs` appends them. It is a record that Edge *considered* the
objective when it authorized. It is not a reason to authorize, and it changes
no status, budget, window or tier.

Accepted, and nothing else:

| Ref | Count |
| --- | --- |
| `advisory:mio-objective-<id>` | exactly 1 |
| `advisory:mio-frame-<id>` | exactly 1 |
| `advisory:mio-hypothesis-<id>` | 0 to 8 |
| `advisory:mio-objective-digest-<hex32>` | 0 or 1 |

`<id>` uses the opaque character set `[A-Za-z0-9._~@=+:-]` (no whitespace,
slash or quote). Each ref is at most 200 characters; at most 16 refs. Refused:
other kinds (`decision:`, `evidence:`), untyped strings, a malformed digest,
duplicates, a partial set, over-long values, and ids whose hyphen/dot-separated
segments spell an instruction. The set is the cross-repo list (C3: `activate`,
`terminate`, `run`, `extend`, `redirect`, `isolate`, ...), compared per
segment split on `_ - . ~ :`, so `frame-dec-1`, `h1` and `redirection` pass.
The current Deception hypothesis form `advisory:mio-hypothesis-<frame_id>~<hid>`
(for example `advisory:mio-hypothesis-frame-dec-1~h1`) is accepted; `~` is in
the Fabric opaque body set.

The digest ref is checked for shape only. The builder never computes a digest;
the rule is Deception's "Digest normalization rule" in
`docs/mio-objective-feedback.md` (Azazel-Deception).

`objective_refs` additionally requires non-empty `evidence_refs` and `reason_codes` (termination: non-empty
`evidence_refs`; `reason` is its code). This is a light lint against passing
advice as the basis, not a guarantee of authorization: the decision to
authorize belongs to the calling Edge arbiter, and the builder cannot check
that the basis is real. Edge's own `evidence_refs` must not carry the kinds
`advisory`, `observation_objective`, `hypothesis` or `frame` (any letter case);
MIO refs travel only through `objective_refs`. Refs are sorted and de-duplicated, so
order does not change the id or signature.

## Compatibility

Additive: a new module and tests, no change to existing modules. Fabric is the
existing optional extra (`requirements/fabric.txt`, `v0.9.0rc6`; both models
are present there). Without Fabric the module cannot be imported, like the
other Fabric-backed producers. A decision built with no `objective_refs`
is a plain accepted/modified activation, which Azazel-Deception PR #59 treats as before
(the objective is retained as advice).

## Remaining work

1. **Production wiring (not implemented).** Which Edge component calls the
   builders (an arbiter-outcome adapter like `transition_decision_from_arbiter`,
   or an API
   endpoint behind operator approval), how the signing key is provisioned, and
   how the signed decision reaches AZ-06 (shadow/replay client). Needs Edge
   review per AGENTS.md; nothing here enables enforcement.
2. **G5, withdrawal path (design note only).** When AZ-06 records isolation
   drift as a failed `EffectObservation`, or a lease reaches its end, Edge may
   decide to withdraw. The intended shape: an Edge-side watcher reads the
   observation through the existing read-only effectiveness client, the
   arbiter (not M.I.O.) judges whether to withdraw, and only then calls
   `build_termination_decision` with `reason` such as `isolation-drift` or
   `lease-expired` and the observation id as `evidence_refs`. Lease expiry is
   already enforced by the consumer's own `expires_at`, so a termination is for
   early withdrawal. One case that matters: Deception records
   `lease_expired_runtime_still_active` (a Deception observation name, not
   defined in Edge) when the runtime keeps running after
   the consumer's expiry. Edge may withdraw on that observation, again only
   after the arbiter judges it, with `reason` `lease-expired` and the
   observation id as evidence. Open questions: who owns the policy for drift severity;
   idempotency when the lease ends at the same time; behaviour when Edge or the
   transport is down (the consumer fails closed on expiry, so absence of a
   termination must never extend a lease).
