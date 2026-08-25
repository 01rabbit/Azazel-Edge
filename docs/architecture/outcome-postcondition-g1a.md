# Outcome-as-Evidence G1a — Read-only mechanism postcondition verification

Tracking: #400
Parent baseline: `docs/architecture/outcome-as-evidence-v1.md`

## Purpose

G1a closes one specific epistemic gap in Outcome-as-Evidence v1:

```text
provider says command completed
        !=
requested mechanism is actually present
```

The existing Rust enforcement path remains authoritative for execution. G1a adds a separate, read-only observation step that may promote an `AppliedMechanism` from `unverified` to `observed` only when host/network readback matches the correlated applied execution.

G1a does not execute, retry, repair, release, authorize, or strengthen any defensive action.

## Authority boundary

```text
existing Rust decision/enforcement
        ↓
ActionExecutionReceipt(status=applied)
        ↓
read-only postcondition probe
        ↓
AppliedMechanism(status=observed|not_observed|unverified)
```

The probe has no executor reference and no write command vocabulary.

## Allowed host queries

Only these logical query shapes are accepted:

```text
tc -j qdisc show dev <validated-interface>
nft -j list chain inet azazel_edge prerouting
nft -j list chain inet azazel_edge input
```

All other argv shapes are rejected before subprocess invocation.

The subprocess runner:

- uses `shell=False`;
- resolves `tc`/`nft` only through `/usr/sbin:/usr/bin:/sbin:/bin`;
- does not inherit the process environment;
- passes only `LC_ALL=C`, `LANG=C`, and the fixed PATH;
- caps each probe at 5 seconds;
- rejects stdout above 1 MiB or stderr above 64 KiB;
- never persists arbitrary stdout into the mechanism record.

## Correlation prerequisite

`execution.decision_id == mechanism.decision_id` and `execution.execution_id == mechanism.execution_id` are mandatory.

A mismatch raises rather than guessing.

Any execution status other than `applied` is ineligible for promotion. Dry-run, rejected, failed, partial, released, or otherwise non-applied provider facts cannot become an observed disruptive mechanism through G1a.

## Traffic shaping verification

Current Rust throttle uses an interface-root TBF qdisc. G1a verifies:

1. scope is `interface_root_qdisc`;
2. interface name passes the strict interface validator;
3. requested command is the current grounded `tc qdisc replace ... root tbf` form;
4. requested `rate`, `burst`, and `latency` can be normalized;
5. readback contains a root `tbf` qdisc;
6. readback `rate`, `burst`, and `lat` are present and match requested semantics within narrow kernel/iproute2 rounding tolerance.

Outcomes:

- exact parameter readback match → `observed`;
- root TBF exists but required parameters cannot be verified → `unverified`;
- complete readback exists but parameters differ → `not_observed`.

A generic/pre-existing root TBF is therefore not sufficient proof of the requested mechanism.

## Redirection verification

For the current nftables redirect path, G1a requires an exact rule in the queried `prerouting` chain matching:

- source IP;
- original TCP destination port;
- requested redirect port.

A redirect to another port or for another source is `not_observed`.

Decoy interaction is still separate Outcome evidence. Rule presence does not prove successful deception or diversion.

## Isolation verification

For the current nftables isolation path, G1a requires an exact source-IP match plus a drop verdict in the queried `input` chain.

nftables JSON encodes a drop verdict as `{ "drop": null }`; presence of the `drop` key is the canonical check.

Rule presence still does not prove containment effectiveness. That belongs to Outcome evidence.

## Evidence handling

Raw provider stdout is parsed transiently and is not copied into durable mechanism evidence.

The mechanism receives a bounded `postcondition_probe` summary containing:

- basis/reason;
- verification strength;
- observation timestamp;
- logical query argv;
- return code;
- bounded stderr;
- normalized expected/observed values where needed.

A `postcondition:<digest>` evidence reference is appended to preserve provenance of the recorded probe summary.

## Failure semantics

| Condition | Result |
|---|---|
| execution not `applied` | no probe; no promotion |
| correlation mismatch | reject |
| invalid interface/IP/port | `unverified` |
| query command rejected | `unverified` |
| binary missing/query runtime failure | `unverified` |
| malformed JSON | `unverified` |
| query non-zero exit | `unverified` |
| TBF parameters missing | `unverified` |
| TBF/nft complete mismatch | `not_observed` |
| exact current mechanism readback | `observed` |
| unsupported mechanism kind | no promotion |

Unknown evidence never strengthens a live action or a tactical-effect claim.

## Explicitly not solved by G1a

- automatic TTL release scheduler;
- release/expiry observation;
- reboot reconciliation;
- authoritative actor/session identity;
- external notification delivery receipts;
- real baseline/post Outcome collectors;
- causal proof of DELAY/DIVERSION/CONTAINMENT;
- daemon enablement;
- Pi/HIL resource validation.

These remain later #400 gates.
