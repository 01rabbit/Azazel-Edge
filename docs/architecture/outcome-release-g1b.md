# Outcome-as-Evidence G1b — Owned release / expiry reconciliation

Tracking: #400  
Parent: `docs/architecture/outcome-as-evidence-v1.md`  
G1a: `docs/architecture/outcome-postcondition-g1a.md`

## Purpose

G1b closes the lifecycle gap between a temporary disruptive action and evidence that
its runtime state is no longer present.

Before G1b, the Rust event engine emitted a TTL only as a textual `rollback_hint` and
returned a `rollback_plan`; the main loop did not schedule or execute that rollback.
Therefore `released` / `expired` could not be claimed truthfully.

G1b adds a durable release lifecycle **inside the existing Rust control plane**.
It does not give Python, M.I.O., Knowledge, Replay, or the shadow observer release
authority.

```text
Policy-authorized Rust apply
        ↓
Durable release intent already persisted
        ↓
Owned mechanism marker
        ↓
TTL due / reboot recovery
        ↓
Read owned state
        ↓
Delete only owned state
        ↓
Read absence postcondition
        ↓
Rust ReleaseEvidence(status=released)
        ↓
Python shadow reconciliation (evidence only)
```

## Non-negotiable release rule

```text
TTL elapsed != released
rollback command exit=0 != released
owned-state absence verified == release evidence prerequisite
```

A release is canonical only when the Rust release engine reports
`postcondition.verified=true`. Python refuses a `released` event without that field.

## Authority boundary

There remains one live authority plane:

```text
Rust event engine
  ├─ apply authority (existing)
  └─ release authority (G1b)

Python Outcome-as-Evidence
  └─ normalize / verify / reconcile evidence only
```

The shadow package has no callback, credential, command runner, or capability that can
request a rollback.

## Durable-before-apply invariant

For a disruptive action (`throttle`, `redirect`, `isolate`):

1. compute deterministic release task / ownership marker;
2. durably persist the release task;
3. only then execute the provider apply command;
4. successful apply activates the task;
5. partial apply marks it `uncertain`;
6. complete apply failure cancels it.

If step 2 fails, the disruptive action is not applied and the provider emits
`mode=release_guard_failed`, `result=planned_not_applied`.

This chooses failure to act over creating a temporary control that cannot later be
reconciled safely.

## Ownership model

### nftables — redirect / isolate

Each G1b-created nft rule receives a deterministic comment:

```text
azazel-edge:release-<task-id>
```

Release reads the chain using nft JSON with handles, and accepts a rule as owned only
when all of the following match:

- rule comment equals the task owner token;
- chain is expected;
- source IP is expected;
- redirect additionally matches destination TCP port and redirect port;
- isolation additionally contains the drop verdict;
- a numeric kernel rule handle exists.

Deletion is by the discovered kernel rule handle. An ownership comment attached to
semantically different rule content is treated as an error and nothing is deleted.

Multiple nft rules for the same source/scope remain independently releasable. A newer
nft task must not supersede an older tagged rule, because both rules can coexist.

### tc TBF — throttle

The current throttle uses the interface root qdisc, so only one root owner can be
current. G1b adds a deterministic qdisc handle and records expected TBF semantics:

- handle;
- rate (`256 kbit/s`);
- burst (`32 kbit` under iproute2 size parsing = 4096 bytes);
- latency.

Release deletes the root qdisc only when readback matches the exact owned handle and
TBF parameters. If another root qdisc/handle is present, it is not deleted.

A newer successfully activated throttle may supersede an older throttle task for the
same root qdisc resource. This supersession rule is not used for nft tasks.

## Ledger

Default path:

```text
/var/lib/azazel-edge/release-ledger.json
```

Override:

```text
AZAZEL_DEFENSE_RELEASE_LEDGER
```

Properties:

- versioned JSON schema;
- atomic temp-file + fsync + rename persistence;
- mode `0600` on newly created ledger files;
- regular-file / non-symlink check on the ledger itself;
- finite non-negative time validation;
- strict lifecycle vocabulary;
- bounded file size and task count;
- bounded retained terminal history;
- deterministic task identity;
- duplicate/replayed provider input is idempotent and does not silently extend TTL.

The default parent directory is expected to be deployment-controlled. Parent-directory
permission/symlink hardening is part of deployment/Pi-HIL validation, not claimed by
this slice.

## Lifecycle

```text
PREPARED
  ├─ apply succeeds ─────────→ ACTIVE
  ├─ partial apply ──────────→ UNCERTAIN
  └─ apply fails completely ─→ CANCELLED

PREPARED / ACTIVE / UNCERTAIN
  ├─ due + owned state present
  │      └─ delete + absence verified ─→ RELEASED
  ├─ due + owned state already absent ─→ RELEASED
  └─ read/delete/postcondition failure ─→ retry_pending evidence + bounded backoff

ACTIVE throttle
  └─ newer ACTIVE throttle owns same root slot ─→ SUPERSEDED
```

`SUPERSEDED` is not normalized as `RELEASED`. It records ownership replacement, not a
verified release postcondition for tactical-effect purposes.

## Reboot / crash semantics

A `PREPARED` task is persisted before apply. A crash can therefore happen in two
indistinguishable windows:

```text
prepare → crash before apply
prepare → apply → crash before activation persistence
```

After reboot, when the task is due, ownership readback resolves this ambiguity safely:

- owned state absent → release postcondition is already satisfied;
- owned state present → delete only that owned state and verify absence.

This does **not** retroactively prove that the mechanism was ever successfully applied.
G1a observation remains the prerequisite for later shadow transition of an observed
mechanism to `RELEASED`.

## Release command boundary

The G1b command runner accepts only the exact release/readback shapes required for:

- `tc -j qdisc show dev <iface>`;
- owned `tc qdisc del ... root handle <handle>`;
- `nft -a -j list chain inet azazel_edge input|prerouting`;
- `nft delete rule inet azazel_edge input|prerouting handle <numeric-handle>`.

It resolves only `tc` / `nft` from fixed system directories, clears inherited
environment variables, caps command runtime, and bounds retained command output.
Arbitrary ruleset flushes and arbitrary command shapes are rejected.

## Shadow reconciliation

Rust execution metadata now grounds:

- release task id;
- due time;
- resource key;
- owner token;
- tc handle where applicable;
- current ledger state.

G1a postcondition verification is ownership-aware for G1b actions. It will not accept
an identical TBF with another handle or an identical nft rule with another comment.

A shadow `ActionExecutionReceipt` / `AppliedMechanism` can transition to `RELEASED`
only when:

1. original execution is `APPLIED` + lifecycle `ACTIVE`;
2. mechanism was independently `OBSERVED` by G1a;
3. G1a recorded the same ownership marker;
4. Rust release evidence has exact decision/action correlation;
5. release owner matches the execution owner;
6. release status is `released`;
7. release postcondition is explicitly `verified=true`.

Legacy actions without ownership markers are never retroactively attributed to a G1b
release task.

## What `released` does not mean

A verified release proves only that the G1b-owned runtime mechanism is absent at the
release observation time. It does not prove:

- DELAY was achieved;
- DIVERSION/DECEPTION succeeded;
- CONTAINMENT was effective;
- the original apply caused any measured outcome;
- all unrelated system state was restored.

Those claims remain in Outcome / Tactical Effect gates.

## Failure semantics

| Condition | Behavior |
|---|---|
| release intent cannot be persisted before apply | block disruptive apply |
| ledger corrupt/oversized/invalid | fail closed; no new guarded apply |
| task not due | no release mutation |
| owner marker absent at due time | release postcondition satisfied as owned state absent |
| owner tag/handle exists with different semantics | do not delete; retry/error |
| rollback command fails | retry_pending |
| delete succeeds but owned state remains | retry_pending |
| verified owned absence | Rust may emit `released` |
| Python sees `released` without `verified=true` | reject event |
| Python has no prior owned G1a observation | do not mark shadow mechanism released |
| wrong decision/action/owner | reject correlation |

## Explicitly not solved by G1b

- real pre/post Outcome telemetry collectors (G3);
- new tactical-effect rules;
- external notification delivery receipts;
- authoritative cross-event actor/session identity;
- end-to-end golden replay fixture (G5);
- installer/systemd enablement;
- actual Raspberry Pi tc/nft HIL syntax, restart, performance, disk-wear and resource
  validation (G6);
- Presented Terrain / Belief / Counterfactual / MAGI / Co-Adaptation.

G1b code remains subject to G6 before claiming production/Pi deployment readiness.
