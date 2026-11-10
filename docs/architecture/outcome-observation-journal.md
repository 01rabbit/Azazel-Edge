# Outcome observation journal — bounded local persistence

Status: software implementation / optional foreground G3 only; **G6 pending**.
Tracking: #400. This extends the existing G3 collector and identity ledger,
without changing canonical Outcome, assessment, enforcement or replay contracts.

## Transaction and authority

The journal belongs exclusively to the separate passive observation process:

```
new live Rust receipt (read-only)
 -> durable begin: append + file fsync
 -> bounded in-memory baseline/post observation
 -> complete inconclusive Outcome: append + file fsync
 -> return Outcome -> best-effort rotating JSONL projection
```

Every durable begin binds decision/execution/objective, operator-supplied OS
boot identity and the header's experiment/collector context. Identity is the
existing execution/objective pair; a conflicting decision is rejected. The
header binds scope, policy/source identity (hashed), interface, sample interval,
collector memory budgets and exact journal budgets. Changing them is not a
recovery procedure. Only `assessment=inconclusive` and
`causal_support=inconclusive` may be committed. Persisting evidence does not
make it assessable, independently sourced, authenticated or causally supported.

A begin is acknowledged only after sync, before allocating a pending window.
A result is emitted only after its complete frame has synced. The single
commit frame holds the complete Outcome and its identity together, avoiding
an identity-checkpoint/output two-file transaction. JSONL rotation/output loss
can still lose the projection; the journal retains the original result for
explicit recovery/export through `retained_outcomes()`. Consumers must use the
existing execution/objective identity when joining/exporting; projection and
journal copies are not two outcomes. There is no automatic projection replay,
no exactly-once delivery claim for downstream consumers and no complete input
coverage claim for periods when the collector is absent.

No executor, network client, command invocation, provider call, scheduler or
service is introduced. Rust apply/release behavior and ownership remain
unchanged. Sync latency is incurred only by the separately launched observer;
this adapter must not be moved into the deterministic control path. Replay
continues to use recorded data/in-memory ledgers and does not open the journal.
All operations work with networking disabled.

## Storage contract

`ObservationJournal` uses one append-only `observations.journal` with a chain
of canonical SHA-256 JSON frames: header, session open/close, begin, commit,
lost, seal. Every frame append completes short writes and calls file `fsync`;
first creation additionally syncs the private directory. Unsupported sync is
fatal. Hash/sequence/schema/transition/context validation rejects an incomplete
or corrupt tail **without truncation, repair, recreation or resumption**.
A valid reopened file and its directory are re-synced before recovery results
are exposed, including a previously sealed scope that needs no new append. A
complete frame readable from cache after an earlier sync error is not enough.
Hashes detect accidental corruption, not malicious edits, source truth or
rollback of the complete journal. This is not a signed evidence store.

The directory must already exist at a physical absolute path, owned by the
collector UID with mode `0700`. All path components are opened without
following symlinks. The fixed file must be a `0600`, same-UID regular file with
one hard link. The writer holds a nonblocking exclusive `flock`; file identity,
permissions, link count and expected length are checked for every append.
Initialization is explicit, exclusive and restricted to an empty directory;
ordinary recovery never creates a missing file. This protects against
accidental path changes and competing cooperating writers, not hostile root
or same-UID modification, directory replacement or storage rollback. Use a
trusted private parent and retain external provenance separately.

Limits are lifetime limits for the entire declared experiment:

| Resource | Default / hard bound | Exhaustion behavior |
| --- | --- | --- |
| File bytes | 16 MiB / 64 MiB | Seal new admission; retain all history. |
| Execution/objective identities | 4096 / 16384 | Seal; never evict identities or tombstones. |
| Single frame | 64 KiB | Reject oversized result; retain loss rather than return it. |
| Sessions | 64 | Seal; no unbounded growth on clean restart. |

Each pending observation reserves one maximum-size result frame plus bounded
control space. Thus an admission capacity seal cannot steal already-admitted
pending windows' completion/recovery space. Disk quota/free space is not
reserved by this software; actual ENOSPC/EIO still stops writes. Full parsing
and retained state are bounded by these budgets but are not a measured Pi RSS
or CPU guarantee. `status()` exposes usage, pending/committed/lost counts,
sessions, seal reason, continuity, duplicate/drop/write-failure/recovery counts.
Runtime counters reset on open; retained states and seals do not.

## Restart and fault policy

1. **Clean close:** mark each unfinished window lost and sync it, then sync a
   session-close frame. A future session may collect genuinely new identities.
   Earlier pending windows never gain a replacement baseline/post window.
2. **Unclosed session (SIGKILL, process loss, failed write/sync):** validate the
   file, durably mark each known pending identity lost, then permanently seal
   new admission for this scope. Retain completed results exactly once.
   Seal even when there are no pending identities: an event could have arrived
   just before its begin write failed, leaving an unknown input tail. Neither
   OS boot change nor later samples can establish its original window.
3. **Torn/corrupt frame, context mismatch or missing file:** refuse startup;
   preserve bytes. No partial reconstruction, repair or silent new ledger.
4. **Writer conflict/path drift:** refuse/poison the affected observer. A failed
   append poisons the instance so subsequent calls cannot retry I/O or fall
   back to volatile evidence. The foreground CLI reports an error and stops;
   it does not signal/reconfigure the defense process.
5. **Capacity:** refuse new identities and persist a seal when the bound is
   encountered; admitted pending windows may finish, then the CLI stops. A
   sealed journal can be reopened for bounded recovery/export, with no repeated
   growth; the live CLI rejects it before reading procfs or input.

The live reader still starts at EOF on every launch. No stored procfs sample
is replayed, no cursor is fabricated, and no guarantee is made about unseen
input during downtime. Clean restarts preserve known identity/loss history,
not an authenticated complete input stream. A commit whose sync returned an
error is not emitted then; if its complete valid bytes survive, recovery may
retain it once as the original inconclusive observation. This does not recover
an unknown or incomplete window.

## Operator procedure and responsibility

The operator owns directory provisioning, trusted boot/scope input, process
placement, storage and export permissions. See [CLI flags](../CONFIGURATION.md#optional-g3-observation-journal).
Use `--journal-initialize` only once for a new empty directory and a separately
identified experiment. On clean reopen omit that flag, keep scope/context and
budgets identical, and supply the actual current OS boot identity. Close the
journal explicitly; Ctrl-C in the foreground loop closes known windows as loss.
SIGTERM without a graceful handler is intentionally an unclean session.

After an unclean exit, preserve the original file/directory and receipts.
Opening through the Python API performs recovery and can append loss/seal
frames; it is not forensic read-only inspection. Inspect `status()` and export
`retained_outcomes()` using the same context/budgets, then close. The CLI also
performs this recovery before reporting the sealed state and exiting nonzero.
Do not delete, truncate, rotate, raise budgets or reinitialize to clear a seal.
A genuinely new experiment needs an explicit new scope and trusted upstream
boundary that excludes prior identities; a new filename alone cannot establish
that boundary. No automatic unsealing or resumed intake is implemented.

Edge owns journal/collector correctness and failure visibility. #393 owns
independent service measurement; #400/G6 owns device acceptance. No new
registration, installer, systemd configuration or default activation is part
of this implementation.

## Software acceptance and remaining gates

`tests/test_outcome_journal.py` checks sync ordering, complete records and
identity suppression across clean reopen, actual child-process SIGKILL at
empty/pending/committed phases, lost windows with later samples, ENOSPC/EIO and
unsupported sync, failure before any begin bytes, directory sync failure, sealed-reopen sync failure,
short writes/torn tails, corruption/context/permissions, symlinks/hardlinks/
FIFO, writer collision/path drift, finite session/identity/byte budgets,
reserved completion space, CLI opt-in and clean close, and no network/command
dependency. Existing G3/G5/measurement/benefit tests retain their contracts.

These are process/filesystem software tests, not physical power cuts or a G6
pass. Still required: target Pi filesystem/mount/SD behavior under abrupt power
loss, controller caches, fsync latency/error behavior, wear/write amplification,
RSS/CPU/disk growth under hostile load and observers off/on/faulted decision
parity. Authenticated event source/clock/boot identity, a durable trusted intake
cursor, safe automatic resume/rotation and independent service captures remain
separate work. No causal benefit, complete coverage, live admission or default
deployment follows from this slice.
