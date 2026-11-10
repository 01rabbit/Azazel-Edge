# G3 verified-input resumption — observable prefix continuity

Tracking: #400. Status: optional software implementation; **G6 pending**.

This adds `--journal-resume-input` for a **new v2 journal scope and initially
empty input**. Ordinary v1 journaling keeps its permanent unclean-session seal.
No existing v1 journal, seal, history or source is migrated, cleared or guessed.
Default operation remains volatile; no service or installation is enabled.

## Preconditions and limits of the claim

The operator supplies a trusted, append-only local Rust-record producer, its
physical absolute input path, a trusted private parent, and current OS boot ID.
The reader has only a read-only descriptor. It requires a regular, single-link
file owned by root or its own UID, without group/world write, and follows no
symlink path component. It holds no producer lock and never changes input,
permissions, producer configuration, routing, nft/tc, release or defense state.

Continuity means **the same file identity and exact saved byte prefix are
observable again**. The journal binds path hash, device/inode/owner, byte/record
budgets, collector policy/context, scope and boot metadata. Cursor frames save
an exact UTF-8 JSONL newline boundary and SHA-256 of all bytes through it.
Reopen compares these bytes before writing recovery facts or accepting new
observations. A snapshot is read twice; matching consumed prefix and snapshot
bytes are required. Replacement/rotation, missing/truncated/rewritten input,
unsafe metadata, partial restart tail and changed configuration refuse restart.

This is not authenticated producer/clock truth, an anti-rollback store or proof
that unseen records were never removed. A hostile root/same-UID writer can
rewrite history, and a same-inode truncation/regrowth restoring the exact saved
prefix during downtime is not distinguishable. The append-only trusted-source
precondition is explicit. Every startup/restart retains an observation gap;
matching bytes never establishes complete telemetry, action completion time or
protected-service coverage while the observer was absent. There is no new
supported Outcome, tactical assessment or causal-benefit claim.

## Durable ordering and recovery

```
verified complete input line
 -> durable observation begin OR durable known window-loss identity
 -> durable cursor advance (same journal and writer lock)
 -> collect genuinely new bounded samples
 -> revalidate input prefix and clock continuity
 -> durable original inconclusive Outcome -> best-effort JSONL projection
```

Cursor advancement is acknowledged only after file fsync. A cursor may advance
one actually read line at a time; fabricated snapshots, skipped intermediate
lines, duplicate-key/nonfinite/malformed JSON and unknown source shapes cannot
advance it. JSON is validated through the existing Rust adapters. No raw input
payload or address is added to cursor frames; they retain position/digest,
classification and normal existing identity metadata only.

On **every reopen**, including a clean close or OS boot change:

1. Validate and re-sync the journal. Verify file identity, saved prefix and the
   complete startup input snapshot. Failed verification does not alter journal
   bytes and never falls back to EOF or a new empty ledger.
2. Durably mark every previously pending window lost. For v2 only, close the
   unclean session with a recovery marker, keeping its history and counters.
3. Hold new observation admission closed behind an input recovery fence.
   Traverse the bounded unread startup snapshot **only as missed input**.
   Applied disruptive receipts with policy objectives get stable identity
   tombstones (`restart_input_missed`) before their positions advance. Existing
   committed results stay committed; lost identities stay lost. Other valid
   receipts/releases advance as excluded records without adding activity,
   baseline/post samples or live windows.
4. Recheck the prefix and current complete tail. New bytes arriving during
   recovery also go through loss-only processing (at most four catch-up passes;
   failure to catch up stops without opening admission). Append/fsync an
   `input_ready` fence only when that snapshot is fully excluded. Only then start
   an empty telemetry collector and a fresh observation segment. The fence
   counts a startup/restart gap, even if unread bytes were empty.
5. Reject stale/future/naive/unparseable event times and new events lacking a
   wholly fresh pre-window (`input_time_unusable`). Late delivery beyond one
   sampling interval is also loss. The alert timestamp is only a conservative
   freshness filter; G3 keeps its receipt-time boundary and existing
   `provider_execution_timestamp_unavailable` confounder. It is not upgraded to
   provider completion truth. Missing timestamps that cannot produce canonical
   source facts refuse intake instead of inventing an identity.

No historical event is sent to the live collector during recovery. Old samples
are never loaded and missing windows are never extended, restarted or filled
with later unrelated samples. A new date on a previously lost execution cannot
reopen it or add duplicate activity to a fresh baseline. The input missed count
counts excluded raw lines (including retained duplicates), not unique missing
executions or a benefit denominator. Fresh sampling still uses existing coverage/confounder rules and
inconclusive assessments. NTP/wall-time reversal or drift against monotonic
time beyond one sample interval stops collection and pending windows become
loss; original windows are not shifted. Both before processing and before
result commit are checked.

A kill/write failure before the begin leaves the cursor behind: recovery loses
the unread receipt. A kill after begin but before cursor loses the known window
and deduplicates the unread copy. A kill after cursor but before commit loses
the pending window. A surviving completed commit is retained once. A complete
cursor surviving a sync error can be validated/re-synced on reopen; a torn
journal tail is refused without repair. A second interruption during backlog
loss handling resumes only from the last durable position, without reopening
windows or double-counting committed Outcomes.

## Bounds, failure and responsibilities

| Resource | Default / hard limit | Behavior |
| --- | --- | --- |
| Whole input bytes | 16 MiB / 64 MiB (minimum 64 KiB) | Refuse oversize, no rotation following. |
| Whole input records / durable cursor advances | 8192 / 32768 | Count before line-list allocation; close new admission at capacity, never replenish. |
| Complete/incomplete record | 64 KiB | Refuse oversized records; live partial lines wait without cursor movement. A partial startup tail refuses automatic restart. |
| Startup catch-up | 4 passes | Refuse a persistently busy source; no admission without a completed fence. |
| Live batch | 256 records | Return to sampling/validation after each bounded batch. |
| Journal bytes, identities, sessions | Existing exact budgets | Preserve all results, losses and cursors; no eviction, compaction or automatic unsealing. |

Cursor/control frames obey the same sync, exclusive writer, permissions,
poisoning and reserved pending-window space rules as v1. On exhaustion or I/O,
metadata, prefix, decode or clock failure the separate foreground observer
reports failure and stops, preserving its last acknowledged position and
pending/loss evidence. It never invokes an executor or resets the source.
Further open is allowed only if the full configured continuity checks pass;
a complete prefix mismatch is not repaired. At any seal/capacity, retain the
scope and original input. New scope requires an explicitly established new
experiment boundary, not deleting a file or increasing budgets.

The reader does not fsync or block the producer. Input durability is verified
again on restart; if the source did not survive through the saved position,
restart fails closed. Prefix hashes and journal are not a two-file transaction
or exactly-once downstream delivery guarantee. Live mutation checks reduce
accidental stale-source admission; they do not make a mutable hostile producer
an atomic trusted source. Full-prefix verification has bounded but unmeasured
cost and remains outside the deterministic defense process.

Edge owns cursor/observer correctness. The operator owns trusted append-only
source, clock/boot configuration and scope setup. #393 owns independent service
capture; #400/G6 owns Pi physical storage, power cuts, cache/mount behavior,
wear, write amplification and off/on/faulted observer CPU/RSS/latency/decision
parity. These tests do not authorize default deployment or enforcement.

## Software acceptance

`tests/test_outcome_input_resume.py` covers real child-process SIGKILL before
begin, after begin, after cursor, after commit and during backlog recovery;
position ordering/fsync failure/ENOSPC/torn tails; stable committed/lost IDs;
clean/OS-boot reopen; rewrite/truncate/replacement/rotation/missing/partial
source, link/permission/path/budget failures; malformed input and position
forgery/skip; bounded concurrent startup catch-up; stale/unclocked/delayed/warmup losses; bounded inputs; foreground
fresh-only sampling, clock jump and pre-commit mutation refusal; default/opt-in
CLI and no network/command dependency. Existing v1/G3/G5/measurement tests must
remain green. No physical power-loss or complete-source-authentication result
is inferred from these process tests.


The separate [opt-in v3 authenticated-capture profile](outcome-authenticated-input.md)
adds public-key source verification and a separately owned protected-prefix
witness for new scopes. It does not migrate existing records or change this
version's claims; coordinated whole-machine rollback remains outside its
software-only guarantee.
