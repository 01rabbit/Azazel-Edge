# Recorded forged-input refusal and independent state samples — #400/#393

Freeze before implementation, base4a372ef33b5ec49041a247e9ecb1b54d41fafa44.
Reuse existing SourceVerifier, InputAuthentication, BoundedInput,
ObservationJournal, witness and sealed-read paths. No authentication/runtime
policy, provider, privileges, services, installer/security/systemd or production
key/deployment change. Offline only; no repair, backfill, auto-resume or history
rewriting. Existing98%/1.2x and comparative timing gates are untouched.

## Finite challenge and fact boundary

First slice ONLY exercises a well-shaped registered v3 Source with an authentic
nonempty prefix and one otherwise eligible next frame whose Ed25519 signature
is deliberately invalid. Independently verify the exact original challenge with
unchanged SourceVerifier and distinguish its signature failure from malformed
wire, wrong context, permission failure, generic error, silence, timeout or kill.
The submitted bytes must remain unchanged through the attempt. Other forgery
types are future separately frozen controls, not implied coverage.

The actual separate-UID Linux consumer uses existing BoundedInput and journal
authentication. Retain exact refusal class/reason and original worker stdout/
stderr, process UID/PID, code hash, boot and bounded execution facts. These are
Root-controller provenance assertions; exit status alone is never refusal proof.
No synthetic success worker, mocked verifier or re-signed observer fact may stand
in for the actual attempt. Lifecycle event payloads and test keys remain lab data,
not native defense execution or production key-custody evidence.

Before challenge, genuinely initialize the existing witness and observer state,
accept a valid signed prefix and retain its exact independent checkpoints. Stop
or pause existing writers at a documented boundary. The baseline may be a closed
session before a refused reopen, or paused before consumption; specify which.
Acquire independent before/after original Source, journal and anchor bytes plus
dev/inode/uid/gid/mode/nlink/size/mtime/ctime and read times with bounded stable
held descriptors. The comparison interval must bracket the actual verifier
attempt and end BEFORE normal close/recovery/cleanup effects. No closing/reopening
the journal merely to read it. The read-only observation path never writes a
target artifact or requests a witness append. Harness setup/generation/teardown
are separate trusted roles. No private key belongs in a public export.

Validate journal chain and cursor data against the exact baseline bytes and
signed witness tip where feasible using existing primitives; explicitly mark any
semantic journal/cursor verification not established. Raw equality proves only
unchanged sampled persistent bytes/identity, not absence of transient writes,
all-horizon safety, execution truth or physical durability. No same-UID/Root
adversary resistance is claimed. A sealed exported copy's inode is distinct from
the recorded runtime inode; never substitute one for the other.

## Additive offline verification and intake

Add a versioned externally hash-pinned plan binding exact trust/context, Source
prefix and anchor checkpoints, challenge SHA, capture ID, before/after artifact
hashes/metadata and worker evidence. Pure verification consumes bounded original
bytes only; no I/O/process/network/key/signing/live query or witness request.
Root-sealed nonroot intake reuses existing held-FD/protected-ancestor/0444/
single-link/actual UID+boot/all-close fences and external enrollment/plan pins.
No old schema, evaluator, count or admission guard is upgraded implicitly.

Result distinguishes recorded refusal consistency, unchanged sampled state,
observed persistent change, and unknown with reasons. Any valid observed journal,
cursor or anchor change is preserved even when another artifact or worker proof
is missing/invalid. Missing/incomplete/unsafe/unpinned input never yields zero,
unchanged or refusal. The known positive is a bound state-change diagnostic, not
automatically forged acceptance, a safety count or an authentication oracle.
All runtime/experiment/causal/admission authority remains false and qualified
safety counts null. Original measurements stay immutable.

## Controls and acceptance fixed before code

1. Actual valid eligible next input in a separate matched scope advances the
   authenticated cursor/journal/witness, proving a functional positive path.
2. Actual invalid signature refuses with exact exception; submitted Source and
   independently sampled journal/cursor/anchors stay exactly unchanged.
3. Missing/failed/partial/oversized/wrong-context/hash/identity/clock/worker evidence
   remains unknown, without suppressing a valid independently observed change.
4. Synthetic parser/crypto negatives separately cover malformed plans, bool-as-
   integer, duplicate/noncanonical/deep JSON, wrong signature/domain, altered
   baseline/after/cursor/anchor, generic error, exit-only, forced stop, changed
   Source, missing controls and untrusted baseline/checkpoints.
5. Actual Linux intake tests use separate producer/consumer/reader UIDs, check
   unsafe sealed files, original immutability and producer/Root reader refusal.
   Required Linux CI must execute without skips; unsupported environment is
   blocked/unknown, never permissions expansion or simulated success.
6. Independent code review, appropriate regression tests, complete final-head CI
   and exact live base/head/tree are merge gates. Update existing#400/#393; no
   duplicate issue. No deadline/automation is inherited from prior work.
