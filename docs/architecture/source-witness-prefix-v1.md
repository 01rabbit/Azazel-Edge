# Independently checkpointed witness Source prefixes — #400 / #393

## Freeze and scope

Base main2ea62213 (#590). Freeze this file and cases before code. Add a pure
witness-signed Source-prefix diagnostic; preserve all existing Source, safety,
queue, anchor writer and real-systemd reader contracts. In particular the old
whole-Source/whole-journal witnessed_prefixes reader must not be weakened.
No production/services/keys, privilege expansion, installer/security/systemd edit,
network action, journal recreation, anchor request/append or missing-data fill.

## Pure API and exactly bounded proof

verify_witnessed_source_prefix(trust_raw, source_raw, anchors_raw, *,
expected_trust_sha256, expected_context, expected_source_checkpoint,
expected_anchor_checkpoint).
Reuse #590 Source authentication: exact v3/v4 policy, externally pinned context,
nonempty canonical signed prefix, exact seq/head/size/sha256. Missing or invalid
Source provenance cannot authenticate a witness proof. Later Source suffix is
not a prerequisite; bad suffix never suppresses the valid prefix or independent
forged-acceptance positive. expected_context has the unchanged #590 fields.

Anchor checkpoint is independently retained, exact {counter,head,size,sha256};
head hashes complete canonical signed last anchor WITHOUT LF, size/SHA bind
original prefix bytes WITH LF. Checkpoint not derived from the submitted log.
Missing anchor/checkpoint is unknown. Malformed non-None global pins/context are
input errors; submitted byte/signature/chain/binding failure is a diagnostic.
Anchor prefix at most8MiB,4097 rows,8192 bytes/row; Source uses existing policy
bounds. Canonical original rows, existing outcome-input-anchor/v1 schema, exact
fields {schema_version,counter,prev,trust_sha256,state,signature}, existing
ANCHOR_DOMAIN and witness public key. trust_sha256 equals TrustPolicy.digest
(canonical policy WITHOUT LF); raw trust-file pin includes LF.

Anchor counters start1, prev starts zero, then exact monotonic counter/hash chain.
Existing validate_state exact10 fields and uint64/hash grammar apply. Genesis
Source/journal seq/size zero, heads zero and empty-byte SHAs; journal device/inode
zero. Following journal_seq increases exactly1; source_seq/size never decrease;
when Source sequence is unchanged all four Source tip fields are unchanged.
Nonzero journal state has fixed positive enrolled-by-witness device/inode; this
is consistency of witness assertions only, NOT independent journal verification.

Build authenticated Source wire-boundary tips once with incremental hashing;
match EVERY prefix anchor Source seq/head/size/sha256 to an actual authenticated
Source boundary, including the empty boundary. The LAST anchor in the selected
prefix must match the exact externally checkpointed nonempty Source prefix.
No nearest row, inferred boundary, chain repair, reordering or suffix adoption.
Only the externally sized anchor PREFIX is verified. Later valid/invalid/missing
Source or anchor suffix cannot invalidate this earlier bounded proof, and never
becomes a newly witnessed suffix. No wall-clock timestamp exists in anchors:
retained pins provide equality/relative rollback resistance, NOT freshness,
one-use admission, live witness availability, terminal completion or recovery.

Return new edge-source-witness-prefix-diagnostic/v1 with
source_prefix_authenticated, witness_prefix_authenticated, source_checkpoint,
anchor_checkpoint, raw_sha256, reasons, journal_verified=false,
qualified_safety_count=null and all five existing authority flags false.
A normal Source terminal remains a separate #590 claim. Witness signature proves
configured-key provenance of an append-only prefix, not actual independent sensor
truth, execution, journal cursor semantics, physical/Pi-HIL or production custody.
Public test keys and mock anchor fields prove none of those properties.

## Additive composition and sealed intake

A new witness plan binds exact contract_sha256, source_plan_sha256 and
anchor_checkpoint: schema_version=edge-source-witness-plan/v1. Its external
SHA includes LF. Context and trusted Source prefix must match the existing
Source proof plan and safety contract; no supplied success boolean is accepted.
New composition nests the unchanged #590 result and adds witness diagnostic.
Invalid optional witness proof becomes unknown and never erases base positives.
No old result-schema field or safety count is upgraded.

A new root-sealed witness supplement binds the existing enrollment and #590
supplement external hashes plus plan/anchors paths/hashes, using matched None
pairs for deliberately missing evidence. Reuse held-FD/Root0444/single-link,
protected ancestors, nonroot registered reader, boot/UID and all-close fences.
No new signer, collector privilege, private-key read or socket request in product.
Actual Linux test harness may create disposable existing witness/producer/observer
roles and obtain real durable anchors. It must distinguish synthetic event payloads
from actual witness/process/permission behavior, use explicit test keys and cleanup.
This is lab key separation, not production key-custody acceptance.

## Fixed acceptance and stages

1. Commit freeze/cases. Core, tests and independent review use reused agents;
   integration owns actual Linux, composition/intake, CI and refs/tree gates.
2. Real-crypto SYNTHETIC matrix verifies pinned nonempty prefix, malformed/bad or
   stale log, key/domain/context/sequence/hash/genesis/state/boundary negatives.
3. Actual isolated Linux witness anchors and producer/reader role permissions;
   valid Source prefix plus bad Source/anchor suffix and immutable sealed intake.
   Mandatory Linux CI may not skip and call that a pass. Missing capability stays
   blocked/unknown; no privilege workaround to fabricate a successful result.
4. Independent positives survive optional witness failure; pure verifier performs
   no filesystem, network, private-key, runtime or witness-client action.
5. Complete final-head CI and independent review; exact base/head/tree before
   conditional merge and update existing #400/#393. Stop new work at Nov13 08:00JST.
