# Independent safety artifact enrollment and collection v1 — #400 / #393

## Scope and trust boundary

This stage connects sealed signed observation artifacts to the frozen finite
safety evaluator. It implements registration verification and read-only artifact
collection, not a live kernel/packet/execution sensor, signing service, key
provisioning, tailer or runtime deployment. No existing v2 gate is unlocked.
The collector creates no files, sockets, processes, permissions or observations.

An administrator registers a finite capture by placing canonical enrollment,
contract, observation and checkpoint files in a root-controlled directory tree.
Root is trusted to enroll the intended artifacts and preserve the externally
retained enrollment digest. The checkpoint digest is independently retained
AFTER capture. Neither digest may be discovered from the files being evaluated.
No self-reported independent flag enrolls a source. Root compromise, malicious
signers, sensor truth, actual signer process ownership, completeness of physical
capture and cross-file atomic snapshots are outside this boundary.

The nonroot reader UID is checked against enrollment and the frozen contract and
must differ from the producer UID. This proves the artifact-ingester role only;
it does not establish that the registered collector_uid assertion is true.
A repeated read with the same pins is not a new measurement. File times are
stability checks, not freshness evidence. No checkpoint fallback, retry, tail,
missing-data fill, time fitting, key registration mutation or automatic resume.

## Frozen API and formats

`collect_registered_safety(enrollment_path, *, expected_enrollment_sha256,
expected_checkpoint_sha256) -> dict` in
`azazel_edge.benchmark.safety_collection`. Invalid, missing, unsafe, changed or
unregistered inputs raise `SafetyCollectionError(ValueError)` with NO result,
count or score; no synthetic observation is generated to replace a failure.

All JSON uses the evaluator's bounded strict canonical JSON plus exactly one LF:
reject duplicates, unknown fields, floats, noncanonical bytes and depth >12.
Enrollment <=32 KiB, checkpoint <=32 KiB, contract <=128 KiB, observations <=2 MiB.
Enrollment exact fields:
`{schema_version:'edge-safety-enrollment/v1',contract_sha256,scope,observer_uid,
paths:{contract,observations,checkpoint}}`.
`scope` equals the frozen contract scope. `observer_uid` is an exact int >0,
equal to scope.owner.observer_uid and actual effective UID, and distinct from
scope.owner.producer_uid. The externally pinned enrollment digest indirectly
pins the exact contract bytes, its three distinct public keys and all capture IDs.
Keys are never selected from the submitted observation bundle.

Checkpoint exact fields:
`{schema_version:'edge-safety-checkpoint/v1',contract_sha256,scope,
capture_ids:{category:capture_id},stream_heads:{category:sha256_or_null}}`.
Both maps contain exactly the four frozen categories. Contract, scope and capture
IDs must match enrollment and contract. Null heads pass unchanged to the evaluator:
no known violation means unknown, while admissible positive lower bounds survive.
A wrong but well-shaped head makes structural coverage incomplete, never zero.
A changed/stale receipt fails the independently retained checkpoint digest.

The actual boot ID is read only from `/proc/sys/kernel/random/boot_id`, as one
canonical UUID plus LF (bounded), before and after collection. It must match the
frozen scope. No manifest-selected boot reader or caller assertion substitutes.

## File and permission acceptance

All four paths, including enrollment, are distinct normalized physical absolute
paths, <=256 UTF-8 bytes and <=32 components, without empty, dot or parent parts.
Every ancestor is root-owned and has no group/world write bit; sticky writable
/tmp is NOT an exception. Every leaf is root-owned, regular, exact mode 0444,
single-link and bounded. No symlinks, hardlinks, FIFO, devices or directories.

Hold no-follow directory and file descriptors through all reads and evaluation.
Use read-only, nonblocking, close-on-exec opens. Compare named-path and descriptor
identity, uid/gid, full mode, link count, size, mtime_ns and ctime_ns before/after;
read exact bounded bytes to EOF and revalidate all held ancestors by both their
FD and their original parent/name. Any mutation, replacement, growth, truncation,
ancestor rename or close failure blocks return. Attempt all closes independently.
These fences detect ordinary races; they are not an atomic snapshot against Root.

## Result and qualification

Return exact outer fields:
`{schema_version:'edge-safety-collection-result/v1',status:'unqualified_collection',
provenance:{enrollment_sha256,checkpoint_sha256,contract_sha256,
observations_sha256,observer_uid,kernel_boot_id},evaluation,
independently_measured:false,qualified_safety_count:null}`.
`evaluation` is the unchanged existing finite evaluator diagnostic. Its five
authority flags remain false. No Source authentication, cleanup qualification,
production admission, complete experiment or runtime resume is established.
The existing evaluator preserves admissible violations through gaps/corrupt rows,
and returns null for unmeasured categories; zero is only a finite structural claim.

## Frozen test and acceptance stages

1. Commit this contract and `tests/fixtures/safety-collection/v1/cases.json` before
   collector implementation. The cases reuse the prior signed synthetic corpus.
2. Implement only registration verification, sealed read-only intake and evaluator
   composition. No security/systemd/installer or runtime enforcement changes.
3. Exercise every frozen case with unit/adversarial or actual Linux permission
   tests. Include metadata races, post-read and post-evaluation changes, final
   close failures, null checkpoint positive preservation and no write/network/
   process calls. All failures produce no result. Document synthetic assumptions.
4. In offline virtual Linux use actual root enrollment, distinct producer/reader
   UIDs and real denied writes to every registered artifact and enrollment parent.
   Make these tests mandatory in the existing separate-UID CI job (no skips).
5. Independent review, focused offline regressions, full CI and exact head/base/
   tree verification precede merge. Source verification, real sensor collectors,
   cleanup evidence and separately frozen Pi/HIL coverage remain later gates.
