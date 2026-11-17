# Finite capture close barrier v1: frozen contract

Freeze before implementation and trial, 2026-11-17. Owner: Edge #400/#393.
Base e974be06a6e9e46dc7295c517d8d9008c5078930, tree
3c25cc06bfc7e8b0fdc6563ece7b01f3054ea552. The ongoing original plan freezes
substantial features at 2026-11-17T09:55:50Z and stops at 13:55:50Z.

## What this slice proves

Independently execute read-only collection of a **finite controller-owned test
capture object**: fence admission, retain terminal record/frontier and loss
accounting, observe the supervised writer's actual termination, kernel-seal the
held memfd, and verify a separately passed read-only descriptor and its bytes.
Recount IDs/sequence/head/payloads from raw evidence, never just source totals.

This is a new annex and a distinct test capture object, not the existing regular
SignedCaptureWriter Source. Do not bypass original Root/native launch, enroll
this as an old Source, translate its times into old CLOSE, modify old evaluators
or original results, or release any old safety/comparison/runtime authority.
Whole-window/physical-event coverage, upstream completeness, transient history,
application execution and independent production custody remain unestablished.
All old-category counts remain null; old coverage/comparison/production/resume
flags remain false. The Source 5-ms, 98% and 1.2-times gates are unchanged,
separate and not qualified by this small mechanical trial.

The data kind is ACTUAL_LINUX_CAPTURE_OF_PREREGISTERED_TEST_FRAMES: actual
processes, FDs, writes, wait/seals and independent reads; payloads are test data.
Synthetic parser fixtures are separately labelled and never reported as actual
kernel evidence or genuine defensive execution.

## Trust boundary and privileges

Trust the pinned test controller's finite admission ledger and process/FD
construction. Trust the local kernel's wait, FD identity/access and sealing
operations. Do not treat a writer's own done marker, counters, successful send,
exit status alone, hashes, chmod or sampled file stability as complete evidence.

The controller owns the gate and private memfd; the supervised writer receives
only its test job/control descriptors and writable capture FD. Before any
admission, freeze the finite IDs, payload hashes, scope/nonces, protocol/source
pins, held object identity and independently read process incarnations. Actors
may start blocked before this enrollment; no test frames may be admitted first.
The separate collector receives only the enrolled read-only capture FD and
read-side control metadata, no source writer FD or signing key. It may write
its own evidence outputs, but never mutate, seek or close the observed FD, add
seals, chmod, retry/recover/rewrite the target or enable an existing service.

All actors use the existing ordinary UID, capabilities zero, no-new-privileges,
offline namespace and read-only source checkout. Same-UID process separation is
independently executed readback, not adversarial principal independence. No
installer/security/systemd, runtime defaults, production keys, permission changes
or new defensive execution are part of this slice.

## Real boundaries and immutable object

Keep all actual brackets and their common boot/clock/process references:

- C: controller closes the SAME admission gate/token under the same lock as
  attempt assignment/decision and fixes its admitted-ID frontier.
- D: the source writes its terminal data/frontier/accounting record; treat this
  as a claim to cross-check, not proof of drain or termination.
- W: the controller independently observes the actual supervised writer wait
  result/PID incarnation. Require normal exit for complete accounting; never
  replace W with a source marker or assume unknown descendants terminated.
- S: controller requests F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL on
  the same held object; record actual success/error and before/after facts.
- R: the separate collector records actual read brackets, F_GETFL=O_RDONLY,
  F_GET_SEALS before/after, fstat identity/size, full bounded pread/EOF and hash.

Before D/W/S, exercise two frozen late attempts through the SAME closed gate
while the writer is still live. Retain its actual liveness polls and gate
outcomes; verify that those denied IDs did not enter captured DATA. Also run a
negative in which a late ID is actually appended through a writable alias
before sealing; the verifier must retain and flag it. A post-seal EPERM control
is additional evidence, never a substitute for this pre-seal control.

These boundaries are distinct from any prospectively declared deadline E. A
later C/W/R, or a gap below 5 ms, does not establish coverage through E. Never
substitute a deadline for a read clock, interpolate or backfill. Gate transition
timestamps are actual enclosing brackets, not an exact kernel transition ns.

Require all four seals, not F_SEAL_FUTURE_WRITE or a read-only mode substitute.
Kernel seals apply to aliases of the inode, but prove immutability only after S.
They cannot prove no earlier overwrite/transient write, honest payloads or all
upstream events. The positive writer is pinned synchronous append-only test
code using blocking os.write, without AIO/io_uring/shared writable mappings.
The seal-busy negative deliberately retains a real writable shared mapping;
preserve EBUSY/actual mask and do not retry into a passing result.

Linux semantics: [memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
and [file seals](https://man7.org/linux/man-pages/man2/F_ADD_SEALS.2const.html).
The environment-only ordinary-UID feature probe on Linux 6.8.0-117 verified
mask 15, RO access and actual post-seal write EPERM with all capabilities zero.
This feature probe is not one of the capture trials.

## Finite accounting and unknowns

Predeclare 16 pre-C IDs a00..a15 and two late-control IDs late0/late1. Preserve
every attempt and decision. Distinguish assigned/attempted-at-this-trusted-gate
from upstream-produced, which remains null. Exact partitions use distinct IDs:

```text
attempted_at_gate = admitted + denied + failed_before_admission + unresolved
admitted = exact_matching_captured + verified_terminal_missing + unresolved
```

An incomplete/partial controller write is unresolved, not failed-before-admission
with zero bytes. Unexpected/unadmitted DATA, duplicate IDs, wrong payloads and
reordered records are separate anomalies, never hidden in a denominator.
Only an authentic complete terminal/accounting leg, normal W, successful S and
verified full R can establish a finite terminal missing count or measured zero.
Writer counter values are cross-checks against independently recounted data and
the trusted admission ledger. Missing mandatory counters, terminal/read/seal/
wait evidence, or a collector failure leave loss/unresolved totals unknown.
Retain valid raw prefix facts and positive anomalies after later failure; do not
discard good siblings, repair chains, infer endpoints or replace a failed run.

Runtime in-flight/upstream loss/physical coverage remain null even when this
test object's complete finite accounting succeeds. Abnormal writer termination
and missing terminal evidence retain observed matching IDs but do not silently
assign all remaining admitted IDs to lost or fill pending with zero.

## Frozen cases, limits and gates

Six fresh supervised cases, once in fixed order: clean, explicit_loss,
abrupt_writer, missing_loss_counter, late_bypass, seal_busy. The explicit-loss
case omits a07 and retains an explicit terminal loss record; abrupt stops after
eight records with actual nonzero wait and no terminal. Late-bypass performs
an actual unadmitted write while live; missing-counter omits its mandatory loss
field. Each negative must preserve captured facts and the expected unqualified
disposition. Collect all assignments, including failed/incomplete ones.

Maximum 32 attempts, 128 capture rows, 1 MiB per capture/reference, 16 JSON
levels, 6 cases and 30-second process watchdogs. Canonical JSON/LF, strict field
sets, no duplicate keys, uint values excluding bool, bounded lazy prefix decode,
sequence/hash-chain/source/protocol/run/capture/token/FD/actor bindings are
required. Actor/FD enrollment precedes admission; source and collector identities
are independently bound to supervised PIDs, not self-declared FD names.

Before actual collection, test normal/exact loss plus wrong token/actor/FD,
writable/unsealed/replaced descriptor, partial/changed reads, unsupported seals,
clock/order/row/hash/counter/boolean/depth/size faults, unknown/missing originals,
crash/unwaited writer, duplicate/reordered/extra DATA, and preservation of known
prefix facts. Read-only collector guards must reject target writes, F_ADD_SEALS,
close/seek/chmod and malicious paths. Required Linux CI cannot skip-as-pass.

Commit specification and data before implementation; focused/regression checks,
independent source review, one pinned virtual trial, independent original
replay, complete final-head CI and exact base/head/test-merge/tree precede merge.
After merge check the tree, update existing #400/#393 and retain unmeasured
runtime/whole-window/production conditions. Do not create a duplicate issue.
