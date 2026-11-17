# Witness boundary fixture isolation v1

This test-only follow-up to #618 belongs to Edge #400/#393. Base is
`b73b5c2b1ba398ac16a97e071ca6702b67471561`. The original feature freeze
2026-11-17T09:55:50Z and hard deadline 13:55:50Z remain unchanged.

Main CI 44026710040 rejected one existing post-witness UID test: its intended
fault marker was never reached. The captured assertion does not identify whether
the wrapper was entered, its original call failed, or its positive assertion
failed. The historical exception chain and exact cause remain UNKNOWN. Preserve
that failure and the earlier rejected local Source run without retries/backfill.

A separate bounded diagnostic with explicit phase markers demonstrated that
unrelated ancestor-directory entry churn can correctly cause the existing strict
metadata fence to reject before the witness wrapper. Its control reaches the
post-witness UID refusal; fixture bytes stay unchanged and all FDs close. This
demonstrates a test-isolation defect, not the cause of the historical failure.

## Frozen scope and trust boundary

Production collectors, verifiers, metadata/UID/boot fences, permissions, schemas,
old assessments, Source code, CI conditions and published originals are unchanged.
Only the existing post-witness phase test and its explicit synthetic fixtures may
change. No privileges, network, deployment, services or keys are added. The
5ms / 98% / 1.2x conditions and missing-as-unknown rules stay unchanged.

Use a module-local synthetic Root OS adapter for these phase tests only. Outside
the test-owned `tmp_path`, stabilize only directory size, link count and mtime/
ctime epochs, keyed by actual device/inode. These are explicitly SYNTHETIC
ancestor epochs. Preserve actual device/inode/type and the existing modeled
owner/mode protections. Keep all metadata of owned directories and enrolled
files real. A replaced ancestor's actual inode or changed type/mode must still
reject. Do not change the shared adapter or product `_HeldFiles` logic.

Observe these phases explicitly: wrapper entry, original witness return,
authenticated-prefix assertion, then fault injection. UID and boot changes must
fail specifically at `witness reader changed`; anchor mutation must fail its
existing strict final metadata fence. Any earlier refusal remains a test failure,
not an accepted substitute for exercising the intended boundary.

## Fixed cases and acceptance

1. Existing unisolated fixture plus deterministic unrelated ancestor drift:
   rejects with the metadata-fence cause before the wrapper; bytes unchanged,
   every opened FD closed. It is a guard-negative, not an accepted UID trial.
2. Isolated fixture, no fault: witness prefix authenticates, old result preserved,
   no safety/authority qualification, every opened FD closed.
3. Isolated fixture plus the same external epoch drift and each existing
   mutation/UID/boot fault: all four phases occur in order, the intended exact
   final fence rejects, all FDs close. No weakening of `changed == [True]`.
4. Isolated fixture plus actual ancestor identity replacement: rejects before
   qualification; isolation must not hide device/inode/type/mode changes.
5. Enrolled artifact/owned-directory metadata mutation remains detectable under
   the isolated adapter, retaining the existing negative coverage.

Commit this condition before test edits. Use bounded synthetic diagnostics and
affected tests, not an unchanged full-suite retry. After independent review,
create one concrete follow-up PR; require its complete final-head CI and exact
base/head/test-merge/tree gate, merge only on success, and check automatic main
CI. Preserve every failure and report the original causal UNKNOWN. Leave #400/
#393 open for actual native registration/termination, upstream loss/completeness,
physical/production and unchanged performance acceptance conditions.
