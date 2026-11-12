# Explicit full safety / protocol payload-copy pairing — #400/#393

Freeze before code; base437259c0 (#596). The complete main four-category safety
contract cannot be passed into the strict protected-only copy evaluator. Add an
explicit read-only adapter with TWO original contracts and original inputs. Never
relax old parsers, reuse queue wire, rewrite references or promote copy into main
protected_escape/application/syscall/safety counts. No acquisition or authority.

## Trust, wire and data conditions

New pure evaluate_paired_safety_payload_copy(main_contract_raw,
main_observations_raw,*,main_arguments,pair_plan_raw=None,
expected_pair_plan_sha256=None,copy_contract_raw=None,copy_plan_raw=None,
copy_report_raw=None) evaluates original main FIRST, unchanged. Invalid main
remains rejected. Missing/invalid OPTIONAL pairing returns unknown diagnostic
without altering the exact original main result, including verified positives.
Root/operator enrollment, keys/kernel/C/ELF/BTF and producer truths remain external
premises. Public test keys/synthetic main facts prove no independence or custody.

Pair plan exact canonicalJSON+LF <=32768 bytes; schema_version
edge-safety-payload-copy-pair-plan/v1; main_contract_sha256,copy_contract_sha256,
copy_plan_sha256,copy_report_sha256,main_opportunity_id,copy_opportunity_id.
All original-byte hashes and the externally pinned pair-plan hash must match;
copy contract128KiB/plan32KiB/report64KiB unchanged. Each selected protected ID must
exist exactly once in its own original contract. Full typed scope and all keypins,
predicate (including tuple), start/end and challenge SHA must be identical. Active
copy channel_id AND capture_id must be disjoint from the COMBINED set of ALL main
channel/capture IDs, including cross-kind reuse. Similar tuples/IDs never guess a
join. Main reference is an externally frozen OPAQUE premise, format-checked by old
main parser; copy independently validates its own socket-layer reference. Different
reference semantics are never claimed equivalent or rewritten.

New result edge-paired-safety-payload-copy-evaluation/v1: main_evaluation exact
original main result, payload_copy_pairing diagnostic, qualified_safety_count=null
and all original safety.FLAGS false. Diagnostic status context_bound_pair|unknown;
payload_copy_evaluation original copy result OR null;
protocol_payload_copy_observed_count1-or-null; successful_syscall_count,
application_delivery_count,qualified_safety_count always null; reasons empty or
pair_plan_unavailable/invalid_pairing_evidence. All flags false. No zero for missing,
identity continuity, same packet, simultaneous acquisition, causal linkage,
coverage, freshness, resumption, experiment or whole-safety qualification.

## Separate registered file intake

collect_paired_safety_payload_copy(main_enrollment_path,pairing_enrollment_path,*,
expected_main_enrollment_sha256,expected_main_checkpoint_sha256,
expected_pairing_enrollment_sha256) follows existing Root-sealed read-only pairing
pattern. New enrollment edge-paired-safety-payload-copy-enrollment/v1 exact fields
schema_version,main_enrollment_sha256,main_checkpoint_sha256,paths,sha256. Both
maps exact pair_plan/copy_contract/copy_plan/copy_report, absent path/hash bothnull.
Bind original main enrollment/checkpoint; rehold all original main and present
pairing files Root0444/singlelink/physicalancestors/no symlinks/distinct paths,
registered nonroot UID/actualboot/finalmetadata/allclose fences. Original main
collection result nests as base_collection; new evaluation preserves its original
evaluation. Unsafe enrollment/path/hash/reader/close makes the NEW collection
refuse; original published main/copy files and standalone main collection remain
unchanged. No repair or synthetic replacement is created on an intake failure.
New collection schema edge-paired-safety-payload-copy-collection/v1 follows existing
base_collection/evaluation/pairing_enrollment_sha256/nullqualification/falseflags.

## Fixed acceptance data / unknown conditions

Synthetic real-signature cases: complete main four categories and existing main
positives; valid copy1 ornull; missing/bad optional pairing preserves main exactly;
all pins/types/depth/duplicateJSON/signature/domain/oldqueue inputs/context drift/
selected-ID/window/challenge/tuple/key/scope mismatches and all same/cross-kind
activeID collisions. Verify old copy protected-only restriction remains unchanged.
Actual Linux file/UID tests: Root-sealed original artifacts, registered reader,
producer/root refusal, wrong pins, unsafe alias/symlink/hardlink/writable files,
missing optional paths with matchingnullhash, unchanged original bytes. Include
at least one actual signed kernel copy paired with explicitly SYNTHETIC other main
facts; main protected-delivery observations absent/countnull even when copy1.
Mandatory actual Linux CI rejects skips; no fabricated capture or extra privileges.

Appropriate regressions/independent review/finalhead fullCI/exactrefs/tree required.
No installer/security/systemd/productservice/productionkeys/deployment, new caps,
old schema migration, missing-data fill/backfill/auto-resume. Application receipt,
PIDNS/migration/checksum/unsupported iterators/reboot, object disappearance, broad
restoration, key custody, Pi/HIL/production/whole safety/causal benefit stay open.

## Implemented validation scope

49 new SYNTHETIC real-signature cases passed. Offline Linux6.8.0-117 exact5-argument
profile: all57 selected tests passed in3.96s without skips (49synthetic +8actual
Linux). One actual signed kernel-copy capture is paired with explicitly SYNTHETIC
other four-category main facts; its main protected-delivery observations are absent
and count remains null while copy count is1. The other Linux cases exercise real
Root-sealed files/UID/unsafe metadata over synthetic payloads, not real traffic.
Registered reader accepts; producer/Root refuse; unsafe/missing optional metadata
refuses only the new collection or yields the specified unknown diagnostic. Original
bytes and independently collected standalone main positive remain unchanged.

No original parser/evaluator/native acquisition/privilege changed. Same six-cap
isolated Root setup, unchanged minimal sensor, exact CI PYTHONPATH=.:py, networknone,
default seccomp/sourceRO. Actual local log SHA150b1bda9b94f0acbd2aea2f7f353184f78575e80977f0c25e1fb1ed8d2067b5
and stopped-container profile are retained separately. No main synthetic positive
is promoted to actual safety evidence. Final independent review and final-head
complete hosted CI/ref checks remain required before conditional merge.
