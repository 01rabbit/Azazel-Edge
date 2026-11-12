# Recorded fixed NFT chain baseline comparison — #400 / #393

## Freeze and scope

Base main64a6eb2a (#591). Commit this contract/cases before implementation.
Only the recorded chain inet/azazel_edge/throttle is compared at three discrete
query points. This is NOT network/legacy-TC/conntrack restoration, continuous
absence, fresh acquisition, successful execution, whole-system cleanup, safety
qualification, causal efficacy, production or Pi/HIL acceptance. No new command,
permission, service, key, installer/security/systemd change or missing-data fill.
Source signatures identify configured producer statements, not execution truth.

Reuse existing nft_flow_evidence.flow_scope/parse_readback/readback_matches.
A small pure structural-validation extraction may expose the complete validated
chain and exact owner rows, retaining readback_matches old semantic behavior.
Never use readback_matches(released)==False as absence: a changed owned rule may
fail the semantic predicate while remaining present. Count ANY exact owner-token
rule regardless of expression. No second parser or executor.

## Inputs and fixed trust boundary

Pure API evaluate_recorded_nft_restoration(plan_raw, *, expected_plan_sha256,
source_inputs, receipts). source_inputs exact keys contract_raw/source_plan_raw/
trust_raw/source_raw; receipts exact baseline/applied/released map of original
bytes or explicit None. No files, process, network, private key or callback input.
Root separately enrolls the exact plan/source/receipt hashes. Hash equality and
claimed root-query metadata are integrity/binding diagnostics, not kernel
attestation or production collector custody. No success checkbox grants trust.
Receipt originals remain unchanged; no adding missing timestamps/namespaces.

Plan canonical JSON+LF (32KiB), edge-recorded-nft-restoration-plan/v1, exact keys:
schema_version, contract_sha256, source_plan_sha256, source_event_seq,
source_event_sha256, kernel_boot_id, netns_inode, query_window, source_identity,
nft_binary_sha256, receipts. Hashes64lowerhex, source_revision40lowerhex,
canonical UUID boot, namespace positive int, Source event seq1..32768.
query_window exact start/end canonical aware UTC ISO strings, positive <=120s.
source_identity exact source_revision/helper_sha256/network_driver_sha256.
Each receipts phase descriptor is None OR exactly {sha256,root_pid,
actual_child_argv}; PID positive exact int and argv bounded list of literal strings
compared only as data, NEVER executed. Missing descriptor/data =>unknown.

Validate the Source contract using its existing exact schema/key roles and pinned
bytes; reuse #590 Source proof policy/context/prefix/final checks. Require full
Source-byte authentication for Source-owner binding. Selected canonical signed
Source row is exact seq + SHA(includingLF), kind decision_execution. Unwrap only
after authentication and reuse flow_scope on original native command/rollback,
trace, metadata and normalized tuple. Require recorded enforced/applied command
completion, positive typed executed_count, zero failed_count. These remain
producer assertions; execution_fact_verified=false always. Require Source boot
and configured owner/observer roles to match the enrolled context. No Source
normalized.ts is treated as command execution time or bridged to monotonic safety
opportunity windows. This metric changes no existing canonical Outcome facts.

## Original query receipts and comparison

Original receipt byte cap8MiB, strict duplicate/nonfinite JSON parser, depth<=12,
arrays<=4096; retain their exact external SHA (pretty JSON permitted). Exact fields:
argv,returncode,stdout,stderr,query_started_at,query_ended_at,root_pid,root_uid,
kernel_boot_id,source_identity,netns_inode,nft_binary_sha256,capture_boundary,
actual_child_argv,source. argv must equal existing fixed flow.QUERY; typed return0,
root_uid exact int0, expected root_pid/argv, exact boot/ns/source/binary pins.
Source label live_root_query_recorded_once_for_pure_projection and boundary
actual_root_SubprocessReadOnlyRunner_inside_owned_netns are enrolled assertions,
not self-authentication. Bound stdout/stderr and parse original stdout only.
No translated/normalized receipt can replace the enrolled original hash.

Query brackets must fall inside query_window and be ordered baseline.end <=
applied.start <= applied.end <= released.start, with each start<=end. UTC ordering
is recorded wall-clock metadata only, NOT a monotonic clock calibration, proof of
no clock steps, action timing, or safety/efficacy interval coverage.

All three full NFT snapshots must pass existing bounded structural validation,
including exact fixed chain attachment and unique positive handles. Baseline
must have zero exact owner-token rules. Applied has exactly one such row and
existing readback_matches must succeed. Remove that one owner row and compare
EVERY remaining typed canonical structure byte with baseline: full chain fields,
metainfo, foreign rows/order/handles/counters. Released has zero exact owner rules
and complete typed canonical structure equal baseline. No stripping volatile
counters, post-hoc normalization, inferred empty output or Python == (which
conflates bool/int/float). Any difference prevents a restoration positive.

Only complete, correctly bound, ordered input yields status
sampled_fixed_chain_returned_to_baseline. Otherwise unknown or
recorded_residue_or_change. Preserve a valid released owned-rule residue or valid
foreign difference even if another phase fails; don't erase positive lower bounds.
A zero released-owner sample may be reported only from its complete valid snapshot
and authenticated Source-owner binding; it is one recorded chain sample, not a
whole-horizon or safety zero. Missing/denied/malformed/wrong-context samples yield
null. Broad network_mechanism_restored and qualified_safety_count stay null;
execution_fact_verified and independently_measured false; existing authority flags
all false. Keep raw hashes/reasons and each phase's disposition independently.

## Read-only artifacts and stages

Add a new versioned Root-enrolled sealed intake only after pure semantics.
Use existing held-FD/Root0444/single-link/protected-ancestor fences and nonroot
registered observer UID. Plan binds the original Source contract/plan/trust/input
and three receipt hashes. Missing slots explicit None; unsafe declared files or
close/UID/boot drift refuses intake. No runtime query or new privilege.

No archived original NFT triplet was found under this task's work directories.
Do not fabricate actual capture or re-sign synthetic receipt data as real. New
parser/crypto fixtures are explicitly SYNTHETIC. Actual Linux tests may prove
only sealed-file/UID behavior over those fixtures; required CI may not skip that
boundary test. Fresh NET_ADMIN capture remains unavailable to this observer.
The existing opt-in VM harness retains the future raw receipts; new collection
needs its already-authorized environment/provenance, not weakened admission.

1. Freeze contract/cases, split implementation/tests/independent review.
2. Pure verifier plus synthetic adversarial triples, old parser compatibility.
3. Read-only intake and actual UID/file tests, no actual NFT-restoration claim.
4. Final independent review and complete exact-head CI/base/tree before merge.
   Update existing400/393 with actual evidence class and remaining gates.

## Sealed-intake wire clarification

collect_recorded_nft_restoration(enrollment_path, *, expected_enrollment_sha256)
accepts only edge-recorded-nft-enrollment/v1 with exact keys schema_version,
observer_uid,kernel_boot_id,paths,sha256. The last maps have exact keys plan,
contract,source_plan,trust,source,baseline,applied,released. Plan/contract required;
other deliberately missing slots are matched None pairs and evaluate unknown.
Paths normalized distinct absolute physical paths (including enrollment), raw
hashes64lowerhex. Enrolled observer UID must match actual nonroot reader AND
Source contract owner observer UID; boot must match actual kernel/contract/plan.
Caps: enrollment/plan/source_plan/trust32KiB, contract128KiB, source64MiB, each
original receipt8MiB. All original held descriptors/paths/ancestor fences remain
through final verification, all independent closes attempted. No root query,
private key or production endpoint access. This is actual filesystem intake of
recorded assertions, not independent current-kernel NFT observation.

## Source action coherence clarification

Producer signature/live-protocol shape validation alone does not guarantee native
action/target coherence. Before any owner count, require enforcement.selected_action
and defense.action both exactly throttle, and both enforcement.target/defense.target
to be literal IPs canonically equal the grounded flow_scope.source_ip. Re-signed
contradictory action/target inputs stay source_owner_bound=false and every owner
sample count null; valid signatures cannot substitute for this consistency check.
This binds recorded statements only and still proves no actual execution.
