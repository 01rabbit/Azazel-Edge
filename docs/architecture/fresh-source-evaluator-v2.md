# Fresh observer v2 read-only evaluator interface

Prospective interface after1223359, before implementation. Legacy public
fresh_source_observe.evaluate_fresh_source_case remains an exactv1 entry. A private
shared verifier accepts only explicit profile inputs; no global schema/hash
replacement, metadata casting or old evaluated-result conversion occurs.

New module azazel_edge.benchmark.fresh_source_observe_v2 exports FILES (49),
PROTOCOL_SHA256 (107595f5c7d85d410d65517a7f50bdb6e3dd3b31bdb4cffcd3936be98b65ea59),
RECIPE_SHA256 (unchanged46d83e1ea8551a5010f37a45a76044d81ce15d3e8a8e1196ed4d3114fa7da1ea),
file_limit(name), evaluate_fresh_source_case(artifacts,*,expected). It requires exact
v2 schema/profile and49 pins. Result is edge-fresh-source-analysis/v2, retaining
v1 fact fields plus publication. observer remains separately composed by the lab's
strict original clock/fault verifier. Missing publication retains verified callback
facts but withholds v2 status; a visible row is not a committed-prefix claim.

Publication verifier is evaluate_publication(artifacts,*,expected). Actual wire is
frozen by the separate publication interface before its implementation. Output
has status qualified/withheld, streams (per-stream independently validated committed
prefix or null), normal_complete, readiness_verified, interrupt_verified, reasons.
Its qualification cannot replace original cursor/witness/clock/load requirements.
Readiness and interrupt must have Root-observed receipt-prefix checkpoints before
writer/signal and bind exact original call/input-return seq+size+sha and file objects.
Only normal completion permits stream finalization; a verified interrupted prefix
keeps later work unknown. Worker fsync self-report remains trusted-helper evidence.

Run-envelope entry evaluate_fresh_run_evidence(cases,snapshots,disposition,*,expected)
requires cases keyed by fixed2 case IDs, each exact49 raw/null map; snapshots keyed
by caseID with canonical bytes/null; disposition canonical bytes. expected has
exactly cases (case->49 independentsha/null pins), snapshots(case->sha/null),
disposition(sha/null). All original bytes are read-only. Snapshot fields/files and
outer disposition are those fixed by1223359. External provenance must supply the
expected pins; self-reported stored verdicts are never the trust anchor.

Result: schema_version edge-fresh-run-analysis/v1,status qualified/withheld,
cases (case->leaf result or null),disposition (validated object or null),reasons,
authority_flags (allfalse). Only all original positive cases, valid seals and final
accepted disposition can qualify; missing/not_run/rejected/collection_failed/
cleanup_failed is withheld. Rejected case leaf facts remain available; aggregate
failure never changes them to zero. The lab still separately composes original
clock/fault checks before overall trial acceptance. Any post-seal extra case file,
null-slot appearance, stale hash, invalid source_revision or wrong run/protocol
rejects that envelope, never silently discards its error. No self-referential pin:
the leaf proof ignores its own stored evaluation slot, while the external snapshot
and outer disposition pin that file after write.
