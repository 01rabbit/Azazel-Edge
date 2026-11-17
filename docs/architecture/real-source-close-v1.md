# Actual regular Source close annex v1 — frozen implementation contract

Owner: Edge #400/#393. Base e94704e2973d54a833acc99b6454c8b9bd99970d. Commit this specification and protocol before implementation or capture. The original feature freeze (2026-11-17T09:55:50Z) and deadline (13:55:50Z) stand. Protocol: `tests/fixtures/real-source-close/v1/protocol.json`, SHA256 `4b8c23e3adf2b3f082cad016c4270ba845b33aeb25cc36fc155813ae2e3dd3e0`.

## Exact scope and compatibility

Use the existing regular Source, original SignedCaptureWriter append/close, SourceVerifier, real WitnessStore and existing role separation. This measures actual signing/storage/witness/readback mechanics of SYNTHETIC declared v3 origin, registration and payloads. The fixture registration digest is not a Root native enrollment receipt. `native_registry_authentication=not_exercised`, `actual_native_execution=false`, `actual_native_terminal_verified=null`. An authenticated declared session_end is not actual native termination evidence. Do not claim APPLIED action, create production keys, enable providers, modify runtime algorithms, bypass Root/native gates or downgrade any profile.

Source remains its original producer-owned single-link regular file. No memfd replacement, sealing, chmod, copying into a new Source, old CLOSE conversion, old assessment change or safety-zero manufacture. This annex does not invoke
#617's test-frame parser on signed Source rows. Source immutability, upstream
completeness/loss/inflight, native atomic admission/drain, whole-window coverage, physical effects and production independence remain unestablished/null. The existing 5-ms, 98%, and 1.2-times gates remain unchanged and separate.

## Files and APIs

New product files only:

- `py/azazel_edge/benchmark/real_source_close.py`:
`evaluate_real_source_close(trust_raw, source_raw, anchors_raw, *, source_arguments, witness_arguments, plan_raw=None, controller_raw=None, read_raw=None, expected)` returns a separate read-only annex.
- `py/azazel_edge/benchmark/real_source_close_collection.py`:
`collect_regular_source_fd(fd, *, expected_identity, maximum=1048576)` returns `{raw: bytes, receipt: dict}`. Export `process_identity()` for independent bootstrap; it returns the identity shape below using fixed self-proc reads.

New tests/harness: `tests/test_real_source_close.py`, `tests/test_real_source_close_collection.py`, `tests/real_source_close_lab.py`, `tests/test_real_source_close_lab.py`, `tests/test_real_source_close_linux.py`, and `tests/run_real_source_close.py`. The test agent owns runner/harness files; the integration lead owns CI and provenance review. Mutation, producer/gate/witness setup and original observer execution stay in tests only.

The evaluator calls unchanged `verify_source_bytes(trust_raw, source_raw, **source_arguments)` and `verify_witnessed_source_prefix(trust_raw, source_raw, anchors_raw, **witness_arguments)` independently. Preserve each entire returned object unchanged under `original_source_evaluation` and `original_witness_evaluation`; original input exceptions become separate `original_errors` type/reason entries and do not erase the other result. Standalone old APIs and their behavior remain unchanged. Do not accept caller precomputed evaluations or import old eligibility as new qualification.

The two argument dictionaries have EXACT original API keyword field sets:

```text
source_arguments: expected_trust_sha256, expected_context,
                  expected_prefix_checkpoint, expected_final_checkpoint
witness_arguments: expected_trust_sha256, expected_context,
                   expected_source_checkpoint, expected_anchor_checkpoint
```

Original context/checkpoint grammars remain unchanged. The prefix checkpoint and corresponding protected anchor are independently selected at actual prefix4 BEFORE suffix/finish permission. It may incidentally equal abrupt final4; never select it retrospectively or advance a witness to manufacture final-tip equality. Final checkpoint comes from actual independent Root readback after actual writer wait, not a source-owned total. Source/witness arguments are independent of optional annex receipts, allowing known signed and witnessed prefix4 facts to survive malformed annex receipts or bad Source suffix.

`expected` EXACT keys:

```text
trust_sha256, source_sha256, anchors_sha256, plan_sha256,
controller_sha256, read_sha256, source_arguments_sha256,
witness_arguments_sha256
```

Raw pins hash exact original bytes; dictionary pins hash canonical JSON plus LF of the two original argument dictionaries. A null raw pin is permitted ONLY when that raw input is None. Required dictionary pins cannot be null. Missing, malformed or mismatched pins quarantine that leg, preserve old replay and valid siblings, and prevent full finite test accounting. No inferred/fallback pins.

## Closed wire

All new JSON objects are canonical UTF8 JSON plus LF, strict duplicate/unknown field/type/finite/depth checks; no bool-as-int conversion. IDs use bounded ASCII identifier grammar (1..128 chars), hashes lowercase SHA256, clocks uint64 excluding bool. All clocks are actual enclosing reads, never substituted payload timestamps, deadlines or exact kernel transition instants.

```text
identity: pid, uid, process_start_ticks, boot_id, clock_domain
clock_domain: time_namespace_device, time_namespace_inode, timens_offsets,
              established
timens offset: clock, seconds, nanoseconds
object_identity: device, inode, owner_uid
regular_object: device, inode, owner_uid, mode, nlink, size, mtime_ns, ctime_ns

plan: schema_version, run_id, capture_id, case_id, protocol_sha256,
      source_inventory_sha256, trust_sha256, expected_context,
      controller_identity, producer_identity, collector_identity,
      source_identity, gate_id, gate_token, attempts, late_ids, maximum_bytes
plan attempt: id, kind, event_sha256, native_seq

controller: schema_version, run_id, capture_id, controller_identity,
            producer_identity, gate_id, gate_token, enrollment, attempts,
            C, late_controls, prefix_selection, final_selection,
            writer_close, post_close_append, W, test_loss_ids
controller enrollment: started_ns, finished_ns, plan_sha256, plan_bytes_read,
                       source_inventory_sha256, source_inventory_bytes_read,
                       source_identity
controller attempt: id, decision, started_ns, finished_ns
C: started_ns, finished_ns, gate_id, gate_token, admitted_ids
late control: id, gate_id, gate_token, started_ns, finished_ns,
              poll_before_ns, poll_after_ns, poll_before_returncode,
              poll_after_returncode
prefix_selection: started_ns, finished_ns, source_checkpoint, anchor_checkpoint
final_selection: started_ns, finished_ns, source_checkpoint
writer_close: started_ns, finished_ns, returned
post_close_append: attempted, started_ns, finished_ns, outcome,
                   exception_type, source_unchanged
W: started_ns, finished_ns, pid, process_start_ticks, returncode, waited

read receipt: schema_version, collector_identity, source_before, source_after,
              access_mode, read_started_ns, read_finished_ns, bytes_read,
              sha256, complete, errors
```

Schemas: `edge-real-source-close-plan/v1`, `edge-real-source-close-controller/v1`, `edge-real-source-close-read/v1`. The original trust/Source/anchors retain their ORIGINAL schemas and bytes. Object mode is the full actual st_mode integer; Source nlink must remain1, producer ownership matches enrollment, regular type and no group/world write. The two expected_context objects in original arguments and plan must match exactly before new binding/accounting can succeed. The original helper checkpoint types are `seq,head,size,sha256` for Source and `counter,head,size,sha256` for anchor.

Plan attempts are exactly a00..a07 in protocol order: prepare, start, five TEST observe decisions, end. `event_sha256` hashes the complete original unsigned `event` object as canonical JSON plus LF, including capture_origin. Match only actual authenticated Source rows; never join by time proximity. `native_seq` is the prospective SYNTHETIC recipe ordinal, not a missing native event repair. Clean uses0..7. Explicit loss omits a04 BEFORE append, a04.native_seq=null; a05/a06/a07 have4/5/6 and Source signed sequence remains genuinely contiguous. The actual signed Source is never edited/backfilled to fit a ledger. Abrupt uses the clean planned sequence but exits7 after first4; un-emitted IDs remain unresolved, never automatic loss. Late IDs are exactly late0/late1.

Controller decisions are admitted, rejected_closed or not_attempted. Eight original IDs are admitted before Source starts under the trusted TEST gate; late IDs are denied after C under the SAME lock/token while producer remains live and its Source writer is held open. Late controls enclose the same actual attempt and real Popen polls; null returncode means measured still-live ONLY when actual non-null poll brackets and enrolled incarnation bind. Not-attempted clocks are null and cannot satisfy complete accounting. The actual prefix4 selection precedes C/finish permit/suffix, and the enrollment readback completes before first admission. W is actual supervised process wait, not source done. Final selection occurs after W and before the independent collector's read.

Source producer records original close call return/error and, for clean/loss, one SAME closed writer object's actual append refusal. A real OutcomeJournalError/unavailable refusal plus unchanged Source is a local API control, not an inode seal or proof no future writer can append. No attempt uses attempted=false, other fields null. Interrupted cases retain actual partial receipts/nulls; no fabricated completed close/terminal/control. `test_loss_ids` is [] for clean, ['a04'] for explicit_loss, null for abrupt. It is a trusted test omission declaration, NEVER a native loss counter.

## Reader behavior and provenance

Root opens and pins the actual Source O_RDONLY|O_NOFOLLOW before passing only that held FD to existing collector UID61002. Producer UID1000 and observer UID65534 remain original roles; Root/controller and witness use existing UID0. No new principal/account/group/capability or Source mode change. Root exports anchors; the Source-only independent collector has no anchor/key access, witness RPC or journal/Outcome write.

`expected_identity` has exactly device,inode,owner_uid. The reader validates regular/nlink1/owner/non-writable mode, F_GETFL access mode0 and bounded size; uses bounded pread plus actual EOF without seek; repeats fstat including size, mtime/ctime. It never writes/closes/seals/chmods the supplied FD or follows caller paths. Fixed self-proc identity/clock reads are allowed. Invalid initial identity/type/mode refuses bytes; later read/probe faults retain bounded prefix. `complete=true` means a verified bounded read bracket, not source immutability or continuous absence of modifications. Source regular-file mutation outside read brackets/future writers remains unknown even if all sampled bytes match.

## Output and acceptance

Output schema `edge-real-source-close-analysis/v1`, with original evaluations, raw/pin provenance, `known_signed_ids`, `unexpected_ids`, `finite_test_gate_accounting_complete`, `complete_assigned_test_capture`, `test_gate_missing_count` (null unless complete qualified TEST accounting), `test_gate_missing_ids`, `unresolved_ids`, per-leg reasons and independent-read status. Exact clean gate accounting may show8 matching/0 finite test omissions; explicit loss7/1; abrupt4/unknown. Missing/corrupt suffix must preserve signed and witness prefix4 original results and retained known IDs. Counters are scoped to the trusted TEST gate and actual signed file, never upstream/native counters.

Always: `native_registry_authentication=not_exercised`, `actual_native_execution=false`, `actual_native_terminal_verified=null`, `source_immutability=false`, `native_atomic_close=null`, `upstream_produced=null`, `upstream_loss=null`, `runtime_inflight=null`, `whole_window_coverage=false`, `old_evaluation_modified=false`, `performance_acceptance=false`, old category counts/safety count null, and all comparison/whole-measurement/production/resume/authority flags false. Preserve original `normal_terminal_verified` only inside its unchanged original report; new labels must say authenticated DECLARED test terminal, not actual native end. Witness prefix may be shorter than final Source; report that boundary explicitly, never force final witnessing/equivalence or synthesize a v4 terminal receipt.

Bounds:3 cases,10 attempts,128 Source rows in this annex,1MiB Source and each reference,32KiB trust, depth16,30s process watchdog. Keep old original API limits unchanged; reject overbounds before hash/parse and lazily decode at most129 rows.

Tests before collection: exact old Source/witness replay parity; clean/loss/ abrupt expected accounting; bad suffix preserving prefix4; missing receipt/pin; wrong actor/context/gate/token/Source FD/Source owner/nlink/mode; writable FD, partial/changed read, unknown fields/duplicate JSON/NaN/bool/byte/row/depth limits; missing/abnormal W, fake close/refusal, late-control absent/already-dead, wrong ordering or cloned source; unproved origin never native/APPLIED; no I/O in pure API and no target mutation/close/seek in reader. Actual virtual Linux captures all three assigned cases once after review; no favorable retry. Independent raw replay, mandatory positive CI, final-head/base/testmerge/tree and postmerge checks remain separate gates. Update #400/#393, keep both open. No new issue or admission.
