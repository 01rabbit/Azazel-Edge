# Finite ingress / signed Source binding v1

## Frozen authority and acceptance

Base is `6f5f5fa551783133d1ecc5c91f877ed09a860abc`. This opt-in addition
measures the bytes actually consumed by the existing ingress reader and binds
normalized decisions to the same signed Source session. It does not authorize
actions, resume, production, safety zeros, or a comparison. Existing evaluations
and published originals retain their meanings. 5ms, 98%, and 1.2x are unchanged;
none is established by this finite accounting experiment. No privileges,
profiles, quotas, startup sampling order, dependencies, or services are added.

Native processing, the registered receiver and trusted Root custodian are trust
subjects. The separate UID61002 reader continues to read only Source. Root
retains an O_RDONLY EVE descriptor and snapshots its bytes independently of the
native counters; this does not attest against a compromised Root or native.
The existing Source verifier, protected witness, registration, private receipt
pipes, manager incarnation and Source readback are mandatory independent legs.

## Explicit opt-in and wire versions

`AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING=v1` requires accounting=v1,
close-receipts=v1 and native registration v4. Existing trust v3/v4 is retained.
Absent this new flag, the v1 receipt schemas, bounds and behavior are unchanged.
With it, native emits `outcome-native-close-receipt/v2`: the original four
fields plus `ingress`. Root emits `outcome-live-close-custody/v2` with the
existing fields. Native pipe limit is4096 bytes (one nonblocking write);
receiver4096 and Root16384 remain unchanged. Old v1 analysis rejects v2;
the new explicit v2 close profile reads original bytes without conversion.
Receiver close schema, Source framing, lifecycle and activity counting do not
change. Optional input origins are structurally validated, never used to repair
or resume a stream. A reset invalidates range qualification, not legacy defense.

Each signed decision COPY adds `ingress_origin` with exactly:
`schema_version=azazel-edge/ingress-origin/v1`, `range_ref` (session32),
`device`, `inode`, `start_offset`, `end_offset`, `raw_sha256` (hex64).
Hash the complete original raw line INCLUDING LF before trim/lossy decoding.
Ordinary normalized logs, AI forwarding and core event golden shape stay intact.
Release events have no input span and count separately from decisions.

The native `ingress` snapshot has exactly:
`schema_version=azazel-edge/finite-ingress/v1`, `range_ref`,
`measurement_valid`, `invalid_reason`, `input_identity` (device,inode or null),
`start_offset`, `committed_end_offset`, `last_observed_length`,
`committed_bytes`, `committed_sha256`, `last_stop`, `unfinished_tail`,
`oversized_in_progress`, `counts`.
Tail is null or `{start_offset,observed_bytes,raw_sha256}` and is NOT consumed.
Counters are null on arithmetic/invariant failure or exactly:
`polls,examined,admitted,alerts_admitted,shed_by_type,shed_rate,shed_backlog,
oversized_started,oversized_possible_alerts,file_replacements,truncation_resets,
unread_bytes_lost_observed,normalized_decisions,blank,admitted_without_source`.
Shed keys are `flow,dns,stats,other,unparseable`. Integers are nonnegative <2^63.
First invalid reason is null or `initial_metadata_unavailable,identity_changed,
truncation_observed,io_error,hash_overflow,counter_overflow,invariant_failure`.
Hash is null for a discontinuous range. `measurement_valid` only establishes
the consumed cohort, never whole-file EOF. Last observed length may precede
newly consumed bytes; saturating subtraction must not prove EOF.

Reuse the SAME existing startup metadata sample to bind offset/device/inode.
Fold actual existing PollReport transitions with checked lifetime arithmetic.
`polls` counts all attempted calls, including early missing/open/metadata/seek
failures; those actual zero-count reports are folded once. Existing periodic
summary/Pending counters keep their old meaning.
E=examined, A=admitted, S=sum shed, O=oversize starts; blank=E-A-S-O.
N counts actual normalized decision callbacks; A-N is only an aggregate of
admitted inputs without Source decisions. It is not a parse failure count.
Hash only offset-advancing bytes, including oversize continuation bytes exactly
once. Prefetch and repeated partial-line reads are not consumption. Shutdown
never rereads/drains input, forces a window, or manufactures a final poll.
Use bounded incremental SHA256 while retaining existing hash outputs/API.

## Additional pure analysis

New analysis `edge-finite-ingress-analysis/v1` accepts the original24 close
artifacts plus exactly8 additions: `ingress-controller.json`, `eve-start.raw`,
`eve-after-writer.raw`, `eve-before-mutation.raw`, `eve-held-final.raw`,
`eve-path-final.raw`, `normalized-log-before.raw`, `normalized-log-final.raw`.
Each has an external SHA256 pin or explicit null/null absence. EVE cap16MiB
each/64MiB total; old Source8MiB and all old bounds remain unchanged.
The controller and raw recipes are fixed in the companion lab freeze/protocol.
Missing optional legs do not erase independently verified raw/Source prefixes.

The public entry point is `evaluate_finite_ingress(artifacts, *, expected)`;
both arguments have the exact32-name map above. The output has exactly
`schema_version,case_id,status,raw_sha256,pins,legs,reasons,close,ingress,
source_decisions,source_releases,matched_decision_spans,committed_range_verified,
raw_population,unconfirmed_decision_outputs,whole_input_complete,authority_flags`.
Unknown scalar facts are null, not zero; `legs` is a map of named bool checks.
`raw_population` is null or `{bytes,complete_lf_records,tail_bytes,
committed_lf_records,unread_bytes}` from verified actual final raw input.
`close` is the explicit original-byte v2 close result, never a rewritten v1
report. `ingress` is the validated original snapshot or null.
Statuses: `unknown` when required custody/context fails; `bound_consumed_prefix`
when raw consumed-range and all signed decision spans validate but a whole-input
condition is absent; `bound_complete_input` only when additionally stable held
and path snapshots agree, no unread/tail/oversize continuation/reset, exact
examined/blank/admitted/shed/oversize and normalized/Source arithmetic agree,
ACK+receiver close+End+witness+normal exit independently validate. Otherwise
`bound_partial_evidence` retains individually verified raw/Source facts, with
explicit reasons. These labels are finite facts, never safety/performance gates.
Whole-input complete remains null without sufficient legs; explicit observed
tail/discontinuity/interruption makes it false. Native last observed tail may
be stale or null: final raw tail never overwrites that report. A historical
preimage may verify an individual signed span while final range stays unknown.

Require registration/code/actor/manager/private-pipe binding before using native
counts; authenticate Source independently even when those legs fail. Require
raw snapshot metadata before/after stability, actual O_RDONLY descriptor,
matching held object, session/range, offsets and exact raw digest for a finite
range. Check every signed decision span's types, order, bounds, object, raw
digest and normalized count. Identical SIDs or hashes at different offsets are
distinct inputs. Do not join by timestamp proximity. Mutation preimages are
historical evidence and cannot stand in for a stable final range.

Expose separately: original close facts; authenticated decision/release counts;
actual native ingress snapshot; raw verified range; input population/exclusions;
observed unread/tail bytes; unconfirmed decision outputs; and reasons blocking
whole-input completion. N-D is known only when both native and Source legs bind,
N>=D and every Source decision has a valid span. It is not proof of physical
loss. Missing native receipt leaves final counters/difference null. Missing End
leaves Source completion unknown even when N-D=0. A partial tail may leave the
consumed prefix valid while whole input remains incomplete. Never invent missing
record counts, zero loss, 98% success, delivery, or safety results.

## Tests and stop conditions

Before capture freeze the protocol/cases. Synthetic parser/crypto fixtures are
labelled synthetic and cannot prove Linux collection/independence. Cover valid
prefix, blank/nonalert/invalid, partial and oversize across polls, duplicate SID,
shedding, reset/rename/truncate/equal-length rewrite, stale session, reused
identity, reordered/overlapping spans, modified raw/pins, counter overflow,
I/O/receipt failure, native/receiver kill and missing witness/End. Incremental
SHA vectors must independently cover block boundaries and long input.
Actual Linux case acceptance is original preservation plus correctly bounded
facts/unknowns, not a requirement that every case be complete. Mandatory Linux
CI cannot pass through skip. No successful fallback, retry unchanged, permission
increase, history reset, or missing-value backfill is permitted.

Independent raw classification counts LF records, blank records and oversized
records before bounded parse classification. `raw_parseable_records` in the
fixed protocol counts nonblank records within the unchanged1MiB line bound;
oversized records are separately excluded before that classification. It never
measures actual callback invocation. Case recipe pins are trial controls only;
all reported populations still derive from saved actual raw bytes.
