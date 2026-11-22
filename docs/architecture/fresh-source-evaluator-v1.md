# Read-only fresh Source evaluator, version 1

Prospective API refinement before dependent code/collection. Preserve all old
evaluators, schemas and raw outputs. No I/O or caller-supplied approval flags.

`nonalert_lines()` returns the immutable27004 deterministic600B lines.
`event_specs(case_id)` returns the frozen ordered recipe with occurrence and
duplicate_of (null except duplicate-two). `materialize_alert(spec, epoch_ns)`
renders the frozen template at actual UTC microsecond floor, applying only the
predeclared -/+600s control. Duplicate bytes must be copied, not regenerated.
These are generation controls, never the measured input denominator.

`evaluate_fresh_source_case(artifacts, *, expected)` accepts exactly48 original
byte-or-null values and exactly48 external SHA256-or-null pins. Null/null is
missing, not empty. Ignore stored evaluation.json as authority. Enforce original
per-file limits and the new128KiB/64KiB/4MiB256row limits. Verify protocol and
recipe SHA256 of canonical JSON PLUS LF. Require exact objects/types/canonical
frames and bounded parsing; each failed leg withholds only dependent facts.

Output fields exactly schema_version,case_id,status,raw_sha256,pins,reasons,
finite,input_manifest,load,intake,handler_facts,callback_facts,scope_facts,
observer,authority_flags. Schema edge-fresh-source-analysis/v1; status withheld,
bound_fresh_controls or bound_interrupted_prefix. These are scoped evidence
statuses, never whole safety/performance acceptance. Observer remains null in
this core; the lab separately recomputes original identity/completion/fault/clock
evidence and requires both gates. Every authority flag remains false.

Reuse the generic finite/close checks only via explicit protocol/cases/fresh
analysis selector. Never relabel this as an old623 case. Reconstruct each actual
EVE byte from the frozen static lines and prospectively ruled timestamp receipts,
then compare independent held-FD snapshots, actual writer receipts, Source spans
and signed events. A dynamic actual hash must never be labelled pre-known.
Load and intake retain original actual shared writer/time/identity checks,
full>=9s/warmup>=3s/measurement>=6s, exact integer2% rate bounds and98% native
examined nonalert floor. Native intake is not callback coverage. Source closure
must verify separately even when the observer was killed.

Root observations bind exact Source end-offset/prefixSHA and authenticated
checkpoint to the actual event/ingress span. Reconstruct the unwrapped canonical
event+LF from the already signature-verified Source. Handler intent/return must
match this event, exact previous/candidate Source positions, actual original
live_floor and supplied_now. Compare freshness using those ORIGINAL arguments
and the explicit100ms context, not a fitted/replaced epoch. Match each callback
to the actual old CallRecording event sequence, full event, supplied epoch,
original False return and actual six-field activity value. Same SID/trace/hash
does not alias two positions. No APPLIED or execution-dedup claim.

Validate the original observer journal chain and cursor missed flags against
the authenticated Source prefix. Protected witness assertions must match
journal sequence/head/size/hash/object within the measured original journal,
not a post-window audit suffix. Prove the original recovery input_ready fence
and first original completed sample before writer start. Actual live_floor comes
only from handler arguments, not a helper-invented startup timestamp.

Input-call records are separately hashchained by SHA256 of FULL prior row+LF;
old clock-call and journal rows use their original unsigned-row hash conventions.
Retain verified complete prefixes and partial tails without inventing a footer.
No callback absence proves filtering unless its original handler returned,
cursor/missed record and witness are verified. A returned callback whose cursor
is not protected remains a returned-call fact, not completed durable intake.
Intent/return/cursor/witness/exit are distinct. Unmatched/orphan or malformed
rows never erase independently verified Source/earlier callback facts.

Controls require7 completed handlers,5 actual False callbacks with activity,
2 durable stale/future filters, exact repeated byte pair at separate positions,
normal input-recorder footer. Interrupted requires the first completed callback
prefix and durable cursor/witness before actual kill; later callbacks are null/
unknown and observation_complete false, never zero/backfilled. Clock is gated
by the separate unchanged5ms original oracle; the incomplete clock stays null.

Tests include full positive synthetic TEST-key records and every missing/pin/
session/span/event/epoch/cursor/witness mismatch, same-SID swaps, exact duplicate
positions, partial/intent/return fragments, signed-wire replay and belowfloor
inputs. Synthetic tests are distinct from mandatory real-Linux original capture.
