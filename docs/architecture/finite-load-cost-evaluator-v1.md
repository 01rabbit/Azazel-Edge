# Finite load evaluator interface, version 1

Freeze before dependent implementation. `materialize_corpus()` is a pure
deterministic function returning `(raw_bytes, manifest)` using the pinned
finite-load-cost protocol's exact canonical recipe. The manifest has exactly
schema_version (`edge-finite-load-corpus/v1`), protocol_sha256, sha256, bytes,
lf_records, nonalert_records, per_class and markers. Per-class keys are exactly
flow/dns/stats/http. Markers are ordered objects with sid, after_nonalert,
start_offset, end_offset and raw_sha256. Manifest hashes are intended control
pins, never the actual measured denominator. No runtime entropy is permitted.

`evaluate_finite_load_cost_case(artifacts, *, expected)` accepts exactly the
original 32 finite-ingress files and the twelve extras in the frozen lab
interface. Each value is immutable original bytes or null. Expected has exactly
the same keys, each SHA-256 or null. A null/null pair means missing, not an empty
file. Stored evaluation.json is diagnostic only and never an input verdict.
Every other nonnull pin must match, and facts requiring an invalid file are
withheld. Unrelated verified facts are retained. Existing Source, witness,
private-pipe, actor, manager, raw input, span and EOF checks run via the new
explicit load profile; the old public evaluators and old output shapes persist.

Output exact top-level fields: schema_version (`edge-finite-load-analysis/v1`),
case_id, status, pins, raw_sha256, reasons, finite, corpus, load, intake,
native_cost, receiver_cost, observer and authority_flags. Each fact object has
its own status and reasons. Overall status is `withheld` until all necessary
actual data are verified; it is not a safety/production or superiority verdict.
Observer verification is separate in the lab analysis, directly re-reading raw
recordings and pinned Root identity/custody; a stored pass is not trusted.
The core evaluator leaves observer null rather than synthesize a clock result.

Intake reports examined_nonalert, written_nonalert, percent and status. A
verified committed prefix can establish a measured below-98-percent result;
missing counters, raw mismatch, unknown examined markers or bad binding cannot
establish a numerator. Determine examined alert population from the verified
raw committed prefix, requiring it agrees with actual signed/admitted markers;
never subtract all three planned markers from an incomplete prefix.

Load uses actual bound writer receipt, raw corpus equality and real monotonic
brackets. Check whole and measurement intervals and each class against 3000/s
and 750/s within 2 percent, warmup >=3s, measurement >=6s, whole >=9s. A complete
write count without matching raw bytes or writer FD identity is insufficient.
Failed conditions are adverse/withheld and do not cause a recollection.

Cost objects are the original validated runtime aggregates, not normalized
substitutes. Bind them to each authenticated close receipt and preserve null
unused phases and sticky incompleteness. They are scoped totals, not additive
critical-path latency, causal attribution or a 5ms clock substitute.

`evaluate_finite_load_cost_comparison(cases)` takes the ordered three original
case analyses (OFF/ON/FAULTED). It reports schema_version
`edge-finite-load-comparison/v1`, status, reasons, cases, differences and
authority_flags. Differences has exactly ON-minus-OFF and FAULTED-minus-OFF
entries, each with case_id, status, reasons, native_cost and receiver_cost.
Only equal verified actual corpora, qualified load/intake, complete finite
input and complete valid phase costs permit a descriptive delta. Each role
maps original phase names to null (unavailable in either arm), or signed
differences of count/wall/process CPU/thread CPU/maximum wall. These are
sequential observed differences, not a causal estimate; overlapping phases
remain separate. Any missing gate withholds the affected comparison.
It requires all actual raw corpus hashes/populations equal, load and 98-percent
gates verified, and finite completion separately verified. Observer OFF and
FAULTED remain unqualified for a complete observer clock; therefore this three
arm pilot never silently opens full performance/safety/comparison authority.
It may expose measured costs and descriptive differences with these blockers.

Synthetic negatives must cover missing/bad pins, changed corpus, partial native
prefix, missing End, wrong session, absent phase/CPU, counter overflow, wrong
rate/duration and below-98-percent. ActualLinux is a separate required path;
synthetic fixture success is never reported as Linux measurement.
