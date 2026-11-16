# Timing and observer cost at the declared 120% ingress load

Tracking #400/#393. Base: `523ec792fa596742d852d00908e827cde2815e05`
(#609). This prospective contract and the protocol fixture are committed before
implementation or new collection. Historical reports, failed trials and clock
refusals remain immutable.

## Existing conditions and trust boundary

Reuse the declared `core_eve_reader` non-alert quota, not an adaptive throughput
calibration: 2,500 lines/s × **1.2 = 3,000 lines/s**. The existing SO11 mix is
flow/dns/stats/http, 750 lines/s each, approximately 600 bytes per line. Retain
SO11's existing 2% per-class offered-rate tolerance and actual 3,000ms warmup.
The **98%** floor is examined non-alert accounting divided by actual written
non-alert lines; it is not alert success rate or statistical confidence. Reuse
`quota_load_problems`, its strict post-exit audit checks and its unchanged
`EXAMINED_TOLERANCE`. Exactly 9,800/10,000 passes that floor, 9,799 does not.

The **5,000,000ns** gate remains the original `qualify_clock`, using original
supplied epochs, whole callback brackets, boot identity and full-run anchor
enclosure. Short phase bodies cannot replace it. Missing clock closure, overflow,
loss or invalid evidence withholds qualification; nothing is shifted or fitted.

Use only fresh v3 unconfined cost-lab registrations already used by #609.
Refuse any declared native/capture/AppArmor profile; never remove a profile or
fall back from confinement. Root bootstrap/controller, host/kernel, code and
known test keys are explicit lab premises, not independent production custody.
Keep producer/observer UIDs, groups, capabilities, NNP, private FD, registration,
sealed native image, Source verification and witness paths unchanged. Root
witness shares the controller process; its process costs remain mixed.

No production deployment, services, production keys, grants, new capabilities,
accounts, connection permissions, kernel probes, traffic or enforcement. No
changes under installer/security/systemd. The workload is an isolated EVE file
writer, not live network traffic. Enforcement/high-impact actions stay disabled,
dry-run stays enabled, and the objective policy remains empty.

## Frozen arms, load window and lifecycle

Run six fresh scopes once in fixed order: original_off, instrumented_off,
original_on, instrumented_on, original_faulted, instrumented_faulted. Reuse the
original #609 launcher, observer and phase helpers with scoped module bindings;
do not patch shared stdlib modules or alter product code. Keep native/controller/
observer/sample polling at 10/20/50/50ms. All arms keep signer and witness active;
this is not an unsigned-core comparison.

Start the existing SO11 `QuotaLoad` only after the real core and, where present,
observer are ready. Wait from the writer's actual ready/start timestamp for the
existing 3,000ms warmup. Offer load for at least 6 seconds from that actual start,
then request stop and join within 10 seconds. Do not shorten the observed window
to improve rate. Preserve actual start/end, successful/error status, per-class
counts and actual bytes. Writer errors, unjoined threads, underdelivery, malformed
or interleaved input, early core exit or lost input identity invalidate the load.
Recount the retained original EVE bytes separately; erroring attempted counts
cannot stand in for completed writes. Bound retained EVE at 16MiB/32,768 rows.

After warmup, deliver the same three original marker alert bytes/SIDs in their
original order and wait through the unchanged native/signed/cursor checks. Keep
the writer active through its minimum window even if those markers finish sooner.
The fixed marker recipe and semantic projection match across all six arms;
actual background counts/file hashes may differ with scheduling and must be
reported, not relabeled byte-identical. Preserve marker start/end timestamps
within actual warmup/end boundaries. No new event timestamp or objective window
is created to manufacture an observation.

Faulted mode keeps the original SIGKILL after the first alert's three cursors;
remaining two marker decisions must still reach native/signed records and remain
unprocessed by the observer. On mode remains alive with five cursors through
the load, then receives its original SIGTERM. Do not delay kill to finish a span,
add a signal handler or invent a footer. The narrow #609 fault-prefix functional
exception is unchanged; other missing/corrupt phase data remains incomplete.

After writer join, retain the pre-stop original audit separately. Allow the
existing one-audit-interval plus 0.5s drain, then require bounded graceful launcher
exit 0 and native-child disappearance before collecting final original audit.
Use #600 `FinalAudit` and stable bounded file/prefix/rotation/error checks. A
forced kill, unknown native exit, missing post-exit proof or unverifiable final
audit remains failed/unknown. Never synthesize a terminal summary or counters.
Verify authenticated signed Source closure and exact native/signed marker parity.
Cleanup all owned processes; preserve every failed/partial scope and its originals.

## Prospective clock and phase recording

Keep phase trace bounds at 4,096 rows/4MiB per role and nesting depth 16.
Six seconds at 50ms polling is roughly 120 loops, with background non-alerts
producing no signed frames. This is a bounded pilot, not a guarantee against
overflow: retain valid prefixes and report overflow/unknown without increasing
bounds, dropping slow rows, reducing sampling or rerunning unchanged for success.

Add an explicit opt-in v2 TEST bootstrap configuration for the existing worker;
v1 configuration behavior stays unchanged and rejects v2-only fields. Pin all
staged clock helper bytes before launch under the same Root-readonly bootstrap.
The observer records original sample/event/finalize callbacks through the
existing `record_collector`, with its unchanged 900-row/4MiB limit, actual
supplied epochs and before/after anchors. No extra callback is made. Preserve
actual observer start context/anchor, controller anchors and common boot/domain
observations. Write an observer end anchor only after a genuine normal return.
Clock-sidecar failure invalidates this instrumented observer trial; native
defense/source operation remains separate. Preserve earlier facts and originals.

The current v3 CLI normally stops by SIGTERM/SIGKILL and provides no normal end
anchor. Therefore this profile's full 5ms qualification is expected to remain
**withheld** if that evidence is absent, even when individual callback diagnostics
are available. Do not substitute a last callback or a controller anchor for the
missing observer end. No new stop/terminal protocol or v4/confinement migration
is authorized by this slice. No active-window finalization is exercised.

## Reports, controls and acceptance

Separate offered-load validity, attained written rate, examined coverage,
shedding/alert checks, original 5ms qualification, phase-prefix coverage, process
cost and functional trial status. Keep original reports and actual raw bytes;
valid earlier facts survive later failure. Missing counters/times are null,
never zero. Receiver waits include idle blocking; controller waits include
polling. Inclusive spans overlap; wall-minus-thread CPU does not identify I/O
or scheduling cause. Instrumented-original differences include trace work and
fixed sequential scheduling variation, not causal cost estimates. Write-loop
timing is not total tracing cost, physical durability or SD wear.

SYNTHETIC unit controls cover exact rate/window/type boundaries; requested but
underdelivered load; missing classes; incomplete writer/stop/audit; 98% edges;
alert omission/duplicate/reorder; malformed/rotated/truncated audit; wrong boot/
clock domain; missing clock end; original over-5ms refusals; trace overflow;
phase failure; unchanged v1 rejection/behavior; strict profile refusal and
immutable published reports. Tests must not manufacture active finalization.

After independent precollection review, run one bounded real offline Linux
six-arm pilot. A mandatory CI path must execute the real test, never count a
skip as a pass, retain public allowlisted receipts and expose withheld gates.
Software tests may pass by correctly classifying missing qualification; the
measurement verdict must remain withheld. Full final-head CI, independent
code/artifact replay and exact base/head/test-merge/tree checks precede merge.
Update existing #400/#393 only. No duplicate issue, history repair or favorable
retry substitution. Pi/HIL, provisional quota acceptance, production, physical
durability, causal benefit and whole-system safety remain outside this pilot.
