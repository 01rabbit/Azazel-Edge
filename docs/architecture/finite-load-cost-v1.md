# Finite input load and observation cost, version 1

Prospective freeze. Base: PR #622, revision
`54be48be21495ddeea54affb702ebd55dc1256db`. This document and the adjacent
machine protocol must be committed before implementation or collection.

## Question and boundaries

Compare observer OFF, ON and FAULTED against the same retained finite EVE byte
range at 3,000 non-alert lines/second (1.2 times the existing 2,500 baseline).
This is a sequential virtual-Linux pilot, not a causal or scientific superiority
claim. All three arms retain the native, signer and witness roles. OFF disables
only the observer. ON requests genuine normal observer completion. FAULTED kills
the independently identified observer after the first authenticated marker; it
does not kill the native or signer and does not invent an observer end.

Reuse the existing native v4 registration, named enforcing AppArmor profiles,
UIDs, capability masks, private receipt pipes, read-only Source path and Root
custody. No profile, service authority, installer, security or production change
is permitted. Old profiled-registration refusals and legacy evaluators remain
unchanged. Only explicit new versioned entry points select the new protocol.

Root controls the isolated writer, process lifecycle and immutable public
snapshots. The observer reads authenticated Source and owns its existing journal
directory. Neither a producer claim nor a callback count is input evidence.
Known lab keys establish parser/signature behavior, not operational independence.

## Fixed input and allocation

Order is OFF, ON, FAULTED, once each, seed 0, without adaptive retries. The
canonical corpus has 27,004 non-alert rows, round-robin flow/dns/stats/http,
6,751 of each, each exactly 600 UTF-8 bytes including LF. Rows contain their
zero-based load_index and deterministic padding. Insert alert markers
90232001/90232002/90232003 after 9,000/18,000/27,004 non-alert rows respectively.
Use the fixed timestamp `2026-01-01T00:00:00Z`. Publish the exact corpus SHA-256,
size, marker byte spans and structural manifest before arm one; never alter it
between arms. Source sessions/signatures legitimately differ; compare retained
raw input bytes and bound marker spans, not Source wire equality.

These stale markers synchronize native and authenticated cursor work. They do
not establish fresh observe_event activity, APPLIED execution or a nonempty
defense observation window. Those costs remain unmeasured when absent. Do not
change admission timestamps or the policy horizon to manufacture such activity.

Pace actual writes at 3,000 non-alert rows/second, 750/class/second. Retain actual
write timing, byte counts, errors, fsync and join. Require the existing 2 percent
rate tolerance, at least 3 seconds warmup and 6 seconds offered measurement.
All final native counters cover the whole finite session, including warmup;
never subtract planned warmup from actual lifetime counters. Retain initial,
after-writer, held-final and path-final snapshots within #622's unchanged bounds.

## Separate acceptance and unknown conditions

1. Input equality: retained raw hashes, full LF populations and actual writer
   receipts must match the prospectively pinned corpus for every arm.
2. Load: actual timing and actual per-class populations meet the fixed rate and
   durations. Intended pacing is not an observed rate.
3. Intake floor: actual examined non-alert records / actual written non-alert
   records >= 98 percent, subtracting only independently bound examined marker
   alerts. Admitted records and Source decisions are not the numerator.
4. Finite completion: #622's original identity, committed prefix, raw hash,
   Source span, End, witness, readback, exclusion and loss checks apply through
   an explicit profile. A 98 percent floor does not imply full coverage.
5. Clock: reuse the unchanged qualify_clock 5,000,000 ns budget, supplied epochs
   and entire actual callback brackets. Require genuine ON API return/resource
   closure, actual end anchors and exit zero, plus independently bound boot and
   time domain. OFF has no observer clock result. Killed/incomplete/missing or
   mismatched evidence is withheld. Short processing time is not this clock gate.
6. Costs: report actual bounded phase wall/process/thread CPU aggregates and
   independently bound process/unit metrics, where available. Inclusive or
   overlapping phases are never added. Process CPU can include other threads.
   Missing CPU/I/O/final snapshots or mixed roles are explicitly unknown/scoped;
   wall minus CPU is not scheduler wait. RUSAGE_CHILDREN cannot measure services
   managed by PID 1. No unobserved per-event linkage is inferred from aggregates.

Registration opts in with AZAZEL_LIVE_ORIGIN_LOAD_COST=v1, requiring existing
ACCOUNTING, CLOSE_RECEIPTS and INGRESS_ACCOUNTING v1. Native close v3 and Root
custody v3, receiver close v2 carry bounded aggregates through existing pipes;
native 4,096, receiver report 3,072/stream 4,096 and Root 16,384 byte bounds stay
fixed. Each aggregate identifies its actual operation, count, wall, process CPU,
thread CPU and maximum wall duration. Overflow/clock/publication loss stays
sticky unknown and never interrupts or replays defense. Absent phases are not
measured zeros. No new signer sidecar, hotpath lock, input read or fsync is added.

Observer test records use existing observer/** access, real clocks and unchanged
callbacks. Root independently binds actual PID/start ticks, boot and time
namespace while the actor is alive. This provenance is not a fabricated child
self-read. Missing domain proof withholds qualification. Partial recordings and
already verified Source facts survive later failure; no backfill or repair.

## Tests and final gates

Synthetic tests: equal/mismatched input, wrong pins/session/span, original
tampering, missing End or final counter, partial/overflow cost, missing CPU,
invalid clock/domain, sub-98-percent, wrong load and interrupted observer.
Mandatory real Linux tests: all three actual arms under unchanged profiles and
offline isolation; skip is not pass. Preserve every arm/failure and hash original
artifacts. Independent review rechecks raw facts, not only stored evaluations.
Run relevant regressions, complete final-head CI and compare live base/head/test
merge/tree before conditional normal merge. Preserve old outputs and originals.
Safety acceptance, comparison authority, restart, production, hardware, and
whole-system zero-incident gates remain closed regardless of this pilot.
