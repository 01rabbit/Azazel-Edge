# Prospective ingress shutdown accounting — Edge #400/#393

Frozen before implementation, base b41d2235. The prior 468-line SO04 deficit is
compatible with an omitted admission-only final interval, but its historical cause
is NOT proven. This changes prospective evidence production/collection only; never
reclassify or repair prior Source/audits/results. Preserve 98% examined tolerance,
1.2x overload, quota/rate/pacing/poll/sample/warmup/duration/decision logic exactly.

## Producer boundary and finite observations

IngressReader owns actual in-memory counters. Keep periodic summary policy and
all reading/admission/shedding/offset/alert/decision/provider behavior unchanged.
At shutdown ONLY, pending actual examined/admitted work must produce one existing
bounded ingress_shed-schema summary even when no shedding occurred. Zero shedding
then means the tracked counter, never inferred absence/missing input. Preserve
existing reset/oversized/backlog summaries and all counts. Empty intervals emit
nothing; already emitted counters are not duplicated; repeated shutdown and later
audit calls cannot emit again. At most ONE additional shed/accounting row versus
old behavior, no periodic chatter or new unbounded queue. Existing append/fsync/
rotation/cap and Source-budget failure handling stays fail-closed; a summary return
or graceful exit does not alone prove file persistence. No new authority.

## Collector / validator boundary

For current SO11-owned Core runs (SO03/SO04-start/SO07), retain the original
pre-stop audit snapshot separately. Stop and join the existing load writer before
Core shutdown, retain exact offered window/written counts/error, then request a
bounded graceful Core stop. Capture actual exit/forced-kill/error facts; only after
confirmed graceful exit0 acquire a NEW strict bounded stable original audit read.
A read before exit cannot become final through a flag or caller assertion.
SO03's standalone harness may expose an optional inert after-Core callback; absent
callback preserves its ordinary API/behavior. The SO11 collector uses that callback
within the original work-directory lifetime, not after deletion.

New fresh SO11 accounting carries an explicit v1 audit_finalization profile with
actual writer-join, stop/exit/read ordering and audit file/prefix integrity facts.
The validator recomputes required gates from this metadata, retained snapshots and
counts; missing/wrong-typed/false/unknown metadata never implies normal completion.
Old reports without this profile remain unfinalized under the new gate; do not
silently migrate them or rewrite published bytes. Existing observed positives and
pre-stop evidence remain available even when new finalization fails.

Final read must NOT use the old tolerant parser that drops missing/bad lines.
Missing/unsafe/replaced/truncated/rotated files, partial UTF8/JSON, unknown/malformed
records, append/write errors, failed writer join, early/nonzero exit, timeout/forced
kill or unavailable post-exit proof remain failed/unknown. No original rows or
counters are synthesized, appended by the harness, merged from different files or
filled to reach 98%. Require stable original prefix/snapshot and strict row/count
consistency. Error evidence must survive temp-directory cleanup in returned data.

Root/kernel/process/measurement harness remain external trust premises. Exit/status
and filesystem controls are local software evidence, not independent production
attestation, physical delivery, causal benefit or overall safety qualification.
No network/capability/user/service/key/policy/config/installer/security/systemd or
production changes. No auto-resume; offline operation remains possible.

## Frozen test data and acceptance

Rust deterministic finite files and controlled clocks: admission-only final work;
pressure summary then quiet accepted tail; mixed work; already summarised/empty
interval; repeated flush/later audit; actual counts sum without duplicate; periodic
admission-only behavior unchanged. Audit-file integration checks new row, failure
on existing write/rotation limits and bounded one-row growth, no decision/read parity
change. Existing historical archived fixtures are untouched.

Python synthetic process/reader controls: successful writer join -> graceful0 ->
strict final read ordering; stop timeout/kill/nonzero/early exit, writer alive/error,
write-error stderr, missing/rotated/replaced/truncated/malformed/partial audit;
retain pre-stop data and no invented counters; typed/missing final metadata refused
by both build and record revalidation. Explicit 9800/10000 accepted and9799/10000
rejected at the original 98% boundary; original1.2x factor/rate/quota unchanged.

Fresh real-Core SO11 tests under unchanged100%/120% profiles must show shutdown
rows/read ordering and pass unchanged load checks; SO03/SO07 receive the same strict
exit/read gate. Resource acceptance is software-bounded only: at most one additional
accounting row per shutdown, same cap/rotation and Source limits. Pi CPU/storage
wear/physical durability remain unmeasured. Independent review, targeted Rust and
Python regressions, final-head complete CI and exact base/head/tree are required
before conditional merge. Any gate failure is recorded, never skipped/retried until
pass or relaxed. Update existing #400/#393; create no duplicate issue.

## Frozen collector profile details

Use a shared strict helper ingress_final_audit.py and optional SO03 after_core
callback (defaultNone), invoked only after its owned Core stop inside work lifetime.
New quota_load fields:
- ingress_audit_pre_stop: original records/records_read/raw_sha256/raw_bytes/
  file_identity/read_started_ns/read_ended_ns/rotated/error.
- ingress_audit_finalization: profile=so11-post-exit-ingress/v1,writer_joined,
  stop={requested,forced,returncode,exit_confirmed,error,requested_ns,exited_ns},
  read_started_ns/read_ended_ns/raw_sha256/raw_bytes/pre_stop_prefix_preserved/error.
The exact profile/types, ordered writer/stop/exit/read facts, raw row/count/prefix
consistency and errors are mandatory in fresh SO11 build AND independent record
revalidation. Legacy missing metadata is not silently finalized. Preserve original
load_end core-alive fact; stopping afterward cannot turn it into an early-exit pass.

Final original audit can contain zero or one ingress_shed shutdown row and an
existing distinct alert-backlog shutdown row. If no counters remained after a
periodic summary, empty shutdown still emits none: finalization proves post-exit
collection ordering/bytes, NOT complete coverage or zero unseen pending work.
Absent shutdown row alone must never fabricate zero counters or defeat the
unchanged98% test. If shutdown rows exist, they form a terminal suffix with no
repeated kind or subsequent periodic row. Missing final read/exit/error/prefix
proof remains unknown. This avoids requiring a fabricated empty marker and keeps
periodic/empty behavior unchanged. All actual emitted counters remain additive
without duplicated earlier snapshots.

### Explicit join clock and pre-stop absence

Also record actual writer_joined_ns (not the writer window-end), and require
window_end <=writer_joined_ns <=pre-stop read-start/read-end <=stop.requested_ns
<=stop.exited_ns <=final read-start/read-end. Unknown/missing/boolean-as-integer
clock facts cannot satisfy imported record revalidation.

Pre-stop snapshot disposition distinguishes present / observed_absent / unavailable.
An actual lstat FileNotFound BEFORE shutdown is permitted as observed_absent:
records/records_read/raw_sha256/raw_bytes/file_identity are null, not fabricated
zero counters or a synthetic empty file. Other pre-stop errors remain unavailable.
FINAL file absence always fails. For an observed-absent pre-state require a genuine
new final file and explicit final pre_stop_binding=created_after_observed_absence;
for present pre-state require same-file exact original prefix and
pre_stop_binding=same_file_prefix. The general prefix-preserved gate means this
explicit binding was checked, not that a missing file was read as empty evidence.
This supports the first admission-only summary creating its audit at shutdown
without claiming missing traffic or unknown counters are zero.

### Original bytes in imported records

Both present pre-stop metadata and finalization carry bounded original raw_utf8,
strict UTF-8 roundtripped directly from the original file bytes. Observed-absent
pre-stop raw_utf8 is null. Revalidation MUST re-encode, enforce16MiB per snapshot
and32MiB total raw budget, recompute actual SHA/size, strictly parse and typed-
compare the retained records/counts, then check exact original byte prefix (or
explicit observed-absence creation binding). Never infer original bytes through
canonical reserialization, or accept an unrelated well-shaped hash beside rows.
Failed/unattempted final audit fields remain null, not []/0/false masquerading as
measurement; preserve pre-stop data and failed final-attempt diagnostics separately.

This adds bounded evidence serialization/memory after load and exit, not on the
control path. Row/line/depth bounds still apply. Pi memory/CPU/storage-wear and
physical persistence are unmeasured; no resource acceptance is inferred from the
bounds or host tests. Existing record consumers cannot silently discard this proof
and retain fresh finalized status.

## Implementation validation (2026-11-13)

Targeted Python regressions: 140 passed (95 final-audit negatives/lifecycle and
45 SO11); Linux SO03/runtime regressions: 130 passed. Host Rust: 202 passed with
three existing Linux-only tests ignored on macOS; Linux CI must exercise its
applicable tests. Two actual host-Core file tests passed, covering the quiet final
tail and unsafe audit-path write refusal. Synthetic parser tests are separate
from these actual process/file observations.

A fresh offline Linux run used an unprivileged UID, no capabilities, no network,
and read-only source/binary mounts. All six small-profile role/level combinations
passed unchanged accounting checks after confirmed graceful exit0. Examined/written
non-alert counts were SO03 8596/8596 and10348/10348, SO04-start17588/17588
and21128/21128, SO0712440/12440 and14760/14760 at100% and120% respectively.
Nominal runs observed pre-stop absence followed by a genuine final shutdown row;
overload runs had already reported all counters and emitted no fake empty marker.
Original full JSONL: 158310 bytes, SHA256
`fe1a3842b46a8486c313ff925b79e1d001f3ab564672d9f0a8f10106ef4f82f9`.

Limitations retained: an earlier Linux run's full export failed (only its compact
result survived); the distinct successful run above retained complete evidence.
An earlier macOS matrix had unavailable SO04/SO07 starts, which remain failed/
unknown, not zero; a minimal host regression environment lacked PyYAML. The
complete-dependency Linux regression above passed. No historical 468-line deficit
is repaired or causally explained. Small profiles do not establish full objective,
Pi/HIL, durability, resource, production, independent kernel restoration, or
whole-system safety acceptance. Final-head CI and independent review remain merge
gates.

## Additional frozen condition: actual writer-start warm-up boundary

Full final-head SO11 CI run43344219754 failed the unchanged offered-load gate:
the first SO03 nominal sample began593989ns before actual writer-start+3000ms.
The parent previously waited3000ms immediately after Thread.start(), which can
precede the writer thread recording its actual start. All six final-audit
consistency gates passed; this failure must remain recorded, not retried away.

Before further implementation, freeze this correction: keep WARMUP_MS=3000,
98%,1.2x, writer pacing/rate, sample count and sample intervals unchanged. Begin
sampling only after the actual writer-start timestamp plus the same3000ms on
CLOCK_MONOTONIC. Startup/readiness waiting must be bounded; missing readiness,
early writer exit, writer error or timeout cannot satisfy the offered-load gate.
Do not move or widen recorded windows, change sample timestamps, discard the
early sample, or repair this failed record. Deterministic tests must cover delayed
writer startup, exact warm-up boundary and missing/failed readiness; actual new
final-head CI and independent review are required after the correction.

Correction validation: 158 affected synthetic tests passed (the original140 plus
18 delayed-start/readiness/boundary tests); three real-Core cases were deliberately
not repeated locally because new final-head CI must exercise actual processes.
Independent review of the correction is clean. The small Linux six-case evidence
above belongs to the preceding implementation before this warm-up correction;
its bytes remain immutable and are not represented as a new-head execution.

## Additional frozen integration expectation: existing forwarding/spool path

Original PR CI43344116074 completed with21420 Python passes and five failures:
one old test expected no row after100 admitted lines; four spool tests assumed
all forwarded records were normalized decisions. Existing shutdown forwarding
also forwards ingress audit rows, so the new single accounting row contributes
one generic forwarded/spooled/lost/unconfirmed record. It is not a new decision.

Freeze before adapting those tests: preserve the existing forwarding, spool,
capacity, drop and durability behavior. An empty input must still emit nothing;
actual admission-only input must emit exactly one truthful shutdown summary.
Require exact normalized-decision identities/counts and exactly one separate
actual ingress summary, with all-record accounting conserving both. Rotation and
wedged-delivery tests must count both types without tolerances or permitting any
decision loss to disappear. Generic legacy spool counters/stderr wording do not
prove decision-only counts; an extra audit record cannot substitute for a missing
decision. No production change is authorized or needed for these test expectations.
Keep original failures and require new final-head full CI after test adaptation.

The existing forward-stats/v1 control heartbeat bypasses undelivered event
accounting. Tests validate its exact closed shape and integer types separately;
it is forbidden in the spool and cannot substitute for any decision/audit event.
Unknown records still fail. Targeted offline Linux validation initially passed
eight cases and exposed a test classifier omission for this heartbeat; the failed
case passed after that test-only correction. Both attempts are retained, with no
runtime change. All nine cases are covered; no unchanged successful cases were
repeated locally.

The warm-up-corrected production head10eec8bf also completed full SO11 CI's six
conditions (200/200 SO03,150/150 SO04-start,110/110 SO07 at each load level), with
no unmet prerequisites and graceful exit0 throughout. Record SHA256
`7f0ff9ea2691183438b52bdb2318702c1e2c3d52ca03e8ba5d2c9eab08b20de0`.
The verdict remains not_measurable for declared provisional/hardware gaps.
Test-only integration adaptation still requires final-head full CI before merge.
