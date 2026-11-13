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
