# Real Source close connector: bounded execution plan

This is an additive implementation slice under Edge #400/#393. The original
24-hour clock is not restarted: T0 is 2026-11-16 13:55:50 UTC, feature freeze is
2026-11-17 09:55:50 UTC, and the hard deadline is 2026-11-17 13:55:50 UTC.
This slice started at 2026-11-17 04:44:28 UTC from main
`e94704e2973d54a833acc99b6454c8b9bd99970d`.

1. Before implementation or collection, commit the trust boundary, closed wire
   contract, fixed three-case protocol, positive/negative acceptance and unknowns.
2. In parallel, implement the read-only original Source connector and its
   adversarial unit tests, and the isolated real-Linux three-role Source/witness
   harness with a separate Source-only reader (existing producer, witness and
   cursor-observer roles remain distinct). The integration lead owns CI and
   provenance. The independent reviewer implements none of these changes.
3. Commit the reviewed candidate before the first offline Linux collection.
   Preserve every assigned case and failure. Reuse unchanged originals for
   read-only replay; do not recollect to obtain a favorable result.
4. Require targeted regressions, independent original-byte replay and review,
   a concrete PR, complete final-head CI and exact base/head/test-merge/tree
   agreement before merging. Recheck the merged tree and existing main CI.
5. Update the existing open issues with the actual scope, unknown conditions,
   evidence and gates. Delete only an exactly verified merged branch.

The three existing specialist agents are reused without nested agents or model
changes. Share contract, diff, test summaries and evidence paths instead of
repeated full-source reads. New tests or collection require a change, failure or
unresolved condition. At feature freeze stop adding functionality; at the hard
deadline preserve pending candidates and report remaining gates without merging.

The existing 5 ms, 98% and 1.2x load requirements remain unchanged and are not
qualified by these synthetic-payload Source-mechanics trials. No production
activation, deployment, keys, new capabilities or protected installer/security/
systemd changes are authorized. Old evaluations and published originals remain
unchanged. Missing observations stay unknown; no backfill is permitted.
