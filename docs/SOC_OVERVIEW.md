# Optional read-only SOC overview

Refs #548. The `SOC overview layout` button is an opt-in presentation on the
existing overview tier. Toggling it again restores the classic console; reload
starts with the classic layout. Existing control, authentication, action routes,
polling cadence and atomic dashboard bundle are unchanged. No external assets,
network clients, model, additional polling or activation are introduced.

The four cards describe the current snapshot, not historical incident totals.
The priority count comes from the server count and can exceed the bounded list.
Rows show at most 24 of the retained queue items (100 per band); filters preserve
the selected evidence while it remains retained. Removed selections are explicit.
Only `decision_trace_id` can associate an alert to the latest decision; alert
`trace_id`, SID, source IP and temporal proximity cannot establish that join.
A displayed decision is never an execution receipt. Dry run is shown only for
a bound decision with explicit dry-run metadata; all other execution is unverified.

The 1/6/24-hour selector filters the **retained** trend samples (at most 60),
not a promise of that much history. The processing-queue metric is not attack
volume. Stale samples and gaps greater than 60 seconds are not connected or
filled with zero. Endpoints, sample count and scale are visible. Missing data,
missing health metadata, stale snapshots and failed refresh are separate states.
A local expiry timer also ages a snapshot when updates stop; it makes no request.

English and Japanese labels, semantic tables, keyboard controls, explicit focus
and text-only untrusted values are included. Software tests and browser checks
with synthetic fixtures cover display behavior; screenshots do not prove human
usefulness, real operator task speed, target resource budgets or field support.
The randomized task study, real retained-history measurements and final rollout
gates in #548 remain open. The optional view is removable without affecting Edge
arbitration or enforcement.
