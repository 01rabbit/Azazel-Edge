# Service-objective declarations (OF-05, OF-06, SO-04 hostile load, SO-02, SO-05)

Tracking: #414  
Assignment: `01rabbit/Azazel:docs/roadmaps/service-objective-assignments.md` (SO-02, SO-04, SO-05, SO-11, OF-05, OF-06)  
Harnesses: `py/azazel_edge/service_objectives/`

Two rows the assignment gives Edge presume a value that Edge has to declare:
SO-04's rollback *completion* bound ("action-specific", OF-05) and SO-11's
"each declared ingress quota" (OF-06). This page records what Edge declares,
where it lives, and what it is not.

**Nothing here changes a program-plan §8 target.** The SO-04 start bound
(5 s), its sample count (150) and every other target are unchanged.

## OF-05 — per-action rollback completion bound (declared, provisional)

### Where it lives

`config/service_objectives/rollback_completion_bounds.json`
(schema `azazel-edge/rollback-completion-bounds/v1`). The SO-04 harness and the
validator read it through
`py/azazel_edge/service_objectives/declarations.py`. The core never reads it;
no bound in it changes when or how a lease is released.

| Action type | Bound | Status | Hardware class | Basis |
| --- | --- | --- | --- | --- |
| `throttle` | 5000 ms | provisional | container-aarch64, not hardware | 3 runs, 150 samples (150 completed), max observed 2237.5 ms (nominal max 915.7 ms) |
| `isolate` | 5000 ms | provisional | container-aarch64, not hardware | 3 runs, 150 samples (150 completed), max observed 2302.7 ms (nominal max 923.6 ms) |
| `redirect` | 5000 ms | provisional | container-aarch64, not hardware | 3 runs, 150 samples (150 completed), max observed 2339.2 ms (nominal max 980.1 ms) |

Margin rule: twice the maximum observed, rounded up to the next 1000 ms. Half
of each run's leases expire while the harness writes 2000 synthetic EVE alerts
per second into the core's input; that load dominates the maximum.

The runs were taken on main after #439 (monotonic lease deadlines) and #441
(throttle TBF readback from `options`): every lease carried a monotonic deadline
and expired on it (`expiry_clock: monotonic` in every sample), start and end
were both read on `CLOCK_BOOTTIME`, and every rollback of every action type
completed with `rollback_applied_and_absence_verified`.

**The basis is not clean.** `wall_clock_stable_during_run` was unmet in all
three runs: the wall-minus-monotonic drift was −107.0, −121.7 and −113.5 ms
against a 50 ms tolerance (the colima VM's wall clock was adjusted during each
run). The elapsed times do not depend on the wall clock, but no run would count
as evidence. Earlier run sets (before #439, and before #441 when no throttle
rollback completed) are superseded and not used for the bounds.

### How SO-04 cites it

The `rollback_completion` part of the SO-04 record
(`so04_rollback_completion.py`):

- **start** — the start half's own start (`so04_lease_rollback.lease_start`):
  the lease's monotonic deadline (`due_boottime_ns`, `CLOCK_BOOTTIME`), or the
  wall deadline mapped onto `CLOCK_MONOTONIC` for a legacy lease. A test checks
  that both halves give identical starts;
- **end** — the first `rust_release_engine_v1` outcome naming the lease with
  `status: released` and `result: rollback_applied_and_absence_verified`, read on
  the clock the start is on;
- **pass rule** — `every_sample_max_elapsed_per_action`: each sample against the
  bound its action type declares. The part carries the bounds, the declaration
  path and its SHA-256. The validator reloads the file from the tree and rejects
  a record whose bounds or digest differ.
- **never pass on missing** — a sample whose action type declares no bound is a
  violation, and `per_action_completion_bound_declared` is recomputed from the
  file and the samples. The sample rule is 50 per action type, checked per type
  and not only as a total of 150 (the start half has the same check). If an
  action type's bound were removed from the file, the part would be
  `not_measurable` whatever the samples show.
- **provisional is not evidence** — the gap `SO04-COMPLETION-BOUND-PROVISIONAL`
  is mandatory for the part. It stays until a hardware-derived declaration
  replaces the provisional one. `SO04-HOSTILE-LOAD-UNDECLARED` applies too,
  because the sample rule is the same, and is closed the same way as for the
  start half (see "SO-04 hostile-load profile" below). `SO04-LEASE-EXPIRY-ON-WALL-CLOCK` is
  listed under `gaps_closed_by_samples` for this part as for the start half: it
  may be left out only when the validator's own recomputation
  (`so04_monotonic_expiry_observed`) holds for every sample. An unfinished
  sample never satisfies it.

Rollback completes only if there is owned state to roll back, so the harness
installs it before the core starts: one TBF root qdisc per throttle lease on a
dummy interface of its own, and one `inet azazel_edge` rule tagged with the
lease's owner token per isolate and redirect lease. It reads that state back
before the core starts and again afterwards, so the core's "absence verified"
is confirmed from outside (`completion_confirmed_by_readback`). This needs
root, `CAP_NET_ADMIN` and the dummy link type, e.g.
`docker run --cap-add NET_ADMIN`. Without them, or when an `inet azazel_edge`
table already exists (a live node's firewall, which the harness never
touches), nothing is installed and the part is `not_measurable`.

The harness removes only what it verifiably created. The table is made with
`nft create table` (which fails if a table exists, even one that appeared after
the check) and its chains with `create chain`; on failure nothing is touched
and nothing is deleted. An interface is used only if it did not exist just
before the harness added it. On SIGTERM, SIGHUP or SIGINT the core is stopped
and the harness's interfaces and table are removed; an `atexit` hook covers
other interpreter exits.

### Throttle

Before #441 no throttle bound could be declared: the core read the TBF
parameters from the top level of `tc -j qdisc show`, iproute2 puts them under
`options`, and every throttle rollback ended `release_attempt_failed` with
`tc ownership handle exists with unexpected TBF parameters`. #441 fixed the
readback; in the runs above all 150 throttle rollbacks completed, and throttle
is declared by the same rule as the others.

## OF-06 — Core ingress quota (declared, provisional, enforced)

Owner decision on #414 (2026-10-25), as revised in the review of #452: bound
the Core's EVE reader per poll; never shed or rate-limit alerts; hold
non-alert lines to a declared quota and shed the lowest-importance types first
(flow, dns, stats, then other); count what is shed and record it as a
rate-bounded `ingress_shed` summary; never shed silently. This section records
what was built.

### Where it lives

| What | Where |
| --- | --- |
| The bound (enforced) | `rust/azazel-edge-core/src/ingress.rs`, `IngressLimits::DECLARED` (compile-time constants; no environment variable raises or disables them) |
| The declaration | `config/service_objectives/ingress_quota.json` (schema `azazel-edge/ingress-quota/v1`), read by `declarations.load_ingress_quotas()`. The core does not read it; a core unit test fails if it and `IngressLimits::DECLARED` differ, and a pytest checks the same from the Python side. |
| The shed record | `ingress-audit.jsonl` beside the normalized event log (`AZAZEL_NORMALIZED_EVENT_LOG`'s directory): opened with `O_NOFOLLOW`, mode 0600, `fsync` after each record (at most about two a second), rotated to `ingress-audit.jsonl.1` at 16 MiB. Each record is also printed to stdout, or to stderr under `AZAZEL_EVENT_STDOUT=off` (that setting silences per-event output, not audit). If the file cannot be written, the error and the record go to stderr. Its own file, so readers of the normalized log never meet a record of another shape. |
| SO-11 starting point | `py/azazel_edge/service_objectives/so11_ingress_probe.py` |

**The declared quota is a non-alert quota.**

| Limit | Value | Applies to |
| --- | --- | --- |
| `value` (quota) | 2500 lines/s, token bucket of 1500 | non-alert lines |
| `alerts_per_poll` | 1000 | alerts, per poll only (no rate) |
| `examine_per_poll` | 6000 lines | every line, shed ones included |
| `poll_work_limit_ms` | 500 ms | one poll's reading and deciding |
| `max_line_bytes` | 1 MiB | a longer line is skipped to its newline and counted |
| `backlog_bound_bytes` | 8 MiB unread | second-line shedding of non-alerts |
| `alert_backlog_bound_bytes` | 256 MiB unread | record point for `ingress_alert_backlog`; nothing is dropped |

Status `provisional`, hardware class `container-aarch64, not hardware`.

**Basis.** The old reader had no bound, so its sustained decision rate is the
Core's capacity on this path: 200000 pre-written alerts in the SO-04
`eve_flood` line shape, read from the start, release build on main at
`4b5242c`, enforcement off: 5641, 6768 and 7676 lines/s in three runs
(colima, aarch64). The non-alert quota is less than half the minimum, rounded
down to 500 (a non-alert line is parsed but not decided, so it costs no more
than an alert), leaving at least half the capacity for alerts.
`alerts_per_poll` is about 0.13–0.3 s of alert work at the measured per-alert
cost, far below the SO-04 5 s bounds; `poll_work_limit_ms` caps a poll on a
slower host. **Alerts are not throttled below capacity:** with a 60000-alert
backlog, main and this tree decided 6495–6530 and 6502–6524 alerts/s in three
alternating runs in the same container.

### How the reader behaves

Each poll the reader:

1. **Checks the file.** A new inode (rotation by rename) or a file shorter than
   the offset (truncation) restarts at 0; the old file's unread bytes are
   counted (`file_replacements`, `truncation_resets`, `unread_bytes_lost`).
2. **Measures the backlog** (`len − offset`) and picks a backlog shed level: 0
   up to 8 MiB, then one more class per further 8 MiB.
3. **Reads raw bytes up to each newline**, at most `max_line_bytes + 1` at a
   time. Invalid UTF-8 is decoded lossily, so a bad byte never stops the
   reader; a line that does not parse is `unparseable`. A line still being
   written (no newline yet) is left for the next poll. A line longer than
   `max_line_bytes` is skipped up to its newline without being buffered, and
   counted (`oversized_lines_skipped`; `oversized_possible_alerts` when its
   first bytes carry `"event_type":"alert"`).
4. **Admits every alert** it reaches. Alerts are never shed and never draw on
   the bucket.
5. **Admits a non-alert** only if the bucket still holds its class reserve
   plus one token: flow keeps 3/8 of the burst in reserve, dns 2/8, stats 1/8,
   other and unparseable none. Otherwise the line is shed at once
   (`shed_by_reason.non_alert_rate`). Under overload the bucket hovers near
   empty, so flow goes first, then dns, then stats. Past the backlog bound the
   backlog level sheds classes whatever the bucket holds
   (`shed_by_reason.backlog`). Unparseable lines might have been alerts, so
   they are never shed ahead of flow, dns or stats; they share the last rank
   with "other" and are counted under their own key.
6. **Stops** after 1000 alerts, 6000 lines, 500 ms of work, at the end of the
   file, or at a partial line. The offset has moved only past lines it
   handled; everything else is read on the next poll.
7. **Emits audit summaries**, at most one `ingress_shed` and one
   `ingress_alert_backlog` per second, each only when there is something to
   report, with per-class and per-reason counts for the interval and
   cumulative totals (so a lost summary shows as a jump). When the process is
   stopped, the last interval's summaries are written once more
   (`interval_end: "shutdown"`; see below).
8. **Runs the release sweep**, on every iteration (`poll_iteration` in
   `main.rs`; tested with a five-poll flood already in the file). If the poll
   stopped on a budget, the next poll follows without the 200 ms sleep, so a
   flood is read at capacity with a sweep between bounded polls.

**Alerts beyond capacity.** Alerts are never dropped. Beyond capacity they wait
in the EVE file and are read oldest first. The backlog costs disk Suricata
already wrote, not Core memory: the reader holds at most one line (≤ 1 MiB).
Past 256 MiB unread an `ingress_alert_backlog` summary is recorded (once per
second while it lasts, `alerts_shed: 0`) and reading continues. What a
sustained alert flood costs is decision latency, and the summary is what makes
that visible. Dropping alerts to keep latency low would trade a visible delay
for an invisible miss; the owner chose the delay. The one exception is a line
over 1 MiB, which is skipped to bound memory and counted, flagged when it
looks like an alert.

**Rotation.** Detected by inode and by size. A rotated file's unread tail is
not read from the old inode; it is counted as lost. Reading the old file to its
end before switching is not done.

### SO-11 starting point (not a measurement)

`python -m azazel_edge.service_objectives.so11_ingress_probe --core-bin PATH --out FILE`
starts the real core and, for 40 s, writes flow, dns, stats and http records
in equal parts at 120% of the declared quota (3000 lines/s, about 600 bytes
each) together with 1000 alerts/s. It then checks the core's own output:
shedding recorded, no alert shed, every alert decided, flow shed at least as
much as dns and dns at least as much as stats, summaries at most one per
interval. It reports `not_measurable` with gaps, because SO-11's referenced
rows (SO-03, SO-04, SO-07) are not re-run at the quota, the quota is
provisional and container-derived, SO-11 has no specification in `record.py`,
and only one traffic mix is offered.

One container run (colima, aarch64, 2026-10-25): 119997 non-alerts and 39999
alerts written over 40 s; 19318 non-alerts shed, all for the non-alert rate
(14433 flow, 4885 dns, 0 stats, 0 other; the expected excess at 120% is about
20000), none by backlog (peak backlog 0.57 MB); 0 alerts shed and all 39999
decided; 39 `ingress_shed` summaries at least 1.001 s apart.

### SO-04 under the bound

`python -m azazel_edge.service_objectives run --objective SO-04` on this tree
(docker `--cap-add NET_ADMIN`, colima aarch64, `eve_flood` at 2000 alerts/s;
alerts are outside the quota, so nothing was held back), two runs. Start:
150/150 samples each, max 1119.8 ms and 1833.7 ms against the 5 s start
bound, 0 violations. Completion: 150/150 each, max 975.6 / 1458.8 ms
(throttle), 1071.8 / 1360.7 ms (isolate), 1048.2 / 1262.8 ms (redirect)
against the provisional 5000 ms bounds, 0 violations. Wall clock stable in
every part. The record is `not_measurable` for the same gaps as before
(`SO04-HOSTILE-LOAD-UNDECLARED`, `SO04-COMPLETION-BOUND-PROVISIONAL`).

At the time `SO04-HOSTILE-LOAD-UNDECLARED` was left in place: a declared
ingress quota is not a declared hostile-load profile, and the `eve_flood`
phase was a harness-chosen load. The `eve_flood` phase has since been replaced
by the declared profile below.

### Still open

- **Hardware classes.** Only container-aarch64 is measured. Raspberry Pi 5 and
  x86_64 appliance quotas, and the R7 hardware confirmation, are not done.
- **Per peer.** §5 R5 speaks of per-peer quotas; this is one node-wide quota.
- **A full SO-11 harness** re-running SO-03, SO-04 and SO-07 at the quota and
  at 120% of it, with a `record.py` specification.
- **Across restarts.** The next process still starts its cumulative totals at
  zero; the shutdown summary below is the last word of the one before.
- **Hard kills.** SIGKILL, a crash or a power loss still loses the last
  interval; only a stop the process is told about (SIGTERM, SIGINT) writes it.

### Counted at shutdown and readable from the AI socket and the dashboard (Edge#414 SO-11)

Two former items of "Still open" are done. Neither changes what is read, shed
or decided, the quota, or the SO-11 verdict (still `not_measurable`; the quota
is still provisional and container-derived).

- **The last interval at shutdown.** SIGTERM (systemd's stop) and SIGINT set a
  flag; the main loop ends after its current iteration and the reader writes
  whatever the last interval holds, at most one `ingress_shed` and one
  `ingress_alert_backlog`, to the same `ingress-audit.jsonl` and console, in
  the same shape. Every summary now carries `interval_end`:
  `"audit_interval"`, or `"shutdown"` for this one, which closes an interval
  shorter than a second on purpose (the SO-11 probe leaves it out of its
  rate-bound check). An empty last interval writes nothing. The reader
  refuses a second flush and any later summary, so the interval is never
  written twice. The handler sets a flag and nothing else; there is no other
  way to stop or skip anything. The poll interval (`AZAZEL_EVE_POLL_MS`) is
  kept but slept in 50 ms slices with a look at the flag between them, so a
  stop is not held up by a long interval.
- **SO-04 records.** The SO-04 harness reads `ingress-audit.jsonl` after it
  terminates the core. It drains first (every alert decided, then one audit
  interval), so normally nothing is pending and no shutdown line is written;
  the record's numbers are the same as before. When the drain timed out and
  a shutdown line is written, it comes after every load window and is
  attributed to the last phase (profile rule "attribution"): one more
  summary in `ingress_audit`, and that phase's examined and shed counts
  include lines the core really read, which were lost before. The cumulative
  check now closes over it instead of hiding the loss.
- **Read-only copies.** With the AI forward on, the `ingress_shed` object
  (counts, interval end, emit time and the compiled quota; no address, MAC or
  id) is also queued on the AI socket, the shutdown one with a bounded wait
  (2 s) for the forwarder. If the forward queue is full at that moment the
  wait is skipped and the shutdown summary may not reach the AI socket (a
  line that could not be queued is counted in the core's forward drops); it
  is in `ingress-audit.jsonl` and on the console either way. The AI agent keeps the counts of the newest one as
  the `core_ingress_shed` metric in `ai_metrics.json` (never as an event, an
  advisory input or a decision; a malformed or older one is ignored), and
  `/api/dashboard/health` shows them under `ingress_shed`
  (`{"available": false}` until one has arrived). Nothing reads them back as
  a gate.

Checked by unit tests (Rust: a stop in the middle of an interval after a
summary, a stop in the first interval, an empty last interval, a second
flush, counts read after the flush, the sliced sleep; Python: no summary yet
and a summary present), by `tests/test_core_shutdown_ingress_flush_v1.py`
(the release core stopped by SIGTERM, SIGINT and SIGTERM twice with a 10 s
poll interval: exit 0, one shutdown summary, stop within 3 s; and a stop with
nothing pending writes nothing) and by the full suites in
a container (colima, aarch64). This is not a hardware measurement and not an
SO-11 record.

## SO-04 hostile-load profile (declared, derived from OF-06, factors confirmed by the owner)

SO-04's sample rule asks for leases expiring under hostile load. Until OF-06
nothing declared that load, so the harness flooded the core with a load it
chose itself (`eve_flood`, 2000 alerts/s) and kept `SO04-HOSTILE-LOAD-UNDECLARED`.
With the OF-06 quota declared and enforced by the core, and the core named the
enforcement authority (Edge#412), the load can be declared against what the
core enforces.

### Where it lives

`config/service_objectives/hostile_load_profile.json`
(schema `azazel-edge/hostile-load-profile/v1`), read by
`declarations.load_hostile_load_profile()`. The core never reads it; nothing in
it changes how the core reads, sheds or decides. Status `confirmed` (the owner
confirmed the phase factors as they stood on 2026-10-26; see "Owner
confirmation" below), hardware class `container, not hardware`.

**Every rate is derived from `ingress_quota.json`.** The loader re-derives each
phase's rates from the quota file as it stands and refuses the whole profile
(declares no phase) when any differs, when a phase is malformed, or when one of
the three kinds of load below is missing. A change to the quota therefore
invalidates the profile until it is re-derived, and a test checks the core's
default poll interval (200 ms, `AZAZEL_EVE_POLL_MS` in `main.rs`) that the
alert rule uses.

| Phase | Non-alert lines/s | Alerts/s | Malformed | Rule |
| --- | --- | --- | --- | --- |
| `non_alert_flood` | 3000 (flow, dns, stats, http: 750 each) | 1000 | — | 2500 × 1.2; over the quota, so the core must shed |
| `malformed_mix` | 3000 (flow, dns, stats, http, invalid UTF-8: 600 each) | 1000 | 1 oversized line/s of 2 MiB | 2500 × 1.2; oversized = 2 × `max_line_bytes`, at 0.25 × `backlog_bound_bytes` per second |
| `alert_flood` | 0 | 5000 | — | `alerts_per_poll` 1000 per 200 ms poll: the poll cap |
| `backlog_flood` | 30000 (flow, dns, stats, http: 7500 each), one burst per second | 1000 | — | 2500 × 12 (over 10 × the quota); each burst is about 18 MB, more than twice the 8 MiB `backlog_bound_bytes`, so the core's backlog shedding must act | (the last phase, see attribution below)

Alert rate rule: `alert_poll_fill × alerts_per_poll × 1000 / poll_ms`. Other
lines are padded to about 600 bytes (as the SO-11 probe does). Timing:
`warmup_ms` 3000 (the 1500-token bucket empties at 3000 − 2500 = 500 lines/s
net in 3 s, and the loader checks this for every over-quota phase),
`hold_after_ms` 2000, `quiet_gap_ms` 3000 between phases, and
`audit_attribution_slack_ms` 2000 (at least the 1 s audit interval and below the
quiet gap).

**Attribution.** An `ingress_shed` summary belongs to the phase whose window
started last before it was emitted, up to the next phase's window start; the
last phase keeps every later summary. Nothing is written in the quiet gap, so a
core still reading a phase's lines after its window stays accounted to that
phase. The backlog phase must be the last one (the loader checks it): a slow
host can still be reading its backlog well after the window, and as the last
phase that tail is covered by the harness's final drain. The driver writes
alerts last in every chunk, so once the core has decided every alert written
(what the drain waits for) it has read every line.

Until main 3dc2801 a summary belonged to a phase only up to `window +
audit_attribution_slack_ms`. On a GitHub runner the core was still reading the
backlog phase about 2.4 s after its window (55 MB unread at the peak), so the
summary accounting for the last 55000 lines fell outside, and the excess,
computed from every line written, counted lines the core had not yet read
(run 40221768896: 182509 shed against a floor of 196562; with the summary,
233433). The accounting below replaces it (and, after review, fixes `read_s` outside the backlog phase).

**Factors confirmed by the owner.** The factors under `owner_defaults`
were chosen when the profile was written, and the owner confirmed them
unchanged on 2026-10-26: `non_alert_factor` 1.2 (SO-11's
overload point), `flood_alert_poll_fill` 1.0, `background_alert_poll_fill` 0.2,
`oversized_line_factor` 2.0, `oversized_backlog_share` 0.25,
`backlog_non_alert_factor` 12 and `backlog_burst_interval_ms` 1000. The rates
follow from them and from the quota; changing a factor means re-deriving the
rates. `rate_tolerance` (0.05) may be at most 0.2 and `shed_tolerance` (0.1)
at most 0.2.

### How SO-04 applies it

Both SO-04 halves (`so04_lease_rollback.py`, `so04_rollback_completion.py`)
use `so04_hostile_load.py`. Of the 50 leases per action type,
`leases_per_phase_per_action` (10) expire under each of the four phases and 10
nominal (unloaded): 120 of 150 under load. The driver writes each phase's lines into
the core's EVE input at the declared rates for the phase's window, each phase
lease expires after the warm-up (plus a 0.5 s margin) and before the window
ends, and after the run the harness waits until the core has decided every
alert written. Each part carries a `hostile_load` observation: per phase, the
window on `CLOCK_BOOTTIME` and the wall clock, the lines written per class, and
the alerts the core decided (counted from the normalized log by the phase's
signature ids); and the core's own `ingress-audit.jsonl` summaries as written.

### When the gap closes

`SO04-HOSTILE-LOAD-UNDECLARED` is listed under `gaps_closed_by_samples` for
both SO-04 parts. A record may leave it out only when the validator's
recomputation (`record.PART_GAP_CLOSERS` →
`so04_hostile_load.hostile_load_problems`) finds nothing wrong. It reloads the
profile and the quota from the tree and checks that:

- the observation cites both files at their current SHA-256 and its windows
  are on `CLOCK_BOOTTIME`;
- every declared phase was applied: for every line class, the lines written
  are within ±5% (at least one line) of the declared rate times the window, and
  the window is at least the warm-up;
- the core decided every alert written in every phase;
- the core's summaries: `alerts_shed` 0 and `oversized_possible_alerts` 0 in
  every one, the quota block equal to the declared quota, no summary missing
  (cumulative totals equal the summed intervals), the audit not rotated; for
  every summary adds up (`examined = shed_total + admitted +
  oversized_lines_skipped`); for each over-quota phase, the summaries attributed
  to it account for at least `(1 − shed_tolerance)` of the non-alert lines
  written in it (examined minus `alerts_admitted`: alerts are never shed, and
  another phase's alerts read late must not count here). With `read_s` the time
  the phase's lines could have been admitted, the lines shed are at least
  `max(1, (1 − shed_tolerance) × (non-alert written − value × read_s −
  non_alert_burst))`, at least one of them for the rate, and the non-alert lines
  admitted are at most `value × read_s + non_alert_burst`.

  `read_s` (profile rule "read"): outside the backlog phase the core keeps up
  (peak unread backlog under 4 MB in every run), so `read_s` is fixed at window +
  `read_lag_cap_ms` (1000 ms: the audit interval, five polls, and more than the
  time to read the largest unread backlog seen), whenever the summaries are
  emitted. A summary is due up to one audit interval after the shedding it
  reports, so its emission time says when it was written, not how long the core
  read; tying `read_s` to it made the check flaky (a late honest summary
  stretched it, lowering the excess) and let a forged late summary lower the
  floor. In the backlog phase the core may read long after the window (the largest lag
  seen is about 12 s from the window end to its last summary, on a GitHub
  runner), so `read_s` runs to the last summary, at least the window and at most
  window + `backlog_read_lag_cap_ms` (60000 ms: five times that, and within the
  harness's 90000 ms drain, which the loader checks); summaries emitted after
  that are not counted as shed. Even at the cap the floor stays near 61000 lines;
  honest records shed more than 170000. With every summary adding up, claiming
  fewer lines shed either raises `admitted` above the quota over `read_s` or
  lowers `examined` below what was written. In the backlog phase the summaries must also show
  lines shed for the backlog and a shed level of at least 1. For each phase, the
  oversized lines the core skipped equal those written;
- every hostile sample's lease expired inside its phase's window after the
  warm-up, on `CLOCK_BOOTTIME`; every phase has at least
  `leases_per_phase_per_action` samples of every action type, at least
  `min_hostile_share` (0.8) of all samples are under a declared phase, and every
  other sample is `nominal`.

CI also checks this directly: after `validate --ci`, the `service-objectives`
job runs `python -m azazel_edge.service_objectives.so04_hostile_load
service-objective-records`, which fails unless both SO-04 parts pass the same
recomputation and keep no gap but `SO04-COMPLETION-BOUND-PROVISIONAL` and
`SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL`. The same job runs the real-core test of
the driver (`-k real_core`), which is skipped in `test-python` because that job
builds no core; the step fails unless the test passed.

A part without the observation, with a load short of its rate, or with an
invalid profile in the tree keeps the gap. `SO04-COMPLETION-BOUND-PROVISIONAL`
has no closer and stays on the completion part, so the SO-04 record stays
`not_measurable` (`diagnostic_only`).

### Owner confirmation: `SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL`

Both SO-04 parts carry a second, mandatory gap while the profile's factors
await the owner's confirmation. The owner confirmed them on 2026-10-26, as
they stood (no factor or rate changed): the profile now has status
`confirmed`, `owner_defaults.status` `confirmed` and
`owner_defaults.confirmed_phase_factors` naming the four phases' factors. A
record taken against this file therefore closes the gap; one taken against the
provisional file (an earlier digest) keeps it. Like `SO04-COMPLETION-BOUND-PROVISIONAL`, it
is about the declaration, not the run, and the validator decides it from the
tree, never from the record (`record.PART_GAP_CLOSERS` →
`so04_hostile_load.profile_confirmed_problems`). It may be left out only when

- `hostile_load_profile.json` in the tree is valid and declares status
  `confirmed`. The only statuses are `provisional` and `confirmed`. `confirmed`
  is accepted only with `owner_defaults.status` exactly `confirmed` and
  `owner_defaults.confirmed_phase_factors` equal to every phase's current factors
  (`non_alert_factor`, `alert_poll_fill`, `oversized_line_factor`,
  `oversized_backlog_share`, `burst_interval_ms`); otherwise the whole profile
  is invalid. A confirmation therefore names the values it confirmed, and a
  later change to a factor undoes it; and
- the part's load was taken against that very file (same path and SHA-256).

There is no other way to close it: no approval flag, no environment variable.
The owner confirms by changing the declaration in the tree, which also changes
its digest, so records taken against the provisional file keep the gap. `load_phase_applied` stays a run-health
prerequisite (every declared phase was driven); `CI_DECLARED_PREREQUISITES`
is unchanged (empty).

While the profile was provisional, neither part could derive `pass` from it:
the start part was `not_measurable` on that gap alone, and the completion part
also on `SO04-COMPLETION-BOUND-PROVISIONAL`. With the profile confirmed, a
clean start part (every prerequisite met, `wall_clock_stable_during_run`
included) may now be `pass`; the completion part stays `not_measurable` on
`SO04-COMPLETION-BOUND-PROVISIONAL`, so the SO-04 record as a whole stays
`not_measurable` (`diagnostic_only`). Under `--ci` both are declared gaps, so a
clean run is green.

### Container runs (not hardware evidence)

With the four phases (after the review: backlog phase, 10 leases per phase and
action type), one run on colima aarch64: every part 150/150, 0 violations,
start max 488.0 ms; `backlog_flood` shed 227054 / 227110 lines (start /
completion), 60000 / 70500 of them for the backlog, at shed level 2 / 3 with up
to 18.6 / 29.4 MB unread; the recomputation found nothing in either part.
`wall_clock_stable_during_run` was unmet in that run (colima clock drift).

Earlier, with three phases (12 leases per phase), three runs of `run --objective SO-04` on this change (docker `--cap-add
NET_ADMIN`, colima, aarch64, 2026-10-26), taken before
`SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL` was added (the load and timing are
unchanged by it). Every part 150/150 samples, 0 violations, and
`SO04-HOSTILE-LOAD-UNDECLARED` closed by the recomputation in all six parts.

| Run | Start max | Completion max | Lines shed by the core (start / completion) | Oversized skipped | Alerts written = decided | Alerts shed |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 641.1 ms | 1260.8 ms | 7931 / 10373 | 9 / 9 | 63076 / 63309 | 0 |
| 2 | 715.7 ms | 1197.6 ms | 8424 / 9740 | 9 / 9 | 63180 / 63121 | 0 |
| 3 | 457.3 ms | 1344.1 ms | 7902 / 10977 | 9 / 9 | 63124 / 63320 | 0 |

In runs 2 and 3 `wall_clock_stable_during_run` was unmet on the start part
(drift −101.6 and −208.6 ms against 50 ms: the colima VM's wall clock was
adjusted during the run), so those records are red under `--ci`; run 1 was
clean (green).

## SO-02 — source/interface failure visible (virtual-lab harness, not measurable)

Harness: `py/azazel_edge/service_objectives/so02_source_failure.py`
(`python -m azazel_edge.service_objectives run --objective SO-02`, as root).

What Edge already does, and what the harness measures without changing it:

- **Capture process death.** `GET /api/state` computes `monitoring.suricata`
  on every request (`azazel_edge_web/app.py` `get_monitoring_state`): `OFF`
  once the Suricata unit is inactive or the pid in `/run/suricata.pid` is gone.
  The lab has no systemd, so it measures the pidfile-liveness path only; the
  production `systemctl is-active` path is not measured.
- **Capture interface link down.** The control daemon's NOC projection lists in
  `noc_blast_radius.affected_uplinks` every interface whose path probes fail
  (`py/azazel_edge/evaluators/noc.py` `_evaluate_affected_scope`). `br0` is
  Edge's default capture interface (`SURICATA_IFACE`) and internal monitor
  bridge. The daemon's defaults are `AZAZEL_NOC_REFRESH_SEC` 20 s and
  `AZAZEL_SNAPSHOT_REFRESH_SEC` 12 s; the harness runs on those defaults and
  does not shorten them. Besides that periodic loop, the daemon watches the
  monitored interfaces' carrier/operstate (`py/azazel_edge/sensors/link_watch.py`:
  netlink `RTMGRP_LINK` multicast, which needs no capability; a sysfs poll at
  most every 1 s where netlink cannot be opened) and, on a change, re-runs the
  path probes of that interface at once (debounced, at most one re-evaluation
  per 2 s, bounded to 5 s). It is observation only: the same probes and
  evaluator, published sooner; the periodic loop stays the backstop. Each
  collector of the periodic collection also has an explicit upper bound
  (`COLLECTOR_TIMEOUTS_S` in `py/azazel_edge/sensors/noc_monitor.py`). This
  changes behaviour only on overrun: a collector that overruns is reported as a
  collector failure (the evaluator's usual `collector_failure` penalty) with
  its empty default, as one that raised; path probes instead run one thread
  per interface and report an overrunning interface's targets as unreachable
  (`error: collector_timeout`), so a timeout never scores better than the
  probes failing; name resolution, whose `timeout_sec` was previously
  ignored, is now held to 5 s per name and reads as an unresolved name. These
  values feed the operator surface only: the live NOC evaluation in the
  control daemon is consumed by the snapshot, `/api/state` and the dashboard
  payloads; the action arbiter and M.I.O. read NOC evaluations only in
  replay, dry-run, benchmark and harness tools, never from this collection.
  When a link-event refresh starts during a full collection, the full result
  keeps the refresh's rows for that interface and its own rows for the rest.
  The harness measures only the total from injection to the surface. Each
  sample also carries diagnostic stages, never read for the verdict: wall-clock
  stamps (the injection, the `noc_runtime.updated_epoch` and `snapshot_epoch`
  the surface showed at the end) and `end_noc_collection`, the NOC collection
  behind the end response as `noc_runtime.collection` reports it -- its trigger
  (`periodic` or `link_event`), its start on the same CLOCK_MONOTONIC as the
  injection stamp, and each collector's start offset and duration.

The harness builds two network namespaces, runs the control daemon, the web UI
under gunicorn and Suricata on `br0` inside them, injects each failure ten
times, and polls the surface with a viewer-role token.

It refuses to start (record `not_measurable`, nothing created) when a Suricata
is running, `/run/suricata.pid` exists, a lab namespace from an earlier run is
left over, or PyYAML is missing. Without PyYAML the daemon would ignore the
lab's `suppress_auto_wifi: false` and run `nmcli` against the host. Before it
starts the daemon, it also asks the daemon's own `load_control_flags()`, in
the lab environment, and stops unless the answer is `false`.

On teardown, SIGTERM, SIGINT and SIGHUP are blocked. The harness stops every
process inside its namespaces, found by network-namespace inode, so a
daemonized Suricata whose pid was never read is stopped too. It removes
`/run/suricata.pid` only if the file names a Suricata the harness started. A
harness killed with SIGKILL cannot clean up: its `so02e-*`/`so02p-*`
namespaces and the processes in them remain, and the next run refuses until
they are removed (`ip netns pids <ns> | xargs -r kill; ip netns del <ns>`).

The row stays `not_measurable` because of three gaps the owner has to close:
the configuration is not Edge integrated into a Nexus Core install
(`SO02-NOT-NEXUS-INTEGRATED`); Edge declares no list of source types, and no
feed source type is declared (`SO02-SOURCE-TYPES-UNDECLARED`); and the
interface has no commissioned identity (`SO02-NO-COMMISSIONED-INTERFACE-IDENTITY`).
The physical-NIC variant is hardware-only (R7). A virtual-lab record declares
`hardware_evidence: false`, and the validator rejects one that does not.

## SO-05 — local M.I.O. failure reflected as `CORE ONLY` (no harness: the state does not exist)

No harness is built, because the behaviour SO-05 measures does not exist in Edge:

- **No `CORE ONLY` capability state.** No code, configuration or surface in this
  repository has such a state.

What does reflect model failure today, and why it is not this state:

- **`llm.status` on the surface** (`azazel_edge_web/app.py`
  `situation_board.threat_posture.llm_status`, shown as "LLM Status"). It is
  the outcome of the AI agent's last LLM call for an advisory
  (`py/azazel_edge_ai/agent.py` `advisory["llm"]`): `fallback` with a reason
  when the model call failed, or else `completed`, `queued`, `deferred`,
  `skipped_non_ambiguous` or `disabled`. The daemon resets it to `idle` once
  the advisory expires. It changes only when an ambiguous event triggers a
  model call, so a model that dies while no such event arrives never changes
  it. It reports one request, not the node's capability. Its reason goes to
  the AI event JSONL, not to the audit chain.
- **Nothing reflects a local-model failure as a capability state.** Beyond
  `llm.status`, the AI agent's only runtime policy is `normal` / `degraded`
  (`py/azazel_edge_ai/agent.py` `_set_policy_mode`, `_recompute_policy`). It
  switches only on answer-quality ratios after at least 10 requests, chooses a
  smaller model, and is written to the policy and metrics files. It is not a
  capability state.
- **No audit record names the cause.** The switch is only a log line, so even a
  change there would not satisfy "an audit record names the degradation cause".
- **The dashboard's `ai_agent` ON/OFF** (`azazel_edge_web/app.py`
  `service_summary`) shows whether the `azazel-edge-ai-agent` unit is active.
  It does not show the model runtime (Ollama), and it is not a capability
  state.
- **No health probe of the model runtime.** Nothing probes it, so a hung health
  probe (one of the definition's failure modes) has nothing to act on.

The assignment already defers SO-05 to R6 because the local M.I.O. runtime
profile is not implemented (Azazel-Nexus#5). Building the state, its audit
record and a probe would add product function, and that is the owner's decision.


## CI exit semantics (`--ci`)

Edge#414 asks that a job holding a harness refuse to go green by skipping: a
job existing is not a run. Before this, `run` and `validate` exited 0 only for
an all-`pass` set, so the `service-objectives` jobs were red on every push for
as long as any declared gap stood, which hides a real regression in a job that
is always red.

`run --ci` and `validate --ci --objective ...` (`.github/workflows/ci.yml`)
change only the exit status; no verdict is changed and no validator check is
relaxed. Without `--ci` the exit status is as before (0 pass, 1 fail,
2 not_measurable, 3 invalid).

| Record | `--ci` exit | CI |
|---|---|---|
| harness did not execute: fewer samples than the `OBJECTIVE_SPECS` row requires (or a per-action shortfall), a crash part, or a pass downgraded for an unidentified commit | 4 | red |
| executed, but a prerequisite is unmet that is not in `CI_DECLARED_PREREQUISITES` (run health: lab built, daemon started, load applied, wall clock stable, chain verifies, coverage, ...) | 4 | red |
| invalid record, or a requested objective with no record | 3 | red |
| verdict `fail` | 1 | red |
| verdict `not_measurable`, but a part's pass rule does not hold (a violation or an unfinished sample) | 2 | red |
| verdict `not_measurable`, executed, valid, every part holds, every unmet prerequisite allowlisted: blocked only by declared gaps | 0 | green, verdict table in the step summary |
| verdict `pass`, executed and valid | 0 | green |

"Executed" is recomputed from the samples against the fixed `OBJECTIVE_SPECS`
row (`record.not_executed_reasons`), never read from a field the record sets.
A harness whose environment is missing (no root, no lab, no core binary) takes
no samples and is red. A full sample count is not enough: a gap-blocked record
whose samples break the bound (the verdict stays `not_measurable` because
`derive_verdict` checks gaps first) is red, and so is one whose run-health
prerequisites failed while its harness still emitted rows.

`CI_DECLARED_PREREQUISITES` (`record.py`) lists, per objective, the
prerequisites that may be unmet in a green record. Only a prerequisite stating
a declared structural absence that a declared gap stands for may go there.
It is empty for every objective today:

| Objective | Allowlisted unmet prerequisites | Why |
|---|---|---|
| SO-02 | none | `lab_built`, `no_live_capture_touched`, `edge_stack_answering` are lab health; `every_injection_from_healthy_baseline`, `every_lab_source_type_sampled` are recomputed coverage |
| SO-03 | none | `core_binary_present`, `core_daemon_started`, `agent_service_relay_attached` are run health (the Rust core and the AI agent service of its unit's ExecStart ran, Edge#412); `core_enforcement_not_applied` and the queue, chain, decision-id, P0-class and fsync checks are recomputed measurement correctness |
| SO-04 | none | core present/started, load applied, wall clock stable, chain/order, owned state and readback are run health; `per_action_completion_bound_declared` unmet would mean the declaration file lost a type |
| SO-07 | none | both are coverage of the kill matrix |

When unsure, a prerequisite stays off the list and its record is red. Adding
one needs the review a target change needs. `validate --ci` writes a table of
every part (verdict, executed, samples, max ms, violations, blocking gaps,
unmet prerequisites, CI result) to `$GITHUB_STEP_SUMMARY`, so a green
`not_measurable` is always visible. It is never a pass and never gate evidence
(`evidence_class: diagnostic_only`).

Jobs:

- `service-objectives`: SO-03 and SO-07 unprivileged, SO-04 as root (its
  completion half installs owned tc/nft state on dummy interfaces;
  unprivileged it takes no samples and would be red). SO-02 is not run here.
- `service-objectives-lab`: SO-02 as root. It takes about 25-30 runner minutes,
  so it runs on pushes to `main` and on `workflow_dispatch` only; on a pull
  request the job is shown as skipped, which is the job not running, not a
  harness result.

SO-02 under these semantics: the lab run on `main` at 9f02dfb took 20/20
samples with 10 over the 10 s bound (max 33.8 s). Its verdict is
`not_measurable`, not `fail`, because `derive_verdict` checks blocking gaps
before the pass rule and SO-02 declares three (`SO02-NOT-NEXUS-INTEGRATED`,
`SO02-SOURCE-TYPES-UNDECLARED`, `SO02-NO-COMMISSIONED-INTERFACE-IDENTITY`).
The verdict is unchanged, but with `--ci` that record is red (exit 2: the pass
rule does not hold), so the lab job stays red until the measured latency is
within the bound (the link-state re-evaluation in #455 measured a 3.8 s
maximum). A gap-blocked record is green only when its numbers would pass.
