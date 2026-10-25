# Service-objective declarations (OF-05, OF-06, SO-02, SO-05)

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
  because the sample rule is the same. `SO04-LEASE-EXPIRY-ON-WALL-CLOCK` is
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
   cumulative totals (so a lost summary shows as a jump).
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

`SO04-HOSTILE-LOAD-UNDECLARED` is left in place: a declared ingress quota is
not a declared hostile-load profile, and the `eve_flood` phase is still a
harness-chosen load.

### Still open

- **Hardware classes.** Only container-aarch64 is measured. Raspberry Pi 5 and
  x86_64 appliance quotas, and the R7 hardware confirmation, are not done.
- **Per peer.** §5 R5 speaks of per-peer quotas; this is one node-wide quota.
- **A full SO-11 harness** re-running SO-03, SO-04 and SO-07 at the quota and
  at 120% of it, with a `record.py` specification.
- **Where else the counter is read.** The summaries are in a file and on
  stdout; nothing forwards them to the AI socket or the health surface yet.
- **Summaries pending at shutdown.** Counts from the last interval (under one
  second) are not flushed when the process is killed; the next process starts
  its cumulative totals at zero.

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
