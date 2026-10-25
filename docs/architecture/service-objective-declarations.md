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

Owner decision on #414 (2026-10-25): bound the Core's EVE reader per poll;
past a backlog bound shed the lowest-importance event types first; never shed
alerts; count what is shed and record it as a rate-bounded `ingress_shed`
summary; never shed silently. This section records what was built.

### Where it lives

| What | Where |
| --- | --- |
| The bound (enforced) | `rust/azazel-edge-core/src/ingress.rs`, `IngressLimits::DECLARED` (compile-time constants; no environment variable raises or disables them) |
| The declaration | `config/service_objectives/ingress_quota.json` (schema `azazel-edge/ingress-quota/v1`), read by `declarations.load_ingress_quotas()`. The core does not read it; a core unit test fails if it and `IngressLimits::DECLARED` differ, and a pytest checks the same from the Python side. |
| The shed record | `ingress-audit.jsonl` beside the normalized event log (`AZAZEL_NORMALIZED_EVENT_LOG`'s directory), plus one stdout line (stderr when `AZAZEL_EVENT_STDOUT=off`). Its own file, so readers of the normalized log never meet a record of another shape. |
| SO-11 starting point | `py/azazel_edge/service_objectives/so11_ingress_probe.py` |

| Ingress | Quota | Per poll | Backlog bound | Alert backlog record point | Status | Hardware class |
| --- | --- | --- | --- | --- | --- | --- |
| `core_eve_reader` | 2500 EVE lines/s | admit ≤ 1500, examine ≤ 6000 | 8 MiB unread | 256 MiB unread | provisional | container-aarch64, not hardware |

**Basis.** The old reader had no bound, so its sustained decision rate is the
Core's capacity on this path: 200000 pre-written alerts in the SO-04
`eve_flood` line shape, read from the start, release build on main at
`4b5242c`, enforcement off: 5641, 6768 and 7676 lines/s in three runs
(colima, aarch64). The quota is less than half the minimum, rounded down to
500, and above the SO-04 harness's `eve_flood` rate (2000 alerts/s) so SO-04
is not throttled by it. Re-measured with other containers on the same 2-CPU
VM the old reader decided 3348–5252 lines/s; the new one admitted 2263–2493
lines/s against its 2500 lines/s bucket. The quota is a ceiling, not a
promise.

### How the reader behaves

Each poll (200 ms) the reader:

1. **Refills a token bucket** at 2500 lines/s, capacity 1500. A line is
   admitted (handed to the decider) only against a token, so at most 1500
   lines are decided per poll and at most 2500 per second.
2. **Measures the backlog**, the unread part of the EVE file (`len − offset`),
   and picks a shed level: 0 up to 8 MiB, then one more class per further
   8 MiB — `flow`/`netflow` first, then `dns`, then `stats`, then every other
   non-alert type (and unparseable lines).
3. **Reads lines** until it runs out of tokens, has examined 6000 lines, or
   reaches the end. A shed line is counted by class and skipped without a
   token. An alert is never shed: it has no class.
4. **Advances the offset only past lines it handled.** Everything else stays in
   the file and is read on a later poll; a line without its newline yet is
   left until it is complete. A bound on work per poll, not data loss.
5. **Emits audit summaries**, at most one `ingress_shed` and one
   `ingress_alert_backlog` per second, each only when there is something to
   report, with per-class counts for the interval and cumulative totals (so a
   lost summary shows as a jump). Counts not yet reported carry over.
6. **Runs the release sweep.** It runs on every iteration whatever is waiting
   in the file (`poll_iteration` in `main.rs`; tested with a five-poll flood
   already in the file before the first poll).

**Alerts beyond capacity.** Alerts are never dropped. Beyond the quota they
wait in the EVE file and are read at the quota rate, oldest first. The backlog
costs disk Suricata already wrote, not Core memory, because the reader holds
one line at a time. Past 256 MiB unread an `ingress_alert_backlog` summary is
recorded (once per second while it lasts, `alerts_shed: 0`) and reading
continues. What a sustained alert flood costs is decision latency, and the
summary is what makes that visible. Dropping alerts to keep latency low would
trade a visible delay for an invisible miss; the owner chose the delay.

**Truncation.** If the EVE file becomes shorter than the offset (rotation by
truncation, or replacement by a shorter file), the reader restarts at 0 and
the unread bytes of the old file are counted in the next `ingress_shed`
summary (`truncation_resets`, `unread_bytes_at_truncation`). Rotation by
rename to a file already longer than the offset is not detected; that was
true before OF-06 and is unchanged.

### SO-11 starting point (not a measurement)

`python -m azazel_edge.service_objectives.so11_ingress_probe --core-bin PATH --out FILE`
starts the real core and writes half alerts, half flow records (about 1.5 KB
each) at 120% of the declared quota for 40 s, then checks the core's own
output: shedding recorded, no alert shed, every alert decided once the backlog
drained, summaries at most one per interval. It reports `not_measurable` with
gaps, because SO-11's referenced rows (SO-03, SO-04, SO-07) are not re-run at
the quota, the quota is provisional and container-derived, SO-11 has no
specification in `record.py`, and only one traffic mix is offered.

One container run (colima, aarch64, 2026-10-25): 3000 lines/s offered for
40 s, 59994 alerts and 59994 flow records written; 14414 flow records shed
(`max_shed_level` 1, so nothing above `flow` was needed), 0 alerts shed, all
59994 alerts decided 42.4 s after the writer started, 20 `ingress_shed`
summaries at least 1.09 s apart, peak backlog 8.76 MB.

### SO-04 under the bound

`python -m azazel_edge.service_objectives run --objective SO-04` on this tree
(docker `--cap-add NET_ADMIN`, colima aarch64, `eve_flood` at 2000 alerts/s,
below the quota so nothing was held back), two runs. Start: 150/150
samples each, max 2408.7 ms and 1415.7 ms against the 5 s start bound, 0
violations. Completion: 150/150 each, max 1664.1 / 1497.6 ms (throttle),
1677.9 / 1375.1 ms (isolate), 1773.6 / 1592.9 ms (redirect) against the
provisional 5000 ms bounds, 0 violations. Wall clock stable in every part. The record is `not_measurable` for the same gaps as before
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
  does not shorten them. It measures only the total from injection to the
  surface. Each sample also carries wall-clock stage stamps (the injection,
  the `noc_runtime.updated_epoch` and `snapshot_epoch` the surface showed at
  the end) for diagnosis; they do not attribute the probe-collection time and
  are never read for the verdict.

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

