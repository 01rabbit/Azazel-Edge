# Service-objective declarations (OF-05, OF-06)

Tracking: #414  
Assignment: `01rabbit/Azazel:docs/roadmaps/service-objective-assignments.md` (SO-04, SO-11, OF-05, OF-06)  
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

## OF-06 — Core ingress quota (not declared: no mechanism exists)

SO-11 asks for the SO-03, SO-04 and SO-07 pass rules to hold "at each declared
ingress quota", and at 120% of the highest one for the quota to **shed**
("a quota that is declared but not enforced fails this row"). A quota can only
be declared provisionally if something already enforces it. Nothing does on
the Core's ingress path, so Edge declares no ingress quota and adds no shedding
mechanism here. That is a design decision for the owner.

### What exists today

| Place | Bounded? | Sheds? | Why it is not an ingress quota |
| --- | --- | --- | --- |
| `azazel-edge-core` EVE reader (`main.rs`, `read_new_lines`) | No | No | Reads every new line on each poll (200 ms) and decides each one. No line or rate limit, no drop counter. Under a flood the release sweep waits for the read to finish, which is what the SO-04 `eve_flood` phase shows. |
| Core → AI socket forwarder (`main.rs`, `AI_FORWARD_QUEUE` = 1024, `AI_FORWARD_DROPPED`) | Yes | Yes, counted | Downstream of the decision. It protects detection from a slow receiver; every ingress line has already been decided and logged. It does not limit what the Core admits. |
| AI agent LLM queue (`azazel_edge_ai/agent.py`, `AZAZEL_LLM_QUEUE_MAX` = 32) | Yes | Defers (`queue_full`) | Bounds advisory LLM work, not Core intake. |
| `EvidenceBus` (`evidence_plane/bus.py`, `queue_max` = 1024) | Yes | No: `put_nowait` raises `queue.Full` | Not on the Core path; no drop policy or counter. |

There is no SO-11 harness in this repository, and none is added: with no
declared quota, the row has nothing to iterate. `SO04-HOSTILE-LOAD-UNDECLARED`
already keeps the SO-04 parts `not_measurable` for the same reason.

### What would need to exist

1. **An enforced intake bound on the Core's ingress**, with a declared policy
   for excess (drop or queue), a counter of what it shed, and a way for the
   harness to read that counter from outside (for example a line on the
   existing forward-stats channel, or the health surface).
2. **A declaration** of each quota (unit, value, hardware class, status), in the
   same form as the OF-05 file, that the SO-11 harness and validator read.
3. **An SO-11 harness** that re-runs SO-03, SO-04 and SO-07 while offering
   traffic at each declared quota, then once at 120% of the highest, and checks
   that the shed counter moves at 120% and that admitted traffic still meets the
   referenced rows.

### Candidate locations

- `read_new_lines` in `azazel-edge-core`: a per-poll line budget (lines beyond
  it left for the next poll, i.e. queued in the file) or a token bucket over
  decided events (excess dropped and counted).
- A bounded channel between the EVE reader and the decision step, in the same
  pattern as the AI forwarder: bounded `sync_channel`, `try_send`, an atomic
  drop counter.
- Suricata's own EVE output rate, outside Edge. This would make the quota a
  sensor setting rather than a Core property.

### Open questions for the owner

- **Unit.** Events per second, lines per poll, or bytes per second? Per peer
  (§5 R5 speaks of per-peer quotas) or for the whole node?
- **Policy for excess.** Drop and count, or leave unread in the EVE file (queue)?
  Queuing in the file delays decisions and the release sweep; dropping loses
  detections. Should an alert from a source that already holds a lease be
  admitted ahead of others?
- **Order of work per poll.** Should the release sweep run before ingress is
  drained, so rollback timing does not depend on ingress volume?
- **Hardware classes.** Which classes are declared (Raspberry Pi 5, x86_64
  appliance), and who runs the R7 hardware confirmation?
- **Where the shed counter is reported**, so that a harness can read it without
  privileged access to the Core.
