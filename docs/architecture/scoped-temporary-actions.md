# Scoped temporary actions: design and safety rules

Status: accepted and implemented in `rust/azazel-edge-core` (this change).
The shipped posture is unchanged: enforcement off, dry run on, level
`advisory`. Nothing here turns enforcement on.

Scope: the automatic path of the Rust core — the only Edge process that
changes the network (`X86_64_INTEGRATION_BOUNDARY.md`). It covers the owner
policy that automatic handling is limited to **notification, temporary
restriction of traffic and redirection to a decoy**, that the AI proposes and
Edge's deterministic rules decide whether, on what and for how long, and that
management, expert-contact and mission communication is preserved.

Findings addressed (independent survey of `cc769e0`): S-06 (throttle acted
on the whole NIC), S-07 (redirect without decoy checks; fallback to isolate),
S-08 (no apply time bound, no readback, no product lease bound), S-23 (a full
release ledger refused new actions forever), and the Edge parts of S-09
(crash recovery) and S-10 (independent evidence). The Nexus unit
(`Restart=`, capabilities) is a separate change.

## 1. Decision

### 1.1 What the automatic path may do

| Decision | Automatic action | Executed only if |
|---|---|---|
| severity ≤ 1 | `throttle`, strict (16 kbytes/s) | §1.3–§1.7 hold |
| severity 2 | `redirect` to a prepared decoy port | §1.3–§1.8 hold; otherwise the policy fallback (`notify` by default) or a refusal with its reason |
| severity 3 | `throttle`, standard (32 kbytes/s) | §1.3–§1.7 hold |
| severity 4 | `notify` | — |
| otherwise | `observe` | — |

`isolate` is **not an automatic action**:

* `decide_defense()` never returns it (severity ≤ 1 was `isolate`; it is now
  the strict throttle).
* A redirect policy fallback may only be `observe`, `notify` or `throttle`;
  `isolate` (and `redirect`) in the file become `notify`
  (`normalize_safe_action`). The shipped `config/redirect_policy.yaml` names
  `notify`.
* No enforcement level and no `AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO` value
  puts `isolate` in the allowed actions (`full-auto` used to).
* The plan builder produces no command for `isolate`, and the static safety
  rule turns an `isolate` decision into `notify`
  (`isolate_not_automatic`), so no automatic path can reach a source-wide
  drop. A unit test walks every level × flag × policy × severity × port and
  asserts it.

The release path still releases an `isolate` lease found in an existing
ledger (written by an older core): releasing is always allowed.

Permanent blocking and broad isolation are outside the delegated scope. If
they are ever wanted, they need an owner decision, an operator approval path
that is not automatic, and their own design; this change adds none.

### 1.2 Protected communications set

Declared by the deployment in `AZAZEL_PROTECTED_FLOWS_PATH` (default
`/etc/azazel-edge/protected-flows.yaml`), read once at start:

```yaml
protected_flows:
  version: 1
  entries:
    - {name: mgmt-lan,  role: management,     network: 192.0.2.0/28}
    - {name: expert,    role: expert_contact, network: 198.51.100.7, ports: [443]}
    - {name: radio-gw,  role: mission,        network: 2001:db8:10::/64}
  # A role the site has none of is stated, with who approved that:
  # roles_not_applicable:
  #   - {role: mission, approved_by: field-lead, reason: no mission link here}
```

* Roles: `management` (the management path), `expert_contact` (the
  channel to the remote expert), `mission` (communication the mission needs).
* Matching is deterministic and done by Edge, never by the AI: a flow is
  protected when its **source** is inside any entry (every port — restricting
  a source affects all of its communication) or its **destination** is inside
  an entry and the destination port is listed (every port when none is). It
  is matched against what the rule would act on (§1.3): a scope with no port
  (ICMP) matches every destination entry, so no listed port can be excluded.
* A protected flow is never restricted or redirected. The alert becomes
  `notify` and `policy_reason` ends in
  `:safety_refused:protected_flow:<role>:<entry name>`. This is evaluated in
  every mode, so a dry run shows the refusal too.
* Execution requires a usable declaration: absent
  (`protected_set_not_configured`), invalid (`protected_set_invalid`: unknown
  key, role, network or version, more than 256 entries, a file that is a
  symlink, group/world-writable, not owned by root or the core's user, or
  over 64 KiB), without a `management` entry
  (`protected_set_has_no_management_entry`), or with `expert_contact` or
  `mission` neither declared nor listed under `roles_not_applicable` with
  `approved_by` and `reason` (`protected_set_role_undeclared:<role>`) refuses
  every restriction and redirect. A role left out is a missing
  declaration, never "nothing to protect"; `management` can never be "not
  applicable", and a role cannot be both declared and not applicable. An
  unreadable declaration never reads as "nothing to protect".

### 1.3 Target: one flow

A temporary restriction is scoped to the alert's flow: source, destination,
protocol and, for TCP/UDP, the destination port. The scope never widens:

| Alert | Scope | Otherwise |
|---|---|---|
| TCP/UDP with a port | `ip saddr S ip daddr D tcp/udp dport P` | — |
| TCP/UDP without a port | — | refused, `target_port_missing` |
| ICMP (IPv4) / ICMPv6 (IPv6) | `… daddr D meta l4proto icmp / ipv6-icmp` | — |
| any other protocol | — | refused, `target_protocol_unsupported` |
| source and destination of different families | — | refused, `target_not_a_flow` |

A redirect is scoped the same way and to the ingress interface the decoy
evidence names (§1.8): `iifname "<AZAZEL_DEFENSE_IFACE>" ip saddr S ip daddr D
tcp dport P redirect to :<decoy port>`. It needs a TCP alert with a port and
an IPv4 source. Another destination of the same source on the same port (a
protected host, say) is not redirected; the protected set is matched against
this scope (before this change the redirect rule had no destination, so it
caught the source's traffic to every host on that port).

### 1.4 Mechanism and strength

The restriction is an nft rule in the core's own chain, never a qdisc:

```
nft insert rule inet azazel_edge throttle ip saddr S ip daddr D tcp dport P \
    limit rate over 32 kbytes/second burst 32 kbytes drop comment "<owner token>"
```

Packets of this flow above the rate are dropped: the flow keeps working,
slowed (TCP adapts), and no other flow is touched. Strength is fixed by Edge:
strict 16 kbytes/s for critical alerts, standard 32 kbytes/s otherwise (the
old TBF rate was 256 kbit/s = 32 kbytes/s for the *whole interface*).

The previous throttle (`tc qdisc replace dev <iface> root … tbf`) replaced
the interface's root qdisc and deleted it at release, destroying whatever
shaping was there. The core no longer runs `tc` at all. A ledger written by
an older core may still hold such a lease; it is still released by its
handle (legacy path), never applied.

The deployment declares the owned chain (the core does not create tables or
base chains):

```
add table inet azazel_edge
add chain inet azazel_edge throttle { type filter hook prerouting priority -150; policy accept; }
add chain inet azazel_edge prerouting { type nat hook prerouting priority -100; policy accept; }
```

The `prerouting` filter hook sees forwarded traffic and traffic to the Edge
itself. Without the chain the apply fails, is recorded as `failed`, and its
lease is released at once (§1.6).

### 1.5 Lease bounds: TTL, extension, cumulative, count

Compiled-in constants; no environment variable or file raises them:

| Bound | Value | Effect |
|---|---|---|
| `MIN_LEASE_TTL_SEC` / `MAX_LEASE_TTL_SEC` | 30 s / 900 s | `AZAZEL_DEFENSE_ACTION_TTL_SEC` is clamped into this range (`metadata.safety.ttl_source`: `configured`, `clamped_to_max`, `raised_to_min`, `invalid_default`, `default`) |
| `MAX_LEASE_EXTENSIONS` | 3 | A new alert for a flow already held extends the lease (no new rule) at most 3 times; then `lease extension limit reached` |
| `MAX_CUMULATIVE_LEASE_SEC` | 3600 s | A *family* of leases of one flow ends at most 3600 s after its first lease began, extended or re-created; a new lease within `MIN_LEASE_TTL_SEC` of that bound is refused (`lease cumulative limit reached`) |
| `FLOW_COOLDOWN_SEC` | 900 s | A flow whose lease family reached `MAX_CUMULATIVE_LEASE_SEC` is not restricted again from the family's end until 900 s later: its alerts are refused (`policy_gated`, `safety.gate = refused:cooldown`, `release_cooldown_until_epoch`) and notified only. Never longer, never permanent; afterwards a new family may start on a new alert |
| `MAX_ACTIVE_LEASES` | 64 | More held leases are refused (`active lease limit reached; restriction not widened`) so many alerts cannot add up to a broad restriction |
| `MAX_ALERT_AGE_SEC` | 300 s | An alert older than this by its own EVE time, more than 60 s in the future, or undated, starts nothing (`alert_stale`, `alert_time_in_future`, `alert_time_unreadable`) |

**Cooldown in the ledger.** Families and cooldowns belong to the **flow**
(`flow_key`: source, destination, protocol, port), not to a mechanism: a
throttle family and a redirect of the same flow share them, so switching the
action cannot step around a cooldown. The lease that brings its family to
the bound (a new lease cut at the bound, an extension that reaches it, or —
when a new lease would be shorter than `MIN_LEASE_TTL_SEC` before the
bound — the family's latest lease, even an old released one) records the
cooldown, which runs from that moment until family start + 3600 s + 900 s:

* on both clocks: `cooldown_until_epoch` and, with this boot's id,
  `cooldown_until_boottime_ns`. In its own boot the monotonic clock decides,
  so stepping the wall clock back (or forward) neither ends it early nor
  re-opens the family. In another boot, or when the wall clock is behind the
  recording time, it is re-anchored on the current boot for the wall-clock
  remainder, at most `FLOW_COOLDOWN_SEC` — finite, never permanent.
* in the ledger: it holds across restarts, and recording it counts the task
  as changed. A task whose cooldown may still run (wall clock less than a
  cooldown past its end, or its boot's monotonic end not passed) is never
  compacted, by admission or by `--release-ledger-compact`.

A cooldown refusal writes nothing (except a re-anchoring): the alert
executed nothing, so there is nothing a replay could repeat, and every
replay guard (event keys, tombstones, checkpoint) is unchanged by it.

An alert that asks for no more time than a held lease already has is
recorded (`already_held`) and changes nothing. Every alert merged into a held
lease is kept as a `merged` tombstone, so a replay of it is refused.

Release is unconditional: when either the wall or the monotonic deadline
passes (existing rule, `release.rs`), the sweep deletes the owned rule and
verifies its absence. Lease expiry never depends on the AI, Nexus, the UI or
Knowledge.

### 1.6 Apply: time bound, readback, immediate release on doubt

* Each apply command runs with a 3 s bound (`APPLY_COMMAND_TIMEOUT`); past
  it the command is killed and counted as failed (`command timeout`). The
  release path keeps its own 5 s bound per command.
* After the commands succeed, the core reads its owned rule back
  (`nft -a -j list chain`) and requires exactly one rule with the owner
  token and the planned semantics (source, destination, port or protocol,
  an inverted limit of exactly the planned rate and burst per second, and
  `drop`; for a redirect, the ingress interface and the redirect port). Only
  then is the lease `active` and the outcome `applied`.
* Removal is checked apart from that: a rule is ours to delete when it
  carries the owner token **and** the lease's complete flow identity
  (source; destination when the lease has one; protocol and port, or
  `meta l4proto` for a portless flow; the ingress interface of a flow
  redirect). A rule that is ours but deviates only in how it acts (another
  rate or burst, redirect port or ct mark) is deleted, and counted in the
  release outcome (`postcondition.deleted_deviating_rules`); a rule with the
  token on another flow is not ours, nothing is deleted and the release is
  retried with the error.
* Any failure, timeout, missing or different readback: the lease becomes
  `uncertain` and **due now** on both clocks (`abandon_release_task`), so
  the next sweep deletes whatever owned rule exists and verifies absence. It
  is never left for its TTL (before: a failed apply was `cancelled` — a
  terminal state, so a command that timed out after applying would have left
  a rule with no lease — and a partial apply waited for the TTL).
* The release sweep runs on its own thread. The decision loop holds the
  ledger lock only while it updates the ledger, never while a command runs,
  so a wedged apply cannot hold a release back. A lease whose apply is in
  flight is skipped by the sweep (in-process registry): releasing it before
  the apply lands would verify absence and then leave the rule behind.

### 1.7 Restart and crash: no new grant

* At start, before any alert is read, every lease still `prepared` (its
  apply was in flight when the previous process stopped) is made `uncertain`
  and due now: it is released, never activated
  (`recover_unconfirmed_on_start`).
* `active` leases keep their deadlines; a lease of another boot counts as
  expired (existing monotonic rule). A restart extends nothing.
* The EVE file is read from its end unless `--from-start`; replayed alerts
  are refused by the ledger and by the alert-age rule. The ledger guard is
  the alert's own **event key** (EVE time, addresses, port, protocol, rule
  id; not the decided action or mechanism, which a policy or code change can
  alter for the same alert), the task id, `merged` tombstones and the
  checkpoint watermark. For a ledger written by the previous core (v1,
  whose task ids came from the old mechanism and have no event key) two
  guards hold together: the **trace id** the previous core gave the alert
  for any action it could have decided (isolate, redirect, throttle) is
  matched against its tasks, whatever the times say; and a migration
  boundary refuses every alert dated at or before the latest of the file's
  mtime and every time its tasks carry, plus the 60 s an alert may be dated
  ahead and still be acted on. A previous core whose clock was stepped back
  before it wrote therefore cannot move the boundary below an alert it
  handled.
* Enforcement settings are read from the environment at start only; the
  restart itself is the service manager's (`Restart=` in the Nexus unit,
  separate change). A restart never widens what the configuration allows.

### 1.8 Decoy redirect preconditions

A redirect is executed only when all of these hold; otherwise it is refused
(`policy_gated`, `metadata.safety.gate = refused:<reason>`,
`decoy_preconditions = unmet`) and the operator is notified with the reason:

1. **Eligibility** — §1.2 (not protected) and §1.3 (TCP, IPv4 source, a
   prepared port mapping).
2. **Separation** — `decoy_separation_evidence_path` in the redirect policy
   names a JSON file written by the deployment that placed the decoy
   (for example Nexus after putting it in its own network namespace):

   ```json
   {"schema": "azazel-edge/decoy-separation/v1", "boot_id": "<this boot>",
    "observed_epoch": 1793300000.0, "separation": "network_namespace",
    "decoy_ports": [12222, 18080], "ingress_interface": "br0",
    "ingress_path_check": {"result": "reachable", "checked_epoch": 1793300000.0,
                           "via_interface": "br0", "decoy_ports": [12222, 18080]}}
   ```

   `ingress_path_check` is the deployment's own check of the real path: a
   TCP connection from the ingress side, through `ingress_interface`, to
   `<that interface's IPv4>:<decoy port>`. The core cannot see that path
   itself (its own probe is local: an INPUT rule on the ingress, a reverse
   path filter or a wrong route are invisible to it). It must name the
   interface and the port, say `reachable`, and be at most
   `decoy_evidence_max_age_sec` old; otherwise `decoy_ingress_path_unverified`,
   `decoy_ingress_path_unreachable` or `decoy_ingress_path_check_stale`.

   It must be this boot's (`/proc/sys/kernel/random/boot_id`), name the
   decoy port and the ingress interface the core redirects on
   (`AZAZEL_DEFENSE_IFACE`; otherwise `decoy_evidence_other_interface`), say
   `network_namespace` or `separate_host`, be at most
   `decoy_evidence_max_age_sec` old (capped at 3600 s by Edge), and be a
   trusted file (regular, owner root or the core's user, not group/world
   writable, ≤ 16 KiB). Missing → `decoy_separation_evidence_missing`;
   other boot, stale, wrong port, untrusted → their own reasons.
3. **Reachability** — `nft redirect` in prerouting delivers traffic
   arriving on an interface to that interface's primary address, so the
   probe is a TCP connect to `<ingress interface IPv4>:<decoy port>` within
   300 ms (cached 5 s per address and port). A decoy listening on loopback
   only is not reached there: `decoy_unreachable` (no IPv4 on the interface:
   `decoy_ingress_interface_has_no_ipv4`).

**Release of a redirect.** Deleting the rule stops new connections from
being redirected, but connections it already redirected keep their NAT
binding in connection tracking and would stay on the decoy. So the rule also
marks what it redirects (`ct mark set <mark>`, a mark with the fixed Azazel
prefix `0xA2E` and 20 bits of the lease's id), and after the rule is verified
absent the core deletes only the tracking entries with **that mark and the
flow's tuple** (`conntrack -D -p tcp --orig-src S --orig-dst D --dport P
--mark M`; the allowlist requires the mark). Such a connection then ends;
new ones reach the real destination; a connection of the same tuple the
redirect did not take (opened before it, say) keeps going. The mark replaces
any mark the redirected connection had.

Rule absence and connection clean-up are separate states. The lease is
`released` only when both hold (`existing_connections`: `cleared` or
`none_found`). If the clean-up fails (`conntrack_unavailable`,
`failed:<why>`, a timeout), the outcome is `retry_pending` /
`connections_not_cleared`, the lease records `rule_removed_epoch` and stays
eligible, and the clean-up is retried with the release backoff until it
succeeds. To avoid that state, a redirect is not applied at all without the
`conntrack` tool (`refused:conntrack_unavailable`).

Without a policy file (the environment honeypot fallback) there is no
evidence path, so no redirect is executed. In a dry run the separation and
reachability checks are not evaluated (`not_evaluated`): a dry run opens no
connection.

### 1.9 Release ledger capacity and generation migration

The ledger keeps every terminal task as the replay guard. Before this
change it refused new actions forever once it held 4096 tasks.

* Admission compacts first when the ledger reaches 3/4 of its task bound or
  1/2 of its 2 MiB byte bound: terminal tasks unchanged for
  `COMPACT_MIN_AGE_SEC` (4200 s: longer than a lease family and the alert-age
  bound) leave the ledger, and the **checkpoint** records
  `replay_watermark_epoch`, the latest alert time (or creation time) among
  them, with a generation counter. A task whose alert is at or before the
  watermark is refused (`replayed disruptive apply blocked`), so a compacted
  task can never be replayed, even with the wall clock stepped back.
* Eligible tasks (prepared, active, uncertain) are never compacted.
* Admission stops at 7/8 of the task bound or 3/4 of the byte bound
  (`release ledger capacity reached; … (release continues)`). The rest is
  reserved for the release path, which only updates existing tasks; if a
  release save would still exceed the byte bound, it compacts and saves
  again. New actions are refused; release never stops on capacity.
* Notice: the sweep thread writes a `release_ledger_capacity` record (state
  `warning` or `full`, counts, checkpoint) to the normalized log and stderr
  when the state leaves `ok`, and every 10 minutes while it stays out.
* Maintenance entry: `azazel-edge-core --release-ledger-status` prints the
  capacity; `azazel-edge-core --release-ledger-compact` runs one migration
  under the same rules (never removes a held lease, keeps the watermark).
  Both take the same lock as the daemon (process lock plus `flock` on
  `.<ledger>.lock`). Deleting the ledger by hand is never needed and loses
  the replay guard; do not.
* Schema: `azazel-release-ledger/v2` (adds the checkpoint, the event key
  and the flow fields). A v1 ledger is read with the migration boundary of
  §1.7 and rewritten as v2; an older core refuses a v2 ledger rather than
  ignoring its checkpoint. Going back to an older core therefore needs the
  leases released first (stop the new core after its sweep has released
  them, or release by hand), since the older core will not read the ledger.

### 1.10 Evidence (S-10, Edge part)

`enforcement-evidence.jsonl` beside the ledger receives, fsynced and capped
at 8 MiB with one rotation, every decision that reached the execution path
(applied, extended, already held, failed, refused at execution or by
admission), with enforcement executing every refusal by a static rule
(protected flow, isolate, unscopable target), and every release outcome,
whatever `AZAZEL_FORWARD_LOG` says and whether the intake socket is up.
Numbering, the size check, the rotation and the append are one critical
section (the decision loop and the sweep both write), and a rotation or a
new file is made durable with a directory fsync. Each record carries a
per-run sequence number, so a rotation or a lost write shows as a gap.
Dry-run "would" decisions are not in this file (an fsync per alert would load
the decision path); they are covered by the spool below.

**Undelivered decisions** (`undelivered.rs`). Every line the forwarder could
not hand to the intake socket (no listener, refused, write timeout) or
could not even queue (queue full) goes to
`AZAZEL_UNDELIVERED_SPOOL` (default
`/var/lib/azazel-edge/undelivered-decisions.jsonl`), in every mode,
observe-only included, whatever `AZAZEL_FORWARD_LOG` says. While the intake
takes the lines nothing is written. For a small device it is buffered:
flushed every second, synced every five, never an fsync per decision;
capped (`AZAZEL_UNDELIVERED_SPOOL_CAP_BYTES`, 64 KiB–64 MiB, default 8 MiB)
with one rotated segment. Beside it, `undelivered-decisions.state.json`
keeps across restarts: runs, unclean stops (a run that ended without a clean
stop — its last second may be missing), lines spooled, lines lost before the
spool (hand-off full, or still queued for the forwarder at a clean stop),
lines the cap rotated out, and the wall-clock range of undelivered lines.
Every undelivered decision is therefore either in the spool or counted, with
its time range.

## 2. Record fields

**Observe-only outcomes keep their shape.** An outcome in mode `disabled` or
`dry_run` carries exactly the twelve metadata keys it had before this change,
which Nexus's intake (`edge_intake.py`) accepts as a closed set; a refusal's
reason is in `policy_reason`. So this Edge can be deployed before any Nexus
change (distribution order: Edge first; Nexus needs nothing for
observe-only). Every other outcome (`policy_gated`, `release_guard_failed`,
`enforced` — all refused by Nexus today as not observe-only) carries
`metadata.safety` (fixed shape), plus `release_extended_task_id` (and
`release_extensions` when extended) for a held flow, and
`release_cooldown_until_epoch` for a flow in cooldown. For a held flow the
`release_*` fields, `safety.strength` and the rollback plan are those of
the lease in force (its task, owner token, resource, expiry, strength);
the new alert is `release_merged_task_id`:

| Field | Values |
|---|---|
| `protected_set` | `not_configured`, `invalid:<reason>`, `loaded:<n>`, `loaded:<n>:not_applicable:<roles>` |
| `protected_match` | `null` or `{name, role, side}` |
| `scope` | `flow:<src>><dst>:<proto>:<port>` (`<proto>`: tcp, udp, icmp, ipv6-icmp; port 0 without one), `source_and_port:<src>:<port>`, `unscoped`, `none` |
| `gate` | `passed`, `passed:extended`, `passed:already_held`, `refused:cooldown`, `refused:<reason>`, `not_evaluated:not_executing`, `not_applicable` |
| `ttl_sec`, `ttl_source` | the bounded TTL and how it was obtained |
| `strength` | `strict`, `standard`, or empty |
| `decoy_preconditions` | `met`, `unmet`, `not_evaluated`, `not_applicable` |
| `isolate_automatic` | always `false` |

Modes and results keep their meanings (`explanations/trace.py`): a static
refusal is `selected_action: notify` with an empty plan; an execution-time
refusal is `policy_gated` / `planned_not_applied`; an admission refusal is
`release_guard_failed`; a held flow is `enforced` / `extended` or
`already_held` with no command (`release_ledger_state: merged`; the Python
explanation shows it as `held`, "HELD - existing restriction continues",
with the held lease and its expiry, and the outcome adapter binds it to the
held lease); a failed apply is `enforced` / `failed` or `partial_failure`
with `release_ledger_state: uncertain_release_scheduled`.

## 3. Relation to the Python ActionArbiter

`py/azazel_edge/arbiter/action.py` (NOC fragility, client impact) is not
moved into the core. It is the replay/dry-run decision copy and its inputs
(NOC health, client impact) are not available to the core's EVE path.
Porting it would make two implementations of one judgement. The core's rules
here are of a different kind: a declared, deterministic set of protected
endpoints and fixed bounds, which hold whether or not a NOC estimate exists.

## 4. Verification

* Unit tests (`cargo test`): every rule above, including a sweep of every
  level × high-impact flag × policy × severity × port that never reaches
  `isolate`, apply failure/timeout/readback mismatch released at once, a
  held apply not holding the sweep back, the in-flight skip, extension and
  cumulative bounds, generation migration with replay refusal, capacity
  refusal with release continuing, crash recovery, decoy evidence and
  reachability.
* Real network (`tests/test_core_scoped_actions_netns_v1.py`, root, CI
  `service-objectives` job): four network namespaces with real TCP — only the
  attack flow is limited while the management flow keeps its throughput, an
  alert naming the management host restricts nothing, the interface's
  `fq_codel` root qdisc is unchanged throughout, release at expiry restores
  the attack flow, and a wedged `nft` is killed at its bound while a due
  lease is released on time. Also: an apply that landed and then hung, an
  apply that landed with another rate, and a core killed during an apply
  that had landed all end with the rule removed (the last at restart); an
  ICMP alert limits ICMP only while TCP to the same host keeps its
  throughput; a redirect sends the attacker's connection to the named
  destination to the decoy but not its connection to another host on the
  same port, is refused while the decoy listens only on loopback, and at
  release ends a connection held on the decoy (conntrack) so a new one
  reaches the real service.
* Nexus compatibility (local, not in CI): the default-mode output of the
  new core for observe/notify/throttle/redirect, protected and portless
  alerts was fed to the fixed Nexus intake parser and all accepted; a
  `safety` key added to such an outcome is still refused (`EDGE_SHAPE`).
* `tests/test_core_nft_owned_lease_v1.py`: throttle and redirect leases
  applied, read back and released by the real core, no `input` rule.

Container and runner results are not hardware evidence.

## 5. Decided points (2026-10-30, delegated technical decisions)

Recorded by the orchestrator as delegated technical decisions:

1. **Protected set and "not applicable"**: declared in the Mission Pack,
   confirmed and recorded at commissioning, placed on the node by Nexus as
   a root-owned file. Edge only reads it. (Nexus side: to be implemented.)
2. **Decoy separation evidence** (including `ingress_interface`): written by
   Nexus at activation, after it verifies the decoy's namespace, and
   re-written within `decoy_evidence_max_age_sec`. (Nexus side: to be
   implemented.)
3. **Cooldown after a used-up lease family**: Edge-fixed 900 s
   (`FLOW_COOLDOWN_SEC`), notify only during it, no re-restriction, never
   permanent. Implemented here (§1.5).
4. **Permanent blocking and broad isolation**: not built.

Still not measured: the strength values and bounds are engineering
defaults, not measured on the target hardware.
