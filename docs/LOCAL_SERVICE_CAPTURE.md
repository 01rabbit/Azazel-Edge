# Bounded local synthetic service capture (#393)

`benchmark.local_service_capture` adds an opt-in, actual separate-process
service measurement. It is deliberately outside the offline measurement/replay
modules. Nothing installs or activates it, and it imports no Edge executor,
provider, model, observer, arbiter or production service. The original nine-case,
36-assignment synthetic pilot remains unchanged.

## What is actually measured

The controller launches the fixed checked-in Python child with isolated Python
startup (`-I`), no shell, no stdin and one inherited AF_UNIX socketpair endpoint.
There is no target address, external connection, arbitrary service command or
filesystem socket. Both processes run under the caller's UID; this is process
separation, not a sandbox, separate-principal protection or authenticated source
attestation. The child performs actual requests and commits a synthetic
service-owned state value as its protected objective. It never handles a real
secret or protected resource.

The controller records actual monotonic start/end times and explicit results for
1–32 legitimate requests. Error responses remain in the transaction denominator.
A separate terminal audit on child stdout reports service-side objective commit,
start/end times and the exact request sequence. Protocol version, per-run random
challenge, child PID, request/result sequence and actual horizon coverage must
match. Client success alone never establishes objective completion. Both clocks
use the same host's monotonic counter; no external host/boot clock alignment is
established. `boot_id` in the existing capture denotes this synthetic process
session and is not a kernel boot identifier.

The actual common horizon must be 0.05–5 seconds. The controller observes it in
real time, then requests the terminal audit. Only after the child proves it was
present across that horizon is `IndependentServiceCapture.finish(H)` called.
Scheduling overhead after H is outside the recorded horizon. A goal/transaction
response beyond H, early exit, timeout, wrong challenge, missing audit or other
protocol failure raises `LocalCaptureError`, produces no receipt and reaps the
child. No truncated timeout is turned into a successful full-horizon receipt;
there is no retry, fixture substitution, missing-record backfill or automatic
repair. Readiness has one absolute one-second deadline beginning before process spawn.
Every request send/receive fragment shares the run's absolute H deadline; a
partial message cannot renew the budget. Close, child exit and audit reading
share one absolute one-second teardown deadline. The child has a single
seven-second absolute channel deadline for its entire lifetime, including
fragments, rather than a timeout renewed per byte/request. Messages are bounded
to 16 KiB. On failure, kill/reap has a separate one-second wait. These are bounds
on protocol/process waiting, not real-time guarantees for OS process creation,
kernel scheduling or Python execution.

## Freeze the local plan before running

`local_service_plan(profile=..., transactions=...)` returns the exact fixed
configuration, including protocol, transport and objective definition. Its
`manifest_digest` must equal the assigned arm's frozen `config_sha256`; changed
profiles/counts are refused before starting the child. The manifest must declare `evidence_kind=recorded_lab` and
pin the actual source checkout and environment, retain assigned denominators
and distinguish recorded local evidence from historical fixtures. This harness
does not authenticate preregistration, order execution or source pins. Keep the
manifest and source/configuration review from before the run. Do not change
existing frozen pilot manifests to force them through this capture.

Fixed controls (all are synthetic service behavior, never real defense):

| Profile | Child behavior | Expected measured truth |
|---|---|---|
| `goal_allowed` | Commit objective; legitimate success | Objective observed; zero service errors |
| `goal_denied` | Refuse objective; legitimate success | Objective censored only after full audit |
| `goal_ack_only` | Acknowledge goal without committing | No objective despite client success |
| `legitimate_error` | Commit objective; return legitimate errors | Every legitimate error counted |
| `audit_loss` | Process traffic, omit terminal audit | Failure; no normalized receipt |

The caller must supply all `SAFETY_FIELDS` as explicit independently reviewed
observations for this precise run/scope; omitted or malformed safety is refused.
The harness does not independently measure unauthorized Edge actions, protected
escape, evidence admission or advisory authority conversion. **Do not supply
zeros for those dimensions when unobserved.** When safety cannot be established,
record an unusable/missing run outside this API instead of manufacturing a
complete receipt. The closed test harness supplies zeros for its own limited
synthetic scope; those are not production security observations. A service or
monitor failure never supplies default safety or a normalized receipt.

The returned object contains the unchanged existing capture/receipt, complete
service audit and its digest, plan, protocol, controller/child PIDs and explicit
local scope. Retain the entire object privately alongside the frozen manifest
and exact evaluator revision; the receipt's evidence hash covers its existing
capture contract, while the separate audit digest binds the additional source
artifact. The API itself provides no durable write/journal/fsync guarantee.
On any exception the owning run ledger must preserve the attempted assignment
as failed/missing; a caller may not drop or silently rerun it.

Minimal invocation after the plan/manifest have been frozen and safety reviewed:

```python
from azazel_edge.benchmark.local_service_capture import capture_local_service

# frozen_manifest's assigned arm config_sha256 must already match
# manifest_digest(local_service_plan(profile='goal_allowed', transactions=4)).
result = capture_local_service(
    frozen_manifest, assignment_id, run_id=unique_run_reference,
    safety_observations=reviewed_safety_observations,
    profile='goal_allowed', transactions=4,
)
# Store the complete result without overwriting an earlier attempt.
# Only result['receipt'] enters the existing offline analysis.
```

Successful receipts feed existing `benefit.analyze` offline. They can be stored
for later review through `benefit_receipt.build_receipt` without starting another
service. This slice does not fabricate G5/Edge recordings, join an unrelated
recorded decision to a new process run, or invent clock/session linkage. An
actual Edge/service joined trial still needs independent matching evidence.

## Validation and limits

```sh
PYTHONPATH=.:py python -m pytest -q tests/test_local_service_capture.py \
  tests/test_benefit_comparison.py tests/test_measurement_path.py
```

Tests use real separate children and actual channel traffic, including denied
objectives, client ACK without objective commit, service errors, omitted audit,
forged ACK/challenge, actual response overrun, drip-byte readiness/response/
teardown and shared absolute receive deadlines, changed frozen configuration,
explicit safety failures and child cleanup. Four fresh process runs also feed
the existing paired analyzer, with process launch forbidden during analysis.
No replay fixture substitutes for these requests or measured timings.

This is local synthetic **process/transport instrumentation evidence**. It does
not measure real networking, hostile adaptive behavior, provider effects,
resource overhead, independent-UID/service protection, defense efficacy or
C0–C6/Pi/HIL/G6 acceptance. An assigned arm name never activates that arm or
proves its advertised defense ran. Analysis remains `mechanical_only`; field
budgets, sample-size/power, independent source review and final claim review
remain open.
