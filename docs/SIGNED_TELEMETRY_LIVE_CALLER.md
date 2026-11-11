# Fixed manual telemetry live caller (code only)

`signed_network_telemetry_live.live(output, *, abi_sha256,
interpreter_sha256, source_sha256, expected_sources, namespace_fd,
namespace_identity, initialization)` is a context manager for one fixed new live
observer unit and its original three-pipe client. It has no scope provisioning,
installation, key creation, witness/core launch, traffic, horizon or four-run
manifest. It never changes the observer, profile, authenticated schema or legacy
runner. Its actual source bytes are mandatory in the current material pin map.

The trusted Root controller supplies the **direct successful return of its
current initializer call**, not a saved JSON receipt as admission authority.
Before launch the caller reuses the initializer's protected output, current
material, closed prelaunch unit-material refusal, owned CLOEXEC EDGE descriptor,
full-PID1 cgroup absence and shared binding builder. It requires the same boot,
EDGE, source/material, both role specifications, policy and public-auth snapshot
as initialization. Initializer and live PID/unit/mode intentionally differ; each
actor has its own independently checked Root pre-API evidence.

The full successfully returned live proof `{ready,effective,actor,metadata}` and
current binding/digest are exclusively saved and file- plus directory-fsynced
before exact GO. Current material/public-auth/policy/boot/owned namespace are
rechecked first. The worker's existing two-second GO bound, forty-second role
limit and five-second stop bound remain unchanged. READY is consumed separately
from terminal stdout and is neither durable input_ready nor an experiment start.

The yielded `LiveSession` exposes only `pid`, `poll()`, `returncode` and `result`.
It owns no public pipe/wait/communicate interface. The helper exclusively drains,
waits for and reaps its owned client. The outer controller independently awaits
**actual durable input_ready**, then owns the real native core's natural stop.
It must never read/wait/communicate with the helper's client or infer readiness
from pre-API GO. The outer witness/core/namespaces remain its responsibility on
all paths. A context body that hangs is bounded by the role's existing runtime,
but this Python context manager cannot preempt arbitrary outer-controller code.

On normal exit, original remaining stdout/stderr/return code are retained before
parsing, bounded by forty seconds from launch. The unchanged worker's terminal
result is checked for exact shape/types, CONTROL flags, context versus current
Root bindings, position/length relationships, reported witness tip and ordered
anchor shapes. This is validation of a pinned worker's report, **not independent
reverification of signed wire, journal, witness endpoint or sampled-clock
qualification**. Public config/material continuity is sampled again afterward.
Both before-GO and after-terminal sampled bindings are retained before their
comparisons, including a mismatching snapshot on drift refusal.

All teardown steps independently attempt the fixed live unit's stop/full-PID1
cgroup proof, residual stream retention, owned client reap and every pipe close.
Any outer exception, parse/retention/config/cleanup error, forced reap or unknown
state stays sticky. `session.result` stays `None` until clean completion and a
successful result-file write. The receipt always keeps transition, experiment
and production-admission flags false. It proves no whole-scope quiescence.

Tests combine real private subprocess pipes with explicitly synthetic Root,
unit, role, config, READY and terminal reports. They exercise no real UID61002,
AppArmor, scope, observer API, native stop or VM. Fresh joined-source actual API
positive/negative/terminal commissioning remains required before any assignment
freeze; neither old v6 profile evidence nor these JSON fixtures qualify it.
