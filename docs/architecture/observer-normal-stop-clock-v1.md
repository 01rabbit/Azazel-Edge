# Prospective observer control stop and genuine end-clock evidence

Tracking #400/#393. Base `26d23e3b74a5af88835e5888b4757bc185f0b85f`
(#610). Commit this contract and protocol before implementation/collection.
Existing reports, refusals and incomplete historical clock records are immutable.

## Authority and scope

Add an explicit programmatic opt-in control stop to authenticated resumable
observation. This stops only the observer under its existing authority to exit;
it never stops a core/witness, invokes a provider, grants execution, resumes,
repairs history or turns unread input into observations. Production CLI/default
behavior has no new signal handler or activation flag. No service deployment,
production keys, accounts, capabilities, connection permissions or changes under
installer/security/systemd. Keep offline operation and existing UID/group/NNP,
private-FD, Source/witness, sealed-core and profile-refusal gates unchanged.

The existing v4 authenticated terminal-control registration and receipt are
unchanged. Never cast this operator/test stop as a v4 terminal proof, bypass
its profile requirements, downgrade an enforcing registration or assert that the
Source producer terminated. Fresh v3 unconfined test scopes are explicit premises,
not fallback from an enforced scope or production confinement acceptance.

## Opt-in runtime contract

`run_live_resumable` and its `telemetry.run_live` forwarding API accept optional
`stop_requested=None`. Default None preserves existing behavior. An explicit
value must be callable, authenticated, resumable and mutually exclusive with
the existing terminal-stop registration; other combinations refuse. Each query
must return exact bool. An exception or non-bool fails; it never produces a
normal-stop receipt or end anchor. `telemetry.main` keeps its signature and
integer return behavior unchanged. A scoped test wrapper captures the actual
forwarded API result; it does not infer closure from CLI exit zero alone.

Check the optional callback only at the **start of an iteration**, before its
clock reads, sample, snapshot, input processing or finalization. A request during
an iteration lets that existing iteration finish unchanged: it may include up
to MAX_BATCH_RECORDS input operations, sample/finalize/output and sleep. Do not
claim immediate exclusion at signal delivery. Do not interrupt/retry an original
callback or add a sample, finalization, source drain or special timestamp.
The observed control boundary is when the loop actually sees True; signal delivery
time remains unknown. All callback epochs/brackets stay exactly supplied/measured.

At that boundary retain the journal cursor/state and require usable authenticated
continuity, no poisoned/sealed/recovery/admission failure and no prior write error.
Break through the ordinary context managers. Existing `journal.close` must mark
each pending window explicitly lost and append its ordinary session_close through
real write/fsync/witness acknowledgement. Do not finalize pending windows or
fabricate Outcomes. Existing Source descriptor cleanup must succeed too.

After BOTH context managers really return, construct a distinct immutable
ObserverControlStop receipt. Verify actual sequence increment pending_before+1,
pending_after=0, lost_after=lost_before+pending_before, committed and input cursor
unchanged, no write failures, closed journal/source descriptors, and protected
witness journal seq/head/size matching the resulting journal state. Any skipped
close, write/fsync/witness/descriptor error prevents the receipt. Do not fabricate
a native/session-end or reset state to make closure pass.

Unread complete frames remain unread; no cursor advancement, Source drain or
extra shutdown snapshot is introduced. Existing close/witness validation still
refuses invalid/partial Source where encountered. The receipt asserts no input
completeness, whole-Source stability, exact signal receipt time or no future append.
Record those unknowns explicitly, with all admission/resume/measurement authority
flags false. Later recovery retains existing pending-loss/backlog exclusions.

## Explicit test bootstrap and end evidence

Introduce a new explicit bootstrap configuration/profile, retaining exact v1/v2
behavior and rejection rules. Root stages and pins the worker and every new
helper read-only before launch. Mode `stop_only` is the baseline; mode
`phase_and_clock` records the existing bounded spans and original clock callbacks.
Both compared on observers use the SAME prospective control-stop semantics.
Do not silently relabel old #609/#610 signal termination as normal completion.

Only the new profile installs a SIGTERM handler that sets one idempotent flag.
The handler performs no I/O, clock sampling, collector calls or exception-based
unwinding; it restores the previous handler on Python exit. Duplicate requests
cannot produce repeated close/end records. SIGKILL is unchanged and uncatchable.
The test wrapper passes the flag callback to the original run_live exactly once,
retains its genuine ObserverControlStop and validates it before leaving the
clock-recording context. Other returns/exceptions cannot authorize an end row.

Keep original clock callback rows and 900-row/4MiB bound, phase 4096-row/4MiB
and depth16 bounds. The observer samples a genuine final epoch/MONOTONIC bracket
only after real API resource closure and successful callback-recording closure.
Never substitute Root send/wait time, last callback, interpolation or expected
deadline. Root records a separate send-before/send-after bracket; it is only
request evidence, not observer delivery/end time.

A final END row alone does not prove descriptor close or process success.
Publish a separate bounded exclusive completion/stop receipt only after required
clock/phase sidecars close successfully. Bind run/arm/policy/boot/PID/start, actual
control result, file hashes and completion ordering. Require actual observer exit
0, receipt validity and original sidecar closures before new end qualification.
Close/receipt/handler failure or a forced stop keeps end eligibility withheld
even if an earlier END row exists. Preserve all prefixes; never erase or repair.

## Frozen virtual evaluation

Reuse the six fresh off/on/faulted original/instrumented arms, EVE recipe,
3-marker projection, 10/20/50/50ms polling and existing disabled enforcement.
Use the unchanged 1.2 × 2500 = 3000 non-alert lines/s, existing 2% per-class
offered-rate tolerance, actual 3-second warmup and at least 6-second window.
Keep strict final audit and **98% examined-accounting floor**. On observers
remain alive with five cursors through load, then receive the new explicit
cooperative request. Off has no observer/end. Faulted gets the original SIGKILL
at three cursors and retains two unprocessed marker decisions with no end/receipt.
No kill delay, callback additions, slow-row removal, budget increase or retries
to replace an unfavorable result. Retain failures and every assigned fresh scope.

Recompute the unchanged original **5,000,000ns qualify_clock** from actual complete
callback rows, original epochs, actual observer/controller begin/end brackets,
same boot and externally bound clock domain. Genuine normal closure only supplies
a prerequisite: an excessive row or offset envelope still withholds. Partial or
missing rows/controller anchors/bindings/process receipt stay unqualified.
No statistical, causal, physical, Pi/HIL or whole-system safety acceptance follows.

## Tests and merge gates

Explicit SYNTHETIC controls: default/legacy/v4 unchanged; before-start and
mid-iteration request; all original callbacks return/raise once; non-bool/raising
stop callback; duplicate requests; unread cursor unchanged; pending losses and
session close exactly once; poisoned/sealed/admission/recovery failure; bad/partial
Source, lost witness ACK, write/fsync/descriptor/recording-close/receipt errors;
wrong boot/PID/start/policy/scope/hash; forged END/exit-zero alone; missing original
clock or controller end; unchanged over-5ms refusal; all old caps and no backfill.

After independent precollection review run one bounded offline Linux matrix,
including actual normal on and uncatchable fault, and retain public allowlisted
original Source/trust/journal/anchor/callback/context/phase/control/audit/input
evidence without private keys. Actual normal end and its timing verdict must
replay independently. Mandatory CI must execute, never count a skip as a pass.
Require independent final-head/artifact review, all final-head CI and exact
base/head/test-merge/tree before merge. Update existing #400/#393 only.

## First bounded virtual matrix (2026-11-16 JST)

The first collection used implementation commit
`fab7b27b22e087b855d4f5a8047c7c35ce37ce94` (tree
`3ad7854e40149c4942f628d3b7f416b31ab999a0`), after the frozen contract
`817093d`. The existing aarch64 core digest was
`b735f44863a97d05b2c36f4dbfa3ca8d9206e8761b87e6df7c4677d92dddc024`.
The disposable Linux container used the same existing Root/role separation,
`--network none`, a read-only checkout/core and no added capabilities.
The required six-arm test executed: **1 passed, no skips, 49.48s**.

Both `original_on` and `instrumented_on` returned actual observer exit 0 with
valid normal-control receipts, Source authentication, witness-acknowledged
ordinary journal closure, closed resources and retained request/wait evidence.
The instrumented on arm also retained its genuine end anchor and all three
closed sidecars. Independent raw replay is a separate review gate.

All six unchanged declared 120-percent load gates passed the existing 98-percent
examined-accounting floor and marker parity. There were 108,032 written non-alert
records; actual offered rates were 2999.454–2999.790/s. The original unchanged
5,000,000ns qualifier on the **262 retained on-arm callbacks** returned qualified
sampled-anchor consistency: worst supplied-epoch/call-interval discrepancy
1,684,854ns; observed offset-envelope width 33,293ns. These are finite recorded
clock checks, not a 5ms defense-response SLA or continuous clock attestation.
The baseline stop-only arm deliberately has no clock qualification.

Both faulted arms retained actual exit -9, three processed marker cursors and
two unprocessed marker decisions; the instrumented fault prefix retained 110
callbacks with no end or completion. Off arms have no observer. Neither absence
is converted into zero, normal closure or a clock pass. Source input completeness,
future append exclusion, production custody, Pi/HIL, physical durability,
whole-system safety and comparative/causal benefit remain unqualified.
Historical #609/#610 artifacts are unchanged and their missing-end results stay
withheld. All admission/resume/whole-comparison flags remain false.

The exported report SHA256 is
`a6cb064eb296df27a36185cf77056a7070a86a5d3422fe6eca1199068decd82a`;
61 allowlisted raw originals accompany it, without private keys or bootstrap
configuration. CI must execute a fresh mandatory offline matrix on its own
platform; its measured clock result may differ and must be retained without a
threshold change or a favorable-result retry.
