# Virtual Linux phase-cost pilot v1

Tracking #400/#393. Conditions were committed before implementation/collection
in `timing-observer-cost-attribution-v1.md` and the v1 protocol fixture.

## Completed software and actual evidence

Source `402fd05b3e8a79f2423fd468beb5cd49903288cb` completed one bounded
network-disabled Linux container trial: six fresh original/instrumented arms
for observer off, on and faulted. All six retained identical fixed-input and
ordered decision projections, three native/signed decisions, and verified clean
signed Source closure. On arms observed five cursors; faulted arms retained
three, exited by SIGKILL and left two decisions unprocessed. They were not filled.
The mandatory Linux test passed once in 3.78 seconds, without skips.

The first container invocation used the image's default non-root account and
skipped before any arm ran. Its log is retained separately and is not acceptance.
The actual invocation used the same root driver account as the existing cost
lab, the existing default container capability set, read-only source/core mounts
and `--network none`; no capability was added. Producer/observer remained their
original distinct unprivileged UIDs. No production or enforcing profile changed.

The actual report SHA-256 is
`96fac3281cdc0c332e40d3b0e404f2d9c9a004d545b9ae7e360eeed2b5647187`.
The retained public export contains that report and eleven exact role traces;
the off arm has no observer trace. Private fixture stores remain in the stopped
disposable container. The host precollection manifest pins source/helper/core
bytes; the container cannot resolve the host worktree's Git metadata, so its
embedded `source_head` is honestly null. CI runs from a normal checkout and
uploads its own fresh report and role traces, not this local trial's artifacts.

## Descriptive measurements

The following are medians of completed calls in the **instrumented on arm**,
in milliseconds. They are inclusive, may nest and are not additive. Receiver
wait includes blocking for new bytes; controller polling detects completion
after the event and is not an exact event-edge timestamp.

| Actual call boundary | Median ms | Proven scope |
| --- | ---: | --- |
| Input receive | 55.150 | Original userspace blocking `recv`, same FD |
| Native frame validation | 0.019 | Original frame validator |
| Source append | 0.949 | Inclusive signing/verification/write path |
| Source signature generation | 0.061 | Actual Source-domain signing |
| Source fsync | 0.589 | Actual fsync call, not physical durability |
| Witness RPC | 1.331 | Client request/response, inclusive transport/server |
| Witness request | 0.805 | Server processing, separately recorded thread |
| Witness append | 0.715 | Server append, including actual fsync |
| Observation | 3.233 | Original observation and cursor progression |
| Journal append | 2.122 | Original journal append and authentication |
| Finalize-due call | 0.006 | No-op call under empty/stale policy |
| Controller detection wait | 20.936 | Existing polling function |
| Observer process stop wait | 0.694 | Existing process wait after SIGTERM |
| Source closure wait | 61.704 | Existing launcher stop and signed closure |

The active-window finalization wait remains **null / not exercised**. No
enforcement/objective window was created to measure it. A successful original
return footer does not prove trace descriptor close or durable storage.

Recorded elapsed-loop differences (instrumented minus original) were +6.53ms
off, +26.19ms on and -21.01ms faulted. Logical store-growth differences were
27,682 / 82,747 / 47,185 bytes. These include tracing and sequential scheduling
variation; the negative difference is retained. One fixed sequential smoke
does not estimate a causal performance effect, a percentile population or SD wear.

## Coverage and remaining conditions

All required phase calls were observed. Signer, witness and controller traces
have normal-return footers. Both active observers have valid partial prefixes
without footers, consistent with unchanged SIGTERM/SIGKILL. Their earlier
completed calls remain available; missing tail intervals remain unknown.

Root witness and driver share a process. Witness thread CPU is separate, but
process CPU/RSS/IO include the harness and instrumentation. Write-loop timing
excludes serialization/hash/lock/clock costs; those remain included but
unallocated in process and enclosing spans. Wall minus thread CPU is descriptive,
not a determination of I/O or scheduler cause. Cross-process timeline joins
remain unavailable without an external common-domain pin.

The original **5ms, 98% and 1.2x load gates are unchanged**. This three-alert
pilot does not exercise the 1.2x hostile workload or qualify its 98% acceptance
fraction. A short function body cannot repair an original clock qualification,
and long blocking receive/closure calls are not whole-wrapper clock errors.
Historical ABBA evidence/refusals remain unchanged. No safety count, comparative
benefit, production admission, automatic resume, Pi/HIL, enforcing AppArmor or
physical durability acceptance follows from this result.

Next evidence owners: Edge can use these opt-in test hooks for a separately
frozen workload with valid original clock evidence; the target operator retains
confinement/activation/key commissioning. Physical device, hostile load and
causal comparison gates remain open. The new helper refuses profile-declared
registrations rather than expanding their access.
