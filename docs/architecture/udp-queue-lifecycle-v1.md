# UDP queue observer lifecycle and evidence continuity — #400 / #393

## Freeze, scope and acceptance

Base PR #588 observes queue admission only. This stage tests actual observer death,
userspace stalls, owned link loss, event overflow and target identity replacement.
It grants no delivery/safety, restart or production authority. Freeze this contract
and 12 cases before implementation; old #588 fixtures and expectations stay intact.
No installer/security/systemd change, services, key deployment or environment-wide
network change. Product observer remains target-read-only with BPF+PERFMON+NNP.
Only isolated test harnesses signal their own children or close their own link FDs.

## Published versus volatile evidence

A previously returned, root-sealed and externally pinned signed report remains
byte-for-byte historical evidence after every later fault. Preserve its validated
positive lower bound. Re-reading/replaying it is not a fresh run or missing-data
replacement. Published artifacts are never extended, re-signed, renamed into a new
capture or repinned to make corruption pass. Missing intervals remain null.

Before API return/sealing, BPF maps are volatile. SIGKILL can destroy all owned
links/maps with no signed report. The harness may confirm a real event existed in
a map first, but that observation does not authorize reconstructing a sensor report.
No journal/durable recovery or one-use registration registry is added by this task.

SIGSTOP pauses the userspace loader, not the kernel BPF program. Both entry and exit
remain subject to the originally frozen absolute kernel deadline. After SIGCONT,
return only earlier valid events; no deadline extension or late data adoption.
Sampled link checks never establish uninterrupted or whole-window coverage.

## Owned link identity and loss

Actual Linux 6.8 probe: BPF_LINK_DETACH on a tracing link returns -95 EOPNOTSUPP;
GET_INFO is unchanged and has no universal attached boolean. Never hardcode
vmlinux target_obj_id=0: this kernel reports1 while attached.

After each successful attachment, cache its FD once from the still-owned libbpf
link and query kernel BPF object info. Verify tracing type2, nonzero link/program
IDs, exact expected attach type24(entry)/25(exit), matching actual program ID and
stable target object/BTF ID. Both links must target the same object/BTF function.
Read the cached FD's /proc/self/fdinfo and require link_type tracing plus matching
IDs/attach/target fields. Query object info BEFORE opening fdinfo so an already
closed FD cannot be reused by that read. Retain the exact baseline per link.

Sample those cached FD identities during waiting and immediately before teardown.
Missing, replaced or unverifiable identity is sticky observer_link_lost. Stop the
wait, never reacquire by ID, reattach, regenerate config, extend the deadline or
adopt a replacement link. Clean up remaining owned resources, then read owned maps
only after safe teardown. Preserve earlier independently bound valid events as
partial lower bounds. Missing/unpaired/overflowing data never supplies zero.

Add observer_link_lost to the existing v1 partial_reasons closed enum in provider
and evaluator. This is an explicit diagnostic extension only: report fields/domain,
all existing counts/authority and old report verification are unchanged. Older
readers may reject the new diagnostic conservatively; they cannot upgrade it.
No continuously-attached assertion or additional measurement qualification is added.

## Safe cleanup with lost/reused FDs

A libbpf pointer remains owned when only its FD was closed. Before destroying a
pointer whose cached FD is known missing/changed, call bpf_link__disconnect to skip
closing that stale FD; then destroy/free the still-owned pointer exactly once.
Never invoke disconnect/destroy on an already freed pointer. Remove ownership
BEFORE any destroy: libbpf frees the struct even if it reports an error.

Recheck identity before intentional cleanup. Healthy links use normal detach;
unknown/lost links are disowned before pointer destruction. Every remaining link
and object cleanup is attempted independently; cleanup failure blocks a result.
Do not close a foreign file that reused the FD number. No fake successful cleanup,
reattachment or retry. Hostile Root/concurrent arbitrary mutation is outside the
trusted-code boundary; identity checks are sampled and do not prove gaplessness.
Primary implementation references: Linux v6.8 kernel/bpf/syscall.c tracing link ops;
libbpf v1.5.0 src/libbpf.c disconnect/destroy semantics.

## Real fault controls

Actual harness tests must establish both hooks through kernel metadata before
traffic. Read only owned map counters/events to know when a real early event has
arrived, and immediately close temporary duplicate FDs: keeping map handles open
must not manufacture durability after observer death. Never use those harness
samples as signed sensor evidence.

Exercise SIGKILL with no published report, SIGSTOP across the fixed deadline,
entry-FD and exit-FD loss, FD reuse by an unrelated owned file, max_events1 with a
real matching burst, target PID restart with the same port, and same-process FD
number reuse with a new socket cookie/inode. Earlier events remain bound ONLY to
the original socket; new identity is never adopted. A later target lifecycle change
is partial evidence, not a reason to rewrite the frozen target or erase positives.

Expired old plans are rejected. An explicitly requested fresh run uses new run,
scope, session, capture and opportunity IDs, challenge, window and external pins.
Do not imply durable one-use enforcement for a manual repeated call within an
unexpired plan; current code provides no automatic resume or concatenation API.
No gap is filled by replaying an earlier report or resetting counters.

Real Linux fault outcomes must be distinct from mocked error/cleanup tests. Test
reader compatibility, signature/unknown semantics and exactly-once cleanup with
lost/reused FDs. Keep actual tests mandatory in CI without skip-as-pass. Final
scoped offline regressions, independent review, full CI, exact base/head/tree check
and conditional merge precede issue updates. No physical-device or production
recovery acceptance follows from these virtual experiments.
