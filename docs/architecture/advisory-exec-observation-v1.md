# Advisory boundary and finite process-exec observation — #400/#393

Initial feasibility freeze BEFORE probe/code, baseaf025b562e65b298fceb35cfce89b5324dc9766f.

## Actual architecture and scope

Python AIGovernance.authorize/invoke/validate_output accepts advisory data;
ActionArbiter.decide returns data. The authoritative native Rust decision/execution
path forwards events outward to the agent, with no evidenced return path that
executes advisory strings. Do not invent such a bridge, patch an executor, or
report a test-only bridge as real authority conversion. Existing mocked advisory
unit tests do not establish an independently observed absence of execution.

The first useful slice exercises the named REAL AIGovernance boundary with
declared deterministic TEST invoker output (no model/network), and separately
observes actual process-exec syscall ATTEMPTS of the owned worker. This is NOT
general advisory-to-native executor isolation. Direct in-process file/network/
netlink/IPC dispatch and previously existing executors remain outside this
observation layer; qualified advisory-safety counts and authority flags stay
null/false. Native effect success, command identity and causal conversion are
not inferred from a syscall ID, worker log, process exit, counter or absent event.

## Frozen feasibility procedure

Investigate actual offline Linux support for raw syscall-entry tracing with
existing BPF/PERFMON-only observer authority and NNP. Historical lab container
edge-copy-links-actual-v1-20261113 has ONLY BPF,PERFMON,KILL,SETUID,SETGID,SETPCAP
setup capabilities, cap-drop ALL, network-none/default seccomp. Reuse this profile
as an upper bound; actual observer irreversibly drops to BPF+PERFMON+NNP before
load/attach. No SYS_ADMIN,SYS_PTRACE,NET_ADMIN,MAC_ADMIN, privileged/seccomp bypass
or additional grant. Capability insufficiency means unknown/blocked, not fallback.

Candidate kernel point raw_tracepoint/sys_enter exposes entry syscall ID. Actual
compile/load/attach/control proof is mandatory, not inferred from UDP BPF success
or kernel source/BTF existence. Freeze exact available architecture/syscall IDs
and identity helper layout from the actual environment before product collection.
Avoid target userspace memory reads; no argv/filename or execution-success claim
without a separately reviewed observable. Observer never sends/blocks/executes
defenses or writes target state. Its own bounded maps/links are separately owned.
No ptrace target stop/resume, register writes or target socket reads.

Positive feasibility controls: a fresh cap0/NNP owned actor attempts a fixed
benign executable; a separate actor attempts a fixed absent executable. Failed
attempts MUST remain observable; successful-image effects need a different layer.
Actor creation/GO/cleanup belong to the isolated harness, not the observer.
Bind exact boot/PID namespace/UID/actor PID and process-start identity, code/input
hashes and finite interval. Namespace-local versus kernel IDs must be resolved
with an actually verified existing helper, never guessed equal.

Coverage is not absence: late attachment, link loss, map overflow, unknown task
identity, incomplete interval, abnormal exit, possible child/thread escape or
missing observations keep absence unknown. Detect creation syscall attempts and
either prove a bounded whole tree or withhold coverage on ANY creation attempt.
First slice may deliberately scope to a single pre-GO thread/no-child actor;
do not quietly treat a parent-only trace as all descendant execution coverage.
Preserve known matching attempts despite later loss, never fill gaps or reattach
and reinterpret a lost interval as complete. Owned FD cleanup is not proof of
global kernel-object disappearance.

## Frozen governance controls

After feasibility, freeze exact input/config/invoker/code and process boundaries
before implementation. Actual allowed ordinary advisory is the matched normal
control; command-looking prose in allowed advice/candidate remains DATA; extra
execute/command/action output keys and execute intent exercise actual rejection.
No evaluator or invoker patch may implement command execution in the negative
path. Positive exec controls demonstrate only the independent observation layer,
not a real native defense nor a found authority-conversion vulnerability.

Publish original bounded raw kernel observations and process/control evidence
separately; Root metadata/receipts are trust premises, not cryptographic execution
authentication or production observer-key independence. No zero-for-missing,
backfill, repair, auto-resume, production keys/services/deployment, restricted
installer/security/systemd or existing enforcement/governance modification.
Offline operation and98%/1.2x/comparative timing gates unchanged.

Implementation, Linux-test and independent-review agents are reused; no nested
agents/model changes. Root integrates fixed conditions, evidence, final-head CI
and exact base/head/tree, merges only clean candidates and updates existing400/393.
If the environment cannot support passive observation, retain exact limitations
and complete only safe independently testable parts without fabricated success.
