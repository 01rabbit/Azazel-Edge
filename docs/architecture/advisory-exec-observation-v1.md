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

## Actual feasibility and final product freeze BEFORE implementation

The first probe compiled but cross-UID /proc/actor/ns/pid stat was refused EACCES;
retain this failure. A scoped second probe enrolled observer's own PID namespace
and actually matched actors with the existing kernel namespace helper. Offline
Linux AArch64 raw_tp/sys_enter loaded/attached with exactly BPF+PERFMON and NNP;
two cap0/NNP UID1000 actors produced actual execve entries (benign and absent-path).
Task group-leader start_boottime matched proc startticks (USER_HZ100). This proves
only feasibility, not execveat, governance, creation or absence coverage.

FIRST PRODUCT ONLY supports native64 AArch64, rejecting other architectures
before compile/load. x86 CS/ELF checks alone do not exclude INT0x80 compatibility
syscalls; no unproven x86 profile or relaxed guard is accepted. A dedicated
mandatory ubuntu-24.04-arm CI job must run actual cases without skips. General
x86 CI still runs pure/regression tests, not a skipped substitute ARM acquisition.

Kernel mode guard reads KERNEL pt_regs.pstate and requires(pstate&0x1f)==0;
no user memory, argv or filenames. Closed actual native syscall IDs are getpid172,
execve221,execveat281,clone220,clone3435; fixed root-build headers/BTF/layout verified.
One raw_tp/sys_enter program owns ARRAY maps config1/state1/events64/stats1.
ABI exact Config56: u64 pidns_device,pidns_inode,actor_start_ticks,started_ns,
deadline_ns; u32 actor_tgid,actor_uid,user_hz,max_events. State32: u64
calibrated_at_ns,start_boottime_ns; u32 tgid,tid,uid,native_abi. Event48: u64
monotonic_ns,start_boottime_ns,syscall_id; u32 tgid,tid,uid,event_kind,native_abi,
reserved. Stats64 eightu64: observed,emitted,overflow,identity_failure,abi_rejected,
uncalibrated,creation_attempts,calibration_conflict. native_abi only1; reserved0.
event_kind is independently derived getpid0/exec1/creation2, never caller authority.

Actual getpid after attachment calibrates immutable kernel group-leader start_ns
before GO, after proc-tick/namespace/UID match. Later events require EXACT start_ns;
conflict is sticky. Initial counter/tick/proc/actor reports alone do not calibrate.
Any creation attempt, ABI/identity/calibration failure, overflow or link loss
withholds consistency. Do not attach again and repair a lost interval. Any already
valid captured exec entries survive later failure, including cleanup uncertainty;
snapshot data before owned cleanup, return partial reasons rather than erase it.
Owned link identity is sampled {fd,link_id,prog_id,link_type:1,tp_name:'sys_enter',
prog_tag}; IDs positive, tag16hex. Its normal close is not global object absence.

Nine closed actual cases: ordinary_advice,command_prose,extra_keys,
forbidden_intent,execve_success,execve_failed,execveat_failed,creation_attempt,
link_loss. Four governance cases call UNCHANGED AIGovernance.invoke and real
P0AuditLogger with a fixed declared TEST invoker, no model/network or executor
patch. Allowed ordinary/command-looking prose produces input/output-adopted;
extra executable keys produces input/review-rejected/output-fallback; execute
intent produces input/decision-blocked and zero TEST invoker calls. Real exec
controls use fixed /usr/bin/true and fixed absent paths, not advisory strings.
execveat tests only a failed fixed-path attempt. Creation control reaps its own
bounded child, while observation stays incomplete. Link-loss control loses only
own observer link AFTER a captured failed exec and preserves that positive.
These controls prove the observation layer, not native defense execution.

## Frozen data/API/intake

verify_advisory_exec_observation(plan_raw,*,expected_plan_sha256,probe_raw,
governance_raw,audit_raw) is PURE: no files/processes/network/signing/audit writes.
Plan canonical JSON+LF <=32KiB exact keys schema_version(edge-advisory-exec-plan/v1),
capture_id,case_id,kernel_boot_id,architecture(aarch64),actor,configuration,go,
worker,observer_source_sha256,observer_object_sha256,probe_sha256,
governance_sha256,audit_sha256. Actor exact tgid,uid,start_ticks,pidns_device,
pidns_inode,user_hz100,code_sha256,input_sha256. Input hash binds canonical+LF
{case_id,context,raw_payload,invoker_output} for governance cases; controls bind
canonical+LF{case_id}. Code/object/source hashes are external Root premises, not
cryptographic execution truth. Acquisition uses the fixed first-party BPF source
and externally pinned object, no arbitrary callback/command or target write.
GO exact release_before_ns/release_after_ns brackets actual pipewrite; do not
retime. Require calibration<=before<=after; event/call timestamps>=before mean
inside the possible challenge interval, not precise causation after write.
Worker exact started_ns,exited_ns,returncode,forced,error. Optional raw None iff
corresponding hash None; missing is unknown, never an empty successful measurement.

Probe canonical+LF <=64KiB, exact schema_version(edge-advisory-exec-probe/v1),
architecture,started_ns,finished_ns,configuration,calibration,events,counters,
partial_reasons,link_identity. Config/State/Event/Stats field names follow exact
ABI above; calibration may be None, counters may be None if unavailable and
link_identity may be None after actual link loss. <=64 events, strict typed uints.
Partial reason vocabulary: observer_link_lost,identity_failure,abi_rejected,
uncalibrated,creation_attempt,calibration_conflict,overflow,acquisition_error,
observer_cleanup_unverified. Raw known entries must survive missing stats/link.

Governance canonical+LF <=64KiB exact case_id,context,raw_payload,invoker_output,
result,invoker_calls,call_started_ns,call_finished_ns. Recompute exact boundary
semantics with pure existing should_invoke/sanitize_payload/validate_output only;
never invoke callbacks or logging in analysis. Audit ORIGINAL P0 serialization
is not canonical sorted wire: strict bounded parse <=64KiB/8rows, existing hash-
chain/genesis, exact stage/payload/trace/source sequence, no rotation/extra rows.
ai_assist is not a durable-kind record; no fsync/physical persistence claim.

New sealed intake collect_advisory_exec_observation(enrollment_path,*,
expected_enrollment_sha256,expected_plan_sha256). Enrollment canonical+LF32KiB,
exact schema_version(edge-advisory-exec-enrollment/v1),plan_sha256,reader_uid,
kernel_boot_id,paths:{plan,probe,governance,audit}; missing paths/hashes matchedNone.
Reuse protectedRoot0444/single-link/heldFD/allclose/actualboot reader fences,
nonroot reader distinct actorUID. Published copies may be0755 directories/0444
files; original worker/audit and sensor resources remain separate. No keys.

Diagnostic edge-advisory-exec-diagnostic/v1 separately reports nullable
governance_boundary_consistent and kernel_exec_attempt_count (>0 or None NEVER0),
coverage_disposition unknown|single_task_window_consistent, reasons/raw hashes.
Even healthy absence remains unknown; no finite safety zero. Bad audit/governance
never erases valid kernel-positive entries. Missing probe never becomes zero.
All5authorityflagsFALSE/qualified_safety_countNULL. Strict duplicate/nonfinite/
bool/depth32/size limits, old schemas unchanged, supported ARM only; native ELF,
original link and capability proof are Root/controller provenance premises.

Implementation owns pure diagnostic/intake/unit tests; Linux owner owns passive
native/FFI and nine actual cases; Root owns CI/public replay/final integration.
Freeze positive/negative/loss/unsupported/identity/bad-audit cases before code,
run appropriate regressions, exact-head review/fullCI and refs/tree before merge.

Exact four governance input literals are fixed in
tests/fixtures/advisory-exec/v1/governance.json before actual tests. Case labels
are externally registered challenge premises, not natural-language classifiers.
Pure verification binds original complete input SHA and checks actual governance
semantics; it must not execute command-looking text to classify it. Test invoker
output is data, not a real model response or native execution fact.

Public layout fixed before acquisition: EDGE_ADVISORY_EXEC_PUBLIC_DIR is fresh0755,
nine fixed case directories0755, files0444. Each has plan.json,probe.json,
actor-control.json,diagnostic.json,manifest.json. Four governance cases additionally
have governance.raw/audit.raw. Five sensor controls OMIT those two files; their
manifest slots are None, matching plan None hashes/intake None paths, never empty
measured files. Manifest has exact six filename keys (all except manifest itself),
values SHA/size or the two permitted None. Actor-control is explicitly control_only,
not independent exec evidence. A final ONCE-written case-index.json has exactnine
case keys, complete/missing artifact state and manifest hash/None; complete is not
coverage or safety. No overwrite/repair of original captured files. CI fixed64-path
upper allowlist yields54 actual files for a complete nine-case bundle. No private
fixtures/keys or native object exported; source/object hashes remain Root premises.

Build profile fixed before actual product tests: clang BPF target uses explicit
-mcpu=v3 for the immutable-calibration atomic operations. Actual kernel load must
accept that object; unsupported compiler/kernel is a retained setup failure, no
weaker fallback or capability expansion. Dedicated ARM CI's disposable OUTER
driver creates an empty network namespace before tests; this is harness setup,
not observer authority. Observer drops to exact BPF/PERFMON+NNP and actorcap0 as
before. No production networking/service or confinement configuration changes.

## Frozen post-test corrections and scope clarification

First actual product batch retained8passes/1failed link_loss test. The test cached
a stats map FD before object load, yielding-1, and injected no valid after-event
fault. Its report honestly stayed uncalibrated/unknown. Original eight public
cases and explicit missing ninth index remain immutable. Fix only that test hook
to resolve the map FD AFTERload, and publish available raw capture before verdict
assertions so future failed controls retain evidence. Index complete describes
artifact availability, never a passing test. Rerun only that failed actual case.

Focused synthetic FFI regressions independently exposed two implementation guards:
after a successful kernel identity query, /proc/fdinfo read errors9/77 must mean
unknown rather than proven lost; disconnect/destroy must preserve any foreign FD.
Capture must take a bounded exact-dict snapshot BEFORE validation/loading/alllater
reads, preventing caller mutation from shrinking the captured-event budget after
the original config was loaded. Retain these failing tests, apply only the guards
and rerun appropriate affected tests. No permissions/ABI/governance change.

Pre-GO full thread/child inventory is NOT independently observed in this slice.
The fixed single-thread test worker/code hash is an external harness premise;
calibration TID==TGID is not a census. Historical diagnostic value
single_task_window_consistent means only internally consistent calibrated target
samples, not complete process-tree/window coverage. Absence ALWAYS remains null;
unseen pre-existing tasks, direct file/network/netlink/IPC authority and native
executor isolation stay unmeasured. Do not relabel original results or add a
success flag. Any actual creation attempt still forces unknown consistency.
