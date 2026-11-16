# Prospective timing and observer-cost attribution v1

Tracking #400/#393. Base3e33146584df18ea223913a9f7900d74a57d558b.
Freeze before implementation and any new actual trial.

## Scope and unchanged gates

Extend existing tests-only run_observer_cost lab, not product runtime or existing
safety/clock evaluators. Original qualify_clock budget5000000ns,98% and1.2xload
remain unchanged. Historical four-VM ABBA originals/refusals stay immutable;
new instrumented process spans cannot prove their CPU/I/O/scheduling cause or
repair their clocks. No new efficacy, Pi/HIL, production or safety qualification.

Use ONLY the already-existing fresh v3 cost-lab registration profile with NO
capture/native/AppArmor profile declarations. Explicitly REFUSE instrumentation
if any profile is declared; never drop fields, fall back from an enforcing scope,
load policy or grant trace-file access to a confined role. Existing production/
QEMU-v4 confinement cannot be instrumented by these new workers and staysunknown.
No installer/security/systemd changes, services, productionkeys, new capabilities,
NET_ADMIN/BPF/SYS_ADMIN/SYS_PTRACE, groups or connection grants. Existing dryrun,
enforcementdisabled/highimpactdisabled, exact registerednative/sealedimage gate,
receiver UID/GID/groups/NNP/peer/source/witness checks remain original. Testkeys
and Root/bootstrap/kernel are lab premises, not independentproductioncustody.

## Frozen arms, workload and controls

Six fresh scopes, paired fixedorder:
original_off,instrumented_off,original_on,instrumented_on,original_faulted,
instrumented_faulted. Same existing3SIDs42001/42002/42003, exact originalTRANSCRIPT
stale epochs/inputhash, emptyobjectivepolicy,10msnativepoll/20mscontrollerpoll/
50msobserverpoll+sample and originaltimeouts/budgets. No workload/timestamp changes
or extra telemetry samples/events/finalize calls. Compare exact ordered native/
signed semantic projections across ALLsix arms (and signed cleanSourceclosure).
Observeoff means downstreamobserver absent, not unsigned/signaturefree pipeline.
Signers/witness active inALLarms. Faultafterfirstalert exactcursor3, native/signed
3decisions complete, remaining2observerdecisions unprocessed notfilled. Oncursor5
before originalSIGTERM; preserve originalSIGTERM and SIGKILL return semantics,
no specialhandler to invent a complete trace. Cleanup all ownedprocesses, preserve
failed/partial scopes separately; no retry until favorable or failedrunreplacement.

## Opt-in test bootstrap and actual phase boundaries

New pinned Root-readonly staged testworker/helper execute original input_live.main
and telemetry.main. Moduleattribute forwardingproxies ONLY (never global stdlib
patches) transform exact declaredlauncher/receiver/observer CLI shapes. Original
interpreter, policy/registration/key/boot/session args,private inheritedFD, Popen
UID/GID/groups/cwd/env/passfds/close/stdio/nativegate/seals unchanged. Receiver
transform occurs exactlyonce and refuses unknown shape/repeatedreceiver. This
is an instrumented TEST bootstrap, not identicalproductionentry/provenance.

Producer socketproxy wraps only original receiveFD constructor, originalsocket
createdonce; recv delegates SAME FD/args/flags and exact returnedbytes/exception.
No duplicate,hold,peek,extra recv,SCM_RIGHTS,buffer rewrite or forcedflush. A recv
can contain partial/multiple frames, so callordinal never implies eventidentity.
Phases: input_receive (user-space blockingrecv duration, not kernel-eventproof),
native_frame_validation,source_append(inclusive realappend),source_sign(actual
SOURCE_DOMAIN sign),source_verify(real signature-chain verification),witness_rpc
(realclient request/ack including transport/server/signature),witness_request
(realRootserver request),witness_append,witness_sign,input_snapshot,observation
(real observe_input +cursor),journal_append,observation_sample,observation_event,
finalize_due. Named fsync subspans may instrument only rolemoduleos bindings;
if unsupported leave unavailable, never inferfsynctime from totals. Alloriginal
calls executeONCE, preserving exact args/return and SAMEoriginalexception. Sidecar
failure cannot change originalcall return/exception; sticky recordingincomplete,
no measurement acceptance/backfill. No rawargs/results/exceptiontext/keybytes/
signatures/payloads/privatekeypaths/environment in publicreceipts.

Record monotonic_ns,process_time_ns andthread_time_ns bracketing actualcall body,
plus processPID/startticks,thread/nativeTID,boot/run/arm/inputSHA,phase sequence/
parent IDs and bounded nonsecret eventkind/sequence or operation enums only.
MONOTONIC elapsed is distinct from BOOTTIME processbirth; bind commonclockdomain
with actualsame time namespace/zerooffsets before any crossprocess timeline.
Unknown domain or PID reuse makes thatjoin unavailable. Individual bodyelapsed,
threadCPU andprocessCPU are differentmetrics; processCPU may include otherthreads.
Wall-threadCPU residual is not proof of I/O or schedulerdelay; negative/inconsistent
residuals unavailable, never clamped. Parent spans are INCLUSIVE and maycontain
childcalls/tracewrites; doNOTsum them or subtract unobserved gaps toassigncauses.

## Bounded trace and analysis contract

New explicit edge-phase-timing-record/v1 append-only canonicalJSON+LF hashchain,
role-owned recording under existing role-owned writableprivate/journal paths,
max4096rows/4MiB perrole, depth<=16, no secretdata. Rootowned stagedhelper+config
pins before launch; no privatekey copies/sidecar read grants acrossroles. Header
binds run/arm/role/inputSHA/code/core/interpreter/boot/processincarnation/clock;
intent records can survive kill but doNOTprove originalcall ran. Complete span
records include originalcall start/end+CPUbrackets+original outcomeclass, explicit
parent ID. Record an end marker only if actual originalnormalreturn executes it;
missing/overflow/truncated/failure/unmatched/reversed/duplicate spans stayunknown,
retain earlier valid complete spans. Record/writeCPU+elapsed overhead whereknown,
mark unallocated footer/flush overhead explicitly. Allcost metrics include actual
instrumentation within measuredprocesses; original armreports stayseparate.

New offline boundedanalyzer edge-timing-cost-attribution/v1 retains originalcost
report and phase reports/unknowns perarm; code/hash/version/workload/order/roles/
actualproc samples+SC_CLK_TCK+clockresolutions/recordlimits declared. Perphase
min/median/p95/max describe only completedobservedcalls, not populationestimates;
phase absent→null/not_exercised, missingtrace→null/unavailable, never zero-cost.
Known prefixfacts survive endmarkerloss. Per-role metrics partial if coverage
incomplete. Compare instrumented-original cost deltas descriptively only, no
causal effect or statistically powered performance claim in fixedsequentialsmoke.

Actual suppliedepoch/pre/postanchors may be recorded on callback boundaries for
readonlyanalysis; original5msqualifier is NEVER relaxed/replaced by bodyduration.
Flag bodyspans>5ms as boundeddiagnostic, but body<=5ms cannot certify original
wholewrapper/epoch/offset gate. If original full clockevidence is supplied, return
unchanged originalqualification beside newattribution; missingnewclockclosure
staysunqualified. No fittedclock/epoch shift/interpolation/droppedslowrow.

## Interpretation and missing finalization

Empty/stalepolicy exercises real finalize_due CALLS only. Appliedwindow count0
is unexercised; actualactive-window deadlinewait, outcome finalization/durability
and effect remain NULL/not_exercised, never infer them from no-opduration. Signer
cleanEOF/terminal append andcontroller processstopwait are separately recorded;
controller20ms polling is an upper detectionwait, not5ms eventedge. Rootwitness
sharescontrollerPID: its threadCPU can be measured, but RSS/IO/processCPU are
MIXEDharness+witness+trace, not standalonewitness attribution. Originalprocmetrics
retain PID/start/availablefences; faultedmissingfinalsamples yield null fullCPU/IO,
earlier peaks explicitpartial. Logicalbytegrowth/procIO are not physicalSDwear,
fsynclatency or durability. Witness/signer common cost not downstreamincrement.

## Fixed acceptance and work division

Unitdata clearly SYNTHETIC: exact return/exception passthrough, noextra recv/FDhold,
strictCLI/profile refusal, traceboundedloss/corrupt/truncated/duplicate/nesting/
clock/PID/domain, missingphase/null, original5msverdict+overbudgetpreservation,
nonadditive stats, unrelatedthreadCPU, originalreports immutable. Harness tests
require original+instrumented exactworkload/parity/faultprefix/sourceclosure,
allprocesscleanup, failurepreservation andno prohibitedactions. Onlyafterindependent
precollectionreview run boundedactualofflineLinux sixarms once; retain original
receipts/processmetrics/source+core+bootstrap hashes beforeanalysis. Required CI
no skip-as-pass; fullfinalheadCI+independentreview+exactbase/head/tree beforemerge.
All comparison/measurement/admission/resume/authorityflagsfalse; qualifiedsafety
countsnull. No new issue, no rootcause conclusion or retry/historyrepair allowed.

## Pre-collection clarification: required phase evidence

Before the first actual run, require at least one valid completed call in each
of these phase groups for every instrumented arm:

- Signer: `input_receive`, `native_frame_validation`, `source_append`,
  `source_sign`, `source_verify`.
- Witness: `witness_request`, `witness_append`, `witness_sign`.
- Controller: `controller_wait`, `source_closure_wait`; also
  `observer_stop_wait` when the observer is present.
- Observer, when present: `input_snapshot`, `source_verify`, `witness_rpc`,
  `observation`, `journal_append`.

Missing required calls make phase collection incomplete even when original
decisions match. Keep the original reports and all available trace prefixes.
Do not retry solely to replace an unfavorable result. An observer absent in
the off arm is not a recording failure. Planned SIGTERM/SIGKILL can leave
observer trace closure unknown while completed individual calls remain facts.
`finalize_due` and sample statistics describe only actual recorded calls; no
extra call is made to satisfy a coverage condition.

Write-cost brackets cover the `os.write` loop only. Serialization, hashing,
locking, metadata, clocks, final writes and descriptor close remain unallocated
within the instrumented process totals. A normal-return footer records return
from the original function, not successful descriptor close or durable storage.
An externally known recorder failure overrides a clean-looking footer without
discarding earlier verified complete calls. Child descriptor closure remains
unproven unless separately recorded; no original result is changed to report it.
