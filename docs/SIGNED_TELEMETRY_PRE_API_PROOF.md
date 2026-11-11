# Fixed signed telemetry pre-API Root evidence

`signed_network_telemetry_proof.collect_pre_api` accepts only `initialize` or
`live`, an existing original three-pipe process, an independently owned EDGE
namespace identity, actual kernel boot UUID, externally frozen observer source
SHA256 and an existing protected Root output directory. It requires the existing
marked offline disposable-VM Root guard and explicit
`EDGE_SIGNED_NETWORK_TELEMETRY=1`. It neither launches a process nor sends GO.
The fixed worker argv selects `--telemetry-lab-v2` explicitly for either initialize
or live; the legacy selector remains unchanged. Root collection never sends GO.

Before an API is opened, the reviewed manual callers use this collector to
retain the consumed READY prefix (including a bound-plus-one overflow byte), raw
typed effective-unit queries and actual Root actor metadata. It checks the fixed
new unit/label/alias and 40-second lifetime, actual PID/start-time/cgroup, private
proc view, binfmt endpoint metadata and exactly three original FIFO identities.
The three literal provider namespace handles are sampled before and after;
EDGE must match the caller's owned identity. All three targets must appear in
actual actor nsfs mount rows; every row must match both the named regular
namespace object's device and inode. Identical duplicate bind rows are allowed.
Ordinary files or missing rows do not supply namespace proof. The existing precheck's public roles and two-target namespace
allowlist remain unchanged. READY alone authenticates nothing.

This is sampled Root metadata, not cryptographic observer-label binding,
continuous actor liveness, API permission/terminal-operation proof, negative
probe qualification, experiment admission or efficacy evidence. The separate
[one-boot positive connection](SIGNED_TELEMETRY_COMMISSION.md#reviewed-positive-runtime-evidence-v8-2026-11-12)
and separate signature-refusal case exercise the joined worker/orchestrator;
these narrow results do not authorize a trial. Root source/archive trust
is an external operator boundary; a caller-supplied digest is not an attestation.


## Worker fence and remaining qualification

The optional worker first verifies its fixed Linux source path, literal alias and
argv, actual enforcing new label, all real/effective/saved UID/GID values,
thread-group identity, empty capability sets, NNP, dumpability and actual boot.
Only self/source/kernel guard reads occur here. It emits the exact public READY
schema before opening trust, policy, telemetry, bounded input, journal, sidecar,
witness or live API material. The Root controller must retain and validate its
independent complete proof before supplying the exact public GO frame.
Controller/GO sending lives in the separate reviewed callers.

GO has an absolute two-second deadline and a fixed bound plus one overflow byte.
Malformed input, EOF, overflow or timeout aborts and emits the bounded consumed
control prefix as a stderr diagnostic for Root retention. Successful GO rejoins
the existing authenticated initialize/live body and terminal flow unchanged.
The experiment horizon is not involved; the existing process limit
remains 40 seconds. GO is neither durable input_ready nor API success.

Focused tests use synthetic guard identities/source/time, ephemeral trust,
synthetic witness callbacks and an explicit local input-owner adapter. The
initialize success exercises real input/authentication/journal/recovery classes;
the signed live terminal smoke uses existing synthetic API/witness callbacks.
Neither constitutes an actual UID/LSM, live authenticated permission or runtime
negative proof. Separate runtime evidence covers one exact signature refusal;
other negative behaviors and trial qualification remain open. The scoped
positive/terminal result above does not upgrade these synthetic tests. Origin
registration v4 and persistence context do not cryptographically bind the observer
label/interpreter.
