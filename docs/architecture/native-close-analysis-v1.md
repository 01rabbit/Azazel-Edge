# Native close analysis v1 — exact read-only evaluation freeze

Commit before parser implementation and actual collection. Runtime/controller
schemas: native-close-receipts-v1.md. Actual/synthetic assignments and complete
export allowlist: native-close-receipts-lab-freeze-v1.md and canonical protocol
SHA256 `27b5674e1d2b7704bbb4e788ab5581fde2d7ee2f968c17d6519793217fb5639b`.

## Inputs and limits

Pure API `evaluate_native_close_receipts(artifacts, *, expected)` accepts exactly
the24 fixed public filenames listed in the lab freeze as keys. Values are bytes
or None; expected has the SAME exact keyset, SHA256 string or None for explicitly
unavailable data. Pin mismatches/invalid envelope fail qualification; optional
failure.json/evaluation.json absence is not itself a failed observation. No
missing bytes/pin becomes empty content, false ACK, zero loss or successful exit.
Recorded evaluation.json is never consumed as evidence for itself. Its supplied
external pin is validated, but its raw_sha256/pins output slots always remain
null, preventing circular hashes or changed results when replay includes the
previously recorded evaluation. Other supplied pin mismatches block status even
if that optional leg is not otherwise needed; explicit None+None is unavailable.

8MiB each Source/anchor/journal/readback; trust/registration32KiB; all controller
and auxiliary JSON128KiB; journal diagnostic64KiB; Root custody32KiB; native1024;
receiver4096 TOTAL including readiness. Maximum4096 Source/anchor rows,256 FDs
per actor, JSON depth16. Require exact canonical original JSON (trust/registration
without LF, all new JSON with LF), no duplicate keys/nonfinite numbers and exact
integer types rather than bool. Raw runtime stream parsing accepts exactly old
Root core_started line then one custody record, or one managed refusal record;
receiver exactly readiness then one close report, or one direct refusal report.
Do not extract plausible markers from extra/mixed stderr lines.

Auxiliary JSON equal their controller counterparts: actor-fd-custody.json equals
fd_custody, root-custody-object.json equals root_custody, launcher-systemd.json
equals invocation. unit-exec-start.raw is canonical actual typed exec_start;
its SHA equals invocation.exec_start_sha256. witness-boundary.json is the existing
`{source_checkpoint,anchor_checkpoint}` shape. code-pins.json is exactly
`{source_revision,protocol_sha256,core_image_sha256}`. These hash-bound copies
corroborate the explicit trusted collection premise, never attest Root merely
because an arbitrary caller supplied matching claims.

## Context and custody predicates

Require trust/registration exact bytes, existing TrustPolicy validation, v4
registered native/capture profiles, Root witness/61001 producer/61002 observer,
ACCOUNTINGv1+CLOSE_RECEIPTSv1+EVENT_STDOUToff/EVE_FROM_START0. Bind actual original
Source through SourceVerifier to exact scope/key/stream/registration/boot/session.
Source tip, signed prefix and signed End remain separate even if controller
validation later fails. Reuse original protected-anchor verifier/checkpoints.

Fixed cases/actions/custody modes are exactly the seven protocol entries; no
posthoc case selection, outcome substitution or implicit old-format upgrade.
Controller outcome is exactly `collected` for completed collection (including
expected negative trials), or `failure` with a retained error. Only collected
with error=null qualifies; it is not a claim of successful runtime completion.
attempt_ref is exactly32 lowercase hex digits. Canonical protocol has the fixed
complete base commit, and its exact raw bytes must match the frozen digest.
Check live normal challenge SIDs and downtime exclusion against signed activity,
not intended denominator. Witness-stop has its original shorter checkpoint;
native/receiver fault has no signed End. Refusal selects the actual prior unclosed
session, fresh attempted invocation and null attempted native session.

Live custody requires #620 actual actors/caps/NNP/profile and native sealed image
checks; parent/child PID/ppid/incarnation/session/image/registration binding;
Root fd1-to-file identity and complete same-incarnation FD inventories with no
Root sink descriptor in either child. Native fd1 is FIFO/write-only/CLOEXEC/
NONBLOCK; receiver fd1 FIFO/write-only/CLOEXEC, separate inode; fd2 differs from
Root sink. Root file is original Root0600/singlelink regular object; prepared size0,
same identity after writes; stable bounded readback after actual same-invocation
exit, actual typed stdout modeappend and stderrjournal. Root runtime fstat(1)
must match that independently pinned identity. Child stderr cannot supply Root
custody. Missing actual FD/custody data fails binding, never gains trust from a
body PID or journal marker alone.

Managed prelaunch refusal uses only its separately frozen Root/systemd premise:
actual ExecMainPID+InvocationID, exact protected fixed Python/service_entry
ExecStart/bundle/boot args and code pins, per-attempt fresh protected sink,
matching Root runtime fd1 metadata, actual failure exit, typed same-branch
refusal context. Live actors/FD observations may remain null. This does not
invent a launched receiver/native or claim kernel-global process absence.

## Output facts and qualification

Output schema `edge-native-close-analysis/v1`; exact keys:
`schema_version,case_id,status,raw_sha256,pins,legs,reasons,native_local_worker_ack_observed,receiver_close_report,source_authenticated,source_tip,authenticated_prefix_tip,selected_end_present,source_readback_verified,witness_checkpoint,witness_covers_selected_end,native_returncode,receiver_returncode,launcher_exit,managed_refusal_verified,stores_unchanged,authority_flags`.

- native_local_worker_ack_observed: bool only from one valid native private-pipe
  report under complete Root/live custody; otherwise null. True is local only;
  false does not invalidate signed End.
- receiver_close_report: exact three completion booleans and source_checkpoint
  only from valid private-pipe report under Root custody; otherwise null.
- source_authenticated/tips: original signature verification independent of
  reporting/custody; preserve authentic prefix on bad suffix.
- selected_end_present: actual signed End for selected session, nullable if
  context/signatures unavailable; never infer from normal process exit.
- source_readback_verified: original O_RDONLY read, same object and unchanged
  byte/hash/metadata to EOF, exactly equal retained Source; reader actor/custody
  validated as #620. Missing reader is null, not a failed Source signature.
- witness_checkpoint and witness_covers_selected_end: original signed protected
  anchor boundary; true only covering exact authentic End, false for valid
  strictly shorter coverage, null if no selected End or verification unavailable.
- native/receiver_returncode: exact Root-observed raw wait values only when
  custody/channel/child identity binds. Never infer from Source or missing PID.
- launcher_exit: `{exec_main_code,exec_main_status,result}` from bound current
  manager invocation, separately from child returns.
- managed_refusal_verified: true only valid bound managed-ready refusal, actual
  invocation exit1, no receiver/native spawn reported at the original ready gate,
  matching verified prior unclosed Source and all three state stores unchanged.
  False for contradictory measured evidence, null when missing/unbound.
- stores_unchanged: true only exact before/after bytes AND same objects/full
  mtime/ctime metadata for Source/anchors/journal around actual attempt; false
  on measured mutation, null on missing data. Outside refusals may be false
  naturally and never count as a test failure by itself.

Status is `bound_finite_close` only normal-four/restart-one with complete bound
ACKtrue/receiverclose, both child returns0, launcher normalexit0, authentic End+
RO readback and witness covering End. Witness-stop remains `bound_partial_close`
with receiver/End/waits facts but false witness coverage. Native/receiver fault
is `bound_partial_close` only authentic retained prefix, actual bound fault/waits
and no End/final count; absence alone isn't qualified failure evidence. Managed
refusal status `bound_prelaunch_refusal` requires its full predicate. Other cases
remain `unknown`; never turn partial evidence into full capture completion.

authority_flags exact `{safety_acceptance,comparison,performance,production,
deployment,resume,applied_provider_claim}` are always false. This output contains
no safety count, full-lifetime loss estimate or overall-completion flag. A finite
close label qualifies only the declared software evidence legs, not Pi/HIL,
physical durability, independent operational keys or 5ms/98%/1.2x acceptance.

Synthetic negatives include every omitted/bad pin/context/role/custody/receipt
and mutated state, forged stderr markers, report loss after signed End, false
ACK despite valid End, sender/receiver confusion, wrong original checkpoint,
short witness and restarted/mismatched process incarnation. Actual protocol
must not count unavailable ACK-timeout experiments or skipped Linux paths as
success. Preserve old outputs/originals and all failed assigned runs.
