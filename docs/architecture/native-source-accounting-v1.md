# Registered native Source accounting v1: implementation freeze

Tracking: Edge #400/#393. Base main is
`e7b320cf24cb1a5581d04fee59489d389a624b44`. This is a new request on
2026-11-21; the completed 2026-11-17 deadline is historical, not a new gate.
Commit these conditions before implementation or collection.

## Scope and trust

Connect the actual registered Rust core through the existing trusted launcher,
private AF_UNIX socketpair/SO_PEERCRED receiver and original SignedCaptureWriter.
Direct synthetic signing is not native-origin evidence. Preserve original image
hash/0500/all-four-seals/lease, v4 native and capture enforcing AppArmor labels,
separate identities, private descriptor custody, keys and witness boundaries.
SO_PEERCRED authenticates the Root creator/parent, not the ELF: native identity
also depends on the pinned trusted launcher and sealed-image execution.

No changes under installer/, security/ or systemd/, production activation,
deployment, production keys, added capabilities or profile weakening. Reuse
unchanged existing disposable native-AppArmor CI provisioning and actor grants;
do not fall back to v1/unconfined execution when v4 is unavailable. The local
default container lacks established edge400 profiles: its actual native test
is NOT_AVAILABLE. Use cached offline builds and the mandatory real-VM CI path.
Preprovisioning is separate from network-isolated collection/analysis.

5ms, 98% and 1.2x remain unchanged. Capture correctness is not performance, Pi,
physical durability, complete EVE ingress, whole-window safety or comparative
acceptance. Normal disabled/dry-run provider facts remain such; no APPLIED claim.
Preserve old evidence, old-format evaluation meaning, failures and unknowns.

## Enrollment and explicit versioning

Add only optional registered environment `AZAZEL_LIVE_ORIGIN_ACCOUNTING=v1`.
Absent means legacy; any other value (including empty) refuses. Exact existing
registration bytes/digest bind the choice. No new trust/provenance schema or
automatic migration is introduced. Native reads this option only for an
explicit installed private live-origin descriptor. Receiver derives the expected
profile from verified registration and rejects missing/unexpected/downgraded
start profiles before signing start. An unsupported old enrolled image may
leave the existing durable uncertain prepare, but never a qualified start/end.

The outer native envelope stays `outcome-live-origin/v1`; exact legacy lifecycle
payloads stay unchanged and unmeasured. NEW opt-in lifecycle payloads are:

```text
start.capture_lifecycle = {
  schema_version: "outcome-live-origin-lifecycle/v2",
  state: "start", accounting_profile: "v1"
}
end.capture_lifecycle = {
  schema_version: "outcome-live-origin-lifecycle/v2",
  state: "end", accounting_profile: "v1",
  counts: {produced, admitted, enqueued, written, dropped, inflight}
}
```

Keep the original pipeline/source and signed capture_origin/v2. Every new field
is signature-covered. Each counter is a required exact integer, not bool, in
`0 <= n < 2**63`; unknown fields/versions or omitted fields reject. LiveState
adds defaulted fields after its existing four positional fields; legacy state
and returned old reports retain their behavior. Accounted state tracks only
decision_execution/release activity and resets per session. Preparation/start/
end are not activity. Mixed, removed or switched profiles reject. Resume and
terminal classification reuse strict lifecycle validation; do not reinterpret
new payloads as old `{state:end}` or grant old measurement eligibility.

## Finite population, atomic close and failure

The atomic native gate admission is the population's linearization point.
`produced` counts actual capture callbacks joining the open pre-close cohort,
not generated EVE lines, planned identifiers or full process-lifetime inputs.
`admitted` counts valid serialized events; `enqueued` successful queue insertions;
`written` successful complete native socket frame writes. These are not signed
Source durability counts. Local post-close rejections are outside the closed
cohort and cannot be backfilled into an already signed terminal.

Use one closed-bit/inflight atomic gate before serialization, with a bounded
CAS attempt budget (16). An admitted callback owns a guard through serialization,
counter updates and nonblocking enqueue. Guard retirement must be reliable on
every exit. Close has one owner, atomically fences further admission, waits only
in the finisher for pre-close guards, then queues exactly one End. Use one shared
one-second deadline covering guard drain and acknowledgement; preserve the
32-slot queue, event/frame bounds and existing 250ms socket write bound. No
unbounded defense-path mutex wait, new command, reconnect or shutdown replay.

For a CLEAN terminal only, require:

```text
produced = admitted = enqueued = written = receiver-observed activity_count
dropped = inflight = 0
```

The worker constructs this snapshot after all preceding activity frames are
written, not from sender expectations. Checked counters never wrap. Overflow,
CAS exhaustion, serialization/frame bound, queue saturation, disconnect, write
failure or drain timeout before terminal emission poisons capture and prevents
a valid terminal. An acknowledgement timeout may happen AFTER End/EOF and Source
fsync; it cannot retract authentic terminal bytes. Preserve those bytes and any
authenticated counter facts, but do not infer successful local acknowledgement
or overall normal capture completion from them. Later defense can continue.
No valid terminal means final produced/
loss/inflight totals UNKNOWN, even if local diagnostics or a signed prefix exist.
Do not claim complete failure/lifetime loss totals from a permanently closed
capture stream. Repeated finish cannot append another End or reopen admission.

Receiver verifies profile/counts against actual accepted activity frames. It
still withholds end until complete clean EOF/no extra or partial tail, then
original append/fsync succeeds. Native write acknowledgement is not durable
Source acceptance. Local finisher acknowledgement is a separate field and stays
unknown without positive, independently bound evidence. Finite signed-cohort
accounting can be verified separately from overall capture completion; an absent
finish receipt never silently becomes acknowledged=true. Exact durable agreement additionally requires unchanged
signed Source replay, actual receiver/launcher normal wait, original readback and
selected protected witness boundary. Regular Source is not immutable/sealed.

## Read-only recorded annex

Add a separately versioned `edge-native-source-accounting-analysis/v1` report.
Require exact actual public registration bytes and externally retained digest,
trust bytes, Source bytes/checkpoints, and selected session. Validate their
key/scope/stream/registration/profile/boot bindings and existing Source signatures.
An original structural Source replay alone does not know registration contents
and cannot prove accounting was required. Preserve that result separately.

Separate: registered profile required, authenticated declared native counters,
actual launcher/native/profile/receiver observation, stream-written count,
durably signed activity, witness-covered prefix, clean end and overall qualified
finite accounting. Missing/invalid legs stay unknown; valid authenticated prefix
facts survive bad optional receipts or suffixes. Do not import caller-computed
evaluations or join by time proximity. Actor/process/boot/session/inode/registration
and exact byte hashes must bind. Keep all safety/comparison/performance/production/
resume authority flags false and old categories unmeasured. Analysis performs no
I/O, key loading, RPC, process launch or mutation; collection is separate and RO.

## Fixed test classes before collection

Rust module tests (synthetic event concurrency, not normal-provider execution):
normal finite queue, deterministic record/close interleaving, serialization held
across close, post-close rejection, repeated/concurrent finish, oversize, queue
full, closed receiver/partial-write failure, bounded timeout/CAS/counter overflow.
Clean end cannot precede a pre-close accepted record. Preterminal faults have no
valid end; postterminal timeout controls preserve authentic end bytes but withhold
overall acknowledged/normal completion. Never discard a valid signed prefix.

Python parser/replay tests (synthetic signed fixtures, not native capture):
legacy parity; counted start/end and activity agreement; unknown/missing/bool/
negative/overflow counters; missing/switched profile; enrolled downgrade; gaps/
replay/extra/partial tail; invalid registration/key/scope/hash; prefix retention;
strict resume/terminal classification; pure/RO behavior and immutable originals.

Actual registered normal-core v4 CI cases, offline with existing permissions:

1. Normal bounded session: existing core consumes four predeclared distinct EVE
   challenges appended only after its verified start. Observe four original
   disabled/dry-run activity records, then normal stop; clean native counts4,
   Source/EOF/fsync/waits/witness/readback agree. Planned IDs are matching controls,
   never the produced denominator. Preserve exact provider facts and raw bytes.
2. Restart: one challenge inserted during stopped time is excluded, not replayed.
   After verified new start, one new challenge yields finite activity1. Bind new
   session and boot; no synthetic addition to fill the gap.
3. Final interrupted session: actual native or signer SIGKILL after a known
   authenticated prefix; no clean end/final totals, defense-preservation as
   applicable, and subsequent connected launch refuses without Source mutation.
   Preserve previously collected clean snapshots; do not reset/migrate history.

Existing negative enrollment/key/parent/profile/image/seal/duplicate gates remain
mandatory. Enforcing actual native/receiver labels and capability masks must be
observed; health JSON or image names do not substitute. Unavailable environment
means NOT_RUN, never skipped-as-pass, profile fallback or added privilege.

All fixed cases/failures/raw public evidence and externally pinned code/registration
references are retained; export no private keys. Run affected Rust/Python tests,
independent review, complete final-head CI, exact base/head/test-merge/tree and
postmerge main checks before closeout. Update existing #400/#393, keep them open.

## Recorded annex API and receipt freeze

`benchmark/native_source_accounting.py` exports the pure function
`evaluate_native_source_accounting(trust_raw, registration_raw, source_raw,
anchors_raw, controller_raw, *, expected)`. All raw arguments are exact bytes or
None. `expected` has exactly `trust_sha256, registration_sha256, source_sha256,
anchors_sha256, controller_sha256`; pins are lowercase SHA256, null only when
that raw input is absent. No derived substitute pin. Each bad leg quarantines
its qualification, not independently valid Source signature facts. JSON is
strict duplicate-free/finite canonical JSON plus LF, depth at most16; Source
retains its existing signed format. Limits: trust32KiB, registration32KiB,
controller128KiB, Source/anchors8MiB and at most4096 rows; bound before hashing
or parsing. Original library verification limits remain separately enforced.

Controller schema `edge-native-source-accounting-controller/v1` exact fields:

```text
schema_version, case_id, protocol_sha256, source_revision,
core_image_sha256, registration_sha256, trust_sha256,
boot_id, source_boot_ref, session_ref, source_identity,
prefix_checkpoint, checkpoint, native, launcher, receiver,
wait, reader, challenge_sids, observed_sids, excluded_sids,
planned_activity_count, witness_boundary, outcome, local_finish_acknowledged

source_identity: device, inode, owner_uid, mode, nlink
Source checkpoint: seq, head, size, sha256
anchor checkpoint: counter, head, size, sha256
actor: pid, ppid, start_ticks, uid, gid, groups, apparmor_label,
       cap_eff, cap_prm, cap_bnd, cap_amb, no_new_privs
native: actor fields plus image
image: sha256, owner_uid, mode, nlink, seals
wait: unit_state, exec_main_code, exec_main_status
reader: actor, source_before, source_after, access_mode, started_ns,
        finished_ns, bytes_read, sha256, complete, errors
source_before/after: device, inode, owner_uid, mode, nlink, size,
                     mtime_ns, ctime_ns
witness_boundary: source_checkpoint, anchor_checkpoint
```

Nullable unavailable receipt legs/checkpoints/actor values are retained as null
and cannot qualify a missing fact. Actual unreadable process metadata is never
invented. `local_finish_acknowledged` is null in this harness (no independent ack
receipt); authentic Source footer cannot supply it. `source_revision` is exact
tested checkout SHA, image hash matches the registered sealed running image.
The Source boot ref and kernel boot ID are separately recorded and must bind
according to the existing launcher boot-ref convention, without replacing clocks.
All numeric types reject bool. actor capability fields are actual integer masks.
All scopes/keys/stream refs and declared registration digest match the original
TrustPolicy; actual registration must be v4 with distinct native/capture labels
and the explicitly required accounting environment. Wrong/missing required
profile never qualifies. Do not use `validate_registration` for pure analysis if
it would read target paths; repeat only bounded recorded structural binding.

Actual native and receiver parents bind to the observed Root launcher PID,
process incarnations are positive, native UID/GID0 and receiver roles match
TrustPolicy. Actual enforcing labels match registration. Native image is Root
0500/unlinked/all-seals15 with exact registered SHA. Existing native/launcher
capabilities are subsets of unchanged baseline mask0x10c4, no ambient capabilities,
NNP true; receiver has zero effective/permitted/ambient capabilities. Reader
matches observer UID/GID, has no supplemental privileged groups, zero retained
capabilities, NNP true and existing enforcing observer label. Missing observations
leave the actual-native/read leg unknown, never a successful synthetic stand-in.

Readback is from the original single-link producer-owned0644 Source via actual
O_RDONLY FD with equal before/after metadata, EOF/length/hash and selected
checkpoint. It performs no key load, witness RPC or target writes. Fixed proc
metadata reads use only existing profile permissions; denial is recorded, not
fixed by rule/capability additions. Root separately exports protected anchor
bytes; this is a trusted-custodian copy, not observer access to private anchors.
Source replay and original protected-anchor chain verification remain separate.

Select the independently retained prefix checkpoint and final checkpoint exactly
by byte size/hash/sequence/head, not by time proximity. Verify the signed chain
before interpreting activity. Multiple legitimate historical sessions remain
intact; select the exact session_ref and require its boot/profile consistency.
Preserve authenticated prefix facts when later bytes or receipts fail. A prior
clean checkpoint is not overwritten by the interrupted tail. Match challenge
SIDs only as positive/negative input controls; compute activity count from actual
authenticated session records. Planned count is never the produced denominator.

Report independent leg statuses, raw hashes, exact original Source/anchor tips,
known activity prefix and declared authenticated counters separately from
`finite_accounting_verified`. That boolean needs trusted recorded native/receiver/
wait/reader/witness binding plus authenticated end, clean profile and exact actual
activity/count equality. Overall capture completion and local ack remain unknown
without separate proof. Interrupted/malformed/unregistered/missing legs retain
null qualified totals. All authority, safety, performance, comparison, production
and resume flags stay false. Legacy start/end receive `legacy_unmeasured`, never
implicit counted values or a schema conversion.

Qualification clarifications before annex implementation:

- The required protocol SHA256 is exactly
  `ddf6d2babb348e2d43307ec4c78cbd5d628778b14a273cb9d7e964f84c4fd445`.
  The three case IDs, clean/interrupted outcomes and challenge/excluded SID
  combinations must match that fixed protocol, not merely a self-consistent
  controller digest. Normal-four means four actual activity records and the
  prescribed four SIDs; restart-one means one and excludes the downtime SID.
- Qualified finite accounting requires the selected protected witness Source
  checkpoint to reach the selected session's authenticated End (at least that
  exact byte boundary). A shorter valid witnessed prefix stays a positive prefix
  fact but cannot qualify the final cohort. The anchor checkpoint remains exact.
- All mode fields contain full actual `st_mode`; check regular type and
  `S_IMODE(mode)==0o500` for native image / `0o644` for Source. Do not confuse
  permission bits with the complete mode value.
- Existing managed launch uses systemd `%b` as Source boot_ref, i.e. the kernel
  UUID without hyphens. Require `source_boot_ref == boot_id.replace('-', '')`
  for this declared CI profile, then exact signed session boot-ref agreement.
