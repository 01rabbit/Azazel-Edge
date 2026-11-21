# Finite ingress to signed Source: proposed lab freeze

Base: `6f5f5fa`. This is a dataset/collector proposal for coordinator review and
commit before implementation or collection. Runtime/schema authority belongs to
the separately frozen ingress-accounting design. No production, role, profile,
capability, default quota or Source-history changes are proposed here.

## Independent population and reusable boundaries

The dedicated fresh `finite-ingress` native-AppArmor job uses the existing
accounts/profiles, protected v4 enrollment, trusted Root launcher, sealed native
image, separate private stdout pipes, exclusive Root custody file, witnessed
Source and UID61002 read-only Source handshake. Reuse those low-level collectors,
not the seven old close-case dataset/status rules. Existing ordinary CI remains
mandatory; this new job need not manually replay its seven close experiments.

Register accounting=v1, close-receipts=v1 and ingress-accounting=v1 in the new
scope before preparation. The main variant keeps FORWARD_LOG=0. A separate fresh
`finite-ingress-fault` job registers FORWARD_LOG=1 before preparation for its one
receiver-kill experiment; the existing `native/log.jsonl` path/profile is reused.

Source callback counts are not EVE population. The actual LF records and trailing
bytes come from original Root O_RDONLY EVE snapshots. Root is explicitly a
trusted custodian, separate from native processing; this is not independent
Root-compromise attestation. The existing observer profile cannot read EVE and
gets no new grant. It continues to read only the authenticated Source.

Root opens and retains one O_RDONLY/no-follow EVE FD before each start through
all final snapshots. Observe full original metadata and stable read brackets.
This prevents physical inode recycling while that FD is held. Start input is
genuinely empty: the existing native metadata sample binds object and EOF offset
together before callbacks, and final evidence must confirm offset0/empty hash.
Between cases only, after the owned core is stopped and all prior originals are
archived, explicitly reset the synthetic EVE fixture. Never reset Source,
anchors, journal, keys or scope. Use the existing guarded single fixture
reset-failed preparation; never retry a failed experiment unchanged.

## Raw recipes and signed barriers

The companion `finite-ingress-source-protocol-v1.json` defines exact raw recipes.
JSON lines use UTF8 canonical compact sorted keys plus LF. Blank is one LF;
invalid is exactly ASCII `not-json` plus LF. The denominator is the actual saved
EVE bytes, not a generated recipe count or writer return value.

After verified native session start and the current invocation's existing
input-start barrier, append through the single owned O_APPEND writer, fsync and
join it; preserve its actual FD object, byte counts, errors and completion times.
Do not append any input after the declared end. Root waits for the specified
original signed Source event with matching session and actual ingress_origin
byte span/hash through the original verifier; sender success is never readiness.
For the repeated SID case require both distinct spans and the last end offset,
not the first matching SID. Repeated raw hashes are legal at distinct positions.

Partial-tail readiness is the last complete signed alert before the tail. The
final consumed offset/hash must stop at that complete prefix; the independent
raw end includes the exact unterminated bytes. Do not infer that an unconsumed
tail was parsed or counted. Oversized skipping includes every actually consumed
raw byte exactly once, even across polls. Never hash repeated partial read
attempts as additional consumed input.

Backlog pressure uses exactly576 flow records of16384 bytes (9MiB), between two
alerts. After readiness on empty input, Root sends SIGSTOP only to the verified
owned native incarnation and observes its actual stopped state. It appends,
fsyncs, joins and snapshots the full finite dataset before SIGCONT. Initial
backlog exceeds the unchanged8MiB threshold, so at least one flow is eligible
for actual backlog shedding. All576 flows together are below the initial flow
token allowance937. Zero rate shedding is an expected test result that must be
checked against actual counters, never supplied from this calculation. A
different result is retained as adverse evidence. The exact backlog/admitted
split is observed, never predicted from clock proximity. After resume, wait for
the final signed alert span.

Before the controlled pressure append, the existing bounded /proc FD inventory
must show no EVE object descriptor on the actually stopped native process.
Otherwise a poll may already have sampled an old empty length. An open matching
FD makes this fixed trial unavailable/adverse: archive it and stop without
resume/re-pause retries to seek a favorable scheduling point. This adds no
inspection grant; it reuses the existing Root native FD collector. Expected
rate/backlog splitting remains an actual result, not an inferred guarantee.

## Cases and expected knowledge

Main sequence:

| Case | Fixed observation |
| --- | --- |
| ingress-mixed | 9 LF records:4 alerts,3 valid nonalerts, blank, invalid. Examined9/admitted8/raw parseable records7/normalized Source activity4. |
| ingress-partial-tail | 3 complete records:alert/flow/alert, then fixed partial alert bytes. Examined3/admitted3/Source activity2; tail remains unconsumed. |
| ingress-oversize | Alert, one flow line over1MiB, alert. Examined3/admitted2/oversized1/Source activity2. |
| ingress-duplicate-sid | Two identical alert lines, same SID/raw SHA but distinct byte spans. Examined2/admitted2/Source activity2; no deduplication. |
| ingress-backlog-shed | 578 complete LF records; examined578, alerts admitted2, Source activity2, admitted flows+backlog-shed flows=576, backlog shed>=1/rate shed0. |
| ingress-rename | After first signed alert, pause owned core; rename old EVE while holding FD, create/fsync replacement at configured path, resume. Preserve both objects; finite single-object range unknown. |
| ingress-truncate | After padded first signed alert, pause; truncate/write a strictly shorter replacement on the same inode, fsync, resume. Preserve pre-mutation bytes; finite range unknown. |
| ingress-same-inode-overwrite | After first signed alert, pause; overwrite with equal-length different-SID bytes on the same inode, fsync, resume. No second signed alert is expected at the already consumed offset. Native consumed hash binds the earlier bytes; final raw hash differs. |
| ingress-native-killed | FINAL: after first signed alert and writer join, kill actual native. Keep input denominator/prefix facts; final native counts/receipt/End are absent and unknown. No next Source session. |

Mutation cases must preserve valid signed Source facts and obtain an ordinary
clean Source session end without claiming a stable ingress range. They must not
poison/reset Source to continue the matrix. Root observes mutation operations,
identities and exact before/after hashes; a missing native mutation detector is
not replaced with a fabricated flag. In particular, unchanged device/inode/size
does not prove equal-length content continuity. Do not concatenate different
object generations into an invented input stream. For rename/truncate use the
second signed marker if the original channel remains available; timeout is
adverse evidence, never a generated zero or successful fallback.

The fresh secondary job has only `ingress-receiver-killed`: append90231901 and
wait for its signed span, kill the actual receiver, then append90231902 and join
the writer. Check the actual existing normalized log by bounded stable Root
O_RDONLY reads for the second normalized event. If unavailable, do not assume
second processing; the bound native v2 ingress snapshot's actual normalization
count governs. Explicitly stop the owned core; the native may still provide its
actual final ingress snapshot while signed Source remains unclosed.
`known_unconfirmed_output = actual_native_normalized - authenticated_Source`
only when both legs bind. No End means Source completeness unknown even if that
measured difference is zero. SIGKILL's missing native snapshot leaves the final
difference null rather than a made-up zero. Neither survival nor append success
proves normalization. No source-capacity extra job is added in this slice.

## Fields, originals and bounds

Retain the new protocol/context separately from old reports. Reuse existing
close artifacts/metadata without changing their historical evaluation meaning.
Additional original EVE artifacts: `eve-start.raw`, `eve-after-writer.raw`,
`eve-before-mutation.raw` (mutation cases), `eve-held-final.raw`,
`eve-path-final.raw`; corresponding full metadata and FD identities belong to
the new Root controller receipt. The fault job also retains original
`normalized-log-before.raw` / `normalized-log-final.raw`, observed-absence or
read failure, and full stable-read metadata. Intended bytes never substitute
for an unavailable actual snapshot.

Exact controller schema `edge-finite-ingress-controller/v1`:

```text
schema_version, case_id, protocol_sha256, session_ref, range_ref,
started_ns, finished_ns, held_fd, snapshots, writer, mutation, markers, errors

OBJECT: device, inode, owner_uid, mode, nlink, size, mtime_ns, ctime_ns
held_fd: fd, object (OBJECT), opened_ns, closed_ns

snapshots: exactly the seven additional raw filenames listed above
snapshot value: null or {before (OBJECT), after (OBJECT), sha256, size, fd, flags}

writer: ordered list of append receipts
append receipt: stage, pid, tid, fd, flags, before (OBJECT), after (OBJECT),
                started_ns, finished_ns, offset_before, offset_after,
                requested_bytes, written_bytes, write_calls,
                fsync_completed, joined, joined_ns, pause, resume, error
stage: initial or post_receiver_failure

mutation: null or {kind, pid, tid, started_ns, finished_ns,
                   path_before (OBJECT), path_after (OBJECT),
                   held_before (OBJECT), held_after (OBJECT),
                   renamed_relative_name, operation_completed,
                   fsync_completed, pause, resume, error}
kind: rename_replace, same_inode_truncate_shorter,
      or same_inode_same_length_overwrite
renamed_relative_name: null except the fixed Root-owned renamed fixture path

pause/resume: null or {pid, start_ticks, signal, requested_ns,
                      observed_ns, observed_state, error}

markers: ordered list of marker receipts
marker: kind, sid, occurrence, observed_ns, session_ref, range_ref,
        source_checkpoint, ingress_origin, normalized_log_checkpoint
kind: source or normalized_log
source_checkpoint: null or existing {seq, head, size, sha256}
ingress_origin: null or the exact original runtime ingress_origin object
normalized_log_checkpoint: null or {object (OBJECT), bytes, sha256}

errors: ordered list of {stage, type, message}
error: null or {type, message}
```

These are actual observations, not caller-computed ingress evaluations. All
numeric fields reject bool; unavailable observations stay null. All modes are
full st_mode. Snapshots are actual O_RDONLY FDs with flags proving access mode0,
equal before/after metadata and exact raw byte size/hash. `object` in held_fd is
the actual initial fstat object; its opened_ns precedes native start, and it
remains open through all final snapshots and finished_ns. Close it afterward
and record actual closed_ns, so closed_ns>=finished_ns. No physical inode reuse
claim is made after that lifetime ends.

Writer fields come from the actual bounded writer thread and its actual join,
write returns, fstat/lseek and fsync return, not intended recipe counts. A short
write/error preserves actual written_bytes and errors. Pause/resume are actual
Root signal requests to the already verified native incarnation; require an
observed stopped state before a controlled mutation/pressure append. Mutation
path fields refer only to the configured EVE path, held fields only to the held
FD; no arbitrary command or path is accepted.

A source marker carries the original verified Source checkpoint and original
ingress_origin; normalized_log_checkpoint is null. A normalized-log marker has
source_checkpoint/ingress_origin null and actual original log checkpoint. It
does not invent a Source record for failed capture. Markers are matching/barrier
controls, not the denominator or a native callback counter. Parseability in
the protocol means independently counted raw parseable records, not an
instrumented callback measurement.

An actually absent optional normalized-log-before snapshot stays null with an
explicit observed-absence error at that stage, not an empty file. Other missing
or unsafe snapshots retain their stage errors. Optional log snapshots use the
unchanged8MiB log/old artifact bounds and do not consume the EVE64MiB snapshot
budget. Errors affect the relevant leg; valid EVE/Source prefixes survive.

Native last-tail fields may be stale or null when no fresh partial read was
observed. Independent raw trailing bytes never substitute for native last-tail
observation. The consumed offset/hash and raw suffix permit only the separately
stated known-unconsumed-byte fact. Runtime/source ingress_origin, native v2
snapshot and pure-analysis output schemas remain governed by the Root spec.

Raw EVE limit16MiB per snapshot and64MiB total EVE snapshots per case. Existing
Source/anchor/journal limits stay unchanged. Native private report bound4096,
receiver4096 and Root custody16384; native publication remains one nonblocking
write. Keep old private-channel/capture queue bounds. Invalid/partial/oversize/
missing Source or receipt retains independently valid raw and signed prefixes;
it never supplies measured zeros. Physical inode-ID recycling, forced receipt
publication failure and source-capacity failure remain labelled synthetic
Rust/parser cases, separate from actual kernel/native/reader trials.

Resource/clock/rate/load performance and Pi acceptance remain separate. Keep
5ms/98%/1.2x, disabled/dry-run provider facts and all existing authority flags
false. Preserve every adverse/unavailable result before another changed-code
candidate; no profile broadening, privileged observer or scope repair.

## Preparation amendment after first candidate

CI44888983528 at candidate1ffd4ae failed in both new variants before assigning
the first input case: the existing strict `systemctl reset-failed` returned1.
Its stderr was not preserved; the historical cause remains UNKNOWN. Inactive
unit unloading is a possible mechanism, not an established explanation. Both
trials remain preparation failures, all their assigned input cases NOT_RUN,
and their public inventories/logs remain preserved without success conversion.

The finite fixture may replace only that one counter-reset adapter with an
explicit persistent system-bus transaction for the fixed owned lab unit:
open one existing libsystemd client, set a bounded call timeout,
RefUnit (which loads and references atomically), independently recheck
loaded/inactive-or-failed/no-core configuration,
ResetFailedUnit exactly once, UnrefUnit in finally, then close the client.
The original Source-closed/archive guards run before this adapter. Method
returns/error names/messages and cleanup errors are recorded boundedly in the
existing Root lab results. An unavailable method/library or any failed call is
a failure, never ignored, retried, or replaced by a start. This transaction
adds no dependency, permission, unit file/property, or StartLimit change.
The old close fixture retains its original adapter. No Source/input case is
started until this separate preparation succeeds. The new candidate must be
reviewed and receive fresh full CI; the original failed trials stay failed.

The manager API and client reference semantics are documented at
https://www.freedesktop.org/software/systemd/man/256/org.freedesktop.systemd1.html;
using one connection is necessary for a reference to survive between calls.
The fixed systemd255 implementation's RefUnit loads its unit, while
ResetFailedUnit deliberately does not:
https://github.com/systemd/systemd/blob/v255/src/core/dbus-manager.c#L803-L827.

## Case-lifetime reference and failed-collection facts

CI44889796669 at candidate25baa3f collected the receiver-kill case successfully.
The main trial stopped during the first mixed case because the actual final
manager InvocationID differed from the earlier live sample. It remains a failed
collection; subsequent main cases are NOT_RUN. Saved originals/evaluation and
the successful fault originals are immutable. No missing manager ID may be
replaced by a prior ID or an invented exit.

Extend the same single client/reference from preparation through the entire
assigned case: retain it during actual start/stop, final manager/custody/store/
Source/EVE reads and public export. Unref/close exactly once after originals
are archived, or in failure cleanup after preserving all available originals.
Pending ownership before begin creates its context must also be cleaned up.
No extra Ref/reset, method/property/permission change or repeat of the failed
assignment is permitted. Each new candidate uses a fresh CI scope.

New v2 analysis may validate a typed failed collection's selector/context when
its exact pinned failure object matches controller.error (type/message strings).
This only preserves independently authenticated Source counts and stable raw
population facts. Add `collection_completed` to the v2 close result, false for
that failure. A failed collection can NEVER receive bound_finite_close or
bound_complete_input, even if other legs happen to be available. Missing native
receipt/manager completion still withholds final native counters/difference.
The old v1 evaluator remains unchanged. Original reports are not rewritten;
new diagnostic replays are additional results tied to their evaluating commit.
