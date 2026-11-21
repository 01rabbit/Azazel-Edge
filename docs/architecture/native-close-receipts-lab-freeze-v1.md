# Native close receipts: disposable-lab freeze

Base: `02b036f5787d7733f1cb37d596ad6b69fe70f144`. This companion protocol and
the runtime freeze are committed before implementation/collection.

## Cases and ownership

The companion declaration is
`tests/real_systemd/native-close-receipts-protocol-v1.json`. Pin its exact canonical
bytes externally before implementation. Keep the previous accounting protocol
and its evaluation meaning unchanged.

The existing native-AppArmor job collects normal-four, restart-one, then the new
witness-stopped-close case, then interrupted-prefix and its dedicated managed
restart refusal. A separate `native-close-fault` matrix variant uses the identical
native-AppArmor preparation, accounts, capability masks and policy bytes, with
`--native-core --receipt-fault receiver-kill`. After existing baseline exercises
and native checks leave clean history, it collects only receiver-killed-prefix
and its dedicated managed refusal. Never reset/delete/migrate an unclosed Source
to run another fault. No successful unchanged-code recapture.

Keep deterministic post-End local-ack timeout testing in the Rust synthetic
module class. Receiver suspension does not delay the local native ack, and
whole-core suspension is not a deterministic actual ack-timeout oracle. Do not
add a normal-provider test knob or classify synthetic output as native capture.

## Exclusive Root output object

Before each selected managed start, including refusal, the Root controller
creates a fresh random `BASE/close-custody/<case>-<nonce>.raw` using
`O_EXCL|O_NOFOLLOW`, Root ownership, regular type, mode0600 and one link. It pins
the original object before starting. A disposable-lab unit drop-in assigns only
`StandardOutput=append:<that object path>` and `StandardError=journal`, followed
by the ordinary manager reload. This happens after existing Switch/native
baseline exercises. No repository installer/security/systemd file, existing
profile, account or actor grant changes.

For running cases the actual Root MainPID fd1 must match this object. Native and
receiver fd1 must be distinct private pipes, both fd2 must differ from the Root
object, and bounded live descriptor inventories must contain no Root-output
object in either child. This is a recorded observation, together with trusted
`close_fds=True`/explicit child stdout handling and unchanged enforcing policy;
it is not independent kernel attestation of an entire process lifetime.

Read the Root output after its invocation exits and before assigning the next
output object. Pin full original metadata, bytes and hash. Parse the exact
allowed records: at most the existing core_started record and exactly one typed
Root close/refusal custody record, with no ignored tail/extra record. Native and
receiver raw bytes are decoded only from that custody record's private-pipe
capture, including actual EOF/return codes. Journal text is diagnostic only and
cannot attribute a native record by journald PID or message proximity.

The short managed refusal occurs in `service_entry` / `service_switch.ready`
before launcher/receiver/core creation. Its typed stage is
`managed_ready_unclosed_history`; attempted native session is null. Record the
actual prior session/tip, trust/registration, boot/invocation and no-spawn branch
facts. Do not fabricate live child actors/fds. An alternate qualification uses
the actual retained systemd ExecMainPID/InvocationID, typed fixed protected
service_entry ExecStart, trusted tested code pins, fresh exclusive Root output
object and the matching typed prelaunch refusal. No-survivor observation alone
cannot prove no native launch.

## Exact controller schema

Schema: `edge-native-close-controller/v1`. Required exact top-level fields:

```text
schema_version, case_id, protocol_sha256, source_revision,
core_image_sha256, trust_sha256, registration_sha256,
boot_id, source_boot_ref, session_ref, previous_session_ref,
attempt_ref, action, custody_mode, started_ns, finished_ns,
actors, invocation, root_custody, fd_custody, stores,
reader, outcome, error

actors: launcher, native, receiver
actor: pid, ppid, start_ticks, uid, gid, groups, apparmor_label,
       cap_eff, cap_prm, cap_bnd, cap_amb, no_new_privs
native: actor fields plus image
image: sha256, owner_uid, mode, nlink, seals

invocation: unit, invocation_id, exec_main_pid,
            exec_main_start_monotonic_us, exec_main_exit_monotonic_us,
            active_state, result, exec_main_code, exec_main_status,
            exec_start_sha256, exec_start, standard_output, standard_error

root_custody: relative_name, prepared, launcher_fd1, after, bytes, sha256
object: device, inode, owner_uid, mode, nlink, size, mtime_ns, ctime_ns
fd_object: fd, device, inode, owner_uid, mode, nlink, flags

fd_custody: sampled_ns, launcher, native, receiver
role_fd_inventory: pid, start_ticks, complete, entries, errors
entries: list of fd_object, ordered by fd
errors: list of objects with exact fields fd, error

stores: source, anchors, journal
store: before, after
source/anchors: store fields plus before_checkpoint, after_checkpoint
before/after: object, bytes, sha256
Source checkpoint: seq, head, size, sha256
anchor checkpoint: counter, head, size, sha256

reader: existing exact native accounting O_RDONLY readback receipt, or null
error: type, message; null when no collection error
```

All modes are full actual st_mode. All numeric fields require exact integers,
never bool. Source is original producer-owned0644; the exclusive Root object is
Root-owned0600. `attempt_ref` is a controller nonce, never an invented native
session. For refusals, session_ref and previous_session_ref identify the actual
preceding unclosed session; runtime attempted_session remains null.

`custody_mode` is `live_parent_and_children` for running cases, or
`managed_prelaunch_refusal` for the two fixed refusal cases only. Actors and
descriptor observations unavailable for a short refusal stay null. They cannot
qualify the ordinary live-actor path.

`exec_start` contains actual typed command arrays from the fixed manager bus
getter, and exec_start_sha256 pins its separately retained canonical raw bytes.
`standard_output` is exactly `{mode,path}` from typed manager properties. When
no typed path property exists, path remains null and actual Root runtime
`root_stdout` fstat identity MUST match the independently pinned file instead.
`standard_error` is the actual typed string `journal`. No unit-text guesses.
The Root report includes actual root_stdout metadata; fast-refusal uses that
explicit trusted-code/systemd-bound premise, never invented live controller fd
samples. Unavailable mode/custody stays unknown.

Native/receiver finish and wait receipts remain separate raw inputs, not
controller-supplied evaluations. No derived acknowledgement/completion booleans
are accepted in this controller schema. The pure close annex owns their meaning.

## Public files and bounds

Export under `BASE/native-close-receipts-public/<fixed case ID>/`. The fixed
allowlist is:

```text
protocol.json, trust.json, registration.json, close-controller.json,
root-custody.raw, root-custody-object.json, actor-fd-custody.json,
native-close.raw, receiver-close.raw, launcher-systemd.json,
unit-exec-start.raw, launcher-journal.raw,
source-before.raw, source-after.raw,
anchors-before.raw, anchors-after.raw,
journal-before.raw, journal-after.raw,
readback-source.raw, reader-binding.json, witness-boundary.json,
code-pins.json, failure.json, evaluation.json
```

Trust and registration retain the original provisioned canonical bytes without
LF. New JSON is canonical plus LF. No key, bundle directory, arbitrary fd target
path or private runtime argument is exported. Observation-journal raw copies
are limited to the existing key-free synthetic disposable-lab
`bundle/observer/observations.journal`, not its directory.

Source/anchors/journal/readback are each bounded by their original configured
limit and 8MiB. The Root output is bounded32KiB; native/receiver receipt frames
retain the separately frozen runtime bound. Controller/metadata JSON is
bounded128KiB. Descriptor inventories are bounded256 entries per actor. Journal
diagnostics retain at most160 records/64KiB with explicit truncation. Missing,
oversize, partial, extra, malformed or unavailable evidence refuses the affected
leg and retains available originals/errors; no silent truncation qualifies.

For a refusal, freeze before and after raw Source/anchors/journal and full
metadata around that exact invocation, without observer journal/RPC activity
inside that boundary. Require byte equality and the same objects; retain
non-equality as adverse evidence. Read-only Source verification/readback remains
separate and does not mutate the journal. The witness-stop case freezes its
original End and then-current shorter anchors before any ordinary witness
restart; subsequent catch-up never overwrites or upgrades that prior artifact.

Stop only the exact owned lab units on failure, retaining all historical Source
and case checkpoints. The observer handshake uses the existing identity/profile
and Root process binding, without added profile rules, capabilities or sockets.
5ms/98%/1.2x, offline collection, no missing-data reconstruction and all existing
safety/comparison/production exclusions remain unchanged.

## Actual fixture start-limit separation

Run44881536133 at85af9cc preserved successful normal/restart/witness-stop
originals, but systemd refused the next declared interrupted-prefix start with
`start-limit-hit` before native creation. Its native-kill/refusal assignments
therefore remained NOT_RUN; do not report native SIGKILL success from this run.
The separate receiver-fault job completed its two assignments. Preserve all
these original outcomes; no unchanged-code rerun or original replacement.

Before each explicitly declared new case/attempt, the disposable controller
must prove the owned unit inactive/failed, no existing native process, and the
original verified Source state: closed for ordinary/fault-start cases, unclosed
ONLY for the two dedicated refusal cases. Previous invocation wait/custody must
already be harvested before any manager reset. Then exactly one `reset-failed`
prepares the fixture counter before the single start request; move the existing
refusal reset into this common preparation to avoid double reset. Never reset
after an unexpected active/unknown state or use it to retry a failed assignment.
No StartLimit setting, production policy, capability, profile, Source/history,
key, auto-restart or duplicate-exclusion rule changes. This separates cumulative
disposable-fixture starts from the actual specified evidence experiment.
