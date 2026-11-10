# Signed input from the normal defense process

Tracking: #400. Optional **software implementation**, not device commissioning,
service activation, complete telemetry, mechanism/effect proof or G6 acceptance.
It complements the [read-only origin](outcome-registered-origin.md); the two
origins are separate, non-interchangeable trust profiles.

## Facts and responsibilities

The normal Rust `process_value` path still calls `maybe_enforce`, creates its
existing `core_event`, and now optionally copies that exact event to a private
capture stream **after** the call returns. `process_release_events` similarly
copies the existing `ReleaseOutcome` event returned by the release provider.
The signer does not rerun decisions, normalize another EVE log, reclassify the
result, replay commands or create an alternative executor.

| Record | Meaning | Does not establish |
| --- | --- | --- |
| `session_prepare` | Producer durably recorded an uncertain upcoming launch attempt. | Rust started, read input or executed a command. |
| `session_start` | Enrolled normal core opened its private native reporting session. | Any provider action was applied. |
| `decision_execution` | Exact existing normal-path decision/provider result after `maybe_enforce` returned. | That a selected action ran; disabled/dry-run/gated/failed reports retain those values. |
| `release` | Exact existing release-provider result, with its own IDs, counts and postcondition fields. | A fabricated alert/Outcome, independent mechanism truth or causal success. |
| `session_end` | All queued native records reached the producer, and a normal core stop/stream EOF was verified. | Complete ingress, complete downtime telemetry, durable physical media or downstream exactly-once delivery. |

A live record is not synonymous with `applied`. Existing adapters retain their
original distinctions between provider completion, independent mechanism,
Outcome and effect; no causal-support or assessment rule changes. The read-only
origin's `capture_only` metadata cannot enter this live profile, and live facts
cannot enter its read-only verification profile.

## Optional root launch boundary and private channel

`input_live` is an explicit **trusted root launcher**, not an observer endpoint.
A root-owned public registration pins the capture public key/scope/stream,
exact root-owned ELF hash and a bounded allowlist of the existing core's
`AZAZEL_*` configuration values. It launches only that sealed image with fixed
private-channel arguments. It accepts no arbitrary command/argv, listening
socket, shell, control request, retry, hot attachment or key-generation request.
The registered environment is explicit: input/release/log/policy paths and
enforcement/forwarding choices cannot fall back to inherited environment.
Loader/Python/other arbitrary environment variables are refused. `EVE_FROM_START`
must be `0`, stdout must be `off`; stdout/old normalized logs are not evidence.
State/config/input paths must have protected root-owned ancestors; existing
leaves must have the intended type, one link, root ownership and no group/world
write. Evidence/journal/anchor paths cannot be core log/input targets. Existing
AI socket layouts not satisfying this boundary require separate commissioning,
not automatic permission relaxation.

The launcher creates an anonymous AF_UNIX stream pair before dropping the
signing worker to the registered producer UID, primary GID of the same numeric
ID and no supplementary groups. The signing worker verifies Linux `SO_PEERCRED`
for root and the exact parent launcher PID. These credentials identify the
**trusted launcher that created the pair**, not independent kernel attestation
of the subsequent Rust executable. The launcher verifies and seals the ELF,
passes the other endpoint only to that child, and closes its own endpoints.
The key's bytes are loaded only in the non-root signer; the core gets no key,
key argument, observer journal, witness key or anchor descriptor. Capture fds
are marked close-on-exec before provider commands can run. The observer still
has public keys only and the separate witness remains mandatory.

The root launcher, core and privileged witness share root's ultimate authority;
this is not root-compromise isolation. Their code, Python interpreter/modules,
loader/libraries, dependencies and invocation configuration must be trusted and
not writable by producer/observer/AI roles. A compromised root/producer key can
forge future facts. Hash-pinning an operator-selected image is not proof that
its contents or upstream Suricata/clock/boot claims are true. Registration is
an operator trust decision, not remote software attestation.

No users, ACLs/capabilities, privileged service, installer/security/systemd file,
MIO pin, default activation or new enforcement permission is installed. The
normal core's existing explicit enforcement/safety/release gates stay in place.
Do not run this launcher alongside another live core. Production service
handoff and exact key/software/permission commissioning are still operator gates.
The software tests use isolated temp files and disabled/dry-run enforcement;
this work has not started a production core or installed a production key.

## Schemas, ordering and failure

New empty scopes use `outcome-input-trust/v3`: the existing policy fields plus
`origin_registration_sha256` over **exact public registration bytes**. Its full
digest remains in the existing v3 observation-journal header; no old scope is
migrated, reset or downgraded. The registration schema is
`outcome-live-origin-registration/v1`, with exactly:

- `schema_version`, `mode=live-core`;
- `scope_ref`, `producer_ref`, `stream_ref`, `producer_public_key`: exact match;
- `binary_path`, `binary_sha256`, `launcher_uid=0`, `environment`.

The native private stream carries bounded newline JSON:
`outcome-live-origin/v1`, `session_ref` (fresh 32-digit lower hex), `seq` starting
at 1, `kind`, and the unchanged `event`. Native frames cannot inject signed
provenance or producer preparation. The signed event adds `capture_origin` with
`schema_version=outcome-registered-origin/v2`, pinned `registration_sha256`,
`mode=live-core`, the session reference/native sequence/kind. The existing
Ed25519 source envelope/sequence/hash chain remains unchanged. Session/native
sequences, types, key/scope/enrollment and replay are checked by the signer,
observer and witness before admission. Unknown or malformed records are not
skipped. Release records stay separate from alert/provider decision records.

Launch and close ordering:

```
verify registration + sealed image
 -> non-root signer verifies kernel parent/peer, key and complete source chain
 -> require previous session's verified clean end (or genuinely empty source)
 -> fsync signed session_prepare(seq=0) before reporting signer ready
 -> root launcher starts the enrolled normal core
 -> native start(seq=1), exact provider/release events, native end
 -> verify stream EOF with no extra/partial bytes
 -> fsync signed session_end (only now is the session closed)
```

Preparation is explicitly producer control metadata, never a Rust execution
fact. Failed/uncertain launch after preparation, SIGKILL, signer loss, malformed
or missing/replayed frames, queue saturation, timeout, partial/extra tail,
source capacity or I/O/sync failure leave an unclosed history. The source is
preserved; a later launch refuses before starting a new core. In particular,
an end followed by invalid bytes is never committed as a clean end. There is
no reconnect to a running core, catch-up, repair, implicit rotation, cleanup of
old evidence or automatic new scope. A failed preflight before preparation
starts no core and adds no frame. A new explicit attempt still verifies all
registration/key/history conditions; unavailable evidence has no fallback.

Once launched, signer/observer/witness failure does not stop/restart/alter the
normal defense process. The root launcher reports signer failure and keeps the
core running; its eventual exit is non-success if capture failed. Explicit
operator SIGTERM/SIGINT is forwarded to the core for normal graceful shutdown.
Automatic launch from an unclean history stays refused. Missing execution
reports remain missing; no elapsed time or later event supplies them.

## Observation windows and restart gaps

Initialize the witness and observer against the empty source **before** launching
the core; existing empty-scope and finite-budget rules apply. A running observer
that encounters preparation/start/end stops before cursor/activity mutation.
It must reopen through the existing verified journal/witness recovery path:
known pending windows become losses, startup backlog is excluded, and the
readiness fence opens a fresh collector. This deliberately trades availability
for an explicit process-boundary loss; no old baseline/post window continues
through a core restart. Lifecycle records are accepted for exclusion only from
the authenticated live profile, never as activity or provider execution.

The core starts at raw EVE EOF; stopped/unobserved intervals and startup signed
backlog are not replayed, re-signed, reconstructed or filled. Even a clean signed
session does not establish complete ingress or trustworthy clocks. Existing
witness exact-head/nonce/peer checks independently gate observer reopen; signer
readiness alone cannot authorize it. Whole-machine/coordinated store rollback,
root/witness compromise, unseen suffix deletion and independently monotonic
clock/storage anchoring retain the prior contract's limitations.

## Offline preparation and explicit launch

Preprovision the optional crypto profile and reviewed core/Python artifacts
before offline use. Create a separately identified empty evidence scope using
the existing three-role setup. As the configured root witness/operator:

```sh
python -m azazel_edge.outcome.input_live_enroll --policy /physical/new-trust-v1.json \
  --binary /trusted/azazel-edge-core --environment /trusted/core-environment.json
```

This emits public `registration` and `trust_policy` candidates without file
writes/private keys. The environment JSON explicitly declares all required
core paths and choices; unknown variables/replay/stdout evidence are refused.
Review the image and configuration; install exact canonical compact sorted
registration bytes without a newline and the resulting public v3 policy under
protected root ownership. Candidate output is not authority to change an old
scope or enable enforcement. Start the separate witness and observer with this
same policy and their original new-scope flags, then explicitly launch:

```sh
python -m azazel_edge.outcome.input_live --policy /physical/trust-live.json \
  --registration /physical/live-origin.json --private-key /private/producer.raw \
  --boot-ref operator-declared-core-boot
```

`--receive-fd`/`--session-ref` are internal inherited-channel flags, not a public
signing service. No existing process is attached; preserve any service's current
state until a separately reviewed commissioning handoff. Do not delete a failed
source to claim continuity. Revocation/rotation and forensic reconciliation are
not implemented by this slice.

## Bounds, tests and remaining gates

The core has 32 queue slots, at most 60,000 serialized event bytes, 64 KiB native
frames and a 250 ms worker write timeout. Hot-path enqueue uses `try_send` and
never waits for the signer/fsync/witness. Oversize/full/failed capture is
permanently poisoned and its private stream closed; the defense path continues.
Graceful capture shutdown waits at most one second. The signer bounds each
native frame to 64 KiB and retains existing finite source/journal/anchor budgets;
there is no unbounded queue or rotation. The image remains at most 64 MiB.
Actual CPU/RSS/fsync/latency/hostile-load costs on Pi and kernel scheduling/disk
power-loss guarantees are unmeasured. Source resumption uses protected signed
history; it does not claim physical durability or absolute host anti-rollback.

Tests include the compiled normal core with real root/producer/observer UIDs,
private peer/parent checks, exact disabled-provider records, witnessed observer
reopen, clean new sessions and downtime exclusion, signer/core SIGKILL and full
source behavior, malformed/replayed/read-only/extra-end records, preflight
refusal without launch, fd close-on-exec, unchanged core progress after capture
failure, and pending-window loss across lifecycle recovery. Synthetic provider
applied/failed/partial and release fixtures check preservation and conservative
adapters; they are not hardware execution or independent effect evidence.

Edge owns this optional connection and remaining production commissioning,
rotation/revocation and trusted software/clock/boot work. #400/G6 retains actual
power cuts/storage/cache/wear, Pi CPU/RSS/disk/latency and observer off/on/faulted
live-decision parity. #393 retains independent protected-service measurement;
external/TPM monotonic anchoring remains separate. Keep #400 open. Passing the
software CI does not authorize deployment or prove comparative/causal benefit.
