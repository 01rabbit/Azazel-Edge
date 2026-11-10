# Registered read-only Rust input origin

Tracking: #400. Optional software slice; no installed service or production
activation. This connects a real Rust core calculation to the signed v3 input,
not to the live enforcing process. G6 and source commissioning remain open.

## Contract and roles

A new `outcome-input-trust/v2` public policy adds exactly one field to the
[existing trust contract](outcome-authenticated-input.md):
`origin_registration_sha256`, the SHA-256 of the **exact bytes** of an
operator-installed public registration file. The v3 journal already binds the
entire policy digest; changing registration/key/path/budgets cannot reopen an
existing scope. V1 policies remain supported for their original explicitly
selected API-only scopes; no registered scope downgrades to that profile.

The witness/operator installs the registration and policy under its protected
ownership, using preprovisioned distinct Ed25519 producer/witness keys. The
observer receives public data only. No default/shared key, runtime key generation,
installer, permission/user/capability change or service activation is added.
The capture producer remains a separate **non-root** UID. Its key and supervised
Rust origin share that trusted producer role, not the observer or AI role.

The exact `outcome-origin-registration/v1` fields are:

| Field | Requirement |
| --- | --- |
| `schema_version` | `outcome-origin-registration/v1` |
| `mode` | `readonly-core` only |
| `scope_ref`, `producer_ref`, `stream_ref`, `producer_public_key` | Exact policy match; key is public, never private material. |
| `binary_path`, `binary_sha256` | Physical absolute witness-owned regular ELF executable; single link, no set-ID or group/world write; protected ancestors; at most 64 MiB. |
| `raw_path`, `raw_uid`, `raw_device`, `raw_inode` | Physical absolute raw EVE file, independent root/witness owner, single link, protected ancestors, exact device/inode. Never the normalized/signed input or observer journal. |

Raw EVE provenance assumes trusted ownership/writer commissioning; this is not
cryptographic authentication of Suricata, the clock, boot, or upstream network
facts. Root can enroll a dishonest binary/input. The system loader/libraries,
Python capture code, dependencies and host kernel must also be trusted. A
compromised producer key/UID can forge future claims. This is an input-key and
software-image binding under those assumptions, not remote execution attestation.

## Connection and fixed authority

`input_origin.RegisteredOrigin` verifies registration, producer role, exact key,
raw identity and binary hash before signing any event. It copies the verified
image into a Linux `memfd`, seals write/grow/shrink changes and executes that
sealed descriptor through `/proc/self/fd`. Replacement or mutation of the disk
binary cannot change an already opened session's executable; a new session
must verify enrollment again. Missing memfd/seals/proc execution support refuses
operation. Python API reference: [memfd](https://docs.python.org/3/library/os.html#os.memfd_create).

For each new bounded raw EVE record, the producer invokes only that enrolled
image with the fixed `--capture-origin-once` argument. Anonymous stdin/stdout
pipes connect the parent and its child; there is no public payload-signing
socket, shell, arbitrary command argument or log-derived normalized-event
signature endpoint. The child receives a fixed minimal environment and root
working directory, with inherited configuration/loader variables removed and
only its sealed executable descriptor passed explicitly. The private key stays
in the producer process; it is not an argument, environment variable or pipe
payload. The child is in the same trusted producer UID, not a new isolation role.

The Rust mode returns **before configuration loading and normal main startup**.
It reuses `build_normalized_event` and `decide_defense`, emits a dry-run record
with zero executed commands and empty apply/release plans, and never enters
`maybe_enforce`, release recovery/sweep, forwarding, spooling or normal ingress
startup. Environment enforcement flags cannot enable that mode's executor.
Non-alert EVE records return `null`, not fabricated observations. It does not
claim these records describe what the separately running live core executed.

A signed `capture_origin` event field binds:

- `schema_version=outcome-registered-origin/v1`, `mode=readonly-core`;
- exact `registration_sha256`;
- `raw_cursor.offset` and `raw_cursor.prefix_sha256` for the consumed raw prefix.

V2-policy verification rejects missing/different registration, malformed prefix
hashes and non-increasing/out-of-budget raw offsets, even with otherwise valid
producer signatures. Existing signature chains, witness peer checks, durable
high-water acknowledgement, freshness/loss handling and inconclusive assessment
remain mandatory. No signature upgrades causal support or action authority.

## Restart, gaps and failure

At startup all bounded existing raw records must be structurally valid and
newline complete. A reopened signed source must fully verify, and the last
signed raw cursor must match the exact enrolled raw prefix. Missing/replaced,
rewound/changed or malformed history stops startup. No automatic source rotation,
key rotation/revocation, repair, reset, guessed cursor or registration refresh.

Every producer start then begins at **current raw EOF**, excluding any unread
startup/downtime suffix. It does not turn historical records into new captures.
Signed sequence/chain and raw offsets continue; only newly completed raw lines
can be signed. Live partial lines wait for newline within the bound; partial
startup records refuse. Invalid raw/child output, capacity, deadline, signature,
fsync or path failure stops the foreground producer and poisons that session.
Raw namespace and consumed bytes are checked again after the Rust calculation,
before signing, so rotation/change during that calculation refuses the append.
No signed position advances before signed source fsync. Earlier acknowledged
records are preserved. An observer independently requires its fresh matching
protected witness head before resumption; producer availability is no proof
that observation can resume. Missing windows remain lost, without baseline,
post-window, downtime telemetry or provider-execution reconstruction.

Like the existing witness, this cannot detect every unseen suffix deletion or
coordinated rollback of raw input, signed source, journal and protected anchor.
A raw cursor is a signed capture assertion; the observer/witness does not gain
arbitrary raw-file reads. Root/witness compromise and trusted-clock/whole-host
rollback need separate commissioning and external monotonic trust anchors.

## Explicit offline preparation and launch

1. Build/review the Rust core and preprovision `requirements/input-auth.txt`
   before offline operation. Use a new empty source/journal/anchor scope and
   the existing protected role/key/file ownership rules. The raw EVE file is
   owned by root/witness and readable, never writable, by the capture producer.
2. As the configured witness/operator, prepare **public candidates only**:

   ```sh
   python -m azazel_edge.outcome.input_enroll --policy /physical/new-trust-v1.json \
     --binary /trusted/azazel-edge-core --raw-input /physical/eve.json \
     --raw-owner-uid 0
   ```

   This emits a JSON object with `registration` and `trust_policy`, writes no
   files, never generates/reads private keys and refuses non-empty evidence
   scopes. Review the exact scope/key/image/raw identity. The operator installs
   the registration as canonical compact sorted JSON bytes **without a trailing
   newline**, and the resulting public v2 policy with witness ownership and
   protected ancestors. Its digest covers exact registration bytes; reformatted
   JSON is a different registration and fails. This candidate is not authority
   to update/reinitialize an existing scope. Admission rechecks all conditions.
3. Start the existing separate witness and v3 observer with this **same v2
   policy**, using their original explicit new-scope initialization flags.
4. As the producer UID, explicitly start:

   ```sh
   python -m azazel_edge.outcome.input_origin --policy /physical/trust-v2.json \
     --registration /physical/origin.json --private-key /private/producer.raw \
     --boot-ref operator-declared-producer-boot
   ```

   There is no installed unit or enabling default. On restart preserve all
   stores, enrollment and keys; omit witness/journal initialization. A genuinely
   new experiment requires a separately identified empty scope, never deletion
   of failed evidence. Production key installation is an operator activity and
   has not been performed by software tests.

## Bounds, software evidence and remaining gates

Raw bytes/records use the policy's existing finite input budgets (default
16 MiB/8192). Each raw line and child response is at most 64 KiB. One child is
active at a time; nonblocking bidirectional pipes have a five-second per-record
I/O/exit deadline and the child is killed/reaped on failure. Process creation
and kernel I/O scheduling are not hard real-time guarantees. Polling is every
200 ms; no queue, log rotation or retention eviction is introduced. Sealed image
copying and full-prefix checks are bounded but consume additional memory/CPU;
per-record subprocess cost is deliberately outside the defense hot path.

Tests use the compiled real core and actual producer/observer/witness UIDs,
network disabled and repository source read-only in local Linux validation.
They cover normal signed emission, witnessed observer reopen, excluded downtime,
wrong/missing registration/key/image, file identity/owner/link faults, raw
rewrite/truncation/partial/malformed input, sealed disk-image replacement,
retained raw-prefix rollback and v2-to-v1 downgrade refusal. Protocol tests also
inject bounded child failures/deadline/output faults; existing v1/v2/v3 journal,
SIGKILL, freshness/loss, witness and dependency tests remain in the regression.

Still open: production raw EVE writer and exact software/key/permissions
commissioning, root live-execution receipt handoff (not this dry-run sidecar),
revocation/rotation, clock/boot authentication, external monotonic anchors,
physical power loss/SD cache/durability/wear, hostile-load CPU/RSS/disk/latency,
and observer off/on/faulted live-decision parity. #393 retains independent
protected-service capture. No software pass is G6 or causal/comparative-benefit
acceptance; keep #400 open.

For actual normal-path provider/release reports, use the separately registered
[live-core connection](outcome-live-origin.md). Its v3 trust profile is not
interchangeable with this v2 read-only profile. This origin continues to assert
only dry-run calculation; its output cannot satisfy live-provider provenance.
