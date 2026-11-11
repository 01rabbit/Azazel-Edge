# G3 authenticated capture and protected-prefix witness

Tracking: #400. Status: optional software implementation; **G6 and production
commissioning remain open**. New v3 pathname scopes or explicit v4 abstract
scopes only; no automatic migration or unsealing.

## What is authenticated

A configured **capture producer** signs canonical input envelopes using Ed25519.
The observer has public keys only. A separate-UID local witness owns a second
signing key and a private, fsynced high-water log. The witness verifies capture
signatures and anchors the complete source prefix it sees together with the
exact observation-journal head before acknowledging a journal append.

This authenticates the configured capture key and detects changes to protected
observed prefixes. It does not prove that a captured Rust claim is true, that a
provider applied a mechanism, or that an alert timestamp is execution-completion
truth. No signature upgrades an Outcome, causal-support or tactical assessment.
The existing G1/G3/G5 contracts remain authoritative and inconclusive where
proof is missing. `SignedCaptureWriter` is an explicit producer API accepting
origin-capture facts; it never automatically tails/re-signs an unauthenticated
log. The [registered read-only Rust origin](outcome-registered-origin.md) adds
an explicitly enrolled private-pipe connection outside the enforcing hot path;
ordinary v1 trust scopes retain this API-only contract.

The implementation uses the PyCA [Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).
No cryptographic primitive is implemented locally. Source, anchor and response
signatures use distinct domain prefixes; producer and witness keys must differ.
Raw private keys are 32-byte files, mode `0600`, owned by the signing role, with
no symlink component or hard link. There is no default key, environment-secret
fallback, auto-generation, signing endpoint in the observer, or reuse of the
agent's shared HMAC capsule/transport keys.

## Roles and offline boundary

| Role | UID/key | Files and capabilities |
| --- | --- | --- |
| Capture producer | Its own UID and capture private key | Explicit bounded signed append API on its precreated source; no observer or defense capability. |
| Observer | Different UID, **public keys only** | Existing private `0700` journal directory/`0600` file; read-only authenticated input; Unix witness client. No signing key or anchor write access. |
| Witness | Third UID and witness private key | Read-only access to the two fixed configured source/journal paths; exclusive writer to its own private anchor log; fixed local Unix endpoint. No executor, provider, network route, approval or release capability. |

All three UIDs must differ; capture producer and observer must be non-root.
Their isolation also assumes no privileged capabilities or ACLs grant key or
anchor access across those roles. Protected file ancestors must belong to root or the declared file role and
cannot be group/world writable (root-owned sticky transit directories are
allowed). In particular, a root-owned anchor below an observer-owned parent
is refused: private leaf modes alone do not prevent directory replacement.
Witness code, dependencies and launch configuration must also be trusted and
not writable by the producer/observer. The Linux tests use producer 1000, observer 65534,
witness 0, with real UID changes in child processes. A privileged witness can
read the existing observer-private journal; an unprivileged witness would need
separately reviewed read access/capability provisioning. This PR grants no
privileges, creates no users and installs/enables no unit. A privileged witness
is an additional opt-in trust boundary requiring commissioning review, not a
reason to run the observer as root or relax its private file modes.

The witness accepts only the configured observer UID using Linux
`SO_PEERCRED`. The client verifies the peer witness UID and pinned public key.
The socket parent belongs to the witness and has no group/world write; the
socket is connectable but unauthorized UIDs are refused before request parsing.
Only `read` and compare-and-`advance` of the fixed scope are supported. Requests
cannot name arbitrary paths, sign payloads, issue commands, clear state or
reinitialize. No IP socket, DNS, HTTP service, subprocess or model is used by
these runtime modules. An unavailable/unsupported Unix peer check is refusal,
not a transport fallback. Runtime operation needs no network connection.

## Signed source and trust configuration

`outcome-signed-input/v1` envelopes contain scope/producer/stream/boot references,
strict sequence starting at 1, previous signed-envelope digest, canonical Rust
capture event and signature. The hash chain covers the whole signed envelope.
Canonical JSON, exact schema, signature, identity, order and byte/record bounds
are checked before any event reaches the collector. Duplicate keys, nonfinite
numbers, altered payloads, extra fields, missing/deleted/reordered/duplicated
frames, unsigned input and another key/scope/stream are refused. Capture boot
references are signed claims; sequence never resets on a producer API reopen.

`--input-auth-policy` supplies a public `outcome-input-trust/v1` JSON file owned
by the witness UID, with no group/world write or symlink component. Role/euid
must match. The validated configuration is immutable and its canonical digest
binds both source verifier and v3 journal header. The exact fields are:

- `schema_version`, `scope_ref`, `producer_ref`, `stream_ref`, `witness_ref`;
- `producer_public_key`, `witness_public_key`: distinct 32-byte lowercase hex;
- `producer_uid`, `observer_uid`, `witness_uid`: three distinct numeric UIDs;
- physical absolute `source_path`, `journal_directory`, `socket_path`,
  `anchor_directory`; the named Unix socket path is at most 100 encoded bytes;
- `input_max_bytes`, `input_max_records`, `journal_max_bytes`,
  `anchor_max_bytes`, `anchor_max_records`.

The ordinary v2 byte/record limits remain. Anchor defaults in the tested profile
are 16 MiB / 32768 records; allowed limits are 128 KiB..64 MiB / 2..131072.
Keys, scope, paths and budgets cannot be changed to resume an existing scope.
No automatic key rotation/revocation or re-enrollment is implemented. Offline
key provisioning and permission setup are operator responsibilities.

## Acknowledgement and restart ordering

```
verify authenticated source snapshot
 -> append observation journal frame + file fsync
 -> witness checks extension of its protected source/journal prefixes
 -> append signed witness anchor + witness file fsync
 -> fresh-nonce signed response with exact journal head
 -> apply/acknowledge observer state (then eventual result emission)
```

This order applies to every journal frame, including header, begin, loss,
cursor, readiness fence, commit and clean close. The witness checks the exact
next journal sequence, chained frame integrity, fixed v3 trust/scope header,
file identity, preservation of its earlier byte prefixes and presence of cursor
positions in the authenticated source. It witnesses **append-only prefixes**,
not the semantic truth of arbitrary future observer facts.

The observer must receive a pinned-key response over its fresh random nonce,
with the exact journal sequence/hash/size. Copied signed responses cannot
provide fresh authorization. The witness counter and previous anchor hash
provide compare-and-advance serialization. Anchor logs are signed, chained,
locked, private, finite and fsynced; creation additionally syncs their directory.
Live anchor backing bytes and namespace are checked before a fresh proof and
before/after append; same-size corruption cannot be hidden by process memory.
Existing logs are validated/re-synced, never truncated, rotated, evicted or
reinitialized when missing, corrupt, partial, unsafe or exhausted.

On restart the source and journal are validated, then a fresh witness query
must match the **entire current journal head exactly** before any recovery
write or new admission. A shorter/changed source than the protected witness
prefix is rejected even if its bytes carry valid old signatures and the input
cursor was still zero. Rewinding the journal, or both journal and source, cannot
pass while the protected witness retains the later high-water state. Signed
forks from the same capture key also conflict with the first protected prefix.

Only after this check does the existing recovery path tombstone unfinished
windows, exclude unread startup records and fence a genuinely new telemetry
segment. Retained duplicate/lost executions cannot reopen windows or add
baseline activity. Nothing reconstructs, extends or fills missing telemetry.

## Fault policy and exact guarantee boundary

| Fault | Result |
| --- | --- |
| Missing/wrong key, signature, schema, role, peer, policy, scope or freshness | Refuse; no unsigned/v2/EOF fallback. |
| Source rewind/fork/alteration of a protected prefix | Refuse; no guessed cursor or repair. |
| Journal durable, witness did not durably acknowledge | Commit gap: **refuse automatic catch-up/resume**. Preserve both stores for explicit review. |
| Witness durable, response lost before observer acknowledgement | Poison current observer. On reopen an exact matching protected head may recover, with pending windows lost. |
| Witness write/sync failure | No success response; poison witness writes, no retry/fallback. |
| Missing/corrupt/exhausted witness log or absent service | Refuse; never silently bootstrap a replacement anchor. |

Known unacknowledged commit gaps may therefore reduce availability. This is
intentional: no same-process heuristic can establish whether discarded bytes
were previously acknowledged. Root can inspect preserved evidence separately;
no reconciliation/repair/reset endpoint is provided.

**Protected-prefix scope:** detection covers source/journal history durably
acknowledged by the separate trusted witness. Removal of an unseen or unwitnessed source suffix may remain undetected;
startup remains an observation gap, never proof of complete input. A compromised signing key can create future false capture claims; witness
signatures do not make them true. Compromise/rollback of the witness UID/key,
or coordinated restoration of **source + journal + protected anchor state**,
is outside this software guarantee. Ordinary disk files cannot establish an
absolute monotonic counter against that attack. TPM/independent external
monotonic anchoring, trustworthy boot/clock attestation and recovery of those
trust anchors remain separate G6/commissioning work. Never describe this slice
as complete host-compromise or whole-machine rollback protection.

## Explicit evaluation procedure and bounds

Provision the pinned optional `requirements/input-auth.txt` profile **before**
offline use; no runtime installer/downloader is invoked. Default requirements,
service activation, Rust enforcement/release, trust capsules and MIO pins stay
unchanged. Private material is not passed to the observer or logged.

For a separately identified isolated experiment, precreate an empty readable
source owned by the producer (no group/world write), empty observer-private
journal directory, witness-private `0700` anchor directory and witness-owned
socket parent with traversal permission for the observer. Provision distinct
private key files and public trust policy through the trusted operator path.
From the configured witness UID, explicitly start the foreground witness:

```
python -m azazel_edge.outcome.input_witness --policy /physical/trust.json \
  --private-key /private/witness.raw --initialize
```

Use `--initialize` only once for a fresh empty scope. Normal witness reopen
omits it. The precreated producer source and observer journal must be empty at
witness initialization. A stale existing socket is not removed automatically;
only an operator can verify/remove an obsolete endpoint before relaunch.
Start the observer with the existing explicit journal/scope/boot/initialization
options plus `--journal-resume-input --input-auth-policy /physical/trust.json`.
The capture producer then emits through `SignedCaptureWriter` in its own role.
Normal observer reopen omits journal initialization and keeps all trust context.

Inputs/journals retain their existing bounds. Witness messages are at most
8 KiB, one request per connection, 1-second client/connection timeouts, backlog
4 and at most 131072 accepted requests per witness process. No bound is silently
replenished in the protected anchor log. Full-prefix hashing and cached new
signature verification are bounded but not measured Pi resource guarantees.
All I/O and witness waits stay in the separate passive process, never in the
deterministic decision or release path.

Tests cover public-key authentication, domain/key/scope binding, parser and
sequence faults; actual 3-UID producer/observer/witness permissions and Unix
peer credentials; normal foreground emission and clean restart; SIGKILL at
empty/unread/begin/cursor/commit phases; valid old history and signed-fork
rejection; witness replay/unavailability/capacity/corruption/fsync failures;
and no automatic catch-up of an unacknowledged journal tail. CI explicitly runs
the separate-UID tests as root and rejects a skipped run. Software evidence is
not physical power-loss, SD wear/cache, peak RSS/CPU, latency, hostile-load or
live-source enrollment acceptance. #400/G6 and #393 retain those owners/gates.

## Optional registered-origin policy

New scopes may select `outcome-input-trust/v2`, which adds the exact public
`origin_registration_sha256` field. The existing v3 journal binds that entire
policy digest. Every signed event must then carry the matching registered
read-only origin and strictly increasing raw prefix cursor; an otherwise valid
signature without enrollment is refused. There is no v1 policy fallback for an
existing registered scope. See the [enrollment and real Rust connection
contract](outcome-registered-origin.md) for setup, tests and remaining gates.

The [normal defense-process connection](outcome-live-origin.md) adds a separate
new-scope `outcome-input-trust/v3` registration profile. It authenticates unchanged
normal-path provider/release reports with explicit producer/native lifecycle
records, not read-only computation or causal effect. Existing witness and
protected-prefix trust limits remain; no older scope migrates or downgrades.

## Explicit v4 Linux abstract witness transport

Pathname Unix sockets remain the default for trust v1/v2/v3. A **new** Root-prepared
scope can explicitly call `input_service.prepare(...,
witness_network_namespace={"cookie": ..., "kernel_boot_id": ...})`. This produces trust
v4 with the exact additional public field:

```json
{"witness_transport":{"kind":"unix-abstract/v1","name":"azazel-edge-witness-v1-<sha256(scope_ref UTF-8)>","network_namespace":{"cookie":123,"kernel_boot_id":"93840600-9e68-4c6b-a778-b918d81dfe02"}}}
```

The shown namespace values are illustrative, never defaults. Root must obtain
and independently fence the intended owned network namespace. Public preparation
and provisioning do not enter it or infer authority from supplied JSON. The
existing absolute `socket_path` stays present for the protected bundle layout,
but this explicit transport does not read, bind, probe, unlink or fall back to
that pathname. No environment variable, automatic migration or runtime selector
can upgrade an older scope. The foreground witness needs no new argument: its
explicit, protected trust policy selects the transport.

The canonical ASCII abstract name is derived solely from the public scope and is
not a secret. The complete transport and namespace identity are bound into the
trust digest; the nested public descriptor is copied and immutable through its
normal mapping API. As with other Python policy objects, this does not sandbox
trusted in-process Python code. All v3 live-origin registration, signed source,
restart and optional terminal-stop requirements also apply to v4. Native Rust
wire frames and registration schemas are unchanged; the Rust core does not parse
this Python witness trust policy. Existing provisioning imports the exact v4
policy and never rewrites existing source, journal, keys or anchors.

Before using an endpoint, **each** actual client/server checks Linux support
and a newly created unbound Unix stream socket. `getpeername()` must fail with
exactly `ENOTCONN`; connected unnamed sockets refuse. `SO_NETNS_COOKIE` returns
exactly eight native-byte-order bytes, interpreted as an unsigned nonzero 64-bit
value. That cookie and the bounded canonical kernel boot UUID must exactly match
the policy before bind/connect, private-key/store or anchor access. An unsupported
option, unavailable/invalid boot, wrong size, zero cookie or mismatch refuses.
No namespace-file `stat` or permission fallback is used. Root retains owned
namespace device/inode separately from this socket namespace identity.
The endpoint is exactly `b"\0" + canonical_name.encode("ascii")`. An occupied
abstract name refuses without probing, takeover, repair or pathname fallback.
Abstract addresses do not have filesystem DAC permissions. An unrelated process
in the same namespace can deny availability by occupying the public name; it
cannot satisfy both the configured peer UID and signed, nonce-bound witness
response. Both directions retain Linux `SO_PEERCRED`, original UID separation,
bounded requests/responses, domain-separated signatures, counters and exact
source/journal-prefix acknowledgements. No IP transport or namespace FD transfer
is added.

This is an optional transport foundation, **not** confinement, production
commissioning, admission or observer-effect acceptance. A caller must separately
commission its namespace placement, LSM rules and service configuration. The
Linux tests use actual temporary separate-UID processes and Unix sockets; their
structural preparation fixture never executes its synthetic ELF-shaped file.
Host-skipped Linux tests establish no runtime result, and this change makes no
power-loss or new authenticated VM claim.

Linux 6.8's [generic socket getter](https://github.com/torvalds/linux/blob/v6.8/net/core/sock.c#L1867-L1872)
returns `sock_net(sk)->net_cookie` for `SO_NETNS_COOKIE`, requiring an eight-byte
result. [Namespace initialization](https://github.com/torvalds/linux/blob/v6.8/net/core/net_namespace.c#L298-L311)
assigns a generated cookie, and [Unix socket creation](https://github.com/torvalds/linux/blob/v6.8/net/unix/af_unix.c#L903-L941)
allocates the socket in that network namespace before binding. The cookie is
boot-local kernel metadata, not an inode, secret or proof of authority; pairing it
with the actual boot UUID prevents treating a value from another boot as current.
Separate confined Root probes establish permission availability only for their
actual tested role/UID; they do not substitute for authenticated commissioning.
