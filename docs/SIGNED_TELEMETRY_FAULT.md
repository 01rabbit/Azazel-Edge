# Fixed synthetic fault helpers (not a negative controller)

These Root-only helpers operate only on the fixed current bundle layout and an
existing private evidence directory. They require the marked offline Root guard,
explicit `EDGE_SIGNED_NETWORK_TELEMETRY=1`, the direct successful current
initializer return and its matching current public trust/material/boot binding.
No native core may be present. Imported JSON alone authenticates nothing.

`capture_init(output, *, trust, initialization)` captures original empty source,
closed four-frame init journal/zero cursor and witness-anchor bytes plus protected
file identities. The current initializer supplies authentication provenance;
these helpers do not independently reauthenticate the anchor chain. All three
fixed reads/persistence attempts run even if one fails. The evidence directory
is synced before returning the direct in-memory snapshot.

`inject(output, *, snapshot, session_ref)` pretests the explicit synthetic frame
with the unchanged real SourceVerifier and requires exactly `authentication
signature invalid`. It retains the original bytes, labelled fault wire and intent
before append. The fixed source must be Root-parent protected, UID61001, regular,
single-link, exact0644, empty and identical by named and opened descriptor. One
append through that original nofollow descriptor is followed by file and parent
sync. No private key or signer is used; no source replacement, rollback or retry
is provided. Partial writes or sync/retention failures retain the changed source
and all available after-evidence, then fail. Both journal and anchors must remain
byte- and identity-identical. Only fully verified append returns a poisoned
snapshot. Outer actor/namespace ownership never transfers to this helper.

`classify_refusal(output, *, snapshot, live_output, failure)` consumes retained
actual live-helper artifacts from that same trusted Root call. It requires the
precise worker-failed exception without cleanup notes, empty terminal stdout,
nonzero return code, exact final signature-error traceback line, full persisted
Root binding/proof, clean helper cleanup/reap and no live result/start-context/
sidecar/outcomes/terminal artifacts. Current source bytes must equal the injected
wire with the original identity, while journal and anchor bytes/identities remain
unchanged. Generic failures, permissions errors, missing evidence, activity,
configuration drift or forced cleanup do not count as expected refusal.

Its receipt explicitly says **outer scope cleanup pending** and keeps transition,
experiment, production-admission and measurement flags false. It is not a complete
negative commissioning result, witness endpoint call, source admission, observer-
label cryptographic binding or a claim that verification did not READ the source.
No actor, scope, namespace, key, VM or four-run manifest is created or run here.

Tests perform real private file/descriptor IO and real signature rejection using
ephemeral public policies. Root/UID ownership metadata, prior initializer/witness
facts and live process receipts are explicitly synthetic adapters. They prove no
actual confinement, authenticated witness operation or VM negative case. Future
Root orchestration must retain failed cases and independently prove all outer
actor/cgroup/client/namespace cleanup before publishing a completed negative case.
