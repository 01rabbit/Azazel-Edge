# Pure invalid-signature commissioning fixture

`synthetic_prepare_frame(policy, *, kernel_boot_id, session_ref)` reads no files,
keys, source data or endpoints and launches nothing. It takes only the current
public v3 `TrustPolicy`, canonical raw kernel UUID and fresh lowercase native
session reference. It returns an immutable `SyntheticPrepare` wrapper explicitly
marked `SYNTHETIC_INVALID_SIGNATURE_PREPARE`, containing one canonical newline-
terminated source envelope with matching public scope/stream/registration and
boot context, outer sequence1 and inner prepare sequence0.

The signature is fixed 64-byte `ff` data: hexadecimal format is valid, but its
Ed25519 scalar is noncanonical, so it cannot authenticate. No real private key,
signer API or valid execution claim is used. The standard source envelope has no
extra fixture fields; the wrapper/doc/controller evidence must retain the
synthetic label separately. Never describe this as an actual producer frame.

Focused pretests call the unchanged real `SourceVerifier.verify` and require the
exact `OutcomeJournalError: authentication signature invalid`; a schema, context,
permission or other failure cannot stand in for that crypto refusal. The verifier's
accepted bytes, sequence, head and live state remain unchanged after failure.
This is a pure crypto/format pretest, not confinement, API/journal operation,
registration validation, source admission or actual VM commissioning evidence.

Any future manual negative case needs separate Root review, fresh VM/scope/keys,
owned input FD/inode checks and explicit operator-fault retention. Source append,
fsync, witness/journal nonconsumption, actual Root pre-API proof and actor/namespace
cleanup are not implemented here. No source file is written, scope provisioned,
production validator changed or four-assignment manifest created by this chunk.
