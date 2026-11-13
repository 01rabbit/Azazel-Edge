# Five finite forged-input refusal challenges — Edge #400/#393

Freeze BEFORE implementation, base9ac6e72f05d209c2ebc6a4dfe75f29d34ec57aeb.
Reuse #601 sampled original-state, witness, cursor, sealed-reader and runtime
authentication paths. No executor/auth/provider/privilege/service/key deployment
or installer/security/systemd change. Offline, no missing-data zeros/backfill,
history repair or auto-resume. Existing98%/1.2x and timing gates remain unchanged.

## Frozen challenge premises and exact rejection boundaries

Each fresh scope first genuinely accepts one nonempty registered prepare prefix,
advances its cursor, closes its journal and retains independent Source/witness
checkpoints. Retain ONE canonical original signed eligible next session_start
frame as a separate reference artifact. Independently authenticate prefix+reference
with unchanged SourceVerifier, including selected session/boot and registration.
The submitted Source is exactly the authenticated prefix plus the case suffix.
Producer alone writes its fixed owned Source; observer never repairs it.

| kind | Required original-byte premise | Actual consumer's exact reason |
| --- | --- | --- |
| wrong_key | Reference core unchanged; only signature differs. A separately pinned distinct test public key verifies that signature; configured producer key rejects it. Key differs from producer AND witness. | authentication signature invalid |
| scope_mismatch | Only scope_ref and signature differ from reference. Scope is a valid nonmatching reference; configured producer signature verifies the modified canonical core independently. | signed input identity/sequence mismatch |
| replay | Suffix equals the LAST complete original LF frame of the authenticated prefix, including its genuine signature. No rewriting/re-signing. | signed input identity/sequence mismatch |
| chain_corruption | Only prev and signature differ. prev is a valid SHA unequal to authenticated prefix head; configured producer signature verifies modified canonical core. | signed input identity/sequence mismatch |
| partial_frame | Suffix is an exact nonempty proper byte prefix of the authenticated reference, no LF. Actual lab recipe removes17 terminal bytes, retaining the original complete reference separately. | incomplete input tail; automatic resume refused |

Scope/sequence/prev checks happen before cryptography in SourceVerifier; therefore
the shared refusal string NEVER establishes which premise was exercised. Prove
the isolated mutation and real signature separately. Partial-frame consumer refusal
is BoundedInput.snapshot(require_complete=True), before authentication; direct
SourceVerifier independently refuses the same bytes as invalid bounded signed
source. Do not conflate the two layers or patch either production path.

Each of five cases has its OWN fresh matched valid-next-frame scope/control, not
a reused successful assignment. Existing recovery advances that control's cursor
as explicit missed backlog; this is not Outcome/app consumption. Ten actual
Linux scopes are finite challenge evidence, not statistics of all possible inputs.
Normal constructor open/lock/load/fsync may precede refusal; no pre-open claim.

## Explicit v2 wire and implementation ownership

New verify_forged_input_refusal_v2(plan_raw, *, expected_plan_sha256, trust_raw,
before, after, stdout_raw, stderr_raw, reference_frame_raw). Plan retains exact v1
keys plus challenge and uses edge-forged-input-refusal-plan/v2. Challenge has exact
keys kind,reference_frame_sha256,challenge_public_key,partial_bytes. Key is a64hex
public key ONLY for wrong_key, otherwise None; partial_bytes exact positive int
ONLY for partial_frame, otherwise None. Never allow caller-provided refusal kind
or a valid reference hash beside different unverified bytes.

Intake collect_forged_input_refusal_v2 has unchanged external enrollment/plan pins;
new enrollment edge-forged-input-refusal-enrollment/v2 adds only paths.reference_frame.
Reference is a held Root0444 single-link artifact, <=65536 bytes, under existing
protected ancestors. Plan/trust/enrollment32KiB, each original sample1MiB/4097rows,
stdout/stderr64KiB; all existing original metadata/read/worker clock and separate
reader UID+boot/allclose fences remain. No new live query, signer or private key.

Result edge-forged-input-refusal-diagnostic/v2 uses challenge_verified instead of
v1 invalid_signature_verified, adds challenge_kind,reference_frame_authenticated,
expected_refusal_reason, and preserves sampled-state/change/baseline/structural
journal diagnostics, all5authorityflagsFALSE and qualified_safety_countNULL.
New collection wrapper is explicitly v2. V1 APIs/exact schemas/defaults must
refuse v2 and retain original behavior; no synthetic v1 plan, untrusted old-result
approval flag or implicit format conversion. An internal shared bounded fact
verifier may be extracted with exact v1 parity regression and original #601
public-record replay. Unknown v2 cannot weaken old authentication or admission.

Independent valid per-artifact changes survive missing reference/worker/siblings;
missing or inconsistent challenge/coverage never becomes refusal or safety zero.
Root receipts/signatures/metadata remain stated provenance premises, not proof
of cryptographic process execution or independent production custody. Equality
means unchanged sampled bytes/identities, not no transient writes, continuous
safety, full journal semantics, physical durability, global antirollback or cleanup.

## Stages, data and acceptance

1. Commit this freeze+cases first. Reuse implementation, Linux-test and independent
   review agents; no nested agents/model switches or duplicate actual runs.
2. Product owner extracts shared immutable semantics and adds v2 pure verifier /
   sealed intake with synthetic real-test-crypto adversarial cases. Wrong labels,
   wrong reference/key/cut/delta, mixed-case failures, typed bounds and v1/v2
   cross-version refusals must fail closed. Preserve known state changes on loss.
3. Test owner implements five actual negatives + five separate matched controls
   using existing producer1000/consumer65534/witnessRoot/reader65533. Same five
   setup capabilities, NNP, network-none and read-only code; no new privileges.
   Before/after original Source/journal/anchors and exact error/worker facts must
   bracket each attempt before teardown; original challenged bytes remain.
4. Public exports retain each case separately, complete valid reference and fixed
   #601 public files/manifest, never keys/private fixtures. Explicit case inventory
   reports missing cases as missing, never zero. Keep legacy public export separate.
   CI actual Linux selection may not skip and pass. Published originals immutable;
   offline exact replay of each public case is separate from new observation.
5. Appropriate regressions, independent final review, final-head complete CI and
   exact live base/head/tree precede conditional merge; update existing #400/#393,
   no duplicate issue. Keep production/Pi-HIL/whole-system/comparative gates open.

## Frozen public layout

New test-only EDGE_FORGED_REFUSAL_V2_PUBLIC_DIR is distinct from the v1 export.
Fresh0755 root has five fixed case directories named by kind, each0755, each
containing exactly the v1 public12files plus reference-frame.raw, all0444.
Each manifest binds12 original files by exact SHA/size. Never export enrollment
paths, keys or whole private fixtures. CI uses an explicit66-path allowlist:
five times13files plus root case-index.json. The finalizer writes the index ONCE
after collection, including failures: exact five kind keys map to
{state:'complete'|'missing',manifest_sha256:sha256_or_null}. Completeness describes
public artifact availability only, not safety/admission. Missing remains explicit;
no repair, invented measurements or replacement of completed case files.
