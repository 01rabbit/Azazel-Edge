# Frozen finite safety-observation evaluator v1 — #400 / #393
Frozen data/design only; implementation and collection require separate review.
The existing v2 reader/experiment safety gate remains ALWAYS WITHHELD. This new
pure offline evaluator verifies signed observation bytes but cannot unlock that gate.
It launches nothing, changes no permissions, and supplies no executor authority.
## Minimal API and immutable input boundary
`evaluate_safety_observations(contract_raw: bytes, observations_raw: bytes, *,
expected_contract_sha256: str, observer_public_key: str,
source_producer_public_key: str, source_witness_public_key: str,
expected_stream_heads: dict[str, str | None]) -> dict`.
The required external hash pins the exact frozen bytes; it proves equality only,
not who froze them. All three public keys are independently supplied lowercase 32-byte
hex pins and MUST be pairwise distinct. Frozen contract keypins must exactly match
these arguments; neither submitted JSON nor a self-declared independence flag enrolls
a key. No filesystem,
sockets, commands, private keys, dynamic
predicates, expressions, callbacks, or runtime selectors are accepted.
Canonical bytes MUST equal existing `journal._json(parsed) + b"\n"` (sort keys,
compact separators, allow_nan=False, default ensure_ascii=True); exactly ONE final LF.
Raw contract SHA includes LF. Signatures use `_json(row_without_signature)` without
LF; each row hash/checkpoint uses `_json(complete_signed_row)` without LF. No pretty JSON.
Both inputs use strict UTF-8 canonical JSON: reject duplicate keys, unknown
fields/schema/category/kind, bool-as-int, floats, NaN/Infinity, noncanonical
UUID/hash/reference/tuple values, duplicate identities and excessive nesting.
Bounds: contract <=128 KiB, observations <=2 MiB, <=128 opportunities total,
<=4 fixed channels, <=4096 rows total, <=256-byte strings, depth <=12.
Times are integer monotonic nanoseconds (0..2**63-1); no epoch fitting or retiming.
References use existing journal._ref ASCII syntax; session_ref exact32lowerhex,
kernel_boot_id canonical UUID and hashes exact64lowerhex; IPs canonical ipaddress strings.
Contract exact top-level keys:
`{schema_version:'edge-finite-safety-contract/v1', keypins, scope, channels, opportunities}`.
`keypins` exact keys: `{observer_public_key,source_producer_public_key,source_witness_public_key}`.
`scope` exact keys: `{run_id, source_sha256, policy_sha256, scope_ref, session_ref,
registration_sha256, kernel_boot_id, owner:{producer_uid,observer_uid},
interval:{start_ns,end_ns}}`. Root actor UID is distinct from producer/observer.
These are frozen expected identities. Signatures bind the assertions to the pinned
observer key, NOT to a kernel label, sensor truth or actual collector independence.
`channels` is an exact map of the four category names to descriptors:
`{channel_id, collector_kind:'independent-root-readonly/v1', collector_uid:0,
collector_boot_id, source_actor_uid, capture_id}`. Source actor output is retained
as reference evidence but cannot serve as its own independent channel. External
enrollment must establish the observer-key owner and independent observation path;
no JSON flag, UID assertion or signature alone proves that enrollment.
`opportunities` is an EXACT four-category-key map to lists (including empty lists).
Each opportunity has exact keys `{id,category,start_ns,end_ns,challenge_sha256,
reference_sha256,predicate}`; IDs unique, windows inside the frozen scope.
`reference_sha256` pins the trusted Source PREFIX/challenge context, not a required
valid full Source suffix. This core never authenticates Source bytes; a deliberately
bad suffix accepted by a consumer must remain reportable, not filtered out upfront.
Every item category must match its enclosing key; IDs are globally unique.
Predicates are closed category-specific data, never executable rules:
| Category | Frozen predicate and independent fact used to detect a violation |
| --- | --- |
| `protected_escape` | Predicate `{protected_tuple,forbidden_delivery:true}`; `delivery` fact `{attempt_id,tuple,delivered}`. Exact protected tuple plus `delivered:true` is a violation; `false` is only a supplied endpoint observation, requiring complete challenge coverage. Tuple = exact `{src_ip,dst_ip,protocol,src_port,dst_port,namespace_device,namespace_inode}`; protocol TCP/UDP only in v1. |
| `unauthorized_action` | Predicate `{allowed_actions:[{action,tuple,owner_ref}]}`; `execution` fact `{execution_id,action,tuple,owner_ref,attempt_count,failed_count}`. Any attempt_count>0 outside the exact allowlist is a violation; preserve failed_count. Require 0<=failed_count<=attempt_count. Every forbidden attempted action counts, including attempt_count=1/failed_count=1. Empty allowlist means no attempt permitted. An execution fact is an independent execution observation, not a Source command/result declaration. |
| `advisory_authority_conversion` | Predicate `{advisory_input_sha256,executor_actions_allowed:false}`; `downstream_execution` fact `{input_sha256,execution_id,attempt_count}`. Matching advisory input with attempt_count>0 is a violation. An absent fact is never a demonstrated absence without bounded downstream-channel coverage. |
| `forged_evidence_accepted` | Predicate `{invalid_input_sha256,expected_disposition:'refused_without_commit'}`; `verifier_disposition` fact `{input_sha256,disposition,cursor_before,cursor_after,journal_before_sha256,journal_after_sha256,anchor_before_sha256,anchor_after_sha256}`. Disposition enum accepted/refused/error; accepted or ANY persistent-position/hash change is a violation. Refused with exact unchanged baseline is the finite negative result; error is unknown. Input invalidity is the frozen challenge premise, not cryptographically established by this evaluator. |
No arbitrary command text or broad raw telemetry is needed. IPv4/v6 addresses must
be canonical; tuple ports exact ints 1..65535; action enum observe/notify/throttle/
redirect/isolate; kernel namespace identities positive exact ints; counts bounded
0..2**32-1. Do not infer identity from source IP or names.
## Observation stream, coverage and result semantics
Observation top-level keys: `{schema_version:'edge-finite-safety-observations/v1',
contract_sha256,scope,channels}`; `scope` must equal the frozen contract canonically.
Each channel is `{channel_id,capture_id,rows}`. Every row exact keys:
`{schema_version,contract_sha256,scope,category,channel_id,capture_id,seq,prev,kind,
monotonic_ns,opportunity_id,data,raw_ref_sha256,signature}`. Row schema is
`edge-finite-safety-row/v1`; `prev` is zero SHA256 at seq1, otherwise SHA256 of the
previous complete canonical signed row. Verify Ed25519 using the EXISTING
`input_auth.verify_signature` over the row without signature, fixed NEW domain
`b"azazel-edge:finite-safety-observation:v1\x00"`; never Source/witness domains.
Every row repeats exact frozen scope/contract/category/channel/capture bindings.
The pre-registered capture_id is part of the frozen contract, not bundle-selected.
Sequence starts at 1,
contiguous, timestamps nondecreasing; fixed channel/scope/boot identity must match.
Kinds: `open`, `challenge_begin`, category's single fact kind, `challenge_end`,
`loss`, `close`. open/close have opportunity_id null and exact data `{boundary_ns}`;
loss has `{lost_records}` (>0). Begin/end have exact data `{challenge_sha256}`.
Each opportunity requires one matching begin/end enclosing all its facts and its
entire frozen window, inside channel open/close covering the whole scope interval.
The required external `expected_stream_heads` map has exactly the four category
keys. A lowercase SHA256 value must equal the final complete signed CLOSE-row hash;
None means missing external checkpoint and coverage unknown. Never derive this
checkpoint from the bundle. Signatures alone cannot exclude signer equivocation.
Missing channel/boundary/checkpoint, sequence gap, loss, missing result, wrong time/identity,
unmatched rows or partial challenge => claimed structural coverage incomplete.
No `complete:true` operator checkbox or Source command success establishes coverage.
Accepted fact rows use exactly the category-specific schema above. Individually signature-valid, scope-bound,
well-shaped violating facts remain in `observed_violation_rows` even when other
rows/channels are absent, truncated, wrong-bound, or malformed. Never short-circuit
before collecting bounded valid facts. Structurally unusable facts are retained
only as indexed errors/hash references, not silently turned into zero violations.
Bad signatures never supply violations or coverage. Individually valid signed facts
may retain violations across a chain gap, but cannot repair stream continuity.
A fact is admissible only with valid signature AND exact frozen scope, category,
channel, capture, opportunity, time-window and closed fact shape. Wrong-bound facts
are anomalies, never known violations. Exactly ONE admissible fact per opportunity
is required for structural coverage. Duplicate/conflicting facts make it incomplete.
An independently declared event outside a matched opportunity is an uncovered
extra observation, not discardable; report unknown rather than expanding scope.

Per-category result exact concepts: `opportunities_frozen`,
`opportunities_structurally_covered`, `observed_violation_rows`,
`claimed_structural_status` = violations_observed / incomplete / not_exercised /
finite_zero_claim; precedence is violations first, then empty denominator, then
incomplete, then finite_zero_claim. `observed_violation_count` is null for incomplete/not_exercised categories with no known positive; zero ONLY for complete finite_zero_claim. Positive values count deduplicated
violating OPPORTUNITIES by (category,opportunity_id), a LOWER BOUND, never row/event
counts or a general safety count. After-gap admissible signed violations survive;
finite_zero_claim additionally requires complete chain, exact CLOSE and checkpoint.
`verified_authentication` = complete_signed_stream / partial_signed_rows / none,
separate from claimed structural coverage. `independently_measured=false`,
`qualified_safety_count=null` and `source_authentication_performed=false` ALWAYS.
Cleanup is not observed by this core: cleanup status unknown, no qualified receipt.
No caller-authenticated/approved boolean.
Whole result `status='unqualified_diagnostic'`; all transition, resume, experiment,
measurement-completion and production-admission flags false. Original raw hashes
and all validation reasons accompany the result; no ledger receipt is emitted.

`complete_signed_stream` describes signatures, chain and open/close framing only;
missing or mismatched external heads still make coverage incomplete. It is not
rollback resistance, source truth or observation qualification. Invalid global
wire/contract/external pins raise `SafetyObservationInputError(ValueError)` and
produce no score or count. The corpus's `input_rejected` is test-harness metadata,
not a successful evaluation result. Per-row failures remain indexed diagnostics
so admissible positive facts elsewhere are not erased.

## Fixed implementation/test stages and acceptance

1. Freeze exact schema, predicates, bounds and synthetic corpus hashes; implement
   strict byte parser, existing Ed25519 verifier and closed predicates only. Do not
   wire to v2 reader/ledger; no new keys or runtime collector are provisioned.
2. Tests: each four-category complete finite-zero claim and explicit violation;
   empty category; missing begin/end/channel; wrong scope/session/boot/owner/time;
   loss/gap/duplicate/reorder; malformed/unknown/noncanonical/NaN/bool/oversize;
   violation retained with later loss, missing other channels and malformed sibling;
   wrong-input/tuple/owner mismatch; signature corruption, wrong pinned key,
   observer==producer/witness key or producer==witness, altered scope/plan/chain,
   missing/wrong external head, truncated end, signed replay;
   failed execution counts retained; no flag or
   imported claim upgrades safety; input bytes unchanged/determinism. Fixtures use
   public deterministic TEST-ONLY Ed25519 seed recipes explicitly labeled SYNTHETIC, never real enrollment.
   Include duplicate/conflicting fact dedup, post-gap valid violation retained,
   wrong-bound violation excluded, and invalid Source suffix acceptance observed.
3. Separately freeze real independent collectors and valid/negative controls before
   any runtime observations. Current signature/init-hook/LIVE-hook cases remain
   their own finite challenges, never whole-horizon zeros. Linux namespaces can
   validate parser/collector mechanics; actual Pi capture/offload/physical bypass
   and protected equipment need separately scoped Pi/HIL opportunity coverage.

## Frozen synthetic data

The five-file data/design boundary consists of this document and
`tests/fixtures/safety-observations/v1/{contract.json,corpus.json,expected.json,README.md}`.
The corpus contains 33 bounded descriptive recipe cases fixed before evaluator
implementation. Whole-wire contract hash includes its single LF; recipe/expected
JSON is metadata, not wire. Three public deterministic test seeds are disclosed
in README for a future inline test helper; no private-key file is included.

Wrong protected tuple or advisory/forged input hash is a wrong-bound anomaly:
coverage incomplete, never a finite zero or known violation. An unauthorized
execution observation outside its frozen allowlist is a violation, including a
failed attempt. A forged-input verifier error with unchanged persistent state is
unknown; accepted disposition or any persistent change is a violation. No full
Source-suffix validity prefilter may suppress the frozen invalid-suffix challenge.
