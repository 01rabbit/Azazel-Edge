# Frozen synthetic finite-observation corpus v1

DATA ONLY. No evaluator, signer, collector or test implementation is supplied.
`contract.json` is canonical wire JSON: existing `journal._json(parsed)` plus
exactly one LF. Its SHA256 includes that LF. `corpus.json` and `expected.json`
are human-readable recipe/expectation metadata, NOT accepted wire inputs.
Future observation wire bytes must use the same compact canonical encoding/LF.
Row signature bodies and complete signed-row chain/checkpoint hashes use existing
`journal._json` with NO LF. Never hash a pretty-printed document as wire data.

The three distinct public test pins derive from Ed25519 TEST-ONLY seeds
`bytes([1])*32` (observer), `bytes([2])*32` (Source producer), and `bytes([3])*32`
(Source witness). These publicly disclosed deterministic seed recipes may appear
inline in a future test helper only. No private-key file is present or generated
by this corpus. They are disposable fixture credentials, never actual enrollment,
authentic independent collectors, real Source/witness keys or production trust.
The evaluator must receive all three matching pins externally, plus the exact
contract hash and four independently retained stream-head arguments.

The complete base has four channels, one frozen opportunity each, and exactly
open/begin/fact/end/close with row times/sequences specified in `corpus.json`.
Every generated row repeats the exact frozen binding fields; begin/end repeat
the challenge hash, open/close repeat their boundary, and each category uses its
listed closed fact kind. Each channel starts with zero `prev`; later `prev` and
external CLOSE checkpoints use complete signed-row hashes without LF. A future
fixture writer retains those heads BEFORE applying observation-bundle mutations;
it may explicitly alter external pins only for the named negative recipes.
Untargeted fields/channels remain identical. Recipe operations are descriptive
closed mutations for a future test helper, never executable evaluator rules.

For an empty opportunity category, retain its open/close channel but omit the
challenge/fact rows, renumber and re-sign canonically. For content mutations,
re-sign and rechain only when `resign` or structural insertion is specified;
missing rows without rechaining preserve the original signed surviving rows.
The gap-positive recipe preserves the original signed fact after removing begin.
Duplicate/conflicting facts are distinct valid signed rows referring to ONE
opportunity; their violation count deduplicates to one and coverage is incomplete.
The forbidden unauthorized fixture has attempt_count=1 AND failed_count=1: a
forbidden failed attempt is still a known violation, never normalized to success0.

Expected values describe fixed semantics, not runtime observations. A known
positive survives incomplete/lost/malformed sibling coverage as a lower bound.
No-known-positive incomplete/not-exercised violation counts are null, NOT zero;
zero occurs only in a complete finite_zero_claim. Planning/coverage counts may be
zero. Qualified safety counts remain null in every case. Input rejection is not a
qualified diagnostic and supplies no inferred counts. Repeated identical bytes
must produce identical results; input bytes and frozen definitions stay unchanged.

All addresses, namespaces, clocks, scopes, UIDs, role separation and challenge
premises are SYNTHETIC assertions. Signatures test byte binding only. These files
prove no physical bypass protection, sensor truth, actual independence, Source
authentication, cleanup, hardware/HIL coverage, runtime authority or admission.
The current v2 qualified safety gate remains WITHHELD regardless of this corpus.

## Explicit recipe-phase revision 2

Each mutation now carries `phase`. The ONLY scenario operations are
`empty_other_opportunity_lists`, `empty_all_opportunity_lists`,
`replace_fact_with_violation`, `insert_loss`,
`append_duplicate_and_conflicting_violation_facts`,
`forged_disposition_error_unchanged`, and `frozen_invalid_challenge_suffix`.
Construct those semantic observations, sign/rechain, and retain external heads
FIRST. Apply every `post_checkpoint` mutation afterwards, including corruptions
of submitted contract bytes; never repair, re-pin, or normalize checkpoints after
a negative mutation. Only named `external_head*` operations change head arguments;
the separately named external-key collision changes its key argument, not heads.
Expected outcomes and all 33 cases are unchanged. This is an explicit metadata
revision; the original corpus hash remains historical, not silently reused.
