# Offline operator task study harness

Refs #548, Nexus #415, Gadget #24 and Azazel #67. This is a separate research
tool, not deployed product analytics. It uses no network client, account,
model, admission or control interface. The product UI remains unchanged.

## Freeze before collecting

Prepare a plan with an independently retained registration, sample-size plan,
held-out corpus, blinded rubric and exact classic/overview render digests.
Both arms of each participant/case pair must have identical backend snapshot
bytes, read permissions and task truth. Freeze consent/withdrawal handling,
participant recruitment, practical time gain and correctness/handoff
non-inferiority margins, exclusion criteria and analysis seed before viewing
outcomes. The default study recommendation is **zero permitted correctness or
safety loss**; any proposed margin needs prior independent review.

Use anonymous random `p-` plus 16 hexadecimal IDs, never names/accounts.
Assignments are crossed participant × case × arm, with both orders present
and counterbalanced within each case. Caps: 200 participants, 20 cases, 8,000
assignments, 10 options/card, 8 MiB/file and 2 million participant bootstrap
draws. Repeated-case learning/order and fixed-case generalization need explicit
review; counterbalancing alone does not eliminate them.

Keep the full rubric and truth outside the collector and hidden from the task
participant and layout label in the scoring export. The facilitator loads the
assigned fixture/layout separately in an isolated browser with the declared
permissions. The collector never opens a URL or selects a product capability.

| Product | Cases to freeze from existing read fixtures before a human study |
|---|---|
| Edge | priority alert; matching/missing decision reference; stale/future/missing observation; dry-run vs unverified execution; retained-history gap |
| Nexus | observe-only would vs actual enforcement; denied/missing snapshot; model absent/blocked/model-free guidance; unverified citation; next safe setup/handoff |
| Gadget | current vs requested mode; denied/failed request; uplink vs client reachability; missing sensor/SSE recovery; WARNING is not a mode |

The shipped two-case synthetic fixtures test mechanics only. They are not a
held-out product corpus and their fabricated digests must never be relabelled
as human, release or hardware evidence. Preparing the complete reviewed case
corpus, real participants and power/sample-size justification remains open.

## Collect locally, then score separately

```bash
PYTHONPATH=py python -m azazel_edge.benchmark.operator_study \
  tests/fixtures/operator_study/synthetic-plan.json --collector-plan > collector-plan.json
python -m http.server 9131 --bind 127.0.0.1 --directory tools/operator_study
```

Open the local collector, select the prepared JSON and planned anonymous ID,
and confirm consent and the independently loaded assigned fixture before each
task. Start, choose closed responses and finish. The harness stores only
assignment IDs, choices, elapsed monotonic time and pinned bindings in memory.
Timeout uses the common horizon and discards post-deadline choices. Export
unscored captures; closing the page loses unexported work. No storage, analytics,
remote request, raw answer text, log, credential or free-form personal field is
used. The source of any consent/clock/fixture declaration still needs review.

A separate blinded reviewer applies the frozen rubric and records `correct`,
`unsafe_choice`, `handoff_score`, `timed_out`, `consented`, `blinded_scoring`,
elapsed time and exact assignment/rubric/render bindings. Combine the minimized
unscored `captures` with the reviewer `receipts`; each score must carry the
canonical SHA-256 of its capture (`capture_sha256`). The analyzer verifies
snapshot/render/rubric bindings and refuses a score that rewrites captured
consent, elapsed time or deadline. A hash still does not authenticate a person
or an independent clock. The reviewer must not
score timed-out answers as correct. No self-rating or AI output is ground truth.

```bash
PYTHONPATH=py python -m azazel_edge.benchmark.operator_study \
  tests/fixtures/operator_study/synthetic-plan.json \
  tests/fixtures/operator_study/synthetic-receipts.json
```

The analyzer preserves expected/received/missing denominators, complete pairs,
both-correct time pairs, unsafe/unconsented/unblinded counts and participant
clusters. It bootstraps participant means, not correlated trials as independent
people. Primary time assigns the same horizon to incorrect/unfinished answers;
fast wrong answers cannot create benefit. Both-correct time is secondary and
shows its smaller denominator. Any unsafe choice or missing consent/scoring
fails the complete safety gate. Task correctness/handoff non-inferiority and
preregistered practical time gain must also pass. Missing trials cannot become
successful zero-cost outcomes.

Pilot/synthetic reports are always `mechanical_only`. Even a confirmatory
report meeting recorded criteria requires independent review; hashes/flags do
not authenticate preregistration, source truth, consent or scoring. No automatic
rollout, model admission, hardware qualification or external-tool superiority
claim follows. Compare resource/asset/request costs separately on the named
browser and later on target hardware; a desktop result does not qualify a Pi.
