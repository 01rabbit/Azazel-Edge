# Benchmark Corpus Format

Each session uses two files:
- `<name>.jsonl`: EVE replay lines
- `<name>.labels.json`: expected behavior metadata

This corpus is synthetic and designed for deterministic regression checks.

## Fields

EVE lines mirror what Suricata emits plus `attack_type`, the free-text label the
production normalizer surfaces (the live agent scores `suricata_signature` from
`attack_type`, not from the rule `msg`). `alert.category` is the real Suricata
**classtype** for that SID and is pinned against `security/suricata/azazel-lite.rules`
by `test_scorer_wiring_v1.py::test_corpus_categories_match_real_classtypes`.

## Positive vs benign sessions

- **Positive** sessions (`expected_detection: true`) carry a real AZAZEL SID and must
  score `risk_score >= 60` (the arbiter "high" detection gate).
- **Benign** control sessions (`benign_*`, `expected_detection: false`) carry `sid: 0`
  and benign classtypes; they establish a measurable false-positive baseline. Detection
  and breach rates are computed over positives only; false-positive rate over benign only.

## Step 0 scope and known follow-ups

The harness now runs the real `TacticalScorer` on production-identical features (it
previously hardcoded `risk_score = 75 + severity*5` and never called the scorer). What
is intentionally deferred to the scorer recalibration (ranks 2-5), NOT silently assumed:

- **Benign resolution**: 9 benign control *sessions* today (5 baseline + 4 adversarial),
  not the 30 benign *events* the target spec wants. Event-level FP resolution and an
  independently-captured benign set are follow-ups.
- **Adversarial benign** (`benign_cleartext_http`, `benign_bad_unknown_arp`,
  `benign_smb_admin_sev2`, `benign_rdp_admin_sev2`): severity-2 benign traffic on the
  SHARED catch-all classtypes (`policy-violation`, `bad-unknown`) and on admin ports —
  the cases the old additive scorer pushed to >=60 (55 base +5 sid +4 action +8 port).
  The SID-keyed dampener crushes them to 25 while a real AZAZEL threat on the SAME
  classtype is lifted by its SID; `test_scorer_calibration_v1` pins both halves.
- **Severity spread**: all sessions are severity 2 (no rule sets `priority:`/`severity:`).
  Measure the classtype->priority->severity mapping on real hardware before trusting the
  per-severity base curve.
