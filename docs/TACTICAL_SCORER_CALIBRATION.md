# Tactical Scorer Calibration

Last updated: 2026-06-29

How the rule-based first-pass "judge" (`TacticalScorer`) turns a Suricata alert into
a 0-100 risk score, why it is calibrated the way it is, and what is deliberately
deferred. This is the deterministic, ML-free triage that runs before any LLM; the LLM
is advisory only and is consulted only for ambiguous-band scores.

## The verified detection gate

A single alert is *detected* (the arbiter leaves `observe`) only when:

```
risk_score >= 60   (soc _bucket "high")   AND   confidence >= 60
```

`confidence` is not an independent field — Suricata EVE carries none, so
`decision_layers._normalized_confidence_from_risk` back-fills it from the risk score
(risk>=50 -> 70, risk>=70 -> 80, ...). After the soc single-event `-10` penalty,
`risk_score >= 60` always yields `confidence >= 60`. **The two conditions collapse to
`risk_score >= 60`.** Earlier design rounds mis-read this gate as >=80/>=40; it is 60.

## Score bands (coherent with downstream constants)

| Band | Meaning |
|---|---|
| `< 40` | auto-dismiss (below `LLM_AMBIG_MIN`) |
| `[20,40)` | correlation window — low-and-slow repeats from one src escalate to the LLM |
| `[40,79]` | LLM advisory band (`LLM_AMBIG_MIN..MAX`) |
| `>= 60` | HIGH suspicion — arbiter detection gate |
| `>= 85` | CRITICAL (`CRITICAL_MIN`) — auto-ops escalation |

`CRITICAL_MIN = 85` is a single source of truth in `agent.py`
(`_risk_level` / `_state_name` / `_recommendation` / the ops enqueue all agree), so no
threat lands in an `[80,84]` dead zone. The soc `_bucket` "critical" boundary stays at
80 by design (a coarser SOC scale that drives isolate/redirect, not the operator
display); a test asserts no single-event corpus session scores in `[80,84]`.

## The model (deterministic, O(1), explainable)

1. **Threat class, SID-first (saturating max).** Exact `SID -> class` for AZAZEL rules
   is primary; a small SAFE `classtype -> class` map is the fallback for non-AZAZEL
   rules; `attack_type` free-text tokens are tertiary corroboration with a **hard
   ceiling** (a token-only match cannot alone reach 40, so a missing/novel/non-English
   label degrades to SID/classtype scoring, never a silent FN or FP). The threat weight
   is the **max** over matched classes, added once.
2. **Severity is a weak prior.** Base `{1:38, 2:30, 3:24, 4:18}`; no severity alone
   reaches 40. The `+5` SID bonus is gated on a real class or a deception SID.
3. **Ports corroborate, never manufacture.** Admin/web/dns `+8` only when
   `threat_weight > 0`; decoy ports `+10` always (honeypot-only, TP by construction).
   A class-less hit on a decoy port lands at the LLM advisory floor (40) by design —
   below the 60 detection gate, but worth a second opinion since decoy ports are
   suspicious by construction. In practice such hits also carry an OpenCanary SID
   (9901101-103) and are floored to 60 anyway.
4. **Action is neutral-or-positive.** `blocked/drop/rejected -> +2`; everything else
   `+0`. Never subtract — an attacker who influences the reported verdict must not be
   able to suppress the score.
5. **Deception floor.** Any AZAZEL deception SID floors to 60 (arbiter-detected and
   LLM-visible even in degraded mode).
6. **Benign dampener.** Catch-all classtypes (`policy-violation`, `bad-unknown`,
   `tcp-connection`, ...) with `threat_weight == 0` normalize to **25** — below the 40
   detection floor but inside the `[20,40)` correlation window, so genuine low-and-slow
   benign-looking repeats still reach the LLM. `policy-violation`/`bad-unknown` are
   shared by real AZAZEL threats; the SID map lifts those out first, so only genuinely
   benign traffic on those classtypes is dampened.

### Decision on record

- **Benign correlation preserved (operator choice).** The dampener targets 25 (in the
  correlation window) rather than 15 (below it), keeping the existing
  correlation-escalation behavior for benign-classtyped low-and-slow repeats. The cost
  is that a heavy benign user can spend some LLM budget via correlation; this was an
  explicit choice to not silently disable a shipped detection capability.

## Measurement

The detection-accuracy benchmark (`py/azazel_edge/benchmark/detection_accuracy.py`)
runs the real scorer on production-identical features over
`tests/benchmark/corpus/` (7 positive + 9 benign sessions). It previously hardcoded
`risk_score = 75 + severity*5` and never called the scorer; that is fixed. Metrics are
split: detection/breach over positives, false-positive over benign, plus band telemetry
(`llm_band_count` / `critical_count` / `dead_zone_count`).

Current corpus baseline: **detection 100% / breach 0% / FP 0%**, positives 75-91
(c2/dns_exfil/phishing reach CRITICAL>=85), benign normalized to 25, separation margin
50, zero dead-zone. CI gates assert the *separation and band properties* (not memorized
per-class numbers) to guard against overfitting.

## Deferred (open questions — NOT yet implemented)

These need real hardware data or a product decision and are intentionally out of scope:

- **Severity base curve (rows 1/4 provisional).** No rule sets `priority:`/`severity:`,
  so production severity is Suricata's classtype-default priority, unmeasured. The
  corpus is all sev2/3; a `base-row-coverage` test fails loudly if a session starts
  relying on the unmeasured rows. Measure `classtype -> priority -> severity` on the box
  before freezing rows 1 and 4.
- **Benign resolution.** 9 benign control *sessions* today, not the target 30 benign
  *events* with event-level FP resolution and an independently-captured benign set.
- **Config externalization (v4).** The SID map, classtype map, weight table,
  `DECEPTION_SIDS`, decoy ports, and benign classtypes are tuned to `azazel-lite.rules`
  and pinned by test. v4 should load them from a versioned config derived from the rule
  file so a different ruleset ships its own map without a code change.
- **Stateful correlation (v4).** A per-src bounded counter to give benign-classtyped
  low-and-slow its own 25-cap path is deferred; the current dampener level keeps benign
  correlatable unconditionally instead.
- **Ops / decoy LLM load tuning.** Whether `OPS_ESCALATE_MIN_RISK` should rise and
  whether high-volume decoy probes should bypass the LLM are policy calls to make once
  `llm_band_count` / `ops_escalation_count` are measured on real probe volume.
