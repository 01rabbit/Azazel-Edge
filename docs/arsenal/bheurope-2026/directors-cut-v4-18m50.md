# Black Hat Europe 2026 Arsenal — Director's Cut V4 (18:50)

**Public title:** Azazel-Edge: Auditable Edge SOC/NOC Gateway  
**Presenter:** Makoto SUGITA  
**Branch:** `arsenal/bheurope-2026` (do not merge, rebase or sync `main`)  
**Target recording:** 18:50; official instructed range 10–20 minutes, so export must remain under 20:00, including title and end card.  
**Presentation file:** `Azazel_Edge_BHEurope_2026_18m50_Arsenal_Directors_Cut.pptx` (separate produced slide artifact; this repository file is the authoritative edit and capture plan).

## Creative thesis

**When an incident happens, can you explain and prove your security decision?**

Use **one** synthetic incident and **one** real trace ID. The viewer should be able to answer what evidence appeared, which bounded action was selected, why alternatives were not, what permits release, and what the recorded audit actually verifies. No fictional terminal output, mocked result or fabricated hardware footage.

## Exact timeline and narration direction

| Cut | Timestamp | Duration | Visual | Spoken direction |
|---|---|---:|---|---|
| 01 | 00:00–00:25 | 0:25 | Title / short authentic teaser only if available | A decision alone is insufficient when operators must justify a response. |
| 02 | 00:25–01:05 | 0:40 | Four operator questions / cold open | What happened? What was selected? Why? Can a second operator verify? |
| 03 | 01:05–01:40 | 0:35 | Presenter introduction | Makoto SUGITA, research objective. Do not claim credentials not verified. |
| 04 | 01:40–02:35 | 0:55 | Azazel doctrine / delaying action | Limit attacker tempo and preserve defender observation and response time, subject to policy. |
| 05 | 02:35–03:35 | 1:00 | AZ-01 SENTINEL | Edge is the local-first deterministic SOC/NOC gateway; AI is advisory, not the action authority. |
| 06 | 03:35–04:20 | 0:45 | Asia → USA → Europe | Offline SOC/NOC emphasis → bounded deterministic decisions → inspectable explanations and audit. |
| 07 | 04:20–05:15 | 0:55 | Single synthetic incident story | Describe constrained field network and synthetic local evidence without asserting an unevidenced attack technique. |
| 08 | 05:15–06:25 | 1:10 | NOC/SOC evaluation / arbitration | Distinguish Python replay Arbiter and live Rust core. Five possible action labels ≠ five auto-enforcement permissions. |
| 09 | 06:25–07:00 | 0:35 | What to check in JSONL | Selected/rejected actions, reasons, release condition, policy, config hash, trace ID. |
| 10 | 07:00–09:00 | 2:00 | **Actual footage:** launch replay | Show branch, command, exit status, gate, result, trace. |
| 11 | 09:00–12:00 | 3:00 | **Actual footage:** explain decision | Show local monitor and explanation JSONL, rejected alternatives and release. |
| 12 | 12:00–15:00 | 3:00 | **Actual footage:** audit integrity | Clean retained chain verification, copied-file modification, genuine failed verification. |
| 13 | 15:00–17:00 | 2:00 | **Actual footage:** operator review | Trace same ID across output files and state what a reviewer can establish. |
| 14 | 17:00–17:45 | 0:45 | Demonstrated / not demonstrated | The replay is not live packet filtering, network isolation, externally anchored signing or verified Pi operation. |
| 15 | 17:45–18:35 | 0:50 | Return to four questions | Bounded decision + reasons + release condition + retained trace: operator accountability. |
| 16 | 18:35–18:50 | 0:15 | Repository URL / thank you | Reproduce the offline demo. |

## Production commands (run in repository root)

```bash
git switch arsenal/bheurope-2026
python3 tools/arsenal_bheurope_2026.py --out artifacts/bheurope-2026
python3 tools/arsenal_bheurope_monitor.py --artifacts artifacts/bheurope-2026
# Open http://127.0.0.1:8765 on the same device
```

The monitor is loopback-only and read-only. Real output artifacts:
- `result.json` – selected action and execution metadata;
- `explanations.jsonl` – selected and rejected actions, `why_not_others`, release condition, policy profile, configuration hash, trace ID;
- `audit.jsonl` – retained hash-chained evidence;
- `gate.json` – real acceptance status and chain verification.

Before filming the altered-copy proof, inspect `py/azazel_edge/audit/logger.py` and invoke its actual read-only verifier against a **copy**. Never replace operational records, never manufacture a success/failure screen. Gate must actually pass and the modified copy must actually fail for those statements to be voiced.

## Must-have screen evidence

1. Dedicated branch visibly checked out.
2. Test scenario identified as synthetic and offline.
3. Uncut replay command and real exit status.
4. Actual action and trace ID, repeated consistently.
5. Explanation JSONL: real selected/rejected alternatives and explicit release condition.
6. Actual clean verification result for retained chain.
7. Actual failed verification result for altered copy, with the original unchanged.
8. The same trace used for operator review; if a field is missing, explain absence rather than implying success.

## Engineering honesty / authority boundary

The replay wrapper sets `AZAZEL_DEFENSE_ENFORCE=0`; it does not use AI or live telemetry. The Python `ActionArbiter` supports replay/dry run; live decisions and enforcement are a separate Rust core path. `isolate` is not an automatic response. A retained hash-chain verification detects some edits but does **not** prove protection against whole-log coherent replacement or deletion; no external digital signature or trusted anchoring is shown. ARM64 hardware execution is a separate proof requirement; no claims without human-recorded runs. No Nexus footage/content. Raw data stays local by default.

## Quality gates before submission

- [ ] Narration recorded in intelligible English; captions reviewed.
- [ ] Source footage truly captured, not replaced with simulated UI.
- [ ] Actual outputs match spoken statements (especially selected action).
- [ ] Clean audit and altered-copy failure captured.
- [ ] Text readable at 1920×1080; zoom terminal to comfortably readable size.
- [ ] Pi-class ARM64 run labelled correctly if provided; don't imply one otherwise.
- [ ] No secrets, personal network data, API tokens or real incident details.
- [ ] Final rendered video verified under 20:00.
- [ ] Black Hat instructions/deadline confirmed from correspondence; project runbook currently says Dec 1.
- [ ] Publish slide deck and submitted video only after evidence review.

## Editorial rules

No long product-family inventory, no unproven effectiveness metrics, no staged attacker attribution, no unverified live enforcement claim. Explain the consequence of each screen to an operator rather than reading raw JSON line-by-line. Cut directly from the four opening questions into a concrete, inspectable answer at the end.
