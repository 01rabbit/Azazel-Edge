# Black Hat Europe 2026 — demo-first submission cut

**Branch:** `arsenal/bheurope-2026` (work on this branch as-is; no main merge).
**Recording target:** 18:30 (organizer-specified 10–20 minutes; leave 1:30 headroom).
**Deck:** `Azazel_Edge_BHEurope_2026_18m30_Demo_First.pptx` produced as a downloadable presentation artifact; this Markdown is the repository-side editorial and capture plan.
**Scope:** Azazel-Edge only; no Nexus demonstrations; M.I.O. is advisory-only and optional.

## Narrative thesis

An incident occurs on a constrained field network. Can an operator determine:
1. What evidence entered the system?
2. What bounded action was selected, and why not the alternatives?
3. What policy and release condition governed the decision?
4. Can a second operator validate the recorded evidence later?

The recording depicts the **actual offline synthetic scenario replay**, not simulated screenshots, live packet enforcement, or an AI-selected action.

## Timed cut (18:30)

| Range | Duration | Story | Slide(s) |
|---|---:|---|---|
| 00:00–01:15 | 1:15 | Title and presenter | 1–2 |
| 01:15–02:00 | 0:45 | The operator's four questions | 3 |
| 02:00–03:00 | 1:00 | Azazel system doctrine | 4 |
| 03:00–04:00 | 1:00 | What Azazel-Edge is and is not | 5 |
| 04:00–04:55 | 0:55 | Asia → USA → Europe development emphasis | 6 |
| 04:55–06:10 | 1:15 | Local evidence, NOC/SOC, bounded Arbiter | 7 |
| 06:10–07:05 | 0:55 | Explanation JSONL fields | 8 |
| 07:05–07:35 | 0:30 | Synthetic incident scenario framing | 9 |
| 07:35–09:35 | 2:00 | **FOOTAGE**: run scenario, show result/trace | 10 |
| 09:35–12:35 | 3:00 | **FOOTAGE**: rejected actions / release / config | 11 |
| 12:35–15:35 | 3:00 | **FOOTAGE**: verify chain then tamper a **copy** | 12 |
| 15:35–17:35 | 2:00 | **FOOTAGE**: operator review of the same trace | 13 |
| 17:35–18:05 | 0:30 | Limits of the evidence | 14 |
| 18:05–18:25 | 0:20 | Three takeaways | 15 |
| 18:25–18:30 | 0:05 | Credits / closing | 16 |

## Capture

Run from the dedicated branch on a verified environment:

```sh
python3 tools/arsenal_bheurope_2026.py --out artifacts/bheurope-2026
python3 tools/arsenal_bheurope_monitor.py --artifacts artifacts/bheurope-2026
```

Read-only monitor at `http://127.0.0.1:8765`. Capture the actual:
- `result.json` (real action from replay; don't assume `throttle`);
- `explanations.jsonl` (`selected_action`, `rejected_actions`, `why_not_others`, `release_condition`, `policy_profile`, `config_hash`, `trace_id`);
- `audit.jsonl` (retained chain, same trace);
- `gate.json` (nonzero exit or `ok=false` means demo is not accepted).

For the altered-copy proof, **do not touch original operational evidence**. Use an independently copied audit JSONL file, alter a retained entry, and run an appropriate read-only verification against that copy. Show the successful clean verification and actual failed modified-copy verification in the recorded footage; do not substitute a fabricated verdict.

## Editing / QA

- English narration, readable at 1080p, terminal zoomed sufficiently.
- Use the exact observed output values; redact environment secrets and personal data.
- Do not claim device-level enforcement, external anchoring, whole-chain substitution resistance, or ARM64 hardware execution without separately recorded proof.
- Replay tool explicitly sets `AZAZEL_DEFENSE_ENFORCE=0`, no AI invocation in the deterministic run, and no raw log exfiltration.
- Replace slides 10–13 with real screen footage in the final video; the PPTX placeholders are not a completed submission.
- First record footage, verify evidence, then finalise narration and splice into this 18:30 timeline.
- Target `<20:00` with intro/outro and encode overhead included.
