# Black Hat Europe 2026 — Official Speaker Template Edition

Prepared from user-supplied `EUR26-Speaker Template_ARSENAL.pptx` and `blackhat-europe-arsenal-reviewer-packet.txt`. Slide source rendered as separately downloadable `Azazel_Edge_BHEurope_2026_Official_Template_18m50.pptx` (16 slides, 16:9, English speaker notes). **Deck binary is not committed to this repository.**

## Editorial priorities from the reviewer packet

1. Deterministic authority, not model-selected defense.
2. All five bounded decision labels, with explicit distinction between selection and live enforcement.
3. Explanation JSONL shows chosen/rejected alternatives, reasons, release, policy, configuration hash, trace and operator wording.
4. Tamper-evident hash-chained audit records with actual verification.
5. Local-first/privacy and advisory-only optional AI.
6. Offline reproducible synthetic incident on constrained environments. Do not claim verified Pi hardware without captured evidence.

## Exact 18:50 timeline

| Slide | Time | Topic |
|---|---|---|
| 01 | 00:00–00:25 | Title, presenter |
| 02 | 00:25–01:05 | Four review questions |
| 03 | 01:05–01:40 | Makoto SUGITA |
| 04 | 01:40–02:35 | Azazel doctrine |
| 05 | 02:35–03:35 | AZ-01 SENTINEL |
| 06 | 03:35–04:20 | Asia / USA / Europe evolution |
| 07 | 04:20–05:15 | Synthetic incident |
| 08 | 05:15–06:25 | NOC/SOC, arbiter, authority boundaries |
| 09 | 06:25–07:00 | Explanation evidence contract |
| 10 | 07:00–09:00 | Actual footage: run replay |
| 11 | 09:00–12:00 | Actual footage: explanation and release |
| 12 | 12:00–15:00 | Actual footage: retained chain clean/tampered copy |
| 13 | 15:00–17:00 | Actual footage: operator review via one trace ID |
| 14 | 17:00–17:45 | Demonstrated vs not demonstrated |
| 15 | 17:45–18:35 | Answers and conclusion |
| 16 | 18:35–18:50 | Repository / closing |

## Design

Preserve template master/layout/theme. Editorial reinterpretation: black/white contrast, original Arsenal identity from supplied template, restrained yellow-orange accents and oversized typography. Source template images of unrelated event attendees/presenters must not be misrepresented as Azazel footage or Makoto's photograph. Demo slides are clearly marked placeholders for *real* screen recordings.

## Recorded proof gate

From existing dedicated branch `arsenal/bheurope-2026`, without merging main:

```sh
python3 tools/arsenal_bheurope_2026.py --out artifacts/bheurope-2026
python3 tools/arsenal_bheurope_monitor.py --artifacts artifacts/bheurope-2026
```

Output `result.json`, `explanations.jsonl`, `audit.jsonl`, `gate.json`. The selected action must match genuine runtime output. Demonstrate a clean hash chain and a mutated **copy** that fails verification; never tamper with operational originals. No live packet enforcement, no AI used in replay; no hardware or signature claims without independent evidence.

## Source precedence

The reviewer packet describes the earlier *candidate submission* and explicitly says it does not itself establish acceptance. The current user-supplied accepted public listing establishes this talk's public schedule. The technical design contract in that packet informs content, but the verified present-day repo implementation and explicit recording mode govern demonstrations.

## Completion status

- [x] Official-template-based PPTX draft, design and English narration notes
- [x] 16-slide 18:50 timing plan, 10 minutes of marked screen-recording segments
- [ ] Actual tool footage captured
- [ ] Raspberry Pi-class execution evidenced if claimed
- [ ] Video rendered and QA-approved (10–20 minute submission requirement)
