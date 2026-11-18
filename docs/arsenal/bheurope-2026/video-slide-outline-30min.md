# Black Hat Europe 2026 — 30-minute slide storyboard

**Presentation:** Azazel-Edge: Auditable Edge SOC/NOC Gateway  
**Presenter:** Makoto “Mr. Rabbit” SUGITA  
**Branch:** `arsenal/bheurope-2026` — preserve divergence; do not merge main.

## Production warning

This is the requested **30-minute editorial/storyboard cut**, **not a validated submission-length video**. The existing branch recording runbook specifies **10–20 minutes (15-minute target), deadline 2026-12-01**. Verify organiser instructions before rendering/submitting. The on-site Arsenal schedule (9 Dec, 11:30–12:50) is separate from video-length requirements.

**Scope:** Azazel-Edge only. Other Azazel family members are mentioned as conceptual context, never shown as integrated demo capabilities. No Nexus content or Nexus demo. M.I.O. is optional and advisory-only.

## Timing (30:00)

| Section | Duration | Focus |
|---|---:|---|
| Introduction + presenter | 02:00 | Motivation and speaker |
| What is Azazel System? | 04:00 | Cyber Scapegoat Gateway, bounded delaying action, responsibilities |
| What is Azazel-Edge? | 05:00 | AZ-01 SENTINEL, local-first, explicit claims/limits |
| Evolution | 03:00 | Asia 2026 offline → USA deterministic → Europe auditable |
| Core idea / architecture | 06:00 | NOC/SOC, five actions, Rust live vs Python replay, explanations, audit, privacy |
| Demo video insert | 08:00 | Offline gate + real outputs + verification + altered copy |
| Conclusion | 02:00 | Evidence, rejected alternatives, release condition and review |
| **Total** | **30:00** | |

## Slide sequence

1. Title — defence that can explain itself
2. Project question
3. Presenter introduction
4. Roadmap
5. Azazel doctrine
6. Product family roles (context, not maturity claims)
7. AZ-01 SENTINEL
8. Edge scope and non-claims
9. Three Arsenal milestones
10. Why alerts are insufficient
11. Deterministic replay pipeline
12. Separate NOC and SOC evaluators
13. Five bounded action candidates
14. Decision vs enforcement vs post-decision advisory
15. Explanation JSONL fields
16. Selected/rejected/release
17. Hash-chained audit log
18. Privacy boundaries
19. **Demo video insertion placeholder**
20. Gate command and output artifacts
21. Inspect result and explanation
22. Verify clean chain and detect tampering in a copied record
23. Evidence and non-evidence
24. Safety / scope limits
25. Operator questions
26. Key takeaway
27. Thank you / project URL

## Recording instructions

Use `python3 tools/arsenal_bheurope_2026.py --out artifacts/bheurope-2026` in the dedicated branch. Capture **actual**, unedited selected action and real gate state; do not assume a specific action. Required evidence includes `result.json`, `explanations.jsonl`, `audit.jsonl`, `gate.json`.

Record clean-chain verification, then show failure from modifying **a copy** of retained chain evidence. No network enforcement, no remote model call, no production hardware assertion. For any ARM64 claim, run and capture separate Raspberry Pi-class device evidence. Retained hash chain is tamper-evident but not externally anchored or signed.

## Editing plan

Slides in English, 16:9, with speaker notes. Replace slide 19's video placeholder with the actual 8-minute recording. Slides 20–22 serve as cutaway chapters or overlays during this same segment, **not additional sequential 8-minute blocks**. Rehearse total runtime and trim/expand before final export. Prepare a shorter conforming cut if the 10–20-minute recording limit applies.

## Grounding

- `README.md`
- `docs/arsenal/bheurope-2026/README.md`
- `docs/arsenal/bheurope-2026/narration-en.md`
- `docs/arsenal/bheurope-2026/implementation-checkpoint.md`
- `docs/ARSENAL_DEMO_PROFILE.md`
- Umbrella `01rabbit/Azazel` repository README

_This storyboard does not indicate a successful physical-device run or a submitted recording._
