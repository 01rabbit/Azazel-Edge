# Black Hat Europe 2026 — V5 First-Viewer Edition

**Working branch:** `arsenal/bheurope-2026` (leave `main` untouched).  
**Deck:** `Azazel_Edge_BHEurope_2026_Official_Template_V5_First_Viewer.pptx` — separate downloadable local PowerPoint artifact (not yet committed as a binary).  
**Format:** 17 slides, 16:9, official EUR26 Arsenal template theme/layout retained, English presentation and speaker notes.  
**Run time:** 18:50, maintaining exactly 10:00 of actual screen-recorded demonstration.

## Core change from V4

Immediately after the opening four questions, insert a plain-language slide:

**Slide 3 — WHAT IS AZAZEL-EDGE?** (00:50–01:40)

> A local security gateway that watches, decides, and explains.

Explain left-to-right:
- **Local network:** devices, network traffic and local security evidence.
- **Azazel-Edge:** observes evidence, evaluates the NOC/SOC state, chooses a bounded response under deterministic policy, records why.
- **Human operator:** reviews and verifies the decision and audit record.

Bottom prompts: **WHERE** (small, temporary or isolated networks); **WHAT** (select one bounded response); **WHY** (explainable, reviewable decisions).

This is an **editable conceptual diagram**, not an actual screenshot or proof of packet enforcement. Avoid saying the explanation record *applies* a network action: the synthetic replay has enforcement disabled.

## Rebalanced full edit plan

| Slide | Timestamp | Duration | Topic |
|---|---|---:|---|
| 01 | 00:00–00:20 | 0:20 | Official title |
| 02 | 00:20–00:50 | 0:30 | Four incident questions |
| 03 | 00:50–01:40 | 0:50 | **New: What is Azazel-Edge?** |
| 04 | 01:40–02:10 | 0:30 | Presenter Makoto SUGITA |
| 05 | 02:10–02:55 | 0:45 | Azazel system doctrine |
| 06 | 02:55–03:40 | 0:45 | AZ-01 SENTINEL technical scope |
| 07 | 03:40–04:15 | 0:35 | Asia → USA → Europe evolution |
| 08 | 04:15–05:10 | 0:55 | Synthetic incident scenario |
| 09 | 05:10–06:20 | 1:10 | Decision authority boundaries |
| 10 | 06:20–07:00 | 0:40 | Explanation JSONL evidence contract |
| 11 | 07:00–09:00 | 2:00 | **Footage:** replay |
| 12 | 09:00–12:00 | 3:00 | **Footage:** selected and rejected actions |
| 13 | 12:00–15:00 | 3:00 | **Footage:** authentic clean-chain verification + altered-copy failure |
| 14 | 15:00–17:00 | 2:00 | **Footage:** operator review of same trace |
| 15 | 17:00–17:45 | 0:45 | Shown vs not shown |
| 16 | 17:45–18:35 | 0:50 | Answer to opening questions |
| 17 | 18:35–18:50 | 0:15 | Thank you / project URL |

## Safety / correctness guardrails

- `tools/arsenal_bheurope_2026.py` runs **synthetic offline deterministic replay**; no live traffic enforcement or AI-selected actions.
- Five possible labels do not imply five permitted automatic enforcement actions; `isolate` is not automatic.
- Live Rust core and Python replay Arbiter are distinct, not interchangeable.
- Explain the actual action and actual rejected alternatives from `explanations.jsonl`; never invent values.
- Audit verification establishes retained hash-chain consistency, not an externally anchored signature or resistance to coherent whole-file replacement.
- Raspberry Pi-class hardware execution must be separately captured before claiming it.
- No demo video has yet been inserted into the slide placeholders.
- CFP reviewer packet is conceptual submission background; actual branch implementation and confirmed recording conditions govern the technical demonstration.

## Narration for slide 3 (target ~50 seconds)

“Azazel-Edge is a small, local-first security gateway designed for networks where connectivity, resources, or dedicated security staff may be limited. It examines local network evidence, evaluates security and operational conditions, and selects a bounded response under deterministic rules. Most importantly, it records why the response was selected, why alternatives were rejected, and what conditions apply to its release. A human operator can then review and verify that decision, even after the incident. This diagram shows the responsibility flow, not live network enforcement.”

## Deliverables

- [x] Slide 3 added as editable native PPTX shapes.
- [x] 17-slide deck rendered and visually checked.
- [x] Speaking notes and timing adjusted.
- [ ] Real replay / dashboard / JSONL / audit video footage inserted.
- [ ] Device hardware evidence and final video QA.
