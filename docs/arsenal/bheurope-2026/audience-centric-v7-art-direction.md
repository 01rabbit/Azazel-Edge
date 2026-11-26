# BHEurope Arsenal — V7 Audience-Centric Art Direction

**Deck:** `Azazel_Edge_BHEurope_2026_V7_Audience_Centric.pptx` (separate conversation artifact; not committed to GitHub as binary).  
**Branch:** `arsenal/bheurope-2026`; do not merge or rebase main.  
**Runtime target:** 18:50, including 10 minutes of real demo recording.  
**Visual brand source:** user-provided official `EUR26-Speaker Template_ARSENAL.pptx`, retaining Black Hat Arsenal identity and 16:9 format.  
**Technical framing:** user-provided reviewer packet plus actual recorded macOS synthetic replay evidence.

## Audience

- Security researchers and defenders who are familiar with SIEM/SOC tools but usually unfamiliar with Azazel-Edge.
- Arsenal attendees want a demonstration, not a vendor brochure.
- Remote watchers should understand each evidence scene even without access to the live booth.

## Emotional sequence

1. **Curiosity** — An incident occurs; a bounded action is selected. Why?
2. **Orientation** — In under a minute, understand the tool and its user.
3. **Tension** — Why `throttle`, and why not `isolate`?
4. **Trust through evidence** — Explain the choice; inspect the record; test copied-log tamper detection.
5. **Credible confidence** — State what was not demonstrated.

## One slide, one purpose

| Slide | Sole message | Art-direction change |
|---|---|---|
| 1 | The Arsenal presentation identity | Official title slide retained |
| 2 | Why was throttle chosen instead of isolate? | Cinematic oversize action vs one contrasting question |
| 3 | Azazel-Edge is a small local decision-and-explanation gateway | Preserve first-viewer local network → Edge → operator diagram |
| 4 | Presenter and research motivation | Presenter slide retained |
| 5 | The defender needs time | Observe / **Delay** / Preserve, emphasizing delay visually |
| 6 | Five action labels resolve to one bounded decision | Dramatic selected-action emphasis; selection is not enforcement |
| 7 | From offline to deterministic to auditable | Three-stage time axis rather than uniform cards |
| 8 | One synthetic alert enters the demo | Network scene illustration; expressly not live traffic |
| 9 | AI cannot select the action | Separation of decision authority from post-decision AI advisory |
| 10 | Every decision creates an inspectable record | Flight-recorder metaphor: explanation → audit chain |
| 11 | Real result: one trace | Actual user-provided Mac monitor screenshot, labelled placeholder for screen footage |
| 12 | Alternatives matter as much as the selected response | Actual screenshot, focus on investigation/rejected actions |
| 13 | Retained audit chain is verifiable | Actual screenshot; explicitly demand real altered-copy footage |
| 14 | Human operator can reconstruct the decision | Actual screenshot, same trace ID, future authentic video insert |
| 15 | Replay evidence has boundaries | Asymmetric proven/not-proven comparison |
| 16 | Explainability and evidence make decisions reviewable | Single bold concluding sentence |
| 17 | Follow the open project | Official closing layout retained |

## Production guardrails

- Actual observed macOS offline replay: `throttle`; Trace ID `demo:auditable_edge_socnoc`; original audit 3 entries verify; copied modified audit fails with `chain_hash_mismatch_at:1`.
- These observations are not proof of live packet throttling, AI autonomous action selection, external cryptographic anchoring, or Raspberry Pi execution.
- The four demo slides carry **still images only** sourced from user-provided Mac screenshots. They must be replaced by authentic video footage for submission. Each is visibly marked as such.
- No fake KPI history, attack classification, event counts, network topology measurement, or simulated packet graph.
- Viewer sees raw JSON as optional drill-down, not as the primary interface.
- Slides rendered and locally checked for overflow; this is editorial QA, not recorded-video QA.

## Next steps

1. Capture actual monitor walkthrough with a clean fullscreen browser, including original-chain/modified-copy visual after updating the dedicated branch.
2. Capture replay command and authentic terminal verification footage.
3. Replace demo-slide stills with footage and record English voiceover against the 18:50 cut.
4. Review readability, factual boundaries, and run time below the 20-minute cap.
