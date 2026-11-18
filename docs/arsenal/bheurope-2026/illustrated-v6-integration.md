# Black Hat Europe 2026 — V6 Illustrated Deck

**Branch:** `arsenal/bheurope-2026`. Main remains untouched; no merge/rebase.

**PowerPoint deliverable:** `Azazel_Edge_BHEurope_2026_Official_Template_V6_Illustrated.pptx` (generated as a separate downloadable artifact; this document records the changes, not the PPTX binary).

## Changes to existing 17 slides

- **Slide 3:** existing first-viewer explanation retained: local network → Edge → human.
- **Slide 5:** replaced text-heavy doctrine exposition with an editable three-stage visual: **Observe → Delay → Preserve**.
- **Slide 6:** replaced text-heavy core overview with five editable bounded-action cards; explicitly says these are labels, not five automatic controls. Live Rust and replay Python paths distinguished.
- **Slide 7:** replaced verbose evolution exposition with three-stage visual: **Asia offline → USA deterministic → Europe auditable**.
- **Slide 8:** integrated previously prepared `01_incident_context` as the incident context slide. Synthetic telemetry and no-live-capture boundaries prominent.
- **Slide 9:** integrated `02_decision_authority` for NOC/SOC → Action Arbiter → decision record, with Rust live and Python replay distinguished.
- **Slide 10:** integrated `04_audit_review` as the explanation → hash chain → human review diagram.
- **Slides 11–14:** unchanged demo footage placeholders; actual screenshots/video are required from the dedicated branch before submission.
- **All other slides:** preserved, including the introduction, presenter, technical limits, closing and 18:50 timeline.

The five-action visual content also reuses the prepared bounded-actions concept in native editable PowerPoint shapes. The full-slide concepts are embedded as PNGs (not editable individually); originals are separately available as SVG sources in the visual kit.

## Evidence policy

No simulated dashboard screenshot is shown as genuine; local monitor status at `http://127.0.0.1:8765` and actual JSONL audit evidence must be captured from a real replay run.

```sh
python3 tools/arsenal_bheurope_2026.py --out artifacts/bheurope-2026
python3 tools/arsenal_bheurope_monitor.py --artifacts artifacts/bheurope-2026
```

Do not claim hardware execution, actual packet enforcement, or external hash-chain anchoring without independent proof. Preserve the same real trace ID through demo segments. All slide illustrations are conceptual; results are not preselected.

## Finalization checklist

- [x] Integrated explanation diagrams into existing slide sequence (no appended diagram dump).
- [x] Retained 17 slides and 10-minute real-footage allotment.
- [x] Rendered output for visual quality checks.
- [ ] Capture genuine incident replay and read-only local dashboard screenshots.
- [ ] Capture normal audit and modified-copy failure.
- [ ] Replace footage placeholders and render, check total <=20 minutes.
