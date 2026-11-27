# BHEurope 2026 — V10 readability pass

Artifact: `Azazel_Edge_BHEurope_2026_V10_Readable_Master.pptx` (delivered as conversation download, not repository binary). Dedicated branch: `arsenal/bheurope-2026`; main untouched.

## Changes
- Audited all 17 V9 slides for native typography with small labels.
- Increased 66 text styles, setting small footer metadata near 17 pt and explanatory labels to 20–30 pt where relevant.
- Rebuilt demo slides 11–14 with native large text and actual user-provided Mac screenshots as secondary evidence. Source screenshots are cropped proportionally rather than distorted. Large result text shows real replay evidence from user-supplied execution output.
- Kept synthetic-replay / no-enforcement boundary labels.
- Retained the official Black Hat visual identity, the existing art direction, English speaker notes, and 17-slide sequence.
- Rendered the whole deck and passed automated overflow check.

## Scope and caveats
Some editorial image slides contain rasterized lettering. Enlarging native PowerPoint fonts does not modify the lettering embedded in images; substantial raster text revisions require replacing/rebuilding those art assets. Actual 10-minute video footage and narration remain separate unfinished tasks.

Proof: synthetic macOS replay selected throttle, trace `demo:auditable_edge_socnoc`; chain verified 3 entries; altered independent copy yielded `chain_hash_mismatch_at:1`. No live packet-control proof.
