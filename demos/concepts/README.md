# Concept Demo Packs

This directory groups deterministic replay scenarios by operational concept profile.

Runtime scenario definitions remain in `py/azazel_edge/demo/scenarios.py`.
These files provide concept-oriented grouping and sequencing metadata.

## Packs
- `offline-edge-ai-socnoc.yaml`
- `deterministic-edge-decision-support.yaml`
- `auditable-edge-socnoc.yaml`
- `field-deployable-scapegoat-gateway.yaml`

## Compatibility
No scenario IDs are renamed here. Existing IDs remain valid for:
- `bin/azazel-edge-demo run <scenario_id>`
- `/api/demo/run/<scenario_id>`
