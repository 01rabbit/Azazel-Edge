# Concept Profiles (Configuration Layer)

This directory maps operational concept profiles to reusable configuration intent.

It does not replace runtime defaults under `config/`.
Current runtime policy loading remains controlled by:
- `AZAZEL_SOC_POLICY_PATH`
- `config/soc_policy.yaml`
- `config/soc_policy_profiles/*.yaml`

## Concept Profile Mapping

| Concept Profile ID | Primary SOC Policy Baseline | Demo Concept Pack |
|---|---|---|
| `offline-edge-ai-socnoc` | `config/soc_policy_profiles/demo.yaml` | `demos/concepts/offline-edge-ai-socnoc.yaml` |
| `deterministic-edge-decision-support` | `config/soc_policy_profiles/balanced.yaml` | `demos/concepts/deterministic-edge-decision-support.yaml` |
| `auditable-edge-socnoc` | `config/soc_policy_profiles/conservative.yaml` | `demos/concepts/auditable-edge-socnoc.yaml` |
| `field-deployable-scapegoat-gateway` | `config/soc_policy_profiles/balanced.yaml` | `demos/concepts/field-deployable-scapegoat-gateway.yaml` |

## Notes
- These profiles are documentation/runtime-alignment metadata for concept-oriented operation.
- Existing policy files under `config/soc_policy_profiles/` remain authoritative for score thresholds.
- Avoid event-specific profile names in this layer.
