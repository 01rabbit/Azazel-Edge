# ATT&CK Mapping Guide

Azazel-Edge maps selected detection evidence to MITRE ATT&CK using a transparent rule file:

- `config/attack_mapping.yaml`
- override path: `AZAZEL_ATTACK_MAPPING_PATH`

## Output fields

Mapped events can include:
- `technique_id`
- `technique_name`
- `tactic`
- `confidence`

Unmapped events are explicitly labeled as `unmapped` and do not produce guessed ATT&CK claims.

## Rule maintenance

Rules support matching by:
- `sid`
- `attack_type_contains`
- `category_contains`
- `service_contains`

Guidelines:
- Keep confidence conservative.
- Prefer explicit mapping over broad pattern matching.
- Review rule diffs like code changes.

## Important limits

ATT&CK mapping is contextual enrichment, not proof of adversary intent.
Operators must treat mapped techniques as investigation leads and corroborate with full evidence.

