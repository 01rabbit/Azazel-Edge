# Sigma Rule Packs (`config/sigma`)

MiniSigma rules for Azazel-Edge Evidence Plane events.

## YAML Schema

Top-level `rules:` list. Each rule supports:
- `id` (required)
- `title` (required)
- `source` (optional exact match)
- `kind` (optional exact match)
- `subject_contains` (optional substring match)
- `attrs` (optional exact key/value map)
- `min_severity` (optional integer)
- `mitre_technique` (optional metadata)

## Mapping to `MiniSigmaRule`

- `id` -> `rule_id`
- `title` -> `title`
- `source` -> `source`
- `kind` -> `kind`
- `subject_contains` -> `subject_contains`
- `attrs` -> `attrs`
- `min_severity` -> `min_severity`

## Notes

- Rules operate on normalized Evidence Plane events, not raw packets.
- Keep rules deterministic and lightweight for Raspberry Pi runtime.
- Validate with:
  - `PYTHONPATH=py:. pytest -q tests/test_sigma_assist_v1.py tests/test_sigma_rules_disaster_v1.py`
