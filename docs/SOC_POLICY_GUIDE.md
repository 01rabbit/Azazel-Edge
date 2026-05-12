# SOC Policy Guide

`soc_policy.yaml` provides deterministic tuning without code changes.

Default location:
- `config/soc_policy.yaml`
- override with `AZAZEL_SOC_POLICY_PATH`

## Current policy surfaces

- `action_mapping.strong_soc.confidence_min`
- `action_mapping.throttle.{confidence_min, blast_min}`
- `action_mapping.redirect.{suspicion_min, confidence_min, blast_min}`
- `action_mapping.isolate.{suspicion_min, confidence_min, blast_min}`
- `suppression_defaults` for `SocEvaluator`

Profiles:
- `config/soc_policy_profiles/conservative.yaml`
- `config/soc_policy_profiles/balanced.yaml`
- `config/soc_policy_profiles/demo.yaml`

## Safety rules

- Keep changes conservative and review diffs before deployment.
- Invalid policy files fail closed at load time.
- Record policy `version` and hash in decision outputs for auditability.

## Minimal edit flow

1. Update `config/soc_policy.yaml`.
2. Run tests:
   - `PYTHONPATH=. .venv/bin/pytest -q`
3. Restart impacted services and verify dashboard decision traces.

## Dry-run

Use the dry-run helper to evaluate local normalized events without changing enforcement:

```bash
bin/azazel-soc-policy-dry-run --policy config/soc_policy.yaml --events /var/log/azazel-edge/normalized-events.jsonl --limit 200
```
