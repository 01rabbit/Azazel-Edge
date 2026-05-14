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

## Redirect safety policy (v0.1.1 hardening)

Runtime redirect planning in `azazel-edge-core` supports protocol-aware mapping via:
- `config/redirect_policy.yaml`
- override with `AZAZEL_REDIRECT_POLICY_PATH`

Example:

```yaml
redirect_policy:
  enabled: true
  prepared_ports:
    22: 12222
    80: 18080
    8080: 18080
  unsupported_port_action: notify
  high_risk_unsupported_port_action: isolate
  scan_burst_action: throttle
```

Behavior:
- If mapping exists, redirect uses the prepared decoy port.
- If destination port is unsupported, action falls back deterministically (`notify`, `throttle`, `isolate`, or explicit `observe`) instead of blind redirect.
- If policy file is absent, runtime keeps backward compatibility with `AZAZEL_DEFENSE_HONEYPOT_PORT` and marks fallback in enforcement metadata.
- If policy file is invalid, runtime fails safe to `notify` (no blind redirect).
- If policy is present but `enabled: false`, runtime fails safe to `notify`.

Important:

Azazel-Edge does not generate a new decoy for every event. On constrained hardware, prepared lightweight decoys are kept ready, and suspicious flows are redirected only when a protocol-aware mapping exists.
