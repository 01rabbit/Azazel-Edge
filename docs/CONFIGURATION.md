# Configuration Reference

This document is the configuration entry point for Azazel-Edge.

## Runtime Configuration Layers

- Runtime defaults and environment files under `/etc/default/azazel-edge-*`
- Deterministic SOC policy files under `config/soc_policy*.yaml`
- Concept-to-profile mapping under `configs/profiles/*.yaml`
- Installer toggles under `installer/internal/*.sh`

## Key Configuration Domains

- Authentication and fail-closed posture
- SOC/NOC policy thresholds
- AI assist thresholds and resource guardrails
- Demo replay and overlay behavior
- Aggregator and optional integration toggles

## Authoritative Documents

- AI-related runtime tuning: [AI Operation Guide](AI_OPERATION_GUIDE.md)
- SOC threshold and redirect policy controls: [SOC Policy Guide](SOC_POLICY_GUIDE.md)
- Deployment profile intent and scope: [Deployment Profiles](DEPLOYMENT_PROFILES.md)
- Socket/runtime permission posture: [Post-demo Socket Permission Model (#105)](POST_DEMO_SOCKET_PERMISSION_MODEL_105.md)
- Concept-profile mapping layer: [../configs/profiles/README.md](../configs/profiles/README.md)

## Implementation Sources

- Policy loader: `py/azazel_edge/policy.py`
- AI governance entrypoint: `py/azazel_edge/ai_governance.py`
- Installer scripts: `installer/internal/`

## Operational Note

Use deployment-appropriate profiles and validate changes in a dry-run or test environment before production field use.
