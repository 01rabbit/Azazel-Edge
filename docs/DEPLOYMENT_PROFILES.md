# Deployment Profiles

Last updated: 2026-05-14

This matrix separates required deterministic core runtime from optional integrations.

## Profile matrix

| Profile | Purpose | Required components | Optional components | Not recommended by default |
|---|---|---|---|---|
| Core | Minimal deterministic edge gateway and decision loop | internal network, Suricata, Rust core, Evidence Plane, NOC/SOC evaluators, Action Arbiter, Web UI/API, audit | OpenCanary | Ollama, Mattermost, Wazuh, Vector, Aggregator |
| Demo | Arsenal-ready reproducible demonstration | Core + deterministic replay + OpenCanary (if redirect shown) | Mattermost | heavy AI, Wazuh, Vector, broad integration tours |
| SOC integration | Standards-oriented downstream exchange and enrichment | Core + ATT&CK mapping + TI feed + Sigma + STIX/TAXII | Aggregator | co-located heavy AI on constrained hardware |
| NOC expansion | Field network observability | Core + Wi-Fi sensors + SNMP + NetFlow | Aggregator | Wazuh/Vector unless resources are validated |
| Heavy lab | Integration testing and development sandbox | most components enabled for integration verification | Ollama, Mattermost, Wazuh, Vector, Aggregator, TAXII | use as field default on constrained Raspberry Pi |

## Notes per profile

Core profile:
- preserves Deterministic First with minimal operational risk.
- suitable default for constrained Raspberry Pi deployment.

Demo profile:
- optimized for reproducibility over breadth.
- deterministic replay is the safety baseline.

SOC integration profile:
- adds standards exchange surfaces without changing core action arbitration logic.

NOC expansion profile:
- expands observability while keeping core deterministic runtime clear.

Heavy lab profile:
- useful for integration burn-in and compatibility checks.
- not equivalent to default field runtime sizing.
