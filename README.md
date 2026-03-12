# Azazel-Edge

<p align="center">
  <a href="./README.md">
    <img alt="English" src="https://img.shields.io/badge/Language-English-1f6feb?style=for-the-badge">
  </a>
  <a href="./README_ja.md">
    <img alt="日本語" src="https://img.shields.io/badge/Language-日本語-2ea44f?style=for-the-badge">
  </a>
</p>

Azazel-Edge is an operator-aware defensive edge appliance for Raspberry Pi-class hardware.
It combines a managed gateway, deterministic SOC/NOC evaluation, explicit action arbitration, audited decision explanations, and governed local AI assistance into one field-ready system.

<p align="center">
  <img src="https://img.shields.io/badge/-Raspberry%20Pi-C51A4A.svg?logo=raspberry-pi&style=flat">
  <img src="https://img.shields.io/badge/-Python-F9DC3E.svg?logo=python&style=flat">
  <img src="https://img.shields.io/badge/-Rust-000000.svg?logo=rust&style=flat">
  <img src="https://img.shields.io/badge/-Flask-000000.svg?logo=flask&style=flat">
  <img src="https://img.shields.io/badge/-Mattermost-0058CC.svg?logo=mattermost&style=flat">
  <img src="https://img.shields.io/badge/-Ollama-111111.svg?style=flat">
</p>

## Why Azazel-Edge Stands Out

- **Deterministic before AI**
  Tactical Engine performs the first-minute triage. Evidence Plane and deterministic evaluators add second-pass context. AI is bounded and governed, not the core control loop.
- **SOC + NOC + edge gateway in one appliance**
  Azazel-Edge is not just a dashboard and not just a packet filter. It is an edge gateway with shared evidence, operational monitoring, threat evaluation, and operator actions.
- **Built for constrained hardware**
  The system is designed to run on Raspberry Pi 5-class devices without letting the AI path dominate memory, CPU, or operator trust.
- **Operator surfaces, not just APIs**
  Dashboard, `ops-comm`, Mattermost `/mio`, TUI, and EPD each have a distinct role in the workflow.
- **Reproducible and demoable**
  The installer can reproduce the current runtime stack, and the deterministic demo pack can replay end-to-end decision scenarios without polluting live state.

## What You Can Do With It

- Stand up a **managed internal segment and uplink gateway**
- Normalize **Suricata, flow, NOC probe, and syslog** events into a shared evidence model
- Evaluate **operational degradation** and **security suspicion** separately, then arbitrate an action
- Guide professional operators and temporary staff with **runbooks, triage state machines, and M.I.O.**
- Run **deterministic scenario replays** for demos, validation, and review
- Export auditable, explainable decisions instead of opaque model guesses

## Core Architecture

1. **Evidence inputs**
   - `suricata_eve`
   - `flow_min`
   - `noc_probe`
   - `syslog_min`
2. **Evidence Plane**
   - shared schema with `event_id`, `ts`, `source`, `kind`, `subject`, `severity`, `confidence`, `attrs`
3. **First-pass triage**
   - Tactical Engine for immediate Suricata-driven risk scoring
4. **Second-pass deterministic evaluation**
   - NOC evaluator: availability, path health, device health, client health
   - SOC evaluator: suspicion, confidence, technique likelihood, blast radius
5. **Action Arbiter**
   - `observe`, `notify`, `throttle`, `redirect`, `isolate`
6. **Decision Explanation and audit**
   - why chosen, why not others, evidence IDs, operator wording, JSONL audit trail
7. **Governed assist layer**
   - local Ollama-backed M.I.O. assist for ambiguous cases, operator questions, and runbook support

## Operator Surfaces

### Dashboard
The main situation board for command posture, threat evidence, NOC health, action selection, demo replay, and M.I.O. overview.

### `ops-comm`
The focused operator workspace for direct M.I.O. interaction, triage state machine flows, runbook review, Mattermost bridge, and demo control.

### Mattermost `/mio`
Chat entrypoint for operator queries, reviewed runbook suggestions, and guided handoff.

### TUI and EPD
Low-friction local visibility surfaces for runtime state, mode, and current posture.

## Platform Capabilities

### Managed edge gateway
- Internal network baseline around `br0`
- Default internal address space: `172.16.0.254/24`
- AP-mode internal access plus NAT/forwarding toward external uplink
- Host-side orchestration built around `NetworkManager`, `dnsmasq`, `nftables`, and systemd services

### Deterministic NOC/SOC pipeline
- Tactical Engine for first-minute triage on normalized Suricata events
- Evidence normalization through adapters
- Second-pass evaluation through Evidence Plane and deterministic evaluators
- Action decisions that remain explicit and reviewable
- Decision explanations and audit records by default

### Governed local AI
- Current Ollama model strategy:
  - `qwen3.5:2b`
  - `qwen3.5:0.8b`
- AI is used for:
  - ambiguous alert assistance
  - operator questions
  - runbook suggestion support
  - bilingual guidance output
- AI is not the primary decision-maker

### Guided triage and runbooks
- Deterministic triage state machine for temporary and beginner workflows
- Diagnostic-state-to-runbook selection
- Runbook review and approval flow
- Mattermost handoff from triage sessions

### Advanced and research extensions
- config drift audit
- multi-segment NOC evaluation
- cross-source correlation
- ATT&CK / D3FEND visualization payloads
- Sigma assist execution
- YARA / YARA-X assist matching
- upstream integration envelopes and sinks
- deterministic demo scenario pack

## Install and Reproduce

### Unified installer

```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_INTERNAL_NETWORK=1 \
     ENABLE_APP_STACK=1 \
     ENABLE_AI_RUNTIME=1 \
     ENABLE_DEV_REMOTE_ACCESS=0 \
     bash installer/internal/install_all.sh
```

Main toggles:
- `ENABLE_INTERNAL_NETWORK=1|0`
- `ENABLE_APP_STACK=1|0`
- `ENABLE_AI_RUNTIME=1|0`
- `ENABLE_DEV_REMOTE_ACCESS=1|0`
- `ENABLE_RUST_CORE=1|0`

### App stack only

```bash
sudo ENABLE_SERVICES=1 bash installer/internal/install_migrated_tools.sh
```

### AI runtime only

```bash
sudo ENABLE_OLLAMA=1 ENABLE_MATTERMOST=1 bash installer/internal/install_ai_runtime.sh
```

## Quick Tour

Default local endpoints after installation:
- Dashboard: `https://172.16.0.254/`
- M.I.O. ops console: `https://172.16.0.254/ops-comm`
- Mattermost: `http://172.16.0.254:8065/`
- Local backend: `http://127.0.0.1:8084/`

Mattermost operator shortcut:

```text
/mio What is the current highest-priority concern?
```

Deterministic demo replay:

```bash
bin/azazel-edge-demo list
bin/azazel-edge-demo run mixed_correlation_demo
```

## Repository Layout

| Path | Role |
|---|---|
| `py/azazel_edge/` | Evidence Plane, evaluators, arbiter, audit, SoT, triage, demo, and research/runtime extensions |
| `py/azazel_edge_control/` | Control daemon and action handlers |
| `py/azazel_edge_ai/` | AI agent integration and M.I.O. assist path |
| `azazel_edge_web/` | Flask backend, dashboard, ops-comm UI |
| `rust/azazel-edge-core/` | Rust defense core |
| `runbooks/` | Runbook registry |
| `systemd/` | Services and timers |
| `security/` | Compose stacks and security-side assets |
| `installer/` | Unified installer and staged install scripts |
| `docs/` | Public architecture, AI operation, persona, and demo documentation |
| `tests/` | Unit and regression coverage |

## Documentation

- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [AI build and operation detail](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md)
- [M.I.O. persona profile](docs/MIO_PERSONA_PROFILE.md)
- [Demo guide](docs/DEMO_GUIDE.md)
- [Demo guide (Japanese)](docs/DEMO_GUIDE_JA.md)


## Current Status

- P0, P1, and P2 implementation lines are present in the repository
- The installer has been updated to deploy the current runtime module set and required assets
- The repository currently contains **38** Python test modules and **15** runbook definitions

## License

See `LICENSE` if present in this repository.
