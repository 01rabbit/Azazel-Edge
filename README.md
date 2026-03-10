# Azazel-Edge

Azazel-Edge is a Raspberry Pi-class defensive edge gateway for small internal networks.
It combines a local gateway/AP stack, deterministic NOC/SOC evaluation, operator-facing UI surfaces, and tightly governed AI assistance for ambiguous security and operational events.

<p align="center">
  <img src="https://img.shields.io/badge/-Raspberry%20Pi-C51A4A.svg?logo=raspberry-pi&style=flat">
  <img src="https://img.shields.io/badge/-Python-F9DC3E.svg?logo=python&style=flat">
  <img src="https://img.shields.io/badge/-Rust-000000.svg?logo=rust&style=flat">
  <img src="https://img.shields.io/badge/-Flask-000000.svg?logo=flask&style=flat">
  <img src="https://img.shields.io/badge/-Mattermost-0058CC.svg?logo=mattermost&style=flat">
  <img src="https://img.shields.io/badge/-Ollama-111111.svg?style=flat">
</p>

## Concept

Azazel-Edge is not just a dashboard or a packet filter.
It is designed as an operator-aware edge appliance that:

- provides a managed internal segment and uplink gateway
- observes network and service health continuously
- ingests security and operational evidence into a shared evidence plane
- evaluates NOC and SOC conditions deterministically first
- chooses actions through an explicit arbiter
- explains decisions, logs them, and only then uses AI as a governed assist layer

The design goal is practical field use on constrained hardware, especially Raspberry Pi 5-class systems, without letting the AI path dominate or destabilize core defensive functions.

## What It Does

### 1. Internal edge gateway
- Builds an internal network baseline around `br0`
- Default internal address space: `172.16.0.254/24`
- Supports AP-mode internal access and NAT/forwarding toward an external uplink
- Uses `NetworkManager`, `dnsmasq`, `nftables`, and related host-side plumbing

### 2. Operational control plane
- Maintains a unified runtime snapshot consumed by WebUI, TUI, and EPD
- Exposes local control/actions through the control daemon
- Supports mode changes, reprobe, containment, Wi-Fi scan/connect, and related actions

### 3. Deterministic NOC/SOC pipeline
- Evidence Plane normalizes:
  - `suricata_eve`
  - `flow_min`
  - `noc_probe`
  - `syslog_min`
- NOC evaluator scores:
  - availability
  - path health
  - device health
  - client health
- SOC evaluator scores:
  - suspicion
  - confidence
  - technique likelihood
  - blast radius
- Action Arbiter selects:
  - `observe`
  - `notify`
  - `throttle`
  - `redirect`
  - `isolate`

### 4. Governed AI assistance
- Ollama-hosted local models are used only as a bounded assist path
- Current model strategy:
  - `qwen3.5:2b`
  - `qwen3.5:0.8b`
- AI is used for:
  - ambiguous Suricata alerts
  - operator questions
  - runbook suggestion support
- AI is not the primary decision-maker

### 5. Operator interfaces
- Web dashboard
- `/ops-comm` M.I.O. assist console
- Mattermost integration with `/mio`
- TUI status/control surface
- E-paper status display

## Current Runtime Architecture

High-level pipeline:

1. Evidence inputs
2. Evidence Plane
3. NOC / SOC evaluators
4. Action Arbiter
5. Decision Explanation
6. Notification / AI governance
7. Audit logging

Related implementation notes:
- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [AI build and operation detail](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md)

## Feature Highlights

### Unified evidence and evaluation
- Shared event schema with consistent fields:
  - `event_id`
  - `ts`
  - `source`
  - `kind`
  - `subject`
  - `severity`
  - `confidence`
  - `attrs`
- Source-specific adapters normalized into one downstream format

### Lightweight defensive research extensions
- config drift audit
- multi-segment NOC evaluation
- cross-source correlation
- ATT&CK / D3FEND visualization payloads
- Sigma assist execution
- YARA / YARA-X assist matching
- upstream integration envelope/sinks
- demo scenario pack

### M.I.O. operator assistance
M.I.O. is the operator support persona used in:
- dashboard assist
- `/ops-comm`
- Mattermost `/mio`

M.I.O. is designed as a governed assistant, not an unrestricted autonomous agent.

See:
- [M.I.O. persona profile](docs/MIO_PERSONA_PROFILE.md)

## Installation

### Unified installer

This is the main entrypoint for reproducing the current Azazel-Edge stack on another host:

```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_INTERNAL_NETWORK=1 \
     ENABLE_APP_STACK=1 \
     ENABLE_AI_RUNTIME=1 \
     ENABLE_DEV_REMOTE_ACCESS=0 \
     bash installer/internal/install_all.sh
```

Main flags:
- `ENABLE_INTERNAL_NETWORK=1|0`
- `ENABLE_APP_STACK=1|0`
- `ENABLE_AI_RUNTIME=1|0`
- `ENABLE_DEV_REMOTE_ACCESS=1|0`
- `ENABLE_RUST_CORE=1|0`

### App stack only

```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_SERVICES=1 bash installer/internal/install_migrated_tools.sh
```

### AI runtime only

```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_OLLAMA=1 ENABLE_MATTERMOST=1 bash installer/internal/install_ai_runtime.sh
```

## Access Points

Default local endpoints after installation:

- Dashboard: `https://172.16.0.254/`
- M.I.O. ops console: `https://172.16.0.254/ops-comm`
- Mattermost: `http://172.16.0.254:8065/`
- Local web backend: `http://127.0.0.1:8084/`

Mattermost operator shortcut:

```text
/mio 現在の警戒ポイントは？
```

## Core Services

Main systemd units:

- `azazel-edge-control-daemon.service`
- `azazel-edge-web.service`
- `azazel-edge-ai-agent.service`
- `azazel-edge-core.service`
- `azazel-edge-epd-refresh.service`
- `azazel-edge-epd-refresh.timer`
- `azazel-edge-opencanary.service`
- `azazel-edge-suricata.service`

## Quick Verification

```bash
systemctl status azazel-edge-control-daemon --no-pager
systemctl status azazel-edge-web --no-pager
systemctl status azazel-edge-ai-agent --no-pager
systemctl status azazel-edge-core --no-pager
curl http://127.0.0.1:8084/health
curl http://127.0.0.1:8084/api/state
```

AI runtime:

```bash
sudo docker exec azazel-edge-ollama ollama list
curl -sS http://127.0.0.1:8084/api/ai/capabilities | jq
```

## Repository Layout

| Path | Role |
|---|---|
| `py/azazel_edge/` | Core runtime libraries, evaluators, arbiter, AI governance, research extensions |
| `py/azazel_edge_control/` | Control daemon and action handlers |
| `py/azazel_edge_ai/` | AI agent integration and M.I.O. assist path |
| `azazel_edge_web/` | Web backend, dashboard, ops-comm UI |
| `rust/azazel-edge-core/` | Rust defense core |
| `runbooks/` | Runbook registry |
| `systemd/` | Service/timer units |
| `security/` | Compose stacks and security-side assets |
| `installer/` | Unified installer and staged install scripts |
| `docs/` | Architecture, AI operation, redesign and implementation notes |
| `tests/` | Unit/regression coverage for P0-P2 slices |

## Documentation

- [Architecture redesign notes](docs/ARCHITECTURE_REDESIGN.md)
- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [AI build and operation detail](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md)
- [Dashboard plan](docs/AZAZEL_EDGE_SOC_NOC_DASHBOARD_PLAN.md)

## Status

The repository currently contains completed P0, P1, and P2 issue lines as implemented runtime/library slices.
The installer has been updated to deploy the P0-P2 runtime module set and associated assets required by the current Azazel-Edge stack.

## License

See `LICENSE` if present in this repository.
