# AZ-01 Azazel-Edge - Deterministic Edge SOC/NOC Gateway

> **Codename:** `SENTINEL`

![Azazel-Edge Banner](images/Azazel-Edge_Banner.png)
[![CI](https://github.com/01rabbit/Azazel-Edge/actions/workflows/ci.yml/badge.svg)](https://github.com/01rabbit/Azazel-Edge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/01rabbit/Azazel-Edge)](https://github.com/01rabbit/Azazel-Edge/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-index-blue)](docs/INDEX.md)
![Platform: Raspberry Pi](https://img.shields.io/badge/Platform-Raspberry%20Pi-C51A4A?logo=raspberry-pi)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-Core-000000?logo=rust)
![Flask](https://img.shields.io/badge/Flask-Web%20API-000000?logo=flask)
[![Black Hat Arsenal](https://img.shields.io/badge/Black%20Hat-Arsenal%202025--2026-111111)](https://www.blackhat.com/)

Azazel-Edge is the AZ-01 core platform of the Azazel system, a Raspberry Pi-oriented deterministic edge SOC/NOC gateway and Cyber Scapegoat Gateway for constrained, temporary, and high-risk networks.

It observes local network evidence, evaluates NOC/SOC state deterministically, selects bounded actions (`observe`, `notify`, `throttle`, `redirect`, `isolate`), and records operator-visible explanations and audit traces.

Optional local AI assist may summarize or explain events, but it does not replace the deterministic decision loop.

Azazel-Edge is not a production SIEM replacement, not an autonomous AI defender, and not a promise of complete attack prevention.

**Who this is for:** security operators, field defenders, incident responders, training teams, and researchers working with constrained local networks.

2025 -> 2026 evolution line:
- `Deployable` focus (rapid portable edge setup) -> `Auditable` focus (explainable deterministic decisions, rejected alternatives, and reviewable trace evidence)

## Requirements

| Requirement | Detail |
|---|---|
| Hardware | Raspberry Pi-oriented; tested/developed for constrained edge deployment |
| OS | Raspberry Pi OS / Linux |
| Runtime | Python 3.10+, Rust core components |
| Network | Local edge segment with optional Suricata/OpenCanary integration |
| Optional | Ollama, Mattermost, Wazuh, Vector, Aggregator |

## Quick Start

```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_INTERNAL_NETWORK=1 \
     ENABLE_APP_STACK=1 \
     ENABLE_AI_RUNTIME=1 \
     ENABLE_DEV_REMOTE_ACCESS=0 \
     bash installer/internal/install_all.sh
```

Minimal verification:

```bash
sudo systemctl status azazel-edge-web azazel-edge-control-daemon azazel-edge-core --no-pager
```

Detailed install/deploy guidance:
- [Deployment Profiles](docs/DEPLOYMENT_PROFILES.md)
- [Operator Guide](docs/OPERATOR_GUIDE.md)
- [Field Deployment Guide](docs/FIELD_DEPLOYMENT_GUIDE.md)

## Architecture Overview

```mermaid
flowchart LR
    E[Event Inputs] --> P[Evidence Plane]
    P --> N[NOC Evaluator]
    P --> S[SOC Evaluator]
    N --> A[Action Arbiter]
    S --> A
    A --> X[Decision Explanation]
    X --> O[Operator Plane]
    X --> G[AI Assist Governance]
    G --> L[Local LLM Optional]
    A --> U[Audit Logger]
```

Full architecture:
- [Interactive Architecture Flow (HTML)](docs/architecture/azazel_edge_arch.html)
- [Decision Loop](docs/architecture/decision-loop.md)
- [Deception Routing](docs/architecture/deception-routing.md)
- [Local AI Triage](docs/architecture/local-ai-triage.md)
- [Evidence Model](docs/architecture/evidence-model.md)

## What Azazel-Edge does

- runs a local edge gateway and operations surface
- ingests local telemetry such as Suricata EVE
- evaluates NOC and SOC state through deterministic evaluators
- selects bounded actions through an Action Arbiter
- records explanations, alternatives, and audit traces
- supports replay-safe demos and operator workflows
- optionally uses local AI assist for summaries and triage hints

## Security Boundary Summary

Azazel-Edge claims:
- local-first deterministic decision support
- explicit bounded actions
- operator-visible explanation and audit traces
- optional AI assist that remains secondary to deterministic control

Azazel-Edge does not claim:
- complete attack prevention
- full SIEM replacement
- autonomous AI defense
- legal or regulatory compliance by itself
- safe deployment without operator understanding

## Concept Profiles

Azazel-Edge is maintained as a single core platform.
Different operational profiles are documented as concept profiles, not forks.

- [Evolution Map](docs/concepts/evolution-map.md)
- [Offline Edge-AI SOC/NOC](docs/concepts/offline-edge-ai-socnoc.md)
- [Deterministic Edge Decision Support](docs/concepts/deterministic-edge-decision-support.md)
- [Auditable Emergency SOC/NOC](docs/concepts/auditable-emergency-socnoc.md)
- [Auditable Edge SOC/NOC](docs/concepts/auditable-edge-socnoc.md)
- [Field-Deployable Scapegoat Gateway](docs/concepts/field-deployable-scapegoat-gateway.md)

Candidate CFP and planning material:
- [Candidate CFP Draft: Auditable Edge SOC/NOC](docs/cfp/blackhat-europe-arsenal-auditable-edge-socnoc.md)
- [Paper: Auditable Edge SOC/NOC Gateway](docs/papers/auditable-edge-socnoc-paper.md)

## Arsenal Demonstrations

Only accepted and public Black Hat Arsenal appearances are recorded here.

- [Black Hat Asia 2026](docs/arsenal/blackhat-asia-2026.md)
- [Black Hat USA 2026](docs/arsenal/blackhat-usa-2026.md)

BHUSA 2026 presenter note:
- [BHUSA 2026 Booth Message](docs/arsenal/bhusa-2026-booth-message.md)

See [Arsenal Demonstration History](docs/arsenal/README.md).

## Documentation Map

Primary entry points:
- [Documentation Index](docs/INDEX.md)
- [Core Runtime Architecture (P0)](docs/P0_RUNTIME_ARCHITECTURE.md)
- [API Reference](docs/API_REFERENCE.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [Deployment Profiles](docs/DEPLOYMENT_PROFILES.md)
- [Arsenal Demo Profile](docs/ARSENAL_DEMO_PROFILE.md)
- [Operator Guide](docs/OPERATOR_GUIDE.md)
- [AI Operation Guide](docs/AI_OPERATION_GUIDE.md)
- [Privacy and Legal Notes](docs/PRIVACY_AND_LEGAL.md)
- [Changelog](docs/CHANGELOG.md)

## Repository Layout

| Path | Role |
|---|---|
| `py/azazel_edge/` | Evidence Plane, evaluators, arbiter, explanations, audit |
| `py/azazel_edge_control/` | Control daemon and action handlers |
| `py/azazel_edge_ai/` | AI agent integration and M.I.O. assist path |
| `azazel_edge_web/` | Flask backend, dashboard, ops-comm UI |
| `rust/azazel-edge-core/` | Rust defense core |
| `runbooks/` | Runbook registry |
| `concept_profiles/` | Concept-to-configuration mapping layer |
| `demos/concepts/` | Concept-oriented deterministic demo grouping |
| `docs/` | Architecture, concept, operations, and reference documentation |

## Azazel Series / Related Repositories

Azazel-Edge is one form in the **Azazel** family (naming spec: `Azazel-<Form> <Role>`;
Forms: Gadget/Edge/Boot, Roles: Gateway/Shield/Probe). The umbrella doctrine hub is
the [Azazel](https://github.com/01rabbit/Azazel) project ("Cyber Scapegoat Gateway").

| Form | Codename | Class | Role in the series |
|---|---|---|---|
| **Azazel-Edge** | AZ-01 (formerly Azazel-Pi) | Resident edge-class gateway (Pi 5) | This repository — deterministic edge SOC/NOC gateway |
| Azazel-Gadget | AZ-02 (formerly Azazel-Zero) | USB-gadget-class portable device | Portable companion gateway; ships an EPD-on-Web dev preview |
| Azazel-Boot | AZ-03 | Reserved | Reserved form; no repository yet |
| Azazel-CTI | working name (formal name deferred) | Advisory-only on-prem CTI node (Pi 4) | Deterministic threat-context advice; never commands — Edge's arbiter keeps final authority and functions fully without it |
| Azazel-Common | shared contracts library | `pip install azazel-common` | Shared Pydantic contracts (`azazel_common`); Edge integration is design-only today (see [Edge adapter plan](docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md)) |

Azazel-Edge and Azazel-Gadget are MIT-licensed. See the [Azazel](https://github.com/01rabbit/Azazel)
umbrella project for series-wide doctrine.

## License

MIT. See [LICENSE](LICENSE).
