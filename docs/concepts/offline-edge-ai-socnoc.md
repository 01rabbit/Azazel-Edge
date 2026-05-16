# Offline Edge-AI SOC/NOC

## Purpose
Define an operational profile for running Azazel-Edge as a local-first SOC/NOC gateway when internet connectivity is unavailable or intentionally disabled.

## Operational Assumption
- Core detection and response must work without cloud services.
- Deterministic evaluation remains authoritative.
- Local AI assist is optional and bounded by AI Assist Governance.

## Target Environment
- Temporary emergency networks
- Isolated field offices
- Connectivity-constrained exercises and incident drills

## Core Capabilities
| Capability | Status | Notes |
|---|---|---|
| Deterministic NOC/SOC evaluation | Implemented | Core evaluator/arbiter path in repository runtime. |
| Local replay-based demo path | Implemented | Deterministic demo scenarios are available. |
| Local LLM advisory (Ollama) | Implemented | Optional; not required for deterministic operation. |
| Offline-first fallback operation | Implemented | Core functions do not require cloud access. |

## Demo Narrative
This profile demonstrates first-response operations where telemetry is normalized locally, evaluated deterministically, and translated into explicit actions with audit traces. AI output is treated as advisory context only.

## Relationship to Core Architecture
This profile uses the same Decision Loop, Evidence Model, and local AI triage boundaries as other Azazel-Edge profiles.

## What This Concept Is Not
- Not an autonomous AI defense system
- Not a replacement for full-scale SIEM operations
- Not a separate product fork

## Related Architecture Documents
- [Decision Loop](../architecture/decision-loop.md)
- [Local AI Triage](../architecture/local-ai-triage.md)
- [Evidence Model](../architecture/evidence-model.md)
