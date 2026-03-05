# Azazel-Edge Redesign (Rust core + Python AI)

## Goals
- Real-time defense first, AI assist second.
- Event-driven pipeline from Suricata EVE.
- Safe migration: existing Python services remain operational.

## Runtime split
- Rust (`azazel-edge-core`): event intake, normalization, immediate defensive decisioning.
- Python (`azazel_edge_ai.agent`): tactical advisory only (no direct packet control).
- Shell: installation and host configuration only.

## Event flow
1. Suricata writes `/var/log/suricata/eve.json`.
2. Rust core tails EVE and normalizes alert events.
3. Rust core emits normalized JSONL to `/var/log/azazel-edge/normalized-events.jsonl`.
4. Rust core pushes normalized events over Unix socket `/run/azazel-edge/ai-bridge.sock`.
5. Python AI agent consumes events and writes advisory output to `/run/azazel-edge/ai_advisory.json`.

## Defensive priority
1. Real-time defense decision in Rust.
2. Observation and evidence retention.
3. AI tactical analysis.

## Rollout strategy
- Default: `ENABLE_RUST_CORE=0` (existing stack only).
- Opt-in: `ENABLE_RUST_CORE=1` enables Rust build + `azazel-edge-core` and `azazel-edge-ai-agent` services.
- Rollback: disable both services and keep current Python control plane.
