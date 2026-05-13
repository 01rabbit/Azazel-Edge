# Next Development Execution Index (2026Q2)

Last updated: 2026-05-13
Tracking Epic: #149

## Purpose
This index defines a repeatable execution order for the next development cycle across environments.
It fixes issue priority, tags, dependencies, and environment-specific execution expectations.

## Work Index

Priority | Issue | Title | Labels | Depends on
---|---|---|---|---
P1 | #150 | Rust defense enforce path: dry-run to controlled enforcement | `priority:P0`, `area:rust`, `area:security`, `area:runtime` | -
P1 | #151 | Introduce GitHub Actions baseline CI for Python+Rust | `priority:P0`, `area:ci`, `area:quality` | -
P1 | #152 | Fix EPD CLI help crash (incomplete format) | `priority:P1`, `area:ops`, `area:quality` | -
P2 | #153 | Implement Decision Trust Capsule for audit-grade explainability | `priority:P1`, `area:ai`, `area:security`, `area:integration` | #150
P2 | #154 | Correlation engine expansion: sequence and distributed patterns | `priority:P1`, `area:core`, `area:quality`, `soc` | #150
P2 | #155 | Add SoT dynamic update API with re-evaluation trigger | `priority:P1`, `area:api`, `area:core`, `area:security` | #151
P3 | #156 | Runbook schema validation and quality gate tests | `priority:P1`, `area:runbook`, `area:quality` | #151
P3 | #157 | Dashboard visibility: AI contribution/fallback metrics | `priority:P1`, `area:ai`, `area:integration`, `ui` | #151, #153
P3 | #158 | Notification fallback hardening (SMTP/Webhook + ack audit) | `priority:P1`, `area:notify`, `area:ops`, `area:security` | #151
P4 | #159 | Add repository LICENSE and align README legal metadata | `priority:P2`, `area:license` | -

## Environment Matrix

Environment | Primary goal | Minimum setup | Must-run checks
---|---|---|---
macOS/Linux dev | Implementation and unit tests | `python3.10+`, `rust`, `.venv` | `PYTHONPATH=py:. pytest -q`, `cargo test` (core)
Ubuntu CI | Automated regression detection | GitHub Actions runner | workflow green (`pytest` + `cargo test`)
Raspberry Pi runtime | systemd/permission/runtime validation | Suricata, systemd, `/run/azazel-edge` | service status, socket mode, API path checks

## Execution Order (Strict)
1. `#150` (enforce path)
2. `#151` (CI baseline)
3. `#152` (EPD crash)
4. `#153`, `#154`, `#155` (P2 line)
5. `#156`, `#157`, `#158` (P3 line)
6. `#159` (license)

## Ownership Split (Parallel-safe)
- Runtime/Defense owner: `#150`, `#152`
- Platform/CI owner: `#151`, `#156`, `#159`
- SOC/AI owner: `#153`, `#154`, `#157`
- Ops/Integration owner: `#155`, `#158`

Rule:
- For cross-cutting file sets, declare write scope among owners before implementation starts.

## Definition of Done (Common)
- Acceptance criteria are satisfied.
- Added tests are green.
- README/docs impacts are reflected.
- Audit or operational boundary changes include explicit rationale.

## Topo-Lite Execution Track (from #143 policy memo)

Priority | Issue | Title | Labels | Depends on
---|---|---|---|---
P0 | #173 | [Topo-Lite] Default monitoring scope to internal network (br0/172.16.0.0/24) | `priority:P0`, `initiative:topo-lite`, `area:integration`, `area:ops`, `noc` | #140
P0 | #172 | [Topo-Lite] Synthetic seed mode with strict live-evidence separation | `priority:P0`, `initiative:topo-lite`, `area:security`, `area:integration`, `soc`, `ui` | #173
P0 | #174 | [Topo-Lite] Left-sidebar integration and single-screen visual triage UI | `priority:P0`, `initiative:topo-lite`, `area:integration`, `ui`, `soc`, `noc` | #173, #172
