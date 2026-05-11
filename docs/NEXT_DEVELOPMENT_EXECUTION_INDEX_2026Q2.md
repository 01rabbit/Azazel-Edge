# Next Development Execution Index (2026Q2)

Last updated: 2026-05-11  
Tracking Epic: #149

## Purpose

このドキュメントは、次の開発サイクルを「誰が・どの環境でも・同じ順序で」実行できるようにするための実行インデックスです。  
Issue の優先度、タグ、依存関係、環境別の実施手順を固定します。

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
macOS/Linux dev | 実装・単体テスト | `python3.10+`, `rust`, `.venv` | `PYTHONPATH=py:. pytest -q`, `cargo test` (core)
Ubuntu CI | 自動回帰検知 | GitHub Actions runner | workflow green (`pytest` + `cargo test`)
Raspberry Pi runtime | systemd/権限/実挙動検証 | Suricata, systemd, `/run/azazel-edge` | service status, socket mode, API path checks

## Execution Order (Strict)

1. `#150` (enforce path)
2. `#151` (CI baseline)
3. `#152` (EPD crash)
4. `#153`, `#154`, `#155` (P2 line)
5. `#156`, `#157`, `#158` (P3 line)
6. `#159` (license)

## Ownership Split (Parallel-safe)

- **Runtime/Defense owner**: `#150`, `#152`
- **Platform/CI owner**: `#151`, `#156`, `#159`
- **SOC/AI owner**: `#153`, `#154`, `#157`
- **Ops/Integration owner**: `#155`, `#158`

Rule:
- 同一ファイル群を跨ぐ実装は、先に owner 間で write scope を宣言してから着手する。

## Branch/PR Convention

- Branch: `feature/<area>-i<issue-number>-<short-name>`
  - Example: `feature/rust-i150-enforce-path`
- PR title: `[#<issue>] <short summary>`
- PR body must include:
  - Scope
  - Risk
  - Rollback
  - Validation commands

## Definition of Done (Common)

- issue の acceptance 条件を満たす
- 追加テストが緑
- README / docs への影響が反映済み
- 監査ログ・運用境界に関わる変更は理由を明文化

