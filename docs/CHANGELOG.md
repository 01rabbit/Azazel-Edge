# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Tamper-evident audit log chaining in `P0AuditLogger` with `chain_prev` and `chain_hash`.
- Audit chain verifier: `P0AuditLogger.verify_chain(path)` to detect tampering.
- CI supply-chain baseline job:
  - CycloneDX SBOM generation (`sbom-runtime.cdx.json`)
  - Dependency vulnerability scan baseline (`pip-audit-runtime.json`)
  - Artifact upload for supply-chain outputs

### Changed
- Dependency review CI job now runs only when repository variable `ENABLE_DEPENDENCY_REVIEW` is set to `true`.
  - This avoids false CI failures on repositories where Dependency Graph is disabled.

## [2026-05-12]

### Added
- Tamper-evident audit chaining baseline in `P0AuditLogger` (`chain_prev`, `chain_hash`) and chain verification helper.
- Supply-chain CI baseline:
  - CycloneDX SBOM artifact generation
  - `pip-audit` dependency vulnerability baseline scan
  - artifact upload for security review workflows

### Changed
- CI dependency-review job is now guarded by repository variable `ENABLE_DEPENDENCY_REVIEW=true` to avoid unsupported-repository failures.

## [2026-05-11]

### Added
- Topo-Lite integration line:
  - Internal network default monitoring scope (`#176`)
  - Synthetic seed mode with live-evidence separation (`#177`)
  - Left-rail integration and single-screen triage UI (`#178`)
- Decision trust capsule output (`#167`).
- Correlation expansion for sequence/distributed patterns (`#168`).
- Dashboard AI governance visibility panel/API (`#169`).
- Notification fallback line with webhook/SMTP and ack audit (`#170`).
- SoT devices dynamic update API (`#166`).
- Baseline CI workflow for Python/Rust (`#162`).
- Runbook schema and approval quality gate tests (`#164`).
- Rust dry-run enforcement planning path (`#165`).
- 2026Q2 indexed execution plan docs (`#160`).

### Fixed
- EPD `--help` percent-format crash (`#161`).

### Changed
- Documentation line:
  - Added MIT license and aligned metadata (`#163`)
  - Consolidated docs to English-only
  - Standardized README badges and banner presentation
  - Synced open-work index and policy-to-implementation mapping (`#171`, `#175`)

## [2026-03-16]

### Fixed
- Stabilized onboarding guide behavior (`#103`).

## [2026-03-15]

### Added
- Client identity closure and documentation line completion (`#102`).

## [2026-03-14]

### Added
- Beginner-default dual audience mode in UI (`#95`).
- Normal Assurance, Primary Anomaly, and Client Identity View (`#94`).
- Live NOC runtime projection integration into control-daemon (`#88`).
- SOC state maturation and dashboard integration (`#86`).

### Changed
- Web UI auth contracts and i18n coverage hardening (`#87`).

## [2026-03-13]

### Added
- Dedicated demo workspace split from live dashboard (`#74`).
- Resource guard and localization refinement (`#75`).
- NOC operational line:
  - blast radius summaries (`#70`)
  - config drift health tracking (`#71`)
  - incident compression summaries (`#72`)
  - runbook workflow support (`#73`)
