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

## 2026-Q1 (P0 completion line)

| Capability | PR | Commit |
|------------|-----|--------|
| Dedicated demo workspace | #74 | d084852 |
| NOC runtime projection integration | #88 | 8d3937a |
| SOC state dimensions in runtime/UI | #86 | a4a6fa0, bebdd13 |
| Auth contract and i18n hardening | #87 | 72e9253 |
| Beginner-default UI mode | #95 | 7773624 |
