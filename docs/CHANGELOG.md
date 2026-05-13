# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Aggregator MVP scaffold (design-to-implementation bridge):
  - in-memory node registry with registration and summary ingest
  - freshness classification (`fresh` / `stale` / `offline`)
  - protected APIs: `/api/aggregator/nodes/register`, `/api/aggregator/ingest/summary`, `/api/aggregator/nodes`
  - regression tests for registry behavior and API role enforcement
- Multi-node Azazel Aggregator architecture design baseline:
  - node identity/registration model
  - minimal summary schema
  - stale/offline behavior model
  - communication security assumptions
  - phased roadmap (`MVP` / `field-ready` / `extended`)
  - explicit out-of-scope boundaries
- Tamper-evident audit log chaining in `P0AuditLogger` with `chain_prev` and `chain_hash`.
- Audit chain verifier: `P0AuditLogger.verify_chain(path)` to detect tampering.
- CI supply-chain baseline job:
  - CycloneDX SBOM generation (`sbom-runtime.cdx.json`)
  - Dependency vulnerability scan baseline (`pip-audit-runtime.json`)
  - Artifact upload for supply-chain outputs
- Dashboard evidence alert queue aggregation (`now/watch/backlog`) with suppression snapshot and escalation candidate projection.
- Lightweight dashboard trends API (`/api/dashboard/trends`) backed by JSONL time-series points for queue depth, fallback rate, latency EMA, and stale flags.
- Dashboard evidence panel cards for Alert Queues and Trend Snapshot (wired to deterministic evidence and trends APIs).
- Tunable alert-queue thresholds via env vars:
  - `AZAZEL_ALERT_QUEUE_NOW_THRESHOLD`
  - `AZAZEL_ALERT_QUEUE_WATCH_THRESHOLD`
  - `AZAZEL_ALERT_QUEUE_ESCALATE_THRESHOLD`
- Auth hardening baseline:
  - fail-closed role-based API auth (`viewer/operator/responder/admin`)
  - optional mTLS fingerprint enforcement for action-capable endpoints
  - authorization audit log with principal, role, trace_id, requested action, and decision result
- Alert aggregation baseline with suppression window, aggregation window, and escalation count threshold.
- SOC policy baseline:
  - `config/soc_policy.yaml`
  - `AZAZEL_SOC_POLICY_PATH`
  - policy version/hash attached to arbiter decisions
- Rust defense enforcement path baseline for action set:
  - `observe`, `notify`, `throttle`, `redirect`, `isolate`
  - staged enforcement level (`advisory` / `semi-auto` / `full-auto`)
  - structured enforcement outcome with trace_id, selected action, target, command plan, result, and rollback hint
- SOC policy dry-run helper (`bin/azazel-soc-policy-dry-run`) and profile examples (`conservative`, `balanced`, `demo`).
- Dashboard trends expanded with CPU/memory/temperature/interface utilization fields and windowed trend query support.
- ATT&CK evidence enrichment baseline:
  - `config/attack_mapping.yaml` mapping rules with confidence
  - mapped/unmapped handling in SOC evaluator summary (`attack_techniques`)
  - mapping schema validation + mapped/unmapped/conflict tests
- Supply-chain CI baseline completion:
  - lightweight Python static check job (`compileall`)
  - release checksum artifact generation (`release-checksums.sha256`)
  - release verification documentation (`docs/RELEASE_VERIFICATION_GUIDE.md`)
- Notification transport hardening line:
  - Syslog CEF notifier adapter (`SyslogCEFNotifier`)
  - offline queue notifier with recovery flush (`OfflineQueueNotifier`)
  - summary-only transfer mode in `DecisionNotifier`
- Installer/runtime integration line:
  - Vector installer + service/config baseline
  - Wazuh ARM64 installer baseline
  - periodic self-test timer/service and helper script
  - encrypted storage default installer path (`SKIP_LUKS=1` opt-out)
  - captive portal consent page and registration API baseline
- Operations/deployment documentation pack:
  - operator/deployment/legal/maintenance guides
  - docs index and GitHub Pages docs landing refresh
  - implementation cycle feature inventory (`docs/IMPLEMENTATION_CYCLE_2026Q2_FEATURE_INVENTORY.md`)

### Changed
- Dependency review CI job now runs only when repository variable `ENABLE_DEPENDENCY_REVIEW` is set to `true`.
  - This avoids false CI failures on repositories where Dependency Graph is disabled.
- README refreshed to align with current runtime capabilities and fail-closed posture.

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
