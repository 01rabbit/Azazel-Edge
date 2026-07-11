# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Azazel-Fabric の pin を `v0.3.0` → `v0.4.0` に更新(`requirements/fabric.txt`)。
  `py/azazel_edge/audit/fabric_adapter.py` の AuditEvent 射影を、v0.4.0 で追加
  された `azazel_fabric.audit.project_audit_event`/`to_jsonl_line` に委譲する
  よう小さくリファクタ(ドロップイン、挙動変更ゼロ)。`event_id` は従来どおり
  Edge 側の `chain_hash`(フォールバック `trace_id:kind`)規約を明示的に渡すため
  `project_audit_event` の `make_event_id` デフォルトには委譲しない。ハッシュ
  チェーン書込み経路(`P0AuditLogger`)は無変更。emit されるフィールド集合は
  不変だが、シリアライズが Pydantic の `model_dump_json()`(挿入順・空白区切り)
  から `to_jsonl_line`(キーソート・コンパクト区切り)に変わり、
  `<name>.fabric.jsonl` の行はバイト同一ではなくなった(内容は意味的に同一。
  このストリームを行位置/バイト比較で読むコンシューマは存在しない)。
  `tests/test_fabric_adapters_v1.py` の `ApiStateStatusViewTests` を
  `azazel_fabric.testing.make_status_view` で簡素化(StatusView のマッピング
  ロジック自体は `StatusViewTests` で別途検証済みのため、API 読み戻しテストは
  Edge 独自のスナップショット変換に依存しない汎用フィクスチャへ切替)。
- Azazel-Fabric の pin をオプションの `requirements/fabric.txt` に分離(Fabric
  リポジトリは private のため、無認証環境 = CI では解決不能。全統合点は
  ガード付き no-op なので未導入でも動作は同一。導入時のみ射影が有効化)。

### Added
- Azazel-Fabric adoption — Phase 3 (2026-07-10): Edge now ships the three §3
  emit-alongside projections from `docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md` plus
  an owner-directed StatusView extension, making Edge the top consumer of the
  shared contracts library. All paths are guarded (`try: import azazel_fabric`)
  and are exact no-ops when the package is absent — zero behavior change:
  - **DecisionExplanation projection** (§3.1): each persisted v2 decision
    explanation is additionally serialized as
    `azazel_fabric.schema.DecisionExplanation` to a separate
    `fabric-decision-explanations.jsonl` stream; Edge's own
    `decision-explanations.jsonl` is byte-for-byte unchanged. Lossy interop
    projection (`why_chosen` dict→str, `selected_action` name→`ActionIntent`,
    `why_not_others` flattened to strings).
  - **TrustCapsule projection** (§3.2): emitted as
    `azazel_fabric.schema.TrustCapsule` to `fabric-trust-capsules.jsonl` with
    the plan's field mapping (`hmac_sig`→`hmac`, `timestamp`→`issued_at`,
    `config_hash` sourced from the explanation).
  - **AuditEvent projection** (§3.3): `P0AuditLogger.log()` additionally
    projects `azazel_fabric.schema.AuditEvent` to a separate, non-interleaved
    sibling file (`<name>.fabric.jsonl`) so the hash chain and `verify_chain()`
    are never perturbed. `tactics_engine/decision_logger.py` is left untouched
    (§3.4, deferred).
  - **StatusView emit + surface** (scope extension, owner-directed): new
    `py/azazel_edge/fabric_view.py` builds `azazel_fabric.view.StatusView` from
    the runtime snapshot (carrying the full snapshot under
    `product_view.edge_snapshot`) and writes `ui_status_view.json` alongside
    `ui_snapshot.json`. `GET /api/state` gains a `status_view` key (null when
    unavailable). See `docs/API_REFERENCE.md`.
  - Pins `azazel-fabric` in `requirements/runtime.txt` at the exact merged
    commit (v0.3.0 tag pending).
- Documentation updates for the Azazel series naming change (2026-07-10): Azazel-CTI → Azazel-Knowledge (AZ-04) and Azazel-Common → Azazel-Fabric (AZ-05). Updated the README series table, `docs/INDEX.md`, and added a naming-update status note to `docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md` (file not renamed; body text and `azazel_common` references pre-`v0.3.0` are left as originally written).
- EPD-on-Web preview for Azazel-Edge: read-only, viewer-gated web routes that expose the physical e-paper panel state — `GET /api/epd` (mode/state plus raw `epd_state.json`, desired render spec, and last-drawn frame), `GET /api/epd/preview.png` (pixel-parity PNG rendered in-memory by the real `py/azazel_edge_epd.py` renderer, fail-closed `503` when the renderer/assets are unavailable), and `GET /dev/epd` (self-contained dark-themed dev page). Adds `AZAZEL_EPD_RUNTIME_DIR` / `AZAZEL_EPD_STATE_PATH` / `AZAZEL_EPD_LAST_RENDER_PATH` dev overrides. See `docs/API_REFERENCE.md` and `docs/CONFIGURATION.md`.
- Design-only integration plan `docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md` (2026-07-09) describing the azazel-common contract adapter for Edge; documents planning intent only (no shipped code), with Edge↔CTI integration deferred to FY2027+.
- Candidate CFP draft (`docs/cfp/blackhat-europe-arsenal-auditable-edge-socnoc.md`) and paper-style concept document (`docs/papers/auditable-edge-socnoc-paper.md`) for the Auditable Edge SOC/NOC profile (pre-acceptance planning material; not accepted-appearance records).
- Submission-preparation roadmap (`docs/archive/roadmaps/auditable-edge-socnoc-cfp-roadmap.md`) and gh-registerable issue drafts (`docs/archive/issues/auditable-edge-socnoc/`) for the Auditable Edge SOC/NOC profile.
- BHUSA 2026 booth-preparation document set covering docs sync, talk track, replay runbook, audit walkthrough, booth decision-support view, live/replay boundary, rehearsal runbook, freeze candidate, and final command sheet.
- BHUSA 2026 status helper (`bin/azazel-edge-bhusa-status`) to summarize recorded rehearsals, optional freeze-check results, and GitHub child issue state in one snapshot.
- BHUSA 2026 readiness reports now embed the status snapshot and persist `status.json` through report/archive/freeze-record artifacts.
- BHUSA 2026 issue helper can now render a parent roadmap progress comment from the current readiness snapshot.
- BHUSA 2026 status helper can now render and write the repository `15-status.md` tracking document from the live readiness snapshot.
- BHUSA 2026 issue helper can now sync the created-issue links doc from live GitHub child issue state.
- BHUSA 2026 issue helper can now persist the parent roadmap progress comment as a repo artifact.
- BHUSA 2026 issue helper can now persist the parent issue child-links comment as a repo artifact.
- BHUSA 2026 prep helper now includes `repo-sync` to refresh repo-side status and issue-tracking artifacts in one command.
- BHUSA 2026 prep helper now includes `daily-pack` to refresh repo-side tracking artifacts and generate the operator pack in one command.
- BHUSA 2026 prep helper now includes `candidate-pack` to refresh tracking artifacts, generate the operator/freeze packs, and run the local freeze gate in one command.
- BHUSA 2026 candidate-pack output now includes a concise freeze-readiness summary with open-issue and blocker counts.

### Changed

## [0.1.2] - 2026-05-17

### Changed
- Added interactive architecture flow document link to `README.md` and introduced `docs/architecture/azazel_edge_arch.html`.
- Synced benchmark report artifacts in `docs/BENCHMARK_RESULTS.json` and `docs/BENCHMARK_RESULTS.md` after validation rerun.
- Consolidated AI governance charter to a single authoritative `AGENTS.md` (English) and removed `AGENTS_EN.md`.
- Renamed concept profile mapping directory from `configs/profiles/` to `concept_profiles/` and updated documentation references accordingly.

## [0.1.1] - 2026-05-14

### Added
- Protocol-aware redirect policy baseline for prepared decoy services:
  - redirect mapping by destination port
  - unsupported-port deterministic fallback action
  - compatibility fallback to `AZAZEL_DEFENSE_HONEYPOT_PORT` only when policy file is absent
  - fail-safe `notify` fallback when redirect policy is invalid or disabled
  - enforcement metadata for mapping/fallback traceability
- Arsenal demo profile runbook (`docs/ARSENAL_DEMO_PROFILE.md`).
- Deployment profile matrix (`docs/DEPLOYMENT_PROFILES.md`) for constrained hardware clarity.
- Benchmark scope boundary and hardware-in-the-loop plan (`docs/BENCHMARK_SCOPE_AND_HIL_PLAN.md`).
- Benchmark report metadata fields:
  - `benchmark_mode`
  - `hardware`
  - `claim_scope`

### Changed
- README testing/current status wording to avoid stale validation claims.
- Benchmark report wording to identify software-only EVE replay scope.
- SOC policy guide updated with prepared decoy redirect model notes.

## [0.1.0] - 2026-05-13

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
- Cycle 3 implementation line:
  - aggregator pull-mode polling engine and admin poller control API
  - disaster-context TI IOC feeds with default SOC load path
  - MiniSigma YAML rule packs with default SOC integration
  - Wi-Fi congestion and rogue-AP Evidence Plane dispatch integration
  - TAXII 2.1 outbound push client and admin push/test APIs
  - optional SNMP/NetFlow sensor systemd units + installer wiring
  - captive portal multilingual baseline (`es`, `uk`, `tl`) with safe fallback
  - cycle tracker documentation/index updates (`#242`-`#249`)

### Changed
- Dependency review CI job now runs only when repository variable `ENABLE_DEPENDENCY_REVIEW` is set to `true`.
  - This avoids false CI failures on repositories where Dependency Graph is disabled.
- README refreshed to align with current runtime capabilities and fail-closed posture.
- Local developer runtime execution standardized on `.venv`:
  - new `bin/azazel-edge-dev` helper (`bootstrap`, `test`, `python`)
  - launcher scripts prefer repository `.venv` with `/opt/azazel-edge/venv` fallback
  - development dependency split introduced via `requirements/dev.txt`

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
