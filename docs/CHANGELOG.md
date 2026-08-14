# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Focus screens informed by commercial SIEM/SOC/NOC dashboard patterns
  (design notes in `docs/architecture/socnoc-workspace-design.md`):
  - **Simple+**: the Simple landing view gains a Splunk-style KPI strip
    (Risk / Now queue / Direct critical / Impacted clients / Uplink /
    Services, with ~1-min trend arrows), a band-colored 60-min activity
    strip, and a deterministic pipeline funnel
    (`events → signals → now/watch → action`).
  - **SOC Focus panel** (SOC workspace): NOW/WATCH/BACKLOG + critical +
    visibility + oldest-unhandled-NOW KPIs, a real triage **table** over the
    deterministic queue bands (band chips + keyword filter), a Decision card
    (arbiter's pick, why, why-not-stronger, confidence/evidence/AI role),
    and a 6-hour alerts-over-time strip.
  - **NOC Focus panel** (NOC workspace): uplink/internet/capacity/clients/
    impacted/services KPIs, a five-hop **path health strip**
    (clients → edge → uplink → gateway → internet; the edge-local answer to
    a geo map), a top-talkers table joined with the client identity view,
    runtime meters, and service chips.
  - **BHUSA 2026 decision rationale per jurisdiction**: the booth-focus
    payload now exposes `domains.noc` / `domains.soc` (per-domain evaluator
    `reasons` from the same v2 explanation record), and the bundle carries
    the whole projection as `decision_focus`. The SOC focus panel's decision
    card shows the arbiter's pick, the SOC evaluator rationale, why-not-
    stronger, the release condition, and the audit line (trace · policy ·
    config hash · evidence ids · DRY RUN/ENFORCED); the NOC focus panel
    gains the mirrored card with the NOC jurisdiction's rationale. Falls
    back to the live actions payload when no explanation record exists.
  - Backend: the dashboard bundle gains an `activity` key — time-bucketed
    alert counts (1h/2min, 6h/20min) banded with the same thresholds and
    `_normalize_alert_event` normalizer as the alert queues; queue item caps
    raised 5→12 per band (8 for escalation) for the triage table. Documented
    in `docs/API_REFERENCE.md`.

- `GET /api/dashboard/bundle`: one-request snapshot for the dashboard poll,
  aggregating summary / actions / health / evidence / trends / state /
  topolite seed mode / Mattermost status plus role-gated operator-progress
  and handoff blocks (null for viewers). The WebUI now polls this single
  endpoint instead of ~11 parallel requests per tick — removing the
  documented worker-starvation / OFFLINE-flicker failure mode and reading
  shared inputs (state.json, AI metrics/advisory, JSONL tails) once
  server-side instead of once per endpoint. Per-panel endpoints unchanged;
  documented in `docs/API_REFERENCE.md`.

### Changed

- WebUI baseline language is now English: with no explicit `?lang=` /
  `X-AZAZEL-LANG` header / `azazel_lang` cookie / saved browser choice, pages
  render in English (`Content-Language: en`). Japanese remains fully available
  via the existing 日本語/English toggle, and an explicit or previously saved
  choice always wins. Aligns the UI with the repository language policy
  (English default, Japanese supplemental). Non-web surfaces (notifications,
  runbook wording defaults) are unchanged.

### Removed

- Dashboard audience split (Beginner/Professional toggle): the Simple view
  now serves the "show me less" need, so the audience axis, the
  `pro-only`/`temp-only` gating, the Temporary Mission panel, the temporary
  triage / ask-tell blocks, and the dashboard progress-checklist block are
  gone. The workspace toggle (`Simple | All | NOC | SOC`) is fully available
  to every operator; `/api/dashboard/actions` still accepts `audience` for
  other surfaces (the dashboard always requests professional wording).
- Dashboard routes to the AI assist (M.I.O.): the topbar "Ask M.I.O." link,
  the M.I.O. assist rail (ask form, shortcuts, rationale/review blocks), and
  the per-panel "Ask about this" buttons are removed. The rail now hosts a
  deterministic Handoff panel (brief pack, copy, send to Ops Comm /
  Mattermost, Mattermost reachability). The `/api/ai/*` endpoints and the
  Ops Comm surface are unchanged.

- Simple view as the dashboard's default landing screen: three verdict tiles
  answering "Overall — are we safe? / SOC — any threat? / NOC — is the network
  healthy?", each with a one-line reason, the top "Do now" action, and
  glance chips; click a tile to drill into the full board or the SOC/NOC
  workspace. Verdicts have four states (GOOD/WATCH/BAD and UNKNOWN when
  inputs are stale — a stale snapshot never renders a false green) and reuse
  the existing deterministic `summarize*`/`strongestTone` logic, so the Simple
  tile can never disagree with the full board. Available in both audiences;
  the workspace toggle is now `Simple | All | NOC | SOC` (NOC/SOC still
  professional-only). Design rationale added to
  `docs/architecture/socnoc-workspace-design.md`.

- SOC / NOC workspace modes for the dashboard (design note:
  `docs/architecture/socnoc-workspace-design.md`, informed by SIEM/SOC/NOC
  dashboard design research — role-specific views over a single pane of glass,
  the 5-second rule, alert-by-exception, NOC glanceability). A topbar
  `All | NOC | SOC` toggle (professional audience only, persisted, `?workspace=`
  override) re-composes the existing panels per domain: the SOC workspace leads
  with posture → SOC/NOC split → action board → evidence timelines (split and
  evidence folds auto-open), hiding NOC-only detail blocks; the NOC workspace
  leads with client identity → path/service boards → runtime health → node
  fleet, hiding the threat-posture card, SOC detail split card, and the
  evidence audit board. Cross-domain glance cards are never hidden (the
  doctrine requires checking the other domain before stronger control). Fold
  persistence now records only explicit summary clicks so workspace defaults
  don't overwrite operator choices. No new endpoints or payload changes.

- Dashboard usability pass (post-BHUSA 2026 polish, roadmap #283): sticky
  section navigation over the dashboard panels (audience-aware; absorbs and
  replaces the old Topo-Lite mini nav panel) with a back-to-top button;
  `<details>` fold state now persists across reloads (localStorage);
  header freshness controls — an "UPD" seconds-since-last-update chip that
  turns amber when stale, a manual refresh button, and a pause/resume
  auto-refresh toggle (LINK chip shows `PAUSED`); evidence timelines gained a
  keyword filter and "+N more" expanders instead of silent `.slice()`
  truncation (alert queues now keep up to 8 now / 4 escalation entries
  available). Accessibility: `aria-pressed` on language/audience/mode/pause
  toggles, `role="group"` instead of misused `role="tablist"`.
  i18n: ~25 hardcoded English strings in `index.html` and the JS timeline
  empty-state/`Switch to Live` labels now go through `tr()` with new ja/en
  catalog keys. No API surface change; dashboard payload contracts unchanged
  (`tests/test_dashboard_data_contract.py` extended for the new elements).

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
- Added `SECURITY.md` (private GitHub Security Advisory reporting process, response targets, and appliance-flavored in/out-of-scope boundary between scapegoat/deception surfaces and the protected segment / control plane). Aligned `CONTRIBUTING.md` with a "Security" section pointing to it and a "License" section (MIT), and updated the pytest checklist line with the current baseline (502 passing; known `bhusa` sandbox-only failures in constrained/offline environments).
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
