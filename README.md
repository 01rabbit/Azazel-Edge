# Azazel-Edge

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

Track record: This project line has been presented through Black Hat Arsenal review tracks (2025-2026).  
Azazel-Edge is the successor project to Azazel-Pi; earlier accepted sessions were presented under the Azazel-Pi name.

Azazel-Edge is a Raspberry Pi-oriented edge operations stack that combines:
- internal network/gateway setup
- deterministic NOC/SOC evaluation and action selection
- Web UI + API + runbook workflow for operators
- optional local AI assist (Ollama + Mattermost integration)

This README is based on verified repository contents (code, scripts, tests, git history, GitHub issue/PR metadata) as of **2026-05-14**.

## What is Azazel-Edge?

Azazel-Edge is a **lightweight SOC/NOC gateway for emergency operations**, designed to run on a Raspberry Pi.

**Who it's for**
- Security staff running a temporary network segment (event venue, field office, training exercise)
- Operators who need first-response triage without a full SIEM
- Teams practicing incident response with a local, offline-capable stack

**When to use it**
- You need a working gateway + alert triage surface in under an hour
- You have no cloud connectivity or want to keep traffic fully local
- You want a deterministic decision engine with optional local AI assist (Ollama), not a black-box

**What it is not**
- A replacement for a production SIEM or full-time SOC platform
- An autonomous AI that makes decisions without operator confirmation
- Cloud-dependent: all core functions work offline

## Verified Purpose

The implemented purpose in this repository is:

1. Run an internal edge segment (`br0`, DHCP, NAT/forwarding) and expose an operations surface.
2. Consume normalized telemetry and evaluate NOC/SOC state deterministically.
3. Produce explicit actions (`observe`, `notify`, `throttle`, `redirect`, `isolate`) with explanation/audit payloads.
4. Provide operator workflows (dashboard, triage, runbooks, Mattermost bridge, deterministic demo).
5. Optionally assist with local LLM inference through Ollama (bounded assist path, not mandatory for deterministic demo path).

Evidence:
- Gateway/network baseline: `installer/internal/install_internal_network.sh`
- Deterministic action model: `py/azazel_edge/arbiter/action.py`
- Web/API surfaces: `azazel_edge_web/app.py`
- Demo deterministic replay: `bin/azazel-edge-demo`, `py/azazel_edge/demo/scenarios.py`
- AI agent runtime: `py/azazel_edge_ai/agent.py`, `systemd/azazel-edge-ai-agent.service`

## Core Architecture

```mermaid
flowchart LR
    subgraph ingestion["Event Ingestion"]
        SUP[Suricata EVE] --> RC[Rust Core]
        RC --> EP[Evidence Plane]
    end
    subgraph evaluation["Deterministic Evaluation"]
        EP --> NOC[NOC Evaluator]
        EP --> SOC[SOC Evaluator]
        NOC --> ARB[Action Arbiter]
        SOC --> ARB
    end
    subgraph action["Operator Plane"]
        ARB --> EXP[Decision Explanation]
        EXP --> WEB[Web UI / API]
        EXP --> NOTIF[Notification]
    end
    subgraph ai["AI Assist\n(optional)"]
        EXP --> GOV[AI Governance]
        GOV --> LLM[Ollama]
        LLM --> GOV
    end
    WEB --> OPR([Operator])
    NOTIF --> MM[Mattermost]
    ARB --> AUD[Audit Logger]
```

1. **Event ingestion + normalization**
   - Rust core tails Suricata EVE (`AZAZEL_EVE_PATH`, default `/var/log/suricata/eve.json`) and emits normalized alert events.
   - Rust core forwards to Unix socket (`/run/azazel-edge/ai-bridge.sock`) and/or JSONL log.
2. **Deterministic evaluation**
   - NOC evaluator and SOC evaluator are implemented under `py/azazel_edge/evaluators/`.
   - Action arbiter decides explicit actions with rejected alternatives and decision trace.
3. **Operator plane**
   - Flask app serves dashboard (`/`), demo (`/demo`), ops workspace (`/ops-comm`), and `/api/*`.
   - Control daemon exposes Unix socket control plane at `/run/azazel-edge/control.sock`.
4. **Optional AI assist plane**
   - AI agent consumes normalized events/manual queries and writes advisory/metrics/audit JSONL.
   - Ollama and Mattermost are provisioned by optional compose-based runtime scripts.

## Entrypoints And Interfaces

### Service entrypoints
- Web app: `azazel_edge_web/app.py` (gunicorn via `systemd/azazel-edge-web.service`)
- Control daemon: `py/azazel_edge_control/daemon.py` (`systemd/azazel-edge-control-daemon.service`)
- AI agent: `py/azazel_edge_ai/agent.py` (`systemd/azazel-edge-ai-agent.service`)
- Rust core: `rust/azazel-edge-core/src/main.rs` (`systemd/azazel-edge-core.service`)
- EPD refresh timer: `systemd/azazel-edge-epd-refresh.timer`

### Web routes
- UI: `/`, `/demo`, `/ops-comm`
- Health: `/health` (no token)
- CA metadata/download: `/api/certs/azazel-webui-local-ca/meta`, `/api/certs/azazel-webui-local-ca.crt`

### Primary API groups

| Group | Endpoints | Auth required |
|-------|-----------|---------------|
| State | `GET /api/state`, `GET /api/state/stream` | Yes |
| Control | `POST /api/mode`, `POST /api/action`, `/api/wifi/*`, `/api/portal-viewer*` | Yes |
| SoT | `POST /api/clients/trust`, `PUT/PATCH /api/sot/devices` | Yes |
| Dashboard | `GET /api/dashboard/*` | Yes |
| Triage | `/api/triage/*` | Yes |
| Runbooks | `GET /api/runbooks`, `POST /api/runbooks/propose`, `POST /api/runbooks/act` | Yes |
| Demo | `/api/demo/*` | Yes |
| AI | `POST /api/ai/ask`, `GET /api/ai/capabilities` | Yes |
| Mattermost | `POST /api/mattermost/command`, `POST /api/mattermost/message` | Token |
| Health | `GET /health` | No |
| CA cert | `GET /api/certs/*` | No |

### Socket interfaces
- Control socket: `/run/azazel-edge/control.sock`
- AI bridge socket: `/run/azazel-edge/ai-bridge.sock`

### Authentication behavior
- Most `/api/*` endpoints are token-protected.
- Installer-managed runtime sets fail-closed by default (`AZAZEL_AUTH_FAIL_OPEN=0`).
- Legacy fail-open compatibility is controlled by `AZAZEL_AUTH_FAIL_OPEN` when token file is absent.
- Managed default token file is `/etc/azazel-edge/web_token.txt` via `AZAZEL_WEB_TOKEN_FILE`.

## Changelog

See [`docs/CHANGELOG.md`](docs/CHANGELOG.md) for the full implementation history and PR traceability.
See [`docs/IMPLEMENTATION_CYCLE_2026Q2_FEATURE_INVENTORY.md`](docs/IMPLEMENTATION_CYCLE_2026Q2_FEATURE_INVENTORY.md) for the current execution cycle feature inventory.

## Requirements

### Runtime packages (installed by scripts)
- Core/app stack: `python3`, `python3-venv`, `network-manager`, `iw`, `dnsmasq`, `nginx`, `openssl`, `rustc`, `cargo`, and related Python system packages
- Security stack option: `docker.io`, `suricata`
- AI runtime option: `docker.io`, `qemu-user-static`, `binfmt-support`, `jq`

### Python runtime dependencies
From `requirements/runtime.txt`:
- `Flask`
- `gunicorn`
- `rich`
- `textual`
- `Pillow`
- `requests`
- `PyYAML`

### Optional external services
- Ollama container (`security/docker-compose.ollama.yml`)
- Mattermost + PostgreSQL (`security/docker-compose.mattermost.yml`)
- OpenCanary (`security/docker-compose.yml`)

## Install and Reproduce

### Unified installer

```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_INTERNAL_NETWORK=1 \
     ENABLE_APP_STACK=1 \
     ENABLE_AI_RUNTIME=1 \
     ENABLE_DEV_REMOTE_ACCESS=0 \
     bash installer/internal/install_all.sh
```

For all installer toggles and runtime variables, see [Configuration](#configuration).

### App stack only

```bash
sudo ENABLE_SERVICES=1 bash installer/internal/install_migrated_tools.sh
```

### AI runtime only

```bash
sudo ENABLE_OLLAMA=1 ENABLE_MATTERMOST=1 bash installer/internal/install_ai_runtime.sh
```

Install result (default scripts):
- Runtime files under `/opt/azazel-edge`
- Launchers under `/usr/local/bin`
- Systemd units installed and optionally enabled

## Configuration

### Installer toggles
- `ENABLE_INTERNAL_NETWORK=1|0`
- `ENABLE_APP_STACK=1|0`
- `ENABLE_AI_RUNTIME=1|0`
- `ENABLE_DEV_REMOTE_ACCESS=1|0`
- `ENABLE_RUST_CORE=1|0`

### Main runtime config files
- `/etc/default/azazel-edge-web` (Web/Mattermost-related env)
- `/etc/default/azazel-edge-security` (security stack options such as `SURICATA_IFACE`)
- `/etc/azazel-edge/first_minute.yaml` (control flags such as `suppress_auto_wifi`)

### Important environment variables (selected)
- Web bind: `AZAZEL_WEB_HOST`, `AZAZEL_WEB_PORT`
- Rust core: `AZAZEL_EVE_PATH`, `AZAZEL_AI_SOCKET`, `AZAZEL_NORMALIZED_EVENT_LOG`, `AZAZEL_DEFENSE_ENFORCE`
- AI agent: `AZAZEL_OLLAMA_ENDPOINT`, `AZAZEL_LLM_MODEL_PRIMARY`, `AZAZEL_LLM_MODEL_DEGRADED`
- Mattermost command trigger/token: `AZAZEL_MATTERMOST_COMMAND_TRIGGER`, `AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE`
- Runbook controlled execution gate: `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC`
- Auth hardening / RBAC:
  - `AZAZEL_AUTH_FAIL_OPEN` (default `0` fail-closed)
  - `AZAZEL_AUTH_TOKENS_FILE` (role-mapped API tokens, default `/etc/azazel-edge/auth_tokens.json`)
  - `AZAZEL_AUTHZ_AUDIT_LOG` (authorization decision audit log)
  - `AZAZEL_AUTH_MTLS_REQUIRED` (`0|1`, optional hardened mode)
  - `AZAZEL_AUTH_MTLS_HEADER` (client fingerprint header key, default `X-Client-Cert-Fingerprint`)
  - `AZAZEL_AUTH_MTLS_FINGERPRINTS` (CSV allowlist)
  - `AZAZEL_AUTH_MTLS_FINGERPRINTS_FILE` (line-based allowlist file)
- Topo-Lite/NOC monitor scope:
  - `AZAZEL_NOC_MONITOR_SCOPE` (`internal` default, or `external`)
  - `AZAZEL_INTERNAL_BRIDGE_IF` (`br0` default)
  - `AZAZEL_MANAGED_CLIENT_CIDRS` (`172.16.0.0/24` default)
  - `AZAZEL_INTERNAL_MONITOR_TARGET` (`172.16.0.254` default)
  - `AZAZEL_NOC_EXTRA_INTERFACES` (optional CSV for multi-segment probes)
- Topo-Lite synthetic seed mode:
  - `AZAZEL_TOPOLITE_SEED_MODE_PATH` (mode state file, default `/run/azazel-edge/topolite_seed_mode.json`)
  - API: `POST /api/topolite/seed-mode` with `mode=live|synthetic` and optional `seed_id`
- Alert queue classification thresholds:
  - `AZAZEL_ALERT_QUEUE_NOW_THRESHOLD` (default `80`)
  - `AZAZEL_ALERT_QUEUE_WATCH_THRESHOLD` (default `50`)
  - `AZAZEL_ALERT_QUEUE_ESCALATE_THRESHOLD` (default `90`)
  - `AZAZEL_ALERT_SUPPRESSION_WINDOW_SEC` (default `120`)
  - `AZAZEL_ALERT_AGGREGATION_WINDOW_SEC` (default `300`)
  - `AZAZEL_ALERT_ESCALATION_COUNT_THRESHOLD` (default `5`)
- SOC policy:
  - `AZAZEL_SOC_POLICY_PATH` (default `config/soc_policy.yaml`)
  - profiles: `config/soc_policy_profiles/{conservative,balanced,demo}.yaml`
  - dry-run helper: `bin/azazel-soc-policy-dry-run`
- Aggregator freshness tuning (MVP scaffold):
  - `AZAZEL_AGGREGATOR_POLL_INTERVAL_SEC` (default `30`)
  - `AZAZEL_AGGREGATOR_STALE_MULTIPLIER` (default `2`)
  - `AZAZEL_AGGREGATOR_OFFLINE_MULTIPLIER` (default `6`)

### Token auth
- API token can be supplied by header `X-AZAZEL-TOKEN` (or `X-Auth-Token`) or `?token=`.
- Default runtime posture is fail-closed (`AZAZEL_AUTH_FAIL_OPEN=0`): missing token material must not open protected endpoints.

## Usage

### Service status
```bash
sudo systemctl status \
  azazel-edge-control-daemon \
  azazel-edge-web \
  azazel-edge-ai-agent \
  azazel-edge-core
```

### Access endpoints (default installer assumptions)
- Web backend (gunicorn): `http://127.0.0.1:8084/`
- If internal network + HTTPS proxy are installed: `https://172.16.0.254/`
- Mattermost (if enabled): `http://172.16.0.254:8065/`

### API call example
```bash
TOKEN="$(cat ~/.azazel-edge/web_token.txt)"
curl -sS -H "X-AZAZEL-TOKEN: ${TOKEN}" http://127.0.0.1:8084/api/state | jq .
```

### SoT devices API contract
- `PUT /api/sot/devices`
  - Replaces the full `devices` array in SoT.
  - Request body: `{"devices": [<SoT device objects>]}`.
- `PATCH /api/sot/devices`
  - Merge/upsert semantics by `id` only (no delete behavior).
  - Existing device fields are preserved unless overwritten by payload fields.
  - Request body: `{"devices": [<partial or full SoT device objects with id>]}`.
- Both endpoints:
  - Require token auth (`@require_token()`).
  - Validate resulting full SoT via `SoTConfig.from_dict`.
  - Append audit records to `AZAZEL_SOT_AUDIT_LOG` including `actor` (`X-AZAZEL-ACTOR` preferred, then caller address).
  - Trigger re-evaluation through `refresh` after successful updates.

### Deterministic demo replay

```bash
bin/azazel-edge-demo list
bin/azazel-edge-demo run mixed_correlation_demo
```

### Runbook broker CLI
```bash
python3 py/azazel_edge_runbook_broker.py list
python3 py/azazel_edge_runbook_broker.py show rb.noc.service.status.check
python3 py/azazel_edge_runbook_broker.py propose --question "Wi-Fi intermittent disconnects"
```

## Development

### Local setup
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip wheel setuptools
pip install -r requirements/dev.txt
```

### Local run (without systemd)
```bash
PYTHONPATH=py:. .venv/bin/python azazel_edge_web/app.py
PYTHONPATH=py:. .venv/bin/python py/azazel_edge_control/daemon.py
PYTHONPATH=py:. .venv/bin/python py/azazel_edge_ai/agent.py
```

Notes:
- Several tests import `azazel_edge_web` as top-level package, so `PYTHONPATH=.` is required in repository layout.
- `py/azazel_edge_status.py` is a continuous renderer (Ctrl-C to stop), not a typical `--help` CLI.

## Testing

Run:
```bash
PYTHONPATH=py:. .venv/bin/pytest -q
```

Status guidance:
- Use the CI badge and latest GitHub release notes as the source of current validation status.
- Avoid treating static README test counts as authoritative across commits.

## Repository Layout

| Path | Role |
|---|---|
| `py/azazel_edge/` | Evidence Plane, evaluators, arbiter, audit, SoT, triage, demo, and research/runtime extensions |
| `py/azazel_edge_control/` | Control daemon and action handlers |
| `py/azazel_edge_ai/` | AI agent integration and M.I.O. assist path |
| `azazel_edge_web/` | Flask backend, dashboard, ops-comm UI |
| `rust/azazel-edge-core/` | Rust defense core |
| `runbooks/` | Runbook registry |
| `systemd/` | Services and timers |
| `security/` | Compose stacks and security-side assets |
| `installer/` | Unified installer and staged install scripts |
| `docs/` | Public architecture, AI operation, persona, and demo documentation |
| `tests/` | Unit and regression coverage |

## Deployment

### Systemd units included
- `azazel-edge-control-daemon.service`
- `azazel-edge-web.service`
- `azazel-edge-ai-agent.service`
- `azazel-edge-core.service`
- `azazel-edge-epd-refresh.service`
- `azazel-edge-epd-refresh.timer`
- `azazel-edge-opencanary.service`
- `azazel-edge-suricata.service`

### Security/AI stack deployment
- Security stack install: `installer/internal/install_security_stack.sh`
- AI runtime install: `installer/internal/install_ai_runtime.sh`
- Compose assets under `security/`

### Runtime logs/artifacts (selected)
- `/var/log/azazel-edge/normalized-events.jsonl`
- `/var/log/azazel-edge/ai-events.jsonl`
- `/var/log/azazel-edge/ai-llm.jsonl`
- `/var/log/azazel-edge/triage-audit.jsonl`
- `/run/azazel-edge/ui_snapshot.json`

## Documentation

### For operators

| Document | Description |
|----------|-------------|
| [AI Operation Guide](docs/AI_OPERATION_GUIDE.md) | LLM thresholds, daily checks, incident response |
| [AI Operation Guide (JA)](docs/AI_OPERATION_GUIDE_JA.md) | 日本語版 AI 運用要領 |
| [Demo Guide](docs/DEMO_GUIDE.md) | Deterministic demo replay walkthrough |
| [Operator Guide](docs/OPERATOR_GUIDE.md) | Field operator quick start and first-response workflow |
| [Operator Guide (JA)](docs/OPERATOR_GUIDE_JA.md) | 日本語版オペレータガイド |

### For developers

| Document | Description |
|----------|-------------|
| [P0 Runtime Architecture](docs/P0_RUNTIME_ARCHITECTURE.md) | Pipeline, modules, and constraints |
| [AI Agent Build and Operation Detail](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md) | AI agent internals |
| [AI Agent Build and Operation Detail (JA)](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL_JA.md) | 日本語版 AI エージェント構築・運用詳細 |
| [M.I.O. Persona Profile](docs/MIO_PERSONA_PROFILE.md) | Operator persona design spec |
| [M.I.O. Persona Profile (JA)](docs/MIO_PERSONA_PROFILE_JA.md) | 日本語版 M.I.O. ペルソナ仕様 |
| [Post-demo Main Integration Boundary (#104)](docs/POST_DEMO_MAIN_INTEGRATION_104.md) | What is mainline vs. exhibition-only |
| [Post-demo Socket Permission Model (#105)](docs/POST_DEMO_SOCKET_PERMISSION_MODEL_105.md) | Unix socket permission decisions |
| [Next Development Execution Index 2026Q2](docs/NEXT_DEVELOPMENT_EXECUTION_INDEX_2026Q2.md) | Roadmap and execution plan |
| [Arsenal Demo Profile](docs/ARSENAL_DEMO_PROFILE.md) | Reproducible deterministic demo profile |
| [Deployment Profiles](docs/DEPLOYMENT_PROFILES.md) | Core/Demo/SOC/NOC/Heavy-lab profile matrix |
| [Benchmark Scope and HIL Plan](docs/BENCHMARK_SCOPE_AND_HIL_PLAN.md) | Scope boundary and hardware-in-the-loop plan |

### For contributors (AI agents and humans)

| Document | Description |
|----------|-------------|
| [AGENTS.md](AGENTS.md) | AI agent working charter — read before making any change |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Human contributor guide (branch, PR, test rules) |
| [Changelog](docs/CHANGELOG.md) | PR and feature traceability history |
| [Implementation Cycle Feature Inventory](docs/IMPLEMENTATION_CYCLE_2026Q2_FEATURE_INVENTORY.md) | Verified feature inventory for Epic #196 implementation cycle |
| [Release Verification Guide](docs/RELEASE_VERIFICATION_GUIDE.md) | Checksum/SBOM/dependency scan verification workflow |
| [Document Language Policy](docs/DOCUMENT_LANGUAGE_POLICY.md) | English-first documentation policy and EN/JA split map |

## Limitations and Known Issues

### Design constraints (by intent)

- Rust enforcement is fail-safe by default:
  - `AZAZEL_DEFENSE_ENFORCE=false` and `AZAZEL_DEFENSE_ENFORCE_LEVEL=advisory` keep runtime advisory-only
  - staged mode support: `advisory`, `semi-auto`, `full-auto`
  - optional high-impact auto gate: `AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO=false`
- AI assist is optional and bounded — the deterministic path works without Ollama
- Ollama models above 2b parameters are not recommended for co-located deployments
- Test count and runbook count are verified at each release; see CI results for current status.
- Redirect behavior uses prepared lightweight decoys with protocol-aware mapping (v0.1.1 hardening line), not per-event decoy spawning.
- Benchmark outputs are scoped to software-only deterministic replay unless hardware-in-the-loop evidence is explicitly provided.

### Known bugs

- None currently tracked in this document. Use GitHub Issues for current defects.

### Open work items

See [GitHub Issues](https://github.com/01rabbit/Azazel-Edge/issues) for the current list.
Priority items are tracked in GitHub Issues and may change daily.

## Current Status

- Latest release: `v0.1.1`.
- `v0.1.1` hardening line completed (redirect safety, demo reproducibility profile, deployment profile clarity, benchmark claim boundary).
- Deterministic demo scenarios available: `mixed_correlation_demo`, `noc_degraded_demo`, `soc_redirect_demo`.
- Optional integrations remain optional; deterministic core operation does not require Ollama/Mattermost/Wazuh/Vector/Aggregator.

## License

This repository is licensed under the MIT License. See [LICENSE](LICENSE).
