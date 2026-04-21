# Azazel-Edge

<p align="center">
  <a href="./README.md">
    <img alt="English" src="https://img.shields.io/badge/Language-English-1f6feb?style=for-the-badge">
  </a>
  <a href="./README_ja.md">
    <img alt="日本語" src="https://img.shields.io/badge/Language-日本語-2ea44f?style=for-the-badge">
  </a>
</p>

Azazel-Edge is a Raspberry Pi-oriented edge operations stack that combines:
- internal network/gateway setup
- deterministic NOC/SOC evaluation and action selection
- Web UI + API + runbook workflow for operators
- optional local AI assist (Ollama + Mattermost integration)

This README is based on verified repository contents (code, scripts, tests, git history, GitHub issue/PR metadata) as of **2026-03-15**.

<p align="center">
  <img src="https://img.shields.io/badge/-Raspberry%20Pi-C51A4A.svg?logo=raspberry-pi&style=flat">
  <img src="https://img.shields.io/badge/-Python-F9DC3E.svg?logo=python&style=flat">
  <img src="https://img.shields.io/badge/-Rust-000000.svg?logo=rust&style=flat">
  <img src="https://img.shields.io/badge/-Flask-000000.svg?logo=flask&style=flat">
  <img src="https://img.shields.io/badge/-Mattermost-0058CC.svg?logo=mattermost&style=flat">
  <img src="https://img.shields.io/badge/-Ollama-111111.svg?style=flat">
</p>

## Language Parity

`README.md` and `README_ja.md` are maintained to carry the same technical meaning.

- Commands, API paths, environment variables, service names, and file paths are kept identical across both files.
- Differences between files should be wording/locale only, not behavior claims.
- Dates and verification snapshots are intended to match across both files.

Terminology alignment used in both files:

Canonical term | Japanese equivalent in `README_ja.md`
---|---
deterministic demo replay | 決定論デモ
operator workflow | 運用ワークフロー
controlled execution | 制御実行
token-protected endpoint | トークン保護エンドポイント
optional AI assist path | 任意の AI 補助経路

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

1. **Event ingestion + normalization**
   - Rust core tails Suricata EVE (`AZAZEL_EVE_PATH`, default `/var/log/suricata/eve.json`) and emits normalized alert events.
   - Rust core forwards to Unix socket (`/run/azazel-edge/ai-bridge.sock`) and/or JSONL log.
2. **Deterministic evaluation**
   - NOC evaluator and SOC evaluator are implemented under `py/azazel_edge/evaluators/`.
   - Action arbiter decides explicit actions with rejected alternatives and decision trace.
3. **Operator plane**
   - Flask app serves the Arsenal booth landing page (`/`), dashboard (`/dashboard`), demo (`/demo`), ops workspace (`/ops-comm`), and `/api/*`.
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
- state/stream: `/api/state`, `/api/state/stream`
- control/mode/action: `/api/mode`, `/api/action`, `/api/wifi/*`, `/api/portal-viewer*`
- dashboard views: `/api/dashboard/*`
- triage: `/api/triage/*`
- runbooks: `/api/runbooks*`
- demo: `/api/demo/*`
- AI/Mattermost: `/api/ai/*`, `/api/mattermost/*`

### Socket interfaces
- Control socket: `/run/azazel-edge/control.sock`
- AI bridge socket: `/run/azazel-edge/ai-bridge.sock`

### Authentication behavior
- Most `/api/*` endpoints are token-protected.
- If token file is absent, token checks are bypassed (`verify_token()` in `azazel_edge_web/app.py`).
- Token file candidates include `~/.azazel-edge/web_token.txt` (see `web_token_candidates()` usage).

## Feature Traceability

Implemented capability | Code evidence | History evidence
---|---|---
Dedicated demo workspace separated from live dashboard | `azazel_edge_web/app.py` (`/demo`), `azazel_edge_web/templates/demo.html` | PR #74, commit `d084852`
NOC runtime projection integration | `py/azazel_edge_control/daemon.py`, `tests/test_noc_runtime_integration_v1.py` | PR #88, commit `8d3937a`
SOC state dimensions integrated in runtime/UI | `py/azazel_edge/evaluators/soc.py`, `tests/test_soc_evaluator_v1.py` | PR #86, commits `a4a6fa0`, `bebdd13`
Auth contract and i18n hardening | `azazel_edge_web/app.py`, `tests/test_api_auth_contract.py`, `tests/test_i18n_*` | PR #87, commit `72e9253`
Beginner-default UI mode | `azazel_edge_web/templates/index.html`, `azazel_edge_web/static/app.js` | PR #95, commit `7773624`

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

Main toggles:
- `ENABLE_INTERNAL_NETWORK=1|0`
- `ENABLE_APP_STACK=1|0`
- `ENABLE_AI_RUNTIME=1|0`
- `ENABLE_DEV_REMOTE_ACCESS=1|0`
- `ENABLE_RUST_CORE=1|0`

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

### Token auth
- API token can be supplied by header `X-AZAZEL-TOKEN` (or `X-Auth-Token`) or `?token=`.
- If no token file exists, protected endpoints become effectively open.

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
- If internal network + HTTPS proxy are installed:
  - Arsenal booth page: `https://172.16.0.254/`
  - Operational dashboard: `https://172.16.0.254/dashboard`
- Mattermost (if enabled): `http://172.16.0.254:8065/`

### API call example
```bash
TOKEN="$(cat ~/.azazel-edge/web_token.txt)"
curl -sS -H "X-AZAZEL-TOKEN: ${TOKEN}" http://127.0.0.1:8084/api/state | jq .
```

### Deterministic demo replay

```bash
bin/azazel-edge-demo list
bin/azazel-edge-demo run mixed_correlation_demo
```

### Arsenal-Demo port configuration

To run Arsenal-Demo on a separate port (e.g., 8885), see [ARSENAL_DEMO_PORT_SETUP.md](docs/ARSENAL_DEMO_PORT_SETUP.md) for configuration options.

**Development (temporary):**
```bash
AZAZEL_ARSENAL_DEMO_PORT=8885 AZAZEL_ARSENAL_DEMO_MODE=1 python3 azazel_edge_web/app.py
```

**Production (persistent):**
```bash
sudo cp systemd/azazel-edge-web.defaults.template /etc/default/azazel-edge-web
# Edit /etc/default/azazel-edge-web to set:
# AZAZEL_ARSENAL_DEMO_PORT=8885
sudo systemctl restart azazel-edge-web
```

When you launch `python3 azazel_edge_web/app.py` directly, `AZAZEL_ARSENAL_DEMO_MODE=1` switches the whole Web UI process to `8885`. If you want both `8084` and `8885` to listen at the same time, use the systemd configuration above.

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
pip install -r requirements/runtime.txt
```

### Local run (without systemd)
```bash
PYTHONPATH=. python3 azazel_edge_web/app.py
PYTHONPATH=. python3 py/azazel_edge_control/daemon.py
PYTHONPATH=. python3 py/azazel_edge_ai/agent.py
```

Notes:
- Several tests import `azazel_edge_web` as top-level package, so `PYTHONPATH=.` is required in repository layout.
- `py/azazel_edge_status.py` is a continuous renderer (Ctrl-C to stop), not a typical `--help` CLI.

## Testing

Run:
```bash
PYTHONPATH=. .venv/bin/pytest -q
```

Latest verified result (2026-03-15): **183 passed in 3.57s**

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

- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [AI build and operation detail](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md)
- [M.I.O. persona profile](docs/MIO_PERSONA_PROFILE.md)
- [Demo guide](docs/DEMO_GUIDE.md)
- [Demo guide (Japanese)](docs/DEMO_GUIDE_JA.md)

## Limitations

- Rust enforcement path is a placeholder by default:
  - `AZAZEL_DEFENSE_ENFORCE=false` in `systemd/azazel-edge-core.service`
  - `maybe_enforce()` in Rust core contains placeholder comment.
- `python3 py/azazel_edge_epd.py --help` currently fails with `ValueError: incomplete format`.
- CI workflow files are not present (`.github/workflows` not found in repository tree).
- `LICENSE` file is not present at repository root.

## Known Issues (as of 2026-03-15)

Open GitHub issues include:
- #96 P1着手: Azazelらしさラインの実装分解
- #97 P1-1: M.I.O.文体統一レイヤ
- #98 P1-2: Decision Trust Capsule
- #99 P1-3: Handoff Brief Pack
- #100 P1-4: 初動Progress Checklist
- #101 P1-5: Beginnerオンボーディング

## Current Status

- Recent merged PRs include #95, #94, #88, #87, #86 (UI, NOC runtime integration, auth/i18n, SOC maturation).
- Repository currently contains **44** Python test modules and **15** runbook YAML definitions.
- Deterministic demo scenarios available: `mixed_correlation_demo`, `noc_degraded_demo`, `soc_redirect_demo`.

## Verification Notes

Verified on 2026-03-15:
- `PYTHONPATH=. .venv/bin/pytest -q` -> `183 passed`
- `find tests -maxdepth 1 -type f -name 'test_*.py' | wc -l` -> `44`
- `find runbooks -type f -name '*.yaml' | wc -l` -> `15`
- `python3 py/azazel_edge_epd.py --help` -> fails (`ValueError: incomplete format`)
- GitHub open issues include #96-#101 (`gh issue list --state open`)

## License

No top-level `LICENSE` file is present in this repository (status: unknown).
