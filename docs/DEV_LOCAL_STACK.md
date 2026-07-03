# Local Dev Stack Launcher

## Purpose
`bin/azazel-edge-devstack` is a one-shot launcher that brings up the full Azazel-Edge runtime on a macOS development machine (Apple Silicon). Until now, `bin/azazel-edge-dev` only covered build/test workflows (`bootstrap`, `test`, `rust-test`, `python`) — there was no single command to actually run the live services (control-daemon, AI agent, Rust core, web dashboard) wired to a local LLM and a local Mattermost instance. `azazel-edge-devstack` fills that gap: one command starts the whole pipeline in dependency order, in safe mode, against dev-local infrastructure.

It wires the stack to:
- **ollama** — the local LLM runtime, run as the macOS GUI app, serving `qwen3.5:2b` at `http://127.0.0.1:11434`.
- **Mattermost** — run via `docker compose` on OrbStack, reachable at `http://localhost:8065`.

The launcher itself does not replace `bin/azazel-edge-dev`. Use `azazel-edge-dev` to build/test; use `azazel-edge-devstack` to run.

## Prerequisites
- macOS on Apple Silicon.
- [OrbStack](https://orbstack.dev/) (or another Docker Desktop-compatible engine) installed and running, for Mattermost.
- Rust toolchain (`cargo`) installed, for building `rust/azazel-edge-core`.
- Python 3 installed.
- [Ollama](https://ollama.com/) GUI app installed and running, with the `qwen3.5:2b` model pulled:
  ```bash
  ollama pull qwen3.5:2b
  ```

## Quickstart
```bash
bin/azazel-edge-devstack up
```

This preflight-checks dependencies (creating the Python venv and building the Rust core if needed), then starts control-daemon, ai-agent, the Rust core, and the web dashboard, in that order. On success it prints a summary including:
- the dashboard URL and its auth token
- the Mattermost URL
- ollama status (reachable / model present)

Open the dashboard URL from the summary in a browser to see the running system. Open `http://localhost:8065` for Mattermost.

To also see live pipeline data flowing through the dashboard, start the `dummy-eve` test-event injector at the same time:
```bash
bin/azazel-edge-devstack up --inject
```

## Command Reference

| Command | Flags | Description |
|---|---|---|
| `up` (default) | `--inject` | Also start the `dummy-eve` test-event injector so the pipeline shows live data. |
| | `--all` | Also (re)start external dependencies (Mattermost via OrbStack). |
| `down` | `--all` | Stop the azazel processes. By default, Mattermost and ollama are left running; `--all` additionally stops the Mattermost containers. `down` never touches ollama. |
| `status` | — | Show each component's state (running/stopped + PID) and ollama/Mattermost reachability. |
| `restart` | `--inject` | Equivalent to `down` followed by `up`. |
| `logs [component]` | — | Tail a specific component's log, or list available logs if no component is given. |

`up` is idempotent: components that are already running are skipped rather than restarted.

## Components and Startup Order
`up` starts components in this order:

1. **control-daemon** — coordinates runtime state and the local control socket.
2. **ai-agent** — bridges to ollama for LLM-assisted triage/advisory output.
3. **Rust core** (`rust/azazel-edge-core`) — event normalization and the deterministic decision loop.
4. **web dashboard** — the operator-facing UI and API.

With `--inject`, the `dummy-eve` test-event injector also starts, feeding synthetic events into the pipeline so the dashboard shows live activity.

With `--all`, external dependencies (currently: Mattermost on OrbStack, via `security/docker-compose.mattermost.yml`) are also (re)started before the azazel components.

The runtime runs in **safe mode**: defense enforcement is dry-run/advisory only, matching `AZAZEL_DEFENSE_DRY_RUN=true` / `AZAZEL_DEFENSE_ENFORCE_LEVEL=advisory` in `tools/macdev/env.sh`.

## Injector — test/demo control panel
`bin/azazel-edge-injector` is a **self-contained** front-end for the `dummy-eve` test-event generator. It sources the dev environment itself, so it runs standalone — no need to have `devstack` up first — and writes fabricated Suricata EVE alerts to the dev `eve.json` that the Rust core tails.

Two modes:

```bash
bin/azazel-edge-injector                              # interactive menu (demo screen)
bin/azazel-edge-injector emit --scenario port_scan --count 5   # pass-through CLI
bin/azazel-edge-injector list                         # pass-through CLI
```

The interactive menu shows live status (eve.json event count, background-stream state, whether the pipeline/dashboard is up) and lets you: list scenarios, fire a single scenario, run a staged attack flow, start/stop a continuous background stream, view recent events, and reset `eve.json`.

**Demo flow:** run `bin/azazel-edge-devstack up` first, then drive attacks from the injector menu and watch the real dashboard react — this is the intended way to demo (live pipeline injection rather than a mocked screen). Available scenarios: `recon_probe`, `port_scan`, `arp_spoof`, `dns_exfil`, `cred_harvest`, `c2_beacon`, `phishing`, `benign`. (`up --inject` starts the continuous stream automatically; the injector menu is for hands-on, scenario-by-scenario control.)

## Environment
The launcher sources `tools/macdev/env.sh`, which sets macOS-appropriate runtime paths under `~/.azazel-edge-dev` (instead of the appliance's Linux paths), `PYTHONPATH`, and the ollama endpoint. On top of that, `azazel-edge-devstack` points the stack's Mattermost integration at `127.0.0.1:8065` for local dev (the appliance default is `172.16.0.254`).

State is kept under `~/.azazel-edge-dev/`:
- PID files: `~/.azazel-edge-dev/run/devstack/`
- Logs: `~/.azazel-edge-dev/log/devstack/`

## Troubleshooting

**ollama not reachable**
Open the Ollama app: `open -a Ollama`. Then re-run `bin/azazel-edge-devstack status` to confirm.

**Model `qwen3.5:2b` missing**
```bash
ollama pull qwen3.5:2b
```
Preflight only warns about a missing model — it does not block startup — but the AI agent will not produce useful output until the model is present.

**Mattermost not reachable**
Confirm OrbStack is running and the containers are up:
```bash
docker compose -f security/docker-compose.mattermost.yml ps
```
Use `bin/azazel-edge-devstack up --all` to (re)start Mattermost along with the rest of the stack.

**Port already in use**
Another process may be bound to a port the stack needs (dashboard, control socket, or Mattermost's `8065`). Check `bin/azazel-edge-devstack status` for what the launcher thinks is running, and use `lsof -i :<port>` to find the conflicting process.

**Rust build is slow on first run**
The first `up` builds `rust/azazel-edge-core` in release mode (`cargo build --release`) if no build is present, which can take several minutes. Subsequent runs reuse the existing build and start immediately.

**Where are the logs?**
```bash
bin/azazel-edge-devstack logs            # list available logs
bin/azazel-edge-devstack logs ai-agent   # tail a specific component
```
Raw log files live under `~/.azazel-edge-dev/log/devstack/`.

## Related Documents
- macOS dev environment variables: `tools/macdev/env.sh`
- Build/test helper: `bin/azazel-edge-dev`
- Mattermost compose definition: `security/docker-compose.mattermost.yml`
