# Privilege inventory (#471 stage 0)

Tracking: #471 (privilege separation), context #462 (item 2) and #472  
Status: inventory and plan (stages 0–2); **stages 1 and 2 implemented**, see §10.9 and §11.7.  
Last updated: 2026-10-26

#471 splits the Edge services into separate non-root accounts. The owner
approved three stages:

| Stage | Scope | Status |
| --- | --- | --- |
| 0 | This inventory. No code, unit or installer change. | this page |
| 1 | Run the Web UI (`azazel-edge-web`) as `azazel-web`, and add the agent query socket for `manual_query`. | implemented (§10.9); device check by the owner pending |
| 2 | Run the AI agent (`azazel-edge-ai-agent`) as `azazel-agent`. | implemented (§11.7); device check by the owner pending |
| 3 | Run the core with only the capabilities it needs. | later; needs hardware |

The core stays root in stages 0 to 2.

## 0. How this was gathered, and what it is not

- **Static analysis** of `azazel_edge_web/`, `py/azazel_edge_ai/`,
  `py/azazel_edge_control/`, `rust/azazel-edge-core/`, `bin/`, `installer/`
  and `systemd/`, at the commit this page was added in. For the Web UI and the
  agent, every module they import from `py/azazel_edge*` was followed,
  including lazy imports. Line numbers drift; search for the function name.
- **A container observation** (§9): the Web UI and the agent were started as
  non-root accounts inside a throwaway Linux container (Debian, aarch64,
  colima), with a Python audit hook and `strace`. That shows what fails
  without root **in a container**. It is not a device: there is no Wi-Fi, no
  EPD, no Suricata, no control daemon and no core in it. Nothing here is
  hardware evidence, and nothing in §9 is to be generalized to hardware.
- Where static analysis could not settle a point, the text says so
  ("uncertain").

Privilege marks used below:

| Mark | Meaning |
| --- | --- |
| **root** | needs uid 0 (or an equivalent such as the docker group or a polkit grant) |
| **cap:X** | needs Linux capability X |
| **group:Y** | needs membership of group Y (today these files are root-owned, so only root has it) |
| **owner** | needs write on a file or directory that root owns today; solved by ownership, not by privilege |
| **none** | works as any account |

## 1. Summary

| Unit | Account today | What really needs root | Everything else |
| --- | --- | --- | --- |
| `azazel-edge-web` | root (no `User=`) | `ip link set <uplink> down` (fallback), `docker ps`, writing `/etc/azazel-edge/sot.yaml`, the `systemctl restart` runbook, reading two 0600 tokens | owner / group for logs, runtime files, `control.sock`, the agent socket |
| `azazel-edge-ai-agent` | root (no `User=`) | nothing intrinsic | owner only: `mkdir` under `/run`, `chmod` of the shared `/run/azazel-edge`, `/var/log/azazel-edge`, `/opt/azazel-edge/logs` |
| `azazel-edge-control-daemon` | root | Wi-Fi (nmcli, `iw scan`, nft NAT, `sysctl`), `systemctl` start of fixed units, reboot/poweroff, writes under `/etc/azazel-edge`, path-schema migration | stays root in #471 |
| `azazel-edge-core` | root | `nft` / `tc` (cap:NET_ADMIN at least; unverified) | stage 3, needs hardware |

The Web UI and the agent have **no device access** (no `/dev/*`, SPI, GPIO
or audio) and **no listening port below 1024**. Their root needs are a short,
enumerable list; §10 and §11 say where each one goes.

## 2. Web UI (`azazel-edge-web`)

### 2.1 Unit

- `systemd/azazel-edge-web.service`: no `User=`/`Group=`, so root.
  `ExecStart` is `bash -lc 'exec gunicorn …'`, 2 workers × 4 threads, bound
  to `${AZAZEL_WEB_HOST}:${AZAZEL_WEB_PORT}` = `127.0.0.1:8084` (**none**).
- `EnvironmentFile=-/etc/default/azazel-edge-web`. systemd reads it as root
  before the service starts, so secrets passed as variables
  (`AZAZEL_MATTERMOST_BOT_TOKEN`, `AZAZEL_MATTERMOST_COMMAND_TOKEN`,
  `AZAZEL_AGGREGATOR_INGEST_HMAC_KEY`, Knowledge tokens) keep working under a
  non-root `User=`.
- `app.run` binds `0.0.0.0` only on the development path, not under gunicorn.

### 2.2 Child processes

There is no `os.system`, `sudo` or shell string anywhere the Web UI imports.
Every child is an argv list.

| Where | Command | Reached from | Mark |
| --- | --- | --- | --- |
| `app.py` `execute_disconnect_action` | `ip link set ${AZAZEL_UP_IF:-wlan0} down` | `action=disconnect` on `POST /api/action` and `/api/action/<action>`, **only when nothing answers on port 8082** | **cap:NET_ADMIN**. The interface comes from the environment, not the request. |
| `app.py` `_status_api_json` | `curl -s [-X POST] http://<host>:8082/…` for `/`, `/action/contain`, `release`, `disconnect`, `stage_open`, `details`; hosts are a fixed list (code default includes `127.0.0.1`) | `/api/action` | none |
| `app.py` `_container_running` | `docker ps --format {{.Names}}` | `get_monitoring_state()` → `GET /api/state`, `/api/state/stream`, `/api/dashboard/bundle`; runs for **both** OpenCanary (`azazel-edge-opencanary`) and Suricata (`azazel-edge-suricata`) when their `systemctl is-active` checks fail | **root** (docker group = root-equivalent). Without it the function returns `False` silently. |
| `app.py` `_process_running` | `pgrep -f [o]pencanary.tac` | monitoring state | none; would break under `ProtectProc=invisible` |
| `app.py` `_service_active` | `/bin/systemctl is-active <unit>` for OpenCanary (3 names), Suricata (2), ntfy, `azazel-edge-ai-agent`, `azazel-edge-web`, `azazel-portal-viewer` | monitoring state, portal viewer status | none (D-Bus read) |
| `runbooks.py` `execute_runbook` (called from `/api/runbooks/execute`, `/api/runbooks/act`) | `[exec, *argv]` from runbook YAML in `${AZAZEL_RUNBOOK_DIR:-/etc/azazel-edge/runbooks}` and `<repo>/runbooks`; `exec` must sit under `/bin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin` or `/opt/azazel-edge` | see the next rows | depends on the runbook |
| runbook `rb.noc.service.restart.controlled` | `/bin/systemctl restart` of `azazel-edge-ai-agent`, `azazel-edge-control-daemon` or `azazel-edge-web` | only with `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=1` (installer seeds `0`) and `approved=true` | **root** (or a polkit rule) |
| runbook `rb.noc.service.status.check` | `systemctl status <svc> --no-pager` | read-only | none (journal lines need group:systemd-journal, otherwise output is shorter) |
| runbook `rb.noc.default-route.check` | `/usr/sbin/ip -4 route show default` | read-only | none |
| runbooks `rb.noc.ui-snapshot.check`, `rb.ops.epd.state.check` | `cat /run/azazel-edge/{ui_snapshot,epd_last_render}.json` | read-only | group: the runtime group (directory is 0770) |
| runbook `rb.ops.logs.ai.recent` | `tail -n N /var/log/azazel-edge/ai-llm.jsonl` | read-only | none while the file is 0644 |
| `azazel_edge_epd_mode_refresh.py` `_read_live_ssid` | `iwgetid [iface] -r` | `GET /api/epd`, `/api/epd/preview.png`, only when no last render and no SSID are known | none (uncertain on nl80211-only drivers; failure is harmless) |

Who serves port 8082 is **not in this repository** (uncertain). If nothing
answers there on a device, the `ip link set … down` fallback is the normal
disconnect path, not a rare one.

### 2.3 Unix sockets (the Web UI is a client only)

| Socket | Default / override | Sent | Mark |
| --- | --- | --- | --- |
| `control.sock` | `/run/azazel-edge/control.sock`; hard-coded in `app.py` (no override); `control_plane.py` honours `AZAZEL_CONTROL_SOCKET` for snapshot reads | `refresh`, `reprobe`, `details`, `wifi_scan`, `wifi_connect` (carries the Wi-Fi passphrase), `portal_viewer_open`, `shutdown`, `reboot`, `mode_*`, `sot_trust_client`, `get_snapshot`, `watch_snapshot` | **group**: directory 0770 and socket 0660, root:`AZAZEL_RUNTIME_SOCKET_GROUP` (empty by default = root only) |
| `ai-bridge.sock` | `${AZAZEL_AI_SOCKET:-/run/azazel-edge-ai/ai-bridge.sock}` | only `{"action":"manual_query","params":{question,sender,source,context},"ts":…}` + newline, reads one reply line; from `POST /api/ai/ask`, `/api/mattermost/message`, `/api/mattermost/command` | since #472 the directory is 0700 and the socket 0600, owned by the agent's account. **A web account different from the agent's account cannot connect** (§10.4 adds a dedicated query socket for it). |

`AZAZEL_AI_SOCKET` is read by the Web UI (where it **connects**), by the
agent (where it **binds**) and by the core (where it connects). Today the
three defaults agree. Once stage 1 points the Web UI at the agent query socket
(§10.4), the same variable name means different sockets in different units;
setting it in a shared environment file (for example
`/etc/default/azazel-edge-security`, which both the agent and the core load)
must not leak into the Web UI's file, and vice versa. The installer's #472
rewrite already touches both files; the stage 1 rewrite must treat them
separately.

### 2.4 Network (outbound only)

All **none**. A hardened unit must keep `AF_INET`, `AF_INET6` and `AF_UNIX`.

- Port 8082 status API (curl, above).
- ntfy: `NTFY_BASE_URL`, `first_minute.yaml`, or `http://127.0.0.1:${NTFY_PORT:-8081}` (SSE and health).
- Mattermost: `AZAZEL_MATTERMOST_BASE_URL` (code default is a private LAN address on port 8065): ping, post, fetch.
- Portal viewer TCP probe on `PORTAL_NOVNC_PORT` (6080).
- Aggregator poller to registered nodes (`POST /api/aggregator/poller/start`), TLS verification disabled in `aggregator.py`.
- TAXII push to an operator-supplied URL (verification can be turned off).
- Knowledge advisory via `deception_effectiveness_client`.

### 2.5 Files read

| Path (default) | Override | Mode today | Mark as non-root |
| --- | --- | --- | --- |
| `/etc/azazel-edge/web_token.txt` | `AZAZEL_WEB_TOKEN_FILE` (installer pins it; code default is `~/.azazel-edge/web_token.txt`, so it would move with `HOME`) | 0640 root:root; `provision_web_token.sh` sets `/etc/azazel-edge` to 0750, other installer scripts create it 0755 (final mode depends on run order; uncertain) | **group** read + directory search |
| `/etc/azazel-edge/auth_tokens.json` | `AZAZEL_AUTH_TOKENS_FILE` | not created by the installer | **group** read |
| `/etc/azazel-edge/client-cert-fingerprints.txt` | `AZAZEL_AUTH_MTLS_FINGERPRINTS_FILE` | not created by the installer | read |
| `/etc/azazel-edge/mattermost-command-token` (+ siblings) | `AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE` | **0600 root** (`provision_mattermost_command.sh`) | **unreadable** → slash-command auth has no tokens, silently |
| ntfy token: `NTFY_TOKEN_FILE`, `first_minute.yaml`, or `/etc/azazel/ntfy.token` (installer also writes `/etc/azazel-edge/ntfy.token`) | `NTFY_TOKEN_FILE` | **0600 root** (`install_ntfy.sh`) | **unreadable**; code checks `os.access` and logs only at debug level |
| `/etc/azazel-edge/first_minute.yaml`, `portal-viewer.env`, `mode.json` (in `/etc/azazel` and `/etc/azazel-edge`), `sot.yaml`/`sot.json`, runbooks, triage flows | `AZAZEL_CONFIG_PATH`, `AZAZEL_SOT_PATH`, `AZAZEL_RUNBOOK_DIR`, `AZAZEL_TRIAGE_FLOW_DIR` | 0644 assumed | none (directory search) |
| CA certificate (`.crt` only, never a key) | `AZAZEL_WEBUI_CA_PATH` and fixed candidates under `/etc/azazel-edge/certs`, `/etc/azazel-edge/tls/ca`, `/var/lib/azazel-edge/public` | public | none |
| `/run/azazel-edge/`: `ui_snapshot.json`, `ai_advisory.json`, `ai_metrics.json`, `ui_status_view.json`, `epd_state.json`, `epd_last_render.json`, `booth-input.json` | `AZAZEL_AI_ADVISORY`, `AZAZEL_AI_METRICS`, `AZAZEL_EPD_*`, `AZAZEL_BOOTH_INPUT_PROVENANCE_PATH`; the snapshot path is fixed | directory 0770 | **group** |
| `/var/log/azazel-edge/`: `ai-events.jsonl`, `ai-llm.jsonl`, `runbook-events.jsonl`, `triage-audit.jsonl`, `decision-explanations.jsonl` | `AZAZEL_AI_EVENT_LOG`, `AZAZEL_AI_LLM_LOG`, `AZAZEL_RUNBOOK_EVENT_LOG`, `AZAZEL_TRIAGE_AUDIT_PATH`, `AZAZEL_DECISION_EXPLANATIONS_PATH` | root 0644 in a 0755 directory | none |
| `/run/suricata.pid`, `/home/azazel/canary-venv/bin/opencanaryd.pid`, `/proc/<pid>/cmdline`, `os.kill(pid, 0)` | — | — | none today (`PermissionError` from `kill` is read as "running"). **Under `ProtectHome=yes` (§10.6) the OpenCanary pid file under `/home` is hidden**; see §10.6 for how that is handled. |

Uncertain: the Web UI reads `decision-explanations.jsonl` from
`/var/log/azazel-edge`, but the agent's `DecisionLogger` writes
`decision_explanations.jsonl` under `/opt/azazel-edge/logs/tactics_engine`
(§3.4). Whether anything writes the path the Web UI reads was not settled.

Also read, for completeness:

- **Legacy read paths** (fallback candidates when `path_schema` is not
  importable, plus fixed CA candidates): `/etc/azazel-zero/{first_minute.yaml,
  mode.json,portal-viewer.env,certs/…}`, `/run/azazel-zero/ui_snapshot.json`,
  `~/.azazel-zero/web_token.txt`, `/etc/azazel-gadget/tls/ca/…` and
  `/var/lib/azazel-gadget/public/…`. Read only; same marks as their
  `azazel-edge` counterparts (none, or group for the runtime snapshot).
- **`AZAZEL_DEV_HEALTHY_BASELINE`**: a dev-only override (macOS dev profile)
  that makes the monitoring state report OpenCanary, Suricata and ntfy as ON
  without probing. It is not set on devices and grants nothing; it is listed
  so that a unit or installer change never sets it.
- `azazel_edge_epd.save_preview` (writes a preview under `/tmp`) is **not
  reachable** from the Web UI: the Web UI renders previews in memory, and
  `save_preview` is only called from the EPD script's own `main`.

### 2.6 Files written

Every writer below needs **write on the directory**: the JSON and SoT
writers create a temporary file and rename it, and the JSONL appender
(`io_helpers._append_jsonl`) calls `mkdir(parents=True)`.

| Path (default) | Override | Written by | Mark / behaviour as non-root |
| --- | --- | --- | --- |
| **`/etc/azazel-edge/sot.yaml`** (temp + `os.replace`) | `AZAZEL_SOT_PATH` | `PUT`/`PATCH /api/sot/devices`, then `refresh` on `control.sock` | **root** (write on `/etc/azazel-edge`, the directory that also holds the tokens). The control daemon writes the same file for `sot_trust_client`: two writers today. |
| `/var/lib/azazel-edge/captive-allowlist.json` | `AZAZEL_CAPTIVE_REGISTRY_PATH` | `POST /api/captive/register` | owner. Only the Web UI was found to read or write it (static; uncertain whether a captive-portal script reads it on devices). |
| `/run/azazel-edge/operator-progress.json` | `AZAZEL_OPERATOR_PROGRESS_PATH` | `POST /api/operator-progress` | owner (shared runtime directory) |
| `/run/azazel-edge/topolite_seed_mode.json` | `AZAZEL_TOPOLITE_SEED_MODE_PATH` | `POST /api/topolite/seed-mode` | owner |
| `/run/azazel-edge/dashboard-trends.jsonl` | `AZAZEL_DASHBOARD_TRENDS_PATH` | `_record_dashboard_trend_point`, via `_dashboard_health_payload`, which three routes call: `GET /api/dashboard/bundle`, `/api/dashboard/handoff` and `/api/dashboard/health` | owner. **As non-root the `PermissionError` is not caught.** The last-write timestamp is set before the write, so the first of those requests in each trends interval returns 500 and the others in the same interval skip the write and return 200 (§9 saw the bundle fail and the later health/handoff calls succeed). |
| `/run/azazel-edge/triage-sessions/` (created at import) | `AZAZEL_TRIAGE_SESSION_DIR`, fallback `AZAZEL_TRIAGE_SESSION_FALLBACK_DIR` | `/api/triage/*` | owner. **Falls back silently** to `/tmp/azazel-edge/triage-sessions`. |
| `/var/log/azazel-edge/triage-audit.jsonl` (hash-chained) | `AZAZEL_TRIAGE_AUDIT_PATH` | `/api/triage/*` | owner. **Falls back silently** to `/tmp/azazel-edge-triage-audit.jsonl`; with `PrivateTmp=` that audit would be lost on restart. |
| `/var/log/azazel-edge/authz-events.jsonl` | `AZAZEL_AUTHZ_AUDIT_LOG` | every authorization decision (`auth.py`) | owner. Fails with a warning per request; the request itself still proceeds. |
| `/var/log/azazel-edge/runbook-events.jsonl`, `sot-events.jsonl`, `aggregator-events.jsonl` | `AZAZEL_RUNBOOK_EVENT_LOG`, `AZAZEL_SOT_AUDIT_LOG`, `AZAZEL_AGGREGATOR_AUDIT_LOG` | runbooks, SoT edits, aggregator | owner; some paths swallow the error |
| `/tmp/azazel-edge-demo-explanations.jsonl` | `AZAZEL_DEMO_EXPLANATIONS_PATH` | demo path | none |

`/run/azazel-edge` is group-writable (0770) with no sticky bit. Giving the Web
UI group **write** there would let it rename or replace `control.sock`,
`ui_snapshot.json` and `ai_advisory.json`: the same class of problem #472
fixed for `ai-bridge.sock`. Connecting to a socket needs search on the
directory and write on the socket file, **not** write on the directory.

### 2.7 Devices

None. The EPD view is rendered in memory with Pillow
(`_epd_render_png_bytes`). The hardware driver call in `azazel_edge_epd.py`
is in a function the Web UI never calls. `/dev/epd` is a web route, not a
device node.

### 2.8 Authentication material

`require_token` accepts tokens from `AUTH_TOKENS_FILE` (roles viewer,
operator, responder, admin) or the legacy single `TOKEN_FILE` (admin), from
a header or `?token=`. `AZAZEL_AUTH_FAIL_OPEN` exists; the installer sets it
to `0`. The optional mTLS check reads a fingerprint header set by the proxy.
Nothing here changes in #471 except the file modes in §10.5.

## 3. AI agent (`azazel-edge-ai-agent`)

Modules followed: `_util`, `audit/*`, `correlation/advanced`,
`decision_layers`, `evaluators/{soc,noc}`, `evidence_plane/*`, `fabric_view`,
`i18n`, `knowledge/*`, `notify/{core_decisions,delivery,p0_alert}`,
`path_schema`, `policy`, `runbook_review`, `runbooks`,
`sensors/{noc_monitor,system_metrics}`, `sigma/mini`, `tactics_engine/*`,
`ti/lookup`, `yara/mini`.

Imported but **not called on the agent's path** (call-site review; the
container run in §9 agrees, but it did not exercise every branch):
`evidence_plane` NOC probes (`systemctl is-active`, `ping`, TCP/HTTP),
`sensors/system_metrics`, `notify/delivery` (webhook, ntfy, Mattermost) and
the runbook controlled-exec path (the agent only calls `get_runbook`).

### 3.1 Unit

No `User=`/`Group=`, so root. `EnvironmentFile=-/etc/default/azazel-edge-security`
(the agent never opens `/etc/default/*` itself). No `WorkingDirectory=`, so
the working directory is `/` (see 3.5).

### 3.2 Child processes

| Where | Command | Mark |
| --- | --- | --- |
| `agent.py` `_default_route_info` | `/usr/sbin/ip` (or `/sbin/ip`, `ip`) `-4 route show default`, timeout 3 s | none (netlink read). Seen working as non-root in §9. |

That is the only child process.

### 3.3 Sockets

| Socket | Role | Mark |
| --- | --- | --- |
| `ai-bridge.sock`, `${AZAZEL_AI_SOCKET:-/run/azazel-edge-ai/ai-bridge.sock}` | **server**. `_prepare_ai_socket_dir` makes the directory 0700 under umask 077 and refuses a symlink, a non-directory, an owner other than `geteuid()`, or any group/other bit. `_bind_ai_socket` binds under umask 0177, `chown(-1, getegid())`, `chmod 0600`. | **owner**: `mkdir` under `/run` needs root today; with a pre-created directory owned by the agent's account it works unchanged (§9). |
| Ollama `${AZAZEL_OLLAMA_ENDPOINT:-http://127.0.0.1:11434}/api/chat` | client | none |
| `control.sock` | not used | — |

**Callers of `ai-bridge.sock` today:** the Rust core (one JSON line per
event, plus `azazel-edge/forward-stats/v1` lines) and the Web UI
(`manual_query`). `_handle_request_line` dispatches on the payload only:
forward-stats become metrics, `manual_query` goes to the query handler, and
**anything else** goes to `_handle_event` → `_record_core_decision` (the
core-decision audit chain, the P0 relay and queue, advisory and snapshot
writes). There is no SO_PEERCRED or uid check. A caller that can connect can
therefore inject what looks like a core decision. Today only root and the
agent's own account can connect (#472).

### 3.4 Files written

All need write on the directory (temp + `os.replace`, rotation, `mkdir`).

| Path (default) | Override | Notes | Mark |
| --- | --- | --- | --- |
| `/run/azazel-edge` (shared runtime directory) | parent of `AZAZEL_AI_ADVISORY`; mode `AZAZEL_RUNTIME_DIR_MODE` (0770) | `_prepare_runtime_dir`: `mkdir` + **unconditional `os.chmod`**, not caught in `_serve` | **owner of `/run/azazel-edge`**. As non-root the agent dies at start (`EACCES` on `mkdir`, or `EPERM` on `chmod` when root pre-created it; both seen in §9). |
| `/run/azazel-edge/ai_advisory.json` | `AZAZEL_AI_ADVISORY` | read by the control daemon (**fixed path**, `daemon.py` `AI_ADVISORY_PATH`) and the Web UI | owner |
| `/run/azazel-edge/ui_snapshot.json` | `AZAZEL_UI_SNAPSHOT` | read-modify-replace. **Also written by the control daemon** (`_persist_snapshot`, seed) and seeded by the installer: two writers | owner |
| `/run/azazel-edge/ui_status_view.json` | none (next to the snapshot) | `fabric_view.py`, only with `azazel_fabric` installed | owner |
| `/run/azazel-edge/ai_metrics.json` | `AZAZEL_AI_METRICS` | read by the Web UI | owner |
| `/run/azazel-edge/ai_runtime_policy.json` | `AZAZEL_AI_POLICY` | | owner |
| `/var/log/azazel-edge/ai-events.jsonl`, `ai-llm.jsonl`, `ai-deferred.jsonl`, `ai-audit.jsonl` | `AZAZEL_AI_EVENT_LOG`, `AZAZEL_AI_LLM_LOG`, `AZAZEL_AI_DEFERRED_LOG`, `AZAZEL_AI_AUDIT_LOG` | `ai-audit` is opened at import; if that fails it falls back to `/tmp/azazel-edge-ai-audit.jsonl` (fixed name in a world-writable directory) | owner |
| `core-decision-audit.jsonl` (+ `.1`) | derived from the directory of `AZAZEL_AI_AUDIT_LOG`; no own variable | rotation: unlink + replace + directory fsync | owner (directory) |
| `p0-alert-queue.jsonl` + `.lock` + temp files | same directory | `O_NOFOLLOW`, 0600, `flock`; reconcile cursors are rows in the queue. No reader in this repo. | owner (directory) |
| **`/opt/azazel-edge/logs/tactics_engine/decision_explanations.jsonl`** | `AZAZEL_DECISION_LOG_DIR` (not set by the unit or installer) | `mkdir` at **module import**, append per scored event. The installer creates the directory root 0755. | owner. As non-root it **stops logging with only a warning**. |

### 3.5 Files read

All **none** while modes stay as they are.

- `${AZAZEL_NORMALIZED_EVENT_LOG:-/var/log/azazel-edge/normalized-events.jsonl}`
  (written by the core; root 0644 from the Rust default and umask, not
  verified on a device), tail-read at start for reconciliation.
- `/proc/meminfo`, `/proc/sys/kernel/random/boot_id`.
- `/opt/azazel-edge/config/ti/*.yaml`, `config/sigma/*.yaml`.
- Runbooks: `${AZAZEL_RUNBOOK_DIR:-/etc/azazel-edge/runbooks}` and `/opt/azazel-edge/runbooks`.
- `AZAZEL_SOC_POLICY_PATH` (default `config/soc_policy.yaml`) and
  `AZAZEL_ATTACK_MAPPING_PATH` are **relative to the working directory**,
  which is `/` under the unit. On a device that means the built-in default
  policy is used (uncertain whether intended; tracked separately, §12).
- `path_schema` checks whether `/etc/default/azazel-edge` and `/etc/azazel-edge` exist.

### 3.6 Devices, environment files, secrets

No devices. No token, password or webhook variable is read by the agent;
the Mattermost settings live in `/etc/default/azazel-edge-web`. The keys
seeded into `/etc/default/azazel-edge-security` (`SURICATA_IFACE`,
`AZAZEL_RUNTIME_DIR_MODE`, `AZAZEL_CONTROL_SOCKET_MODE`,
`AZAZEL_RUNTIME_SOCKET_GROUP`) are not secrets.

## 4. Control daemon (`azazel-edge-control-daemon`)

Stays root in #471. Listed because stages 1 and 2 move work to it.

- Unit: root, `EnvironmentFile=-/etc/default/azazel-edge-security`;
  `ExecStart` is the `bin/azazel-edge-control-daemon` wrapper, which runs
  `py/azazel_edge_control/daemon.py` with `AZAZEL_VENV_PYTHON`, the repo
  `.venv` or `/opt/azazel-edge/venv`.
- Socket: `${AZAZEL_CONTROL_SOCKET:-/run/azazel-edge/control.sock}`,
  directory mode `AZAZEL_RUNTIME_DIR_MODE` (0770), socket mode
  `AZAZEL_CONTROL_SOCKET_MODE` (0660). If `AZAZEL_RUNTIME_SOCKET_GROUP` is
  set, both get that group; the default is empty (root:root).
- **No peer check.** Nothing in `py/`, `azazel_edge_web/` or the core calls
  `SO_PEERCRED`. Every action is open to anyone who can connect. One
  `recv(4096)` JSON request per connection.

| Action | Effect | Mark |
| --- | --- | --- |
| `get_snapshot`, `watch_snapshot`, `details`, `path_schema_status`, `mode_status`, `mode_get` | read/build the snapshot (`ip`, `iw dev <if> link`, `ip -j link/addr`, `curl --interface <if>`, `/proc`, `/sys/class/thermal`), read `/etc/azazel-edge/mode.json` | none, except writing `/run/azazel-edge`; `curl --interface` may need cap:NET_RAW on older kernels (uncertain) |
| `mode_set`, `mode_portal`, `mode_shield`, `mode_scapegoat`, `mode_apply_default` | mode validated against portal/shield/scapegoat; writes `/etc/azazel-edge/mode.json` and `/run/azazel-edge/epd_state.json`, `systemctl start azazel-edge-epd-refresh.service` (fixed unit) | root |
| `sot_trust_client` | MAC or private IP required; writes the SoT (0644) | root (`/etc`) |
| `migrate_path_schema` | `mkdir`, `copytree`, `symlink` across `/etc/azazel-*`, `/etc/default/azazel-*`, `/run/azazel-*` and `/root` | root. **A filesystem migration exposed on the socket.** |
| `wifi_scan` | `iw dev`, `nmcli … show`, `nmcli dev wifi rescan`, `iw scan` (rate-limited) | cap:NET_ADMIN / NetworkManager polkit |
| `wifi_connect` | `nmcli con add` (new profile, no secret) or, for a saved profile given a new PSK, `nmcli con clone` (the copy's stored PSK dropped with `wifi-sec.psk-flags 2`/`0`; the original replaced only after the copy is up), then `nmcli con up … passwd-file <file>`; `con delete`, `ip link/addr/route`, `ping`, `curl`; NAT: `sysctl -w net.ipv4.ip_forward=1`, `nft add table ip azazel_nat` + masquerade (iptables fallback) | root. Since #477 the passphrase is not on nmcli's argv: it is in a 0600 passwd-file in a fresh 0700 directory under `/run`, removed when nmcli returns (before #477 it was on argv, readable from `/proc/<pid>/cmdline`). |
| `shutdown`, `reboot` | `scripts/*.sh` → `systemctl --no-block poweroff|reboot` | root |
| `refresh`, `reprobe`, `contain`, `stage_open`, `disconnect` | append `{ts, action}` to `/run/azazel-edge/action_requests.log` only (no reader found; not exhaustive) | owner |
| `portal_viewer_open` | absolute http(s) URL required; writes `/run/azazel-edge/portal-viewer-start-url`, `systemctl start|restart azazel-edge-portal-viewer.service` (fixed; that unit is not shipped in this repo), probes TCP 6080 | root |

Background: `suppress_auto_wifi` (on by default) runs `nmcli con mod …
connection.autoconnect no` and `nmcli dev disconnect` (root/polkit);
`_wifi_sensor_loop` runs `/sbin/iw dev <if> scan` (cap:NET_ADMIN); a netlink
link watcher (none). It reads `/run/azazel-edge/ai_advisory.json` at a fixed
path. No device node is opened.

## 5. Core (`azazel-edge-core`, Rust)

Stays root until stage 3.

- Settings (`main.rs`): `AZAZEL_EVE_PATH` (`/var/log/suricata/eve.json`),
  `AZAZEL_AI_SOCKET` (`/run/azazel-edge-ai/ai-bridge.sock`),
  `AZAZEL_NORMALIZED_EVENT_LOG` (`/var/log/azazel-edge/normalized-events.jsonl`),
  `AZAZEL_DEFENSE_RELEASE_LEDGER` (`/var/lib/azazel-edge/release-ledger.json`),
  `AZAZEL_DEFENSE_IFACE`, `AZAZEL_DEFENSE_HONEYPOT_PORT` (2222),
  `AZAZEL_REDIRECT_POLICY_PATH` (relative `config/redirect_policy.yaml`; with
  no `WorkingDirectory=` it resolves under `/`), plus the poll/forward flags.
  The unit sets enforcement off, dry-run on, level advisory.
- Reads eve.json, the redirect policy, `boot_id`. Writes
  `normalized-events.jsonl` (root, umask → 0644), `ingress-audit.jsonl`
  (0600, `O_NOFOLLOW`, rotated), the release ledger and its rollback audit.
  No installer step creates `/var/lib/azazel-edge` for it; the core does, as
  root.
- Client of `ai-bridge.sock` only; it does not check who is on the other end.
  It listens on nothing.
- Children: apply path (`run_command`) runs `nft insert rule inet azazel_edge …`
  (isolate, redirect) and `tc qdisc replace dev <iface> root …` (throttle)
  via `Command::new(argv[0])` with the **inherited `PATH` and environment**.
  The release path (`release.rs`) runs `tc -j qdisc show`, `tc qdisc del`,
  `nft -a -j list chain`, `nft delete rule … handle <n>` from an allowlist of
  `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin` with the environment cleared.
  Both need **cap:NET_ADMIN at least**; whether that alone suffices is
  #471's hardware question and is not answered here.
- I found no installer step that creates `table inet azazel_edge` or its
  chains (static search; it may be created outside this repository on
  devices; the SO-04 harness creates it for its own runs).

## 6. Other units (brief)

| Unit | Account | Needs | Notes |
| --- | --- | --- | --- |
| `azazel-edge-epd-refresh` (+ timer, 30 s) | root | EPD over SPI/GPIO (`/dev/spidev*`, GPIO) via the Waveshare driver: group:spi + group:gpio, or root | reads `/run/azazel-edge/epd_state.json`, runs `iwgetid` and `azazel_edge_epd.py`, writes `epd_last_render.json` |
| `azazel-edge-selftest` (+ quarterly timer) | root | `systemctl is-active`, `sha256sum --check /etc/azazel-edge/.config_checksums`, `du` | writes `/var/log/azazel-edge/selftest_latest.json`; `dd` as root to a new `mktemp` name in `/tmp` (`conv=nocreat`), removed on exit (a fixed `/tmp/azazel_sdtest` before #477); runs pytest from `/opt/azazel-edge/tests`, which the installer does not install |
| `azazel-edge-netflow-receiver` | `User=azazel` | UDP 2055 (none) | **no installer creates the `azazel` account**; `ExecStart` uses `${VAR:-default}`, which systemd does not expand (uncertain how it behaves on a device) |
| `azazel-edge-snmp-poller` | `User=azazel` | none | same two points; `/etc/default/azazel-edge-sensors` (0644) holds SNMP community strings |
| `azazel-edge-opencanary` | root | docker compose (root-equivalent), host network; HTTP 18080, SSH 12222 | logs to `/var/log/azazel-edge/opencanary`. The core's redirect default is port 2222, not 12222 (not a privilege issue). |
| `azazel-edge-suricata` | root | raw capture on `${SURICATA_IFACE:-br0}` (cap:NET_RAW + NET_ADMIN), `Nice=-5`, realtime IO class | writes `/var/log/suricata/eve.json` |
| `azazel-edge-vector` | root | none intrinsic | reads eve.json and OpenCanary logs, writes `/var/log/azazel-edge/vector/*.jsonl` |

## 7. Installer and filesystem today

- Runs as root; installs unit files 0644.
- **No** account or group creation, no `sysusers.d`, no `tmpfiles.d`, no
  sudoers file, no `RuntimeDirectory=`/`StateDirectory=`/`LogsDirectory=`,
  no capability directives anywhere.
- `/etc/azazel-edge`, `/var/log/azazel-edge`, `/run/azazel-edge`: root:root
  0755 at install. `/run` is cleared at boot; the daemons recreate
  `/run/azazel-edge` and the control daemon sets it to 0770. The seeded
  `ui_snapshot.json` does not survive a reboot.
- Compatibility symlinks `/etc/azazel-gadget`, `/var/log/azazel-gadget`,
  `/run/azazel-gadget`.
- `/etc/default/azazel-edge-web`: `AZAZEL_WEB_TOKEN_FILE=/etc/azazel-edge/web_token.txt`,
  `AZAZEL_AUTH_FAIL_OPEN=0`; `install_ai_runtime.sh` adds Mattermost
  defaults and `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=0`.
- `/etc/default/azazel-edge-security`: `AZAZEL_RUNTIME_DIR_MODE=0770`,
  `AZAZEL_CONTROL_SOCKET_MODE=0660`, empty `AZAZEL_RUNTIME_SOCKET_GROUP`,
  and the #472 rewrite of the old `AZAZEL_AI_SOCKET` default.
- Secrets under `/etc/azazel-edge`: `web_token.txt` (0640 root),
  `mattermost-command-token` (0600), `ntfy.token` (0600, also
  `/etc/azazel/ntfy.token`), `mattermost-credentials.env` (0600 from
  creation since #477: mktemp beside it, renamed over it), `secrets/`,
  `tls/webui.key` (for the HTTPS proxy, not the Web UI).
  `/opt/azazel-edge/security/.env` is installed 0644 (contents not inspected).
- `/opt/azazel-edge` is root-owned, including `logs/tactics_engine` (0755).

## 8. Other components touched

| Component | Who touches it | How |
| --- | --- | --- |
| Suricata `eve.json` | core (read), vector (read), Suricata unit (write) | file |
| Wazuh | installer | file-integrity monitoring of `/etc/azazel-edge`, `/opt/azazel-edge`, `/var/log/azazel-edge`; ownership changes in stages 1–2 will show up there once |
| OpenCanary | Web UI (status via systemctl/pgrep/pid/docker), opencanary unit (docker compose) | process/unit status |
| docker | Web UI (`docker ps`), opencanary unit | docker socket (root-equivalent) |
| NetworkManager / `iw` / nft NAT | control daemon only | nmcli, iw, nft, sysctl |
| Mattermost | Web UI | HTTP client; bot/command tokens |
| ntfy | Web UI | HTTP client (SSE, health); token file |
| Ollama | agent | HTTP client to loopback 11434 (the bundled compose file publishes 11434 on all interfaces; noted, not changed) |
| systemd | Web UI (`is-active`, runbook `status`/`restart`), control daemon (`start` of fixed units, reboot/poweroff), selftest | D-Bus |
| port 8082 status API | Web UI | curl; server not in this repository |
| NetFlow / SNMP sensors | their own units | in-memory evidence bus only |

## 9. Container observation (not a device)

Throwaway `python:3.11` container (Debian, aarch64, colima, `--rm`), repo
copied in read-only, runtime requirements installed, accounts `azazel-web`
and `azazel-agent` created with `useradd -r`. Each run used a Python
`sys.addaudithook` (subprocess, open, socket, chmod/chown/mkdir/rename) and
`strace -f -Z` (failed syscalls only). No control daemon, core, Suricata,
Wi-Fi or EPD exists in the container, and no `/etc/azazel-edge`,
`/run/azazel-edge` or `/var/log/azazel-edge` was pre-created unless stated.

**Web UI as `azazel-web`** (Flask test client: every parameterless `GET`
route except streams, plus a few `POST`s):

- `POST /api/action/disconnect`: curl to 8082 failed, then
  `ip link set <container interface> down` ran and returned
  `RTNETLINK answers: Operation not permitted`; the API answered 500 with that
  error (visible, not silent).
- `GET /api/dashboard/bundle`: **500**, uncaught `PermissionError` on
  `mkdir /run/azazel-edge` from the trends writer. The later
  `/api/dashboard/health` and `/api/dashboard/handoff` calls in the same run
  returned 200 because the trends interval had not passed (§2.6).
- `docker ps` was executed from the monitoring-state path (no docker in the
  container, so it failed and was read as "not running").
- `systemctl is-active` ran for the OpenCanary, Suricata, ntfy, agent, web
  and portal-viewer units; `pgrep -f [o]pencanary.tac` ran.
- Triage sessions: `mkdir /run/azazel-edge/triage-sessions` failed and the
  module silently used `/tmp/azazel-edge/triage-sessions`.
- `authz-events.jsonl`: one warning per request ("Permission denied:
  /var/log/azazel-edge"); requests still proceeded.
- `POST /api/ai/ask`: `ai_socket_not_found` (no agent in that run).
- Outbound TCP to the Mattermost default address was attempted.
- No device node was opened.

**Agent as `azazel-agent`**, three runs:

1. Defaults, nothing pre-created: warning for
   `/opt/azazel-edge/logs/tactics_engine` (decision log disabled), `mkdir
   /var/log/azazel-edge` failed (audit fell back to `/tmp`), then `_serve`
   died with `PermissionError` on `mkdir /run/azazel-edge`.
2. `/run/azazel-edge-ai` pre-created `azazel-agent` 0700 and `/run/azazel-edge`
   pre-created `root:azazel-agent` 0770: `_serve` died with `EPERM` on
   `chmod /run/azazel-edge` (the unconditional chmod in `_prepare_runtime_dir`).
3. Agent-owned directories and the **existing** path variables pointed at
   them (`AZAZEL_AI_ADVISORY`, `AZAZEL_AI_METRICS`, `AZAZEL_AI_POLICY`,
   `AZAZEL_UI_SNAPSHOT`, `AZAZEL_AI_*_LOG`, `AZAZEL_DECISION_LOG_DIR`):
   started, bound `ai-bridge.sock` (0600 in the 0700 directory, owner
   `azazel-agent`), answered a `manual_query` (fallback answer; Ollama was
   pointed at a closed port), ran `ip -4 route show default` without error,
   wrote the P0 queue (0600) and its lock, the advisory, metrics, policy and
   snapshot files and the decision log. No root was needed in that container
   run.

Run 3 shows that, in a container, the agent's code needs no privilege once
its directories exist. It does not show that the same holds on a device
(Ollama, `/run` handling at boot, NetworkManager, Wazuh, the real core and
the control daemon were absent).

## 10. Stage 1 plan: Web UI as `azazel-web`

Nothing below is implemented by this page. No new decision or enforcement
authority, approval flag, environment-variable bypass or generic
command/unit API is added. Existing path variables are set in the unit only
where the code already reads them; preferably the code defaults change to
the new paths so the unit and the code agree.

**Owner decisions taken after the first review of this page** (recorded
here; the plan below follows them):

- disconnect: the Web UI's existing disconnect becomes a fixed,
  parameterless control-daemon action (`uplink_disconnect`);
- SoT edits: fixed, validated control-daemon actions, one writer;
- `docker ps`: removed from the Web UI;
- the controlled-exec restart runbook stays as it is and fails visibly when
  run as non-root;
- `control.sock`: per-uid action table in the daemon; `migrate_path_schema`
  root-only;
- `manual_query`: **stage 1** adds the dedicated agent query socket (§10.4),
  not stage 2, so the Web UI keeps working while the agent is still root;
- the agent's `WorkingDirectory=` stays unchanged in #471 (separate issue);
- the out-of-scope findings in §12 are tracked separately.

### 10.1 Accounts and groups

- `azazel-web`: system user, no login shell, no home (`/nonexistent`),
  primary group `azazel-web`.
- `azazel-control`: group allowed to connect to `control.sock`. Members:
  `azazel-web`. Set through the existing `AZAZEL_RUNTIME_SOCKET_GROUP`.
- Created idempotently by the installer (a `sysusers.d` snippet, or
  `getent || useradd --system`), with a check that the names are not already
  taken by an unrelated account (stop and report if they are).
- The Web UI is **not** added to `docker`, `adm`, `systemd-journal`, `spi`,
  `gpio`, `netdev` or `sudo`.

### 10.2 Root-needing operations: where each one goes

| Today in the Web UI | Stage 1 |
| --- | --- |
| `ip link set <uplink> down` fallback | **Owner decision: relocate** the Web UI's existing disconnect into the control daemon as a fixed action `uplink_disconnect` with **no parameters**: the daemon uses its own configured uplink and the request cannot name an interface, a command or a unit. The Web UI calls it (after the 8082 status API, as today) instead of running `ip`. This moves an existing operator action to the root process; it is an owner-approved relocation, not something the peer checks make free. A failure is returned to the caller as an error, never as success. |
| `docker ps` in `_container_running` (OpenCanary and Suricata) | **Owner decision: remove.** OpenCanary and Suricata state come from `systemctl is-active` (already queried for both) and the existing pid/pgrep checks. No docker group. A Suricata or OpenCanary that runs only as a docker container named `azazel-edge-*`, with no matching unit, would then show OFF; the shipped units are host units, so this is expected not to matter (uncertain for devices set up by hand). |
| `PUT`/`PATCH /api/sot/devices` writing `/etc/azazel-edge/sot.yaml` | **Owner decision:** move to the control daemon as fixed actions `sot_devices_replace` and `sot_devices_patch`: the daemon validates with the same `SoTConfig` model, writes the file with the same temp+replace, appends the same `sot-events` record (with the caller's uid), then refreshes. Merged with the `sot_trust_client` writer so there is one writer. The Web UI keeps its own validation for early errors. |
| Runbook `rb.noc.service.restart.controlled` (`systemctl restart`) | **Owner decision: not moved.** It stays behind `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC` (installer default 0) and approval; under `azazel-web` an enabled run fails with systemd's permission error, returned to the caller (non-zero `exit_code`, `ok:false`). No polkit rule and no daemon "restart unit" action (that would be a unit-operation API). |
| Reading `mattermost-command-token`, `ntfy.token` (0600 root) | Change those files to `0640 root:azazel-web`. Make the unreadable case a visible warning at start instead of a debug line. |
| `web_token.txt`, `auth_tokens.json`, `client-cert-fingerprints.txt` | `0640 root:azazel-web`. |
| `manual_query` over `ai-bridge.sock` (0700 directory owned by the agent's account) | **Owner decision:** the dedicated agent query socket, in stage 1 (§10.4). |

### 10.3 `control.sock` and peer checks

- Directory `/run/azazel-edge`: `AZAZEL_RUNTIME_DIR_MODE=0750`, group
  `azazel-control`. The Web UI can search and read but cannot create, rename
  or unlink in it. The agent (still root in stage 1) and the daemon keep
  writing there.
- Socket `control.sock`: 0660 `root:azazel-control` (unchanged mode).
- The control daemon reads `SO_PEERCRED` on every connection and checks the
  action against a **fixed, in-code** table:
  - uid 0: every action (unchanged behaviour for root tools).
  - the uid of `azazel-web` (resolved with `getpwnam` at start; refuse to
    start if group/user setup is inconsistent): the actions the Web UI sends
    today (§2.3) plus `sot_devices_replace`, `sot_devices_patch` and
    `uplink_disconnect`.
  - anyone else: rejected, logged.
  - `migrate_path_schema` stays root-only.
  - Rejection is an error reply and a log line; nothing is retried or turned
    into success.
- The peer table narrows who may call what. Separately, three actions are
  **added** to the daemon: `sot_devices_replace`, `sot_devices_patch` and
  `uplink_disconnect`. They relocate operations the Web UI performs today
  (writing the SoT file, bringing the uplink down) into the root process as
  fixed, argument-validated actions. They are owner-approved decisions, not
  a consequence of the peer check, and the daemon gains no generic command
  or unit operation with them.

### 10.4 Agent query socket (`manual_query`)

`manual_query` is the only thing the Web UI sends to the agent (`POST
/api/ai/ask`, `/api/mattermost/message`, `/api/mattermost/command`; no other
sender exists in the repository). Since #472, `ai-bridge.sock` sits in a 0700
directory owned by the agent's account, so a Web UI running as `azazel-web`
cannot reach it. Stage 1 therefore adds the query socket while the agent is
still root:

- **Path:** `/run/azazel-edge-agent-query/agent-query.sock`.
- **Directory:** created by the agent, mode 0750, owner the agent's account
  (root in stage 1, `azazel-agent` in stage 2), group `azazel-web`. The same
  refusal rules as #472: symlink, not a directory, wrong owner, or bits
  beyond 0750 → the agent refuses to start the query listener and logs why;
  nothing is relaxed or fixed silently.
- **Socket:** 0660, owner the agent's account, group `azazel-web`, bound
  under a restrictive umask before listening.
- **Peer check:** on every accept the agent reads `SO_PEERCRED` and accepts
  only `uid == getpwnam("azazel-web").pw_uid` or uid 0 (resolved at start; no
  variable can widen it).
- **Messages:** exactly one type, `action == "manual_query"`, with the same
  parameter limits as today. Anything else gets
  `{"ok": false, "error": "forbidden"}` and is **never** passed to
  `_handle_event`, forward-stats or the P0 path. Rejections are logged with
  uid and pid.
- **`ai-bridge.sock`** stays where #472 put it, for the core. Once the query
  socket exists, `manual_query` on `ai-bridge.sock` is rejected.
- **Web UI:** its default for `AZAZEL_AI_SOCKET` becomes the query socket
  path (no new variable; see the warning in §2.3 about the shared name).
- **Authority:** none added. `manual_query` already exists and only produces
  an advisory answer.

### 10.5 Files and directories

| Purpose | New location | Owner / mode | How |
| --- | --- | --- | --- |
| runtime files (operator progress, topolite seed mode, trends, triage sessions) | `/run/azazel-edge-web/` | `azazel-web` 0750 | `RuntimeDirectory=azazel-edge-web`; defaults of `AZAZEL_OPERATOR_PROGRESS_PATH`, `AZAZEL_TOPOLITE_SEED_MODE_PATH`, `AZAZEL_DASHBOARD_TRENDS_PATH`, `AZAZEL_TRIAGE_SESSION_DIR` |
| logs (authz, runbook, SoT\*, aggregator, triage audit) | `/var/log/azazel-edge/web/` | `azazel-web` 0750, group `azazel-web` | `LogsDirectory=azazel-edge/web`; defaults of `AZAZEL_AUTHZ_AUDIT_LOG`, `AZAZEL_RUNBOOK_EVENT_LOG`, `AZAZEL_AGGREGATOR_AUDIT_LOG`, `AZAZEL_TRIAGE_AUDIT_PATH` (\*SoT events move with the daemon writer) |
| captive allowlist | `/var/lib/azazel-edge-web/captive-allowlist.json` | `azazel-web` 0750 | `StateDirectory=azazel-edge-web`; installer moves the old file once |
| secrets the Web UI reads | in place | `0640 root:azazel-web` | installer `chgrp`/`chmod` |
| `/etc/azazel-edge` | in place | planned `0755 root:root`; **implemented: never widened** (§10.9) | resolves the 0750/0755 install-order ambiguity |

Code changes that go with this, so failure is visible rather than silent:

- the trends writer catches `OSError` like the other writers (the bundle
  must not 500);
- the triage session and triage audit `/tmp` fallbacks are removed or log a
  warning at start (a hash-chained audit should not move to `/tmp` quietly);
- the authz-audit failure stays a warning, but is also counted in
  `/health`.

### 10.6 Unit

```ini
[Service]
User=azazel-web
Group=azazel-web
SupplementaryGroups=azazel-control
RuntimeDirectory=azazel-edge-web
RuntimeDirectoryMode=0750
StateDirectory=azazel-edge-web
LogsDirectory=azazel-edge/web
UMask=0027
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
```

- `AF_NETLINK` is needed: the read-only runbook `rb.noc.default-route.check`
  runs `ip -4 route show default` as the Web UI's account, and `iwgetid`
  (§2.2) may use netlink on some drivers (uncertain; it falls back to an
  ioctl on an `AF_INET` socket).
- `ProtectHome=yes` hides `/home`, so the OpenCanary pid file
  `/home/azazel/canary-venv/bin/opencanaryd.pid` (§2.5) becomes invisible.
  The code already treats a missing pid file as "not this check", so
  OpenCanary state then comes from `systemctl is-active` (three unit names)
  and `pgrep`. A device that runs OpenCanary only from that legacy venv,
  with neither a unit nor a visible `opencanary.tac` process, would show OFF.
  If the owner still has such devices, use `ProtectHome=read-only` instead;
  the plan's default is `yes`.

Not `MemoryDenyWriteExecute=` (Pillow/NumPy wheels may need it; to be
tested). Not `ProtectProc=invisible` (it would break `pgrep` and the pid
checks for OpenCanary and Suricata). `ExecStart` can drop `bash -lc` once
the variables are expanded by systemd directly (optional).

### 10.7 Installer migration

1. Create `azazel-web` and `azazel-control` (idempotent, §10.1).
2. Create `/var/log/azazel-edge/web` and `/var/lib/azazel-edge-web` (systemd
   creates them too; the installer does it so the migration can copy).
3. Move existing Web-owned files (`captive-allowlist.json`, the Web logs) to
   the new directories, `chown azazel-web`. Keep the old files read-only in
   place for one release, or leave a note in the log; do not delete audit
   history.
4. `chgrp azazel-web` + `chmod 0640` the token files.
5. Point the Web UI at the query socket: rewrite `AZAZEL_AI_SOCKET` in
   `/etc/default/azazel-edge-web` only if it holds the old (#472) default;
   never touch the same variable in `/etc/default/azazel-edge-security`
   (agent and core, §2.3).
6. Set `AZAZEL_RUNTIME_SOCKET_GROUP=azazel-control` and
   `AZAZEL_RUNTIME_DIR_MODE=0750` in `/etc/default/azazel-edge-security`
   **only if** they still hold the old installer defaults (the #472 pattern);
   otherwise leave them and print a notice.
7. Install the new units, `daemon-reload`, restart the control daemon, then
   the agent (query socket), then the Web UI.
8. Wazuh FIM will report the ownership change once; note it in the release
   notes.

### 10.8 Verification (stage 1)

- Unit tests: control-daemon peer table (root allowed, web uid allowed only
  its actions, other uid rejected, `migrate_path_schema` root-only);
  `sot_devices_*` validation and single writer; `uplink_disconnect` takes no
  parameters and reports failure as failure; the Web UI no longer calls
  `docker` or `ip link`; trends write failure does not 500; token files
  unreadable → visible warning.
- Unit tests for the query socket (§10.4): accepts the `azazel-web` uid and
  root, rejects any other uid; accepts only `manual_query` and never reaches
  `_handle_event`, forward-stats or the P0 path; directory/socket refusal
  rules; `manual_query` on `ai-bridge.sock` is rejected; the Web UI's
  `/api/ai/ask` and Mattermost message/command paths answer through the
  query socket.
- Container (`--rm`, systemd-in-container where possible): Web UI as
  `azazel-web` with the unit's hardening; audit-hook/strace run like §9
  shows no `EACCES`/`EPERM` except the deliberately unprivileged ones.
  Container results stay labelled as container results.
- Device (owner): dashboard, Wi-Fi scan/connect, mode change, SoT edit,
  disconnect, `manual_query` from `/api/ai/ask` and from a Mattermost
  message and command, ntfy SSE; `systemd-analyze security
  azazel-edge-web`; `ps -o user= -C gunicorn` shows `azazel-web`.

### 10.9 Stage 1 as implemented

What the stage 1 change does, where it differs from §10.1–10.8, and how to
upgrade and roll back. Container results are container results (§10.8);
nothing here is device evidence.

**Differences from the plan above**

| Plan | Implemented | Why |
| --- | --- | --- |
| `LogsDirectory=azazel-edge/web` (`/var/log/azazel-edge/web`) | `LogsDirectory=azazel-edge-web` (`/var/log/azazel-edge-web`) | owner instruction for stage 1: one name, `azazel-edge-web`, for the runtime, state and log directories |
| `azazel-web` uid resolved at start; refuse to start if inconsistent | resolved on every check; an account that does not resolve grants nothing (only root keeps access) | an account created after the daemon started is picked up; failure is closed either way |
| uid 0: every action | uid 0 **or the daemon's own uid**: every action | identical under the unit (the daemon is root); on a development host the daemon and the Web UI run as one non-root account. `migrate_path_schema` stays uid 0 only, also for the daemon's own non-root account |
| query socket path not configurable | the agent binds at `AZAZEL_AI_QUERY_SOCKET` (default `/run/azazel-edge-agent-query/agent-query.sock`) | tests and the dev stack must not use `/run`. The variable only moves the socket; the directory/owner/mode checks and the peer check do not change with it |
| existing query directory with wrong bits: refuse | same, and a directory the agent creates is given group `azazel-web` and mode 0750 by the agent | nothing pre-exists in stage 1 (`/run` is cleared at boot) |

**`control.sock` peer table** (`py/azazel_edge_control/daemon.py`,
`peer_action_allowed`; nothing in it comes from the environment or the
request):

| Peer uid (from `SO_PEERCRED`) | Allowed actions |
| --- | --- |
| 0 | every action |
| the daemon's own uid | every action except `migrate_path_schema` (unless it is 0). Under the unit this is root; it must be revisited if the daemon stops running as root (stage 3+) |
| `azazel-web` | `get_snapshot`, `watch_snapshot`, `refresh`, `reprobe`, `details`, `wifi_scan`, `wifi_connect`, `portal_viewer_open`, `shutdown`, `reboot`, `mode_set`, `mode_status`, `mode_get`, `mode_portal`, `mode_shield`, `mode_scapegoat`, `sot_trust_client`, `uplink_disconnect`, `sot_devices_replace`, `sot_devices_patch` |
| anyone else, an `azazel-web` that does not resolve, a peer the kernel does not identify | nothing; `{"ok": false, "error": "forbidden"}`, a warning with uid/pid and a refusal counter |

The `azazel-web` set is what the Web UI sends on the socket today
(`ALLOWED_ACTIONS` minus `contain`/`release`/`disconnect`/`stage_open`, which
go to the 8082 status API only, plus `control_plane`'s snapshot reads) and the
three relocated operations. A unit test derives it from the Web UI's code.

**Relocated operations.** `uplink_disconnect` takes no parameters and no
extra request field; it sets the daemon's `AZAZEL_UP_IF` (default `wlan0`,
the Web UI's former source) down with `ip link set dev <if> down` after
checking the name and that the interface exists, and returns any failure
(the Web UI answers HTTP 500 with the reason). `sot_devices_replace` /
`sot_devices_patch` take only `devices` (and an informational
`requested_by`), validate the whole document with `SoTConfig`, write a new
temporary file, `fsync`, rename, and append `sot-events.jsonl` with the peer
uid; a SoT file that exists but cannot be parsed is never replaced. The
daemon reads one request of up to 1 MiB (it used to read 4 KiB once), all
of it within 10 s in total; a peer the table allows nothing is refused
before anything is read, and at most 32 connections are handled at once;
non-root peers together hold at most 24 of them and at most 16
`watch_snapshot` streams, so root tools always have headroom (beyond that:
`busy`). A watch stream whose client has gone is noticed while nothing
changes (end of stream on the socket, checked every interval) and frees its
slot; `control_plane.watch_snapshots` closes its socket as soon as its
consumer stops. A rewritten SoT file keeps the mode and group of
the file it replaces (the installer makes it 0640 root:azazel-web); a new
one is 0640 root:azazel-web when the daemon is root.

**Query socket.** `/run/azazel-edge-agent-query/agent-query.sock`, directory
0750 `root:azazel-web`, socket 0660 `root:azazel-web`. Peers: uid 0 and
`azazel-web`. Only `{"action": "manual_query", ...}` is answered; anything
else is refused and never reaches `_handle_event`, forward stats or the P0
path. Once it listens, `manual_query` on `ai-bridge.sock` is refused. Without
the `azazel-web` account the query socket is not created (logged as an
error), and `ai-bridge.sock` keeps answering `manual_query` from the peers
that can reach it (owner only).

**`AZAZEL_AI_SOCKET` caution.** For the Web UI it now means the query socket
(default above); for the agent and the core it means `ai-bridge.sock`. Set it
for the Web UI only in `/etc/default/azazel-edge-web`. The installer moves an
old `ai-bridge.sock` value there and never touches
`/etc/default/azazel-edge-security` for this variable; the core unit sets it
with `Environment=`. `bin/azazel-edge-devstack` gives the Web UI its own
value.

**Web UI state.** Defaults moved to `/run/azazel-edge-web` (operator progress,
TopoLite seed mode, dashboard trends, triage sessions),
`/var/log/azazel-edge-web` (authz, runbook, aggregator events, triage audit)
and `/var/lib/azazel-edge-web` (captive allowlist). The triage `/tmp`
fallbacks are gone: triage answers 503 with the reason instead. A trend
store that cannot be written no longer turns `/api/dashboard/*` into a 500;
the trends payload reports `trend_storage_write_failed`. Authz audit write
failures are counted in `/health` (`audit_write_failures`). Token files that
are missing or unreadable are logged (warning / error) and reported
(`command_token_status`; the Mattermost command answers 503 when its token
file is unreadable). `sot-events.jsonl` stays in `/var/log/azazel-edge`,
written by the daemon. `audit_review` defaults to the new triage audit path,
which only root and `azazel-web` can read; another account gets a visible
"error reading audit log" and can pass `--audit-path`. No CLI or offline tool
creates triage sessions or the triage audit (only the Web UI does), so
removing the `/tmp` fallback changes no other caller.

The query socket reads the request within 10 s in total and handles at most
4 queries at once (more are answered `busy`).

**Not changed.** The core, the agent and the control daemon stay root; the
agent's `WorkingDirectory=` is unchanged; the restart runbook is not moved
and, run by `azazel-web`, fails with
`controlled_exec_failed_without_root: …` (HTTP 500). Container state is not
queried any more (`container_check: not_checked` in the monitoring state).
`ProtectHome=yes` hides the legacy OpenCanary pid file under `/home`.

**Upgrade** (`installer/internal/install_migrated_tools.sh`, which calls
`installer/internal/setup_web_account.sh`; both idempotent):

1. the new units are installed; the running Web UI is stopped;
2. system group `azazel-web`, system user `azazel-web` (no login, home
   `/nonexistent`), system group `azazel-control`; `azazel-web` joins
   `azazel-control` only. An existing non-system account with one of these
   names stops the installer;
3. `/etc/default/azazel-edge-security`: `AZAZEL_RUNTIME_SOCKET_GROUP=` (empty)
   → `azazel-control` and `AZAZEL_RUNTIME_DIR_MODE=0770` → `0750` only when
   they hold those old defaults; any other value is kept and reported.
   `AZAZEL_UP_IF` set only for the Web UI is copied there (the daemon now
   brings the uplink down), only if it is a plausible interface name (the
   daemon's own check). A value already in this file wins;
4. `/etc/default/azazel-edge-web`: Web UI path variables and
   `AZAZEL_AI_SOCKET` that still hold an old default move to the new one;
   other values are kept and reported;
5. the Web UI's directories are created and its existing files copied once
   (`captive-allowlist.json`, `authz-events`, `runbook-events`,
   `aggregator-events`, `triage-audit` (+ `.1`), and the `/run` files);
   **the originals are kept** (audit history, rollback);
6. `/etc/azazel-edge` is **never widened**: if others can search it, its mode
   stays; if it is closed to others with group root (0750 root:root), its
   group becomes `azazel-web` (others unchanged); any other group is left and
   reported. The installer scripts no longer reset its mode with `install -d`
   (a missing one is created 0750). Token files the Web UI reads,
   `sot.yaml`/`sot.json` and `first_minute.yaml` (it may hold the ntfy token;
   every other reader is root) become `0640 root:azazel-web`. The local CA and
   server private keys are made 0600 explicitly;
7. restart order: control daemon, agent (query socket), Web UI.

Wazuh FIM reports the ownership and mode changes once; `install_wazuh_agent.sh`
now also watches `/var/log/azazel-edge-web` and `/var/lib/azazel-edge-web`.

**Rollback** (to the previous release):

1. install the previous `azazel-edge-web.service` (no `User=`) and the
   previous code; `systemctl daemon-reload`;
2. in `/etc/default/azazel-edge-security` set
   `AZAZEL_RUNTIME_SOCKET_GROUP=` and `AZAZEL_RUNTIME_DIR_MODE=0770` back if
   wanted (the old code works with either);
3. in `/etc/default/azazel-edge-web` remove `AZAZEL_AI_SOCKET` (the old Web UI
   would otherwise ask the query socket, which the old agent does not have)
   and any path moved in step 4 above;
4. file and directory modes, if wanted: the old code reads them as root, so
   they can stay. To restore the previous state exactly: `chgrp root
   /etc/azazel-edge` (if the installer changed it from root to azazel-web;
   its mode was not changed), `chown root:root` + `chmod 0600` the token
   files (`web_token.txt` was 0640 root:root), and `chown root:root` +
   `chmod 0644` `sot.yaml`/`sot.json`/`first_minute.yaml`;
5. restart the control daemon, the agent and the Web UI.

The old Web UI writes its files in the old places again; entries written in
the new directories meanwhile stay there and are not merged back (copy them
by hand if needed, the triage audit chain included). Token file group
`azazel-web` and the accounts can stay; root reads the files either way.

**Needs the owner's device run** (not shown by the container): the unit's
hardening under real systemd (`systemd-analyze security azazel-edge-web`,
`ps -o user= -C gunicorn`); dashboard, Wi-Fi scan/connect, mode change, SoT
edit, disconnect (status API present and absent), `manual_query` from
`/api/ai/ask` and a Mattermost message and command, ntfy SSE with the token
file, `systemctl is-active` from the sandboxed unit, OpenCanary/Suricata
state without the docker check, and the installer upgrade on a device with
existing state.

## 11. Stage 2 plan: AI agent as `azazel-agent`

### 11.1 Accounts and groups

- `azazel-agent`: system user, no login, no home, primary group `azazel-agent`.
- The agent's directories that the Web UI reads (runtime state, logs) get
  group `azazel-web` with mode 0750, so the Web UI can read but not write
  them. No extra group is needed.
- The agent is **not** added to `azazel-control`: it does not use
  `control.sock`.

### 11.2 Root-needing operations

None move: the agent has no intrinsic root need (§3, §9 run 3). What changes
is ownership:

| Today | Stage 2 |
| --- | --- |
| `mkdir /run/azazel-edge-ai` | `RuntimeDirectory=azazel-edge-ai`, `RuntimeDirectoryMode=0700`. The existing owner/mode checks pass unchanged. |
| `mkdir` + **unconditional `chmod`** of `/run/azazel-edge` | The agent stops writing in the shared directory. Its runtime files move to `/run/azazel-edge-agent/` (`RuntimeDirectory=`, 0750 `azazel-agent:azazel-web`). `_prepare_runtime_dir` no longer chmods a directory it does not own; a wrong mode is an error, not a silent fix. |
| `ai_advisory.json`, `ai_metrics.json` (and `ai_runtime_policy.json`) in `/run/azazel-edge` | Move to `/run/azazel-edge-agent/`. Readers follow: the control daemon's fixed `AI_ADVISORY_PATH` constant changes in code; the Web UI's defaults for `AZAZEL_AI_ADVISORY` and `AZAZEL_AI_METRICS` change in code and, where `/etc/default/azazel-edge-web` holds the old default, the installer rewrites it (#472 pattern). No new variable. |
| `ui_snapshot.json` written by both the daemon and the agent | One writer. Default: the agent writes its fields to `/run/azazel-edge-agent/ai_snapshot.json`; the daemon (the snapshot's owner) merges them when it builds the snapshot. Readers (Web UI, EPD) keep reading the daemon's file. |
| `ui_status_view.json` (written by `fabric_view.write_status_view_alongside` next to the snapshot, read by the Web UI) | Written next to the agent's own snapshot file instead, i.e. `/run/azazel-edge-agent/ui_status_view.json` (`fabric_view` writes beside whatever path it is given). The Web UI's `read_status_view` derives the path from its own snapshot path today (`STATE_PATH` and the fallback, both in `/run/azazel-edge`), so it must change in code to read the agent's directory (a fixed default, no new variable). Only written when `azazel_fabric` is installed. |
| logs in `/var/log/azazel-edge/` (`ai-*.jsonl`, `core-decision-audit.jsonl`, `p0-alert-queue.jsonl`) | `LogsDirectory=azazel-edge/ai` → `/var/log/azazel-edge/ai/`, 0750 `azazel-agent:azazel-web`; defaults of `AZAZEL_AI_AUDIT_LOG`, `AZAZEL_AI_EVENT_LOG`, `AZAZEL_AI_LLM_LOG`, `AZAZEL_AI_DEFERRED_LOG` change (the core-decision audit and P0 queue follow the audit directory). The Web UI and runbook `rb.ops.logs.ai.recent` follow. Only `azazel-agent` can write `core-decision-audit.jsonl` (the #471 goal). |
| decision log in `/opt/azazel-edge/logs/tactics_engine` | `StateDirectory=azazel-edge-agent` → `/var/lib/azazel-edge-agent/decisions`, via the default of `AZAZEL_DECISION_LOG_DIR`. |
| `/tmp/azazel-edge-ai-audit.jsonl` fallback | Removed: if the audit log cannot be opened the agent refuses to start (with `PrivateTmp=` the fallback would vanish anyway). |
| `normalized-events.jsonl` (core, root 0644) | Unchanged in stage 2: readable by all. When stage 3 tightens it, give the agent a read group. |

### 11.3 Query socket after stage 2

The query socket itself is built in stage 1 (§10.4). Stage 2 only changes
ownership:

- the agent now runs as `azazel-agent`, so the query directory and socket are
  owned by `azazel-agent` (group `azazel-web`, modes unchanged), through
  `RuntimeDirectory=` or the agent's own creation with the same refusal
  rules;
- `ai-bridge.sock` and its 0700 directory are owned by `azazel-agent`; the
  core (still root) connects as before. Root can still connect to both;
  that is documented, not solved (#471 does not cover root spoofing);
- after this, only `azazel-agent` can write `core-decision-audit.jsonl` and
  the P0 queue (§11.2).

### 11.4 Unit

As §10.6 with `User=azazel-agent`, `Group=azazel-agent`,
`RuntimeDirectory=azazel-edge-ai azazel-edge-agent azazel-edge-agent-query`
(modes per directory need care: one `RuntimeDirectoryMode=` applies to all,
so either set 0700 and let the agent widen the two shared ones it owns, or
use `tmpfiles.d`; decided at implementation), `LogsDirectory=azazel-edge/ai`,
`StateDirectory=azazel-edge-agent`, `UMask=0027`,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` (Ollama on loopback) and
`AF_NETLINK` (`ip route`), no `SupplementaryGroups=`, empty
`CapabilityBoundingSet=`. `WorkingDirectory=` stays as it is today (owner
decision; the relative policy paths in §3.5 are a separate issue).
The core unit gets `After=`/`Wants=` unchanged.

### 11.5 Installer migration

1. Create `azazel-agent` idempotently.
2. Move existing `ai-*.jsonl`, `core-decision-audit.jsonl(.1)` and
   `p0-alert-queue.jsonl` into `/var/log/azazel-edge/ai/` **together** (the
   chain and the queue's cursors must stay consistent), `chown azazel-agent`.
   Stop the agent before, start after.
3. Move the decision log out of `/opt/azazel-edge/logs/tactics_engine`.
4. Rewrite old default path values in `/etc/default/azazel-edge-security`
   and `/etc/default/azazel-edge-web` only if they equal the old defaults
   (#472 pattern).
5. Order: control daemon (reads the new advisory path) → agent → web → core.

### 11.6 Verification (stage 2)

- Unit tests: the stage-1 query socket tests (§10.8) still pass with the
  agent as `azazel-agent`; runtime directory chmod no longer happens; single
  snapshot writer; migration keeps the audit chain verifiable and the P0
  cursors.
- SO-03 re-measured (the core → agent path changes ownership); SO-04 is
  unaffected until stage 3, but rerun.
- Container: the §9 run 3 shape with the real unit layout and the Web UI as
  `azazel-web` asking through the query socket. Labelled as container.
- Device (owner): P0 relay still arrives, `manual_query` from the Web UI and
  Mattermost works, `systemd-analyze security azazel-edge-ai-agent`.

### 11.7 Stage 2 as implemented

What the stage 2 change does, where it differs from §11.1–11.6, and how to
upgrade and roll back. Container results are container results; nothing
here is device evidence.

**Differences from the plan above**

| Plan | Implemented | Why |
| --- | --- | --- |
| `RuntimeDirectory=azazel-edge-ai azazel-edge-agent azazel-edge-agent-query`, `LogsDirectory=azazel-edge/ai` | `RuntimeDirectory=azazel-edge-ai` (0700) and `StateDirectory=azazel-edge-agent` only. `/run/azazel-edge-agent`, `/run/azazel-edge-agent-query` and `/var/log/azazel-edge/ai` come from tmpfiles.d (`/etc/tmpfiles.d/azazel-edge-agent.conf`, **2750 azazel-agent:azazel-web**), re-applied by `ExecStartPre=+systemd-tmpfiles --create …` and made writable with `ReadWritePaths=` | systemd gives `RuntimeDirectory=`/`LogsDirectory=` the unit's `Group=` (and resets a different group on start), so group `azazel-web` cannot come from them; the agent itself cannot chgrp to a group it is not in. Setgid makes what the agent writes (umask 0027) group-readable by the Web UI only |
| the agent's snapshot file `/run/azazel-edge-agent/ai_snapshot.json` | the same, derived from the advisory's directory (`AZAZEL_AI_ADVISORY`), no new variable. The daemon's advisory path reads the same variable with the new default | `AZAZEL_UI_SNAPSHOT` already names the shared snapshot for the daemon, the Web UI and dev hosts; the agent no longer uses it |
| query directory 0750 | 0750 (created by the agent as root, stage 1) **or 2750** (tmpfiles.d, stage 2); anything else is refused, never fixed | as above |
| move the chain and the P0 queue together | moved together, **and the relay's reconcile cursor is carried** (`azazel_edge.notify.migrate_audit_path`) | the relay scopes its cursor by the audit file's path; a moved file would otherwise be a `fresh_chain` and P0 records no longer in the queue (evicted) would be alerted again as past decisions |

**Directories and files** (all owned by `azazel-agent`)

| Path | Mode | Holds |
| --- | --- | --- |
| `/run/azazel-edge-ai` | 0700 (RuntimeDirectory=) | `ai-bridge.sock` 0600. The core (root) still connects |
| `/run/azazel-edge-agent-query` | 2750, group azazel-web | `agent-query.sock` 0660 (stage 1 peer checks unchanged) |
| `/run/azazel-edge-agent` | 2750, group azazel-web | `ai_advisory.json`, `ai_metrics.json`, `ai_runtime_policy.json`, `ai_snapshot.json` (the agent's snapshot fields), `ui_status_view.json` |
| `/var/log/azazel-edge/ai` | 2750, group azazel-web | `ai-events`, `ai-llm`, `ai-deferred`, `ai-audit` (`.jsonl`), `core-decision-audit.jsonl` (+ `.1`), `p0-alert-queue.jsonl` (0600) |
| `/var/lib/azazel-edge-agent` | 0750 (StateDirectory=) | `decisions/decision_explanations.jsonl` |

Only `azazel-agent` (and root) can write the core-decision audit chain and the
P0 queue. The agent still reads `normalized-events.jsonl` (root, 0644 in the
0755 `/var/log/azazel-edge`), unchanged.

**Code changes**

- The agent creates a missing runtime directory 0750 and uses an existing one
  only if it is a real directory owned by its uid that nobody else can write;
  it never chmods or chowns it and does not touch `/run/azazel-edge`. A wrong
  one stops the service with the reason. The AI audit log has no `/tmp`
  fallback: if it cannot be opened, the service stops.
- One snapshot writer: the agent writes its fields to its own
  `ai_snapshot.json`; the control daemon reads it (no symlink, without
  blocking, a regular file of at most 1 MiB) and merges a fixed key list,
  each key only with its expected type and size (others are dropped, logged
  and counted) (`AGENT_SNAPSHOT_KEYS`: advisory epoch, user
  state, recommendation, reasons, evidence, Suricata and deferred counts,
  LLM / ops coach / decision pipeline / second pass / LLM metrics, internal,
  attack, and `monitoring.suricata`) before it enriches and persists the
  shared `ui_snapshot.json`. Route, connection, health, mode and the rest stay
  the daemon's. After an upgrade the agent's counts start from its own (new)
  file; `/run` is cleared at boot anyway.
- Readers: the daemon's advisory path (`AZAZEL_AI_ADVISORY`, new default); the
  Web UI's `AZAZEL_AI_ADVISORY`, `AZAZEL_AI_METRICS`, `AZAZEL_AI_EVENT_LOG`,
  `AZAZEL_AI_LLM_LOG` defaults and `read_status_view` (beside the advisory);
  runbook `rb.ops.logs.ai.recent`; `DecisionLogger`'s default.
- The runbook loader logs and skips a runbook directory it cannot search
  (the agent cannot search `/etc/azazel-edge` when it is 0750
  root:azazel-web; the shipped runbooks in `/opt/azazel-edge/runbooks` load).
- The agent sends no notification itself (no ntfy, Mattermost, audio or EPD
  access); the P0 relay only writes the queue. No token or device access was
  needed.

**Upgrade** (`install_migrated_tools.sh` → `setup_agent_account.sh`, idempotent,
after `setup_web_account.sh`):

1. the new unit and `/etc/tmpfiles.d/azazel-edge-agent.conf` are installed;
   the running agent is stopped;
2. system group and user `azazel-agent` (no login, home `/nonexistent`, no
   other group); an existing non-system account with the name stops the
   installer; the `azazel-web` group must exist (stage 1);
3. the directories above are created;
4. `core-decision-audit.jsonl` (+ `.1`, `.fabric.jsonl`) and
   `p0-alert-queue.jsonl` move **as one set** to `/var/log/azazel-edge/ai`
   (`migrate_audit_path.migrate_chain`: link + unlink, so nothing at the new
   place is ever replaced), and the relay's cursor is carried. Running it
   again after a crash finishes a partial move and carries the cursor. It
   moves nothing, prints a NOTICE with the manual steps and leaves both
   places untouched when a name exists in both places, when a file of the set
   is not a regular file, or when `AZAZEL_AI_AUDIT_LOG` is set to a custom
   path (the agent keeps its chain beside that file). When the two
   directories are on different filesystems (`link` fails with EXDEV) it
   stops before that file (state `cross_filesystem`, exit 2; nothing copied,
   unlinked or carried) and the NOTICE gives the manual steps: copy with
   `cp -p -n`, compare, only then delete the originals, run the script again
   (#477; before, an unhandled traceback). Each AI log moves only
   when its variable is unset or holds a default;
5. the decision log and the current `/run/azazel-edge/ai_*.json` are copied
   (originals kept; never through or over an existing name or symlink);
6. old default values of `AZAZEL_AI_ADVISORY`, `AZAZEL_AI_METRICS`,
   `AZAZEL_AI_POLICY`, `AZAZEL_AI_*_LOG` and `AZAZEL_DECISION_LOG_DIR` in
   `/etc/default/azazel-edge-security` and `/etc/default/azazel-edge-web` move
   to the new defaults; other values are kept and reported (an agent pointed
   at a directory it cannot own stops with the reason);
7. restart order: control daemon → agent → Web UI (the core is not restarted;
   it connects per event).

Wazuh FIM: `/var/log/azazel-edge` (which contains `ai/`) was already watched;
`/var/lib/azazel-edge-agent` is added.

**Rollback** (to the stage 1 release):

1. stop the agent; install the stage 1 `azazel-edge-ai-agent.service` (no
   `User=`) and code; `systemctl daemon-reload`;
2. move `core-decision-audit.jsonl` (+ `.1`), `p0-alert-queue.jsonl` and the
   `ai-*.jsonl` logs from `/var/log/azazel-edge/ai` back to
   `/var/log/azazel-edge` together (the queue keeps the stage 2 cursor rows;
   the old relay finds its old path's cursor, written before the upgrade, and
   resumes with `cursor_found` or, if the queue evicted it, reconciles as
   before);
3. in `/etc/default/azazel-edge-security` and `/etc/default/azazel-edge-web`
   put back or remove the moved path variables (the old defaults are the old
   code's defaults);
4. restart the control daemon, the agent, the Web UI. The account, the
   tmpfiles.d file and the empty new directories can stay.

**Needs the owner's device run**: the unit under real systemd
(`systemd-analyze security azazel-edge-ai-agent`, `ps -o user= -C python3`),
tmpfiles at boot, the P0 relay from the real core, `manual_query` from the
Web UI and Mattermost, Ollama on loopback, the upgrade of a device with an
existing chain and queue (cursor carried, no replay) and the rollback. SO-03
is re-measured in CI (container, not hardware).

## 12. Open questions

Decided by the owner (see the list at the start of §10): disconnect as a
fixed parameterless daemon action, SoT edits as fixed validated daemon
actions, `docker ps` removed, the restart runbook kept and failing visibly,
the `control.sock` per-uid table with `migrate_path_schema` root-only, the
query socket in stage 1, the agent's `WorkingDirectory=` unchanged, and the
out-of-scope findings tracked separately. Still open:

1. **Port 8082.** Who serves the status API on a device? It decides how
   often the Web UI reaches `uplink_disconnect` instead of the status API.
2. **`migrate_path_schema` on the socket.** It becomes root-only; should it
   leave the socket entirely (a root CLI only)?
3. **`/etc/azazel-edge` mode.** 0755 with per-file modes (default) or keep
   0750 with a group?
4. **`ProtectHome=`.** `yes` (default) hides the legacy OpenCanary venv pid
   file; are there devices that need `read-only`?
5. **Snapshot ownership.** Agent-side file merged by the daemon (default) or
   another split?
6. **`decision-explanations.jsonl`.** The Web UI reads it from
   `/var/log/azazel-edge`, the agent writes elsewhere. Which is intended?
7. **Out-of-scope findings, tracked separately** (not fixed by #471 stages
   0–2):
   - `control.sock` has no peer check today (stage 1 adds one);
   - the Wi-Fi passphrase is passed on nmcli's argv (fixed by #477);
   - `contain`/`disconnect` on `control.sock` only write a log line;
   - the netflow and snmp units use `User=azazel`, which no installer creates,
     and `${VAR:-default}` in `ExecStart`;
   - selftest's fixed `/tmp` file written by `dd` as root (fixed by #477),
     and its pytest step against a directory that is not installed;
   - the core's apply path inherits `PATH`/environment while the release path
     does not; no installer step creates `table inet azazel_edge`;
   - the core's redirect policy default is relative with no
     `WorkingDirectory=`;
   - the agent's SOC policy and ATT&CK mapping paths are relative to `/`
     (§3.5);
   - `azazel-edge-portal-viewer.service` is started by the daemon but not
     shipped;
   - OpenCanary SSH listens on 12222 while the core's honeypot redirect
     default is 2222;
   - the Ollama compose file publishes 11434 on all interfaces.
8. **Hardware.** None of §9 is device evidence. Stage 1 and 2 still need a
   device run by the owner before they are called done; stage 3 needs the
   `CAP_NET_ADMIN`-only core run that #471 describes.
