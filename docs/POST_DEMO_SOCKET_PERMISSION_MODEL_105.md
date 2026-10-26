# Post-Demo Socket Permission Model (#105)

Last updated: 2026-10-26

## Scope

This document defines the post-demo permission model for Unix sockets under `/run/azazel-edge`.

Targets:
- `control.sock` (control daemon command socket)
- `ai-bridge.sock` (AI advisory ingest/query socket)

## Caller Matrix

Socket | Primary callers | Notes
---|---|---
`/run/azazel-edge/control.sock` | Web UI process, local CLI/helpers (root, or members of `AZAZEL_RUNTIME_SOCKET_GROUP`) | Used for operator actions and runtime status calls
`/run/azazel-edge/ai-bridge.sock` | Rust core (`azazel-edge-core`, root) | Normalized event forwarding (test events enter upstream via `azazel-edge-injector` / `dummy-eve` -> `eve.json` -> Rust core)
`/run/azazel-edge/ai-bridge.sock` | Web UI (`azazel_edge_web/app.py`, `_send_ai_manual_query`, root) | `action=manual_query` (operator questions to the AI assist)

The core, the AI agent and the Web UI units have no `User=`/`Group=`: all three
run as root, and the agent's socket is reached as root.

## Runtime Permission Policy

Configured via environment variables:

- `AZAZEL_RUNTIME_DIR_MODE` (default: `0770`)
- `AZAZEL_CONTROL_SOCKET_MODE` (default: `0660`)
- `AZAZEL_RUNTIME_SOCKET_GROUP` (default: empty, optional)

Behavior:
- Runtime directory is created with `AZAZEL_RUNTIME_DIR_MODE` (by the control
  daemon and by the AI agent, with the same value).
- `control.sock` is created with `AZAZEL_CONTROL_SOCKET_MODE`.
- If `AZAZEL_RUNTIME_SOCKET_GROUP` is configured and exists, the control daemon
  sets that group on the runtime directory and on `control.sock`. Members of the
  group can still use `control.sock`; that is what the group is for.
- `ai-bridge.sock` is owner only (Edge#462): mode `0600`, owned by the agent's own
  user and group (root:root under the shipped units). It is **not** affected by
  `AZAZEL_RUNTIME_SOCKET_GROUP`, and the agent never changes the runtime
  directory's group. A member of the shared group cannot connect to it, so it
  cannot forge core events or manual queries. `AZAZEL_AI_SOCKET_MODE` is no
  longer applied; an existing value is ignored with a warning in the agent log.
  There is no setting that widens this socket.
- This is not privilege separation: every process running as root (or as the
  agent's account) can still connect. Separating the core and the Web UI into
  their own accounts, or authenticating the socket traffic, is tracked
  separately in Edge#462.

## Managed Defaults

Installer-managed runtime (`install_migrated_tools.sh`) seeds:

- `/etc/default/azazel-edge-security`
  - `AZAZEL_RUNTIME_DIR_MODE=0770`
  - `AZAZEL_CONTROL_SOCKET_MODE=0660`
  - `AZAZEL_RUNTIME_SOCKET_GROUP=`

Earlier installs also seeded `AZAZEL_AI_SOCKET_MODE=0660`. The line is left in
place on upgrade and has no effect.

Systemd units consume this file:
- `azazel-edge-control-daemon.service`
- `azazel-edge-ai-agent.service`
- `azazel-edge-core.service`

## Validation Checklist

1. Confirm runtime env values:
   - `grep -E 'AZAZEL_RUNTIME_DIR_MODE|AZAZEL_CONTROL_SOCKET_MODE|AZAZEL_RUNTIME_SOCKET_GROUP' /etc/default/azazel-edge-security`
2. Confirm socket modes and groups:
   - `stat -c '%a %U:%G %n' /run/azazel-edge /run/azazel-edge/control.sock /run/azazel-edge/ai-bridge.sock`
   - Expected: `ai-bridge.sock` is `600` and owned by the agent's account (root:root);
     the directory and `control.sock` carry the shared group when it is set.
3. Confirm service health:
   - `systemctl status azazel-edge-control-daemon azazel-edge-ai-agent azazel-edge-core`
4. Confirm end-to-end paths:
   - Web API control path works (`/api/action`, `/api/mode`)
   - Web UI manual query works (`action=manual_query` to ai-bridge)
   - Event forwarding path works (core -> ai-bridge forwarding); this can be
     exercised live with `bin/azazel-edge-dummy-eve flow` or offline with
     `bin/azazel-edge-scenario-replay run mixed_correlation_demo`

## Compatibility Note

If a deployment still requires broader local access to `control.sock` temporarily, adjust only the environment values in `/etc/default/azazel-edge-security` and document the reason in change logs.

`ai-bridge.sock` cannot be widened by configuration. A deployment that set
`AZAZEL_RUNTIME_SOCKET_GROUP` and had a non-root tool connect to `ai-bridge.sock`
through that group loses that access; such a tool has to run as root (as the
core and the Web UI do) until the separation tracked in Edge#462 exists.
