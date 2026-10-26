# Post-Demo Socket Permission Model (#105)

Last updated: 2026-10-26

## Scope

This document defines the post-demo permission model for the Unix sockets under `/run/azazel-edge` and `/run/azazel-edge-ai`.

Targets:
- `control.sock` (control daemon command socket)
- `ai-bridge.sock` (AI advisory ingest/query socket)

## Caller Matrix

Socket | Primary callers | Notes
---|---|---
`/run/azazel-edge/control.sock` | Web UI process, local CLI/helpers (root, or members of `AZAZEL_RUNTIME_SOCKET_GROUP`) | Used for operator actions and runtime status calls
`/run/azazel-edge-ai/ai-bridge.sock` | Rust core (`azazel-edge-core`, root) | Normalized event forwarding (test events enter upstream via `azazel-edge-injector` / `dummy-eve` -> `eve.json` -> Rust core)
`/run/azazel-edge-ai/ai-bridge.sock` | Web UI (`azazel_edge_web/app.py`, `_send_ai_manual_query`, root) | `action=manual_query` (operator questions to the AI assist)

The core, the AI agent and the Web UI units have no `User=`/`Group=`: all three
run as root, and the agent's socket is reached as root. Before Edge#462 the
socket was `/run/azazel-edge/ai-bridge.sock`; the core unit, the core, the
Web UI and the agent now default to `/run/azazel-edge-ai/ai-bridge.sock`.

## Runtime Permission Policy

Configured via environment variables:

- `AZAZEL_RUNTIME_DIR_MODE` (default: `0770`)
- `AZAZEL_CONTROL_SOCKET_MODE` (default: `0660`)
- `AZAZEL_RUNTIME_SOCKET_GROUP` (default: empty, optional)

Behavior:
- The runtime directory `/run/azazel-edge` is created with
  `AZAZEL_RUNTIME_DIR_MODE` (by the control daemon and by the AI agent, with the
  same value; the agent keeps its state files such as `ai_advisory.json` there).
- `control.sock` is created with `AZAZEL_CONTROL_SOCKET_MODE`.
- If `AZAZEL_RUNTIME_SOCKET_GROUP` is configured and exists, the control daemon
  sets that group on the runtime directory and on `control.sock`. Members of the
  group can still use `control.sock`; that is what the group is for. The
  directory has no sticky bit, so members can also rename or remove entries in
  it; that is why `ai-bridge.sock` no longer lives there.
- `ai-bridge.sock` (Edge#462) lives in its own directory, `/run/azazel-edge-ai`,
  which the agent creates with mode `0700`, owned by the agent's account
  (root under the shipped units). The socket is mode `0600` with the agent's own
  user and group, bound under umask `0177`. `AZAZEL_RUNTIME_SOCKET_GROUP` is not
  applied to either, and the agent never changes the shared runtime directory's
  group.
- The agent refuses to start (exits with an error naming the path; no fallback)
  when the socket's directory is a symlink, is not a directory, is owned by
  another account, or has any group/other permission bit, and when the socket
  path holds anything other than a socket (a stale socket is replaced). It
  changes nothing through a path it has not checked. So pointing
  `AZAZEL_AI_SOCKET` back into `/run/azazel-edge` (0770) makes the agent refuse
  rather than share the socket.
- `AZAZEL_AI_SOCKET_MODE` is no longer applied; an existing value is ignored
  with a warning in the agent log. No setting makes the socket or its directory
  group- or world-accessible. `AZAZEL_AI_SOCKET` still chooses the path, but
  only a private directory is accepted.
- Who can connect to, rename, remove or replace `ai-bridge.sock` after this
  change: root, and processes running as the agent's account (root under the
  shipped units). Members of `AZAZEL_RUNTIME_SOCKET_GROUP` cannot.
- This is not privilege separation. Every root process can still connect and
  forge core events or manual queries, or replace the socket. Neither the core
  nor the Web UI checks the peer of the socket it connects to (tracked in
  Edge#471); separating the core and the Web UI into their own accounts, or
  authenticating the socket traffic, is tracked separately in Edge#462.
- Checked by the tests (macOS, and a Linux container as root and as a normal
  user); not validated on a VM or on hardware.

## Managed Defaults

Installer-managed runtime (`install_migrated_tools.sh`) seeds:

- `/etc/default/azazel-edge-security`
  - `AZAZEL_RUNTIME_DIR_MODE=0770`
  - `AZAZEL_CONTROL_SOCKET_MODE=0660`
  - `AZAZEL_RUNTIME_SOCKET_GROUP=`

Earlier installs also seeded `AZAZEL_AI_SOCKET_MODE=0660`. The line is left in
place on upgrade and has no effect.

On upgrade the installer also rewrites a line
`AZAZEL_AI_SOCKET=/run/azazel-edge/ai-bridge.sock` (the old default, optionally
quoted) in `/etc/default/azazel-edge-security` and `/etc/default/azazel-edge-web`
to `/run/azazel-edge-ai/ai-bridge.sock`. Any other value is left as it is.
These files override the units' `Environment=`, so a value that still points
into `/run/azazel-edge` (e.g. written somewhere the installer does not manage)
makes the agent refuse to start, and the core and the Web UI would not reach
it.

Systemd units consume this file:
- `azazel-edge-control-daemon.service`
- `azazel-edge-ai-agent.service`
- `azazel-edge-core.service`

## Validation Checklist

1. Confirm runtime env values:
   - `grep -E 'AZAZEL_RUNTIME_DIR_MODE|AZAZEL_CONTROL_SOCKET_MODE|AZAZEL_RUNTIME_SOCKET_GROUP' /etc/default/azazel-edge-security`
2. Confirm socket modes and groups:
   - `stat -c '%a %U:%G %F %n' /run/azazel-edge /run/azazel-edge/control.sock /run/azazel-edge-ai /run/azazel-edge-ai/ai-bridge.sock`
   - Expected: `/run/azazel-edge-ai` is `700` and `ai-bridge.sock` is `600`, both
     owned by the agent's account (root:root); `/run/azazel-edge` and
     `control.sock` carry the shared group when it is set.
   - `grep -rh '^AZAZEL_AI_SOCKET=' /etc/default/azazel-edge-*` shows nothing
     or the new path.
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

`ai-bridge.sock` cannot be made group- or world-accessible by configuration.
A deployment that set `AZAZEL_RUNTIME_SOCKET_GROUP` and had a non-root tool
connect to `ai-bridge.sock` through that group loses that access; such a tool
has to run as root (as the core and the Web UI do) until the separation tracked
in Edge#462 exists. Tools or scripts that hard-code the old path
`/run/azazel-edge/ai-bridge.sock` must use `/run/azazel-edge-ai/ai-bridge.sock`.
