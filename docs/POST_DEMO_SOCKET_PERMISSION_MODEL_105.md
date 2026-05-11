# Post-Demo Socket Permission Model (#105)

Last updated: 2026-05-11

## Scope

This document defines the post-demo permission model for Unix sockets under `/run/azazel-edge`.

Targets:
- `control.sock` (control daemon command socket)
- `ai-bridge.sock` (AI advisory ingest/query socket)

## Caller Matrix

Socket | Primary callers | Notes
---|---|---
`/run/azazel-edge/control.sock` | Web UI process, local CLI/helpers | Used for operator actions and runtime status calls
`/run/azazel-edge/ai-bridge.sock` | Rust core, local helper (`azazel-edge-inject-test-events`) | Used for normalized event forwarding and manual query path

## Runtime Permission Policy

Configured via environment variables:

- `AZAZEL_RUNTIME_DIR_MODE` (default: `0770`)
- `AZAZEL_CONTROL_SOCKET_MODE` (default: `0660`)
- `AZAZEL_AI_SOCKET_MODE` (default: `0660`)
- `AZAZEL_RUNTIME_SOCKET_GROUP` (default: empty, optional)

Behavior:
- Runtime directory is created with `AZAZEL_RUNTIME_DIR_MODE`.
- Each socket is created with its respective socket mode.
- If `AZAZEL_RUNTIME_SOCKET_GROUP` is configured and exists, runtime dir/socket group ownership is aligned to that group.

## Managed Defaults

Installer-managed runtime (`install_migrated_tools.sh`) seeds:

- `/etc/default/azazel-edge-security`
  - `AZAZEL_RUNTIME_DIR_MODE=0770`
  - `AZAZEL_CONTROL_SOCKET_MODE=0660`
  - `AZAZEL_AI_SOCKET_MODE=0660`
  - `AZAZEL_RUNTIME_SOCKET_GROUP=`

Systemd units consume this file:
- `azazel-edge-control-daemon.service`
- `azazel-edge-ai-agent.service`
- `azazel-edge-core.service`

## Validation Checklist

1. Confirm runtime env values:
   - `grep -E 'AZAZEL_RUNTIME_DIR_MODE|AZAZEL_CONTROL_SOCKET_MODE|AZAZEL_AI_SOCKET_MODE|AZAZEL_RUNTIME_SOCKET_GROUP' /etc/default/azazel-edge-security`
2. Confirm socket modes:
   - `stat -c '%a %n' /run/azazel-edge /run/azazel-edge/control.sock /run/azazel-edge/ai-bridge.sock`
3. Confirm service health:
   - `systemctl status azazel-edge-control-daemon azazel-edge-ai-agent azazel-edge-core`
4. Confirm end-to-end paths:
   - Web API control path works (`/api/action`, `/api/mode`)
   - Demo/event forwarding path works (`/api/demo/*`, core -> ai-bridge forwarding)

## Compatibility Note

If a deployment still requires broader local access temporarily, adjust only the environment values in `/etc/default/azazel-edge-security` and document the reason in change logs.
