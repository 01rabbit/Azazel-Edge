# Operator Guide

## Purpose
Primary field operation guide for non-expert shelter staff and volunteers.

## 1. Quick Start (15 minutes)
1. Connect power, LAN, and display cables.
2. Boot the device and wait for services.
3. Verify:
   - `systemctl is-active azazel-edge-web`
   - `systemctl is-active azazel-edge-control-daemon`
4. Open dashboard from a local-network browser at `http://<pi-ip>:8080`.
5. Confirm posture color and recommended first action.

## 2. e-Paper State and Immediate Action
- GREEN: Continue monitoring and periodic checks.
- YELLOW: Run initial checks and keep system state stable.
- RED: Treat as active incident, escalate, and use reviewed runbooks.

## 3. FAQ (Field)
- Q: Wi-Fi does not connect.
  A: First isolate whether it is one device or many devices, then follow runbook candidates.
- Q: The status turned red.
  A: Confirm current recommendation and execute one approved step at a time.
- Q: How do we reboot safely?
  A: Check logs and execute only approved reboot procedure.

## 4. Emergency Contact Sheet
| Role | Name | Contact |
|------|------|---------|
| Shift lead | | |
| Network support | | |
| Escalation | | |

## 5. Equipment Checklist
- Raspberry Pi unit
- SD card
- Power adapter
- LAN cable
- e-Paper display

## 6. Japanese Version
For full Japanese wording, see `docs/OPERATOR_GUIDE_JA.md`.

## 7. Escalation Decision Tree

```text
GREEN  -> monitor -> continue normal checklist
YELLOW -> check dashboard -> follow reviewed runbook if needed
RED    -> escalate immediately -> run approved runbook only
```

Principle:
- Do not perform destructive or unapproved actions outside reviewed runbooks.

## 8. Common Error Messages

- `auth_failed`:
  token missing/invalid. Confirm token source and retry.
- `control_socket_unavailable`:
  control daemon unavailable. Check service state and socket path.
- `aggregator_registry_unavailable`:
  aggregator store unavailable. Continue local deterministic operations.
- `runbook_not_found`:
  runbook ID mismatch. Refresh list and confirm current runbook catalog.
