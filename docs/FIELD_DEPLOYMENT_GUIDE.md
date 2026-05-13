# Field Deployment Guide

Last updated: 2026-05-13

Stage-based checklist for emergency deployment with deterministic safety
controls. Each item includes expected outcome and fallback note.

---

## Stage 1 - Pre-deployment (before transport)

- [ ] Boot device and confirm baseline selftest and current test baseline.
  Expected: local health check completes without critical failure.
  If something goes wrong: stop and replace boot media before shipment.

- [ ] Check runtime services:
  `systemctl is-active azazel-edge-web azazel-edge-control-daemon azazel-edge-suricata azazel-edge-opencanary`
  Expected: all required services are `active`.
  If something goes wrong: restart failed unit and collect journal logs.

- [ ] Confirm e-Paper displays GREEN.
  Expected: posture is readable and stable.
  If something goes wrong: verify EPD service and cable seating.

- [ ] Confirm token material exists:
  `ls /etc/azazel-edge/secrets/tokens/`
  Expected: token files are present.
  If something goes wrong: restore from secure backup.

- [ ] Confirm encrypted secrets mount:
  `ls /dev/mapper/azazel-secrets`
  Expected: mapper device exists.
  If something goes wrong: unlock and mount encrypted volume before transport.

- [ ] Run SD/media selftest:
  `sudo bin/azazel-edge-selftest`
  Expected: no media integrity critical alert.
  If something goes wrong: replace media and re-image.

- [ ] Pack hardware set (Pi, enclosure, power, UPS, LAN, EPD cable, STATUS_CARD).
  Expected: complete deployment kit is ready.
  If something goes wrong: do not deploy incomplete set.

---

## Stage 2 - Transit

- [ ] Secure Pi in padded case, no loose internal movement.
  Expected: no connector stress during movement.
  If something goes wrong: repack before departure.

- [ ] Keep primary power disconnected until on-site unless UPS is validated.
  Expected: controlled startup at destination.
  If something goes wrong: force cold restart and run quick health check.

- [ ] Avoid direct sunlight >40C inside vehicle/storage.
  Expected: no thermal pre-stress.
  If something goes wrong: cool unit before power-on.

---

## Stage 3 - On-site setup (target <15 minutes)

- [ ] Connect power and verify LED/activity.
  Expected: boot starts immediately.
  If something goes wrong: inspect converter/output rail.

- [ ] Connect WAN uplink (LAN or router path).
  Expected: uplink path is detected.
  If something goes wrong: verify gateway and cable path.

- [ ] Connect LAN switch or AP for local segment.
  Expected: local clients can join segment.
  If something goes wrong: check bridge config and AP state.

- [ ] Wait 60 seconds for service convergence.
  Expected: core services active.
  If something goes wrong: inspect `journalctl -u azazel-edge-*`.

- [ ] Verify e-Paper shows GREEN or YELLOW.
  Expected: YELLOW is acceptable for degraded uplink.
  If something goes wrong: proceed to controlled diagnostics.

- [ ] Open dashboard `http://<pi-ip>:8080`.
  Expected: posture and action guidance visible.
  If something goes wrong: test local bind and token policy.

- [ ] Post STATUS_CARD in visible operator location.
  Expected: disclosure and quick action guidance available.
  If something goes wrong: print local fallback copy.

---

## Stage 4 - Operation

- [ ] Check e-Paper state each shift handover.
  Expected: posture transitions are noticed early.
  If something goes wrong: verify update timer and service freshness.

- [ ] On YELLOW, review dashboard recommendation and runbook prompt.
  Expected: bounded corrective action.
  If something goes wrong: escalate to operator mode.

- [ ] On RED, escalate immediately and execute approved runbook only.
  Expected: controlled high-risk response.
  If something goes wrong: suspend ad-hoc actions and preserve audit trail.

- [ ] At handover, review `/api/handoff/summary`.
  Expected: next shift gets concise state/risk/actions context.
  If something goes wrong: export snapshot manually from dashboard.

---

## Stage 5 - Shutdown and recovery

- [ ] Archive logs:
  `sudo tar czf /tmp/azazel-audit-$(date +%Y%m%d).tar.gz /var/log/azazel-edge/`
  Expected: audit archive created.
  If something goes wrong: verify storage path and permissions.

- [ ] Transfer archive to USB or secure base host.
  Expected: evidence preserved off-device.
  If something goes wrong: retry via alternate transfer path.

- [ ] Stop core services:
  `sudo systemctl stop azazel-edge-web azazel-edge-control-daemon`
  Expected: clean service stop.
  If something goes wrong: capture unit status before shutdown.

- [ ] Sync and power off:
  `sudo sync && sudo shutdown -h now`
  Expected: filesystem clean shutdown.
  If something goes wrong: do not remove power immediately.

- [ ] After power-off, disconnect cables and secure transport case.
  Expected: safe return state.
  If something goes wrong: re-check enclosure and connectors.

---

## Supplementary (日本語)

- 事前準備: サービス・暗号化シークレット・自己診断を確認してから搬送します。
- 現地設置: 15分以内の立上げを目標に、GREEN/YELLOWの表示確認を優先します。
- 運用中: RED時は承認済み手順のみ実行し、引継ぎ時は要約を必ず確認します。
- 終了時: 監査ログを退避してから安全停止し、搬送状態に戻します。
