# Power Playbook

Last updated: 2026-05-13

This document provides power sizing, runtime planning, and shutdown policy for
Azazel-Edge deployments on Raspberry Pi platforms.

---

## 1. Baseline Power Consumption

Measured reference profiles:
- Normal operation (Pi 5, Suricata active, no Ollama): 13W
- With Ollama (2b model, active inference): up to 25W
- Full stack (Pi 5 + all services + e-Paper + SSD): up to 35W
- Idle / low activity standby: approximately 8W

Operational note:
- Always size for peak and transient load, not only average draw.
- For emergency operations, keep at least 20% reserve capacity.

---

## 2. Runtime Estimates

| Configuration | Capacity | Runtime @13W | Runtime @35W | Notes |
|---|---|---|---|---|
| 20Ah USB-C power bank | 72Wh usable (80% efficiency) | ~5.5h | ~2h | Use PD-capable bank (20W+) |
| 105D31R lead-acid x2 (24V) | 864Wh @50% DoD | ~66h | ~24h | Requires isolated 24V->5V converter |
| 105D31R x2 + 100Ah sub x2 | 2,664Wh | ~204h | ~76h | Suitable for multi-day operation |
| 10kVA generator | unlimited | unlimited | unlimited | Standard shelter generator path |
| 50W solar + 20Ah battery | self-sustaining >6h/day sun | indefinite | limited | Add MPPT charge controller |
| PoE+ (802.3at, 30W budget) | limited by switch UPS | up to 30W | up to 30W | Use Pi PoE+ HAT or CM4 PoE carrier |

---

## 3. Recommended Configurations by Scenario

### Emergency shelter (24h deployment)
Recommended:
- 105D31R x2 (24V path) or generator feed
- Isolated converter + surge protection

### Urban shelter (grid available)
Recommended:
- PoE+ from UPS-backed switch
- Keep local battery fallback for short transfer windows

### Field / NGO deployment
Recommended:
- 50W solar + 20Ah battery
- Duty-cycle high-load AI tasks to conserve power

### Vehicle deployment (1.5t truck)
Recommended:
- 24V vehicle battery via isolated DC-DC converter
- Transit mode profile while moving

---

## 4. Graceful Shutdown Hook

Use controlled shutdown before battery depletion to prevent corruption.

```bash
# Trigger controlled shutdown when UPS battery reaches critical level
# Add to UPS HAT config or GPIO trigger:
sudo systemctl stop azazel-edge-web azazel-edge-control-daemon
sudo sync
sudo shutdown -h now
```

Operational baseline:
- Trigger shutdown at or above the low-battery threshold, not at 0%.
- Validate automatic restart behavior after power recovery.

---

## 5. UPS HAT Wiring Note

For PiSugar 3 Pro (or equivalent):
- Set low-battery shutdown threshold to 10%
- Set safe-shutdown GPIO to BCM pin 4 (or platform-equivalent mapping)
- Verify shutdown hook is executed exactly once per low-battery event

Deployment checklist:
- Confirm HAT firmware and battery calibration
- Confirm status telemetry is visible to operator
- Confirm safe shutdown log entry appears after test trigger

---

## 6. Operational Safeguards

- Do not run sustained high-load inference on minimal battery packs.
- During RED incident posture, preserve networking and control-plane services
  over non-essential compute tasks.
- Keep spare power cabling and a known-good converter in field kit.

---

## Supplementary (日本語)

### 早見表
- 13W運用時: 小型電源でも数時間、24Vバッテリ系で長時間運用が可能です。
- 35Wピーク時: 稼働時間は大きく短縮されるため、ピーク前提で容量設計してください。

### 注意点
- 低電圧での強制停止は破損リスクが高いため、必ず安全停止を優先します。
- 車載・屋外運用では、変換器の品質と保護回路（ヒューズ/サージ対策）が必須です。
