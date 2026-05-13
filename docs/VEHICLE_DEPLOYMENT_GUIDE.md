# Vehicle Deployment Guide

Last updated: 2026-05-13

This guide defines a practical deployment baseline for Azazel-Edge in vehicle
or high-vibration environments. The focus is resilient power delivery,
transport-mode safe operation, and predictable thermal behavior.

---

## 1. Power Wiring (24V Vehicle)

### 1.1 Converter requirements
Use an isolated DC-DC converter with:
- Input: 18-32V DC
- Output: 5.1V, 5A minimum continuous

Recommended part class:
- Meanwell DDR-60D or equivalent DIN-rail isolated converter

### 1.2 Protection baseline
Apply the following protections in series with vehicle feed:
- 10A blade fuse on positive input lead
- 60V / 600W TVS diode across input rails for transient suppression
- Proper chassis grounding and strain relief for all terminals

### 1.3 Platform preference for vehicle use
For vehicle deployment, Pi CM4 with a PoE+ carrier board is preferred over
Pi 5 where possible, because power input robustness is typically better on
industrial carrier configurations.

---

## 2. Vibration and Mounting

### 2.1 Mechanical isolation
- Mount the enclosure using M3 silicone grommets or anti-vibration standoffs.
- Avoid direct rigid mounting to high-frequency vibration surfaces.
- Use cable clamps to prevent connector creep.

### 2.2 Storage media durability
- Replace consumer SD cards with industrial-grade media (pSLC NAND class)
  or use USB SSD boot where supported.
- Keep a spare pre-imaged boot medium in deployment kit.

### 2.3 Transit false-positive suppression
During movement, rapid link changes can inflate Suricata reconnection noise.
Apply transit-mode suppression for `network-scan` category while moving.

---

## 3. UC-A (Moving) vs UC-B (Static)

### 3.1 UC-A (moving)
Use conservative posture while the vehicle is moving:
- Set `soc_policy.yaml` profile to `conservative`
- Add Suricata suppression for `classtype:network-scan`
- Reduce logging verbosity where operationally acceptable

### 3.2 UC-B (static)
When vehicle is stationary and serving as local gateway:
- Restore profile to `balanced`
- Re-enable full Suricata rule set
- Resume normal logging fidelity

---

## 4. Thermal Management

### 4.1 Limits
- Pi 5 thermal throttle threshold: 85C
- Pi 5 thermal shutdown threshold: 90C

### 4.2 Cooling policy
- Passive cooling (heatsink case) is generally sufficient to 60C ambient
  under `conservative` profile around 13W operation.
- Above 60C ambient, active fan cooling is required.

### 4.3 Fan trigger baseline
Use fan trigger around 75C based on:
- `/sys/class/thermal/thermal_zone0/temp`

---

## 5. Configuration Switching Procedure

### 5.1 Switch to transit mode (UC-A)

```bash
# Switch to transit mode (UC-A)
sudo azazel-edge-epd --state warning --mode-label "TRANSIT" --risk-status SUPPRESSED
sudo systemctl stop azazel-edge-control-daemon
# Edit /etc/azazel-edge/soc_policy.yaml: set profile: conservative
sudo systemctl start azazel-edge-control-daemon
```

### 5.2 Switch back to static mode (UC-B)

```bash
# Switch back to static mode (UC-B)
sudo azazel-edge-epd --state normal --mode-label "GATEWAY"
# Edit /etc/azazel-edge/soc_policy.yaml: set profile: balanced
sudo systemctl restart azazel-edge-control-daemon
```

---

## 6. Operational Checklist

- Confirm converter output remains within expected 5V rail tolerance.
- Confirm fuse and TVS components are physically installed and intact.
- Confirm enclosure mounts and cable restraints after each long transit.
- Confirm SOC policy profile matches movement/static state.
- Confirm temperature trend remains below throttle region.

---

## Supplementary (日本語)

### 要約
- 24V 車載電源では、絶縁 DC-DC（18-32V入力、5.1V/5A出力）を使用し、
  正極に 10A ヒューズ、入力に 60V/600W TVS を追加してください。
- 振動対策として M3 シリコングロメット等で防振固定し、
  SD は工業グレードまたは USB SSD 起動を推奨します。

### UC-A / UC-B 切替
- 走行中（UC-A）は `conservative` プロファイル + `network-scan` 抑制。
- 停車運用（UC-B）は `balanced` に戻し、通常ルールとログへ復帰します。
- 切替は本書のコマンド手順で実施してください。
