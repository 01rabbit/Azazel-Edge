# OPERATOR GUIDE (JA)

## Purpose
Primary operator guide for non-expert shelter staff and volunteers.

## Japanese Summary
この文書は、避難所スタッフ向けの運用手順です。最初の15分で起動し、状態表示を見て、最小限の安全対応を実施できることを目的にします。

## 1. Quick Start (15 minutes)
1. Connect power, LAN, and display cables.
2. Boot the device and wait for service start.
3. Verify `systemctl is-active azazel-edge-web azazel-edge-control-daemon`.
4. Open dashboard from local network browser.
5. Confirm current posture and first action.

## 2. e-Paper State and Action
- GREEN: Continue monitoring and confirm periodic updates.
- YELLOW: Run initial checks and keep current mode stable.
- RED: Escalate to operator review and avoid destructive changes.

## 3. FAQ (sample)
- Q: Wi-Fiがつながらない
  A: 1台か全体かを先に確認し、Runbook候補へ進む。
- Q: 表示が赤になった
  A: 現在の推奨を確認し、手順どおりに1つずつ実施する。
- Q: 再起動方法
  A: 記録を確認後、承認済み手順で実施する。

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
