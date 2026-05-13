# FIELD DEPLOYMENT GUIDE

## Purpose
Rapid deployment checklist for first responders.

Supplementary JA: 現場展開を短時間で実施するためのチェックリスト。

## Stages
- Pre-deployment: verify hardware and configs.
- Transit: secure power and cables.
- On-site setup: boot, network check, dashboard check.
- Operation: monitor posture and reviewed runbooks.
- Shutdown/recovery: capture logs and safe power-off.

## Encrypted Secrets Unlock (if enabled)
- Check device mapper: `ls /dev/mapper/azazel-secrets`
- If missing, unlock: `sudo cryptsetup open /var/lib/azazel-secrets.img azazel-secrets`
- Mount secrets volume: `sudo mount /dev/mapper/azazel-secrets /etc/azazel-edge/secrets`
- Verify token files: `sudo ls -la /etc/azazel-edge/secrets/tokens`
