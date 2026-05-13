# WAZUH INTEGRATION GUIDE

## Purpose
Guide for Wazuh Agent and Vector integration paths.

Supplementary JA: Wazuh連携の2方式（Agent / Vector）と確認手順。

## Method A: Wazuh Agent
- Install with `installer/internal/install_wazuh_agent.sh`.
- Verify with `systemctl status wazuh-agent`.
- Confirms FIM and active response integration.

## Method B: Vector Forwarding
- Install Vector and set `VECTOR_MODE=wazuh`.
- Set `WAZUH_MANAGER_HOST`.
- Verify forwarded logs in manager syslog input.

## Verification
- `systemctl is-active wazuh-agent`
- `systemctl is-active azazel-edge-vector`
- `vector --version`
