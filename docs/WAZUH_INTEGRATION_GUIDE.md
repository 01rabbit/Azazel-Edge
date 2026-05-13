# Wazuh Integration Guide

Last updated: 2026-05-13

This guide covers two methods for integrating Wazuh with Azazel-Edge on
Raspberry Pi 5 (ARM64/aarch64). Both methods are optional. The device
operates fully without Wazuh.

---

## Architecture Overview

```
Azazel-Edge (Raspberry Pi 5)          Wazuh Manager (separate host)
├── Suricata IDS                       ├── Wazuh Indexer
├── Evidence Plane                     ├── Wazuh Dashboard
├── Arbiter                            └── Active Response engine
└── [Method A] Wazuh Agent  ──────────>    receives alerts, FIM events
    [Method B] Vector ────────────────>    receives Suricata CEF lines
```

The Wazuh Manager should run on a separate host (ARM64 server, x86_64 server,
or equivalent). Running Wazuh Manager on the same Pi as Azazel-Edge is not
recommended due to resource contention.

---

## Method A: Wazuh Agent (Recommended)

Method A provides File Integrity Monitoring (FIM), Security Configuration
Assessment (SCA), and active response (Wazuh can trigger IP blocks on the Pi).

### Prerequisites
- Wazuh Manager accessible on LAN
- `WAZUH_MANAGER_HOST` set to the Manager IP or hostname

### Installation

```bash
sudo WAZUH_MANAGER_HOST=192.168.1.10 \
  bash installer/internal/install_wazuh_agent.sh
```

The installer:
1. Adds the Wazuh APT repository (ARM64)
2. Installs `wazuh-agent`
3. Configures FIM monitoring for `/etc/azazel-edge`, `/opt/azazel-edge`,
   `/var/log/azazel-edge`, `/etc/suricata/rules`, `/etc/azazel-edge/vector`
4. Installs `azazel-block.sh` active response script

### Register the agent on the Manager

On the Wazuh Manager host:
```bash
/var/ossec/bin/manage_agents
# Choose: A) Add agent
# Enter the Pi's IP as the agent address
# Note the agent key shown
```

Then on the Pi:
```bash
sudo /var/ossec/bin/manage_agents
# Choose: I) Import key
# Paste the key from the Manager
sudo systemctl restart wazuh-agent
```

### Verification

```bash
systemctl is-active wazuh-agent
# Expected: active

sudo /var/ossec/bin/agent_control -l
# Expected: Pi appears as active agent on Manager

tail -f /var/ossec/logs/ossec.log
# Expected: no ERROR lines after startup
```

### Active Response

When the Wazuh Manager triggers an active response for IP isolation, the
`azazel-block.sh` script on the Pi runs:

```bash
iptables -I FORWARD -s <attacker_ip> -j DROP
iptables -I INPUT   -s <attacker_ip> -j DROP
```

To test active response manually from the Manager:
```bash
/var/ossec/bin/agent_control -b <ip> -f azazel-block -u <agent_id>
```

---

## Method B: Vector Forwarding (Lightweight)

Method B forwards Suricata alerts to Wazuh Manager via syslog/CEF.
No FIM or SCA support. This path is suitable when only Suricata alerts are
needed.

### Installation

```bash
sudo VECTOR_MODE=wazuh \
     WAZUH_MANAGER_HOST=192.168.1.10 \
  bash installer/internal/install_vector.sh
```

### Verification

```bash
systemctl is-active azazel-edge-vector
# Expected: active

vector top
# Expected: suricata_eve source shows events processed

# On Wazuh Manager:
tail -f /var/ossec/logs/archives/archives.log | grep AZAZEL
```

---

## Comparison

| Capability | Method A (Agent) | Method B (Vector) |
|---|---|---|
| Suricata alert forwarding | Yes | Yes |
| File Integrity Monitoring | Yes | No |
| Security Config Assessment | Yes | No |
| Active Response (IP block) | Yes | No |
| RAM overhead | ~35 MB | ~15 MB |
| Config files monitored | `/etc/azazel-edge`, rules, vector | none |

Both methods can run simultaneously.

---

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| `wazuh-agent: inactive` | Not registered | Run `manage_agents` on both sides |
| Agent shows as disconnected | Firewall blocks port 1514 | Open TCP/UDP 1514 from Pi to Manager |
| No logs in Manager | Wrong Manager IP | Check `WAZUH_MANAGER_HOST` in `/var/ossec/etc/ossec.conf` |
| Vector not forwarding | `WAZUH_MANAGER_HOST` unset | Reinstall with host set, or edit `/etc/azazel-edge/vector/vector.toml` |
| Active response not triggering | Script not executable | `chmod 0750 /var/ossec/active-response/bin/azazel-block.sh` |

---

## Supplementary (日本語)

### 概要
Wazuh との連携は Method A（Wazuh Agent）と Method B（Vector 転送）の2通りです。

- Method A: FIM・SCA・Active Response 対応。推奨。
- Method B: Suricata アラートのみ転送。軽量構成向け。

どちらも Wazuh Manager は別ホストで運用してください。
同一 Pi での同居は非推奨です。
