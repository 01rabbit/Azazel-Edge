# Wazuh Integration Guide

Last updated: 2026-10-26

This guide covers two methods for integrating Wazuh with Azazel-Edge on
Raspberry Pi 5 (ARM64/aarch64). Both methods are optional. The device
operates fully without Wazuh.

Wazuh is observation-only on Azazel-Edge. It receives telemetry (FIM, SCA,
forwarded Suricata alerts) and never applies a defensive action on the device.
Defensive actions (`throttle`, `redirect`, `isolate`) come only from the Rust
`azazel-edge-core` (`decide_defense()` selects, `maybe_enforce()` applies);
see `docs/X86_64_INTEGRATION_BOUNDARY.md`, "Decision and enforcement
authority" (Edge#412).

---

## Architecture Overview

```
Azazel-Edge (Raspberry Pi 5)          Wazuh Manager (separate host)
├── Suricata IDS                       ├── Wazuh Indexer
├── Evidence Plane                     └── Wazuh Dashboard
├── azazel-edge-core (sole enforcer)
└── [Method A] Wazuh Agent  ──────────>    receives FIM and SCA events
    [Method B] Vector ────────────────>    receives Suricata CEF lines

One-way: nothing flows back from the Manager to the Pi as an action.
```

The Wazuh Manager should run on a separate host (ARM64 server, x86_64 server,
or equivalent). Running Wazuh Manager on the same Pi as Azazel-Edge is not
recommended due to resource contention.

---

## Method A: Wazuh Agent (Recommended)

Method A provides File Integrity Monitoring (FIM) and Security Configuration
Assessment (SCA). It does not provide active response: the installer turns the
agent's active response off, so the Wazuh Manager cannot run commands that
block traffic on the Pi.

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
4. Disables active response on the agent (`<disabled>yes</disabled>` in the
   `<active-response>` block of `/var/ossec/etc/ossec.conf`) and removes
   `/var/ossec/active-response/bin/azazel-block.sh` if an earlier version of
   the installer left it there

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

### No active response

Earlier versions of the installer generated
`/var/ossec/active-response/bin/azazel-block.sh`, an `iptables` DROP script
the Wazuh Manager could start. It was a second enforcer outside the Rust core
and has been removed (Edge#412). Re-running the installer on an upgraded host
removes the script and disables active response on the agent; both steps are
idempotent.

If the Wazuh Manager has `<command>` or `<active-response>` entries that name
`azazel-block` (added by hand for the old script), remove them from the
Manager's `ossec.conf` and restart the Manager. With active response disabled
on the agent they have no effect on the Pi, but they no longer describe a
supported path.

To check an agent:
```bash
test ! -e /var/ossec/active-response/bin/azazel-block.sh
grep -A3 '<active-response>' /var/ossec/etc/ossec.conf
# Expected: <disabled>yes</disabled>
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
| Active response (IP block) | No (observation-only) | No |
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

---

## Supplementary (日本語)

### 概要
Wazuh との連携は Method A（Wazuh Agent）と Method B（Vector 転送）の2通りです。

- Method A: FIM・SCA 対応。推奨。Active Response は提供しません（エージェント側で無効化）。
- Method B: Suricata アラートのみ転送。軽量構成向け。

Wazuh は観測専用です。防御アクション（throttle / redirect / isolate）を適用するのは
Rust の `azazel-edge-core` だけで、Wazuh から Pi 上の通信を遮断する経路はありません
（Edge#412）。

どちらも Wazuh Manager は別ホストで運用してください。
同一 Pi での同居は非推奨です。
