# Humanitarian Partner Guide

Last updated: 2026-05-13

This document explains how Azazel-Edge fits humanitarian and NGO field
operations, including deployment boundaries and obligations.

---

## 1. Operational Fit

Azazel-Edge is designed for temporary, resource-constrained operations:
- Approximate 100-person-scale temporary networks
- Typical use in registration sites, field clinics, and relief distribution
- 15-minute setup objective with offline-capable runtime
- Typical baseline power draw around 13W in non-AI-heavy mode

Design boundary:
- Azazel-Edge supplements field operations.
- It does not replace existing NGO or institutional IT systems.

Staffing model:
- Can be operated by volunteers without deep cybersecurity training
  through simplified operator workflows.

License model:
- MIT license, allowing use, modification, and distribution.

---

## 2. Recommended Scenarios

### Refugee registration support
- Gateway for tablet-based workflows
- Suricata-based alerting for suspicious credential activity

### Field hospital network
- Prioritize medical and coordination traffic stability
- Maintain deterministic response boundaries during incidents

### Relief distribution point
- Temporary Wi-Fi with captive consent for accountability
- Lightweight local SOC/NOC posture monitoring

### Emergency coordination hub
- Multi-node fleet visibility via aggregator features
- Node-level deterministic autonomy remains primary

---

## 3. Legal and Data Handling Obligations

- Monitoring disclosure is mandatory in deployment area.
  Use STATUS_CARD and captive consent page.
- Collected by default:
  - IP addresses
  - MAC addresses
  - Suricata alert metadata
- Not collected by default:
  - Packet payload content

Retention baseline:
- 7-day log rotation default
- Extended retention variable is `[planned]`

Equipment return / sanitization:
- Run validation and zeroization workflow before returning devices
  to storage pool or transferring ownership.

Emergency legal rationale reference:
- During declared emergency operations, vital-interest processing
  models may apply based on local jurisdiction.

---

## 4. Contribution and Support Paths

- Source repository:
  `https://github.com/01rabbit/Azazel-Edge`

- Deployment feedback path:
  - Open GitHub Issue with `[field-report]` style title/labeling policy

- Translation contributions:
  - Extend `SUPPORTED_LANGS` and `UI_STRINGS` in `py/azazel_edge/i18n.py`

- Commercial support:
  - No commercial support contract is currently provided
  - Community-supported model only

---

## Supplementary (日本語)

Azazel-Edge は、人道支援現場の一時ネットワーク運用を補助するための
軽量ゲートウェイです。既存IT基盤を置き換えるものではなく、
現場初動の SOC/NOC 支援に特化しています。

運用時は、監視の告知とデータ取扱いの説明を必ず実施してください。
ログは既定で短期保持を前提とし、機材返却前には消去手順を適用します。
