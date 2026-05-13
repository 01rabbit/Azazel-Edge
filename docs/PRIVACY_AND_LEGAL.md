# Privacy and Legal

Last updated: 2026-05-13

This document summarizes data handling, retention, disclosure duties, and legal
considerations for Azazel-Edge field operations.

---

## 1. Data Collected

Collected by default:
- IP addresses (source and destination) from alert metadata
- MAC addresses from DHCP lease and ARP-derived inventories
- Alert metadata: signature, signature ID, timestamp, protocol, port numbers
- Captive consent records: operator name, MAC, timestamp
  (stored in `/var/lib/azazel-edge/captive-allowlist.json`)

Not collected by default:
- Packet payload content

Operational note:
- Suricata default mode is IDS-style metadata extraction and alerting.

---

## 2. Retention

Default retention baseline:
- 7-day rolling log rotation under `/var/log/azazel-edge/`

Long-lived data:
- Audit chain logs are tamper-evident and should not be rotated without
  explicit export and governance controls.

Captive consent records:
- Retained until manual clear or full device reset.

Retention tuning:
- Adjust Vector sink path/date and host logrotate policies based on
  deployment requirements.

---

## 3. Legal Basis by Jurisdiction

| Jurisdiction | Applicable law | Legal basis |
|---|---|---|
| Japan | APPI and Telecommunications-related controls | Emergency life/property protection exceptions where applicable |
| Japan | Active defense-related security operations context | Defensive monitoring within authorized scope |
| EU/EEA | GDPR | Article 6(1)(d) vital interests; Article 6(1)(e) public-interest task |
| USA | CFAA, ECPA | Network operator monitoring and consent-based operation |
| International/Humanitarian | IHL context for civilian protection operations | Relief and civilian infrastructure protection rationale |

Important:
- Legal interpretation must be confirmed by organization counsel.
- This table is operational guidance, not a legal determination.

---

## 4. Disclosure Obligation

Every deployment must include visible monitoring disclosure:
- Physical notice (use `docs/STATUS_CARD.md` template)
- Digital notice via captive consent screen (`/captive`) when applicable

Operators must ensure notice is visible before onboarding users.

---

## 5. Disclaimer

This document is informational only and does not constitute legal advice.
Organizations operating Azazel-Edge should consult legal counsel in their
jurisdiction before deployment, especially for healthcare, government, or
cross-border operations.

---

## Supplementary (日本語)

収集対象は主に通信メタデータ（IP/MAC/アラート情報）であり、既定では
ペイロード本文を取得しません。保持期間は短期ローテーションを基本とし、
監査ログは改ざん検知性を保ったまま管理してください。

運用時は掲示と接続時告知の両方で監視を明示し、法的根拠の解釈は必ず
各組織の法務確認を前提とします。本書は法的助言ではありません。
