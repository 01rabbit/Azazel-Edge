# Physical Setup Guide

Last updated: 2026-05-13

This guide defines wiring, labeling, enclosure, and physical checks for reliable
field operation.

---

## 1. Connection Map (ASCII)

```
 [Power Source]
      |
      v
 [DC-DC / Adapter] ---> [UPS HAT (optional)]
      |
      v
 [Azazel-Edge Unit]
   |        |        |
   |        |        +--> [EPD Display]
   |        +-----------> [LAN Switch / AP]
   +--------------------> [WAN Uplink Router]
```

Rules:
- Route power and data cables separately when possible.
- Use strain relief loops near each connector.

---

## 2. Label Templates

Print and attach labels on enclosure and cable ends:

```
+----------------------+
| PWR-IN               |
| 5V/5A MIN            |
+----------------------+

+----------------------+
| ETH-UPLINK           |
| WAN / BACKHAUL       |
+----------------------+

+----------------------+
| ETH-LAN              |
| CLIENT SEGMENT       |
+----------------------+

+----------------------+
| EPD                  |
| STATUS DISPLAY       |
+----------------------+
```

---

## 3. Storage and Boot Media Health

- Prefer industrial-grade SD or USB SSD boot media.
- Run selftest before every deployment:

```bash
sudo bin/azazel-edge-selftest
```

Expected:
- no critical media errors

---

## 4. Enclosure Recommendation

Minimum recommendation:
- IP54-rated enclosure or better
- Operating temperature: -10C to +55C
- Mechanical retention for all external cables

For vehicle or heavy vibration, use additional anti-vibration mounts.

---

## 5. Pre-deployment Physical Checklist

- Enclosure screws tightened
- Labels visible and consistent
- Cable strain relief in place
- Power connector stable under light pull test
- EPD cable seated and secured

---

## Supplementary (日本語)

- 配線は電源系と通信系を分離し、各端子に必ずストレインリリーフを設けます。
- ラベルは筐体とケーブル両端に貼付し、現地で迷わない状態にします。
- 出動前に selftest で媒体健全性を確認してください。
