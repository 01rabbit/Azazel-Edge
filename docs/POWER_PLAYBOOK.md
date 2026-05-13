# POWER PLAYBOOK

## Purpose
Power selection and runtime estimate guide.

## Japanese Summary
電源構成ごとの運転時間目安と注意点をまとめます。

| Configuration | Capacity | Runtime (13W load) | Runtime (full 90W load) |
|---|---|---|---|
| Pi only, 20Ah mobile battery | 72Wh usable | ~5.5h | ~0.8h |
| 105D31R ×2 (24V, 72Ah) | 864Wh usable @50% DoD | ~66h | ~9.6h |
| 105D31R ×2 + 100Ah sub ×2 | 2,664Wh | ~204h | ~29.6h |
| 10kVA generator | unlimited | unlimited | unlimited |
| 50W solar + 20Ah battery | self-sustaining >6h sun | indefinite | limited |

## Notes
- Use isolated DC-DC converter (5V/5A minimum).
- Configure graceful shutdown trigger.
- Verify battery health before deployment.
