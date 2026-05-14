# Arsenal Demo Profile

Last updated: 2026-05-14

## 1. Purpose

This demo shows the deterministic edge SOC/NOC decision loop. It is not a full SIEM replacement, not an autonomous AI defender, and not a broad feature tour.

## 2. Demo story

1. Evidence is ingested.
2. NOC and SOC are evaluated separately.
3. The Action Arbiter selects a bounded response.
4. The system records explanation, rejected alternatives, and audit evidence.
5. The operator inspects the decision and response trace.

## 3. Required components

Mandatory:
- `azazel-edge-web`
- `azazel-edge-control-daemon`
- deterministic replay CLI (`bin/azazel-edge-demo`)
- `azazel-edge-core` when live Suricata path is included
- `azazel-edge-opencanary` when redirect behavior is shown

Optional:
- Mattermost
- Ollama
- Aggregator
- TAXII/STIX
- SNMP/NetFlow
- Vector
- Wazuh

## 4. Demo modes

Replay-only demo (default):
- safest for Arsenal booth
- stable evaluator output
- no dependency on live packet generation

Live-assisted demo:
- includes Suricata EVE live path
- must preserve immediate fallback to replay-only mode

## 5. Pre-demo checklist

```bash
systemctl status azazel-edge-web --no-pager
systemctl status azazel-edge-control-daemon --no-pager
systemctl status azazel-edge-core --no-pager
systemctl status azazel-edge-opencanary --no-pager
bin/azazel-edge-demo list
bin/azazel-edge-demo run mixed_correlation_demo
```

Recommended API sanity checks:

```bash
TOKEN="$(cat ~/.azazel-edge/web_token.txt)"
curl -fsS -H "X-AZAZEL-TOKEN: ${TOKEN}" http://127.0.0.1:8084/api/state >/dev/null
curl -fsS -H "X-AZAZEL-TOKEN: ${TOKEN}" http://127.0.0.1:8084/api/aggregator/nodes >/dev/null || true
```

## 6. Failure fallback

- Suricata failure: switch to replay-only path immediately.
- OpenCanary failure: continue replay demo without redirect execution path.
- Mattermost failure: continue local Web UI + audit walkthrough.
- Ollama failure: continue deterministic core story (AI assist is optional).
- Network instability: run local replay scenarios only.
- Web UI failure: use CLI replay output + JSON logs for deterministic trace.

Final fallback rule:
- the deterministic replay path must remain the final fallback.

## 7. What not to show first

Do not lead with optional integration tours:
- Wazuh
- TAXII/STIX
- Aggregator fleet view
- multilingual captive portal
- vehicle deployment

Lead with deterministic path consistency and bounded action behavior.
