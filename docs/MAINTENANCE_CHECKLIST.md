# Maintenance Checklist

Last updated: 2026-05-13

This checklist defines annual, quarterly, and per-deployment maintenance
procedures with explicit commands and expected outcomes.

---

## 1. Annual Maintenance

- [ ] Run full selftest and Python regression baseline.

```bash
sudo bin/azazel-edge-selftest
PYTHONPATH=. .venv/bin/pytest -q
```

Expected:
- selftest completes without critical error
- pytest has zero failures

- [ ] Verify release artifact integrity workflow.

```bash
sha256sum -c release-checksums.sha256
```

Expected:
- all relevant files report `OK`

---

## 2. Quarterly Maintenance

- [ ] Check service status matrix.

```bash
systemctl status azazel-edge-web azazel-edge-control-daemon azazel-edge-core azazel-edge-ai-agent --no-pager
```

Expected:
- required units are active for installed profile

- [ ] Validate log rotation behavior.

```bash
sudo logrotate -d /etc/logrotate.conf | head -n 120
```

Expected:
- azazel-edge log paths appear in rotation plan

- [ ] Check Suricata ruleset currency and syntax baseline.

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/azazel-lite.rules
```

Expected:
- configuration test passes

---

## 3. Per Deployment Maintenance

- [ ] Connectivity sanity check.

```bash
ping -c 2 127.0.0.1
curl -fsS http://127.0.0.1:8084/health
```

Expected:
- ping successful
- health endpoint returns success payload

- [ ] Core service health check.

```bash
systemctl is-active azazel-edge-web azazel-edge-control-daemon
```

Expected:
- both return `active`

- [ ] Dashboard API sample check.

```bash
curl -fsS -H "X-AZAZEL-TOKEN: <token>" http://127.0.0.1:8084/api/dashboard/summary | jq .ok
```

Expected:
- output is `true`

---

## 4. Failure Handling Baseline

If any required check fails:
1. Capture journal and relevant logs.
2. Do not proceed with high-risk operations.
3. Escalate to operator review and run approved recovery runbook.

---

## Supplementary (日本語)

- 年次: selftest と回帰テストを必ず実施します。
- 四半期: サービス状態、logrotate、Suricata 設定テストを確認します。
- 出動前: `ping` / `health` / `systemctl` / API の最小確認を実施します。
