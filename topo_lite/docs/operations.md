# Azazel-Topo-Lite Operations Runbook

## Install

1. Copy `topo_lite/` to `/opt/azazel-edge/topo_lite`.
2. Create `/opt/azazel-edge/topo_lite/config.yaml` from `config.yaml.example`.
3. Install Python dependencies with `pip install -r /opt/azazel-edge/topo_lite/requirements.txt`.
4. Initialize the SQLite database with `PYTHONPATH=. python3 scripts/init_db.py`.

## Configure

- Set discovery interface, subnets, and target ports in `config.yaml`.
- Change the default local auth credentials before exposing the UI outside localhost.
- If notifications are required, set `notification.enabled`, `notification.provider`, and `notification.endpoint`.
- If Azazel-Edge queue export is required, set `integration.enabled` and `integration.queue_path`.
- Review `retention_period` values before long-running deployments.

## Start Services

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now azazel-topo-lite-scheduler.service
sudo systemctl enable --now azazel-topo-lite-scanner.service
sudo systemctl enable --now azazel-topo-lite-api.service
```

## Verify Runtime

- `systemctl status azazel-topo-lite-api.service`
- `systemctl status azazel-topo-lite-scheduler.service`
- `systemctl status azazel-topo-lite-scanner.service`
- `curl http://127.0.0.1:8091/health`
- Open `http://<host>:8082/`

## Notifications

- Manual backlog run: `make run-notify`
- Diff-triggered notification run: `make run-diff`
- Only `new_host` and `severity=high` events are notified.
- Duplicate sends are suppressed by `notified_at`.
- Retry storms are limited by `notification.rate_limit_seconds`.

## Azazel-Edge Export Queue

- Manual export run: `make run-export-events`
- Exported files are written to `integration.queue_path`.
- Only `severity=high` events are exported.
- Each event is exported once and recorded via `exported_at`.

## Retention Cleanup

- Manual cleanup run: `make run-cleanup`
- The probe scheduler also runs cleanup after a successful probe cycle.
- Cleanup deletes expired rows from `observations`, `events`, and `scan_runs`.
- Current host and service state is preserved.

## Backup and Recovery

- Create bundle: `make backup-state`
- Restore bundle: `python3 scripts/restore_state.py --bundle-dir <dir> --restore-db --restore-config`
- Rebuild from fresh observations:

```bash
make init-db
make run-discovery
make run-probe
make run-diff
```

## Troubleshooting

- Audit log: `logs/audit.jsonl`
- Scanner log: `logs/scanner.jsonl`
- Access log: `logs/access.jsonl`
- App log: `logs/app.jsonl`
- If `arp-scan` is missing, install it before discovery runs.
