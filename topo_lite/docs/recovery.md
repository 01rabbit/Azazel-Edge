# Topo-Lite Backup and Recovery

## Backup

Create a backup bundle that includes the SQLite database and the active
`config.yaml`:

```bash
cd topo_lite
make backup-state
```

The command writes a timestamped bundle under `topo_lite/backups/` and creates
`manifest.json` with the recorded file paths.

## Restore

Restore both the DB and config into the current workspace:

```bash
cd topo_lite
PYTHONPATH=. python3 scripts/restore_state.py \
  --bundle-dir backups/topo-lite-backup-YYYYMMDDTHHMMSSZ \
  --restore-db \
  --restore-config
```

Initialize an empty DB when you want to rebuild from fresh state:

```bash
cd topo_lite
PYTHONPATH=. python3 scripts/restore_state.py \
  --bundle-dir backups/topo-lite-backup-YYYYMMDDTHHMMSSZ \
  --restore-config \
  --init-db
```

## Rebuild After DB Loss

When the DB is lost and no DB backup is restored, run:

```bash
cd topo_lite
make init-db
make run-discovery
make run-probe
make run-diff
```

This rebuilds the current host, service, and diff state from fresh observations.
Historical `scan_runs` and `events` that were not restored from backup are not
recovered.
