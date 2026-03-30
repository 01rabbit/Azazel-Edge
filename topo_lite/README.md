# Azazel-Topo-Lite Scaffold

Azazel-Topo-Lite is a lightweight network visibility workspace that lives
inside the main Azazel-Edge repository without changing the existing runtime.

## Layout

- `backend/`: Flask API skeleton
- `frontend/`: static UI skeleton
- `scanner/`: discovery-related placeholders
- `db/`: schema and persistence placeholders
- `docs/`: implementation notes
- `scripts/`: local development helpers
- `tests/`: scaffold verification tests

## Quick Start

```bash
cd topo_lite
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
make run-dev
```

Default local endpoints:

- API: `http://127.0.0.1:18080`
- UI: `http://127.0.0.1:18081`

The default exposure policy is local-only. Both backend and frontend bind to
`127.0.0.1` unless you change the config or export explicit environment
variables.

### LAN access

To expose the scaffold on the local network, disable local-only mode, add an
allowlist CIDR, and bind both servers to `0.0.0.0`.

Example `config.yaml` override:

```yaml
exposure:
  backend_bind_host: 0.0.0.0
  frontend_bind_host: 0.0.0.0
  local_only: false
  allowed_cidrs:
    - 192.168.40.0/24
```

You can also override the same settings via environment variables:

```bash
cd topo_lite
AZAZEL_TOPO_LITE_BACKEND_HOST=0.0.0.0 \
AZAZEL_TOPO_LITE_FRONTEND_HOST=0.0.0.0 \
AZAZEL_TOPO_LITE_LOCAL_ONLY=false \
AZAZEL_TOPO_LITE_ALLOWED_CIDRS=192.168.40.0/24 \
AZAZEL_TOPO_LITE_BACKEND_PORT=8081 \
AZAZEL_TOPO_LITE_FRONTEND_PORT=8082 \
make run-dev
```

Then open:

- UI: `http://<your-host-ip>:8082/`
- API: `http://<your-host-ip>:8081/health`

Requests that originate outside the configured allowlist return `403` and are
recorded in `logs/audit.jsonl`.

This scaffold does not serve HTTPS yet.

## Validation

```bash
cd topo_lite
make lint
make test
```

## Config and DB

Create a local config from the example and initialize the SQLite database:

```bash
cd topo_lite
cp config.yaml.example config.yaml
make init-db
```

The default database path is `topo_lite.sqlite3`. You can override it with:

```bash
AZAZEL_TOPO_LITE_DATABASE_PATH=/tmp/topo_lite.sqlite3 make init-db
```

Run a discovery pass with the local config:

```bash
cp config.yaml.example config.yaml
make run-discovery
```

Supplemental passive discovery reads the local ARP cache and DHCP lease data.
To also enable active ICMP and TCP connect discovery for the configured
subnets, set:

```bash
AZAZEL_TOPO_LITE_DISCOVERY_INCLUDE_ACTIVE_SOURCES=true make run-discovery
```

`arp-scan` must be installed on the host OS for real network discovery runs.

On Debian-based systems:

```bash
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y arp-scan
```

If your active LAN interface is not `eth0`, override it at runtime:

```bash
sudo env AZAZEL_TOPO_LITE_INTERFACE=eth1 PYTHONPATH=. python3 scripts/run_discovery.py
```

Run the discovery scheduler in one-shot mode:

```bash
sudo env AZAZEL_TOPO_LITE_INTERFACE=eth1 \
AZAZEL_TOPO_LITE_SCHEDULER_MAX_RUNS=1 \
AZAZEL_TOPO_LITE_SCHEDULER_RETRY_DELAY_SECONDS=10 \
AZAZEL_TOPO_LITE_SCHEDULER_RETRY_BACKOFF_MULTIPLIER=2.0 \
AZAZEL_TOPO_LITE_SCHEDULER_RETRY_MAX_DELAY_SECONDS=60 \
PYTHONPATH=. python3 scripts/run_scheduler.py
```

Run the limited TCP probe after discovery:

```bash
PYTHONPATH=. python3 scripts/run_probe.py
```

Run an immediate deep probe for the latest discovery run:

```bash
AZAZEL_TOPO_LITE_DEEP_PROBE_DISCOVERY_SCAN_RUN_ID=12 \
PYTHONPATH=. python3 scripts/run_deep_probe.py
```

The discovery scheduler runs this automatically when it finds newly discovered
hosts. `deep_probe.target_ports` controls the short follow-up probe, and
`deep_probe.dedupe_window_seconds` prevents the same host from being deep
probed repeatedly in a short span.

Tune probe concurrency, retry, and batch size when a segment has many slow
hosts:

```bash
AZAZEL_TOPO_LITE_PROBE_CONCURRENCY=16 \
AZAZEL_TOPO_LITE_PROBE_TIMEOUT_SECONDS=1 \
AZAZEL_TOPO_LITE_PROBE_RETRY_COUNT=1 \
AZAZEL_TOPO_LITE_PROBE_RETRY_BACKOFF_SECONDS=0.25 \
AZAZEL_TOPO_LITE_PROBE_BATCH_SIZE=32 \
PYTHONPATH=. python3 scripts/run_probe.py
```

Generate diff events from the latest discovery/probe snapshots:

```bash
PYTHONPATH=. python3 scripts/run_diff.py
```

Re-run classification against the current host/service/observation set:

```bash
make run-classification
```

## Auth

The API now requires authentication for detailed endpoints. The initial local
accounts come from `config.yaml`:

- admin: `admin` / `change-me-admin-password`
- read-only: `viewer` / `change-me-viewer-password`

Login with a session:

```bash
curl -c /tmp/topo-lite.cookie \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me-admin-password"}' \
  http://127.0.0.1:18080/api/auth/login
```

Or call the API with a bearer token:

```bash
curl -H 'Authorization: Bearer change-me-admin-token' \
  http://127.0.0.1:18080/api/hosts
```

## Performance Controls

- Probe concurrency, retry count, retry backoff, and DB write batch size are
  configurable through `config.yaml` or environment variables.
- The inventory UI loads the first page first and uses `Load More` for
  additional pages, so the initial browser render stays lighter on larger
  datasets.
- Scheduler retries use bounded exponential backoff to avoid tight retry loops
  during repeated discovery failures.

## systemd Deployment

Topo-Lite now includes systemd assets under `topo_lite/systemd/`:

- `azazel-topo-lite-api.service`
- `azazel-topo-lite-scheduler.service`
- `azazel-topo-lite-scanner.service`
- `azazel-topo-lite.env.example`

The default environment file path is `/etc/default/azazel-topo-lite`.
After installing the workspace under `/opt/azazel-edge/topo_lite`, you can
manage the services with:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now azazel-topo-lite-scheduler.service
sudo systemctl enable --now azazel-topo-lite-scanner.service
sudo systemctl enable --now azazel-topo-lite-api.service
sudo systemctl status azazel-topo-lite-api.service
sudo journalctl -u azazel-topo-lite-api.service -n 50 --no-pager
```

The migrated installer now copies these units and the default environment file.
Set `ENABLE_TOPO_LITE=1` when running `installer/internal/install_migrated_tools.sh`
if you want the services enabled automatically.

## Logs

The scaffold writes JSONL logs by default:

- `logs/app.jsonl`
- `logs/access.jsonl`
- `logs/audit.jsonl`
- `logs/scanner.jsonl`

You can override the paths with environment variables:

```bash
AZAZEL_TOPO_LITE_APP_LOG_PATH=/tmp/topo-lite-app.jsonl \
AZAZEL_TOPO_LITE_AUDIT_LOG_PATH=/tmp/topo-lite-audit.jsonl \
make init-db
```

## Notes

- This scaffold is intentionally isolated from the existing Azazel-Edge web,
  control, and installer stack.
- The workspace now includes a validated config loader, SQLite schema
  initializer, a minimal repository layer, an ARP discovery runner, and a
  scheduler entrypoint for `#114`, `#112`, `#115`, `#116`, and `#117`.
