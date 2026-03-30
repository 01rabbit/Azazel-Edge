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

### LAN access

To expose the scaffold on the local network, bind both servers to `0.0.0.0`
and choose explicit ports.

```bash
cd topo_lite
AZAZEL_TOPO_LITE_BACKEND_HOST=0.0.0.0 \
AZAZEL_TOPO_LITE_FRONTEND_HOST=0.0.0.0 \
AZAZEL_TOPO_LITE_BACKEND_PORT=8081 \
AZAZEL_TOPO_LITE_FRONTEND_PORT=8082 \
make run-dev
```

Then open:

- UI: `http://<your-host-ip>:8082/`
- API: `http://<your-host-ip>:8081/health`

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

`arp-scan` must be installed on the host OS for real network discovery runs.

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
  initializer, a minimal repository layer, and an ARP discovery runner for
  `#114`, `#112`, `#115`, and `#116`.
