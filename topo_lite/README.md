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

## Validation

```bash
cd topo_lite
make lint
make test
```

## Notes

- This scaffold is intentionally isolated from the existing Azazel-Edge web,
  control, and installer stack.
- The workspace is ready for `#114` and `#112` to build on top of it.

