#!/usr/bin/env bash
# Portable demo bootstrap for macOS and Linux (including aarch64).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ "$(uname -s)" != "Darwin" && "$(uname -s)" != "Linux" ]]; then
  echo "Unsupported host; expected macOS or Linux" >&2; exit 2
fi
PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 11), "Python >=3.11 required"'
if [[ ! -d .venv ]]; then "$PYTHON" -m venv .venv; fi
.venv/bin/python -m pip install --upgrade pip
# Replay-only dependency set, deliberately excluding the runtime MIO Git pin,
# Ollama, systemd, Linux packet enforcement, and optional web services.
.venv/bin/python -m pip install 'PyYAML>=6,<7' 'requests>=2.32,<3'
echo "Environment prepared. Run:"
echo "  .venv/bin/python tools/arsenal_bheurope_2026.py"
echo "  .venv/bin/python tools/arsenal_bheurope_monitor.py"
