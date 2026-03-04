#!/usr/bin/env bash
set -euo pipefail
if [[ -f /run/azazel-edge/ui_snapshot.json ]]; then
  cat /run/azazel-edge/ui_snapshot.json
else
  echo '{"ok":false,"error":"snapshot_not_found"}'
fi
