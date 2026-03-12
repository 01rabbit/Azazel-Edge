#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
RUNTIME_ROOT="${2:-/opt/azazel-edge}"

if [[ ! -d "$REPO_ROOT" ]]; then
  echo "[ERROR] repo root not found: $REPO_ROOT" >&2
  exit 2
fi

if [[ ! -d "$RUNTIME_ROOT" ]]; then
  echo "[ERROR] runtime root not found: $RUNTIME_ROOT" >&2
  exit 2
fi

mapfile -t FILES <<'EOF'
azazel_edge_web/app.py
azazel_edge_web/static/app.js
azazel_edge_web/static/ops_comm.js
azazel_edge_web/static/ops_comm.css
azazel_edge_web/static/style.css
azazel_edge_web/templates/index.html
azazel_edge_web/templates/ops_comm.html
py/azazel_edge/__init__.py
py/azazel_edge/control_plane.py
py/azazel_edge/path_schema.py
py/azazel_edge/ai_governance.py
py/azazel_edge/config_drift.py
py/azazel_edge/demo_overlay.py
py/azazel_edge/opencanary_redirect.py
py/azazel_edge/runbooks.py
py/azazel_edge/runbook_review.py
py/azazel_edge/cli_unified.py
py/azazel_edge/cli_unified_textual.py
py/azazel_edge_menu.py
py/azazel_edge_status.py
py/azazel_edge_epd.py
py/azazel_edge_epd_mode_refresh.py
py/azazel_edge_ai/__init__.py
py/azazel_edge_ai/agent.py
py/azazel_edge_control/__init__.py
py/azazel_edge_control/daemon.py
py/azazel_edge_control/mode_manager.py
py/azazel_edge_control/wifi_scan.py
py/azazel_edge_control/wifi_connect.py
py/azazel_edge_runbook_broker.py
security/.env
security/docker-compose.ollama.yml
security/docker-compose.mattermost.yml
security/docker-compose.yml
security/opencanary/Dockerfile
security/opencanary/opencanary.conf
security/suricata/azazel-lite.rules
rust/azazel-edge-core/Cargo.toml
rust/azazel-edge-core/src/main.rs
bin/azazel-edge-demo
bin/azazel-edge-web
bin/azazel-edge-ai-agent
bin/azazel-edge-control-daemon
bin/azazel-edge-epd
bin/azazel-edge-epd-refresh
bin/azazel-edge-runbook-broker
EOF

mapfile -t DIRS <<'EOF'
py/azazel_edge/arbiter
py/azazel_edge/audit
py/azazel_edge/correlation
py/azazel_edge/demo
py/azazel_edge/evaluators
py/azazel_edge/evidence_plane
py/azazel_edge/explanations
py/azazel_edge/impact
py/azazel_edge/integrations
py/azazel_edge/knowledge
py/azazel_edge/notify
py/azazel_edge/sensors
py/azazel_edge/sigma
py/azazel_edge/sot
py/azazel_edge/ti
py/azazel_edge/triage
py/azazel_edge/triage/flows
py/azazel_edge/yara
py/azazel_edge/tactics_engine
runbooks/noc
runbooks/ops
runbooks/soc
runbooks/user
images
fonts
icons/epd
EOF

declare -a mismatches=()

runtime_path_for() {
  local rel="$1"
  case "$rel" in
    bin/*)
      printf '/usr/local/%s\n' "$rel"
      ;;
    azazel_edge_web/*)
      printf '%s/%s\n' "$RUNTIME_ROOT" "$rel"
      ;;
    py/*)
      printf '%s/%s\n' "$RUNTIME_ROOT" "$rel"
      ;;
    runbooks/*|security/*|fonts/*|images/*|icons/*|rust/*)
      printf '%s/%s\n' "$RUNTIME_ROOT" "$rel"
      ;;
    *)
      printf '%s/%s\n' "$RUNTIME_ROOT" "$rel"
      ;;
  esac
}

compare_file() {
  local rel="$1"
  local src="$REPO_ROOT/$rel"
  local dst
  dst="$(runtime_path_for "$rel")"
  if [[ ! -f "$src" ]]; then
    mismatches+=("missing_repo:$rel")
    return
  fi
  if [[ ! -f "$dst" ]]; then
    mismatches+=("missing_runtime:$rel")
    return
  fi
  if ! cmp -s "$src" "$dst"; then
    mismatches+=("content_mismatch:$rel")
  fi
}

compare_dir() {
  local rel="$1"
  local src="$REPO_ROOT/$rel"
  local dst
  dst="$(runtime_path_for "$rel")"
  if [[ ! -d "$src" ]]; then
    mismatches+=("missing_repo_dir:$rel")
    return
  fi
  if [[ ! -d "$dst" ]]; then
    mismatches+=("missing_runtime_dir:$rel")
    return
  fi

  while IFS= read -r -d '' f; do
    local child="${f#$REPO_ROOT/}"
    compare_file "$child"
  done < <(find "$src" -type f \( -name '*.py' -o -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.yaml' -o -name '*.yml' -o -name '*.png' -o -name '*.ttf' -o -name 'Dockerfile' -o -name '.env' \) -print0 | sort -z)
}

for rel in "${FILES[@]}"; do
  compare_file "$rel"
done

for rel in "${DIRS[@]}"; do
  compare_dir "$rel"
done

if (( ${#mismatches[@]} > 0 )); then
  echo "[ERROR] runtime sync verification failed (${#mismatches[@]} mismatches)"
  printf ' - %s\n' "${mismatches[@]}"
  exit 1
fi

echo "[OK] runtime sync verification passed"
