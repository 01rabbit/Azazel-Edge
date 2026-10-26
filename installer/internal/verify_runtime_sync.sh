#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
# Without an argument the default is the checkout this script sits in. The
# installed copies (/opt/azazel-edge/verify_runtime_sync.sh and
# /usr/local/bin/azazel-edge-runtime-sync-check) are not in one, so there the
# checkout must be given: otherwise "/" or "/usr" would be compared and every
# file reported missing.
if [[ $# -lt 1 && ! -f "$REPO_ROOT/installer/internal/verify_runtime_sync.sh" ]]; then
  echo "[ERROR] not run from a repository checkout: give it as the first argument, e.g. $0 /home/azazel/Azazel-Edge" >&2
  exit 2
fi
RUNTIME_ROOT="${2:-/opt/azazel-edge}"
# with-rust-core (the default) or without-rust-core: whether the installer
# built the Rust core (ENABLE_RUST_CORE), so whether its sources are compared.
RUST_CORE="${3:-with-rust-core}"
case "$RUST_CORE" in
  with-rust-core|without-rust-core) ;;
  *) echo "[ERROR] third argument must be with-rust-core or without-rust-core: $RUST_CORE" >&2; exit 2 ;;
esac

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
azazel_edge_web/auth.py
azazel_edge_web/io_helpers.py
py/azazel_edge/__init__.py
py/azazel_edge/control_plane.py
py/azazel_edge/peercred.py
py/azazel_edge/path_schema.py
py/azazel_edge/ai_governance.py
py/azazel_edge/config_drift.py
py/azazel_edge/scenario_replay.py
py/azazel_edge/dummy_eve.py
py/azazel_edge/opencanary_redirect.py
py/azazel_edge/runbooks.py
py/azazel_edge/runbook_review.py
py/azazel_edge/_util.py
py/azazel_edge/aggregator.py
py/azazel_edge/audit_review.py
py/azazel_edge/deception_effectiveness_client.py
py/azazel_edge/deception_shadow.py
py/azazel_edge/decision_layers.py
py/azazel_edge/fabric_view.py
py/azazel_edge/i18n.py
py/azazel_edge/policy.py
py/azazel_edge/snapshot_model.py
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
config/soc_policy.yaml
config/attack_mapping.yaml
bin/azazel-edge-scenario-replay
bin/azazel-edge-dummy-eve
bin/azazel-edge-audit-review
bin/azazel-edge-web
bin/azazel-edge-ai-agent
bin/azazel-edge-control-daemon
bin/azazel-edge-epd
bin/azazel-edge-epd-refresh
bin/azazel-edge-runbook-broker
EOF

mapfile -t DIRS <<'EOF'
azazel_edge_web/static
azazel_edge_web/templates
py/azazel_edge/arbiter
py/azazel_edge/audit
py/azazel_edge/correlation
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

mapfile -t RUST_FILES <<'EOF'
rust/azazel-edge-core/Cargo.toml
rust/azazel-edge-core/Cargo.lock
EOF
mapfile -t RUST_DIRS <<'EOF'
rust/azazel-edge-core/src
EOF
if [[ "$RUST_CORE" == "with-rust-core" ]]; then
  FILES+=("${RUST_FILES[@]}")
  DIRS+=("${RUST_DIRS[@]}")
fi

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
  done < <(find "$src" -type f \( -name '*.py' -o -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.yaml' -o -name '*.yml' -o -name '*.png' -o -name '*.ttf' -o -name 'Dockerfile' -o -name '.env' -o -name '*.rs' \) -print0 | sort -z)
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
