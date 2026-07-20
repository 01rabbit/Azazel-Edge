# Azazel-Edge macOS dev environment.
# Source this before running web / control daemon / AI agent / rust core on a dev Mac:
#   source tools/macdev/env.sh
# All runtime state is kept under $AZAZEL_DEV_STATE (default: ~/.azazel-edge-dev)
# instead of the Linux-only /run, /var/log, /etc paths used on the appliance.

_MACDEV_SELF="${BASH_SOURCE[0]:-$0}"
ROOT_DIR="$(cd "$(dirname "${_MACDEV_SELF}")/../.." && pwd)"

export AZAZEL_DEV_STATE="${AZAZEL_DEV_STATE:-$HOME/.azazel-edge-dev}"
RUN_DIR="$AZAZEL_DEV_STATE/run"
LOG_DIR="$AZAZEL_DEV_STATE/log"
LIB_DIR="$AZAZEL_DEV_STATE/lib"
mkdir -p "$RUN_DIR/triage-sessions" "$LOG_DIR" "$LIB_DIR" "$AZAZEL_DEV_STATE/suricata"

export PYTHONPATH="$ROOT_DIR:$ROOT_DIR/py${PYTHONPATH:+:$PYTHONPATH}"

# --- web ---
export AZAZEL_WEB_HOST="${AZAZEL_WEB_HOST:-127.0.0.1}"
export AZAZEL_WEB_PORT="${AZAZEL_WEB_PORT:-8084}"
export AZAZEL_WEB_TOKEN_FILE="$AZAZEL_DEV_STATE/web_token.txt"
export AZAZEL_AUTH_TOKENS_FILE="$AZAZEL_DEV_STATE/auth_tokens.json"
export AZAZEL_AUTHZ_AUDIT_LOG="$LOG_DIR/authz-events.jsonl"
export AZAZEL_CAPTIVE_REGISTRY_PATH="$LIB_DIR/captive-allowlist.json"
export AZAZEL_DASHBOARD_TRENDS_PATH="$RUN_DIR/dashboard-trends.jsonl"
export AZAZEL_AGGREGATOR_AUDIT_LOG="$LOG_DIR/aggregator-events.jsonl"
export AZAZEL_TOPOLITE_SEED_MODE_PATH="$RUN_DIR/topolite_seed_mode.json"
export AZAZEL_SOT_AUDIT_LOG="$LOG_DIR/sot-events.jsonl"
export AZAZEL_TRIAGE_SESSION_DIR="$RUN_DIR/triage-sessions"
export AZAZEL_OPERATOR_PROGRESS_PATH="$RUN_DIR/operator-progress.json"
export AZAZEL_RUNBOOK_EVENT_LOG="$LOG_DIR/runbook-events.jsonl"
export AZAZEL_TRIAGE_AUDIT_PATH="$LOG_DIR/triage-audit.jsonl"

# --- control plane / daemon ---
export AZAZEL_CONTROL_SOCKET="$RUN_DIR/control.sock"
export AZAZEL_DEFENSE_DRY_RUN=true

# --- AI agent ---
export AZAZEL_AI_SOCKET="$RUN_DIR/ai-bridge.sock"
export AZAZEL_AI_ADVISORY="$RUN_DIR/ai_advisory.json"
export AZAZEL_AI_METRICS="$RUN_DIR/ai_metrics.json"
export AZAZEL_AI_POLICY="$RUN_DIR/ai_runtime_policy.json"
export AZAZEL_AI_EVENT_LOG="$LOG_DIR/ai-events.jsonl"
export AZAZEL_AI_LLM_LOG="$LOG_DIR/ai-llm.jsonl"
export AZAZEL_AI_DEFERRED_LOG="$LOG_DIR/ai-deferred.jsonl"
export AZAZEL_AI_AUDIT_LOG="$LOG_DIR/ai-audit.jsonl"
export AZAZEL_UI_SNAPSHOT="$RUN_DIR/ui_snapshot.json"
export AZAZEL_OLLAMA_ENDPOINT="${AZAZEL_OLLAMA_ENDPOINT:-http://127.0.0.1:11434}"
# Mac dev has plenty of RAM/CPU compared to the Pi: allow longer JSON completions
# (the Pi defaults num_predict=48 / num_ctx=256 truncate qwen3.5:2b JSON mid-string).
export AZAZEL_LLM_NUM_PREDICT="${AZAZEL_LLM_NUM_PREDICT:-192}"
export AZAZEL_LLM_NUM_CTX="${AZAZEL_LLM_NUM_CTX:-1024}"
export AZAZEL_LLM_NUM_THREAD="${AZAZEL_LLM_NUM_THREAD:-4}"

export AZAZEL_DECISION_LOG_DIR="$LOG_DIR/tactics_engine"

# --- dev healthy baseline ---
# Dev host lacks systemd services and the Linux link/route/dns probes, so the
# dashboard would otherwise show SERVICES OFF / PATH DEGRADED at idle. This
# dev-only override presents a clean SAFE baseline (services ON, network health
# SAFE, live NOC projection skipped) so an idle board is green and an injected
# attack produces a clear visual change. NEVER set this on an appliance.
export AZAZEL_DEV_HEALTHY_BASELINE="${AZAZEL_DEV_HEALTHY_BASELINE:-1}"

# --- rust core ---
export AZAZEL_EVE_PATH="$AZAZEL_DEV_STATE/suricata/eve.json"
export AZAZEL_NORMALIZED_EVENT_LOG="$LOG_DIR/normalized-events.jsonl"
export AZAZEL_DEFENSE_ENFORCE_LEVEL="${AZAZEL_DEFENSE_ENFORCE_LEVEL:-advisory}"

# one-time web token
if [[ ! -s "$AZAZEL_WEB_TOKEN_FILE" ]]; then
  python3 -c "import secrets; print(secrets.token_urlsafe(24))" > "$AZAZEL_WEB_TOKEN_FILE"
fi

unset _MACDEV_SELF RUN_DIR LOG_DIR LIB_DIR
