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
# A state directory created here holds the web token: create it 0700 (an
# existing one is left as it is).
[[ -d "$AZAZEL_DEV_STATE" ]] || mkdir -p -m 700 "$AZAZEL_DEV_STATE"
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
export AZAZEL_AI_SOCKET="$RUN_DIR/ai/ai-bridge.sock"
# The agent's manual_query socket for the Web UI (Edge#471 stage 1). The Web
# UI itself reads AZAZEL_AI_SOCKET; bin/azazel-edge-devstack gives the Web UI
# its own value (this socket, or ai-bridge.sock when the agent has none).
export AZAZEL_AI_QUERY_SOCKET="$RUN_DIR/ai-query/agent-query.sock"
# The agent's own runtime directory (Edge#471 stage 2): it refuses a directory
# others can write, such as the control daemon's RUN_DIR (0770).
export AZAZEL_AI_ADVISORY="$RUN_DIR/agent/ai_advisory.json"
export AZAZEL_AI_METRICS="$RUN_DIR/agent/ai_metrics.json"
export AZAZEL_AI_POLICY="$RUN_DIR/agent/ai_runtime_policy.json"
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

# Writes stdin to $1 without the content ever being in a file other than a
# private (0600) temp file in the same directory, then renames it onto $1.
# An existing regular target is replaced, not truncated. A symlink (to a file
# or a directory) or a non-regular target is refused: the content must land at
# exactly this path. umask stays in a subshell, so the caller's umask is never
# touched.
# The parent directory must be owned by the current user, not a symlink, and
# not group- or other-writable; with that, nobody else can swap paths in it,
# so the plain-file check plus the same-directory mv below are sufficient (no
# check-then-use race).
macdev_require_private_parent() {
  local dir wide
  dir="$(dirname -- "$1")"
  if [[ -L "${dir}" || ! -d "${dir}" || ! -O "${dir}" ]]; then
    echo "macdev: refusing to write secrets in ${dir}: it must be a real directory owned by you" >&2
    return 1
  fi
  # Fail closed: if find cannot judge the mode, the directory is not trusted.
  if ! wide="$(find "${dir}" -maxdepth 0 \( -perm -020 -o -perm -002 \) 2>/dev/null)" || [[ -n "${wide}" ]]; then
    echo "macdev: refusing to write secrets in ${dir}: it is group/other-writable or its mode could not be checked" >&2
    return 1
  fi
}

macdev_write_private_file() {
  local dst="$1" tmp
  macdev_require_private_parent "${dst}" || return 1
  if [[ -L "${dst}" || ( -e "${dst}" && ! -f "${dst}" ) ]]; then
    echo "macdev: refusing to write ${dst}: not a plain file (symlink or directory)" >&2
    return 1
  fi
  tmp="$( (umask 077; mktemp "${dst}.XXXXXX") )" || return 1
  if ! cat > "${tmp}" || ! chmod 0600 "${tmp}" || ! mv -f -- "${tmp}" "${dst}"; then
    rm -f -- "${tmp}"
    return 1
  fi
}

# One-time web token. A valid existing token is kept and only tightened to
# 0600; a symlink or non-regular file is refused; a generation or save failure
# is the exit status of `source` (no set -e needed).
_macdev_ensure_web_token() {
  local f="$AZAZEL_WEB_TOKEN_FILE" tok
  macdev_require_private_parent "$f" || return 1
  if [[ -L "$f" || ( -e "$f" && ! -f "$f" ) ]]; then
    echo "macdev: $f is a symlink or not a regular file; refusing" >&2
    return 1
  fi
  if [[ -s "$f" ]]; then
    chmod 0600 "$f" || return 1
    return 0
  fi
  tok="$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")" || return 1
  [[ -n "$tok" ]] || { echo "macdev: token generator produced no output" >&2; return 1; }
  printf '%s\n' "$tok" | macdev_write_private_file "$f"
}
_macdev_ensure_web_token
_macdev_rc=$?
unset -f _macdev_ensure_web_token

unset _MACDEV_SELF RUN_DIR LOG_DIR LIB_DIR
if [[ "${_macdev_rc}" -ne 0 ]]; then unset _macdev_rc; return 1; fi
unset _macdev_rc
