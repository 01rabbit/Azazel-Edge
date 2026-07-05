#!/usr/bin/env bash
# Dev twin of installer/internal/provision_mattermost_workspace.sh +
# provision_mattermost_command.sh for the macOS/OrbStack dev stack.
#
# The installer scripts assume the appliance (root, /etc/azazel-edge,
# systemctl); this script provisions the SAME workspace shape -- admin user,
# team, channel, bot token, incoming webhook, /mio + /azops slash commands --
# against the dev Mattermost on localhost:8065 and writes credentials under
# $AZAZEL_DEV_STATE so bin/azazel-edge-devstack can hand them to the web app.
#
# Idempotent: safe to re-run; existing resources are reused.
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/env.sh"

MM_CONTAINER="${AZAZEL_MATTERMOST_CONTAINER:-azazel-edge-mattermost}"
API_URL="${AZAZEL_MATTERMOST_API_URL:-http://127.0.0.1:8065}"
BASE_URL="${AZAZEL_MATTERMOST_BASE_URL:-http://127.0.0.1:8065}"

MM_USERNAME="${AZAZEL_MATTERMOST_USERNAME:-azazelops}"
MM_EMAIL="${AZAZEL_MATTERMOST_EMAIL:-azazel.ops@example.local}"
MM_PASSWORD="${AZAZEL_MATTERMOST_PASSWORD:-AzazelOps!2026}"
MM_TEAM="${AZAZEL_MATTERMOST_TEAM:-azazelops}"
MM_TEAM_DISPLAY="${AZAZEL_MATTERMOST_TEAM_DISPLAY_NAME:-Azazel Ops}"
MM_CHANNEL="${AZAZEL_MATTERMOST_CHANNEL:-soc-noc}"
MM_CHANNEL_DISPLAY="${AZAZEL_MATTERMOST_CHANNEL_DISPLAY_NAME:-SOC-NOC}"

WEB_ENV="${AZAZEL_WEB_ENV_FILE:-${AZAZEL_DEV_STATE}/mattermost-web.env}"
CRED_ENV="${AZAZEL_MATTERMOST_CREDENTIALS_FILE:-${AZAZEL_DEV_STATE}/mattermost-credentials.env}"
COMMAND_TOKEN_FILE="${AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE:-${AZAZEL_DEV_STATE}/mattermost-command-token}"
# Slash-command callback: the Mattermost container reaches the host web app
# via host.docker.internal (devstack starts the container with that host in
# AllowedUntrustedInternalConnections).
COMMAND_URL="${AZAZEL_MATTERMOST_COMMAND_URL:-http://host.docker.internal:${AZAZEL_WEB_PORT}/api/mattermost/command}"
COMMAND_TRIGGER="${AZAZEL_MATTERMOST_COMMAND_TRIGGER:-mio}"
COMMAND_ALIASES="${AZAZEL_MATTERMOST_COMMAND_ALIASES:-azops}"

AUTH_TOKEN=""; USER_ID=""; TEAM_ID=""; CHANNEL_ID=""; BOT_TOKEN=""; WEBHOOK_URL=""
LAST_STATUS=""; LAST_BODY=""; LAST_HEADERS=""

info() { printf '[dev-mm] %s\n' "$*"; }
fail() { printf '[dev-mm] ERROR: %s\n' "$*" >&2; exit 1; }

json_get() {
  python3 -c 'import json,sys; obj=json.load(sys.stdin); value=eval(sys.argv[1], {"obj": obj}); print("" if value is None else value)' "$1"
}

api_call() {
  local method="$1" path="$2" body="${3:-}" token="${4:-${AUTH_TOKEN}}"
  local headers_file body_file
  headers_file="$(mktemp)"; body_file="$(mktemp)"
  local curl_args=(-sS -D "${headers_file}" -o "${body_file}" -X "${method}" "${API_URL}${path}")
  [[ -n "${token}" ]] && curl_args+=(-H "Authorization: Bearer ${token}")
  [[ -n "${body}" ]] && curl_args+=(-H "Content-Type: application/json" --data "${body}")
  LAST_STATUS="$(curl "${curl_args[@]}" -w "%{http_code}")"
  LAST_HEADERS="$(cat "${headers_file}")"
  LAST_BODY="$(cat "${body_file}")"
  rm -f "${headers_file}" "${body_file}"
}

mmctl_local() { docker exec "${MM_CONTAINER}" mmctl --local "$@"; }

wait_for_ping() {
  local i
  for i in $(seq 1 45); do
    curl -fsS "${API_URL}/api/v4/system/ping" >/dev/null 2>&1 && return 0
    sleep 2
  done
  fail "Mattermost API not ready at ${API_URL} (run: bin/azazel-edge-devstack up)"
}

# On the appliance the provisioned user is the first real user and becomes
# system admin implicitly. In dev the Calls plugin bot may already exist, so
# promote explicitly and enable personal access tokens via local mode.
ensure_admin_user() {
  if ! mmctl_local user list 2>/dev/null | grep -q "(${MM_EMAIL})"; then
    mmctl_local user create --email "${MM_EMAIL}" --username "${MM_USERNAME}" \
      --password "${MM_PASSWORD}" --email-verified --system-admin \
      || fail "mmctl user create failed"
    info "user ${MM_USERNAME} created (system admin)"
  else
    mmctl_local roles system_admin "${MM_USERNAME}" >/dev/null
    info "user ${MM_USERNAME} already exists (system admin ensured)"
  fi
  mmctl_local config set ServiceSettings.EnableUserAccessTokens true >/dev/null
  mmctl_local config set ServiceSettings.EnableIncomingWebhooks true >/dev/null
  mmctl_local config set ServiceSettings.EnableCommands true >/dev/null
}

login() {
  api_call POST /api/v4/users/login "{\"login_id\":\"${MM_EMAIL}\",\"password\":\"${MM_PASSWORD}\"}" ""
  [[ "${LAST_STATUS}" == "200" ]] || fail "login failed: ${LAST_STATUS} ${LAST_BODY}"
  AUTH_TOKEN="$(printf '%s\n' "${LAST_HEADERS}" | awk 'BEGIN{IGNORECASE=1} /^Token:/{print $2}' | tr -d '\r')"
  USER_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
  [[ -n "${AUTH_TOKEN}" && -n "${USER_ID}" ]] || fail "no session token from login"
}

ensure_team() {
  api_call GET "/api/v4/teams/name/${MM_TEAM}"
  if [[ "${LAST_STATUS}" == "200" ]]; then
    TEAM_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
  else
    api_call POST /api/v4/teams "{\"name\":\"${MM_TEAM}\",\"display_name\":\"${MM_TEAM_DISPLAY}\",\"type\":\"O\"}"
    [[ "${LAST_STATUS}" == "200" || "${LAST_STATUS}" == "201" ]] || fail "team create: ${LAST_STATUS} ${LAST_BODY}"
    TEAM_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
  fi
  api_call POST "/api/v4/teams/${TEAM_ID}/members" "{\"team_id\":\"${TEAM_ID}\",\"user_id\":\"${USER_ID}\"}"
  info "team ${MM_TEAM} ready (${TEAM_ID})"
}

ensure_channel() {
  api_call GET "/api/v4/teams/name/${MM_TEAM}/channels/name/${MM_CHANNEL}"
  if [[ "${LAST_STATUS}" == "200" ]]; then
    CHANNEL_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
  else
    api_call POST /api/v4/channels "{\"team_id\":\"${TEAM_ID}\",\"name\":\"${MM_CHANNEL}\",\"display_name\":\"${MM_CHANNEL_DISPLAY}\",\"type\":\"O\"}"
    [[ "${LAST_STATUS}" == "200" || "${LAST_STATUS}" == "201" ]] || fail "channel create: ${LAST_STATUS} ${LAST_BODY}"
    CHANNEL_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
  fi
  api_call POST "/api/v4/channels/${CHANNEL_ID}/members" "{\"user_id\":\"${USER_ID}\"}"
  info "channel ${MM_CHANNEL} ready (${CHANNEL_ID})"
}

ensure_bot_token() {
  if [[ -f "${WEB_ENV}" ]]; then
    local existing
    existing="$(sed -n 's/^AZAZEL_MATTERMOST_BOT_TOKEN=//p' "${WEB_ENV}" | tail -1)"
    if [[ -n "${existing}" ]]; then
      local status
      status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${existing}" "${API_URL}/api/v4/users/me" || true)"
      if [[ "${status}" == "200" ]]; then
        BOT_TOKEN="${existing}"
        info "bot token reused from ${WEB_ENV}"
        return 0
      fi
    fi
  fi
  api_call POST "/api/v4/users/${USER_ID}/tokens" '{"description":"Azazel-Edge WebUI bot token (dev)"}'
  [[ "${LAST_STATUS}" == "200" || "${LAST_STATUS}" == "201" ]] || fail "bot token: ${LAST_STATUS} ${LAST_BODY}"
  BOT_TOKEN="$(printf '%s' "${LAST_BODY}" | json_get 'obj["token"]')"
  info "bot token created"
}

ensure_webhook() {
  api_call GET "/api/v4/hooks/incoming?per_page=200"
  if [[ "${LAST_STATUS}" == "200" ]]; then
    local hook_id
    hook_id="$(printf '%s' "${LAST_BODY}" | python3 -c 'import json,sys; ch=sys.argv[1]; hooks=json.load(sys.stdin); print(next((h["id"] for h in hooks if h.get("channel_id")==ch), ""))' "${CHANNEL_ID}")"
    if [[ -n "${hook_id}" ]]; then
      WEBHOOK_URL="${BASE_URL}/hooks/${hook_id}"
      info "incoming webhook reused"
      return 0
    fi
  fi
  api_call POST /api/v4/hooks/incoming "{\"channel_id\":\"${CHANNEL_ID}\",\"display_name\":\"Azazel Edge WebUI\",\"description\":\"Azazel Edge WebUI bridge (dev)\",\"username\":\"Azazel-Edge WebUI\"}"
  [[ "${LAST_STATUS}" == "200" || "${LAST_STATUS}" == "201" ]] || fail "webhook: ${LAST_STATUS} ${LAST_BODY}"
  WEBHOOK_URL="${BASE_URL}/hooks/$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
  info "incoming webhook created"
}

ensure_command() {
  local trigger="$1" token_path="$2"
  api_call GET "/api/v4/commands?team_id=${TEAM_ID}&custom_only=true"
  local existing_token
  existing_token="$(printf '%s' "${LAST_BODY}" | python3 -c 'import json,sys; t=sys.argv[1]; print(next((c.get("token","") for c in json.load(sys.stdin) if c.get("trigger")==t), ""))' "${trigger}")"
  if [[ -z "${existing_token}" ]]; then
    api_call POST /api/v4/commands "{\"team_id\":\"${TEAM_ID}\",\"trigger\":\"${trigger}\",\"method\":\"P\",\"username\":\"${MM_USERNAME}\",\"auto_complete\":true,\"auto_complete_desc\":\"Ask M.I.O. for SOC/NOC support\",\"auto_complete_hint\":\"<question>\",\"display_name\":\"M.I.O. Ops AI\",\"description\":\"Query M.I.O. from Mattermost\",\"url\":\"${COMMAND_URL}\"}"
    [[ "${LAST_STATUS}" == "200" || "${LAST_STATUS}" == "201" ]] || fail "command /${trigger}: ${LAST_STATUS} ${LAST_BODY}"
    existing_token="$(printf '%s' "${LAST_BODY}" | json_get 'obj["token"]')"
    info "slash command /${trigger} created -> ${COMMAND_URL}"
  else
    info "slash command /${trigger} already registered"
  fi
  printf '%s\n' "${existing_token}" > "${token_path}"
  chmod 0600 "${token_path}"
}

write_outputs() {
  cat > "${CRED_ENV}" <<EOF
MATTERMOST_USERNAME=${MM_USERNAME}
MATTERMOST_EMAIL=${MM_EMAIL}
MATTERMOST_PASSWORD=${MM_PASSWORD}
MATTERMOST_URL=${BASE_URL}
MATTERMOST_TEAM=${MM_TEAM}
MATTERMOST_CHANNEL=${MM_CHANNEL}
EOF
  chmod 0600 "${CRED_ENV}"

  cat > "${WEB_ENV}" <<EOF
AZAZEL_MATTERMOST_HOST=127.0.0.1
AZAZEL_MATTERMOST_PORT=8065
AZAZEL_MATTERMOST_TEAM=${MM_TEAM}
AZAZEL_MATTERMOST_CHANNEL=${MM_CHANNEL}
AZAZEL_MATTERMOST_BASE_URL=${BASE_URL}
AZAZEL_MATTERMOST_OPEN_URL=${BASE_URL}/${MM_TEAM}/channels/${MM_CHANNEL}
AZAZEL_MATTERMOST_WEBHOOK_URL=${WEBHOOK_URL}
AZAZEL_MATTERMOST_BOT_TOKEN=${BOT_TOKEN}
AZAZEL_MATTERMOST_CHANNEL_ID=${CHANNEL_ID}
AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE=${COMMAND_TOKEN_FILE}
EOF
  chmod 0600 "${WEB_ENV}"
}

wait_for_ping
ensure_admin_user
login
ensure_team
ensure_channel
ensure_bot_token
ensure_webhook
ensure_command "${COMMAND_TRIGGER}" "${COMMAND_TOKEN_FILE}"
if [[ -n "${COMMAND_ALIASES}" ]]; then
  IFS=',' read -r -a alias_items <<<"${COMMAND_ALIASES}"
  for alias in "${alias_items[@]}"; do
    alias="$(echo "${alias}" | xargs)"
    [[ -z "${alias}" || "${alias}" == "${COMMAND_TRIGGER}" ]] && continue
    ensure_command "${alias}" "${COMMAND_TOKEN_FILE}.${alias}"
  done
fi
write_outputs

info "workspace provisioned"
info "  login:    ${MM_EMAIL} / (password in ${CRED_ENV})"
info "  channel:  ${BASE_URL}/${MM_TEAM}/channels/${MM_CHANNEL}"
info "  web env:  ${WEB_ENV}"
info "restart the web app to pick this up: bin/azazel-edge-devstack restart"
