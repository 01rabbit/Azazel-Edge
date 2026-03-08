#!/usr/bin/env bash
set -euo pipefail

WEB_ENV="${AZAZEL_WEB_ENV_FILE:-/etc/default/azazel-edge-web}"
CRED_ENV="${AZAZEL_MATTERMOST_CREDENTIALS_FILE:-/etc/azazel-edge/mattermost-credentials.env}"
MATTERMOST_API_URL="${AZAZEL_MATTERMOST_API_URL:-http://127.0.0.1:8065}"
MATTERMOST_HOST_PUBLIC="${AZAZEL_MATTERMOST_PUBLIC_HOST:-172.16.0.254}"
MATTERMOST_PORT_PUBLIC="${AZAZEL_MATTERMOST_PUBLIC_PORT:-8065}"
MATTERMOST_USERNAME="${AZAZEL_MATTERMOST_USERNAME:-azazelops}"
MATTERMOST_EMAIL="${AZAZEL_MATTERMOST_EMAIL:-azazel.ops@example.local}"
MATTERMOST_PASSWORD="${AZAZEL_MATTERMOST_PASSWORD:-AzazelOps!2026}"
MATTERMOST_TEAM="${AZAZEL_MATTERMOST_TEAM:-azazelops}"
MATTERMOST_TEAM_DISPLAY_NAME="${AZAZEL_MATTERMOST_TEAM_DISPLAY_NAME:-Azazel Ops}"
MATTERMOST_CHANNEL="${AZAZEL_MATTERMOST_CHANNEL:-soc-noc}"
MATTERMOST_CHANNEL_DISPLAY_NAME="${AZAZEL_MATTERMOST_CHANNEL_DISPLAY_NAME:-SOC-NOC}"
MATTERMOST_WEBHOOK_DESCRIPTION="${AZAZEL_MATTERMOST_WEBHOOK_DESCRIPTION:-Azazel Edge WebUI bridge}"
MATTERMOST_BOT_TOKEN_DESCRIPTION="${AZAZEL_MATTERMOST_BOT_TOKEN_DESCRIPTION:-Azazel-Edge WebUI bot token}"

LAST_STATUS=""
LAST_BODY=""
LAST_HEADERS=""
AUTH_TOKEN=""
USER_ID=""
TEAM_ID=""
CHANNEL_ID=""
BOT_TOKEN=""
WEBHOOK_URL=""

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

if [[ -f "${WEB_ENV}" ]]; then
  set -a
  source "${WEB_ENV}"
  set +a
fi

PUBLIC_BASE_URL="${AZAZEL_MATTERMOST_BASE_URL:-http://${MATTERMOST_HOST_PUBLIC}:${MATTERMOST_PORT_PUBLIC}}"
PUBLIC_OPEN_URL="${AZAZEL_MATTERMOST_OPEN_URL:-${PUBLIC_BASE_URL}/${MATTERMOST_TEAM}/channels/${MATTERMOST_CHANNEL}}"

wait_for_ping() {
  local i
  for i in $(seq 1 90); do
    if curl -fsS "${MATTERMOST_API_URL}/api/v4/system/ping" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "[ERROR] Mattermost API not ready at ${MATTERMOST_API_URL}"
  exit 1
}

json_get() {
  local expr="$1"
  python3 -c 'import json,sys; obj=json.load(sys.stdin); value=eval(sys.argv[1], {"obj": obj}); print("" if value is None else value)' "${expr}"
}

api_call() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local token="${4:-${AUTH_TOKEN}}"
  local headers_file body_file
  headers_file="$(mktemp)"
  body_file="$(mktemp)"
  local curl_args=(-sS -D "${headers_file}" -o "${body_file}" -X "${method}" "${MATTERMOST_API_URL}${path}")
  if [[ -n "${token}" ]]; then
    curl_args+=(-H "Authorization: Bearer ${token}")
  fi
  if [[ -n "${body}" ]]; then
    curl_args+=(-H "Content-Type: application/json" --data "${body}")
  fi
  LAST_STATUS="$(curl "${curl_args[@]}" -w "%{http_code}")"
  LAST_HEADERS="$(cat "${headers_file}")"
  LAST_BODY="$(cat "${body_file}")"
  rm -f "${headers_file}" "${body_file}"
}

upsert_env() {
  local file="$1"
  local key="$2"
  local value="$3"
  install -d -m 0755 "$(dirname "${file}")"
  touch "${file}"
  if grep -q "^${key}=" "${file}" 2>/dev/null; then
    sed -i "s#^${key}=.*#${key}=${value}#" "${file}"
  else
    printf '%s=%s\n' "${key}" "${value}" >>"${file}"
  fi
}

login_admin() {
  api_call POST /api/v4/users/login "{\"login_id\":\"${MATTERMOST_EMAIL}\",\"password\":\"${MATTERMOST_PASSWORD}\"}" ""
  if [[ "${LAST_STATUS}" == "200" ]]; then
    AUTH_TOKEN="$(printf '%s\n' "${LAST_HEADERS}" | awk 'BEGIN{IGNORECASE=1} /^Token:/{print $2}' | tr -d '\r')"
    USER_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
    return 0
  fi
  return 1
}

bootstrap_admin() {
  api_call POST /api/v4/users "{\"email\":\"${MATTERMOST_EMAIL}\",\"username\":\"${MATTERMOST_USERNAME}\",\"password\":\"${MATTERMOST_PASSWORD}\"}" ""
  case "${LAST_STATUS}" in
    200|201|400) ;;
    *)
      echo "[ERROR] user bootstrap failed with status ${LAST_STATUS}: ${LAST_BODY}"
      exit 1
      ;;
  esac
  if ! login_admin; then
    echo "[ERROR] unable to login after bootstrap: ${LAST_STATUS} ${LAST_BODY}"
    exit 1
  fi
}

ensure_admin_session() {
  if ! login_admin; then
    if [[ "${LAST_STATUS}" != "401" && "${LAST_STATUS}" != "404" ]]; then
      echo "[ERROR] unexpected login status ${LAST_STATUS}: ${LAST_BODY}"
      exit 1
    fi
    bootstrap_admin
  fi
  if [[ -z "${AUTH_TOKEN}" || -z "${USER_ID}" ]]; then
    echo "[ERROR] Mattermost admin session incomplete"
    exit 1
  fi
}

ensure_team() {
  api_call GET "/api/v4/teams/name/${MATTERMOST_TEAM}"
  if [[ "${LAST_STATUS}" == "200" ]]; then
    TEAM_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
    return 0
  fi
  api_call POST /api/v4/teams "{\"name\":\"${MATTERMOST_TEAM}\",\"display_name\":\"${MATTERMOST_TEAM_DISPLAY_NAME}\",\"type\":\"O\"}"
  if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" ]]; then
    echo "[ERROR] team provisioning failed with status ${LAST_STATUS}: ${LAST_BODY}"
    exit 1
  fi
  TEAM_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
}

ensure_team_membership() {
  api_call POST "/api/v4/teams/${TEAM_ID}/members" "{\"team_id\":\"${TEAM_ID}\",\"user_id\":\"${USER_ID}\"}"
  case "${LAST_STATUS}" in
    200|201|400|403) ;;
    *)
      echo "[WARN] team membership status ${LAST_STATUS}: ${LAST_BODY}"
      ;;
  esac
}

ensure_channel() {
  api_call GET "/api/v4/teams/name/${MATTERMOST_TEAM}/channels/name/${MATTERMOST_CHANNEL}"
  if [[ "${LAST_STATUS}" == "200" ]]; then
    CHANNEL_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
    return 0
  fi
  api_call POST /api/v4/channels "{\"team_id\":\"${TEAM_ID}\",\"name\":\"${MATTERMOST_CHANNEL}\",\"display_name\":\"${MATTERMOST_CHANNEL_DISPLAY_NAME}\",\"type\":\"O\"}"
  if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" ]]; then
    echo "[ERROR] channel provisioning failed with status ${LAST_STATUS}: ${LAST_BODY}"
    exit 1
  fi
  CHANNEL_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
}

ensure_bot_token() {
  if [[ -n "${AZAZEL_MATTERMOST_BOT_TOKEN:-}" ]]; then
    local status
    status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${AZAZEL_MATTERMOST_BOT_TOKEN}" "${MATTERMOST_API_URL}/api/v4/users/me" || true)"
    if [[ "${status}" == "200" ]]; then
      BOT_TOKEN="${AZAZEL_MATTERMOST_BOT_TOKEN}"
      return 0
    fi
  fi
  api_call POST "/api/v4/users/${USER_ID}/tokens" "{\"description\":\"${MATTERMOST_BOT_TOKEN_DESCRIPTION}\"}"
  if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" ]]; then
    echo "[ERROR] bot token provisioning failed with status ${LAST_STATUS}: ${LAST_BODY}"
    exit 1
  fi
  BOT_TOKEN="$(printf '%s' "${LAST_BODY}" | json_get 'obj["token"]')"
}

ensure_webhook() {
  if [[ -n "${AZAZEL_MATTERMOST_WEBHOOK_URL:-}" ]]; then
    WEBHOOK_URL="${AZAZEL_MATTERMOST_WEBHOOK_URL}"
    return 0
  fi
  api_call POST /api/v4/hooks/incoming "{\"channel_id\":\"${CHANNEL_ID}\",\"display_name\":\"Azazel Edge WebUI\",\"description\":\"${MATTERMOST_WEBHOOK_DESCRIPTION}\",\"username\":\"Azazel-Edge WebUI\"}"
  if [[ "${LAST_STATUS}" != "200" && "${LAST_STATUS}" != "201" ]]; then
    echo "[ERROR] webhook provisioning failed with status ${LAST_STATUS}: ${LAST_BODY}"
    exit 1
  fi
  WEBHOOK_URL="${PUBLIC_BASE_URL}/hooks/$(printf '%s' "${LAST_BODY}" | json_get 'obj["token"]')"
}

write_outputs() {
  install -d -m 0755 /etc/azazel-edge
  cat > "${CRED_ENV}" <<EOF
MATTERMOST_USERNAME=${MATTERMOST_USERNAME}
MATTERMOST_EMAIL=${MATTERMOST_EMAIL}
MATTERMOST_PASSWORD=${MATTERMOST_PASSWORD}
MATTERMOST_URL=${PUBLIC_BASE_URL}
MATTERMOST_TEAM=${MATTERMOST_TEAM}
MATTERMOST_CHANNEL=${MATTERMOST_CHANNEL}
EOF
  chmod 0600 "${CRED_ENV}"

  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_HOST" "${MATTERMOST_HOST_PUBLIC}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_PORT" "${MATTERMOST_PORT_PUBLIC}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_TEAM" "${MATTERMOST_TEAM}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_CHANNEL" "${MATTERMOST_CHANNEL}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_BASE_URL" "${PUBLIC_BASE_URL}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_OPEN_URL" "${PUBLIC_OPEN_URL}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_WEBHOOK_URL" "${WEBHOOK_URL}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_BOT_TOKEN" "${BOT_TOKEN}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_CHANNEL_ID" "${CHANNEL_ID}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_TIMEOUT_SEC" "${AZAZEL_MATTERMOST_TIMEOUT_SEC:-8}"
  upsert_env "${WEB_ENV}" "AZAZEL_MATTERMOST_FETCH_LIMIT" "${AZAZEL_MATTERMOST_FETCH_LIMIT:-40}"
  upsert_env "${WEB_ENV}" "AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC" "${AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC:-0}"
}

wait_for_ping
ensure_admin_session
ensure_team
ensure_team_membership
ensure_channel
ensure_bot_token
ensure_webhook
write_outputs

echo "[OK] Mattermost workspace provisioned"
echo "base_url=${PUBLIC_BASE_URL}"
echo "team=${MATTERMOST_TEAM}"
echo "channel=${MATTERMOST_CHANNEL}"
echo "channel_id=${CHANNEL_ID}"
