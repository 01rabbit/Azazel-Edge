#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

ENV_FILE="${AZAZEL_WEB_ENV_FILE:-/etc/default/azazel-edge-web}"
TOKEN_FILE="${AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE:-/etc/azazel-edge/mattermost-command-token}"
TRIGGER="${AZAZEL_MATTERMOST_COMMAND_TRIGGER:-azops}"
DISPLAY_NAME="${AZAZEL_MATTERMOST_COMMAND_NAME:-Azazel Ops AI}"
DESCRIPTION="${AZAZEL_MATTERMOST_COMMAND_DESCRIPTION:-Query Azazel-Edge AI from Mattermost}"
AUTOCOMPLETE_DESC="${AZAZEL_MATTERMOST_COMMAND_AUTOCOMPLETE_DESC:-Ask Azazel-Edge AI for SOC/NOC support}"
AUTOCOMPLETE_HINT="${AZAZEL_MATTERMOST_COMMAND_AUTOCOMPLETE_HINT:-<question>}"
COMMAND_URL="${AZAZEL_MATTERMOST_COMMAND_URL:-http://172.16.0.254/api/mattermost/command}"
MATTERMOST_URL_DEFAULT="${AZAZEL_MATTERMOST_URL:-http://127.0.0.1:8065}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[ERROR] env file not found: ${ENV_FILE}"
  exit 1
fi

set -a
source "${ENV_FILE}"
set +a

MATTERMOST_URL="${AZAZEL_MATTERMOST_API_URL:-${MATTERMOST_URL_DEFAULT}}"
TEAM_NAME="${AZAZEL_MATTERMOST_TEAM:-azazelops}"
BOT_TOKEN="${AZAZEL_MATTERMOST_BOT_TOKEN:-}"

if [[ -z "${BOT_TOKEN}" ]]; then
  echo "[ERROR] AZAZEL_MATTERMOST_BOT_TOKEN is not set in ${ENV_FILE}"
  exit 1
fi

api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  if [[ -n "${body}" ]]; then
    curl -fsS -X "${method}" \
      -H "Authorization: Bearer ${BOT_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "${body}" \
      "${MATTERMOST_URL}${path}"
  else
    curl -fsS -X "${method}" \
      -H "Authorization: Bearer ${BOT_TOKEN}" \
      "${MATTERMOST_URL}${path}"
  fi
}

TEAM_JSON="$(api GET "/api/v4/teams/name/${TEAM_NAME}")"
TEAM_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"${TEAM_JSON}")"

COMMANDS_JSON="$(api GET "/api/v4/commands?team_id=${TEAM_ID}")"
EXISTING_ID="$(printf '%s' "${COMMANDS_JSON}" | python3 -c 'import json,sys; trigger=sys.argv[1]; print(next((item.get("id","") for item in json.load(sys.stdin) if item.get("trigger")==trigger), ""))' "${TRIGGER}")"

read -r -d '' PAYLOAD <<EOF || true
{
  "team_id": "${TEAM_ID}",
  "trigger": "${TRIGGER}",
  "method": "P",
  "username": "azazelops",
  "auto_complete": true,
  "auto_complete_desc": "${AUTOCOMPLETE_DESC}",
  "auto_complete_hint": "${AUTOCOMPLETE_HINT}",
  "display_name": "${DISPLAY_NAME}",
  "description": "${DESCRIPTION}",
  "url": "${COMMAND_URL}"
}
EOF

if [[ -n "${EXISTING_ID}" ]]; then
  RESPONSE="$(printf '{"id":"%s"}' "${EXISTING_ID}")"
else
  RESPONSE="$(api POST "/api/v4/commands" "${PAYLOAD}")"
fi

COMMAND_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' <<<"${RESPONSE}")"
COMMAND_TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' <<<"${RESPONSE}")"

if [[ -z "${COMMAND_ID}" ]]; then
  echo "[ERROR] command provisioning failed"
  exit 1
fi

if [[ -z "${COMMAND_TOKEN}" && -n "${EXISTING_ID}" ]]; then
  COMMAND_TOKEN="$(printf '%s' "${COMMANDS_JSON}" | python3 -c 'import json,sys; trigger=sys.argv[1]; print(next((item.get("token","") for item in json.load(sys.stdin) if item.get("trigger")==trigger), ""))' "${TRIGGER}")"
fi

if [[ -z "${COMMAND_TOKEN}" && -f "${TOKEN_FILE}" ]]; then
  COMMAND_TOKEN="$(tr -d '\r\n' < "${TOKEN_FILE}")"
fi

if [[ -z "${COMMAND_TOKEN}" ]]; then
  echo "[ERROR] command token is empty"
  exit 1
fi

install -d -m 0755 "$(dirname "${TOKEN_FILE}")"
printf '%s\n' "${COMMAND_TOKEN}" > "${TOKEN_FILE}"
chmod 0600 "${TOKEN_FILE}"

systemctl restart azazel-edge-web

echo "[OK] Mattermost slash command provisioned"
echo "trigger=${TRIGGER}"
echo "command_id=${COMMAND_ID}"
echo "callback_url=${COMMAND_URL}"
echo "token_file=${TOKEN_FILE}"
