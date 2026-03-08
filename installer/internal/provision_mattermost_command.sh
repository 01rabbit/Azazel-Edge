#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

ENV_FILE="${AZAZEL_WEB_ENV_FILE:-/etc/default/azazel-edge-web}"
TOKEN_FILE="${AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE:-/etc/azazel-edge/mattermost-command-token}"
TRIGGER="${AZAZEL_MATTERMOST_COMMAND_TRIGGER:-mio}"
ALIASES="${AZAZEL_MATTERMOST_COMMAND_ALIASES:-azops}"
DISPLAY_NAME="${AZAZEL_MATTERMOST_COMMAND_NAME:-M.I.O. Ops AI}"
DESCRIPTION="${AZAZEL_MATTERMOST_COMMAND_DESCRIPTION:-Query M.I.O. from Mattermost}"
AUTOCOMPLETE_DESC="${AZAZEL_MATTERMOST_COMMAND_AUTOCOMPLETE_DESC:-Ask M.I.O. for SOC/NOC support}"
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

provision_command() {
  local trigger="$1"
  local token_path="$2"
  local commands_json existing_id payload response command_id command_token

  commands_json="$(api GET "/api/v4/commands?team_id=${TEAM_ID}")"
  existing_id="$(printf '%s' "${commands_json}" | python3 -c 'import json,sys; trigger=sys.argv[1]; print(next((item.get("id","") for item in json.load(sys.stdin) if item.get("trigger")==trigger), ""))' "${trigger}")"

  read -r -d '' payload <<EOF || true
{
  "team_id": "${TEAM_ID}",
  "trigger": "${trigger}",
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

  if [[ -n "${existing_id}" ]]; then
    response="$(printf '{"id":"%s"}' "${existing_id}")"
  else
    response="$(api POST "/api/v4/commands" "${payload}")"
  fi

  command_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' <<<"${response}")"
  command_token="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' <<<"${response}")"

  if [[ -z "${command_id}" ]]; then
    echo "[ERROR] command provisioning failed for trigger=${trigger}"
    exit 1
  fi

  if [[ -z "${command_token}" && -n "${existing_id}" ]]; then
    command_token="$(printf '%s' "${commands_json}" | python3 -c 'import json,sys; trigger=sys.argv[1]; print(next((item.get("token","") for item in json.load(sys.stdin) if item.get("trigger")==trigger), ""))' "${trigger}")"
  fi

  if [[ -z "${command_token}" && -n "${existing_id}" ]]; then
    api DELETE "/api/v4/commands/${existing_id}" >/dev/null
    response="$(api POST "/api/v4/commands" "${payload}")"
    command_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' <<<"${response}")"
    command_token="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' <<<"${response}")"
  fi

  if [[ -z "${command_token}" && -f "${token_path}" ]]; then
    command_token="$(tr -d '\r\n' < "${token_path}")"
  fi

  if [[ -z "${command_token}" ]]; then
    echo "[ERROR] command token is empty for trigger=${trigger}"
    exit 1
  fi

  install -d -m 0755 "$(dirname "${token_path}")"
  printf '%s\n' "${command_token}" > "${token_path}"
  chmod 0600 "${token_path}"
  echo "[OK] Mattermost slash command provisioned"
  echo "trigger=${trigger}"
  echo "command_id=${command_id}"
  echo "callback_url=${COMMAND_URL}"
  echo "token_file=${token_path}"
}

provision_command "${TRIGGER}" "${TOKEN_FILE}"

if [[ -n "${ALIASES}" ]]; then
  IFS=',' read -r -a alias_items <<<"${ALIASES}"
  for alias in "${alias_items[@]}"; do
    alias="$(echo "${alias}" | xargs)"
    [[ -z "${alias}" ]] && continue
    [[ "${alias}" == "${TRIGGER}" ]] && continue
    provision_command "${alias}" "${TOKEN_FILE}.${alias}"
  done
fi

systemctl restart azazel-edge-web
