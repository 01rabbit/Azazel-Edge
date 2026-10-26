#!/usr/bin/env bash
set -euo pipefail

WEB_ENV="${AZAZEL_WEB_ENV_FILE:-/etc/default/azazel-edge-web}"
CRED_ENV="${AZAZEL_MATTERMOST_CREDENTIALS_FILE:-/etc/azazel-edge/mattermost-credentials.env}"
# Mattermost publishes on loopback only (security/docker-compose.mattermost.yml,
# Edge#477); LAN clients use nginx on the public port (ensure_lan_proxy).
MATTERMOST_API_URL="${AZAZEL_MATTERMOST_API_URL:-http://127.0.0.1:18065}"
MATTERMOST_HOST_PUBLIC="${AZAZEL_MATTERMOST_PUBLIC_HOST:-172.16.0.254}"
MATTERMOST_PORT_PUBLIC="${AZAZEL_MATTERMOST_PUBLIC_PORT:-8065}"
MATTERMOST_USERNAME="${AZAZEL_MATTERMOST_USERNAME:-azazelops}"
MATTERMOST_EMAIL="${AZAZEL_MATTERMOST_EMAIL:-azazel.ops@example.local}"
# No default password (Edge#477): AZAZEL_MATTERMOST_PASSWORD, else the one
# kept in ${CRED_ENV}, else a new random one (resolve_admin_password).
MATTERMOST_PASSWORD=""
MATTERMOST_TEAM="${AZAZEL_MATTERMOST_TEAM:-azazelops}"
MATTERMOST_TEAM_DISPLAY_NAME="${AZAZEL_MATTERMOST_TEAM_DISPLAY_NAME:-Azazel Ops}"
MATTERMOST_CHANNEL="${AZAZEL_MATTERMOST_CHANNEL:-soc-noc}"
MATTERMOST_CHANNEL_DISPLAY_NAME="${AZAZEL_MATTERMOST_CHANNEL_DISPLAY_NAME:-SOC-NOC}"
MATTERMOST_WEBHOOK_DESCRIPTION="${AZAZEL_MATTERMOST_WEBHOOK_DESCRIPTION:-Azazel Edge WebUI bridge}"
MATTERMOST_BOT_TOKEN_DESCRIPTION="${AZAZEL_MATTERMOST_BOT_TOKEN_DESCRIPTION:-Azazel-Edge WebUI bot token}"
# nginx site that admits the LAN (install_internal_network.sh LAN_CIDR) and
# loopback to Mattermost on the public port, and nobody else.
NGINX_MM_SITE="/etc/nginx/sites-available/azazel-edge-mattermost.conf"
NGINX_MM_LINK="/etc/nginx/sites-enabled/azazel-edge-mattermost.conf"
MATTERMOST_LAN_CIDR="172.16.0.0/24"
# sha256 of the fixed admin password earlier versions set (the password
# itself is no longer in the code); only used to warn about it.
FORMER_DEFAULT_PASSWORD_SHA256="7030024adfd5d729d1d9540d3a49fd1bc699f5de35dbe8f6841b5cbaba5fcd2e"

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
  local rc=0
  # The files live in WORK_DIR (0700, removed on exit). The session or bot
  # token goes to curl in a file (-H @file) and the body (it may hold the
  # admin password) on stdin, so neither is on curl's command line.
  local headers_file="${WORK_DIR}/headers" body_file="${WORK_DIR}/body" auth_file="${WORK_DIR}/auth"
  : >"${headers_file}"
  : >"${body_file}"
  : >"${auth_file}"
  local curl_args=(-sS -D "${headers_file}" -o "${body_file}" -X "${method}" "${MATTERMOST_API_URL}${path}")
  if [[ -n "${token}" ]]; then
    printf 'Authorization: Bearer %s\n' "${token}" >"${auth_file}"
    curl_args+=(-H "@${auth_file}")
  fi
  if [[ -n "${body}" ]]; then
    curl_args+=(-H "Content-Type: application/json" --data-binary @-)
  fi
  LAST_STATUS="$(printf '%s' "${body}" | curl "${curl_args[@]}" -w "%{http_code}")" || rc=$?
  LAST_HEADERS="$(cat "${headers_file}")"
  LAST_BODY="$(cat "${body_file}")"
  rm -f "${headers_file}" "${body_file}" "${auth_file}"
  if (( rc != 0 )); then
    echo "[ERROR] request to ${MATTERMOST_API_URL}${path} failed (curl exit ${rc})" >&2
    exit 1
  fi
}

# One private scratch directory for the whole run (API headers, bodies and
# tokens), removed on every exit, also on INT/TERM.
setup_work_dir() {
  WORK_DIR="$(umask 077 && mktemp -d)"
  trap 'rm -rf -- "${WORK_DIR}"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

# Set KEY=VALUE in the env file $1 (the bot token and the webhook URL among
# them): the first KEY= line is replaced in place, later ones are dropped, and
# a missing key is appended. The new content goes through write_private_file,
# so the file is 0600 from its first byte (Edge#477; formerly `touch` and
# `sed -i`/`>>` under the default umask). The value reaches awk through the
# environment, not -v, so a backslash or '#' in it is written as is.
upsert_env() {
  local file="$1"
  local key="$2"
  local value="$3"
  local current="" updated=""
  # A line break would end the line early and inject further lines into an
  # env file systemd reads as root; the value is not shown (it may be a token).
  if [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* || "${key}" == *$'\n'* ]]; then
    echo "[ERROR] refusing a line break in the value of ${key%%$'\n'*} for ${file}" >&2
    return 1
  fi
  install -d -m 0755 "$(dirname -- "${file}")"
  # Read first: a file that cannot be read stops here instead of being
  # replaced by one holding only this key.
  if [[ -e "${file}" || -L "${file}" ]]; then
    if ! current="$(cat -- "${file}" && printf x)"; then
      echo "[ERROR] could not read ${file}" >&2
      return 1
    fi
    current="${current%x}"
  fi
  if ! updated="$(printf '%s' "${current}" | UPSERT_KEY="${key}" UPSERT_LINE="${key}=${value}" awk '
    BEGIN { prefix = ENVIRON["UPSERT_KEY"] "="; line = ENVIRON["UPSERT_LINE"] }
    index($0, prefix) == 1 { if (!done) { print line; done = 1 } next }
    { print }
    END { if (!done) print line }
  ' && printf x)"; then
    echo "[ERROR] could not update ${file}" >&2
    return 1
  fi
  printf '%s' "${updated%x}" | write_private_file "${file}"
}

# JSON object from the named JSON_<name> environment values (escaped by
# json.dumps), so a quote in a password cannot break the body.
json_object() {
  python3 -c 'import json,os,sys; print(json.dumps({k: os.environ["JSON_" + k] for k in sys.argv[1:]}))' "$@"
}

login_admin() {
  local body
  body="$(JSON_login_id="${MATTERMOST_EMAIL}" JSON_password="${MATTERMOST_PASSWORD}" json_object login_id password)"
  api_call POST /api/v4/users/login "${body}" ""
  if [[ "${LAST_STATUS}" == "200" ]]; then
    AUTH_TOKEN="$(printf '%s\n' "${LAST_HEADERS}" | awk 'BEGIN{IGNORECASE=1} /^Token:/{print $2}' | tr -d '\r')"
    USER_ID="$(printf '%s' "${LAST_BODY}" | json_get 'obj["id"]')"
    return 0
  fi
  return 1
}

bootstrap_admin() {
  local body
  body="$(JSON_email="${MATTERMOST_EMAIL}" JSON_username="${MATTERMOST_USERNAME}" JSON_password="${MATTERMOST_PASSWORD}" \
    json_object email username password)"
  api_call POST /api/v4/users "${body}" ""
  case "${LAST_STATUS}" in
    200|201|400) ;;
    *)
      echo "[ERROR] user bootstrap failed with status ${LAST_STATUS}: ${LAST_BODY}"
      exit 1
      ;;
  esac
  if ! login_admin; then
    echo "[ERROR] unable to login after bootstrap: ${LAST_STATUS} ${LAST_BODY}"
    echo "[ERROR] If the admin account already exists with another password, put that password in" \
      "MATTERMOST_PASSWORD= in ${CRED_ENV} (or reset it in Mattermost) and run this script again."
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

# The way back after a stop below: the AI runtime installer, which also
# registers the slash command and restarts the Web UI and the AI agent (the
# copy in /opt/azazel-edge cannot find the repository).
print_rerun_hint() {
  echo "[NEXT] Run the AI runtime installer again from the Azazel-Edge checkout used for the install:" \
    "sudo ENABLE_OLLAMA=0 installer/internal/install_ai_runtime.sh (it also registers the slash command and" \
    "restarts the Web UI and the AI agent; ENABLE_OLLAMA=0 only skips the model download). If the device was" \
    "installed with install_all.sh, its later stages did not run either: run the ones that were enabled" \
    "(set_dev_remote_access.sh, install_vector.sh, install_sensors.sh) as install_all.sh would." >&2
}

# A device installed by an earlier version may still have the fixed admin
# password, which is public. The run then ends non-zero with what to do; the
# password is not changed automatically (Edge#477).
require_changed_admin_password() {
  if is_former_default_password "${MATTERMOST_PASSWORD}"; then
    echo "[ACTION REQUIRED] The Mattermost admin account (${MATTERMOST_USERNAME}) still uses the fixed default" \
      "password of earlier versions, which is public. 1) Log in to Mattermost as ${MATTERMOST_USERNAME} and change" \
      "it (Profile > Security > Password). 2) Put the new password in MATTERMOST_PASSWORD= in ${CRED_ENV}" \
      "(0600 root). 3) See below." >&2
    print_rerun_hint
    exit 3
  fi
}

is_former_default_password() {
  local digest
  digest="$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"
  [[ "${digest}" == "${FORMER_DEFAULT_PASSWORD_SHA256}" ]]
}

# The password kept in ${CRED_ENV} by an earlier run (the file is parsed, not
# sourced).
stored_admin_password() {
  [[ -f "${CRED_ENV}" ]] || return 0
  sed -n 's/^MATTERMOST_PASSWORD=//p' "${CRED_ENV}" | head -n 1
}

resolve_admin_password() {
  MATTERMOST_PASSWORD="${AZAZEL_MATTERMOST_PASSWORD:-}"
  if [[ -z "${MATTERMOST_PASSWORD}" ]]; then
    MATTERMOST_PASSWORD="$(stored_admin_password)"
  fi
  if [[ -z "${MATTERMOST_PASSWORD}" ]]; then
    # 192 random bits; the suffix meets a password policy that asks for an
    # upper-case letter and a symbol.
    MATTERMOST_PASSWORD="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')-Az"
    if [[ ! "${MATTERMOST_PASSWORD}" =~ ^[0-9a-f]{48}-Az$ ]]; then
      echo "[ERROR] could not read random bytes" >&2
      exit 1
    fi
    # Kept before the account is created, so a run that stops half way
    # does not lose it.
    write_credentials
    echo "[INFO] New random Mattermost admin password stored in ${CRED_ENV} (0600 root)"
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
    api_call GET /api/v4/users/me "" "${AZAZEL_MATTERMOST_BOT_TOKEN}"
    if [[ "${LAST_STATUS}" == "200" ]]; then
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

# Write stdin to $1 as a 0600 file from its first byte: the content goes to
# a new mktemp file (0600, O_EXCL) beside $1, which is then renamed over $1
# (mv -T: never into a directory a symlink at $1 points to).
# No window with the default umask, an existing file's wider mode is not
# kept, and a symlink at $1 is replaced, not followed.
write_private_file() {
  local dst="$1" tmp
  tmp="$(umask 077 && mktemp "$(dirname -- "${dst}")/.$(basename -- "${dst}").XXXXXX")"
  if ! cat >"${tmp}" || ! chmod 0600 "${tmp}" || ! mv -fT -- "${tmp}" "${dst}"; then
    rm -f -- "${tmp}"
    echo "[ERROR] could not write ${dst}" >&2
    return 1
  fi
}

write_credentials() {
  [[ -d "$(dirname -- "${CRED_ENV}")" ]] || install -d -m 0750 "$(dirname -- "${CRED_ENV}")"
  write_private_file "${CRED_ENV}" <<EOF
MATTERMOST_USERNAME=${MATTERMOST_USERNAME}
MATTERMOST_EMAIL=${MATTERMOST_EMAIL}
MATTERMOST_PASSWORD=${MATTERMOST_PASSWORD}
MATTERMOST_URL=${PUBLIC_BASE_URL}
MATTERMOST_TEAM=${MATTERMOST_TEAM}
MATTERMOST_CHANNEL=${MATTERMOST_CHANNEL}
EOF
}

write_outputs() {
  write_credentials

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

# Print the nginx site that puts Mattermost (loopback only) on the public
# port for the LAN. $1 = upstream host:port.
render_lan_proxy_site() {
  cat <<EOF
# Managed by Azazel-Edge (provision_mattermost_workspace.sh, Edge#477).
# Mattermost publishes on loopback only; this admits the LAN and loopback.
map \$http_upgrade \$azazel_mm_connection_upgrade {
  default upgrade;
  ''      close;
}

server {
  listen ${MATTERMOST_PORT_PUBLIC};
  server_name _;

  allow 127.0.0.1;
  allow ${MATTERMOST_LAN_CIDR};
  deny all;

  client_max_body_size 50m;

  location / {
    proxy_pass http://$1;
    proxy_http_version 1.1;
    proxy_set_header Host \$http_host;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$azazel_mm_connection_upgrade;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 600s;
  }
}
EOF
}

# Something other than nginx listening on the public port (the container of
# an earlier install published it on every interface).
public_port_taken() {
  command -v ss >/dev/null 2>&1 || return 1
  ss -Hltnp "sport = :${MATTERMOST_PORT_PUBLIC}" 2>/dev/null | grep -v '"nginx"' | grep -q .
}

ensure_lan_proxy() {
  local upstream tmp
  upstream="${MATTERMOST_API_URL#*://}"
  upstream="${upstream%%/*}"
  # Both cases leave Mattermost unreachable from the LAN, so the run fails
  # instead of reporting success.
  if ! command -v nginx >/dev/null 2>&1; then
    echo "[ERROR] nginx is not installed: Mattermost is reachable only on this host (${MATTERMOST_API_URL}), not" \
      "from the LAN. Install the HTTPS proxy (sudo /opt/azazel-edge/install_https_proxy.sh) first." >&2
    print_rerun_hint
    exit 1
  fi
  if public_port_taken; then
    echo "[ERROR] Port ${MATTERMOST_PORT_PUBLIC} is held by another process, most likely the Mattermost container of" \
      "an earlier install published on every interface (reachable from the WAN). The re-run below recreates it" \
      "with the current compose file first." >&2
    print_rerun_hint
    exit 1
  fi
  tmp="$(mktemp "$(dirname -- "${NGINX_MM_SITE}")/.azazel-edge-mattermost.XXXXXX")"
  if ! render_lan_proxy_site "${upstream}" >"${tmp}" || ! chmod 0644 "${tmp}" || ! mv -f -- "${tmp}" "${NGINX_MM_SITE}"; then
    rm -f -- "${tmp}"
    echo "[ERROR] could not write ${NGINX_MM_SITE}" >&2
    exit 1
  fi
  ln -sfn "${NGINX_MM_SITE}" "${NGINX_MM_LINK}"
  if ! nginx -t >/dev/null 2>&1; then
    rm -f -- "${NGINX_MM_LINK}"
    echo "[ERROR] nginx rejected ${NGINX_MM_SITE}; the site is left disabled (see: nginx -t)" >&2
    exit 1
  fi
  systemctl reload nginx.service 2>/dev/null || systemctl restart nginx.service
  echo "[OK] nginx serves Mattermost on :${MATTERMOST_PORT_PUBLIC} to ${MATTERMOST_LAN_CIDR} and loopback only"
}

# Files below are private unless made otherwise on purpose (the nginx site).
umask 077
setup_work_dir
resolve_admin_password
wait_for_ping
ensure_admin_session
ensure_team
ensure_team_membership
ensure_channel
ensure_bot_token
ensure_webhook
write_outputs
ensure_lan_proxy
require_changed_admin_password

echo "[OK] Mattermost workspace provisioned"
echo "admin_credentials=${CRED_ENV}"
echo "base_url=${PUBLIC_BASE_URL}"
echo "team=${MATTERMOST_TEAM}"
echo "channel=${MATTERMOST_CHANNEL}"
echo "channel_id=${CHANNEL_ID}"
