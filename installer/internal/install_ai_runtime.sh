#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SECURITY_ROOT="/opt/azazel-edge/security"
WEB_ENV="/etc/default/azazel-edge-web"
ENABLE_OLLAMA="${ENABLE_OLLAMA:-1}"
ENABLE_MATTERMOST="${ENABLE_MATTERMOST:-1}"
ENABLE_SERVICES="${ENABLE_SERVICES:-1}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

echo "[ai/1] Install runtime dependencies"
apt-get update
# docker-compose: Debian's Compose v2 (trixie: 2.26), which ships the
# `docker compose` CLI plugin; docker.io alone has no compose.
DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose qemu-user-static binfmt-support curl jq ca-certificates
systemctl enable --now docker.service

echo "[ai/2] Install compose assets"
install -d "${SECURITY_ROOT}"
install -m 0644 "${REPO_ROOT}/security/docker-compose.ollama.yml" "${SECURITY_ROOT}/docker-compose.ollama.yml"
install -m 0644 "${REPO_ROOT}/security/docker-compose.mattermost.yml" "${SECURITY_ROOT}/docker-compose.mattermost.yml"
install -m 0644 "${REPO_ROOT}/security/.env" "${SECURITY_ROOT}/.env"
install -m 0755 "${REPO_ROOT}/installer/internal/provision_mattermost_workspace.sh" /opt/azazel-edge/provision_mattermost_workspace.sh
install -m 0755 "${REPO_ROOT}/installer/internal/provision_mattermost_command.sh" /opt/azazel-edge/provision_mattermost_command.sh
# `docker compose` or `docker-compose`, whichever is there.
install -m 0755 "${REPO_ROOT}/bin/azazel-edge-compose" /usr/local/bin/azazel-edge-compose
COMPOSE=/usr/local/bin/azazel-edge-compose

echo "[ai/3] Seed WebUI Mattermost defaults"
install -d /etc/default
# An existing /etc/azazel-edge keeps its mode (Edge#471: never widened).
[[ -d /etc/azazel-edge ]] || install -d -m 0750 /etc/azazel-edge
# Each default is added when its key is missing, not only when the file is
# missing: install_migrated_tools.sh creates the file first (token path, auth
# setting), so a whole-file check never seeded these. A key already there is
# kept as it is. systemd reads the file as root (EnvironmentFile=), so it is
# written 0600 root:root like provision_mattermost_workspace.sh's upsert_env
# (Edge#477); the Web UI (azazel-web) does not read it itself.
seed_web_env_defaults() {
  local file="$1" current="" missing="" line key tmp
  if [[ -e "${file}" || -L "${file}" ]]; then
    # A file that cannot be read stops here instead of being replaced.
    if ! current="$(cat -- "${file}" && printf x)"; then
      echo "[ERROR] could not read ${file}" >&2
      return 1
    fi
    current="${current%x}"
  fi
  while IFS= read -r line; do
    key="${line%%=*}"
    # Present in any form systemd reads: leading blanks, blanks around `=`.
    # Not `export KEY=`: systemd 257 ignores such a line ("Ignoring invalid
    # environment assignment"), so the key is still unset for the unit.
    # A here-string, not a pipe into grep -q (no SIGPIPE under pipefail).
    if ! grep -Eq "^[[:space:]]*${key}[[:space:]]*=" <<<"${current}"; then
      missing+="${line}"$'\n'
    fi
  done <<'EOF'
AZAZEL_MATTERMOST_HOST=172.16.0.254
AZAZEL_MATTERMOST_PORT=8065
AZAZEL_MATTERMOST_TEAM=azazelops
AZAZEL_MATTERMOST_CHANNEL=soc-noc
AZAZEL_MATTERMOST_BASE_URL=http://172.16.0.254:8065
AZAZEL_MATTERMOST_OPEN_URL=http://172.16.0.254:8065/azazelops/channels/soc-noc
AZAZEL_MATTERMOST_TIMEOUT_SEC=8
AZAZEL_MATTERMOST_FETCH_LIMIT=40
AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=0
EOF
  if [[ -n "${current}" && "${current}" != *$'\n' ]]; then
    current+=$'\n'
  fi
  tmp="$(umask 077 && mktemp "$(dirname -- "${file}")/.$(basename -- "${file}").XXXXXX")"
  if ! printf '%s%s' "${current}" "${missing}" >"${tmp}" || ! chown root:root "${tmp}" \
      || ! chmod 0600 "${tmp}" || ! mv -fT -- "${tmp}" "${file}"; then
    rm -f -- "${tmp}"
    echo "[ERROR] could not write ${file}" >&2
    return 1
  fi
}
seed_web_env_defaults "${WEB_ENV}"

if [[ "${ENABLE_OLLAMA}" == "1" ]]; then
  echo "[ai/4] Start Ollama and provision models"
  (
    cd "${SECURITY_ROOT}"
    "${COMPOSE}" -f docker-compose.ollama.yml up -d
  )
  docker exec azazel-edge-ollama ollama pull qwen3.5:2b
  docker exec azazel-edge-ollama ollama pull qwen3.5:0.8b
  docker exec azazel-edge-ollama ollama rm qwen3.5:4b >/dev/null 2>&1 || true
fi

if [[ "${ENABLE_MATTERMOST}" == "1" ]]; then
  echo "[ai/5] Start Mattermost stack"
  (
    cd "${SECURITY_ROOT}"
    "${COMPOSE}" -f docker-compose.mattermost.yml up -d
  )
  echo "[ai/6] Provision Mattermost workspace"
  /opt/azazel-edge/provision_mattermost_workspace.sh
  echo "[ai/7] Provision Mattermost slash command"
  /opt/azazel-edge/provision_mattermost_command.sh
fi

if [[ "${ENABLE_SERVICES}" == "1" ]]; then
  systemctl restart azazel-edge-web.service >/dev/null 2>&1 || true
  systemctl restart azazel-edge-ai-agent.service >/dev/null 2>&1 || true
fi

echo "[DONE] AI runtime stack installed."
