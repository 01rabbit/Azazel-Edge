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
DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io qemu-user-static binfmt-support curl jq ca-certificates
systemctl enable --now docker.service

echo "[ai/2] Install compose assets"
install -d "${SECURITY_ROOT}"
install -m 0644 "${REPO_ROOT}/security/docker-compose.ollama.yml" "${SECURITY_ROOT}/docker-compose.ollama.yml"
install -m 0644 "${REPO_ROOT}/security/docker-compose.mattermost.yml" "${SECURITY_ROOT}/docker-compose.mattermost.yml"
install -m 0644 "${REPO_ROOT}/security/.env" "${SECURITY_ROOT}/.env"
install -m 0755 "${REPO_ROOT}/installer/internal/provision_mattermost_workspace.sh" /opt/azazel-edge/provision_mattermost_workspace.sh
install -m 0755 "${REPO_ROOT}/installer/internal/provision_mattermost_command.sh" /opt/azazel-edge/provision_mattermost_command.sh

echo "[ai/3] Seed WebUI Mattermost defaults"
install -d /etc/default /etc/azazel-edge
if [[ ! -f "${WEB_ENV}" ]]; then
  cat > "${WEB_ENV}" <<'EOF'
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
fi

if [[ "${ENABLE_OLLAMA}" == "1" ]]; then
  echo "[ai/4] Start Ollama and provision models"
  (
    cd "${SECURITY_ROOT}"
    docker compose -f docker-compose.ollama.yml up -d
  )
  docker exec azazel-edge-ollama ollama pull qwen3.5:2b
  docker exec azazel-edge-ollama ollama pull qwen3.5:0.8b
  docker exec azazel-edge-ollama ollama rm qwen3.5:4b >/dev/null 2>&1 || true
fi

if [[ "${ENABLE_MATTERMOST}" == "1" ]]; then
  echo "[ai/5] Start Mattermost stack"
  (
    cd "${SECURITY_ROOT}"
    docker compose -f docker-compose.mattermost.yml up -d
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
