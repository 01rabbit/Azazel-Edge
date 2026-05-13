#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT_DEFAULT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="${REPO_ROOT:-$REPO_ROOT_DEFAULT}"
ENABLE_SERVICES="${ENABLE_SERVICES:-1}"
SKIP_LUKS="${SKIP_LUKS:-0}"
SECURITY_ROOT="/opt/azazel-edge/security"
SECURITY_ENV="/etc/default/azazel-edge-security"

resolve_asset_root() {
  local candidate
  for candidate in \
    "$REPO_ROOT" \
    "/opt/azazel-edge" \
    "$(pwd)"
  do
    if [[ -f "${candidate}/security/docker-compose.yml" && -f "${candidate}/bin/azazel-edge-compose" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

if ! ASSET_ROOT="$(resolve_asset_root)"; then
  echo "ERROR: asset root not found. Expected security/docker-compose.yml and bin/azazel-edge-compose."
  echo "Hint: set REPO_ROOT explicitly, e.g. REPO_ROOT=/home/azazel/Azazel-Edge"
  exit 1
fi

echo "[security] Install Docker runtime"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
if ! docker compose version >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose || true
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y suricata
systemctl enable --now docker.service

if [[ "${SKIP_LUKS}" != "1" ]]; then
  echo "[security] Install encrypted storage baseline"
  if [[ -x "${ASSET_ROOT}/installer/internal/install_encrypted_storage.sh" ]]; then
    "${ASSET_ROOT}/installer/internal/install_encrypted_storage.sh" || true
  fi
else
  echo "[security] Skip encrypted storage baseline (SKIP_LUKS=1)"
fi

echo "[security] Install compose project files"
install -d \
  "${SECURITY_ROOT}/opencanary" \
  "${SECURITY_ROOT}/suricata" \
  /etc/opencanaryd \
  /etc/suricata/rules \
  /var/log/azazel-edge/opencanary \
  /var/log/suricata

install -m 0644 "${ASSET_ROOT}/security/docker-compose.yml" "${SECURITY_ROOT}/docker-compose.yml"
install -m 0755 "${ASSET_ROOT}/bin/azazel-edge-compose" /usr/local/bin/azazel-edge-compose
install -m 0644 "${ASSET_ROOT}/security/opencanary/Dockerfile" "${SECURITY_ROOT}/opencanary/Dockerfile"
install -m 0644 "${ASSET_ROOT}/security/opencanary/opencanary.conf" "${SECURITY_ROOT}/opencanary/opencanary.conf"
install -m 0644 "${ASSET_ROOT}/security/suricata/azazel-lite.rules" "${SECURITY_ROOT}/suricata/azazel-lite.rules"
install -m 0644 "${ASSET_ROOT}/security/opencanary/opencanary.conf" /etc/opencanaryd/opencanary.conf
install -m 0644 "${ASSET_ROOT}/security/suricata/azazel-lite.rules" /etc/suricata/rules/azazel-lite.rules
touch /var/log/suricata/eve.json

if [[ ! -f "${SECURITY_ENV}" ]]; then
  cat > "${SECURITY_ENV}" <<'EOD'
# Azazel-Edge security stack runtime options
SURICATA_IFACE=br0
EOD
fi

echo "[security] Build OpenCanary image"
/usr/local/bin/azazel-edge-compose -f "${SECURITY_ROOT}/docker-compose.yml" build opencanary

echo "[security] Install systemd wrappers"
install -m 0644 "${ASSET_ROOT}/systemd/azazel-edge-opencanary.service" /etc/systemd/system/azazel-edge-opencanary.service
install -m 0644 "${ASSET_ROOT}/systemd/azazel-edge-suricata.service" /etc/systemd/system/azazel-edge-suricata.service
systemctl daemon-reload

if [[ "${ENABLE_SERVICES}" == "1" ]]; then
  /usr/local/bin/azazel-edge-compose -f "${SECURITY_ROOT}/docker-compose.yml" stop suricata >/dev/null 2>&1 || true
  docker rm -f azazel-edge-suricata >/dev/null 2>&1 || true
  systemctl disable --now suricata.service >/dev/null 2>&1 || true
  systemctl enable --now azazel-edge-opencanary.service
  systemctl enable --now azazel-edge-suricata.service
fi

echo "[security] Installed (OpenCanary via docker compose, Suricata on host)"
