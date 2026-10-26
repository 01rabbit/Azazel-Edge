#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT_DEFAULT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="${REPO_ROOT:-$REPO_ROOT_DEFAULT}"
ENABLE_SERVICES="${ENABLE_SERVICES:-1}"
# Edge#206: the LUKS secrets volume is set up by default (fail-closed);
# only an explicit SKIP_LUKS=1 skips it. luksFormat and open ask for a
# passphrase on a terminal, so without one the install stops with an error
# (it used to fail silently behind `|| true`).
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

if [[ "${SKIP_LUKS}" != "1" && ! -e /dev/mapper/azazel-secrets ]] && [[ ! -t 0 || ! -t 2 ]]; then
  echo "ERROR: the encrypted secrets volume (Edge#206, on by default) needs a passphrase typed on a terminal, and this is not one. Run the installer from an interactive terminal, or, to install without encrypted storage, re-run it with SKIP_LUKS=1 set explicitly." >&2
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
  echo "[security] Install encrypted storage baseline (Edge#206; needs a terminal)"
  # Fail-closed: a failure stops the install instead of being ignored.
  "${ASSET_ROOT}/installer/internal/install_encrypted_storage.sh"
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
