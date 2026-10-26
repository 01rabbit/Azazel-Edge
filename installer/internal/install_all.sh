#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ENABLE_INTERNAL_NETWORK="${ENABLE_INTERNAL_NETWORK:-1}"
ENABLE_APP_STACK="${ENABLE_APP_STACK:-1}"
ENABLE_AI_RUNTIME="${ENABLE_AI_RUNTIME:-1}"
ENABLE_DEV_REMOTE_ACCESS="${ENABLE_DEV_REMOTE_ACCESS:-0}"
ENABLE_RUST_CORE="${ENABLE_RUST_CORE:-1}"
ENABLE_VECTOR="${ENABLE_VECTOR:-0}"
ENABLE_SNMP="${ENABLE_SNMP:-0}"
ENABLE_NETFLOW="${ENABLE_NETFLOW:-0}"

# MODE=open|close (used only when ENABLE_DEV_REMOTE_ACCESS=1)
DEV_REMOTE_MODE="${DEV_REMOTE_MODE:-open}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

# Checked here too, before anything is changed (install_migrated_tools.sh
# checks it again): a typo must not stop the install halfway.
case "${ENABLE_RUST_CORE}" in
  0|1) ;;
  *) echo "ENABLE_RUST_CORE must be 0 or 1 (got: ${ENABLE_RUST_CORE})" >&2; exit 1 ;;
esac

# Edge#206: the app stack's security stack sets up the encrypted secrets
# volume by default, and its passphrase is typed on a terminal. Checked before
# anything is changed (the network baseline below included), so an unattended
# run stops here with an error. Only SKIP_LUKS=1 skips the volume.
# stdin only: see require_tty in install_encrypted_storage.sh (cryptsetup
# prompts only when stdin is a terminal).
if [[ "${ENABLE_APP_STACK}" == "1" && "${ENABLE_SECURITY_STACK:-1}" == "1" && "${SKIP_LUKS:-0}" != "1" \
      && ! -e /dev/mapper/azazel-secrets ]] && [[ ! -t 0 ]]; then
  echo "ERROR: the encrypted secrets volume (Edge#206, on by default) needs a passphrase typed on a terminal, and stdin is not one. Run the installer from an interactive terminal (to keep a log, use: script -c 'sudo ...' install.log, or pipe only the output: 2>&1 | tee install.log), or, to install without encrypted storage, re-run it with SKIP_LUKS=1 set explicitly." >&2
  exit 1
fi

echo "[all/1] Azazel-Edge unified installer"
echo "repo=${REPO_ROOT}"
echo "ENABLE_INTERNAL_NETWORK=${ENABLE_INTERNAL_NETWORK}"
echo "ENABLE_APP_STACK=${ENABLE_APP_STACK}"
echo "ENABLE_AI_RUNTIME=${ENABLE_AI_RUNTIME}"
echo "ENABLE_DEV_REMOTE_ACCESS=${ENABLE_DEV_REMOTE_ACCESS}"
echo "ENABLE_RUST_CORE=${ENABLE_RUST_CORE}"
echo "ENABLE_VECTOR=${ENABLE_VECTOR}"
echo "ENABLE_SNMP=${ENABLE_SNMP}"
echo "ENABLE_NETFLOW=${ENABLE_NETFLOW}"
echo "DEV_REMOTE_MODE=${DEV_REMOTE_MODE}"

if [[ "${ENABLE_INTERNAL_NETWORK}" == "1" ]]; then
  echo "[all/2] Apply internal network baseline"
  "${REPO_ROOT}/installer/internal/install_internal_network.sh"
  # mDNS on the LAN bridge only, not on the uplink (Edge#477). Step 5 below
  # (dev remote access, MODE=open) widens it again on purpose.
  "${REPO_ROOT}/installer/internal/configure_avahi_lan_only.sh"
else
  echo "[all/2] Skip internal network baseline"
fi

if [[ "${ENABLE_APP_STACK}" == "1" ]]; then
  echo "[all/3] Install Azazel-Edge app stack"
  ENABLE_RUST_CORE="${ENABLE_RUST_CORE}" "${REPO_ROOT}/installer/internal/install_migrated_tools.sh"
else
  echo "[all/3] Skip app stack installation"
fi

if [[ "${ENABLE_AI_RUNTIME}" == "1" ]]; then
  echo "[all/4] Install AI runtime stack"
  "${REPO_ROOT}/installer/internal/install_ai_runtime.sh"
else
  echo "[all/4] Skip AI runtime stack"
fi

if [[ "${ENABLE_DEV_REMOTE_ACCESS}" == "1" ]]; then
  echo "[all/5] Configure dev remote access"
  MODE="${DEV_REMOTE_MODE}" "${REPO_ROOT}/installer/internal/set_dev_remote_access.sh"
else
  echo "[all/5] Skip dev remote access setup"
fi

if [[ "${ENABLE_VECTOR}" == "1" ]]; then
  echo "[all/6] Install Vector log aggregator"
  VECTOR_MODE="${VECTOR_MODE:-local}" "${REPO_ROOT}/installer/internal/install_vector.sh"
else
  echo "[all/6] Skip Vector (set ENABLE_VECTOR=1 to enable)"
fi

if [[ "${ENABLE_SNMP}" == "1" || "${ENABLE_NETFLOW}" == "1" ]]; then
  echo "[all/7] Install optional sensors (SNMP/NetFlow)"
  ENABLE_SNMP="${ENABLE_SNMP}" \
  ENABLE_NETFLOW="${ENABLE_NETFLOW}" \
  NETFLOW_PORT="${NETFLOW_PORT:-2055}" \
  NETFLOW_LISTEN_HOST="${NETFLOW_LISTEN_HOST:-}" \
  SNMP_TARGETS="${SNMP_TARGETS:-}" \
  "${REPO_ROOT}/installer/internal/install_sensors.sh"
else
  echo "[all/7] Skip optional sensors (set ENABLE_SNMP=1 and/or ENABLE_NETFLOW=1)"
fi

echo "Unified installation completed."
