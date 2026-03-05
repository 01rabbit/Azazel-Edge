#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ENABLE_INTERNAL_NETWORK="${ENABLE_INTERNAL_NETWORK:-1}"
ENABLE_APP_STACK="${ENABLE_APP_STACK:-1}"
ENABLE_DEV_REMOTE_ACCESS="${ENABLE_DEV_REMOTE_ACCESS:-0}"
ENABLE_RUST_CORE="${ENABLE_RUST_CORE:-1}"

# MODE=open|close (used only when ENABLE_DEV_REMOTE_ACCESS=1)
DEV_REMOTE_MODE="${DEV_REMOTE_MODE:-open}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

echo "[all/1] Azazel-Edge unified installer"
echo "repo=${REPO_ROOT}"
echo "ENABLE_INTERNAL_NETWORK=${ENABLE_INTERNAL_NETWORK}"
echo "ENABLE_APP_STACK=${ENABLE_APP_STACK}"
echo "ENABLE_DEV_REMOTE_ACCESS=${ENABLE_DEV_REMOTE_ACCESS}"
echo "ENABLE_RUST_CORE=${ENABLE_RUST_CORE}"
echo "DEV_REMOTE_MODE=${DEV_REMOTE_MODE}"

if [[ "${ENABLE_INTERNAL_NETWORK}" == "1" ]]; then
  echo "[all/2] Apply internal network baseline"
  "${REPO_ROOT}/installer/internal/install_internal_network.sh"
else
  echo "[all/2] Skip internal network baseline"
fi

if [[ "${ENABLE_APP_STACK}" == "1" ]]; then
  echo "[all/3] Install Azazel-Edge app stack"
  "${REPO_ROOT}/installer/internal/install_migrated_tools.sh"
else
  echo "[all/3] Skip app stack installation"
fi

if [[ "${ENABLE_DEV_REMOTE_ACCESS}" == "1" ]]; then
  echo "[all/4] Configure dev remote access"
  MODE="${DEV_REMOTE_MODE}" "${REPO_ROOT}/installer/internal/set_dev_remote_access.sh"
else
  echo "[all/4] Skip dev remote access setup"
fi

echo "Unified installation completed."
