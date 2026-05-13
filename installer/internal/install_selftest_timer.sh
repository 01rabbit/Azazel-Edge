#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

ARCH="$(uname -m)"
if [[ "${ARCH}" != "aarch64" ]]; then
  echo "[ERROR] Expected aarch64, got ${ARCH}"; exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENABLE_SERVICES="${ENABLE_SERVICES:-1}"

echo "[selftest 1/4] Install selftest binary"
install -m 0755 "${REPO_ROOT}/bin/azazel-edge-selftest" /usr/local/bin/azazel-edge-selftest

echo "[selftest 2/4] Install systemd units"
install -m 0644 "${REPO_ROOT}/systemd/azazel-edge-selftest.service" /etc/systemd/system/azazel-edge-selftest.service
install -m 0644 "${REPO_ROOT}/systemd/azazel-edge-selftest.timer" /etc/systemd/system/azazel-edge-selftest.timer
systemctl daemon-reload

echo "[selftest 3/4] Verify timer"
systemd-analyze verify /etc/systemd/system/azazel-edge-selftest.timer || true

echo "[selftest 4/4] Enable timer"
if [[ "${ENABLE_SERVICES}" == "1" ]]; then
  systemctl enable --now azazel-edge-selftest.timer
  systemctl is-active azazel-edge-selftest.timer && echo "[selftest] timer started"
fi

echo "[selftest] install complete"
