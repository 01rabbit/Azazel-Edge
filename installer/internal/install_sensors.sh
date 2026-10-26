#!/usr/bin/env bash
# install_sensors.sh — Install optional SNMP/NetFlow sensor components
# Sensors feed existing Evidence Plane via dispatch_syslog_line()
# Both sensors are OPTIONAL (ENABLE_SNMP, ENABLE_NETFLOW env flags)
set -euo pipefail

ENABLE_SNMP="${ENABLE_SNMP:-0}"
ENABLE_NETFLOW="${ENABLE_NETFLOW:-0}"
ENABLE_SERVICES="${ENABLE_SERVICES:-0}"
NETFLOW_PORT="${NETFLOW_PORT:-2055}"
# The NetFlow receiver listens on the internal LAN address by default
# (Edge#477), not on every address: the uplink (WAN) side must not feed flow
# records into the evidence plane. An exporter elsewhere needs this set to an
# address of this device explicitly.
NETFLOW_LISTEN_HOST="${NETFLOW_LISTEN_HOST:-172.16.0.254}"
SNMP_TARGETS="${SNMP_TARGETS:-}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SENSOR_ENV_FILE="/etc/default/azazel-edge-sensors"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

echo "[sensors] ENABLE_SNMP=${ENABLE_SNMP}"
echo "[sensors] ENABLE_NETFLOW=${ENABLE_NETFLOW}"
echo "[sensors] ENABLE_SERVICES=${ENABLE_SERVICES}"
echo "[sensors] NETFLOW_PORT=${NETFLOW_PORT}"
echo "[sensors] NETFLOW_LISTEN_HOST=${NETFLOW_LISTEN_HOST}"

if [[ ! "${NETFLOW_LISTEN_HOST}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "ERROR: NETFLOW_LISTEN_HOST must be an IPv4 address (got: ${NETFLOW_LISTEN_HOST})"
  exit 1
fi

cat > "${SENSOR_ENV_FILE}" <<EOF
# Azazel-Edge sensor configuration
# Edit this file to configure SNMP targets and NetFlow port
SNMP_TARGETS='${SNMP_TARGETS:-[{"host":"192.168.1.1","community":"public","port":161}]}'
SNMP_POLL_INTERVAL_SEC=60
NETFLOW_LISTEN_HOST=${NETFLOW_LISTEN_HOST}
NETFLOW_PORT=${NETFLOW_PORT}
EOF
chmod 0644 "${SENSOR_ENV_FILE}"

if [[ "${ENABLE_SNMP}" == "1" || "${ENABLE_NETFLOW}" == "1" ]]; then
  # Both units run as User=azazel-sensor / Group=azazel-sensor (Edge#477):
  # a system account with no login and no home, created here
  # (setup_sensor_account.sh stops if an azazel-sensor that is not that
  # account already exists; the login account azazel is not touched).
  "${REPO_ROOT}/installer/internal/setup_sensor_account.sh"
fi

if [[ "${ENABLE_SNMP}" == "1" ]]; then
  apt-get update -y
  apt-get install -y --no-install-recommends snmp
  echo "[sensors] SNMP tools installed"
  if [[ -n "${SNMP_TARGETS}" ]]; then
    echo "[sensors] SNMP targets provided via SNMP_TARGETS"
  else
    echo "[sensors] SNMP targets not set (set SNMP_TARGETS JSON when enabling poller runtime)"
  fi
  install -m 0644 "${REPO_ROOT}/systemd/azazel-edge-snmp-poller.service" /etc/systemd/system/azazel-edge-snmp-poller.service
  systemctl daemon-reload
  if [[ "${ENABLE_SERVICES}" == "1" ]]; then
    systemctl enable --now azazel-edge-snmp-poller.service
  fi
fi

if [[ "${ENABLE_NETFLOW}" == "1" ]]; then
  echo "[sensors] NetFlow receiver uses stdlib only — no extra packages needed"
  echo "[sensors] Listening port: ${NETFLOW_PORT}"
  install -m 0644 "${REPO_ROOT}/systemd/azazel-edge-netflow-receiver.service" /etc/systemd/system/azazel-edge-netflow-receiver.service
  systemctl daemon-reload
  if [[ "${ENABLE_SERVICES}" == "1" ]]; then
    systemctl enable --now azazel-edge-netflow-receiver.service
  fi
fi

echo "[sensors] Done. Enable via ENABLE_SNMP=1 or ENABLE_NETFLOW=1"
