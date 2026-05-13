#!/usr/bin/env bash
# install_sensors.sh — Install optional SNMP/NetFlow sensor components
# Sensors feed existing Evidence Plane via dispatch_syslog_line()
# Both sensors are OPTIONAL (ENABLE_SNMP, ENABLE_NETFLOW env flags)
set -euo pipefail

ENABLE_SNMP="${ENABLE_SNMP:-0}"
ENABLE_NETFLOW="${ENABLE_NETFLOW:-0}"
NETFLOW_PORT="${NETFLOW_PORT:-2055}"
SNMP_TARGETS="${SNMP_TARGETS:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

echo "[sensors] ENABLE_SNMP=${ENABLE_SNMP}"
echo "[sensors] ENABLE_NETFLOW=${ENABLE_NETFLOW}"
echo "[sensors] NETFLOW_PORT=${NETFLOW_PORT}"

if [[ "${ENABLE_SNMP}" == "1" ]]; then
  apt-get update -y
  apt-get install -y --no-install-recommends snmp
  echo "[sensors] SNMP tools installed"
  if [[ -n "${SNMP_TARGETS}" ]]; then
    echo "[sensors] SNMP targets provided via SNMP_TARGETS"
  else
    echo "[sensors] SNMP targets not set (set SNMP_TARGETS JSON when enabling poller runtime)"
  fi
fi

if [[ "${ENABLE_NETFLOW}" == "1" ]]; then
  echo "[sensors] NetFlow receiver uses stdlib only — no extra packages needed"
  echo "[sensors] Listening port: ${NETFLOW_PORT}"
fi

echo "[sensors] Done. Enable via ENABLE_SNMP=1 or ENABLE_NETFLOW=1"
