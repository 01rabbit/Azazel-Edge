#!/usr/bin/env bash
# install_vector.sh - Install Vector log aggregator for Azazel-Edge
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"; exit 1
fi

ARCH="$(uname -m)"
if [[ "${ARCH}" != "aarch64" ]]; then
  echo "[ERROR] Expected aarch64, got ${ARCH}. Vector install skipped."; exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VECTOR_MODE="${VECTOR_MODE:-local}"   # local | wazuh | aggregator
WAZUH_MANAGER_HOST="${WAZUH_MANAGER_HOST:-}"
# aggregator mode: where the UDP receiver listens (Edge#477). The default is
# the internal LAN address (port 5514), so other nodes on the LAN can send and
# the uplink (WAN) side cannot; any other address has to be given here
# explicitly, and 0.0.0.0 is refused.
VECTOR_AGGREGATOR_ADDRESS="${VECTOR_AGGREGATOR_ADDRESS:-}"
VECTOR_AGGREGATOR_PORT_DEFAULT="5514"
ENABLE_SERVICES="${ENABLE_SERVICES:-1}"
LAN_IF="br0"
# install_internal_network.sh's LAN address (SSH_LISTEN_IP / LAN_ADDR), used
# only while br0 has no IPv4 address yet.
LAN_ADDR_DEFAULT="172.16.0.254"

# The IPv4 address on br0 (the internal LAN), else LAN_ADDR_DEFAULT.
lan_ipv4() {
  local addr
  addr="$(ip -4 -o addr show dev "$LAN_IF" scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}' || true)"
  if [[ -z "$addr" ]]; then
    echo "NOTICE: ${LAN_IF} has no IPv4 address yet; using the default LAN address ${LAN_ADDR_DEFAULT}" >&2
    addr="$LAN_ADDR_DEFAULT"
  fi
  printf '%s' "$addr"
}

# A unicast IPv4 address to listen on for other hosts: four octets 0..255
# written without leading zeros, the first 1..223 except 127 (so not
# 0.0.0.0 "every address", not loopback, not multicast or the 255.255.255.255
# broadcast).
valid_listen_ipv4() {
  local o
  [[ "$1" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1:4}"; do
    (( o <= 255 )) || return 1
  done
  (( BASH_REMATCH[1] >= 1 && BASH_REMATCH[1] <= 223 && BASH_REMATCH[1] != 127 ))
}

# Checked before anything is installed.
if [[ "${VECTOR_MODE}" == "aggregator" ]]; then
  [[ -n "${VECTOR_AGGREGATOR_ADDRESS}" ]] || VECTOR_AGGREGATOR_ADDRESS="$(lan_ipv4):${VECTOR_AGGREGATOR_PORT_DEFAULT}"
  agg_host="" agg_port=""
  if [[ "${VECTOR_AGGREGATOR_ADDRESS}" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
    agg_host="${BASH_REMATCH[1]}" agg_port="${BASH_REMATCH[2]}"
  fi
  if [[ -z "$agg_port" ]] || ! valid_listen_ipv4 "$agg_host" \
      || (( 10#$agg_port < 1 || 10#$agg_port > 65535 )); then
    echo "ERROR: VECTOR_AGGREGATOR_ADDRESS must be <unicast IPv4 address of this device>:<port>, not 0.0.0.0 (got: ${VECTOR_AGGREGATOR_ADDRESS})"; exit 1
  fi
  echo "[vector] aggregator listens on ${VECTOR_AGGREGATOR_ADDRESS}"
fi

echo "[vector 1/5] Install Vector via official script"
curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- --prefix /usr

echo "[vector 2/5] Verify binary"
vector --version || { echo "ERROR: vector not found after install"; exit 1; }

echo "[vector 3/5] Install configuration"
install -d /etc/azazel-edge/vector /var/log/azazel-edge/vector

if [[ "${VECTOR_MODE}" == "wazuh" ]]; then
  if [[ -z "${WAZUH_MANAGER_HOST}" ]]; then
    echo "ERROR: WAZUH_MANAGER_HOST must be set for wazuh mode"; exit 1
  fi
  install -m 0644 "${REPO_ROOT}/security/vector/vector-wazuh.toml" /etc/azazel-edge/vector/vector.toml
  printf "WAZUH_MANAGER_HOST=%s\n" "${WAZUH_MANAGER_HOST}" > /etc/default/azazel-edge-vector
elif [[ "${VECTOR_MODE}" == "aggregator" ]]; then
  install -m 0644 "${REPO_ROOT}/security/vector/vector-aggregator.toml" /etc/azazel-edge/vector/vector.toml
  printf "VECTOR_AGGREGATOR_ADDRESS=%s\n" "${VECTOR_AGGREGATOR_ADDRESS}" > /etc/default/azazel-edge-vector
else
  install -m 0644 "${REPO_ROOT}/security/vector/vector-local.toml" /etc/azazel-edge/vector/vector.toml
  : > /etc/default/azazel-edge-vector
fi

echo "[vector 4/5] Install systemd service"
install -m 0644 "${REPO_ROOT}/systemd/azazel-edge-vector.service" /etc/systemd/system/azazel-edge-vector.service
systemd-analyze verify /etc/systemd/system/azazel-edge-vector.service || true
systemctl daemon-reload

echo "[vector 5/5] Enable service"
if [[ "${ENABLE_SERVICES}" == "1" ]]; then
  systemctl enable --now azazel-edge-vector.service
  systemctl is-active azazel-edge-vector.service && echo "[vector] Service started OK"
fi

echo "[vector] Install complete. Mode: ${VECTOR_MODE}"
echo "  Config: /etc/azazel-edge/vector/vector.toml"
echo "  Logs:   /var/log/azazel-edge/vector/"
echo "  Toggle: VECTOR_MODE=wazuh WAZUH_MANAGER_HOST=<IP> sudo ${BASH_SOURCE[0]}"
