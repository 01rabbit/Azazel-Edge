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
# records into the evidence plane. An exporter elsewhere needs this set to
# another address of this device explicitly; 0.0.0.0 is refused.
NETFLOW_LISTEN_HOST="${NETFLOW_LISTEN_HOST:-}"
SNMP_TARGETS="${SNMP_TARGETS:-}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SENSOR_ENV_FILE="/etc/default/azazel-edge-sensors"
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

# SNMP targets (Edge#477, #480). There is no default target: a guessed
# address with the community "public" would query whatever device has that
# address on the site's network as soon as the poller runs. With
# ENABLE_SNMP=1, SNMP_TARGETS must be a non-empty JSON list of objects, each
# with a non-empty "host" and "community" (and, if given, a "port" 1..65535);
# the old placeholder (host 192.168.1.1 with the community public) is refused.
# The value is read from stdin, not argv, and the community is never printed.
check_snmp_targets() {
  python3 -I -c '
import json, sys
PLACEHOLDER = ("192.168.1.1", "public")
raw = sys.stdin.read()
def fail(msg):
    print("ERROR: SNMP_TARGETS " + msg, file=sys.stderr)
    sys.exit(1)
if not raw.strip():
    fail("is not set")
if chr(39) in raw or "\n" in raw:
    fail("must be one line without single quotes")
try:
    targets = json.loads(raw)
except ValueError:
    fail("is not valid JSON")
if not isinstance(targets, list) or not targets:
    fail("must be a non-empty JSON list of targets")
for i, t in enumerate(targets):
    if not isinstance(t, dict):
        fail("entry %d is not an object" % i)
    host = t.get("host")
    community = t.get("community")
    if not isinstance(host, str) or not host.strip():
        fail("entry %d has no host" % i)
    if not isinstance(community, str) or not community:
        fail("entry %d (host %s) has no community" % (i, host))
    if (host.strip(), community) == PLACEHOLDER:
        fail("entry %d (host %s) is the old placeholder target, not a device of this site" % (i, host))
    port = t.get("port", 161)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        fail("entry %d (host %s) has an invalid port" % (i, host))
'
}

# Same as provision_mattermost_workspace.sh's write_private_file (Edge#477).
# Write stdin to $1 as a 0600 file from its first byte: the content goes to
# a new mktemp file (0600, O_EXCL) beside $1, which is then renamed over $1
# (mv -T: never into a directory a symlink at $1 points to).
# No window with the default umask, an existing file's wider mode is not
# kept, and a symlink at $1 is replaced, not followed.
write_private_file() {
  local dst="$1" tmp
  tmp="$(umask 077 && mktemp "$(dirname -- "${dst}")/.$(basename -- "${dst}").XXXXXX")"
  if ! cat >"${tmp}" || ! chmod 0600 "${tmp}" || ! mv -fT -- "${tmp}" "${dst}"; then
    rm -f -- "${tmp}"
    echo "[ERROR] could not write ${dst}" >&2
    return 1
  fi
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

echo "[sensors] ENABLE_SNMP=${ENABLE_SNMP}"
echo "[sensors] ENABLE_NETFLOW=${ENABLE_NETFLOW}"
echo "[sensors] ENABLE_SERVICES=${ENABLE_SERVICES}"
echo "[sensors] NETFLOW_PORT=${NETFLOW_PORT}"

[[ -n "${NETFLOW_LISTEN_HOST}" ]] || NETFLOW_LISTEN_HOST="$(lan_ipv4)"
if ! valid_listen_ipv4 "${NETFLOW_LISTEN_HOST}"; then
  echo "ERROR: NETFLOW_LISTEN_HOST must be a unicast IPv4 address of this device, not 0.0.0.0 (got: ${NETFLOW_LISTEN_HOST})"
  exit 1
fi
echo "[sensors] NETFLOW_LISTEN_HOST=${NETFLOW_LISTEN_HOST}"

# Checked before anything is written or installed: a refused SNMP_TARGETS
# leaves the device as it was.
if [[ "${ENABLE_SNMP}" == "1" ]]; then
  if ! printf '%s' "${SNMP_TARGETS}" | check_snmp_targets; then
    echo "ERROR: ENABLE_SNMP=1 needs SNMP_TARGETS naming the devices to poll and their community, e.g." >&2
    echo "  SNMP_TARGETS='[{\"host\":\"<device address>\",\"community\":\"<community>\",\"port\":161}]'" >&2
    echo "There is no default target. Nothing was changed." >&2
    if [[ -f "${SENSOR_ENV_FILE}" ]] && grep -q '"192\.168\.1\.1"' "${SENSOR_ENV_FILE}" && grep -q '"public"' "${SENSOR_ENV_FILE}"; then
      echo "NOTICE: ${SENSOR_ENV_FILE} still holds the placeholder target 192.168.1.1 written by an earlier version;" >&2
      echo "  run again with SNMP_TARGETS set to replace it (keep ENABLE_SNMP=0 until then)." >&2
    fi
    exit 1
  fi
fi

# SNMP_TARGETS is written only when given; otherwise the unit's default
# (Environment="SNMP_TARGETS=[]", no target) applies. The file holds SNMP
# communities, which are secrets: it is written 0600 (root:root, as this
# script runs as root), and a file left 0644 by an earlier version is
# replaced by a 0600 one. systemd reads it as root (EnvironmentFile=); the
# sensors (User=azazel-sensor) do not open it.
{
  echo "# Azazel-Edge sensor configuration"
  echo "# Edit this file to configure SNMP targets and NetFlow port"
  if [[ -n "${SNMP_TARGETS}" ]]; then
    echo "SNMP_TARGETS='${SNMP_TARGETS}'"
  else
    echo "# SNMP_TARGETS='[{\"host\":\"<device address>\",\"community\":\"<community>\",\"port\":161}]'"
  fi
  echo "SNMP_POLL_INTERVAL_SEC=60"
  echo "NETFLOW_LISTEN_HOST=${NETFLOW_LISTEN_HOST}"
  echo "NETFLOW_PORT=${NETFLOW_PORT}"
} | write_private_file "${SENSOR_ENV_FILE}"

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
  echo "[sensors] SNMP targets provided via SNMP_TARGETS"
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
