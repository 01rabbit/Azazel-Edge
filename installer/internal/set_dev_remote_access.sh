#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-open}"                  # open | close
DEVICE_HOSTNAME="${DEVICE_HOSTNAME:-Azazel-Edge}"
LAN_IF="${LAN_IF:-br0}"
LAN_IP="${LAN_IP:-172.16.0.254}"
WAN_IF="${WAN_IF:-}"

SSHD_CONF="/etc/ssh/sshd_config"
AVAHI_CONF="/etc/avahi/avahi-daemon.conf"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

detect_wan_if() {
  if [[ -n "${WAN_IF}" ]]; then
    echo "${WAN_IF}"
    return
  fi
  ip route show default | awk '{print $5; exit}'
}

upsert_ini_key() {
  local file="$1"
  local key="$2"
  local value="$3"

  if grep -Eq "^[#[:space:]]*${key}=" "$file"; then
    sed -i -E "s|^[#[:space:]]*${key}=.*$|${key}=${value}|g" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

configure_ssh_open() {
  cp -a "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
  awk '
    /^[[:space:]]*ListenAddress[[:space:]]+/ { next }
    { print }
  ' "$SSHD_CONF" > "${SSHD_CONF}.tmp"
  mv "${SSHD_CONF}.tmp" "$SSHD_CONF"
  systemctl restart ssh
}

configure_ssh_close() {
  cp -a "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
  awk '
    /^[[:space:]]*ListenAddress[[:space:]]+/ { next }
    { print }
    END {
      print ""
      print "ListenAddress '"${LAN_IP}"'"
    }
  ' "$SSHD_CONF" > "${SSHD_CONF}.tmp"
  mv "${SSHD_CONF}.tmp" "$SSHD_CONF"
  systemctl restart ssh
}

configure_avahi_open() {
  local wan_if="$1"
  cp -a "$AVAHI_CONF" "${AVAHI_CONF}.bak.$(date +%Y%m%d%H%M%S)"
  upsert_ini_key "$AVAHI_CONF" "host-name" "$DEVICE_HOSTNAME"
  upsert_ini_key "$AVAHI_CONF" "allow-interfaces" "${LAN_IF},${wan_if}"
  upsert_ini_key "$AVAHI_CONF" "enable-reflector" "yes"
  systemctl enable --now avahi-daemon
  systemctl restart avahi-daemon
}

configure_avahi_close() {
  cp -a "$AVAHI_CONF" "${AVAHI_CONF}.bak.$(date +%Y%m%d%H%M%S)"
  upsert_ini_key "$AVAHI_CONF" "host-name" "$DEVICE_HOSTNAME"
  upsert_ini_key "$AVAHI_CONF" "allow-interfaces" "${LAN_IF}"
  upsert_ini_key "$AVAHI_CONF" "enable-reflector" "no"
  systemctl enable --now avahi-daemon
  systemctl restart avahi-daemon
}

configure_ufw_open() {
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 22/tcp >/dev/null || true
  fi
}

configure_ufw_close() {
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw delete allow 22/tcp >/dev/null || true
  fi
}

show_hints() {
  local wan_if="$1"
  local wan_ip
  wan_ip="$(ip -4 -o addr show dev "$wan_if" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)"

  echo "mode=${MODE}"
  echo "hostname=${DEVICE_HOSTNAME}"
  echo "wan_if=${wan_if}"
  [[ -n "${wan_ip}" ]] && echo "wan_ip=${wan_ip}"
  echo ""
  echo "VSCode Remote-SSH example:"
  echo "  Host azazel-edge-dev"
  echo "    HostName ${DEVICE_HOSTNAME}.local"
  echo "    User azazel"
  echo "    Port 22"
  echo ""
  echo "If external client cannot resolve .local, add hosts entry:"
  if [[ -n "${wan_ip}" ]]; then
    echo "  ${wan_ip} ${DEVICE_HOSTNAME}.local"
  else
    echo "  <WAN_IP> ${DEVICE_HOSTNAME}.local"
  fi
}

main() {
  local wan_if
  wan_if="$(detect_wan_if)"
  if [[ -z "${wan_if}" ]]; then
    echo "ERROR: WAN interface not found. Set WAN_IF and retry."
    exit 1
  fi

  hostnamectl set-hostname "${DEVICE_HOSTNAME}" || true

  case "${MODE}" in
    open)
      configure_ssh_open
      configure_avahi_open "$wan_if"
      configure_ufw_open
      ;;
    close)
      configure_ssh_close
      configure_avahi_close
      configure_ufw_close
      ;;
    *)
      echo "ERROR: MODE must be open or close"
      exit 1
      ;;
  esac

  show_hints "$wan_if"
}

main "$@"
