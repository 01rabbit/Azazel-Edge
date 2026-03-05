#!/usr/bin/env bash
set -euo pipefail

LAN_IF="br0"
LAN_ADDR="172.16.0.254/24"
SSH_LISTEN_IP="172.16.0.254"
ALLOW_EXTERNAL_SSH="${ALLOW_EXTERNAL_SSH:-false}"
DHCP_RANGE_START="172.16.0.101"
DHCP_RANGE_END="172.16.0.200"
DHCP_LEASE_TIME="12h"
LAN_CIDR="172.16.0.0/24"

AP_SSID="${AP_SSID:-Azazel-Edge-Internal}"
AP_PSK="${AP_PSK:-ChangeMe1234}"

BR_CONN="lan-br0"
ETH_SLAVE_CONN="lan-eth0-slave"
WLAN_AP_CONN="lan-wlan0-ap"

SSHD_CONF="/etc/ssh/sshd_config"
DNSMASQ_CONF="/etc/dnsmasq.d/azazel-internal.conf"
SERVICE_FILE="/etc/systemd/system/azazel-internal-apply.service"
RUNNER_FILE="/usr/local/sbin/azazel-internal-apply"
SYSCTL_FILE="/etc/sysctl.d/99-azazel-internal.conf"
NFT_RULES_FILE="/etc/nftables.d/azazel-internal.nft"
FIRST_MINUTE_CFG="/etc/azazel-edge/first_minute.yaml"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo $0"
    exit 1
  fi
}

validate_ap_credentials() {
  if [[ ${#AP_SSID} -lt 1 || ${#AP_SSID} -gt 32 ]]; then
    echo "ERROR: AP_SSID must be 1..32 characters"
    exit 1
  fi

  if [[ ${#AP_PSK} -lt 8 || ${#AP_PSK} -gt 63 ]]; then
    echo "ERROR: AP_PSK must be 8..63 characters"
    exit 1
  fi
}

backup_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    cp -a "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)"
  fi
}

install_packages() {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    network-manager dnsmasq avahi-daemon openssh-server nftables
}

detect_wan_if() {
  local wan_if="${WAN_IF:-}"
  if [[ -z "$wan_if" ]]; then
    wan_if="$(ip route show default | awk '{print $5; exit}')"
  fi

  if [[ -z "$wan_if" ]]; then
    echo "ERROR: WAN interface not found. Set WAN_IF and retry."
    exit 1
  fi
  echo "$wan_if"
}

configure_nm_internal_bridge() {
  nmcli dev set wlan0 managed yes || true

  if nmcli -t -f NAME con show | grep -qx "$BR_CONN"; then
    nmcli con modify "$BR_CONN" \
      connection.interface-name "$LAN_IF" \
      ipv4.method manual \
      ipv4.addresses "$LAN_ADDR" \
      ipv4.never-default yes \
      bridge.stp no \
      bridge.forward-delay 0 \
      ipv6.method ignore \
      connection.autoconnect yes \
      connection.autoconnect-priority 50
  else
    nmcli con add type bridge ifname "$LAN_IF" con-name "$BR_CONN" \
      ipv4.method manual ipv4.addresses "$LAN_ADDR" ipv4.never-default yes \
      bridge.stp no bridge.forward-delay 0 \
      ipv6.method ignore
    nmcli con modify "$BR_CONN" connection.autoconnect yes connection.autoconnect-priority 50
  fi

  # Prevent autoconnect race where another ethernet profile takes over eth0.
  nmcli -t -f NAME,DEVICE,TYPE,ACTIVE con show | awk -F: '$2 == "eth0" && $3 == "802-3-ethernet" {print $1}' | while IFS= read -r con; do
    if [[ -n "$con" && "$con" != "$ETH_SLAVE_CONN" ]]; then
      nmcli con modify "$con" connection.autoconnect no || true
      nmcli con down "$con" || true
    fi
  done

  if nmcli -t -f NAME con show | grep -qx "$ETH_SLAVE_CONN"; then
    nmcli con modify "$ETH_SLAVE_CONN" \
      connection.interface-name eth0 connection.master "$LAN_IF" connection.slave-type bridge \
      connection.autoconnect yes connection.autoconnect-priority 40
  else
    nmcli con add type ethernet ifname eth0 con-name "$ETH_SLAVE_CONN" master "$LAN_IF" slave-type bridge
    nmcli con modify "$ETH_SLAVE_CONN" connection.autoconnect yes connection.autoconnect-priority 40
  fi

  # Prevent wlan0 profile races so AP profile stays up after reboot.
  nmcli -t -f NAME,DEVICE,TYPE,ACTIVE con show | awk -F: '$2 == "wlan0" && $3 == "802-11-wireless" {print $1}' | while IFS= read -r con; do
    if [[ -n "$con" && "$con" != "$WLAN_AP_CONN" ]]; then
      nmcli con modify "$con" connection.autoconnect no || true
      nmcli con down "$con" || true
    fi
  done

  if nmcli -t -f NAME con show | grep -qx "$WLAN_AP_CONN"; then
    nmcli con modify "$WLAN_AP_CONN" \
      connection.interface-name wlan0 \
      wifi.mode ap \
      wifi.ssid "$AP_SSID" \
      wifi.band bg \
      wifi-sec.key-mgmt wpa-psk \
      wifi-sec.psk "$AP_PSK" \
      connection.master "$LAN_IF" connection.slave-type bridge \
      connection.autoconnect yes connection.autoconnect-priority 100
  else
    nmcli con add type wifi ifname wlan0 con-name "$WLAN_AP_CONN" ssid "$AP_SSID"
    nmcli con modify "$WLAN_AP_CONN" \
      wifi.mode ap \
      wifi.band bg \
      wifi-sec.key-mgmt wpa-psk \
      wifi-sec.psk "$AP_PSK" \
      connection.master "$LAN_IF" connection.slave-type bridge \
      connection.autoconnect yes connection.autoconnect-priority 100
  fi

  nmcli con up "$BR_CONN"
  nmcli con up "$ETH_SLAVE_CONN" || true
  nmcli con up "$WLAN_AP_CONN" || true
}

configure_dnsmasq_dhcp() {
  backup_file "$DNSMASQ_CONF"

  cat > "$DNSMASQ_CONF" <<EOD
interface=${LAN_IF}
bind-interfaces
except-interface=lo
resolv-file=/run/NetworkManager/resolv.conf
dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},255.255.255.0,${DHCP_LEASE_TIME}
dhcp-option=option:router,${SSH_LISTEN_IP}
dhcp-option=option:dns-server,${SSH_LISTEN_IP}
EOD

  systemctl enable --now dnsmasq
  systemctl restart dnsmasq
}

ensure_resolver_baseline() {
  if [[ -f /run/NetworkManager/resolv.conf ]]; then
    rm -f /etc/resolv.conf
    ln -s /run/NetworkManager/resolv.conf /etc/resolv.conf
  fi
}

configure_sshd() {
  backup_file "$SSHD_CONF"

  awk '
    /^[[:space:]]*ListenAddress[[:space:]]+/ { next }
    { print }
  ' "$SSHD_CONF" > "${SSHD_CONF}.tmp"

  if [[ "${ALLOW_EXTERNAL_SSH,,}" != "true" ]]; then
    {
      echo ""
      echo "ListenAddress ${SSH_LISTEN_IP}"
    } >> "${SSHD_CONF}.tmp"
  fi

  mv "${SSHD_CONF}.tmp" "$SSHD_CONF"

  systemctl restart ssh
}

configure_forwarding_and_nat() {
  local wan_if
  wan_if="$(detect_wan_if)"

  mkdir -p "$(dirname "$SYSCTL_FILE")" "$(dirname "$NFT_RULES_FILE")"
  cat > "$SYSCTL_FILE" <<EOD
net.ipv4.ip_forward=1
EOD
  sysctl -p "$SYSCTL_FILE" >/dev/null

  cat > "$NFT_RULES_FILE" <<EOD
table ip azazel_internal {
  chain nat_postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "${wan_if}" ip saddr ${LAN_CIDR} masquerade
  }

  chain filter_forward {
    type filter hook forward priority filter; policy accept;
    iifname "${LAN_IF}" oifname "${wan_if}" accept
    iifname "${wan_if}" oifname "${LAN_IF}" ct state { established, related } accept
  }
}
EOD

  if nft list table ip azazel_internal >/dev/null 2>&1; then
    nft delete table ip azazel_internal
  fi
  nft -f "$NFT_RULES_FILE"
}

configure_control_flags() {
  install -d /etc/azazel-edge
  cat > "$FIRST_MINUTE_CFG" <<'EOD'
suppress_auto_wifi: false
EOD
}

ensure_services() {
  systemctl enable --now NetworkManager
  systemctl enable --now avahi-daemon
  systemctl enable --now ssh
}

install_runner() {
  cat > "$RUNNER_FILE" <<'EOR'
#!/usr/bin/env bash
set -euo pipefail

nmcli con up lan-br0 || true
nmcli con up lan-eth0-slave || true
nmcli con up lan-wlan0-ap || true

systemctl restart dnsmasq
systemctl restart ssh
systemctl restart avahi-daemon
if [[ -f /run/NetworkManager/resolv.conf ]]; then
  rm -f /etc/resolv.conf
  ln -s /run/NetworkManager/resolv.conf /etc/resolv.conf
fi
sysctl -p /etc/sysctl.d/99-azazel-internal.conf >/dev/null || true
if [[ -f /etc/nftables.d/azazel-internal.nft ]]; then
  nft list table ip azazel_internal >/dev/null 2>&1 && nft delete table ip azazel_internal || true
  nft -f /etc/nftables.d/azazel-internal.nft || true
fi
EOR
  chmod 0755 "$RUNNER_FILE"
}

install_service() {
  cat > "$SERVICE_FILE" <<'EOS'
[Unit]
Description=Apply Azazel internal network baseline
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/azazel-internal-apply

[Install]
WantedBy=multi-user.target
EOS

  systemctl daemon-reload
  systemctl enable azazel-internal-apply.service
}

verify_state() {
  echo "===== verify ====="
  nmcli -t -f DEVICE,STATE,CONNECTION dev
  ip -4 addr show "$LAN_IF"
  systemctl is-active dnsmasq
  systemctl is-active avahi-daemon
  sysctl -n net.ipv4.ip_forward
  nft list table ip azazel_internal
  ss -lunp | grep ':67 ' || true
  ss -lntp | grep ':22 ' || true
}

main() {
  require_root
  validate_ap_credentials
  install_packages
  ensure_services
  configure_nm_internal_bridge
  ensure_resolver_baseline
  configure_dnsmasq_dhcp
  configure_sshd
  configure_forwarding_and_nat
  configure_control_flags
  install_runner
  install_service
  verify_state

  echo "Internal AP + DHCP baseline applied."
  echo "AP SSID: $AP_SSID"
  if [[ "${ALLOW_EXTERNAL_SSH,,}" == "true" ]]; then
    echo "SSH listen scope: all interfaces (temporary external access enabled)."
  else
    echo "SSH listen scope: ${SSH_LISTEN_IP} only."
  fi
  echo "From internal host, verify: ssh azazel@Azazel-Edge.local"
}

main "$@"
