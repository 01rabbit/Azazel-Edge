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
# The internal AP passphrase. Unset: the one saved by an earlier run is kept,
# else a random one is generated. It is saved root-only (0600) in
# AP_PSK_FILE and is never printed. The old built-in default is refused.
AP_PSK="${AP_PSK:-}"
AP_PSK_FILE="/etc/azazel-edge/internal-ap.psk"
AP_PSK_OLD_DEFAULT="ChangeMe1234"
# Wi-Fi regulatory country (ISO 3166-1 alpha-2, e.g. JP). Raspberry Pi OS
# keeps Wi-Fi blocked (rfkill) until one is set; unset, the country already
# configured on the device is used.
WIFI_COUNTRY="${WIFI_COUNTRY:-}"

# The internal LAN: br0 bridges the on-board Ethernet and the on-board Wi-Fi
# (as an AP). The uplink (WAN) must be another interface (USB Ethernet or
# USB Wi-Fi); see docs/PHYSICAL_SETUP_GUIDE.md.
ETH_LAN_IF="eth0"
AP_IF="wlan0"
WAN_IF_DETECTED=""

BR_CONN="lan-br0"
ETH_SLAVE_CONN="lan-eth0-slave"
WLAN_AP_CONN="lan-wlan0-ap"

SSHD_CONF="/etc/ssh/sshd_config"
SSHD_CONF_D="/etc/ssh/sshd_config.d"
SSH_DROPIN="/etc/systemd/system/ssh.service.d/azazel-edge-listen.conf"
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

# A NetworkManager profile with this exact name exists. nmcli's output is
# taken into a variable first: piped into `grep -q`, nmcli can be killed by
# SIGPIPE when grep exits early, and pipefail would turn a match into false.
# nmcli failing stops the install: "could not ask" must not read as "absent"
# (a new AP passphrase would replace the one in use).
nm_profile_exists() {
  local names
  if ! names="$(nmcli -t -f NAME con show)"; then
    echo "ERROR: nmcli could not list the NetworkManager profiles." >&2
    exit 1
  fi
  grep -qxF -- "$1" <<<"$names"
}

# Raspberry Pi OS: raspi-config and the firmware config.txt are present.
is_raspberry_pi_os() {
  command -v raspi-config >/dev/null 2>&1 && [[ -f /boot/firmware/config.txt ]]
}

check_ap_psk() {
  if [[ "$1" == "$AP_PSK_OLD_DEFAULT" ]]; then
    echo "ERROR: the AP passphrase is the old built-in default; set AP_PSK to your own (8..63 characters), or leave it unset to generate a random one." >&2
    exit 1
  fi
  if [[ ${#1} -lt 8 || ${#1} -gt 63 ]]; then
    echo "ERROR: the AP passphrase must be 8..63 characters." >&2
    exit 1
  fi
}

validate_ap_credentials() {
  if [[ ${#AP_SSID} -lt 1 || ${#AP_SSID} -gt 32 ]]; then
    echo "ERROR: AP_SSID must be 1..32 characters" >&2
    exit 1
  fi

  if [[ -n "$AP_PSK" ]]; then
    check_ap_psk "$AP_PSK"
  fi

  if [[ -n "$WIFI_COUNTRY" && ! "$WIFI_COUNTRY" =~ ^[A-Za-z]{2}$ ]]; then
    echo "ERROR: WIFI_COUNTRY must be a two-letter ISO 3166-1 country code (e.g. JP)." >&2
    exit 1
  fi
  WIFI_COUNTRY="${WIFI_COUNTRY^^}"
}

# Raspberry Pi OS only, before anything is changed: a Wi-Fi country must be
# set (WIFI_COUNTRY, or one already configured), or the radio stays blocked
# and the AP cannot start.
check_wifi_country() {
  local current=""
  is_raspberry_pi_os || return 0
  [[ -z "$WIFI_COUNTRY" ]] || return 0
  # Only a two-letter code counts; "00" is the world regulatory domain,
  # which is what an unset country looks like, not a country.
  if current="$(raspi-config nonint get_wifi_country 2>/dev/null)" \
      && [[ "$current" =~ ^[A-Z]{2}$ && "$current" != "00" ]]; then
    echo "Wi-Fi country: $current (already configured)"
    return 0
  fi
  echo "ERROR: no Wi-Fi country is configured, so Raspberry Pi OS keeps Wi-Fi blocked (rfkill) and the internal AP cannot start. Re-run with WIFI_COUNTRY=<two-letter ISO 3166-1 code> (e.g. WIFI_COUNTRY=JP)." >&2
  exit 1
}

# Raspberry Pi OS only: set the Wi-Fi country when one was given and unblock
# the radio, so the AP below can start.
prepare_wifi_radio() {
  is_raspberry_pi_os || return 0
  if [[ -n "$WIFI_COUNTRY" ]]; then
    if ! raspi-config nonint do_wifi_country "$WIFI_COUNTRY"; then
      echo "ERROR: raspi-config did not accept WIFI_COUNTRY=$WIFI_COUNTRY." >&2
      exit 1
    fi
    echo "Wi-Fi country: $WIFI_COUNTRY"
  fi
  rfkill unblock wifi
  nmcli radio wifi on
}

generate_ap_psk() {
  local raw
  # 20 characters without look-alikes (0/O, 1/l/I); read into a variable
  # rather than piped to head, so pipefail does not see a SIGPIPE.
  raw="$(LC_ALL=C tr -dc 'A-HJ-NP-Za-km-z2-9' < <(head -c 1024 /dev/urandom))"
  if [[ ${#raw} -lt 20 ]]; then
    echo "ERROR: could not generate the AP passphrase." >&2
    exit 1
  fi
  printf '%s' "${raw:0:20}"
}

save_ap_psk() {
  local dir tmp
  dir="$(dirname -- "$AP_PSK_FILE")"
  # An existing /etc/azazel-edge keeps its mode (Edge#471: never widened).
  [[ -d "$dir" ]] || install -d -m 0750 "$dir"
  tmp="$(umask 077 && mktemp "$dir/.internal-ap.psk.XXXXXX")"
  if ! printf '%s\n' "$1" >"$tmp" || ! chown root:root "$tmp" || ! chmod 0600 "$tmp" \
      || ! mv -fT -- "$tmp" "$AP_PSK_FILE"; then
    rm -f -- "$tmp"
    echo "ERROR: could not write $AP_PSK_FILE" >&2
    exit 1
  fi
}

# AP_PSK when given; else the saved one; else the one an earlier install put
# in the AP profile (unless it is the old default); else a new random one.
# Saved 0600 root:root in AP_PSK_FILE. Never printed.
resolve_ap_psk() {
  local existing=""
  AP_PSK_SOURCE="given"
  if [[ -z "$AP_PSK" && -s "$AP_PSK_FILE" ]]; then
    AP_PSK="$(head -n 1 -- "$AP_PSK_FILE")"
    AP_PSK_SOURCE="kept"
  fi
  if [[ -z "$AP_PSK" ]] && nm_profile_exists "$WLAN_AP_CONN"; then
    existing="$(nmcli -s --escape no -g 802-11-wireless-security.psk con show "$WLAN_AP_CONN" 2>/dev/null || true)"
    if [[ -n "$existing" && "$existing" != "$AP_PSK_OLD_DEFAULT" && ${#existing} -ge 8 && ${#existing} -le 63 ]]; then
      AP_PSK="$existing"
      AP_PSK_SOURCE="kept"
    fi
  fi
  if [[ -z "$AP_PSK" ]]; then
    AP_PSK="$(generate_ap_psk)"
    AP_PSK_SOURCE="generated"
  fi
  check_ap_psk "$AP_PSK"
  save_ap_psk "$AP_PSK"
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
    network-manager dnsmasq avahi-daemon openssh-server nftables rfkill iw
}

# Run before anything is changed: eth0 and wlan0 become ports of br0 below,
# so an uplink through either would be cut (and the NAT rule would point at a
# bridge port). The uplink needs its own interface.
detect_wan_if() {
  local wan_if="${WAN_IF:-}"
  if [[ -z "$wan_if" ]]; then
    wan_if="$(ip route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
  fi

  if [[ -z "$wan_if" ]]; then
    echo "ERROR: WAN interface not found (no default route). Connect the uplink (USB Ethernet or USB Wi-Fi) or set WAN_IF, and retry." >&2
    exit 1
  fi
  case "$wan_if" in
    "$LAN_IF"|"$ETH_LAN_IF"|"$AP_IF")
      echo "ERROR: the uplink is $wan_if, which becomes part of the internal LAN ($LAN_IF = $ETH_LAN_IF + the $AP_IF AP). Connect the uplink through a separate USB Ethernet or USB Wi-Fi adapter (or set WAN_IF to it) and retry; see docs/PHYSICAL_SETUP_GUIDE.md." >&2
      exit 1
      ;;
  esac
  echo "$wan_if"
}

# Escape a value for a NetworkManager keyfile (GLib key file string):
# backslash, space, tab, CR and LF as \\, \s, \t, \r, \n. Pure bash: the
# value is not handed to another program's argv.
keyfile_escape() {
  local v="$1"
  v="${v//\\/\\\\}"
  v="${v// /\\s}"
  v="${v//$'\t'/\\t}"
  v="${v//$'\r'/\\r}"
  v="${v//$'\n'/\\n}"
  printf '%s' "$v"
}

# Write AP_PSK into the AP profile's keyfile and reload it. psk-flags is 0
# (system-owned): NetworkManager keeps the secret in the root-only (0600)
# keyfile and starts the AP at boot without a secret agent; an agent-owned
# (1) or not-saved (2) secret would leave the AP down after a reboot. The
# keyfile is rewritten through a 0600 temporary file in the same directory
# and renamed over it, so it is never partly written or readable by others.
store_ap_psk_in_profile() {
  local uuid listing line file dir tmp section="" written=0 psk_line
  uuid="$(nmcli -g connection.uuid con show "$WLAN_AP_CONN")"
  listing="$(nmcli --escape no -t -f UUID,FILENAME con show)"
  file=""
  while IFS= read -r line; do
    if [[ "${line%%:*}" == "$uuid" ]]; then
      file="${line#*:}"
    fi
  done <<<"$listing"
  if [[ -z "$uuid" || -z "$file" || ! -f "$file" ]]; then
    echo "ERROR: the keyfile of $WLAN_AP_CONN was not found (NetworkManager keyfile plugin expected)." >&2
    exit 1
  fi
  psk_line="psk=$(keyfile_escape "$AP_PSK")"
  dir="$(dirname -- "$file")"
  tmp="$(umask 077 && mktemp "$dir/.azazel-ap-psk.XXXXXX")"
  {
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" =~ ^\[(.*)\]$ ]]; then
        if [[ "$section" == "wifi-security" && "$written" == "0" ]]; then
          printf '%s\n' "$psk_line"
          written=1
        fi
        section="${BASH_REMATCH[1]}"
        printf '%s\n' "$line"
        continue
      fi
      if [[ "$section" == "wifi-security" && "$line" =~ ^psk[[:space:]]*= ]]; then
        continue
      fi
      printf '%s\n' "$line"
    done <"$file"
    if [[ "$written" == "0" ]]; then
      [[ "$section" == "wifi-security" ]] || printf '\n[wifi-security]\n'
      printf '%s\n' "$psk_line"
    fi
  } >"$tmp" || { rm -f -- "$tmp"; echo "ERROR: could not write $tmp" >&2; exit 1; }
  if ! chown root:root "$tmp" || ! chmod 0600 "$tmp" || ! mv -fT -- "$tmp" "$file"; then
    rm -f -- "$tmp"
    echo "ERROR: could not replace $file" >&2
    exit 1
  fi
  if ! nmcli con load "$file"; then
    echo "ERROR: NetworkManager did not reload $file" >&2
    exit 1
  fi
}

configure_nm_internal_bridge() {
  nmcli dev set "$AP_IF" managed yes || true

  if nm_profile_exists "$BR_CONN"; then
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

  if nm_profile_exists "$ETH_SLAVE_CONN"; then
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

  # The passphrase never goes on nmcli's argv (readable by any local user
  # from /proc/<pid>/cmdline): the profile is set up without it and
  # store_ap_psk_in_profile writes it into the profile's root-only keyfile.
  if nm_profile_exists "$WLAN_AP_CONN"; then
    nmcli con modify "$WLAN_AP_CONN" \
      connection.interface-name wlan0 \
      wifi.mode ap \
      wifi.ssid "$AP_SSID" \
      wifi.band bg \
      wifi-sec.key-mgmt wpa-psk \
      wifi-sec.psk-flags 0 \
      connection.master "$LAN_IF" connection.slave-type bridge \
      connection.autoconnect yes connection.autoconnect-priority 100
  else
    nmcli con add type wifi ifname wlan0 con-name "$WLAN_AP_CONN" ssid "$AP_SSID"
    nmcli con modify "$WLAN_AP_CONN" \
      wifi.mode ap \
      wifi.band bg \
      wifi-sec.key-mgmt wpa-psk \
      wifi-sec.psk-flags 0 \
      connection.master "$LAN_IF" connection.slave-type bridge \
      connection.autoconnect yes connection.autoconnect-priority 100
  fi
  store_ap_psk_in_profile

  nmcli con up "$BR_CONN"
  nmcli con up "$ETH_SLAVE_CONN" || true
  activate_internal_ap
}

# The AP not coming up is an error (it used to be ignored). A host without
# the AP interface (a VM) keeps the profile unactivated, except on Raspberry
# Pi OS, where the on-board Wi-Fi is expected.
activate_internal_ap() {
  if [[ ! -e "/sys/class/net/$AP_IF" ]]; then
    if is_raspberry_pi_os; then
      echo "ERROR: $AP_IF (the on-board Wi-Fi for the internal AP) does not exist." >&2
      exit 1
    fi
    echo "NOTICE: there is no $AP_IF on this host; the internal AP profile ($WLAN_AP_CONN) is saved but not activated."
    return 0
  fi
  if ! nmcli con up "$WLAN_AP_CONN"; then
    echo "ERROR: the internal AP ($WLAN_AP_CONN on $AP_IF) did not come up. Check: rfkill list; nmcli radio; the Wi-Fi country (WIFI_COUNTRY); journalctl -u NetworkManager." >&2
    exit 1
  fi
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

# ssh.socket (shipped disabled by Debian trixie's openssh-server) listens on
# port 22 on every address and ignores ListenAddress; with it active,
# ssh.service also cannot bind port 22. Use ssh.service only.
use_ssh_service_not_socket() {
  if systemctl cat ssh.socket >/dev/null 2>&1 \
      && { systemctl is-enabled --quiet ssh.socket || systemctl is-active --quiet ssh.socket; }; then
    echo "NOTICE: ssh.socket listens on every address and ignores ListenAddress; disabling it in favour of ssh.service."
    systemctl disable --now ssh.socket
  fi
}

# sshd listens on the br0 address only. At boot br0 may not have it yet:
# sshd then exits 255 ("Cannot bind any address"), which Debian's ssh.service
# does not restart (RestartPreventExitStatus=255), and SSH stays down. The
# drop-in orders ssh after network-online and retries every 5 s without a
# limit until the address is there. It widens nothing (no other address,
# no ip_nonlocal_bind).
install_ssh_dropin() {
  install -d -m 0755 "$(dirname "$SSH_DROPIN")"
  cat > "$SSH_DROPIN" <<'EOD'
# Installed by Azazel-Edge install_internal_network.sh: sshd listens on the
# internal bridge address only, which may appear after sshd first starts.
[Unit]
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
RestartPreventExitStatus=
Restart=on-failure
RestartSec=5s
EOD
  chmod 0644 "$SSH_DROPIN"
}

# ListenAddress lines in sshd_config.d (included by sshd_config) are the
# operator's and are left as they are, but they add to the scope set here:
# with ALLOW_EXTERNAL_SSH=true sshd still listens only where they say, and
# without it they widen the br0-only scope. Reported, not changed.
notice_dropin_listen_addresses() {
  local f
  for f in "$SSHD_CONF_D"/*.conf; do
    [[ -f "$f" ]] || continue
    if grep -Eqi '^[[:space:]]*ListenAddress[[:space:]]' "$f"; then
      echo "NOTICE: $f sets ListenAddress; it is not changed and applies together with this installer's setting (ALLOW_EXTERNAL_SSH=${ALLOW_EXTERNAL_SSH}). Check: sshd -T | grep -i listenaddress"
    fi
  done
}

configure_sshd() {
  backup_file "$SSHD_CONF"
  notice_dropin_listen_addresses

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

  # A config sshd rejects is never installed (it would not start again).
  # sshd -t needs the privilege separation directory, which only exists while
  # ssh.service runs (RuntimeDirectory=sshd).
  [[ -d /run/sshd ]] || install -d -m 0755 /run/sshd
  if ! sshd -t -f "${SSHD_CONF}.tmp"; then
    rm -f "${SSHD_CONF}.tmp"
    echo "ERROR: sshd rejects the new configuration; $SSHD_CONF is not changed." >&2
    exit 1
  fi
  mv "${SSHD_CONF}.tmp" "$SSHD_CONF"

  install_ssh_dropin
  systemctl daemon-reload
  systemctl restart ssh
}

configure_forwarding_and_nat() {
  local wan_if="$WAN_IF_DETECTED"

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
  # An existing /etc/azazel-edge keeps its mode (Edge#471: never widened).
  [[ -d /etc/azazel-edge ]] || install -d -m 0750 /etc/azazel-edge
  cat > "$FIRST_MINUTE_CFG" <<'EOD'
suppress_auto_wifi: false
EOD
}

ensure_services() {
  systemctl enable --now NetworkManager
  systemctl enable --now avahi-daemon
  use_ssh_service_not_socket
  systemctl enable --now ssh
}

install_runner() {
  cat > "$RUNNER_FILE" <<'EOR'
#!/usr/bin/env bash
set -euo pipefail

nmcli con up lan-br0 || true
nmcli con up lan-eth0-slave || true
# The internal AP not coming up fails this unit (after the rest is applied),
# so it shows in `systemctl --failed` instead of passing silently.
ap_rc=0
if [[ -e /sys/class/net/wlan0 ]]; then
  if command -v rfkill >/dev/null 2>&1; then
    rfkill unblock wifi || true
  fi
  nmcli con up lan-wlan0-ap || ap_rc=$?
fi

systemctl restart dnsmasq
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
# Last, and a failure does not stop the steps above: sshd listens on the br0
# address only, which may not be there yet; the ssh.service drop-in
# (azazel-edge-listen.conf) keeps retrying every 5 s until it is.
systemctl restart ssh || echo "NOTICE: ssh did not start yet (br0 address missing?); ssh.service retries every 5 s." >&2
if [[ "$ap_rc" -ne 0 ]]; then
  echo "ERROR: the internal AP (lan-wlan0-ap) did not come up (nmcli exit $ap_rc). Check: rfkill list; nmcli radio; the Wi-Fi country." >&2
  exit 1
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
  # Checked before anything is changed.
  check_wifi_country
  WAN_IF_DETECTED="$(detect_wan_if)"
  echo "Uplink (WAN) interface: $WAN_IF_DETECTED"
  install_packages
  ensure_services
  resolve_ap_psk
  prepare_wifi_radio
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
  case "$AP_PSK_SOURCE" in
    generated) echo "AP passphrase: a new random one, saved root-only in $AP_PSK_FILE (read it with: sudo cat $AP_PSK_FILE)." ;;
    kept) echo "AP passphrase: unchanged, saved root-only in $AP_PSK_FILE." ;;
    *) echo "AP passphrase: the one given in AP_PSK, saved root-only in $AP_PSK_FILE." ;;
  esac
  if [[ "${ALLOW_EXTERNAL_SSH,,}" == "true" ]]; then
    echo "SSH listen scope: all interfaces (temporary external access enabled)."
  else
    echo "SSH listen scope: ${SSH_LISTEN_IP} only."
  fi
  echo "From internal host, verify: ssh azazel@Azazel-Edge.local"
}

main "$@"
