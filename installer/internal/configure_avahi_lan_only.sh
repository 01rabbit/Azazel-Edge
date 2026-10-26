#!/usr/bin/env bash
# Limit avahi-daemon (mDNS, UDP 5353) to the internal LAN bridge (Edge#477).
#
# avahi-daemon answers on every interface unless allow-interfaces is set, so
# without this it announced the device (Azazel-Edge.local and its services)
# on the uplink (WAN) too, over IPv4 and IPv6. allow-interfaces covers both.
# avahi follows interfaces as they come and go, so br0 need not be up yet.
#
# set_dev_remote_access.sh MODE=open widens this to br0 plus the uplink on
# purpose (development only); MODE=close sets it back to br0, as here.
set -euo pipefail

LAN_IF="br0"
AVAHI_CONF="/etc/avahi/avahi-daemon.conf"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

if [[ ! -f "$AVAHI_CONF" ]]; then
  echo "ERROR: $AVAHI_CONF not found (avahi-daemon is installed by install_internal_network.sh)" >&2
  exit 1
fi

# Set allow-interfaces in the [server] section (avahi reads it only there):
# every existing allow-interfaces line, commented out or not, is dropped and
# one line goes right after [server]; [server] is added if missing.
set_allow_interfaces() {
  local file="$1" value="$2" tmp
  tmp="$(mktemp "${file}.XXXXXX")"
  awk -v value="$value" '
    BEGIN { done = 0; section = "" }
    /^[[:space:]]*\[[^]]*\][[:space:]]*$/ {
      line = $0
      gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", line)
      section = line
      print
      if (section == "server" && !done) { print "allow-interfaces=" value; done = 1 }
      next
    }
    /^[#;[:space:]]*allow-interfaces[[:space:]]*=/ { next }
    { print }
    END { if (!done) { print ""; print "[server]"; print "allow-interfaces=" value } }
  ' "$file" > "$tmp"
  chmod --reference="$file" "$tmp"
  chown --reference="$file" "$tmp"
  mv -f -- "$tmp" "$file"
}

cp -a "$AVAHI_CONF" "${AVAHI_CONF}.bak.$(date +%Y%m%d%H%M%S)"
set_allow_interfaces "$AVAHI_CONF" "$LAN_IF"
echo "[avahi] allow-interfaces=${LAN_IF} in ${AVAHI_CONF}"

if systemctl is-enabled avahi-daemon >/dev/null 2>&1; then
  systemctl restart avahi-daemon
fi
