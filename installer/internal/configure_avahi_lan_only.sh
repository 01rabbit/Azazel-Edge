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

# Write the config with allow-interfaces in the [server] section (avahi
# reads it only there) to stdout: every existing allow-interfaces line,
# commented out or not, is dropped and one line goes right after [server];
# [server] is added if missing.
render_allow_interfaces() {
  local file="$1" value="$2"
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
  ' "$file"
}

# Replace the file only when it changes. The first change keeps the
# original once as ${file}.azazel-edge.bak (never overwritten, so it stays
# the pre-Azazel config); re-runs add no backups. Prints "changed" or
# "unchanged".
set_allow_interfaces() {
  local file="$1" value="$2" tmp
  tmp="$(mktemp "${file}.XXXXXX")"
  if ! render_allow_interfaces "$file" "$value" > "$tmp"; then
    rm -f -- "$tmp"
    echo "ERROR: could not rewrite $file" >&2
    return 1
  fi
  if cmp -s -- "$tmp" "$file"; then
    rm -f -- "$tmp"
    echo unchanged
    return 0
  fi
  [[ -e "${file}.azazel-edge.bak" ]] || cp -a -- "$file" "${file}.azazel-edge.bak"
  chmod --reference="$file" "$tmp"
  chown --reference="$file" "$tmp"
  mv -f -- "$tmp" "$file"
  echo changed
}

result="$(set_allow_interfaces "$AVAHI_CONF" "$LAN_IF")"
echo "[avahi] allow-interfaces=${LAN_IF} in ${AVAHI_CONF} (${result})"

if [[ "$result" == "changed" ]] && systemctl is-enabled avahi-daemon >/dev/null 2>&1; then
  systemctl restart avahi-daemon
fi
