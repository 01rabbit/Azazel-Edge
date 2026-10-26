#!/usr/bin/env bash
# Edge#477: the account of the optional sensor units
# (azazel-edge-netflow-receiver, azazel-edge-snmp-poller: User=azazel,
# Group=azazel). No other installer creates it. Idempotent; run as root
# (install_sensors.sh runs it before it installs either unit).
#
#  - Creates the system group azazel and the system user azazel (no login, no
#    home, primary group azazel, no other group) when they are missing, the
#    way setup_web_account.sh and setup_agent_account.sh create theirs.
#  - An existing azazel that is not that system account stops the script:
#    a uid or gid that is not a system id (a person's login account named
#    azazel, for example), another primary group, a login shell or a home
#    directory that exists. Nothing is changed then; the sensor units would
#    otherwise run as that account.
#
# Nothing here grants a capability, a sudo or polkit rule, or a group.
set -euo pipefail

SENSOR_USER="azazel"
SENSOR_GROUP="azazel"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

say() { echo "[sensor-account] $*"; }
die() { echo "[sensor-account] ERROR: $*" >&2; exit 1; }

login_defs() {
  local key="$1" default="$2" value=""
  if [[ -r /etc/login.defs ]]; then
    value="$(awk -v k="$key" '$1 == k { v = $2 } END { print v }' /etc/login.defs)"
  fi
  if [[ "$value" =~ ^[0-9]+$ ]]; then echo "$value"; else echo "$default"; fi
}
SYS_UID_MAX="$(login_defs SYS_UID_MAX 999)"
SYS_GID_MAX="$(login_defs SYS_GID_MAX 999)"

no_login_shell() {
  case "$1" in
    /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) return 0 ;;
    *) return 1 ;;
  esac
}

if gid="$(getent group "$SENSOR_GROUP" | cut -d: -f3)" && [[ -n "$gid" ]]; then
  if (( gid == 0 || gid > SYS_GID_MAX )); then
    die "group $SENSOR_GROUP already exists with gid $gid, which is not a system group; resolve this by hand"
  fi
  say "group $SENSOR_GROUP exists (gid $gid)"
else
  groupadd --system "$SENSOR_GROUP"
  say "created group $SENSOR_GROUP"
fi
want_gid="$(getent group "$SENSOR_GROUP" | cut -d: -f3)"

if entry="$(getent passwd "$SENSOR_USER")" && [[ -n "$entry" ]]; then
  uid="$(cut -d: -f3 <<<"$entry")"; pgid="$(cut -d: -f4 <<<"$entry")"
  home="$(cut -d: -f6 <<<"$entry")"; shell="$(cut -d: -f7 <<<"$entry")"
  if (( uid == 0 || uid > SYS_UID_MAX )); then
    die "user $SENSOR_USER already exists with uid $uid, which is not a system account (a login account?); the sensor units would run as it. Resolve this by hand"
  fi
  [[ "$pgid" == "$want_gid" ]] || die "user $SENSOR_USER exists with primary group $pgid, not $SENSOR_GROUP; resolve this by hand"
  no_login_shell "$shell" || die "user $SENSOR_USER exists with login shell $shell; resolve this by hand"
  if [[ -n "$home" && "$home" != "/nonexistent" && -e "$home" ]]; then
    die "user $SENSOR_USER exists with the home directory $home; resolve this by hand"
  fi
  say "user $SENSOR_USER exists (uid $uid)"
else
  shell="/usr/sbin/nologin"; [[ -x "$shell" ]] || shell="/bin/false"
  useradd --system --gid "$SENSOR_GROUP" --no-create-home --home-dir /nonexistent --shell "$shell" "$SENSOR_USER"
  say "created user $SENSOR_USER"
fi
extra_groups="$(id -nG "$SENSOR_USER" | tr ' ' '\n' | grep -vx "$SENSOR_GROUP" || true)"
[[ -z "$extra_groups" ]] || say "NOTICE: $SENSOR_USER is also in: $(echo $extra_groups) (not added by this script)"
say "done"
