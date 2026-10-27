#!/usr/bin/env bash
# Create the key for the M.I.O. trace audit digests (Edge#389).
#
#   provision_mio_trace_audit_key.sh [KEY_FILE]
#     KEY_FILE  default /etc/azazel-edge/mio-trace-audit.key
#
# The M.I.O. trace audit keeps keyed digests (HMAC-SHA256) instead of free
# text. With this key the digests stay comparable across restarts; without
# it each process uses a random key and its records say
# "digest_key": "ephemeral". Nothing on the device uses the key today: the
# trace audit is off by default (config/mio_trace_audit.json) and no service
# runs the M.I.O. cognitive core yet (#385). The installer does not run this
# script; run it as root when the trace audit is enabled.
#
# The rules of provision_trust_capsule_key.sh (Edge#477, #498), plus
# stricter checks on what counts as a usable key:
# - A new key is random (256 bits, hex). The file is 0600 root:root (root:
#   when run as root) from its first byte (write_private_file) and the key is
#   never printed or put on a command line.
# - An existing file with a usable key is kept (only its mode and owner are
#   narrowed): running the script again keeps the key.
# - A key is usable only when the file holds one value of at least 32
#   characters of [A-Za-z0-9._~+/=-] (after surrounding whitespace is
#   removed), with at least 8 different characters and none of the markers
#   of a test or example key (test, example, dummy, sample, changeme,
#   devkey, dev-key, not-for-devices), no NUL byte, and a file of at most
#   4096 bytes. The Python side
#   (key_is_usable in trace_recorder.py of the cognitive core) applies the same rule.
#   Anything else is replaced by a new random key with a NOTICE (never the
#   value).
# - There is no environment variable for this key and no built-in key.
# - Do not run it with xtrace (bash -x): xtrace would print the key. The
#   script turns xtrace off first; a trace enabled in another way (for
#   example BASH_XTRACEFD in a parent shell) is the caller's responsibility.
set +x
set -euo pipefail

KEY_FILE="${1:-/etc/azazel-edge/mio-trace-audit.key}"

log() { printf '[mio-trace-audit-key] %s\n' "$*"; }
die() { printf '[mio-trace-audit-key] ERROR: %s\n' "$*" >&2; exit 1; }

# Same as provision_trust_capsule_key.sh's write_private_file (Edge#477):
# stdin goes to a new 0600 mktemp file beside $1, which is renamed over $1
# (mv -T: a symlink at $1 is replaced, not followed).
write_private_file() {
  local dst="$1" tmp
  tmp="$(umask 077 && mktemp "$(dirname -- "${dst}")/.$(basename -- "${dst}").XXXXXX")"
  if ! cat >"${tmp}" || ! chmod 0600 "${tmp}" || ! mv -fT -- "${tmp}" "${dst}"; then
    rm -f -- "${tmp}"
    echo "[ERROR] could not write ${dst}" >&2
    return 1
  fi
}

narrow_mode() {
  chmod 0600 "$1"
  if [[ "${EUID}" -eq 0 ]]; then
    chown root:root "$1"
  fi
}

# The key in file $1 with surrounding whitespace (CR included) removed. The
# value is only kept in a variable, never printed.
key_in() {
  local v size
  # A NUL byte or a file over 4096 bytes is never a key ("$(<file)" would
  # drop NUL bytes silently and read a key Python refuses).
  size="$(wc -c <"$1")" || size=0
  if (( size > 4096 )) || (( $(LC_ALL=C tr -d '\000' <"$1" | wc -c) != size )); then
    return 0
  fi
  v="$(<"$1")" || v=""
  v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "${v}"
}

# Number of different characters in $1 (bash only: no command line sees it).
distinct_chars() {
  local s="$1" seen="" c i
  for (( i = 0; i < ${#s}; i++ )); do
    c="${s:i:1}"
    [[ "${seen}" == *"${c}"* ]] || seen+="${c}"
  done
  printf '%s' "${#seen}"
}

usable() {
  local lowered="${1,,}" marker
  [[ "$1" =~ ^[A-Za-z0-9._~+/=-]{32,256}$ ]] || return 1
  (( $(distinct_chars "$1") >= 8 )) || return 1
  for marker in test example dummy sample changeme devkey dev-key not-for-devices; do
    [[ "${lowered}" != *"${marker}"* ]] || return 1
  done
}

if [[ -L "${KEY_FILE}" || -d "${KEY_FILE}" ]]; then
  die "${KEY_FILE} is a symlink or a directory; refusing to use it"
fi
if [[ -e "${KEY_FILE}" && ! -f "${KEY_FILE}" ]]; then
  die "${KEY_FILE} is not a regular file; refusing to use it"
fi

if [[ -f "${KEY_FILE}" ]]; then
  key="$(key_in "${KEY_FILE}")"
  if usable "${key}"; then
    unset key
    narrow_mode "${KEY_FILE}"
    log "keeping the key in ${KEY_FILE}"
    exit 0
  fi
  unset key
  log "NOTICE: ${KEY_FILE} holds no usable key (empty, shorter than 32 characters, too few different characters, a test or example key, or other characters); writing a new one"
fi

key="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ "${key}" =~ ^[0-9a-f]{64}$ ]] || die "could not read random bytes"

dir="$(dirname -- "${KEY_FILE}")"
[[ -d "${dir}" ]] || install -d -m 0750 -- "${dir}"
# printf is a shell builtin: the key is not on any command line.
printf '%s\n' "${key}" | write_private_file "${KEY_FILE}" || die "could not write ${KEY_FILE}"
unset key
narrow_mode "${KEY_FILE}"
log "wrote ${KEY_FILE} (0600, new random key)"
