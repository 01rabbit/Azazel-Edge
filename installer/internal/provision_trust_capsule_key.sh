#!/usr/bin/env bash
# Create the key that signs the decision trust capsules (Edge#477).
#
#   provision_trust_capsule_key.sh [ENV_FILE] [SECURITY_ENV]
#     ENV_FILE      default /etc/azazel-edge/trust-capsule.env
#     SECURITY_ENV  default /etc/default/azazel-edge-security (only read)
#
# Only the AI agent signs capsules (azazel-edge-ai-agent, as azazel-agent);
# nothing on the device verifies them. systemd (PID 1, as root) reads this
# file through the agent unit's EnvironmentFile=, so the file is 0600
# root:root and the key reaches the agent's environment only. Without a key
# the agent writes unsigned capsules (signature_state "unsigned"); it never
# signs with a built-in key.
#
# - A new key is random (256 bits, hex). The file is 0600 from its first byte
#   (write_private_file) and the key is never printed or put on a command
#   line.
# - An existing file with a key is kept (only its mode and owner are
#   narrowed): running the installer again keeps the key.
# - Without the file, a key set by hand in SECURITY_ENV is carried over, so
#   the device keeps signing with it. That file is read by more units; the
#   line there is left as it is (this file wins for the agent) and a notice
#   says it may be removed.
# - A key is usable only when it is at least 32 characters of
#   [A-Za-z0-9._~+/=-] (after surrounding spaces, tabs, CR and one pair of
#   matching quotes are removed) and is not the public former default. That
#   set has no quote, backslash, space or "$", so systemd reads the value
#   exactly as checked here. A file or a hand-set key that is not usable
#   (missing, too short, the public former default, or a value systemd could
#   read differently) is not kept or carried over: a new random key is
#   written and a NOTICE says why (never the value).
set -euo pipefail

ENV_FILE="${1:-/etc/azazel-edge/trust-capsule.env}"
SECURITY_ENV="${2:-/etc/default/azazel-edge-security}"
KEY_VAR="AZAZEL_TRUST_CAPSULE_HMAC_KEY"
# The fallback key of earlier versions: public, so never kept or carried over.
PUBLIC_FORMER_DEFAULT_KEY="azazel-edge-dev-key"

log() { printf '[trust-capsule-key] %s\n' "$*"; }
die() { printf '[trust-capsule-key] ERROR: %s\n' "$*" >&2; exit 1; }

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

narrow_mode() {
  chmod 0600 "$1"
  if [[ "${EUID}" -eq 0 ]]; then
    chown root:root "$1"
  fi
}

# The last KEY_VAR value in file $1, normalized: surrounding whitespace
# (CR included) and one pair of matching quotes removed. The value is only
# kept in a variable, never printed.
key_in() {
  local v
  v="$(grep -E "^${KEY_VAR}=" "$1" 2>/dev/null | tail -n 1 || true)"
  v="${v#*=}"
  v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
  if (( ${#v} >= 2 )) && [[ ( "${v:0:1}" == '"' && "${v: -1}" == '"' ) || ( "${v:0:1}" == "'" && "${v: -1}" == "'" ) ]]; then
    v="${v:1:${#v}-2}"
  fi
  printf '%s' "${v}"
}

usable() {
  [[ "$1" =~ ^[A-Za-z0-9._~+/=-]{32,}$ && "$1" != "${PUBLIC_FORMER_DEFAULT_KEY}" ]]
}

if [[ -L "${ENV_FILE}" || -d "${ENV_FILE}" ]]; then
  die "${ENV_FILE} is a symlink or a directory; refusing to use it"
fi

key=""
if [[ -f "${ENV_FILE}" ]]; then
  key="$(key_in "${ENV_FILE}")"
  if usable "${key}"; then
    narrow_mode "${ENV_FILE}"
    log "keeping the key in ${ENV_FILE}"
    if [[ -f "${SECURITY_ENV}" ]] && grep -qE "^${KEY_VAR}=" "${SECURITY_ENV}"; then
      log "NOTICE: ${SECURITY_ENV} also sets ${KEY_VAR}; the agent uses ${ENV_FILE}, the line there may be removed"
    fi
    unset key
    exit 0
  fi
  log "NOTICE: ${ENV_FILE} holds no usable key (missing, shorter than 32 characters, the public former default, or characters systemd could read differently); writing a new one"
  key=""
fi

source_note="new random key"
if [[ -f "${SECURITY_ENV}" ]]; then
  key="$(key_in "${SECURITY_ENV}")"
  if usable "${key}"; then
    source_note="key carried over from ${SECURITY_ENV}"
  else
    if grep -qE "^${KEY_VAR}=" "${SECURITY_ENV}"; then
      log "NOTICE: ${SECURITY_ENV} sets ${KEY_VAR}, but it is not usable (shorter than 32 characters, the public former default, or characters systemd could read differently); not carried over, a new random key is used"
    fi
    key=""
  fi
fi
if [[ -z "${key}" ]]; then
  key="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "${key}" =~ ^[0-9a-f]{64}$ ]] || die "could not read random bytes"
fi

dir="$(dirname -- "${ENV_FILE}")"
[[ -d "${dir}" ]] || install -d -m 0750 -- "${dir}"
# printf is a shell builtin: the key is not on any command line.
printf '%s=%s\n' "${KEY_VAR}" "${key}" | write_private_file "${ENV_FILE}" || die "could not write ${ENV_FILE}"
unset key
narrow_mode "${ENV_FILE}"
log "wrote ${ENV_FILE} (0600, ${source_note})"
if [[ "${source_note}" != "new random key" ]]; then
  log "NOTICE: ${SECURITY_ENV} still sets ${KEY_VAR}; the agent uses ${ENV_FILE}, the line there may be removed"
fi
