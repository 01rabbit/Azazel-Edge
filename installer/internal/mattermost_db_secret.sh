#!/usr/bin/env bash
# Create the Mattermost database password before the Mattermost stack starts
# (Edge#477). security/docker-compose.mattermost.yml reads it from this env
# file and holds no password itself.
#
#   mattermost_db_secret.sh [ENV_FILE]   (default /etc/azazel-edge/mattermost-db.env)
#
# - A new password is random (192 bits, hex). The file is 0600 from its first
#   byte (root:root when run as root) and the password is never printed.
# - An existing file is kept as it is (only its mode is narrowed): the
#   database already uses that password.
# - A database created before this change still has the former fixed
#   password. Its password is changed to the new one first (psql on the
#   container's local socket, the statement on stdin), and the file is written
#   only after that worked, so a failed run leaves nothing half done and the
#   next run tries again.
set -euo pipefail

ENV_FILE="${1:-/etc/azazel-edge/mattermost-db.env}"
DB_CONTAINER="azazel-edge-mm-db"
DB_IMAGE="postgres:16-alpine"
DB_USER="mmuser"
DB_NAME="mattermost"
DB_HOST="mattermost-db"
VOLUME_LABEL="com.docker.compose.volume=mattermost_db"

log() { printf '[mattermost-db] %s\n' "$*"; }
die() { printf '[mattermost-db] ERROR: %s\n' "$*" >&2; exit 1; }

narrow_mode() {
  chmod 0600 "$1"
  if [[ "${EUID}" -eq 0 ]]; then
    chown root:root "$1"
  fi
}

if [[ -L "${ENV_FILE}" || -d "${ENV_FILE}" ]]; then
  die "${ENV_FILE} is a symlink or a directory; refusing to use it"
fi

if [[ -f "${ENV_FILE}" ]]; then
  if ! grep -q '^POSTGRES_PASSWORD=.' "${ENV_FILE}" || ! grep -q '^MM_SQLSETTINGS_DATASOURCE=.' "${ENV_FILE}"; then
    die "${ENV_FILE} lacks POSTGRES_PASSWORD or MM_SQLSETTINGS_DATASOURCE; not replacing it (the database may already use its password)"
  fi
  narrow_mode "${ENV_FILE}"
  log "keeping ${ENV_FILE}"
  exit 0
fi

password="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
if [[ ! "${password}" =~ ^[0-9a-f]{48}$ ]]; then
  die "could not read random bytes"
fi

have_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

wait_ready() {
  local i
  for i in $(seq 1 60); do
    # A query as the Mattermost role on its database: it shows that the
    # role and the database answer, which a bare readiness probe does not.
    if docker exec "$1" psql -q -tA -U "${DB_USER}" -d "${DB_NAME}" -c 'select 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

set_db_password() {
  # The statement goes on stdin, so the password is not in any command line.
  printf "ALTER USER %s WITH PASSWORD '%s';\n" "${DB_USER}" "${password}" \
    | docker exec -i "$1" psql -v ON_ERROR_STOP=1 -q -U "${DB_USER}" -d "${DB_NAME}" >/dev/null
}

if have_docker; then
  if docker container inspect "${DB_CONTAINER}" >/dev/null 2>&1; then
    log "existing database container found; replacing its former fixed password"
    if [[ "$(docker container inspect -f '{{.State.Running}}' "${DB_CONTAINER}")" != "true" ]]; then
      docker start "${DB_CONTAINER}" >/dev/null
    fi
    wait_ready "${DB_CONTAINER}" || die "database container ${DB_CONTAINER} did not become ready"
    set_db_password "${DB_CONTAINER}" || die "could not change the database password in ${DB_CONTAINER}"
  else
    # (no mapfile: the dev stack runs this with macOS bash 3.2)
    volumes=()
    while IFS= read -r vol; do
      [[ -n "${vol}" ]] && volumes+=("${vol}")
    done < <(docker volume ls -q --filter "label=${VOLUME_LABEL}")
    if (( ${#volumes[@]} > 1 )); then
      die "more than one Mattermost database volume (${volumes[*]}); set the password by hand"
    fi
    if (( ${#volumes[@]} == 1 )); then
      # Data from an earlier install without its container: start a
      # temporary one on the volume only to change the password.
      tmp_name="${DB_CONTAINER}-password-change"
      log "existing database volume found; replacing its former fixed password"
      docker rm -f "${tmp_name}" >/dev/null 2>&1 || true
      docker run -d --name "${tmp_name}" --network none \
        -v "${volumes[0]}:/var/lib/postgresql/data" "${DB_IMAGE}" >/dev/null
      ok=1
      wait_ready "${tmp_name}" && set_db_password "${tmp_name}" || ok=0
      docker rm -f "${tmp_name}" >/dev/null 2>&1 || true
      (( ok == 1 )) || die "could not change the database password on volume ${volumes[0]}"
    fi
  fi
fi

dir="$(dirname -- "${ENV_FILE}")"
[[ -d "${dir}" ]] || install -d -m 0750 -- "${dir}"
tmp="$(umask 077 && mktemp "${dir}/.$(basename -- "${ENV_FILE}").XXXXXX")"
if ! printf 'POSTGRES_PASSWORD=%s\nMM_SQLSETTINGS_DATASOURCE=postgres://%s:%s@%s:5432/%s?sslmode=disable&connect_timeout=10\n' \
      "${password}" "${DB_USER}" "${password}" "${DB_HOST}" "${DB_NAME}" >"${tmp}" \
    || ! narrow_mode "${tmp}" || ! mv -f -- "${tmp}" "${ENV_FILE}"; then
  rm -f -- "${tmp}"
  die "could not write ${ENV_FILE}"
fi
unset password
log "wrote ${ENV_FILE} (0600)"
