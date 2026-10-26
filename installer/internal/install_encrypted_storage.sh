#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

IMG_PATH="/var/lib/azazel-secrets.img"
MAPPER_NAME="azazel-secrets"
MOUNT_POINT="/etc/azazel-edge/secrets"
SIZE_MB="${AZAZEL_LUKS_SIZE_MB:-512}"
TPM_BIND="${TPM_BIND:-0}"
# Bounds for boot (crypttab): nofail keeps the volume out of the boot's hard
# dependencies, timeout= ends the passphrase prompt and
# x-systemd.device-timeout= the wait for the backing device, so a headless
# device boots (without the volume) when nobody types the passphrase.
CRYPTTAB_OPTIONS="luks,nofail,timeout=90s,x-systemd.device-timeout=30s"

# cryptsetup asks for the passphrase (and the luksFormat confirmation) on the
# terminal; without one it fails or waits. Stop clearly instead. The
# passphrase is typed into cryptsetup only: this script never reads, stores
# or logs it.
# Only stdin is checked: cryptsetup asks for the passphrase (and the
# luksFormat "Type 'yes'" confirmation) only when isatty(STDIN_FILENO), and
# then reads the passphrase from /dev/tty (falling back to stdin); with stdin
# not a terminal it reads stdin as a key file instead. stdout/stderr may be
# piped (`| tee`) without changing that.
require_tty() {
  if [[ ! -t 0 ]]; then
    echo "ERROR: $1: the encrypted secrets volume (Edge#206, on by default) needs a passphrase typed on a terminal, and stdin is not one. Run the installer from an interactive terminal (to keep a log, use: script -c 'sudo ...' install.log, or pipe only the output: 2>&1 | tee install.log), or, to install without encrypted storage, re-run it with SKIP_LUKS=1 set explicitly." >&2
    exit 1
  fi
}

# Checked first, before anything is created: the volume is not open yet, so
# luksFormat and/or open below will ask for the passphrase.
if [[ ! -e "/dev/mapper/${MAPPER_NAME}" ]]; then
  require_tty "setting up the encrypted volume"
fi

if ! command -v cryptsetup >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y cryptsetup
fi

# An existing /etc/azazel-edge keeps its mode (Edge#471: never widened).
[[ -d /etc/azazel-edge ]] || install -d -m 0750 /etc/azazel-edge
install -d /var/lib/azazel-edge "${MOUNT_POINT}"

if [[ ! -f "${IMG_PATH}" ]]; then
  dd if=/dev/zero of="${IMG_PATH}" bs=1M count="${SIZE_MB}" status=none
fi

if ! cryptsetup isLuks "${IMG_PATH}" >/dev/null 2>&1; then
  require_tty "luksFormat of ${IMG_PATH}"
  echo "Initialize LUKS container for ${IMG_PATH}."
  echo "You will be prompted for a passphrase."
  cryptsetup luksFormat "${IMG_PATH}"
fi

if [[ ! -e "/dev/mapper/${MAPPER_NAME}" ]]; then
  require_tty "opening ${IMG_PATH}"
  cryptsetup open "${IMG_PATH}" "${MAPPER_NAME}"
fi

if ! blkid "/dev/mapper/${MAPPER_NAME}" >/dev/null 2>&1; then
  mkfs.ext4 -q "/dev/mapper/${MAPPER_NAME}"
fi

mountpoint -q "${MOUNT_POINT}" || mount "/dev/mapper/${MAPPER_NAME}" "${MOUNT_POINT}"
install -d "${MOUNT_POINT}/tokens" "${MOUNT_POINT}/tls" "${MOUNT_POINT}/wazuh"

for file in /etc/azazel-edge/web_token.txt /etc/azazel-edge/mattermost-command-token; do
  if [[ -f "${file}" ]]; then
    base="$(basename "${file}")"
    cp -f "${file}" "${MOUNT_POINT}/tokens/${base}"
    chmod 0600 "${MOUNT_POINT}/tokens/${base}"
  fi
done

if [[ "${TPM_BIND}" == "1" ]]; then
  echo "TPM_BIND=1 requested; TPM enrollment is environment-specific and should be performed manually."
fi

if ! grep -q "${IMG_PATH}" /etc/crypttab 2>/dev/null; then
  echo "${MAPPER_NAME} ${IMG_PATH} none ${CRYPTTAB_OPTIONS}" >> /etc/crypttab
elif grep -qxE "${MAPPER_NAME}[[:space:]]+${IMG_PATH}[[:space:]]+none[[:space:]]+luks" /etc/crypttab; then
  # The line an earlier install wrote (no nofail, no timeout): bound it too.
  sed -i -E "s#^${MAPPER_NAME}[[:space:]]+${IMG_PATH}[[:space:]]+none[[:space:]]+luks\$#${MAPPER_NAME} ${IMG_PATH} none ${CRYPTTAB_OPTIONS}#" /etc/crypttab
else
  echo "NOTICE: /etc/crypttab already has its own line for ${IMG_PATH}; not changed. Make sure it has nofail and timeout= so boot does not wait for the passphrase." >&2
fi

UUID="$(blkid -s UUID -o value "/dev/mapper/${MAPPER_NAME}" || true)"
FSTAB_OPTIONS="defaults,nofail,x-systemd.device-timeout=30s"
if [[ -n "${UUID}" ]] && ! grep -q "${UUID}" /etc/fstab 2>/dev/null; then
  echo "UUID=${UUID} ${MOUNT_POINT} ext4 ${FSTAB_OPTIONS} 0 2" >> /etc/fstab
elif [[ -n "${UUID}" ]] && grep -qxE "UUID=${UUID}[[:space:]]+${MOUNT_POINT}[[:space:]]+ext4[[:space:]]+defaults,nofail[[:space:]]+0[[:space:]]+2" /etc/fstab; then
  # The line an earlier install wrote (no device timeout): bound it too.
  sed -i -E "s#^UUID=${UUID}[[:space:]]+${MOUNT_POINT}[[:space:]]+ext4[[:space:]]+defaults,nofail[[:space:]]+0[[:space:]]+2\$#UUID=${UUID} ${MOUNT_POINT} ext4 ${FSTAB_OPTIONS} 0 2#" /etc/fstab
elif [[ -n "${UUID}" ]]; then
  echo "NOTICE: /etc/fstab already has its own line for UUID=${UUID}; not changed. Make sure it has nofail so boot does not wait for the volume." >&2
fi

echo "Encrypted storage prepared at ${MOUNT_POINT}."
