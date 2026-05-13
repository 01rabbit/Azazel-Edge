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

if ! command -v cryptsetup >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y cryptsetup
fi

install -d /var/lib/azazel-edge /etc/azazel-edge "${MOUNT_POINT}"

if [[ ! -f "${IMG_PATH}" ]]; then
  dd if=/dev/zero of="${IMG_PATH}" bs=1M count="${SIZE_MB}" status=none
fi

if ! cryptsetup isLuks "${IMG_PATH}" >/dev/null 2>&1; then
  echo "Initialize LUKS container for ${IMG_PATH}."
  echo "You will be prompted for a passphrase."
  cryptsetup luksFormat "${IMG_PATH}"
fi

if [[ ! -e "/dev/mapper/${MAPPER_NAME}" ]]; then
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
  echo "${MAPPER_NAME} ${IMG_PATH} none luks" >> /etc/crypttab
fi

UUID="$(blkid -s UUID -o value "/dev/mapper/${MAPPER_NAME}" || true)"
if [[ -n "${UUID}" ]] && ! grep -q "${UUID}" /etc/fstab 2>/dev/null; then
  echo "UUID=${UUID} ${MOUNT_POINT} ext4 defaults,nofail 0 2" >> /etc/fstab
fi

echo "Encrypted storage prepared at ${MOUNT_POINT}."
